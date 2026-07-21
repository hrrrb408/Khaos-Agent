"""Command line interface for the P0-A Khaos loop."""

from __future__ import annotations

import argparse
import asyncio
import os
import secrets
import subprocess
import sys
import uuid
from pathlib import Path

import yaml

from khaos.agent import AgentConfig, AgentLoop
from khaos.agent.compressor import ContextCompressor
from khaos.agent.error_handler import ErrorHandler
from khaos.cli.skills_commands import handle_skills_command
from khaos.cli.sse import encode_sse
from khaos.config import (
    USER_CONFIG_PATH,
    load_config,
    masked_config,
    reset_user_config,
    run_setup_wizard,
    set_user_config_value,
)
from khaos.db import Database
from khaos.db.state_root import (
    open_state_db_safely,
    project_id as compute_project_id,
    resolve_state_db_path,
)
from khaos.memory import MemoryBudget, MemoryManager, MemoryStore
from khaos.modes import ModeManager
from khaos.permissions import PermissionEngine
from khaos.routing.router import create_default_router
from khaos.skills import SkillManager
from khaos.tools import create_runtime_registry
from khaos.tools.scheduler import ToolScheduler


async def run_once(args: argparse.Namespace) -> int:
    """Run one user message and print SSE frames to stdout."""
    db_path = open_state_db_safely(
        resolve_state_db_path(Path.cwd(), args.db)
    )
    db = Database(db_path)
    await db.connect()
    await db.run_migrations()

    mode_manager = ModeManager(
        db, project_root=Path.cwd(),
        principal_id=f"local-uid:{os.getuid()}",
    )
    await mode_manager.load()
    if args.mode:
        await mode_manager.switch(ModeManager.parse(args.mode))

    session_id = args.session_id or str(uuid.uuid4())
    # M4 batch 3.1.16A-5-1b: compute the project identity from the CWD
    # and stamp it on every session row.  ``build_runtime`` recomputes
    # it from ``project_root`` (which defaults to Path.cwd()) — passing
    # it explicitly here keeps the session row's stamp in sync with the
    # runtime's bound identity.
    cli_project_id = compute_project_id(Path.cwd())
    await db.create_session(
        session_id, mode_manager.current_mode.value,
        principal_id=f"local-uid:{os.getuid()}",
        project_id=cli_project_id,
    )

    from khaos.runtime import RuntimeConfig, build_runtime, close_runtime_or_register
    runtime = None
    try:
        runtime = await build_runtime(RuntimeConfig(db=db, mode_manager=mode_manager, confirm_callback=_confirm_from_args(args), principal_id=f"local-uid:{os.getuid()}", project_id=cli_project_id))
        print(f"session_id: {session_id}", flush=True)
        async for message in runtime.loop.run(args.message, session_id):
            print(encode_sse(message), end="", flush=True)
    finally:
        if runtime is not None:
            await close_runtime_or_register(runtime)
        await db.close()
    return 0


async def run_repl(args: argparse.Namespace) -> int:
    """Run a tiny interactive shell for manual P0-A validation."""
    db_path = open_state_db_safely(
        resolve_state_db_path(Path.cwd(), args.db)
    )
    db = Database(db_path)
    await db.connect()
    await db.run_migrations()

    mode_manager = ModeManager(
        db, project_root=Path.cwd(),
        principal_id=f"local-uid:{os.getuid()}",
    )
    await mode_manager.load()
    session_id = args.session_id or str(uuid.uuid4())
    # M4 batch 3.1.16A-5-1b: see run_once for the rationale.
    cli_project_id = compute_project_id(Path.cwd())
    await db.create_session(
        session_id, mode_manager.current_mode.value,
        principal_id=f"local-uid:{os.getuid()}",
        project_id=cli_project_id,
    )
    from khaos.runtime import RuntimeConfig, build_runtime, close_runtime_or_register
    runtime = None
    try:
        runtime = await build_runtime(RuntimeConfig(db=db, mode_manager=mode_manager, confirm_callback=_interactive_confirm(args), principal_id=f"local-uid:{os.getuid()}", project_id=cli_project_id))
        loop = runtime.loop
        skill_manager = runtime.skill_manager
        print(f"session_id: {session_id}")
        print(f"mode: {mode_manager.current_mode.value}")
        while True:
            user_input = input("> ").strip()
            if user_input in {"/quit", "/exit"}:
                break
            if user_input.startswith("/skills"):
                result = handle_skills_command(user_input, skill_manager)
                if result.handled:
                    print(result.message)
                    continue
            if user_input.startswith("/mode "):
                target = ModeManager.parse(user_input.removeprefix("/mode "))
                await mode_manager.switch(target)
                await db.create_session(
                    session_id, target.value,
                    principal_id=f"local-uid:{os.getuid()}",
                    project_id=cli_project_id,
                )
                print(f"mode: {target.value}")
                continue
            if not user_input:
                continue
            async for message in loop.run(user_input, session_id):
                print(encode_sse(message), end="", flush=True)
    finally:
        if runtime is not None:
            await close_runtime_or_register(runtime)
        await db.close()
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Create the CLI argument parser."""
    parser = argparse.ArgumentParser(prog="khaos")
    parser.add_argument(
        "--db",
        default=None,
        help="SQLite database path (default: ~/.khaos/state/<project-id>/state.db)",
    )
    parser.add_argument("--session-id", help="Existing or new session id")
    parser.add_argument("--mode", choices=["office", "coding"], help="Initial mode")
    parser.add_argument("--message", help="Run one message and exit (non-interactive)")
    parser.add_argument("--no-tui", action="store_true", help="Use the line-oriented REPL instead of the full-screen TUI")
    parser.add_argument("--yes", action="store_true", help="Approve permission prompts")
    parser.add_argument("--remember", action="store_true", help="Remember approved permissions")
    return parser


def build_command_parser() -> argparse.ArgumentParser:
    """Create the product CLI parser with subcommands."""
    parser = argparse.ArgumentParser(prog="khaos", description="Khaos AI Agent Platform")
    subparsers = parser.add_subparsers(dest="command")

    start_parser = subparsers.add_parser("start", help="Start Khaos agent server + gateway")
    start_parser.add_argument(
        "--socket", default=f"/tmp/khaos-{os.getuid()}/agent.sock"
    )
    start_parser.add_argument(
        "--db",
        default=None,
        help="SQLite database path (default: ~/.khaos/state/<project-id>/state.db)",
    )
    start_parser.add_argument("--config", default="config.yaml")
    start_parser.add_argument("--gateway", action="store_true", help="Also start Go gateway")

    chat_parser = subparsers.add_parser("chat", help="Interactive chat session")
    chat_parser.add_argument("--mode", default="office", choices=["office", "coding"])
    chat_parser.add_argument(
        "--db",
        default=None,
        help="SQLite database path (default: ~/.khaos/state/<project-id>/state.db)",
    )
    chat_parser.add_argument("--config", default="config.yaml")
    chat_parser.add_argument("--session-id", help="Existing or new session id")
    chat_parser.add_argument("--no-tui", action="store_true", help="Use the line-oriented REPL")
    chat_parser.add_argument("--yes", action="store_true", help="Approve permission prompts")
    chat_parser.add_argument("--remember", action="store_true", help="Remember approved permissions")

    test_parser = subparsers.add_parser("test", help="Run tests", description="Run tests")
    test_parser.add_argument("--all", action="store_true", help="Run all tests (Python + Go)")
    test_parser.add_argument("--go", action="store_true", help="Run Go tests only")
    test_parser.add_argument("--python", action="store_true", help="Run Python tests only")
    test_parser.add_argument("--verbose", "-v", action="store_true")

    config_parser = subparsers.add_parser("config", help="Configuration management")
    config_parser.add_argument("--path", default="config.yaml")
    config_group = config_parser.add_mutually_exclusive_group()
    config_group.add_argument("--get", type=str, help="Get a config value")
    config_group.add_argument("--set", type=str, help="Set a config value (KEY=VALUE)")

    subparsers.add_parser("version", help="Show version")

    migrate_parser = subparsers.add_parser(
        "migrate",
        help="Trusted state migration tools (A-5-2)",
        description=(
            "Backfill project_id on legacy rows left by A-5-1a/A-5-1b. "
            "Legacy rows have project_id='' (the fail-closed default); "
            "this tool stamps the state DB's owning project_id on every "
            "empty row so they participate in cross-project forensic "
            "queries and future project-scoped filters."
        ),
    )
    migrate_sub = migrate_parser.add_subparsers(dest="migrate_command")

    pi_parser = migrate_sub.add_parser(
        "project-identity",
        help="Backfill project_id on legacy rows (A-5-2)",
    )
    pi_parser.add_argument(
        "--project-root",
        default=None,
        help="Project root to compute project_id from (default: CWD).",
    )
    pi_parser.add_argument(
        "--db",
        default=None,
        help="Override state DB path (default: ~/.khaos/state/<project-id>/state.db).",
    )
    pi_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview would-update counts without writing.",
    )
    pi_parser.add_argument(
        "--yes",
        action="store_true",
        help="Skip the interactive confirmation prompt.",
    )
    pi_parser.add_argument(
        "--table",
        action="append",
        dest="tables",
        help="Backfill only this table (repeatable). Default: all 8 A-5-1a tables.",
    )

    return parser


def cmd_start(args: argparse.Namespace) -> None:
    """Start the Python JSON-line agent server."""
    try:
        import uvloop

        uvloop.install()
    except ImportError:
        pass

    gateway_capability: str | None = None
    gateway_process: subprocess.Popen | None = None
    gateway_pid: int | None = None
    if args.gateway:
        gateway_capability = secrets.token_urlsafe(48)
        cache = _project_root() / ".cache"
        cache.mkdir(mode=0o700, exist_ok=True)
        gateway_binary = cache / "khaos-gateway"
        subprocess.run(
            ["go", "build", "-o", str(gateway_binary), "./cmd/gateway"],
            cwd=str(_project_root() / "go"),
            check=True,
        )
        read_fd, write_fd = os.pipe()
        os.write(write_fd, f"{gateway_capability}\n".encode("utf-8"))
        os.close(write_fd)
        gateway_cmd = [str(gateway_binary)]
        gateway_environment = dict(os.environ)
        gateway_environment.pop("KHAOS_PYTHON_CAPABILITY", None)
        gateway_environment["KHAOS_PYTHON_CAPABILITY_FD"] = str(read_fd)
        gateway_environment["KHAOS_PYTHON_AGENT"] = args.socket
        try:
            gateway_process = subprocess.Popen(
                gateway_cmd,
                cwd=str(_project_root()),
                env=gateway_environment,
                pass_fds=(read_fd,),
            )
        finally:
            os.close(read_fd)
        gateway_pid = gateway_process.pid
        print("Started Go gateway with an inherited boot capability")

    print(f"Starting Khaos agent on Unix socket {args.socket}")
    db_path = open_state_db_safely(
        resolve_state_db_path(Path.cwd(), args.db)
    )
    print(f"Database: {db_path}")
    print(f"Config: {args.config}")
    from khaos.grpc_server import serve_json_lines

    try:
        asyncio.run(
            serve_json_lines(
                args.socket,
                str(db_path),
                project_root=Path.cwd(),
                config_path=Path(args.config),
                gateway_capability=gateway_capability,
                gateway_pid=gateway_pid,
            )
        )
    finally:
        if gateway_process is not None:
            gateway_process.terminate()


def cmd_chat(args: argparse.Namespace) -> None:
    """Launch the interactive Khaos interface."""
    run_interactive(args)


def cmd_test(args: argparse.Namespace) -> None:
    """Run selected test suites."""
    project_root = _project_root()
    results: list[tuple[str, bool]] = []

    if args.all or args.python or not args.go:
        print("Running Python tests...")
        cmd = [
            sys.executable,
            "-m",
            "pytest",
            "python/tests/",
            "-x",
            "--ignore=python/tests/tui",
        ]
        if args.verbose:
            cmd.append("-v")
        result = subprocess.run(cmd, cwd=str(project_root), capture_output=True, text=True)
        print(result.stdout[-500:] if len(result.stdout) > 500 else result.stdout)
        if result.stderr:
            print(result.stderr[-200:])
        results.append(("Python", result.returncode == 0))

    if args.all or args.go:
        print("\nRunning Go tests...")
        result = subprocess.run(
            ["go", "test", "./go/...", "-v"],
            cwd=str(project_root),
            capture_output=True,
            text=True,
        )
        print(result.stdout[-500:] if len(result.stdout) > 500 else result.stdout)
        if result.stderr:
            print(result.stderr[-200:])
        results.append(("Go", result.returncode == 0))

    if not results:
        print("No tests selected. Use --python, --go, or --all")
        return

    print("\n" + "=" * 40)
    for name, passed in results:
        status = "PASSED" if passed else "FAILED"
        print(f"  {name}: {status}")
    print("=" * 40)
    if not all(passed for _, passed in results):
        raise SystemExit(1)


def cmd_config(args: argparse.Namespace) -> None:
    """Read or update a YAML configuration file."""
    config_path = Path(args.path)
    if not config_path.exists():
        print(f"Config file not found: {config_path}")
        print("Creating default config...")
        config_path.write_text(
            yaml.safe_dump({"model": "default", "socket": "/tmp/khaos-agent.sock"}, sort_keys=False),
            encoding="utf-8",
        )
        return

    config = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}

    if args.get:
        value = config
        for key in args.get.split("."):
            if isinstance(value, dict):
                value = value.get(key)
            else:
                value = None
                break
        if value is not None:
            print(f"{args.get} = {value}")
        else:
            print(f"Key not found: {args.get}")
    elif args.set:
        key, value = args.set.split("=", 1)
        config[key] = value
        config_path.write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")
        print(f"Set {key} = {value}")
    else:
        print(yaml.safe_dump(config, allow_unicode=True, sort_keys=False), end="")


def cmd_version() -> None:
    """Show the product version."""
    print("Khaos Agent Platform v0.1.0")
    print("Python + Go + Rust")


def cmd_migrate(args: argparse.Namespace) -> int:
    """Trusted state migration entrypoint (A-5-2).

    Dispatches to ``migrate project-identity`` — the only subcommand
    today.  Returns 0 on success, 2 on argument error, 3 on state-root
    violation.

    Flow:
      1. Resolve state DB path (state-root enforcement).
      2. Open DB, run migrations, close.
      3. Preview pass (dry-run) → per-table legacy-row counts.
      4. Print preview.
      5. If --dry-run: stop here.
      6. If not --yes: prompt for confirmation.
      7. Write pass → UPDATE each table, print per-table updated counts.
    """
    if getattr(args, "migrate_command", None) != "project-identity":
        print(
            "usage: khaos migrate project-identity [--project-root PATH] "
            "[--db PATH] [--dry-run] [--yes] [--table NAME]",
            file=sys.stderr,
        )
        return 2

    from khaos.db.migrations_cli import (
        MigrationError,
        resolve_backfill_db_path,
        run_backfill,
    )
    from khaos.db.state_root import StateRootError

    project_root = Path(args.project_root) if args.project_root else Path.cwd()

    try:
        db_path = resolve_backfill_db_path(project_root, args.db)
    except StateRootError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3

    print(f"Project root: {project_root.resolve()}")
    print(f"State DB:     {db_path}")
    if args.tables:
        print(f"Tables:       {', '.join(args.tables)}")
    else:
        print("Tables:       all 8 A-5-1a tables")
    print()

    async def _open_db():
        from khaos.db import Database
        db = Database(db_path)
        await db.connect()
        await db.run_migrations()
        return db

    async def _preview():
        db = await _open_db()
        try:
            return await run_backfill(
                db, project_root, tables=args.tables, dry_run=True,
            )
        finally:
            await db.close()

    async def _write():
        db = await _open_db()
        try:
            return await run_backfill(
                db, project_root, tables=args.tables, dry_run=False,
            )
        finally:
            await db.close()

    # Step 1: preview (dry-run).
    try:
        preview = asyncio.run(_preview())
    except MigrationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(f"Project ID:   {preview.project_id}")
    print(f"Mode:         {'dry-run (no writes)' if args.dry_run else 'preview then write'}")
    print()
    print(f"{'Table':<32} {'Legacy rows':>12}")
    print("-" * 46)
    for report in preview.reports:
        print(f"{report.table:<32} {report.rows_updated:>12}")
    print("-" * 46)
    print(f"{'TOTAL':<32} {preview.total_rows:>12}")
    print()

    if preview.total_rows == 0:
        print("No legacy rows to backfill — database is already at A-5-1b parity.")
        return 0

    if args.dry_run:
        print(f"Dry run complete — {preview.total_rows} rows would be updated.")
        return 0

    # Step 2: confirm (unless --yes).
    if not args.yes:
        if sys.stdin.isatty():
            answer = input(
                f"Proceed with backfilling {preview.total_rows} rows? [y/N] "
            ).strip().lower()
            if answer not in {"y", "yes"}:
                print("Aborted — no rows written.")
                return 0
        else:
            print(
                "Refusing to write in non-interactive mode without --yes. "
                "Re-run with --yes to proceed.",
                file=sys.stderr,
            )
            return 2

    # Step 3: write.
    try:
        result = asyncio.run(_write())
    except MigrationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print()
    print(f"{'Table':<32} {'Updated':>10}")
    print("-" * 44)
    for report in result.reports:
        print(f"{report.table:<32} {report.rows_updated:>10}")
    print("-" * 44)
    print(f"{'TOTAL':<32} {result.total_rows:>10}")
    print()
    print(f"Backfill complete — {result.total_rows} rows stamped with project_id={result.project_id}.")
    return 0


def _project_root() -> Path:
    """Return the repository root from the installed source layout."""
    return Path(__file__).resolve().parents[3]


def handle_config_command(argv: list[str]) -> int:
    """Handle `khaos config` management commands."""
    if not argv:
        config = masked_config(load_config(strict_env=False))
        print(yaml.safe_dump(config, allow_unicode=True, sort_keys=False), end="")
        return 0

    command = argv[0]
    if command == "setup":
        run_setup_wizard()
        return 0
    if command == "set":
        if len(argv) != 3:
            print("usage: khaos config set <key> <value>", file=sys.stderr)
            return 2
        target = set_user_config_value(argv[1], argv[2])
        print(f"✓ 已保存到 {target}")
        return 0
    if command == "reset":
        removed = reset_user_config()
        if removed:
            print(f"✓ 已删除 {USER_CONFIG_PATH}")
        else:
            print(f"{USER_CONFIG_PATH} 不存在")
        return 0

    print("usage: khaos config [setup|set <key> <value>|reset]", file=sys.stderr)
    return 2


def _confirm_from_args(args: argparse.Namespace):
    def confirm(request: dict) -> dict:
        if args.yes:
            return {"approved": True, "remember": bool(args.remember)}
        if sys.stdin.isatty():
            answer = input(
                f"Allow {request['name']} on {request['target']}? [y/N] "
            ).strip().lower()
            return {"approved": answer in {"y", "yes"}, "remember": bool(args.remember)}
        return {"approved": False}

    return confirm


def _interactive_confirm(args: argparse.Namespace):
    def confirm(request: dict) -> dict:
        if args.yes:
            return {"approved": True, "remember": bool(args.remember)}
        answer = input(
            f"Allow {request['name']} on {request['target']}? [y/N] "
        ).strip().lower()
        remember = bool(args.remember)
        if answer in {"yr", "yes remember"}:
            remember = True
        return {"approved": answer in {"y", "yes", "yr", "yes remember"}, "remember": remember}

    return confirm


def _tui_available() -> bool:
    """True when the optional textual TUI dependency is importable."""
    try:
        import textual  # noqa: F401

        return True
    except ImportError:
        return False


def run_interactive(args: argparse.Namespace) -> None:
    """Launch the full-screen TUI when available, otherwise the line REPL."""
    if not getattr(args, "no_tui", False) and _tui_available():
        from khaos.tui.app import run_tui

        resolved_db = open_state_db_safely(
            resolve_state_db_path(Path.cwd(), args.db)
        )
        run_tui(
            db_path=str(resolved_db),
            project_root=Path.cwd(),
            mode=args.mode or "",
        )
        return
    raise SystemExit(asyncio.run(run_repl(args)))


def main() -> None:
    """CLI process entrypoint.

    Resolution order:
      1. Product subcommands: start/chat/test/config/version.
      2. Legacy flags such as ``--message`` for scriptable SSE output.
    """
    argv = sys.argv[1:]
    command_names = {"start", "chat", "test", "config", "version", "migrate"}
    if not argv:
        parser = build_command_parser()
        parser.print_help()
        return
    if argv[0] in command_names:
        if argv[0] == "config" and len(argv) > 1 and argv[1] in {"setup", "set", "reset"}:
            raise SystemExit(handle_config_command(argv[1:]))
        parser = build_command_parser()
        args = parser.parse_args(argv)
        if args.command == "start":
            cmd_start(args)
        elif args.command == "chat":
            cmd_chat(args)
        elif args.command == "test":
            cmd_test(args)
        elif args.command == "config":
            cmd_config(args)
        elif args.command == "version":
            cmd_version()
        elif args.command == "migrate":
            raise SystemExit(cmd_migrate(args))
        return

    parser = build_parser()
    args = parser.parse_args(argv)
    if args.message:
        raise SystemExit(asyncio.run(run_once(args)))
    if not sys.stdin.isatty():
        args.message = sys.stdin.read().strip()
        if args.message:
            raise SystemExit(asyncio.run(run_once(args)))
    run_interactive(args)


if __name__ == "__main__":
    main()
