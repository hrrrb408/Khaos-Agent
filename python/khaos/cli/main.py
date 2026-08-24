"""Command line interface for the P0-A Khaos loop."""

# KHAOS-PRIVILEGED-SPAWN owner=CliGatewayProcess threat-model=user-authorized-local-gateway boundary=cli-runtime

from __future__ import annotations

import argparse
import asyncio
import json
import os
import secrets
import subprocess
import sys
import uuid
from dataclasses import asdict, is_dataclass
from enum import Enum
from pathlib import Path

import yaml

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
    resolve_state_db_path,
)
from khaos.db.state_root import (
    project_id as compute_project_id,
)
from khaos.modes import ModeManager
from khaos.runtime.context import local_principal_id


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
        principal_id=local_principal_id(),
        project_id=compute_project_id(Path.cwd()),
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
        principal_id=local_principal_id(),
        project_id=cli_project_id,
    )

    from khaos.runtime import (
        ProductionRuntimeConfig,
        build_production_runtime,
        close_runtime_or_register,
    )
    runtime = None
    try:
        runtime = await build_production_runtime(ProductionRuntimeConfig(db=db, mode_manager=mode_manager, confirm_callback=_confirm_from_args(args), principal_id=local_principal_id(), source_transport="cli", foreground_session=True, project_id=cli_project_id))
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
        principal_id=local_principal_id(),
        project_id=compute_project_id(Path.cwd()),
    )
    await mode_manager.load()
    session_id = args.session_id or str(uuid.uuid4())
    # M4 batch 3.1.16A-5-1b: see run_once for the rationale.
    cli_project_id = compute_project_id(Path.cwd())
    await db.create_session(
        session_id, mode_manager.current_mode.value,
        principal_id=local_principal_id(),
        project_id=cli_project_id,
    )
    from khaos.runtime import (
        ProductionRuntimeConfig,
        build_production_runtime,
        close_runtime_or_register,
    )
    runtime = None
    try:
        runtime = await build_production_runtime(ProductionRuntimeConfig(db=db, mode_manager=mode_manager, confirm_callback=_interactive_confirm(args), principal_id=local_principal_id(), source_transport="cli", foreground_session=True, project_id=cli_project_id))
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
                    principal_id=local_principal_id(),
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
        "--socket", default=f"/tmp/khaos-{local_principal_id().removeprefix('local-uid:')}/agent.sock"
    )
    start_parser.add_argument(
        "--db",
        default=None,
        help="SQLite database path (default: ~/.khaos/state/<project-id>/state.db)",
    )
    start_parser.add_argument(
        "--gateway-uid",
        type=int,
        default=None,
        help="Expected UID of the Gateway peer (container deployments set this explicitly)",
    )
    start_parser.add_argument(
        "--gateway-gid",
        type=int,
        default=None,
        help=(
            "Expected GID of the Gateway peer and setgid socket parent "
            "(container deployments set this explicitly)"
        ),
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

    memory_parser = subparsers.add_parser(
        "memory",
        help="Inspect and maintain the canonical Memory V2 system",
    )
    memory_parser.add_argument("--project-root", default=None)
    memory_parser.add_argument("--db", default=None)
    memory_parser.add_argument("--config", default=None)
    memory_parser.add_argument("--profile", default=None)
    memory_parser.add_argument("--mode", choices=["office", "coding"], default=None)
    memory_parser.add_argument("--json", action="store_true", dest="as_json")
    memory_parser.add_argument("--limit", type=int, default=10_000)
    memory_sub = memory_parser.add_subparsers(dest="memory_command")
    memory_sub.add_parser("status", help="Show profile, provider, and index health")
    profile_parser = memory_sub.add_parser("profile", help="Show validated memory profiles")
    profile_parser.add_argument(
        "profile_command", nargs="?", choices=["current", "list"], default="current"
    )
    providers_parser = memory_sub.add_parser("providers", help="List registered providers")
    providers_parser.add_argument(
        "providers_command", nargs="?", choices=["list"], default="list"
    )
    provider_parser = memory_sub.add_parser("provider", help="Manage the active provider")
    provider_parser.add_argument("provider_command", choices=["set", "list"])
    provider_parser.add_argument("provider_id", nargs="?")
    search_parser = memory_sub.add_parser("search", help="Search admitted memory evidence")
    search_parser.add_argument("query")
    show_parser = memory_sub.add_parser("show", help="Inspect one admitted memory")
    show_parser.add_argument("memory_id")
    source_parser = memory_sub.add_parser("source", help="Inspect memory provenance")
    source_parser.add_argument("memory_id")
    evidence_parser = memory_sub.add_parser("evidence", help="Inspect memory evidence")
    evidence_parser.add_argument("memory_id")
    conflicts_parser = memory_sub.add_parser("conflicts", help="List unresolved conflicts")
    conflicts_parser.add_argument("query")
    forget_parser = memory_sub.add_parser("forget", help="Revoke owned memory objects")
    forget_parser.add_argument("memory_ids", nargs="+")
    forget_parser.add_argument("--mode", dest="forget_mode", choices=["soft", "hard", "compliance"], default="soft")
    forget_parser.add_argument("--namespace", choices=["private", "session", "project", "shared"])
    forget_parser.add_argument("--scope")
    memory_sub.add_parser("rebuild", help="Replay the event ledger and rebuild indexes")
    memory_sub.add_parser("verify", help="Verify rebuildable indexes")
    memory_sub.add_parser("maintain", help="Run complete bounded maintenance")
    memory_sub.add_parser("gc", help="Run bounded conservative memory compaction")
    benchmark_parser = memory_sub.add_parser("benchmark", help="Run a live retrieval benchmark")
    benchmark_parser.add_argument("query")
    benchmark_parser.add_argument("--expected", action="append", default=[])
    benchmark_parser.add_argument("--forbidden", action="append", default=[])
    benchmark_parser.add_argument("--repetitions", type=int, default=3)
    memory_sub.add_parser("conformance", help="Run provider conformance checks")
    export_parser = memory_sub.add_parser("export", help="Export a scope-bound memory package")
    export_parser.add_argument("path", type=Path)
    import_parser = memory_sub.add_parser("import", help="Import a scope-bound memory package")
    import_parser.add_argument("path", type=Path)
    import_parser.add_argument("--no-rebuild", action="store_true")

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
        os.write(write_fd, f"{gateway_capability}\n".encode())
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
                gateway_uid=args.gateway_uid,
                gateway_gid=args.gateway_gid,
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
        result = subprocess.run(
            cmd, cwd=str(project_root), capture_output=True, text=True, check=False,
        )
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
            check=False,
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


async def _open_memory_cli(args: argparse.Namespace) -> dict[str, object]:
    """Open one fully composed Memory V2 context for CLI operations."""

    from khaos.audit import (
        AuditLogger,
        resolve_safe_audit_anchor_path,
        resolve_safe_audit_log_path,
    )
    from khaos.memory import MemoryBudget, RuntimeMemoryContext
    from khaos.runtime import build_memory_host
    from khaos.security.effective_policy import load_effective_policy

    root = Path(args.project_root or Path.cwd()).expanduser().resolve()
    db_path = open_state_db_safely(resolve_state_db_path(root, args.db))
    db = Database(db_path)
    await db.connect()
    audit_logger = None
    host = None
    try:
        await db.run_migrations()
        principal_id = local_principal_id()
        project = compute_project_id(root)
        effective_policy = load_effective_policy(root)
        if effective_policy.audit_enabled:
            audit_logger = AuditLogger(
                db,
                log_path=resolve_safe_audit_log_path(effective_policy.audit_log_path),
                anchor_path=(
                    resolve_safe_audit_anchor_path(project)
                    if os.environ.get("KHAOS_DEV_MODE") != "1"
                    else None
                ),
                principal_id=principal_id,
                policy_digest=effective_policy.digest,
                project_id=project,
            )
            await audit_logger.verify_anchor()
        host = await build_memory_host(
            db=db,
            project_root=root,
            config_path=Path(args.config or root / "config.yaml"),
            mode=args.mode or "office",
            profile_id=args.profile,
            principal_id=principal_id,
            project_id=project,
            audit_logger=audit_logger,
            effective_policy=effective_policy,
        )
        profile = host.profile
        if profile is None:
            raise RuntimeError("canonical memory host has no active profile")
        mode = args.mode or ("coding" if profile.profile_id == "coding" else "office")
        runtime = RuntimeMemoryContext(
            principal_id=principal_id,
            project_id=project,
            session_id=None,
            task_id=None,
            workspace_id=None,
            repo_id=None,
            commit_sha=None,
            branch=None,
            mode=mode,
            environment_fingerprint="cli:memory",
            environment={"source_transport": "cli"},
        )
        broker = host.broker
        return {
            "db": db,
            "root": root,
            "profile": profile,
            "profiles": host.profile_registry,
            "profile_store": host.profile_store,
            "registry": host.provider_manager.registry,
            "provider_manager": host.provider_manager,
            "broker": broker,
            "transfer": host.transfer_service,
            "runtime": runtime,
            "budget": profile.budget(MemoryBudget()),
            "codegraph": host.codegraph,
            "host": host,
            "audit_logger": audit_logger,
        }
    except BaseException:
        if host is not None:
            await host.close()
        close_audit = getattr(audit_logger, "close", None)
        if callable(close_audit):
            close_audit()
        await db.close()
        raise


def _memory_print(value: object, *, as_json: bool) -> None:
    if as_json:
        print(json.dumps(value, ensure_ascii=False, sort_keys=True, default=_json_default))
    elif isinstance(value, str):
        print(value)
    else:
        print(json.dumps(value, ensure_ascii=False, indent=2, default=_json_default))


def _json_default(value: object) -> object:
    """Serialize Memory V2 dataclasses/enums without leaking object reprs."""

    if is_dataclass(value):
        return asdict(value)
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, (set, frozenset, tuple)):
        return list(value)
    return str(value)


def cmd_memory(args: argparse.Namespace) -> int:
    """Run one bounded Memory V2 operation through the Broker."""

    async def _run() -> int:
        context = await _open_memory_cli(args)
        try:
            action = args.memory_command or "status"
            broker = context["broker"]
            runtime = context["runtime"]
            profile = context["profile"]
            manager = context["provider_manager"]
            if action == "status":
                health = await broker.health()
                verifier = getattr(broker.provider, "verify_indexes", None)
                indexes = await verifier() if callable(verifier) else {}
                _memory_print(
                    {
                        "profile": profile.to_mapping(),
                        "provider": broker.provider.provider_id,
                        "health": health,
                        "indexes": indexes,
                    },
                    as_json=args.as_json,
                )
                return 0
            if action == "profile":
                if args.profile_command == "list":
                    _memory_print(
                        [item.to_mapping() for item in context["profiles"].list()],
                        as_json=args.as_json,
                    )
                else:
                    _memory_print(profile, as_json=args.as_json)
                return 0
            if action == "providers" or (
                action == "provider"
                and getattr(args, "provider_command", "") == "list"
            ):
                statuses = await manager.statuses()
                _memory_print(
                    [
                        {
                            "provider_id": item.provider_id,
                            "state": item.state,
                            "active": item.active,
                            "healthy": item.healthy,
                            "detail": item.detail,
                            "capabilities": item.capabilities,
                        }
                        for item in statuses
                    ],
                    as_json=args.as_json,
                )
                return 0
            if action == "provider":
                if not args.provider_id:
                    raise ValueError("usage: khaos memory provider set <provider-id>")
                status = await manager.set_provider(args.provider_id, runtime)
                _memory_print(status, as_json=args.as_json)
                return 0
            if action == "search":
                resolution = await broker.search(
                    args.query,
                    runtime,
                    context["budget"],
                )
                _memory_print(resolution, as_json=args.as_json)
                return 0
            if action == "show":
                hit = await broker.get(args.memory_id, runtime, include_historical=True)
                _memory_print(hit, as_json=args.as_json)
                return 0 if hit is not None else 1
            if action == "source":
                source = await broker.source(runtime, args.memory_id)
                _memory_print(source, as_json=args.as_json)
                return 0 if source is not None else 1
            if action == "evidence":
                evidence = await broker.evidence(runtime, args.memory_id)
                _memory_print(evidence, as_json=args.as_json)
                return 0
            if action == "conflicts":
                conflicts = await broker.conflicts(
                    args.query,
                    runtime,
                    context["budget"],
                )
                _memory_print(conflicts, as_json=args.as_json)
                return 0
            if action == "forget":
                from khaos.memory import MemoryForgetRequest

                request = MemoryForgetRequest(
                    tuple(args.memory_ids),
                    runtime,
                    mode=args.forget_mode,
                    namespace=args.namespace,
                    scope=args.scope,
                )
                result = await broker.forget(request)
                _memory_print(result, as_json=args.as_json)
                return 0
            if action == "rebuild":
                from khaos.memory.maintenance import MemoryMaintenanceService

                report = await MemoryMaintenanceService(broker).rebuild(
                    runtime,
                    limit=args.limit,
                )
                _memory_print(report, as_json=args.as_json)
                return 0
            if action == "verify":
                from khaos.memory.maintenance import MemoryMaintenanceService

                report = await MemoryMaintenanceService(broker).verify(runtime)
                _memory_print(report, as_json=args.as_json)
                return 0 if report.consistent else 1
            if action == "maintain":
                from khaos.memory.maintenance import MemoryMaintenanceService

                report = await MemoryMaintenanceService(broker).maintain(
                    runtime,
                    limit=min(args.limit, 10_000),
                )
                _memory_print(report, as_json=args.as_json)
                return 0 if report.consistency.consistent else 1
            if action == "gc":
                removed = await broker.compact(runtime, limit=min(args.limit, 10_000))
                _memory_print({"removed": removed}, as_json=args.as_json)
                return 0
            if action == "export":
                result = await context["transfer"].export(
                    runtime,
                    args.path,
                    limit=min(args.limit, 200_000),
                )
                _memory_print(result, as_json=args.as_json)
                return 0
            if action == "import":
                result = await context["transfer"].import_package(
                    runtime,
                    args.path,
                    rebuild=not args.no_rebuild,
                )
                _memory_print(result, as_json=args.as_json)
                return 0
            if action == "benchmark":
                from khaos.memory.benchmarks import (
                    BenchmarkCase,
                    MemoryBenchmarkHarness,
                )

                report = await MemoryBenchmarkHarness(broker).run(
                    [
                        BenchmarkCase(
                            "cli",
                            args.query,
                            tuple(args.expected),
                            tuple(args.forbidden),
                        )
                    ],
                    runtime,
                    repetitions=args.repetitions,
                )
                _memory_print(report, as_json=args.as_json)
                return 0 if report.status == "COMPLETED" and report.security_violations == 0 else 1
            if action == "conformance":
                from khaos.memory.conformance import run_provider_conformance

                report = await run_provider_conformance(broker, runtime)
                _memory_print(report, as_json=args.as_json)
                return 0 if report.passed else 1
            raise ValueError(f"unknown memory command: {action}")
        finally:
            await context["host"].close()
            audit_logger = context.get("audit_logger")
            close_audit = getattr(audit_logger, "close", None)
            if callable(close_audit):
                close_audit()
            await context["db"].close()

    try:
        return asyncio.run(_run())
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"memory command failed: {exc}", file=sys.stderr)
        return 2


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
    command_names = {"start", "chat", "test", "config", "version", "migrate", "memory"}
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
        elif args.command == "memory":
            raise SystemExit(cmd_memory(args))
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
