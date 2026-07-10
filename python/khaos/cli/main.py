"""Command line interface for the P0-A Khaos loop."""

from __future__ import annotations

import argparse
import asyncio
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
from khaos.memory import MemoryBudget, MemoryManager, MemoryStore
from khaos.modes import ModeManager
from khaos.permissions import PermissionEngine
from khaos.routing.router import create_default_router
from khaos.skills import SkillManager
from khaos.tools import create_runtime_registry
from khaos.tools.scheduler import ToolScheduler


async def run_once(args: argparse.Namespace) -> int:
    """Run one user message and print SSE frames to stdout."""
    db = Database(args.db)
    await db.connect()
    await db.run_migrations()

    mode_manager = ModeManager(db, project_root=Path.cwd())
    await mode_manager.load()
    if args.mode:
        await mode_manager.switch(ModeManager.parse(args.mode))

    session_id = args.session_id or str(uuid.uuid4())
    await db.create_session(session_id, mode_manager.current_mode.value)

    from khaos.runtime import RuntimeConfig, build_runtime
    runtime = None
    try:
        runtime = await build_runtime(RuntimeConfig(db=db, mode_manager=mode_manager, confirm_callback=_confirm_from_args(args)))
        print(f"session_id: {session_id}", flush=True)
        async for message in runtime.loop.run(args.message, session_id):
            print(encode_sse(message), end="", flush=True)
    finally:
        if runtime is not None:
            await runtime.aclose()
        await db.close()
    return 0


async def run_repl(args: argparse.Namespace) -> int:
    """Run a tiny interactive shell for manual P0-A validation."""
    db = Database(args.db)
    await db.connect()
    await db.run_migrations()

    mode_manager = ModeManager(db, project_root=Path.cwd())
    await mode_manager.load()
    session_id = args.session_id or str(uuid.uuid4())
    await db.create_session(session_id, mode_manager.current_mode.value)
    from khaos.runtime import RuntimeConfig, build_runtime
    runtime = None
    try:
        runtime = await build_runtime(RuntimeConfig(db=db, mode_manager=mode_manager, confirm_callback=_interactive_confirm(args)))
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
                await db.create_session(session_id, target.value)
                print(f"mode: {target.value}")
                continue
            if not user_input:
                continue
            async for message in loop.run(user_input, session_id):
                print(encode_sse(message), end="", flush=True)
    finally:
        if runtime is not None:
            await runtime.aclose()
        await db.close()
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Create the CLI argument parser."""
    parser = argparse.ArgumentParser(prog="khaos")
    parser.add_argument("--db", default="khaos.db", help="SQLite database path")
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
    start_parser.add_argument("--host", default="127.0.0.1")
    start_parser.add_argument("--port", type=int, default=50051)
    start_parser.add_argument("--db", default="khaos.db")
    start_parser.add_argument("--config", default="config.yaml")
    start_parser.add_argument("--gateway", action="store_true", help="Also start Go gateway")

    chat_parser = subparsers.add_parser("chat", help="Interactive chat session")
    chat_parser.add_argument("--mode", default="office", choices=["office", "coding"])
    chat_parser.add_argument("--db", default="khaos.db")
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
    return parser


def cmd_start(args: argparse.Namespace) -> None:
    """Start the Python JSON-line agent server."""
    try:
        import uvloop

        uvloop.install()
    except ImportError:
        pass

    gateway_process: subprocess.Popen | None = None
    if args.gateway:
        gateway_cmd = ["go", "run", "./go/cmd/gateway"]
        gateway_process = subprocess.Popen(gateway_cmd, cwd=str(_project_root()))
        print("Started Go gateway with: go run ./go/cmd/gateway")

    print(f"Starting Khaos agent on {args.host}:{args.port}")
    print(f"Database: {args.db}")
    print(f"Config: {args.config}")
    from khaos.grpc_server import serve_json_lines

    try:
        asyncio.run(
            serve_json_lines(
                args.host,
                args.port,
                args.db,
                project_root=Path.cwd(),
                config_path=Path(args.config),
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
            yaml.safe_dump({"model": "default", "port": 50051}, sort_keys=False),
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

        run_tui(db_path=args.db, project_root=Path.cwd(), mode=args.mode or "")
        return
    raise SystemExit(asyncio.run(run_repl(args)))


def main() -> None:
    """CLI process entrypoint.

    Resolution order:
      1. Product subcommands: start/chat/test/config/version.
      2. Legacy flags such as ``--message`` for scriptable SSE output.
    """
    argv = sys.argv[1:]
    command_names = {"start", "chat", "test", "config", "version"}
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
