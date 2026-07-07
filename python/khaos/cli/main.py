"""Command line interface for the P0-A Khaos loop."""

from __future__ import annotations

import argparse
import asyncio
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
    check_needs_setup,
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

    router = create_default_router()
    permission_engine = PermissionEngine(db)
    await permission_engine.load_rules()
    memory_store = MemoryStore(db)
    memory_manager = MemoryManager(
        memory_store,
        budget=MemoryBudget(),
        mode_getter=lambda: mode_manager.current_mode,
        intent_getter=lambda: getattr(mode_manager, "_intent_buffer", ""),
    )
    scheduler = ToolScheduler(create_runtime_registry(), permission_engine)
    compressor = ContextCompressor(router, memory_manager=memory_manager)
    error_handler = ErrorHandler(db=db, router=router, compressor=compressor)
    loop = AgentLoop(
        AgentConfig(),
        mode_manager,
        router,
        db,
        tool_scheduler=scheduler,
        confirm_callback=_confirm_from_args(args),
        context_compressor=compressor,
        memory_manager=memory_manager,
        error_handler=error_handler,
    )

    print(f"session_id: {session_id}", flush=True)
    async for message in loop.run(args.message, session_id):
        print(encode_sse(message), end="", flush=True)

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
    router = create_default_router()
    permission_engine = PermissionEngine(db)
    await permission_engine.load_rules()
    memory_store = MemoryStore(db)
    memory_manager = MemoryManager(
        memory_store,
        budget=MemoryBudget(),
        mode_getter=lambda: mode_manager.current_mode,
        intent_getter=lambda: getattr(mode_manager, "_intent_buffer", ""),
    )
    scheduler = ToolScheduler(create_runtime_registry(), permission_engine)
    compressor = ContextCompressor(router, memory_manager=memory_manager)
    error_handler = ErrorHandler(db=db, router=router, compressor=compressor)
    skill_manager = SkillManager()
    skills_dir = Path.cwd() / "skills"
    if skills_dir.is_dir():
        loaded = skill_manager.load_from_dir(skills_dir)
        if loaded:
            print(f"loaded {len(loaded)} skill(s) from {skills_dir}")
    loop = AgentLoop(
        AgentConfig(),
        mode_manager,
        router,
        db,
        tool_scheduler=scheduler,
        confirm_callback=_interactive_confirm(args),
        context_compressor=compressor,
        memory_manager=memory_manager,
        error_handler=error_handler,
        skill_manager=skill_manager if len(skill_manager.registry) > 0 else None,
    )

    print(f"session_id: {session_id}")
    print(f"mode: {mode_manager.current_mode.value}")
    try:
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


def main() -> None:
    """CLI process entrypoint.

    Resolution order:
      1. ``--message`` or piped stdin -> single-shot SSE output (scriptable).
      2. Interactive TTY, no ``--no-tui``, and textual installed -> full TUI.
      3. Otherwise -> the line-oriented REPL (``run_repl``).
    """
    argv = sys.argv[1:]
    if argv and argv[0] == "config":
        raise SystemExit(handle_config_command(argv[1:]))
    if argv and argv[0] == "chat":
        argv = argv[1:]

    parser = build_parser()
    args = parser.parse_args(argv)
    if args.message:
        raise SystemExit(asyncio.run(run_once(args)))
    if not sys.stdin.isatty():
        args.message = sys.stdin.read().strip()
        if args.message:
            raise SystemExit(asyncio.run(run_once(args)))
    if check_needs_setup():
        run_setup_wizard()
        return
    if not args.no_tui and _tui_available():
        from khaos.tui.app import run_tui

        run_tui(db_path=args.db, project_root=Path.cwd(), mode=args.mode or "")
        return
    raise SystemExit(asyncio.run(run_repl(args)))


if __name__ == "__main__":
    main()
