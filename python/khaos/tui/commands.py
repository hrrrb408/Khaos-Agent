"""Slash-command parsing and dispatch for the TUI.

Kept as pure functions over a small context object so the dispatch logic is
unit-testable without a running Textual app. The TUI widgets call into
``handle_command`` and render the returned :class:`CommandResult`.
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass, field
from typing import Any, Callable, Awaitable

from khaos.skills import SkillManager


@dataclass
class TuiContext:
    """Runtime handles the command dispatcher may touch.

    All fields are optional so tests can build a minimal context. ``loop`` is
    the AgentLoop; ``mode_manager`` switches modes; ``memory_store`` lists
    memories; ``registry`` lists tools; ``router``/``db`` support model/session
    queries.
    """

    loop: Any = None
    mode_manager: Any = None
    memory_store: Any = None
    registry: Any = None
    router: Any = None
    db: Any = None
    skill_manager: SkillManager | None = None
    session_id: str = ""
    # Callbacks the app wires up for state-changing commands.
    on_clear: Callable[[], None] | None = None
    on_quit: Callable[[], None] | None = None
    on_new_session: Callable[[str], None] | None = None


@dataclass
class CommandResult:
    """Outcome of a slash command."""

    handled: bool
    message: str = ""
    # When True the app should exit after rendering the message.
    should_quit: bool = False
    # When True the chat log should be cleared.
    should_clear: bool = False
    # Optional structured payload for richer rendering (e.g. tool tables).
    payload: Any = None

    def __str__(self) -> str:
        return self.message


HELP_TEXT = """\
Khaos TUI — slash commands:

  /mode office|coding       Switch interaction mode
  /skills list              List skills
  /skills load <name>       Force-load a skill into the prompt
  /skills unload <name>     Remove a skill from the forced set
  /memory list              List memories (all scopes)
  /memory search <query>    Full-text search memories
  /tools [mode]             List available tools (optionally per mode)
  /model <name>             Show or set the active model (set is advisory)
  /session new              Start a new session
  /session list             List known sessions
  /help                     Show this help
  /clear                    Clear the chat panel
  /quit                     Exit Khaos

Type a message and press Enter to send. Shift+Enter inserts a newline.
"""


def is_command(line: str) -> bool:
    """True when ``line`` starts with a slash command."""
    return line.lstrip().startswith("/")


async def handle_command(line: str, ctx: TuiContext) -> CommandResult:
    """Parse and execute one ``/`` command line.

    Returns ``handled=False`` for input that is not a recognized command so the
    caller can treat it as a normal chat message.
    """
    stripped = line.strip()
    if not is_command(stripped):
        return CommandResult(handled=False)
    try:
        parts = shlex.split(stripped)
    except ValueError:
        parts = stripped.split()
    if not parts:
        return CommandResult(handled=False)
    cmd = parts[0].lower()
    args = parts[1:]

    if cmd in {"/quit", "/exit"}:
        if ctx.on_quit:
            ctx.on_quit()
        return CommandResult(handled=True, message="bye.", should_quit=True)
    if cmd == "/help":
        return CommandResult(handled=True, message=HELP_TEXT)
    if cmd == "/clear":
        if ctx.on_clear:
            ctx.on_clear()
        return CommandResult(handled=True, message="", should_clear=True)
    if cmd == "/mode":
        return await _cmd_mode(args, ctx)
    if cmd == "/skills":
        return _cmd_skills(args, ctx)
    if cmd == "/memory":
        return await _cmd_memory(args, ctx)
    if cmd == "/tools":
        return _cmd_tools(args, ctx)
    if cmd == "/model":
        return _cmd_model(args, ctx)
    if cmd == "/session":
        return _cmd_session(args, ctx)

    return CommandResult(handled=True, message=f"unknown command: {cmd}\n\n{HELP_TEXT}")


async def _cmd_mode(args: list[str], ctx: TuiContext) -> CommandResult:
    if not args:
        mode = _current_mode_value(ctx)
        return CommandResult(handled=True, message=f"current mode: {mode}")
    if ctx.mode_manager is None:
        return CommandResult(handled=True, message="mode manager not configured")
    try:
        from khaos.modes import ModeManager

        target = ModeManager.parse(args[0])
    except ValueError as exc:
        return CommandResult(handled=True, message=f"invalid mode: {exc}")
    await ctx.mode_manager.switch(target)
    if ctx.db and ctx.session_id:
        await ctx.db.create_session(ctx.session_id, target.value)
    return CommandResult(handled=True, message=f"mode: {target.value}")


def _cmd_skills(args: list[str], ctx: TuiContext) -> CommandResult:
    if ctx.skill_manager is None:
        return CommandResult(handled=True, message="skills not configured")
    from khaos.cli.skills_commands import handle_skills_command

    # Delegate to the existing pure-function skills command handler.
    raw = "/skills " + " ".join(args) if args else "/skills"
    result = handle_skills_command(raw, ctx.skill_manager)
    return CommandResult(handled=True, message=result.message)


async def _cmd_memory(args: list[str], ctx: TuiContext) -> CommandResult:
    if ctx.memory_store is None:
        return CommandResult(handled=True, message="memory store not configured")
    if not args or args[0] == "list":
        memories = await ctx.memory_store.list_all()
        if not memories:
            return CommandResult(handled=True, message="no memories stored.")
        lines = ["memories:"]
        for memory in memories:
            lines.append(
                f"  ({memory.scope.value}) {memory.key}: {memory.value}"
            )
        return CommandResult(handled=True, message="\n".join(lines))
    if args[0] == "search":
        query = " ".join(args[1:])
        if not query:
            return CommandResult(handled=True, message="usage: /memory search <query>")
        results = await ctx.memory_store.search(query)
        if not results:
            return CommandResult(handled=True, message=f"no memories match {query!r}.")
        lines = [f"search results for {query!r}:"]
        for memory in results:
            lines.append(f"  ({memory.scope.value}) {memory.key}: {memory.value}")
        return CommandResult(handled=True, message="\n".join(lines))
    return CommandResult(handled=True, message="usage: /memory [list|search <query>]")


def _cmd_tools(args: list[str], ctx: TuiContext) -> CommandResult:
    if ctx.registry is None:
        return CommandResult(handled=True, message="tool registry not configured")
    mode = args[0] if args else _current_mode_value(ctx)
    try:
        tools = ctx.registry.list_by_mode(mode)
    except Exception:
        tools = ctx.registry.list_by_mode("all")
    if not tools:
        return CommandResult(handled=True, message=f"no tools for mode {mode!r}.")
    lines = [f"tools ({mode}):"]
    for tool in tools:
        lines.append(f"  {tool.name:<16} [{tool.permission_level}] {tool.description}")
    return CommandResult(handled=True, message="\n".join(lines))


def _cmd_model(args: list[str], ctx: TuiContext) -> CommandResult:
    if ctx.router is None:
        return CommandResult(handled=True, message="router not configured")
    if not args:
        return CommandResult(
            handled=True,
            message="model selection is advisory; configure via config.yaml. "
            "registered models: "
            + ", ".join(ctx.router.provider_manager._models.keys()),
        )
    return CommandResult(
        handled=True,
        message=(
            f"model switching is config-driven; add {args[0]!r} to config.yaml "
            "under models.router or models.default_model."
        ),
    )


def _cmd_session(args: list[str], ctx: TuiContext) -> CommandResult:
    if not args:
        return CommandResult(handled=True, message="usage: /session [new|list]")
    if args[0] == "new":
        if ctx.on_new_session:
            new_id = ctx.on_new_session("")
            return CommandResult(handled=True, message=f"new session: {new_id}")
        return CommandResult(handled=True, message="session manager not configured")
    if args[0] == "list":
        if ctx.db is None:
            return CommandResult(handled=True, message="database not configured")
        # Sessions are listed synchronously through whatever the db exposes.
        return CommandResult(
            handled=True,
            message="session listing requires a running database; "
            f"current session: {ctx.session_id or '(none)'}",
        )
    return CommandResult(handled=True, message="usage: /session [new|list]")


def _current_mode_value(ctx: TuiContext) -> str:
    if ctx.mode_manager is None:
        return "office"
    mode = ctx.mode_manager.current_mode
    return getattr(mode, "value", str(mode))


__all__ = [
    "TuiContext",
    "CommandResult",
    "HELP_TEXT",
    "handle_command",
    "is_command",
]
