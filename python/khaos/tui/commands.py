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
    # Optional shared coding-task tracker for the /tasks and /task commands.
    task_manager: Any = None
    # Optional cron engine for the /cron command.
    cron_engine: Any = None
    # Optional session history search for the /history command.
    session_search: Any = None
    channel_registry: Any = None
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
  /tasks                    List active coding tasks (all tasks with -a)
  /task <id>                Show details for one coding task
  /cron list                List scheduled tasks
  /cron create <n> <sched> <prompt>  Create a scheduled task
  /cron pause <id>          Pause a scheduled task
  /cron resume <id>         Resume a scheduled task
  /cron remove <id>         Remove a scheduled task
  /history search <query>   Search past sessions
  /history browse          List recent sessions
  /history read <id>       Read a full session
  /channels                List registered channels
  /channels enable <id>    Enable a channel
  /channels disable <id>   Disable a channel
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
    if cmd == "/tasks":
        return await _cmd_tasks(args, ctx)
    if cmd == "/task":
        return await _cmd_task(args, ctx)
    if cmd == "/cron":
        return await _cmd_cron(args, ctx)
    if cmd == "/history":
        return await _cmd_history(args, ctx)
    if cmd == "/channels":
        return _cmd_channels(args, ctx)
    if cmd == "/session":
        return _cmd_session(args, ctx)

    return CommandResult(handled=True, message=f"unknown command: {cmd}\n\n{HELP_TEXT}")


def _cmd_channels(args: list[str], ctx: TuiContext) -> CommandResult:
    if ctx.channel_registry is None:
        return CommandResult(handled=True, message="channel registry not configured")
    if not args or args[0] == "list":
        channels = ctx.channel_registry.list_all()
        if not channels:
            return CommandResult(handled=True, message="no channels registered.")
        lines = ["channels:"]
        for channel in channels:
            lines.append(f"  {channel.id} [{channel.channel_type.value}] {channel.health.status.value}")
        return CommandResult(handled=True, message="\n".join(lines))
    if len(args) == 2 and args[0] in {"enable", "disable"}:
        ok = getattr(ctx.channel_registry, args[0])(args[1])
        return CommandResult(handled=True, message=f"{args[1]}: {args[0]}d" if ok else f"channel not found: {args[1]}")
    return CommandResult(handled=True, message="usage: /channels [list|enable <id>|disable <id>]")


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


async def _cmd_history(args: list[str], ctx: TuiContext) -> CommandResult:
    if ctx.session_search is None:
        return CommandResult(handled=True, message="session search not configured")
    if not args:
        return CommandResult(
            handled=True, message="usage: /history [search <query>|browse|read <id>]"
        )
    sub = args[0]
    if sub == "search":
        query = " ".join(args[1:])
        if not query:
            return CommandResult(handled=True, message="usage: /history search <query>")
        results = await ctx.session_search.search(query)
        if not results:
            return CommandResult(handled=True, message=f"no matches for {query!r}.")
        lines = [f"search results for {query!r}:"]
        for r in results:
            lines.append(f"  [{r.role}] {r.session_id}  {r.snippet}")
        return CommandResult(handled=True, message="\n".join(lines))
    if sub == "browse":
        summaries = await ctx.session_search.browse()
        if not summaries:
            return CommandResult(handled=True, message="no sessions found.")
        lines = ["recent sessions:"]
        for s in summaries:
            lines.append(f"  {s.session_id}  ({s.message_count} msgs)  {s.title[:50]}")
        return CommandResult(handled=True, message="\n".join(lines))
    if sub == "read":
        if len(args) < 2:
            return CommandResult(handled=True, message="usage: /history read <session_id>")
        sid = args[1]
        messages = await ctx.session_search.read_session(sid)
        if not messages:
            return CommandResult(handled=True, message=f"session {sid!r} is empty or unknown.")
        lines = [f"session {sid} ({len(messages)} messages):"]
        for m in messages:
            lines.append(f"  [{m.get('role', '?')}] {str(m.get('content', ''))[:80]}")
        return CommandResult(handled=True, message="\n".join(lines))
    return CommandResult(
        handled=True, message=f"unknown /history subcommand: {sub}"
    )


async def _cmd_cron(args: list[str], ctx: TuiContext) -> CommandResult:
    if ctx.cron_engine is None:
        return CommandResult(handled=True, message="cron engine not configured")
    if not args:
        return CommandResult(
            handled=True, message="usage: /cron [list|create|pause|resume|remove]"
        )
    sub = args[0]
    if sub == "list":
        tasks = await ctx.cron_engine.list_tasks()
        if not tasks:
            return CommandResult(handled=True, message="no scheduled tasks.")
        lines = ["scheduled tasks:"]
        for t in tasks:
            nxt = t.next_run.isoformat() if t.next_run else "-"
            lines.append(f"  [{t.status.value}] {t.id}  {t.name}  next={nxt}  runs={t.run_count}")
        return CommandResult(handled=True, message="\n".join(lines))
    if sub == "create":
        # /cron create <name> <schedule> <prompt...>
        if len(args) < 4:
            return CommandResult(
                handled=True,
                message="usage: /cron create <name> <schedule> <prompt>",
            )
        name, schedule_expr, prompt = args[1], args[2], " ".join(args[3:])
        from khaos.tools.cron_tools import _parse_schedule

        config = _parse_schedule(schedule_expr)
        task = await ctx.cron_engine.create(name, prompt, config)
        return CommandResult(
            handled=True,
            message=f"created task {task.id} ({name}), next_run={task.next_run.isoformat() if task.next_run else '-'}",
        )
    if sub in {"pause", "resume", "remove"}:
        if len(args) < 2:
            return CommandResult(handled=True, message=f"usage: /cron {sub} <id>")
        task_id = args[1]
        method = {"pause": ctx.cron_engine.pause, "resume": ctx.cron_engine.resume, "remove": ctx.cron_engine.remove}[sub]
        ok = await method(task_id)
        if not ok:
            return CommandResult(handled=True, message=f"task {task_id!r} not found")
        return CommandResult(handled=True, message=f"{sub}d task {task_id}")
    return CommandResult(
        handled=True, message=f"unknown /cron subcommand: {sub}\nusage: /cron [list|create|pause|resume|remove]"
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


async def _cmd_tasks(args: list[str], ctx: TuiContext) -> CommandResult:
    if ctx.task_manager is None:
        return CommandResult(handled=True, message="task manager not configured")
    # ``-a`` / ``--all`` lists every task; default lists active ones only.
    active_only = not (args and args[0] in {"-a", "--all"})
    tasks = await ctx.task_manager.list_active() if active_only else await ctx.task_manager.list_all()
    if not tasks:
        scope = "active" if active_only else ""
        return CommandResult(
            handled=True, message=f"no {scope} coding tasks.".strip()
        )
    label = "active tasks" if active_only else "all tasks"
    lines = [f"{label}:"]
    for task in tasks:
        lines.append(
            f"  [{task['status']}] {task['id']}  "
            f"{task['goal'][:60]}  (fixes={task['fix_attempts']})"
        )
    return CommandResult(handled=True, message="\n".join(lines))


async def _cmd_task(args: list[str], ctx: TuiContext) -> CommandResult:
    if ctx.task_manager is None:
        return CommandResult(handled=True, message="task manager not configured")
    if not args:
        return CommandResult(handled=True, message="usage: /task <id>")
    task = await ctx.task_manager.get(args[0])
    if task is None:
        return CommandResult(handled=True, message=f"task {args[0]!r} not found")
    data = task.to_dict() if hasattr(task, "to_dict") else task
    lines = [
        f"task {data['id']}: {data['goal']}",
        f"  status:       {data['status']}",
        f"  fix_attempts: {data['fix_attempts']}",
        f"  created_at:   {data['created_at']}",
        f"  updated_at:   {data['updated_at']}",
    ]
    if data["error"]:
        lines.append(f"  error:        {data['error']}")
    if data["files_modified"]:
        lines.append("  modified:")
        for path in data["files_modified"]:
            lines.append(f"    - {path}")
    if data["files_viewed"]:
        lines.append("  viewed:")
        for path in data["files_viewed"]:
            lines.append(f"    - {path}")
    if data["test_results"]:
        lines.append("  recent tests:")
        for result in data["test_results"]:
            ok = result.get("success")
            lines.append(f"    - success={ok}")
    return CommandResult(handled=True, message="\n".join(lines))


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
