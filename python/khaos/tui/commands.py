"""Slash-command parsing and dispatch for the TUI.

Kept as pure functions over a small context object so the dispatch logic is
unit-testable without a running Textual app. The TUI widgets call into
``handle_command`` and render the returned :class:`CommandResult`.
"""

from __future__ import annotations

import shlex
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from khaos.runtime.context import local_principal_id
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
    memory_manager: Any = None
    memory_store: Any = None
    memory_provider_manager: Any = None
    memory_profile_registry: Any = None
    memory_transfer: Any = None
    registry: Any = None
    router: Any = None
    db: Any = None
    skill_manager: SkillManager | None = None
    # Optional shared coding-task tracker for the /tasks and /task commands.
    task_manager: Any = None
    # Canonical M8.6 supervision and checkpoint owners.  Presentation code
    # must call these typed services instead of maintaining a second state
    # machine or reading the worktree directly.
    supervision_service: Any = None
    checkpoint_service: Any = None
    principal_id: str = ""
    # Optional cron engine for the /cron command.
    cron_engine: Any = None
    # Optional session history search for the /history command.
    session_search: Any = None
    channel_registry: Any = None
    session_id: str = ""
    # M4 batch 3.1.16A-5-1b: cached project identity, set by the TUI
    # app from ``KhaosTUI._tui_project_id`` so slash commands that
    # create sessions (e.g. ``/mode``) stamp the SAME project_id as
    # the runtime.
    project_id: str = ""
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
  /memory list              List Broker-admitted current memories
  /memory show <id>         Show one memory with provenance
  /memory search <query>    Full-text search memories
  /memory source <id>       Show the canonical source record
  /memory evidence <id>     Show evidence and graph edges
  /memory conflicts <query> Inspect conflicting historical facts
  /memory forget <id>      Revoke a memory (soft by default)
  /memory provider          Show provider lifecycle status
  /memory provider set <id> Switch provider after replay and health checks
  /memory profile           Show the active validated profile
  /memory rebuild           Replay the canonical event ledger
  /memory maintain          Run bounded maintenance and consistency checks
  /memory verify            Verify rebuildable indexes
  /memory gc                Run conservative compaction
  /memory benchmark <query> Run a live Broker benchmark (3 repetitions)
  /memory conformance       Run mandatory provider conformance checks
  /memory export <path>     Export a scope-bound package
  /memory import <path>     Import a scope-bound package
  /tools [mode]             List available tools (optionally per mode)
  /model <name>             Show or set the active model (set is advisory)
  /tasks                    List active coding tasks (all tasks with -a)
  /task <id>                Show details for one coding task
  /status [task_id]         Show typed supervision state
  /pause <task_id>          Request a safe cooperative pause
  /resume <task_id>         Resume a paused task
  /cancel <task_id>         Cancel and drain a task safely
  /checkpoint list [id]     List checkpoint metadata
  /checkpoint show <id>     Show one checkpoint metadata
  /checkpoint create <id>   Create a user checkpoint
  /rewind <checkpoint_id>   Build a safe rewind preview
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
    if cmd == "/status":
        return await _cmd_status(args, ctx)
    if cmd in {"/pause", "/resume", "/cancel"}:
        return await _cmd_control(cmd[1:], args, ctx)
    if cmd == "/checkpoint":
        return await _cmd_checkpoint(args, ctx)
    if cmd == "/rewind":
        return await _cmd_rewind(args, ctx)
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
        await ctx.db.create_session(
            ctx.session_id, target.value,
            principal_id=local_principal_id(),
            # M4 batch 3.1.16A-5-1b: stamp the cached project identity
            # (set by the TUI app from ``KhaosTUI._tui_project_id``).
            project_id=ctx.project_id,
        )
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
    manager = ctx.memory_manager
    broker = getattr(manager, "broker", None) if manager is not None else None
    if broker is not None:
        return await _cmd_memory_v2(args, ctx, manager, broker)
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


async def _cmd_memory_v2(
    args: list[str],
    ctx: TuiContext,
    manager: Any,
    broker: Any,
) -> CommandResult:
    """Expose V2 inspection and maintenance without a provider bypass."""

    from khaos.memory import MemoryBudget, MemoryMaintenanceService

    runtime_builder = getattr(manager, "runtime_context", None)
    if not callable(runtime_builder):
        return CommandResult(handled=True, message="memory runtime context not configured")
    runtime = runtime_builder(ctx.session_id)
    action = args[0].lower() if args else "list"
    if action == "status" and len(args) == 1:
        health = await broker.health()
        provider_manager = ctx.memory_provider_manager or getattr(
            manager, "provider_manager", None
        )
        statuses = await provider_manager.statuses() if provider_manager is not None else ()
        profile = getattr(manager, "profile", None)
        return CommandResult(
            handled=True,
            message=(
                f"memory provider={broker.provider.provider_id} "
                f"healthy={health.healthy}; "
                f"profile={getattr(profile, 'profile_id', 'unknown')}; "
                f"providers={len(statuses)}"
            ),
            payload={"health": health, "profile": profile, "providers": statuses},
        )
    if action == "profile" and len(args) <= 2:
        registry = ctx.memory_profile_registry or getattr(manager, "profile_registry", None)
        if registry is None:
            return CommandResult(handled=True, message="memory profile registry not configured")
        if len(args) == 2 and args[1] == "list":
            profiles = registry.list()
            return CommandResult(
                handled=True,
                message="\n".join(profile.profile_id for profile in profiles),
                payload=profiles,
            )
        profile = getattr(manager, "profile", None)
        return CommandResult(
            handled=True,
            message="profile not selected." if profile is None else _render_mapping(profile.to_mapping()),
            payload=profile,
        )
    if action in {"list", "search"}:
        query = " ".join(args[1:]) if action == "search" else ""
        if action == "search" and not query:
            return CommandResult(handled=True, message="usage: /memory search <query>")
        resolution = await broker.search(query, runtime, MemoryBudget(max_hits=100))
        hits = [*resolution.primary_hits, *resolution.supporting_hits]
        if not hits:
            return CommandResult(
                handled=True,
                message="no memories match the requested view." if query else "no memories stored.",
            )
        lines = [f"memories{f' matching {query!r}' if query else ''}:"]
        lines.extend(_format_memory_hit(hit) for hit in hits)
        return CommandResult(handled=True, message="\n".join(lines))
    if action == "show" and len(args) == 2:
        hit = await broker.get(args[1], runtime, include_historical=True)
        if hit is None:
            return CommandResult(handled=True, message=f"memory not found: {args[1]}")
        return CommandResult(handled=True, message=_format_memory_hit(hit, detailed=True))
    if action == "forget" and len(args) in {2, 3}:
        mode = args[2] if len(args) == 3 else "soft"
        try:
            result = await broker.forget((args[1],), runtime, mode=mode)
        except (RuntimeError, ValueError) as exc:
            return CommandResult(handled=True, message=f"memory forget failed: {exc}")
        return CommandResult(
            handled=True,
            message=f"forgot {len(result.forgotten_ids)} memory(s) with mode={result.mode}.",
        )
    if action == "rebuild" and len(args) == 1:
        report = await MemoryMaintenanceService(broker).rebuild(runtime)
        return CommandResult(
            handled=True,
            message=(
                f"memory rebuild: replayed={report.replayed_nodes}, "
                f"indexed={report.indexed_nodes}, "
                f"consistent={report.consistency.consistent}."
            ),
        )
    if action == "maintain" and len(args) == 1:
        report = await MemoryMaintenanceService(broker).maintain(runtime)
        return CommandResult(
            handled=True,
            message=(
                f"memory maintenance: deduplicated={report.deduplicated_evidence}, "
                f"tiers={report.lifecycle_tiers}, "
                f"consistent={report.consistency.consistent}."
            ),
            payload=report,
        )
    if action == "verify" and len(args) == 1:
        report = await MemoryMaintenanceService(broker).verify(runtime)
        return CommandResult(
            handled=True,
            message=f"memory indexes: supported={report.supported}, consistent={report.consistent}.",
        )
    if action == "source" and len(args) == 2:
        source = await broker.source(runtime, args[1])
        return CommandResult(
            handled=True,
            message="source not found." if source is None else _render_mapping(source),
            payload=source,
        )
    if action == "evidence" and len(args) == 2:
        evidence = await broker.evidence(runtime, args[1])
        return CommandResult(
            handled=True,
            message="no evidence." if not evidence else _render_sequence(evidence),
            payload=evidence,
        )
    if action == "conflicts" and len(args) >= 2:
        conflicts = await broker.conflicts(
            " ".join(args[1:]),
            runtime,
            MemoryBudget(max_hits=100),
        )
        return CommandResult(
            handled=True,
            message="no conflicts." if not conflicts else "\n".join(
                _format_memory_hit(hit, detailed=True) for hit in conflicts
            ),
            payload=conflicts,
        )
    if action == "provider":
        provider_manager = ctx.memory_provider_manager or getattr(
            manager, "provider_manager", None
        )
        if provider_manager is None:
            return CommandResult(handled=True, message="memory provider manager not configured")
        if len(args) == 1:
            statuses = await provider_manager.statuses()
            return CommandResult(
                handled=True,
                message="\n".join(
                    f"{item.provider_id}: state={item.state} active={item.active} "
                    f"healthy={item.healthy} ({item.detail})"
                    for item in statuses
                ) or "no memory providers registered.",
                payload=statuses,
            )
        if len(args) == 3 and args[1] == "set":
            status = await provider_manager.set_provider(args[2], runtime)
            return CommandResult(
                handled=True,
                message=(
                    f"memory provider={status.provider_id} state={status.state} "
                    f"healthy={status.healthy}."
                ),
                payload=status,
            )
    if action == "gc" and len(args) == 1:
        removed = await broker.compact(runtime)
        return CommandResult(handled=True, message=f"memory gc removed={removed}.")
    if action == "benchmark" and len(args) >= 2:
        from khaos.memory import BenchmarkCase, MemoryBenchmarkHarness

        query = " ".join(args[1:])
        report = await MemoryBenchmarkHarness(broker).run(
            [BenchmarkCase("tui-query", query)],
            runtime,
            repetitions=3,
        )
        return CommandResult(
            handled=True,
            message=(
                f"memory benchmark: status={report.status} "
                f"recall={report.metrics.get('recall', 0.0):.3f} "
                f"p95={report.metrics.get('latency_p95_ms', 0.0):.2f}ms."
            ),
            payload=report,
        )
    if action == "conformance" and len(args) == 1:
        from khaos.memory import run_provider_conformance

        report = await run_provider_conformance(broker, runtime)
        return CommandResult(
            handled=True,
            message=(
                f"memory conformance: provider={report.provider_id} "
                f"passed={report.passed} "
                f"checks={sum(report.checks.values())}/{len(report.checks)}."
            ),
            payload=report,
        )
    if action == "export" and len(args) == 2:
        transfer = ctx.memory_transfer or getattr(manager, "transfer_service", None)
        if transfer is None:
            return CommandResult(handled=True, message="memory transfer service not configured")
        result = await transfer.export(runtime, Path(args[1]))
        return CommandResult(handled=True, message=f"memory export: {result}", payload=result)
    if action == "import" and len(args) == 2:
        transfer = ctx.memory_transfer or getattr(manager, "transfer_service", None)
        if transfer is None:
            return CommandResult(handled=True, message="memory transfer service not configured")
        result = await transfer.import_package(runtime, Path(args[1]))
        return CommandResult(handled=True, message=f"memory import: {result}", payload=result)
    return CommandResult(
        handled=True,
        message=(
            "usage: /memory [list|show <id>|search <query>|source <id>|evidence <id>|"
            "conflicts <query>|forget <id> [soft|hard|compliance]|provider [set <id>]|"
            "profile [list]|rebuild|maintain|verify|gc|benchmark <query>|"
            "conformance|export <path>|import <path>]"
        ),
    )


def _render_mapping(value: Any) -> str:
    """Render bounded provenance mappings deterministically for the TUI."""

    return "\n".join(f"  {key}: {value[key]}" for key in sorted(value))


def _render_sequence(values: list[Any]) -> str:
    """Render bounded evidence rows without invoking model formatting."""

    return "\n".join(f"  {index + 1}. {value}" for index, value in enumerate(values))


def _format_memory_hit(hit: Any, *, detailed: bool = False) -> str:
    """Render Broker-admitted metadata for a user, not for model injection."""

    line = (
        f"  {hit.memory_id or hit.external_id} [{hit.status}] "
        f"({hit.scope}) {hit.key or '-'}: {hit.content}"
    )
    if not detailed:
        return line
    return "\n".join(
        (
            line,
            f"    type={hit.memory_type} authority={hit.authority_hint} confidence={hit.confidence_hint}",
            f"    namespace={hit.namespace} source={hit.source_ref or 'unknown'}",
            f"    events={', '.join(hit.event_ids) or 'none'}",
        )
    )


def _cmd_tools(args: list[str], ctx: TuiContext) -> CommandResult:
    if ctx.registry is None:
        return CommandResult(handled=True, message="tool registry not configured")
    mode = args[0] if args else _current_mode_value(ctx)
    try:
        tools = ctx.registry.list_by_mode(mode)
    except Exception:  # noqa: BLE001 - unavailable registry falls back to all tools
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


def _supervision_owner(ctx: TuiContext) -> tuple[str, str]:
    return ctx.principal_id or local_principal_id(), ctx.project_id or "legacy"


def _control_message(payload: dict[str, object]) -> str:
    status = payload.get("status", "UNKNOWN")
    task_id = payload.get("task_id", "")
    control_state = payload.get("control_state", "unknown")
    reason = payload.get("reason")
    suffix = f"; {reason}" if reason else ""
    return f"{task_id}: {status} ({control_state}){suffix}"


async def _cmd_status(args: list[str], ctx: TuiContext) -> CommandResult:
    """Render only the durable supervision projection, never raw model data."""
    if ctx.supervision_service is None:
        return CommandResult(handled=True, message="supervision service not configured")
    if len(args) > 1:
        return CommandResult(handled=True, message="usage: /status [task_id]")
    principal_id, project_id = _supervision_owner(ctx)
    if args:
        task_id = args[0]
        state = await ctx.supervision_service.state(
            task_id, principal_id=principal_id, project_id=project_id
        )
        if state is None:
            return CommandResult(handled=True, message=f"task {task_id!r} has no supervision state")
        payload = state.to_payload()
        activity = payload.get("activity") or {}
        return CommandResult(
            handled=True,
            message=(
                f"task {task_id}: {payload.get('status')} "
                f"generation={payload.get('repository_generation')} "
                f"revision={payload.get('revision')} "
                f"activity={activity.get('kind', 'idle')}"
            ),
            payload=payload,
        )
    if ctx.task_manager is None:
        return CommandResult(handled=True, message="usage: /status <task_id>")
    tasks = await ctx.task_manager.list_active()
    if not tasks:
        return CommandResult(handled=True, message="no active coding tasks.")
    rows: list[str] = []
    for task in tasks:
        task_id = task.get("id", "") if isinstance(task, dict) else getattr(task, "id", "")
        state = await ctx.supervision_service.state(
            task_id, principal_id=principal_id, project_id=project_id
        )
        status = state.status.value if state is not None else "UNINITIALIZED"
        rows.append(f"  {task_id} [{status}]")
    return CommandResult(handled=True, message="supervision:\n" + "\n".join(rows))


async def _task_workspace(ctx: TuiContext, task_id: str) -> str | None:
    if ctx.task_manager is not None:
        task = await ctx.task_manager.get(task_id)
        if task is not None:
            metadata = getattr(task, "metadata", None)
            if isinstance(metadata, dict) and isinstance(metadata.get("workspace_id"), str):
                return metadata["workspace_id"]
    if ctx.supervision_service is not None:
        principal_id, project_id = _supervision_owner(ctx)
        state = await ctx.supervision_service.state(
            task_id, principal_id=principal_id, project_id=project_id
        )
        return state.workspace_id if state is not None else None
    return None


async def _cmd_control(command: str, args: list[str], ctx: TuiContext) -> CommandResult:
    if ctx.supervision_service is None:
        return CommandResult(handled=True, message="supervision service not configured")
    if len(args) < 1 or len(args) > 2:
        return CommandResult(handled=True, message=f"usage: /{command} <task_id> [expected_revision]")
    task_id = args[0]
    try:
        expected_revision = int(args[1]) if len(args) == 2 else None
    except ValueError:
        return CommandResult(handled=True, message="expected_revision must be an integer")
    workspace_id = await _task_workspace(ctx, task_id)
    if not workspace_id:
        return CommandResult(handled=True, message=f"task {task_id!r} has no bound workspace")
    principal_id, project_id = _supervision_owner(ctx)
    handler = getattr(ctx.supervision_service, command)
    result = await handler(
        task_id=task_id,
        workspace_id=workspace_id,
        principal_id=principal_id,
        project_id=project_id,
        expected_revision=expected_revision,
    )
    payload = result.to_payload() if hasattr(result, "to_payload") else dict(result)
    return CommandResult(handled=True, message=_control_message(payload), payload=payload)


def _checkpoint_line(checkpoint: Any, *, detailed: bool = False) -> str:
    payload = checkpoint.to_payload(include_snapshot=False)
    line = (
        f"{payload['checkpoint_id']} [{payload['checkpoint_kind']}] "
        f"generation={payload['repository_generation']} "
        f"label={payload['label'] or '-'}"
    )
    if detailed:
        line += (
            f"\n  task={payload['task_id']} workspace={payload['workspace_id']} "
            f"snapshot={payload['snapshot_digest']} files={len(checkpoint.snapshot)}"
            f"\n  digest={payload['checkpoint_digest']}"
        )
    return line


async def _cmd_checkpoint(args: list[str], ctx: TuiContext) -> CommandResult:
    if not args or args[0] not in {"list", "show", "create"}:
        return CommandResult(
            handled=True,
            message="usage: /checkpoint [list [task_id]|show <id>|create <task_id> [label]]",
        )
    if ctx.checkpoint_service is None and ctx.db is None:
        return CommandResult(handled=True, message="checkpoint service not configured")
    principal_id, project_id = _supervision_owner(ctx)
    sub = args[0]
    if sub == "list":
        task_id = args[1] if len(args) > 1 else None
        if task_id is None:
            if ctx.task_manager is None:
                return CommandResult(handled=True, message="usage: /checkpoint list <task_id>")
            tasks = await ctx.task_manager.list_active()
            task_id = tasks[0].get("id") if tasks and isinstance(tasks[0], dict) else None
        if not task_id:
            return CommandResult(handled=True, message="no task selected")
        if ctx.checkpoint_service is not None:
            checkpoints = await ctx.checkpoint_service.list_checkpoints(
                task_id, principal_id=principal_id, project_id=project_id
            )
        else:
            checkpoints = await ctx.db.checkpoint_repository.list(
                task_id, principal_id=principal_id, project_id=project_id
            )
        if not checkpoints:
            return CommandResult(handled=True, message=f"no checkpoints for {task_id}")
        return CommandResult(
            handled=True,
            message="\n".join(_checkpoint_line(item) for item in checkpoints),
            payload=[item.to_payload(include_snapshot=False) for item in checkpoints],
        )
    if sub == "show":
        if len(args) != 2:
            return CommandResult(handled=True, message="usage: /checkpoint show <checkpoint_id>")
        checkpoint_id = args[1]
        checkpoint = await (
            ctx.checkpoint_service.checkpoint(
                checkpoint_id, principal_id=principal_id, project_id=project_id
            )
            if ctx.checkpoint_service is not None
            else ctx.db.checkpoint_repository.get(
                checkpoint_id, principal_id=principal_id, project_id=project_id
            )
        )
        if checkpoint is None:
            return CommandResult(handled=True, message=f"checkpoint {checkpoint_id!r} not found")
        return CommandResult(
            handled=True,
            message=_checkpoint_line(checkpoint, detailed=True),
            payload=checkpoint.to_payload(include_snapshot=False),
        )
    if len(args) < 2:
        return CommandResult(handled=True, message="usage: /checkpoint create <task_id> [label]")
    task_id = args[1]
    workspace_id = await _task_workspace(ctx, task_id)
    if ctx.checkpoint_service is None or not workspace_id:
        return CommandResult(
            handled=True,
            message="checkpoint capture requires the active workspace owner",
        )
    checkpoint = await ctx.checkpoint_service.create_checkpoint(
        task_id=task_id,
        workspace_id=workspace_id,
        kind="USER_CREATED",
        label=" ".join(args[2:]),
        principal_id=principal_id,
        project_id=project_id,
    )
    return CommandResult(
        handled=True,
        message=f"created {_checkpoint_line(checkpoint)}",
        payload=checkpoint.to_payload(include_snapshot=False),
    )


async def _cmd_rewind(args: list[str], ctx: TuiContext) -> CommandResult:
    """Only preview a rewind in the TUI; execution remains an explicit API action."""
    if len(args) != 1:
        return CommandResult(handled=True, message="usage: /rewind <checkpoint_id>")
    if ctx.checkpoint_service is None:
        return CommandResult(handled=True, message="checkpoint service not configured")
    principal_id, project_id = _supervision_owner(ctx)
    checkpoint = await ctx.checkpoint_service.checkpoint(
        args[0], principal_id=principal_id, project_id=project_id
    )
    if checkpoint is None:
        return CommandResult(handled=True, message=f"checkpoint {args[0]!r} not found")
    plan = await ctx.checkpoint_service.build_rewind_plan(
        args[0], principal_id=principal_id, project_id=project_id
    )
    payload = plan.to_payload(include_transaction_content=False)
    status = "blocked" if plan.conflicts else plan.status
    message = (
        f"rewind preview {plan.rewind_id}: {status}; "
        f"affected={len(plan.affected_paths)} preserved={len(plan.preserved_paths)}"
    )
    if plan.conflicts:
        message += "\n  conflicts: " + "; ".join(plan.conflicts)
    else:
        message += "\n  execution is intentionally not performed by the TUI preview"
    return CommandResult(handled=True, message=message, payload=payload)


def _current_mode_value(ctx: TuiContext) -> str:
    if ctx.mode_manager is None:
        return "office"
    mode = ctx.mode_manager.current_mode
    return getattr(mode, "value", str(mode))


__all__ = [
    "HELP_TEXT",
    "CommandResult",
    "TuiContext",
    "handle_command",
    "is_command",
]
