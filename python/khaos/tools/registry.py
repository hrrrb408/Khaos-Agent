"""Declarative tool registry and JSON Schema validation."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Awaitable, Callable

from khaos.exceptions import ToolNotFoundError


_WORKSPACE_FILE_TOOLS = frozenset({
    "read_file", "search_files", "list_directory", "file_info", "tree_view",
    "file_search_content", "write_file", "patch", "multi_edit", "copy_file",
    "move_file", "code_search", "code_symbols",
})
_OFFICE_WORKSPACE_FILE_TOOLS = frozenset({
    "read_file", "search_files", "list_directory", "file_info", "tree_view",
    "file_search_content", "write_file", "patch", "multi_edit", "copy_file",
    "move_file",
    # B1: browser_file_upload reads a host file and uploads it to a web page;
    # listing it here makes the broker inject ``workspace_root`` so the
    # handler can validate the file path is contained within the workspace
    # root (no symlink escape, no arbitrary host file exfiltration).
    "browser_file_upload",
})
@dataclass(frozen=True)
class ToolCapability:
    name: str
    modes: frozenset[str]
    scopes: frozenset[str]


def _capability(
    name: str,
    modes: set[str],
    scopes: set[str],
) -> tuple[ToolCapability, ...]:
    return (ToolCapability(name, frozenset(modes), frozenset(scopes)),)


# Explicit migration manifest for declarations that predate ToolCapability.
# This is intentionally a closed, name-indexed table: production registration
# never derives authority from permission_level, naming conventions, or tool
# descriptions.  New tools must either declare capabilities on ToolDefinition
# or add a reviewed entry here.
_BUILTIN_CAPABILITY_MANIFEST: dict[str, tuple[ToolCapability, ...]] = {
    "read_file": _capability("filesystem.read", {"all"}, {"task-workspace", "user-selected"}),
    "search_files": _capability("filesystem.read", {"all"}, {"task-workspace", "user-selected"}),
    "list_directory": _capability("filesystem.read", {"office", "coding"}, {"task-workspace", "user-selected"}),
    "file_info": _capability("filesystem.read", {"office", "coding"}, {"task-workspace", "user-selected"}),
    "tree_view": _capability("filesystem.read", {"office", "coding"}, {"task-workspace", "user-selected"}),
    "file_search_content": _capability("filesystem.read", {"office", "coding"}, {"task-workspace", "user-selected"}),
    "code_search": _capability("filesystem.read", {"coding"}, {"task-workspace"}),
    "code_symbols": _capability("filesystem.read", {"coding"}, {"task-workspace"}),
    "write_file": _capability("filesystem.write", {"coding"}, {"task-workspace"}),
    "multi_edit": _capability("filesystem.write", {"coding"}, {"task-workspace"}),
    "patch": _capability("filesystem.write", {"coding"}, {"task-workspace"}),
    "copy_file": _capability("filesystem.write", {"office", "coding"}, {"task-workspace", "user-selected"}),
    "move_file": _capability("filesystem.write", {"office", "coding"}, {"task-workspace", "user-selected"}),
    "quick_note": _capability("host.notes.write", {"office"}, {"local-interactive-user"}),
    "search_notes": _capability("host.notes.read", {"office"}, {"local-interactive-user"}),
    "list_notes": _capability("host.notes.read", {"office"}, {"local-interactive-user"}),
    "delete_note": _capability("host.notes.write", {"office"}, {"local-interactive-user"}),
    "markdown_to_text": _capability("compute.local", {"office"}, {"in-memory"}),
    "extract_headings": _capability("compute.local", {"office"}, {"in-memory"}),
    "count_words": _capability("compute.local", {"office"}, {"in-memory"}),
    "format_markdown_table": _capability("compute.local", {"office"}, {"in-memory"}),
    "clipboard_read": _capability("host.clipboard.read", {"office"}, {"local-interactive-user"}),
    "clipboard_write": _capability("host.clipboard.write", {"office"}, {"local-interactive-user"}),
    "terminal": _capability("process.execute", {"coding"}, {"task-workspace"}),
    "process": _capability("process.execute", {"coding"}, {"task-workspace"}),
    "test_run": _capability("process.execute", {"coding"}, {"task-workspace"}),
    "git_diff": _capability("vcs.read", {"coding"}, {"task-workspace"}),
    "git_log": _capability("vcs.read", {"coding"}, {"task-workspace"}),
    "git_status": _capability("vcs.read", {"coding", "office"}, {"task-workspace"}),
    "git_pr_body": _capability("vcs.read", {"coding"}, {"task-workspace"}),
    "git_commit": _capability("vcs.write", {"coding"}, {"task-workspace"}),
    "git_branch": _capability("vcs.write", {"coding"}, {"task-workspace"}),
    "git_smart_commit": _capability("vcs.write", {"coding"}, {"task-workspace"}),
    "git_undo": _capability("vcs.write", {"coding"}, {"task-workspace"}),
    "git_create_branch": _capability("vcs.write", {"coding"}, {"task-workspace"}),
    "todo_write": _capability("task.state.write", {"coding"}, {"runtime"}),
    "todo_read": _capability("task.state.read", {"coding"}, {"runtime"}),
    "todo_update": _capability("task.state.write", {"coding"}, {"runtime"}),
}


@dataclass
class ToolDefinition:
    """Declarative tool definition."""

    name: str
    description: str
    parameters: dict
    modes: list[str]
    permission_level: str
    parallel: bool
    timeout: int = 60
    handler: Callable[..., Awaitable[Any]] | None = None
    capabilities: tuple[ToolCapability, ...] = ()


class ToolRegistry:
    """Runtime registry for declared tools."""

    def __init__(
        self,
        enforce_capabilities: bool = False,
        *,
        capability_manifest: dict[str, tuple[ToolCapability, ...]] | None = None,
    ):
        self._tools: dict[str, ToolDefinition] = {}
        self.enforce_capabilities = enforce_capabilities
        self._capability_manifest = capability_manifest or {}

    def register(self, definition: ToolDefinition) -> None:
        """Register a tool definition."""
        if definition.name in self._tools:
            raise ValueError(f"tool already registered: {definition.name}")
        if self.enforce_capabilities and not definition.capabilities:
            declared = self._capability_manifest.get(definition.name)
            if not declared:
                raise ValueError(
                    f"tool {definition.name} must declare explicit capabilities"
                )
            definition.capabilities = declared
        self._tools[definition.name] = definition

    def get(self, name: str) -> ToolDefinition:
        """Return a registered tool or raise ToolNotFoundError."""
        try:
            return self._tools[name]
        except KeyError as exc:
            raise ToolNotFoundError(name) from exc

    def list_by_mode(self, mode: str) -> list[ToolDefinition]:
        """List tools available to a mode."""
        return [
            tool
            for tool in self._tools.values()
            if "all" in tool.modes or mode in tool.modes
        ]

    def get_parallel_tools(self, tool_calls: list[dict]) -> tuple[list[dict], list[dict]]:
        """Split tool calls into parallel-safe and serial groups."""
        parallel_calls: list[dict] = []
        serial_calls: list[dict] = []
        for call in tool_calls:
            tool = self.get(str(call["name"]))
            if tool.parallel and tool.permission_level == "read":
                parallel_calls.append(call)
            else:
                serial_calls.append(call)
        return parallel_calls, serial_calls

    def validate_call(self, name: str, params: dict) -> bool:
        """Validate a small useful subset of JSON Schema."""
        schema = self.get(name).parameters
        return self._validate_schema_value(schema, params)

    def capabilities_for(self, name: str) -> tuple[ToolCapability, ...]:
        return self.get(name).capabilities

    def prune(self, tool_names: list[str]) -> "ToolRegistry":
        """Return a new registry containing only ``tool_names``.

        B1: SubAgent tasks declare a tool subset (``task.tools``); the
        spawner previously only *validated* that those names existed in the
        full registry, then handed the subagent a scheduler wired to the
        *full* registry — so a subagent could invoke any registered tool
        regardless of its declared subset.  This method produces a genuine
        pruned view: a fresh ``ToolRegistry`` (same ``enforce_capabilities``
        flag) carrying only the requested tool definitions with their
        handlers and capabilities intact.

        Unknown names are silently skipped — callers are expected to
        validate names beforehand via :meth:`get` / :meth:`_validate_tools`
        so the prune step never silently drops a requested tool.
        """
        pruned = ToolRegistry(enforce_capabilities=self.enforce_capabilities)
        for name in tool_names:
            definition = self._tools.get(name)
            if definition is None:
                continue
            # Re-register the already-validated immutable security contract.
            pruned._tools[name] = definition
        return pruned

    def _validate_schema_value(self, schema: dict, value: Any) -> bool:
        expected = schema.get("type")
        if "enum" in schema and value not in schema["enum"]:
            return False
        if expected == "string":
            return isinstance(value, str)
        if expected == "integer":
            return isinstance(value, int)
        if expected == "boolean":
            return isinstance(value, bool)
        if expected == "object":
            if not isinstance(value, dict):
                return False
            if any(required not in value for required in schema.get("required", [])):
                return False
            properties = schema.get("properties", {})
            return all(key not in properties or self._validate_schema_value(properties[key], item) for key, item in value.items())
        if expected == "array":
            items = schema.get("items")
            return isinstance(value, list) and (items is None or all(self._validate_schema_value(items, item) for item in value))
        return True


class ToolInvocationBroker:
    """Uniform capability gate before any public tool handler is invoked."""

    def __init__(self, registry: ToolRegistry) -> None:
        self.registry = registry

    async def invoke(self, name: str, *, mode: str, context: dict[str, Any], **params: Any) -> Any:
        definition = self.registry.get(name)
        capabilities = definition.capabilities
        if not capabilities and self.registry.enforce_capabilities:
            raise PermissionError(f"tool {name} has no declared capability")
        for capability in capabilities:
            if mode not in capability.modes and "all" not in capability.modes:
                raise PermissionError(f"tool {name} is unavailable in mode {mode}")
            if capability.name == "process.execute":
                service = context.get("execution_service")
                if service is None:
                    raise PermissionError("process.execute requires ExecutionService")
            if capability.name == "filesystem.write" and mode == "coding":
                if (
                    context.get("workspace_id") is None
                    or context.get("task_id") is None
                    or context.get("workspace_manager") is None
                ):
                    raise PermissionError("filesystem.write requires active TaskWorkspace")
            if (
                capability.name == "filesystem.read"
                and mode == "coding"
                and name in _WORKSPACE_FILE_TOOLS
            ):
                if (
                    context.get("workspace_id") is None
                    or context.get("task_id") is None
                    or context.get("workspace_manager") is None
                ):
                    raise PermissionError("filesystem.read requires active TaskWorkspace")
            if capability.name == "network.access" and context.get("network_policy") != "unrestricted-with-approval":
                raise PermissionError("network.access requires server-authorized network policy")
            if capability.name == "host.integration" and mode == "coding":
                raise PermissionError("host integration is unavailable to Coding Agent")
            if capability.name.startswith(("host.notes.", "host.clipboard.")):
                local_uid = (
                    f"local-uid:{os.getuid()}"
                    if hasattr(os, "getuid")
                    else "local-uid:windows"
                )
                if (
                    context.get("principal_id") != local_uid
                    or context.get("source_transport") not in {"cli", "tui"}
                    or context.get("foreground_session") is not True
                ):
                    raise PermissionError(
                        f"{capability.name} requires the local interactive "
                        "OS user in a foreground CLI/TUI session"
                    )
        if definition.handler is None:
            raise ToolNotFoundError(f"tool handler not configured: {name}")
        handler_params = dict(params)
        if any(capability.name == "process.execute" for capability in capabilities):
            handler_params["execution_service"] = context.get("execution_service")
            handler_params["task_id"] = context.get("task_id")
            handler_params["workspace_id"] = context.get("workspace_id")
        if any(capability.name.startswith("vcs.") for capability in capabilities):
            handler_params["execution_service"] = context.get("execution_service")
            handler_params["task_id"] = context.get("task_id")
            handler_params["workspace_id"] = context.get("workspace_id")
            handler_params["approval_context"] = context.get("approval_context")
            handler_params["network_policy"] = context.get("network_policy", "none")
            handler_params["principal_id"] = context.get("principal_id")
            handler_params["requester"] = context.get("requester")
            if name == "git_push":
                handler_params["credential_context"] = context.get("credential_context")
        if any(capability.name == "network.access" for capability in capabilities):
            handler_params["network_policy"] = context.get("network_policy", "none")
            handler_params["credential_context"] = context.get("credential_context")
            handler_params["network_guard"] = context.get("network_guard")
            # H1: pass principal_id so browser tools can select a per-principal
            # BrowserContext (cookie / DOM isolation between principals).
            handler_params["principal_id"] = context.get("principal_id", "")
        # H1: per-principal BrowserContext isolation applies to ALL browser
        # tools that touch a Page, not just network.access ones.  Read-only
        # browser tools (snapshot / screenshot / scroll / vision) declare
        # ``filesystem.read``; without principal_id here they would all
        # share the "default" BrowserContext, leaking one principal's DOM /
        # cookies to another.  ``browser_launch`` / ``browser_close`` are
        # process-global lifecycle operations and don't accept principal_id.
        # B2 + H5: also propagate ``session_id`` + ``runtime_id`` +
        # ``network_guard`` so browser tools key their BrowserContext by
        # (principal, session, runtime) AND install a Playwright
        # ``context.route("**/*")`` interceptor that gates every request,
        # redirect and subresource against the NetworkGuard's domain check
        # (closing the bypass where click / type / evaluate / upload could
        # reach a blocked domain because they don't carry a ``url`` arg).
        if (
            name.startswith("browser_")
            and name not in {"browser_launch", "browser_close"}
        ):
            if "principal_id" not in handler_params:
                handler_params["principal_id"] = context.get("principal_id", "")
            handler_params.setdefault("session_id", context.get("session_id", ""))
            handler_params.setdefault("runtime_id", context.get("runtime_id", ""))
            handler_params.setdefault(
                "network_guard", context.get("network_guard")
            )
        if any(capability.name in {"remote.write", "remote.destructive-write"} for capability in capabilities):
            handler_params["approval_context"] = context.get("approval_context")
            handler_params["principal_id"] = context.get("principal_id")
            handler_params["requester"] = context.get("requester")
        # MEDIUM (batch 3.1.8): the four orchestrator tools declare the
        # ``subagent.spawn`` capability so the broker injects the caller's
        # ``principal_id`` — the spawner / wait_all / stats filter on it,
        # so without this injection a principal could never observe the
        # tasks it spawned (spawner returns an empty list for empty
        # principal, defense-in-depth against cross-principal leakage).
        # M4 batch 3.1.16A-5-1b: also inject ``project_id`` so the spawned
        # ``SubAgentTask`` inherits the parent runtime's bound project
        # identity — every row the sub-agent writes (session, message,
        # turn, audit, memory, coding_task) is then scoped to the same
        # (principal, project) pair as the parent, and the spawner /
        # runner propagate it into ``create_session`` + ``RuntimeConfig``.
        if any(capability.name == "subagent.spawn" for capability in capabilities):
            handler_params["principal_id"] = context.get("principal_id", "")
            handler_params["project_id"] = context.get("project_id", "")
        # M4 batch 3.1.10 (CRITICAL): the five cron tools declare the
        # ``cron.manage`` capability so the broker injects the caller's
        # ``principal_id``.  The engine / DB layer filter every read and
        # mutation by principal — without this injection the cron
        # handlers receive ``principal_id=""`` and:
        #   * ``cron_create`` raises ValueError (principal required);
        #   * ``cron_list`` returns an empty list (no tasks visible);
        #   * ``cron_pause`` / ``cron_resume`` / ``cron_remove`` return
        #     ``not_found`` for every task (no ownership match).
        # In a multi-principal deployment that would let one principal
        # silently control another's scheduled tasks if the broker were
        # ever bypassed — fail-closed on the broker injection path.
        if any(capability.name == "cron.manage" for capability in capabilities):
            handler_params["principal_id"] = context.get("principal_id", "")
        # M4 batch 3.1.16A-4-4-1 (CRITICAL): the five permission tools
        # declare ``permission.read`` / ``permission.manage`` so the
        # broker injects the caller's ``principal_id`` +
        # ``permission_engine`` + ``audit_logger`` from
        # ``tool_context``.  Before A-4-4-1 the handlers read module-
        # global holders that were last-write-wins across concurrent
        # principals — see ``permission_tools.py`` docstring for the
        # race description.  ``permission_engine`` is constructed
        # per-runtime by ``factory.build_runtime`` and bound to
        # ``cfg.principal_id``; ``audit_logger`` may be the server-
        # lifecycle singleton (bound to ``local-uid``), but
        # ``query_audit_logs`` / ``security_status`` pass
        # ``principal_id`` explicitly to ``audit_logger.query`` so the
        # logger's bound default is overridden per-call.
        if any(
            capability.name in {"permission.read", "permission.manage"}
            for capability in capabilities
        ):
            handler_params["principal_id"] = context.get("principal_id", "")
            handler_params["permission_engine"] = context.get("permission_engine")
            handler_params["audit_logger"] = context.get("audit_logger")
        # M4 batch 3.1.16A-4-4-2: the three history tools declare
        # ``history.read`` so the broker injects the caller's
        # ``principal_id`` + ``db`` from ``tool_context``.  The handler
        # constructs a fresh ``SessionSearch(db, principal_id=principal_id)``
        # per call — ``SessionSearch.__init__`` is just two attribute
        # stores, so this is cheaper than maintaining a holder.  No
        # module-global state, no cross-principal leak, no "unavailable"
        # dead code (the old ``set_session_search`` was never called
        # from production).
        if any(capability.name == "history.read" for capability in capabilities):
            handler_params["principal_id"] = context.get("principal_id", "")
            handler_params["db"] = context.get("db")
        # M4 batch 3.1.16A-4-4-3 (CRITICAL): the four channel tools
        # declare ``channel.read`` (list / health) or ``channel.manage``
        # (enable / disable) so the broker injects ``channel_registry``
        # + ``principal_id`` from ``tool_context``.  ``channel.manage``
        # additionally receives ``channel_admins`` — the admin principal
        # allowlist compiled into the immutable
        # :class:`EffectiveSecurityPolicy` from
        # ``khaos_policy.yaml``'s ``channels.admin_principals`` field
        # (user ∪ project, OR semantics).  Without this injection the
        # handlers receive ``principal_id=""`` / ``channel_registry=None``
        # / ``channel_admins=None`` and fail-closed returns
        # ``unavailable`` / ``forbidden`` for every call.  Worse, before
        # A-4-4-3 the handlers read a module-global ``_registry`` holder
        # installed at server startup — every principal sharing the
        # process could enable/disable any channel, bypassing the gRPC
        # RPC path's ``ctx.principal_id`` authorization.
        if any(
            capability.name in {"channel.read", "channel.manage"}
            for capability in capabilities
        ):
            handler_params["principal_id"] = context.get("principal_id", "")
            handler_params["channel_registry"] = context.get("channel_registry")
        if any(capability.name == "channel.manage" for capability in capabilities):
            handler_params["channel_admins"] = context.get("channel_admins", frozenset())
        if mode == "coding" and name in _WORKSPACE_FILE_TOOLS and any(
            capability.name in {"filesystem.read", "filesystem.write"}
            for capability in capabilities
        ):
            handler_params["workspace_manager"] = context.get("workspace_manager")
            handler_params["task_id"] = context.get("task_id")
            handler_params["workspace_id"] = context.get("workspace_id")
        if mode == "office" and name in _OFFICE_WORKSPACE_FILE_TOOLS:
            workspace_root = context.get("office_workspace_root")
            if workspace_root is None:
                raise PermissionError(
                    "Office filesystem access requires a Sandbox root capability"
                )
            handler_params["workspace_root"] = workspace_root
            # H1: mutations (copy/move) are fenced through the shared authority
            # so cancellation/timeout cannot abandon a running thread.
            if name in {"write_file", "patch", "multi_edit", "copy_file", "move_file"}:
                handler_params["office_authority"] = context.get("office_authority")
        return await definition.handler(**handler_params)

    def _validate_schema_value(self, schema: dict, value: Any) -> bool:
        expected = schema.get("type")
        if "enum" in schema and value not in schema["enum"]:
            return False
        if expected == "string":
            return isinstance(value, str)
        if expected == "integer":
            return isinstance(value, int)
        if expected == "boolean":
            return isinstance(value, bool)
        if expected == "object":
            if not isinstance(value, dict):
                return False
            for required in schema.get("required", []):
                if required not in value:
                    return False
            properties = schema.get("properties", {})
            return all(
                key not in properties or self._validate_schema_value(properties[key], item)
                for key, item in value.items()
            )
        if expected == "array":
            if not isinstance(value, list):
                return False
            item_schema = schema.get("items")
            if item_schema is None:
                return True
            return all(self._validate_schema_value(item_schema, item) for item in value)
        return True


# Hermes batch 5: declarative specs for cron + history tools. Defined here
# (not imported from the tool modules) to avoid a circular import at module
# load time — the tool modules are wired lazily in create_runtime_registry().
CRON_TOOL_SPECS = [
    {
        "name": "cron_create",
        "description": "Create a new scheduled task. Schedule formats: cron '0 9' (daily 9am), interval '30m'/'2h', ISO timestamp (one-shot).",
        "parameters": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Task name"},
                "prompt": {"type": "string", "description": "Prompt to execute when triggered"},
                "schedule": {"type": "string", "description": "Schedule expression"},
                "repeat": {"type": "integer", "description": "Max repeat count (optional)"},
                "deliver_to": {"type": "string", "description": "Where to send results"},
            },
            "required": ["name", "prompt", "schedule"],
        },
    },
    {
        "name": "cron_list",
        "description": "List all scheduled tasks.",
        "parameters": {"type": "object", "properties": {}},
    },
    {
        "name": "cron_remove",
        "description": "Remove a scheduled task.",
        "parameters": {
            "type": "object",
            "properties": {"task_id": {"type": "string", "description": "Task ID to remove"}},
            "required": ["task_id"],
        },
    },
    {
        "name": "cron_pause",
        "description": "Pause a scheduled task.",
        "parameters": {
            "type": "object",
            "properties": {"task_id": {"type": "string", "description": "Task ID"}},
            "required": ["task_id"],
        },
    },
    {
        "name": "cron_resume",
        "description": "Resume a paused scheduled task.",
        "parameters": {
            "type": "object",
            "properties": {"task_id": {"type": "string", "description": "Task ID"}},
            "required": ["task_id"],
        },
    },
]

HISTORY_TOOL_SPECS = [
    {
        "name": "history_search",
        "description": "Search past session history. Supports AND/OR/NOT operators and quoted phrases.",
        "parameters": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search query"},
                "limit": {"type": "integer", "description": "Max results (default 10)"},
            },
            "required": ["query"],
        },
    },
    {
        "name": "history_browse",
        "description": "Browse recent sessions by date.",
        "parameters": {
            "type": "object",
            "properties": {"limit": {"type": "integer", "description": "Max sessions (default 20)"}},
        },
    },
    {
        "name": "history_read",
        "description": "Read messages from a specific past session.",
        "parameters": {
            "type": "object",
            "properties": {"session_id": {"type": "string", "description": "Session ID to read"}},
            "required": ["session_id"],
        },
    },
]


def register_builtin_tools(registry: ToolRegistry) -> None:
    """Register the Phase 1 built-in tool declarations."""
    from khaos.tools.channel_tools import CHANNEL_TOOLS
    from khaos.tools.github_tools import GITHUB_TOOL_SPECS

    # M4 batch 3.1.16A-4-4-3: register channel tools separately so they
    # carry the ``channel.read`` / ``channel.manage`` capabilities.  The
    # original loop registered them with no capability (``capabilities
    # = ()``), so the broker treated them as no-capability tools and the
    # handlers fell open to the module-global ``_registry`` holder —
    # every principal sharing the process could enable/disable any
    # channel.  With declared capabilities the broker injects
    # ``channel_registry`` + ``principal_id`` (+ ``channel_admins`` for
    # mutations) from ``tool_context`` and the handlers fail-closed on
    # missing principal / missing admin grant.
    _CHANNEL_READ_CAP_LOCAL = ToolCapability(
        "channel.read",
        frozenset({"all"}),
        frozenset({"app-data"}),
    )
    _CHANNEL_MANAGE_CAP_LOCAL = ToolCapability(
        "channel.manage",
        frozenset({"all"}),
        frozenset({"app-data"}),
    )
    _CHANNEL_CAPS = {
        "channel_list": _CHANNEL_READ_CAP_LOCAL,
        "channel_health": _CHANNEL_READ_CAP_LOCAL,
        "channel_enable": _CHANNEL_MANAGE_CAP_LOCAL,
        "channel_disable": _CHANNEL_MANAGE_CAP_LOCAL,
    }
    for spec in CHANNEL_TOOLS:
        registry.register(
            ToolDefinition(
                name=spec["name"],
                description=spec["description"],
                parameters=spec["parameters"],
                modes=["all"],
                permission_level="write" if spec["name"] in {"channel_enable", "channel_disable"} else "read",
                parallel=spec["name"] in {"channel_list", "channel_health"},
                capabilities=(_CHANNEL_CAPS[spec["name"]],),
            )
        )
    for spec in GITHUB_TOOL_SPECS:
        classification = spec.get("classification")
        capabilities: tuple[ToolCapability, ...] = ()
        modes = ["all"]
        if classification is not None:
            modes = ["coding"]
            capabilities = (
                ToolCapability("process.execute", frozenset({"coding"}), frozenset({"task-workspace"})),
                ToolCapability(classification, frozenset({"coding"}), frozenset({"task-workspace"})),
                ToolCapability("network.access", frozenset({"coding"}), frozenset({"user-selected"})),
                ToolCapability("credential.access", frozenset({"coding"}), frozenset({"temporary"})),
            )
        registry.register(
            ToolDefinition(
                name=spec["name"],
                description=spec["description"],
                parameters=spec["parameters"],
                modes=modes,
                permission_level="write" if spec["name"] in {"github_create_pr", "github_comment_issue", "github_request_review"} else "read",
                parallel=spec["name"] in {"github_read_issue"},
                capabilities=capabilities,
            )
        )
    registry.register(
        ToolDefinition(
            name="read_file",
            description="Read file content with pagination and line numbers.",
            parameters={
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "offset": {"type": "integer"},
                    "limit": {"type": "integer"},
                },
                "required": ["path"],
            },
            modes=["all"],
            permission_level="read",
            parallel=True,
        )
    )
    registry.register(
        ToolDefinition(
            name="write_file",
            description="Overwrite a file and create parent directories.",
            parameters={
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "content": {"type": "string"},
                },
                "required": ["path", "content"],
            },
            modes=["coding"],
            permission_level="write",
            parallel=False,
        )
    )
    registry.register(
        ToolDefinition(
            name="multi_edit",
            description=(
                "Apply multiple search-and-replace edits to a single file in one call. "
                "If any edit fails to match, no changes are written."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "File path"},
                    "edits": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "old_text": {"type": "string"},
                                "new_text": {"type": "string"},
                            },
                            "required": ["old_text", "new_text"],
                        },
                        "description": "List of edits to apply",
                    },
                },
                "required": ["path", "edits"],
            },
            modes=["coding"],
            permission_level="write",
            parallel=False,
        )
    )
    registry.register(
        ToolDefinition(
            name="patch",
            description="Apply an atomic find-and-replace patch to a file.",
            parameters={
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "old": {"type": "string"},
                    "new": {"type": "string"},
                    "fuzzy": {"type": "boolean"},
                },
                "required": ["path", "old", "new"],
            },
            modes=["coding"],
            permission_level="write",
            parallel=False,
        )
    )
    registry.register(
        ToolDefinition(
            name="search_files",
            description="Search filenames by glob or file contents by text.",
            parameters={
                "type": "object",
                "properties": {
                    "root": {"type": "string"},
                    "query": {"type": "string"},
                    "glob": {"type": "string"},
                    "content": {"type": "boolean"},
                    "limit": {"type": "integer"},
                },
            },
            modes=["all"],
            permission_level="read",
            parallel=True,
        )
    )
    registry.register(
        ToolDefinition(
            name="list_directory",
            description="List directory contents with structured info (dirs, files, sizes).",
            parameters={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Directory path (default: current directory)",
                        "default": ".",
                    }
                },
                "required": [],
            },
            modes=["office", "coding"],
            permission_level="read",
            parallel=True,
        )
    )
    registry.register(
        ToolDefinition(
            name="file_info",
            description=(
                "Get detailed file/directory metadata "
                "(size, type, modified date, mime type)."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "File or directory path"}
                },
                "required": ["path"],
            },
            modes=["office", "coding"],
            permission_level="read",
            parallel=True,
        )
    )
    registry.register(
        ToolDefinition(
            name="tree_view",
            description="Generate a tree view of a directory structure.",
            parameters={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "default": "."},
                    "max_depth": {
                        "type": "integer",
                        "description": "Max recursion depth (default 3)",
                        "default": 3,
                    },
                },
                "required": [],
            },
            modes=["office", "coding"],
            permission_level="read",
            parallel=True,
        )
    )
    registry.register(
        ToolDefinition(
            name="copy_file",
            description="Copy a file or directory.",
            parameters={
                "type": "object",
                "properties": {
                    "src": {"type": "string"},
                    "dst": {"type": "string"},
                },
                "required": ["src", "dst"],
            },
            modes=["office", "coding"],
            permission_level="write",
            parallel=False,
        )
    )
    registry.register(
        ToolDefinition(
            name="move_file",
            description="Move or rename a file or directory.",
            parameters={
                "type": "object",
                "properties": {
                    "src": {"type": "string"},
                    "dst": {"type": "string"},
                },
                "required": ["src", "dst"],
            },
            modes=["office", "coding"],
            permission_level="write",
            parallel=False,
        )
    )
    registry.register(
        ToolDefinition(
            name="file_search_content",
            description=(
                "Search file contents for a pattern (literal substring or "
                "RE2-linear regular expression). Patterns that would require "
                "catastrophic backtracking are rejected. Returns matching "
                "lines with file paths and line numbers."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Directory to search in",
                        "default": ".",
                    },
                    "pattern": {"type": "string"},
                    "max_results": {"type": "integer", "default": 50},
                },
                "required": ["pattern"],
            },
            modes=["office", "coding"],
            permission_level="read",
            parallel=True,
        )
    )
    registry.register(
        ToolDefinition(
            name="quick_note",
            description="Quick capture a note with optional title and tags. Saved to ~/.khaos/notes/.",
            parameters={
                "type": "object",
                "properties": {
                    "content": {"type": "string"},
                    "title": {"type": "string", "default": ""},
                    "tags": {
                        "type": "array",
                        "items": {"type": "string"},
                        "default": [],
                    },
                },
                "required": ["content"],
            },
            modes=["office"],
            permission_level="write",
            parallel=False,
        )
    )
    registry.register(
        ToolDefinition(
            name="search_notes",
            description="Search notes by query string (matches title, tags, and content).",
            parameters={
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "max_results": {"type": "integer", "default": 10},
                },
                "required": ["query"],
            },
            modes=["office"],
            permission_level="read",
            parallel=True,
        )
    )
    registry.register(
        ToolDefinition(
            name="list_notes",
            description="List recent notes, optionally filtered by tag.",
            parameters={
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "default": 20},
                    "tag": {"type": "string", "default": ""},
                },
            },
            modes=["office"],
            permission_level="read",
            parallel=True,
        )
    )
    registry.register(
        ToolDefinition(
            name="delete_note",
            description="Delete a note file. Only files under ~/.khaos/notes/ can be deleted.",
            parameters={
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
            modes=["office"],
            permission_level="write",
            parallel=False,
        )
    )
    registry.register(
        ToolDefinition(
            name="markdown_to_text",
            description="Convert Markdown to plain text, stripping all formatting.",
            parameters={
                "type": "object",
                "properties": {"markdown": {"type": "string"}},
                "required": ["markdown"],
            },
            modes=["office"],
            permission_level="read",
            parallel=True,
        )
    )
    registry.register(
        ToolDefinition(
            name="extract_headings",
            description="Extract heading structure (TOC) from Markdown text.",
            parameters={
                "type": "object",
                "properties": {"markdown": {"type": "string"}},
                "required": ["markdown"],
            },
            modes=["office"],
            permission_level="read",
            parallel=True,
        )
    )
    registry.register(
        ToolDefinition(
            name="count_words",
            description=(
                "Count words, characters, lines, paragraphs, "
                "and estimate reading time."
            ),
            parameters={
                "type": "object",
                "properties": {"text": {"type": "string"}},
                "required": ["text"],
            },
            modes=["office"],
            permission_level="read",
            parallel=True,
        )
    )
    registry.register(
        ToolDefinition(
            name="format_markdown_table",
            description="Format structured data as a Markdown table.",
            parameters={
                "type": "object",
                "properties": {
                    "headers": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                    "rows": {
                        "type": "array",
                        "items": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                    },
                },
                "required": ["headers", "rows"],
            },
            modes=["office"],
            permission_level="read",
            parallel=True,
        )
    )
    registry.register(
        ToolDefinition(
            name="clipboard_read",
            description="Read the system clipboard content.",
            parameters={"type": "object", "properties": {}},
            modes=["office"],
            permission_level="read",
            parallel=False,
        )
    )
    registry.register(
        ToolDefinition(
            name="clipboard_write",
            description="Write text to the system clipboard.",
            parameters={
                "type": "object",
                "properties": {"text": {"type": "string"}},
                "required": ["text"],
            },
            modes=["office"],
            permission_level="write",
            parallel=False,
        )
    )
    registry.register(
        ToolDefinition(
            name="terminal",
            description="Run a foreground or background terminal command.",
            parameters={
                "type": "object",
                "properties": {
                    "command": {"type": "string"},
                    "cwd": {"type": "string"},
                    "background": {"type": "boolean"},
                    "timeout": {"type": "integer"},
                },
                "required": ["command"],
            },
            modes=["coding"],
            permission_level="execute",
            parallel=False,
        )
    )
    registry.register(
        ToolDefinition(
            name="process",
            description="Poll, wait, kill, or read logs for a background process.",
            parameters={
                "type": "object",
                "properties": {
                    "action": {"type": "string"},
                    "id": {"type": "string"},
                    "timeout": {"type": "integer"},
                },
                "required": ["action", "id"],
            },
            modes=["coding"],
            permission_level="execute",
            parallel=False,
        )
    )
    registry.register(
        ToolDefinition(
            name="sandbox_exec",
            description="Run a command inside an isolated Docker sandbox.",
            parameters={
                "type": "object",
                "properties": {
                    "command": {"type": "string"},
                    "image": {"type": "string"},
                    "project_dir": {"type": "string"},
                    "network": {"type": "boolean"},
                    "timeout": {"type": "integer"},
                },
                "required": ["command"],
            },
            modes=["coding"],
            permission_level="execute",
            parallel=False,
            capabilities=(
                ToolCapability("process.execute", frozenset({"coding"}), frozenset({"task-workspace"})),
                ToolCapability("filesystem.write", frozenset({"coding"}), frozenset({"task-workspace"})),
            ),
        )
    )
    registry.register(
        ToolDefinition(
            name="sandbox_build",
            description="Build a Docker image for sandbox execution.",
            parameters={
                "type": "object",
                "properties": {
                    "dockerfile": {"type": "string"},
                    "context": {"type": "string"},
                    "tag": {"type": "string"},
                    "timeout": {"type": "integer"},
                },
                "required": ["dockerfile"],
            },
            modes=["internal"],
            permission_level="execute",
            parallel=False,
            capabilities=(
                ToolCapability("host.integration", frozenset({"internal"}), frozenset({"host-system"})),
            ),
        )
    )
    registry.register(
        ToolDefinition(
            name="git_diff",
            description="Show git diff.",
            parameters={
                "type": "object",
                "properties": {"repo": {"type": "string"}, "staged": {"type": "boolean"}},
            },
            modes=["coding"],
            permission_level="read",
            parallel=True,
        )
    )
    registry.register(
        ToolDefinition(
            name="git_commit",
            description="Create a git commit.",
            parameters={
                "type": "object",
                "properties": {"repo": {"type": "string"}, "message": {"type": "string"}},
                "required": ["message"],
            },
            modes=["coding"],
            permission_level="write",
            parallel=False,
        )
    )
    registry.register(
        ToolDefinition(
            name="git_branch",
            description="List or create git branches.",
            parameters={
                "type": "object",
                "properties": {
                    "repo": {"type": "string"},
                    "name": {"type": "string"},
                    "checkout": {"type": "boolean"},
                },
            },
            modes=["coding"],
            permission_level="write",
            parallel=False,
        )
    )
    registry.register(
        ToolDefinition(
            name="git_log",
            description="Show git log.",
            parameters={
                "type": "object",
                "properties": {"repo": {"type": "string"}, "limit": {"type": "integer"}},
            },
            modes=["coding"],
            permission_level="read",
            parallel=True,
        )
    )
    registry.register(
        ToolDefinition(
            name="test_run",
            description=(
                "Run test commands and parse results. Returns structured "
                "output with pass/fail counts and failed test details."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "Test command to run",
                    },
                    "cwd": {
                        "type": "string",
                        "description": "Working directory",
                    },
                },
                "required": ["command", "cwd"],
            },
            modes=["coding"],
            permission_level="write",
            parallel=False,
        )
    )
    registry.register(
        ToolDefinition(
            name="git_status",
            description="Get current git status (branch, modified/added/deleted/untracked files).",
            parameters={
                "type": "object",
                "properties": {
                    "cwd": {
                        "type": "string",
                        "description": "Working directory",
                    },
                },
                "required": ["cwd"],
            },
            modes=["coding", "office"],
            permission_level="read",
            parallel=True,
        )
    )
    registry.register(
        ToolDefinition(
            name="git_smart_commit",
            description=(
                "Stage all changes and commit with an auto-generated or custom "
                "conventional commit message."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "cwd": {
                        "type": "string",
                        "description": "Working directory",
                    },
                    "message": {
                        "type": "string",
                        "description": "Optional commit message. Auto-generated if empty.",
                    },
                },
                "required": ["cwd"],
            },
            modes=["coding"],
            permission_level="write",
            parallel=False,
        )
    )
    registry.register(
        ToolDefinition(
            name="git_undo",
            description="Undo the last commit, keeping file changes staged (soft reset).",
            parameters={
                "type": "object",
                "properties": {
                    "cwd": {
                        "type": "string",
                        "description": "Working directory",
                    },
                },
                "required": ["cwd"],
            },
            modes=["coding"],
            permission_level="write",
            parallel=False,
        )
    )
    registry.register(
        ToolDefinition(
            name="git_create_branch",
            description="Create and switch to a new branch off a base branch (default: main).",
            parameters={
                "type": "object",
                "properties": {
                    "cwd": {
                        "type": "string",
                        "description": "Working directory",
                    },
                    "branch_name": {
                        "type": "string",
                        "description": "Branch name (e.g. fix/login-bug, feat/add-auth)",
                    },
                    "from_base": {
                        "type": "string",
                        "description": "Base branch to branch off (default: main)",
                        "default": "main",
                    },
                },
                "required": ["cwd", "branch_name"],
            },
            modes=["coding"],
            permission_level="write",
            parallel=False,
        )
    )
    registry.register(
        ToolDefinition(
            name="git_push",
            description="Push the current (or named) branch to a remote, setting up tracking.",
            parameters={
                "type": "object",
                "properties": {
                    "cwd": {
                        "type": "string",
                        "description": "Working directory",
                    },
                    "remote": {
                        "type": "string",
                        "description": "Remote name (default: origin)",
                        "default": "origin",
                    },
                    "branch": {
                        "type": "string",
                        "description": "Branch to push (empty = current branch)",
                    },
                },
                "required": ["cwd"],
            },
            modes=["coding"],
            permission_level="write",
            parallel=False,
            capabilities=(
                ToolCapability("process.execute", frozenset({"coding"}), frozenset({"task-workspace"})),
                ToolCapability("vcs.remote-write", frozenset({"coding"}), frozenset({"task-workspace"})),
                ToolCapability("network.access", frozenset({"coding"}), frozenset({"user-selected"})),
                ToolCapability("credential.access", frozenset({"coding"}), frozenset({"temporary"})),
            ),
        )
    )
    registry.register(
        ToolDefinition(
            name="git_pr_body",
            description=(
                "Generate a PR description draft (title, body, changed files) "
                "from the current branch's commits relative to main."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "cwd": {
                        "type": "string",
                        "description": "Working directory",
                    },
                },
                "required": ["cwd"],
            },
            modes=["coding"],
            permission_level="read",
            parallel=True,
        )
    )
    registry.register(
        ToolDefinition(
            name="todo_write",
            description="Write or append to a todo list. Use this to track your plan and progress.",
            parameters={
                "type": "object",
                "properties": {
                    "append": {
                        "type": "boolean",
                        "description": (
                            "If true, append to existing todos; if false, replace entire list"
                        ),
                    },
                    "todos": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "content": {"type": "string"},
                                "id": {"type": "string"},
                                "status": {"type": "string"},
                            },
                            "required": ["content"],
                        },
                    },
                },
                "required": ["append", "todos"],
            },
            modes=["coding"],
            permission_level="read",
            parallel=False,
        )
    )
    registry.register(
        ToolDefinition(
            name="todo_read",
            description="Read the current todo list.",
            parameters={"type": "object", "properties": {}},
            modes=["coding"],
            permission_level="read",
            parallel=True,
        )
    )
    registry.register(
        ToolDefinition(
            name="todo_update",
            description="Update a todo item's status (pending/in_progress/completed).",
            parameters={
                "type": "object",
                "properties": {
                    "todo_id": {"type": "string"},
                    "status": {
                        "type": "string",
                        "enum": ["pending", "in_progress", "completed"],
                    },
                },
                "required": ["todo_id", "status"],
            },
            modes=["coding"],
            permission_level="read",
            parallel=False,
        )
    )
    # ── Phase 6 browser tools (Playwright-backed, mock fallback) ──
    # B1/H1: browser tools now declare explicit capabilities so the
    # capability broker gates them correctly:
    #   * navigation / click / type / evaluate / upload carry
    #     ``network.access`` (they can trigger navigation or form
    #     submission, which is a network side effect);
    #   * ``browser_file_upload`` also carries ``filesystem.read`` (it
    #     reads a host file) and is added to
    #     ``_OFFICE_WORKSPACE_FILE_TOOLS`` so the broker injects
    #     ``workspace_root`` for path containment validation;
    #   * snapshot / screenshot / scroll / vision are read-only page
    #     inspection (``filesystem.read`` — no network side effect).
    _BROWSER_MODES = frozenset({"office", "coding"})
    # read-permission tools
    for name, description, parameters, capabilities in [
        (
            "browser_launch",
            "Launch a browser instance (Chromium/Firefox/WebKit). Must be called before other browser tools.",
            {
                "type": "object",
                "properties": {
                    "headless": {
                        "type": "boolean",
                        "description": "Run in headless mode (default true)",
                        "default": True,
                    },
                    "browser_type": {
                        "type": "string",
                        "enum": ["chromium", "firefox", "webkit"],
                        "description": "Browser engine to use",
                        "default": "chromium",
                    },
                },
            },
            (ToolCapability("host.integration", _BROWSER_MODES, frozenset({"app-data"})),),
        ),
        (
            "browser_close",
            "Close the browser instance and release resources.",
            {"type": "object", "properties": {}},
            (ToolCapability("host.integration", _BROWSER_MODES, frozenset({"app-data"})),),
        ),
        (
            "browser_navigate",
            "Navigate to a URL and wait for the page to load.",
            {
                "type": "object",
                "properties": {"url": {"type": "string", "description": "URL to navigate to"}},
                "required": ["url"],
            },
            (ToolCapability("network.access", _BROWSER_MODES, frozenset({"user-selected"})),),
        ),
        (
            "browser_click",
            "Click an element by CSS selector, text=, or XPath.",
            {
                "type": "object",
                "properties": {
                    "selector": {
                        "type": "string",
                        "description": "CSS selector, text=Label, or xpath=//expression",
                    }
                },
                "required": ["selector"],
            },
            # B1/H1: click can trigger navigation / form submission → network.
            (ToolCapability("network.access", _BROWSER_MODES, frozenset({"user-selected"})),),
        ),
        (
            "browser_snapshot",
            "Get the current page DOM content (HTML).",
            {"type": "object", "properties": {}},
            (ToolCapability("filesystem.read", _BROWSER_MODES, frozenset({"app-data"})),),
        ),
        (
            "browser_screenshot",
            "Take a screenshot and return base64 without writing a file.",
            {"type": "object", "properties": {}},
            (ToolCapability("filesystem.read", _BROWSER_MODES, frozenset({"app-data"})),),
        ),
        (
            "browser_scroll",
            "Scroll the page up or down.",
            {
                "type": "object",
                "properties": {
                    "direction": {"type": "string", "enum": ["up", "down"]},
                    "amount": {
                        "type": "integer",
                        "description": "Scroll amount multiplier (default 3)",
                        "default": 3,
                    },
                },
                "required": ["direction"],
            },
            (ToolCapability("filesystem.read", _BROWSER_MODES, frozenset({"app-data"})),),
        ),
        (
            "browser_vision",
            "Get a text description of the current page state (URL, title).",
            {"type": "object", "properties": {}},
            (ToolCapability("filesystem.read", _BROWSER_MODES, frozenset({"app-data"})),),
        ),
    ]:
        registry.register(
            ToolDefinition(
                name=name,
                description=description,
                parameters=parameters,
                modes=["office", "coding"],
                permission_level="read",
                parallel=False,
                capabilities=capabilities,
            )
        )
    # write-permission browser tools
    for name, description, parameters, capabilities in [
        (
            "browser_type",
            "Type text into an input field (clears existing text first).",
            {
                "type": "object",
                "properties": {
                    "selector": {"type": "string"},
                    "text": {"type": "string"},
                    "press_enter": {
                        "type": "boolean",
                        "description": "Press Enter after typing",
                        "default": False,
                    },
                },
                "required": ["selector", "text"],
            },
            # B1/H1: press_enter can submit a form → network.
            (ToolCapability("network.access", _BROWSER_MODES, frozenset({"user-selected"})),),
        ),
        (
            "browser_evaluate",
            "Execute JavaScript in the browser page context.",
            {
                "type": "object",
                "properties": {
                    "expression": {
                        "type": "string",
                        "description": "JavaScript expression to evaluate",
                    }
                },
                "required": ["expression"],
            },
            # B1/H1: arbitrary JS can issue network requests, change location,
            # submit forms — gate behind network.access.  The regex block on
            # fetch/XHR/WebSocket/sendBeacon remains as defense in depth.
            (ToolCapability("network.access", _BROWSER_MODES, frozenset({"user-selected"})),),
        ),
        (
            "browser_file_upload",
            "Upload a file to a file input element.",
            {
                "type": "object",
                "properties": {
                    "selector": {"type": "string"},
                    "file_path": {
                        "type": "string",
                        "description": "Absolute path to file (must be within workspace root)",
                    },
                },
                "required": ["selector", "file_path"],
            },
            # B1: reads a host file (filesystem.read) AND uploads it to a web
            # page (network.access).  The broker injects ``workspace_root``
            # because browser_file_upload is in ``_OFFICE_WORKSPACE_FILE_TOOLS``;
            # the handler validates the path is contained within the workspace
            # root (no symlink escape, no arbitrary host file exfiltration).
            (
                ToolCapability("filesystem.read", _BROWSER_MODES, frozenset({"user-selected"})),
                ToolCapability("network.access", _BROWSER_MODES, frozenset({"user-selected"})),
            ),
        ),
    ]:
        registry.register(
            ToolDefinition(
                name=name,
                description=description,
                parameters=parameters,
                modes=["office", "coding"],
                permission_level="write",
                parallel=False,
                capabilities=capabilities,
            )
        )
    # ── Phase 6 web content tools (HTML→Markdown, tables, metadata) ──
    _WEB_NETWORK_CAP = ToolCapability(
        "network.access",
        frozenset({"office", "coding"}),
        frozenset({"user-selected"}),
    )
    for name, description, parameters in [
        (
            "web_fetch",
            "Fetch a webpage and extract its content as clean Markdown. Strips ads, navigation, scripts, and formatting noise.",
            {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "URL to fetch"},
                    "timeout": {
                        "type": "integer",
                        "description": "Request timeout in seconds (default 30)",
                        "default": 30,
                    },
                },
                "required": ["url"],
            },
        ),
        (
            "web_extract_tables",
            "Extract structured table data from a webpage.",
            {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "URL containing tables"}
                },
                "required": ["url"],
            },
        ),
        (
            "web_metadata",
            "Get webpage metadata (title, description, author) without downloading full content.",
            {
                "type": "object",
                "properties": {"url": {"type": "string", "description": "URL to inspect"}},
                "required": ["url"],
            },
        ),
    ]:
        registry.register(
            ToolDefinition(
                name=name,
                description=description,
                parameters=parameters,
                modes=["office", "coding"],
                permission_level="read",
                parallel=True,
                capabilities=(_WEB_NETWORK_CAP,),
            )
        )
    registry.register(
        ToolDefinition(
            name="code_search",
            description="Search code files for text.",
            parameters={
                "type": "object",
                "properties": {
                    "root": {"type": "string"},
                    "query": {"type": "string"},
                    "glob": {"type": "string"},
                    "limit": {"type": "integer"},
                },
                "required": ["query"],
            },
            modes=["coding"],
            permission_level="read",
            parallel=True,
        )
    )
    registry.register(
        ToolDefinition(
            name="code_symbols",
            description="Extract symbols from a Python source file.",
            parameters={
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
            modes=["coding"],
            permission_level="read",
            parallel=True,
        )
    )
    # ── Phase 8.3 orchestrator tools (subagent spawn / collect / plan) ──
    # MEDIUM (batch 3.1.8): the four orchestrator tools declare the
    # ``subagent.spawn`` capability so ``ToolInvocationBroker.invoke``
    # injects ``principal_id`` into the handler kwargs.  Without a
    # declared capability the broker treats them as no-capability tools
    # and the handlers receive ``principal_id=""`` even when the caller
    # is authenticated — the spawner then returns an empty list for an
    # empty principal, so ``collect_results`` / ``subagent_status`` can
    # never observe tasks spawned via ``spawn_subagent``.
    _SUBAGENT_SPAWN_CAP = ToolCapability(
        "subagent.spawn",
        frozenset({"office", "coding"}),
        frozenset({"app-data"}),
    )
    registry.register(
        ToolDefinition(
            name="spawn_subagent",
            description=(
                "Spawn a subagent to execute a task in parallel. "
                "The subagent runs independently with its own context and tool set."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "goal": {
                        "type": "string",
                        "description": "Task description for the subagent",
                    },
                    "context": {
                        "type": "string",
                        "description": "Additional context for the subagent",
                        "default": "",
                    },
                    "tools": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Tools available to the subagent (empty = all tools)",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Timeout in seconds (default 300)",
                        "default": 300,
                    },
                },
                "required": ["goal"],
            },
            modes=["office", "coding"],
            permission_level="write",
            parallel=False,
            capabilities=(_SUBAGENT_SPAWN_CAP,),
        )
    )
    registry.register(
        ToolDefinition(
            name="collect_results",
            description="Wait for all running subagents to complete and collect their results.",
            parameters={"type": "object", "properties": {}},
            modes=["office", "coding"],
            permission_level="read",
            parallel=False,
            capabilities=(_SUBAGENT_SPAWN_CAP,),
        )
    )
    registry.register(
        ToolDefinition(
            name="execute_plan",
            description=(
                "Execute a task plan (JSON) with dependencies. Tasks without "
                "dependencies run in parallel; dependent tasks wait for their "
                "upstream to complete."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "plan_json": {
                        "type": "string",
                        "description": "JSON task plan with tasks, dependencies, and context",
                    },
                },
                "required": ["plan_json"],
            },
            modes=["office", "coding"],
            permission_level="write",
            parallel=False,
            capabilities=(_SUBAGENT_SPAWN_CAP,),
        )
    )
    registry.register(
        ToolDefinition(
            name="subagent_status",
            description="Check the status of all subagents without waiting.",
            parameters={"type": "object", "properties": {}},
            modes=["office", "coding"],
            permission_level="read",
            parallel=True,
            capabilities=(_SUBAGENT_SPAWN_CAP,),
        )
    )
    # M4 batch 3.1.16A-4-4-1 (CRITICAL): the five permission tools
    # declare ``permission.read`` / ``permission.manage`` so
    # ``ToolInvocationBroker.invoke`` injects the caller's
    # ``principal_id`` + ``permission_engine`` + ``audit_logger`` from
    # ``tool_context``.  Without a declared capability the broker treats
    # them as no-capability tools and the handlers receive
    # ``principal_id=""`` / ``permission_engine=None`` /
    # ``audit_logger=None`` — fail-closed returns ``not initialized``
    # for every call, breaking permission administration entirely.
    # Worse, before A-4-4-1 the handlers read module-global holders
    # that were last-write-wins across concurrent principals — see
    # ``permission_tools.py`` docstring for the race description.
    _PERMISSION_READ_CAP = ToolCapability(
        "permission.read",
        frozenset({"office"}),
        frozenset({"app-data"}),
    )
    _PERMISSION_MANAGE_CAP = ToolCapability(
        "permission.manage",
        frozenset({"office"}),
        frozenset({"app-data"}),
    )
    registry.register(
        ToolDefinition(
            name="list_permission_rules",
            description="List all permission rules (patterns, approval modes, scopes).",
            parameters={"type": "object", "properties": {}},
            modes=["office"],
            permission_level="read",
            parallel=True,
            capabilities=(_PERMISSION_READ_CAP,),
        )
    )
    registry.register(
        ToolDefinition(
            name="grant_permission",
            description="Grant a permission rule to auto-approve or deny a tool pattern.",
            parameters={
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "Glob pattern (e.g. /home/user/**)",
                    },
                    "permission_level": {
                        "type": "string",
                        "enum": ["read", "write"],
                        "description": "Permission level",
                    },
                    "approval": {
                        "type": "string",
                        "enum": ["auto-approve", "ask-every", "deny"],
                        "default": "auto-approve",
                    },
                    "mode": {
                        "type": "string",
                        "enum": ["office", "coding", "all"],
                        "default": "all",
                    },
                },
                "required": ["pattern", "permission_level"],
            },
            modes=["office"],
            permission_level="write",
            parallel=False,
            capabilities=(_PERMISSION_MANAGE_CAP,),
        )
    )
    registry.register(
        ToolDefinition(
            name="revoke_permission",
            description="Revoke a permission rule by its ID.",
            parameters={
                "type": "object",
                "properties": {"rule_id": {"type": "integer"}},
                "required": ["rule_id"],
            },
            modes=["office"],
            permission_level="write",
            parallel=False,
            capabilities=(_PERMISSION_MANAGE_CAP,),
        )
    )
    registry.register(
        ToolDefinition(
            name="query_audit_logs",
            description="Query audit logs (permission decisions, tool executions).",
            parameters={
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "description": "Filter by tool/action name",
                    },
                    "result": {
                        "type": "string",
                        "enum": ["approved", "denied", "error", "success"],
                        "description": "Filter by result type",
                    },
                    "limit": {"type": "integer", "default": 50},
                },
            },
            modes=["office"],
            permission_level="read",
            parallel=True,
            capabilities=(_PERMISSION_READ_CAP,),
        )
    )
    registry.register(
        ToolDefinition(
            name="security_status",
            description="Get security status overview (rule count, recent denials).",
            parameters={"type": "object", "properties": {}},
            modes=["office"],
            permission_level="read",
            parallel=True,
            capabilities=(_PERMISSION_READ_CAP,),
        )
    )
    # Hermes batch 5: cron + history tools (available in all modes).
    # M4 batch 3.1.10 (CRITICAL): the five cron tools declare the
    # ``cron.manage`` capability so ``ToolInvocationBroker.invoke``
    # injects the caller's ``principal_id`` into the handler kwargs.
    # Without a declared capability the broker treats them as
    # no-capability tools and the handlers receive ``principal_id=""``
    # even when the caller is authenticated — the engine then raises
    # ``ValueError("principal_id is required for scheduled task creation")``
    # on create, and list / pause / resume / remove cannot filter by
    # owner, so any principal could observe or mutate another
    # principal's tasks.  See ``cron_tools._require_principal`` and
    # ``CronEngine._check_principal`` for the fail-closed enforcement.
    _CRON_MANAGE_CAP = ToolCapability(
        "cron.manage",
        frozenset({"office", "coding"}),
        frozenset({"app-data"}),
    )
    # M4 batch 3.1.16A-4-4-2: the three history tools declare
    # ``history.read`` so the broker injects the caller's
    # ``principal_id`` + ``db`` from ``tool_context``.  The handler
    # constructs a fresh ``SessionSearch(db, principal_id=principal_id)``
    # per call — no module-global holder, no cross-principal leak.
    _HISTORY_READ_CAP = ToolCapability(
        "history.read",
        frozenset({"office", "coding"}),
        frozenset({"app-data"}),
    )
    # M4 batch 3.1.16A-4-4-3: the four channel tools' capabilities
    # (``channel.read`` / ``channel.manage``) are declared inside
    # ``register_builtin_tools`` (they need to be set at registration
    # time so the broker gate fires).  Nothing to do here — handler
    # binding happens below.
    for spec in CRON_TOOL_SPECS:
        registry.register(
            ToolDefinition(
                name=spec["name"],
                description=spec["description"],
                parameters=spec["parameters"],
                modes=["all"],
                permission_level="write",
                parallel=False,
                capabilities=(_CRON_MANAGE_CAP,),
            )
        )
    for spec in HISTORY_TOOL_SPECS:
        registry.register(
            ToolDefinition(
                name=spec["name"],
                description=spec["description"],
                parameters=spec["parameters"],
                modes=["all"],
                permission_level="read",
                parallel=True,
                # M4 batch 3.1.16A-4-4-2: the three history tools declare
                # ``history.read`` so ``ToolInvocationBroker.invoke``
                # injects the caller's ``principal_id`` + ``db`` from
                # ``tool_context``.  Without a declared capability the
                # broker treats them as no-capability tools and the
                # handlers receive ``principal_id=""`` / ``db=None`` —
                # fail-closed returns ``unavailable`` for every call,
                # breaking session history search entirely.  Worse,
                # before A-4-4-2 the handlers read a module-global
                # ``_session_search`` holder that was never wired in
                # production (dead code) — see ``history_tools.py``
                # docstring for details.
                capabilities=(_HISTORY_READ_CAP,),
            )
        )


def create_builtin_registry() -> ToolRegistry:
    """Create a registry with the Phase 1 built-in declarations."""
    registry = ToolRegistry(
        enforce_capabilities=True,
        capability_manifest=_BUILTIN_CAPABILITY_MANIFEST,
    )
    register_builtin_tools(registry)
    return registry


def create_runtime_registry() -> ToolRegistry:
    """Create a built-in registry with concrete P0-B tool handlers."""
    from khaos.tools import (
        browser_tools,
        channel_tools,
        clipboard_tools,
        code_search_tools,
        cron_tools,
        file_tools,
        git_tools,
        github_tools,
        history_tools,
        markdown_tools,
        note_tools,
        permission_tools,
        sandbox_tools,
        terminal_tools,
        test_tools,
        todo_tools,
        web_tools,
    )

    registry = create_builtin_registry()
    registry.get("channel_list").handler = channel_tools.channel_list
    registry.get("channel_health").handler = channel_tools.channel_health
    registry.get("channel_enable").handler = channel_tools.channel_enable
    registry.get("channel_disable").handler = channel_tools.channel_disable
    registry.get("github_create_pr").handler = github_tools.github_create_pr
    registry.get("github_read_issue").handler = github_tools.github_read_issue
    registry.get("github_comment_issue").handler = github_tools.github_comment_issue
    registry.get("github_request_review").handler = github_tools.github_request_review
    registry.get("read_file").handler = file_tools.read_file
    registry.get("write_file").handler = file_tools.write_file
    registry.get("patch").handler = file_tools.patch
    registry.get("multi_edit").handler = file_tools.multi_edit
    registry.get("search_files").handler = file_tools.search_files
    registry.get("list_directory").handler = file_tools.list_directory
    registry.get("file_info").handler = file_tools.file_info
    registry.get("tree_view").handler = file_tools.tree_view
    registry.get("copy_file").handler = file_tools.copy_file
    registry.get("move_file").handler = file_tools.move_file
    registry.get("file_search_content").handler = file_tools.file_search_content
    registry.get("quick_note").handler = note_tools.quick_note
    registry.get("search_notes").handler = note_tools.search_notes
    registry.get("list_notes").handler = note_tools.list_notes
    registry.get("delete_note").handler = note_tools.delete_note
    registry.get("markdown_to_text").handler = markdown_tools.markdown_to_text
    registry.get("extract_headings").handler = markdown_tools.extract_headings
    registry.get("count_words").handler = markdown_tools.count_words
    registry.get("format_markdown_table").handler = markdown_tools.format_markdown_table
    registry.get("clipboard_read").handler = clipboard_tools.clipboard_read
    registry.get("clipboard_write").handler = clipboard_tools.clipboard_write
    registry.get("terminal").handler = terminal_tools.terminal
    registry.get("process").handler = terminal_tools.process
    registry.get("sandbox_exec").handler = sandbox_tools.sandbox_exec
    registry.get("sandbox_build").handler = sandbox_tools.sandbox_build
    registry.get("git_diff").handler = git_tools.git_diff
    registry.get("git_commit").handler = git_tools.git_commit
    registry.get("git_branch").handler = git_tools.git_branch
    registry.get("git_log").handler = git_tools.git_log
    registry.get("git_status").handler = git_tools.git_status
    registry.get("git_smart_commit").handler = git_tools.git_smart_commit
    registry.get("git_undo").handler = git_tools.git_undo
    registry.get("git_create_branch").handler = git_tools.git_create_branch
    registry.get("git_push").handler = git_tools.git_push
    registry.get("git_pr_body").handler = git_tools.git_pr_body
    registry.get("test_run").handler = test_tools.test_run
    # Phase 6 browser tools — all backed by browser_tools (Playwright or mock)
    registry.get("browser_launch").handler = browser_tools.browser_launch
    registry.get("browser_close").handler = browser_tools.browser_close
    registry.get("browser_navigate").handler = browser_tools.browser_navigate
    registry.get("browser_click").handler = browser_tools.browser_click
    registry.get("browser_type").handler = browser_tools.browser_type
    registry.get("browser_snapshot").handler = browser_tools.browser_snapshot
    registry.get("browser_screenshot").handler = browser_tools.browser_screenshot
    registry.get("browser_scroll").handler = browser_tools.browser_scroll
    registry.get("browser_vision").handler = browser_tools.browser_vision
    registry.get("browser_evaluate").handler = browser_tools.browser_evaluate
    registry.get("browser_file_upload").handler = browser_tools.browser_file_upload
    # Phase 6 web content tools
    registry.get("web_fetch").handler = web_tools.web_fetch
    registry.get("web_extract_tables").handler = web_tools.web_extract_tables
    registry.get("web_metadata").handler = web_tools.web_metadata
    registry.get("code_search").handler = code_search_tools.code_search
    registry.get("code_symbols").handler = code_search_tools.code_symbols
    registry.get("todo_write").handler = todo_tools.todo_write
    registry.get("todo_read").handler = todo_tools.todo_read
    registry.get("todo_update").handler = todo_tools.todo_update
    # Phase 8.3 orchestrator tools
    from khaos.tools import orchestrator_tools

    registry.get("spawn_subagent").handler = orchestrator_tools.spawn_subagent
    registry.get("collect_results").handler = orchestrator_tools.collect_results
    registry.get("execute_plan").handler = orchestrator_tools.execute_plan
    registry.get("subagent_status").handler = orchestrator_tools.subagent_status
    registry.get("list_permission_rules").handler = permission_tools.list_permission_rules
    registry.get("grant_permission").handler = permission_tools.grant_permission
    registry.get("revoke_permission").handler = permission_tools.revoke_permission
    registry.get("query_audit_logs").handler = permission_tools.query_audit_logs
    registry.get("security_status").handler = permission_tools.security_status
    # Hermes batch 5: cron + history tool handlers.
    registry.get("cron_create").handler = cron_tools.cron_create
    registry.get("cron_list").handler = cron_tools.cron_list
    registry.get("cron_remove").handler = cron_tools.cron_remove
    registry.get("cron_pause").handler = cron_tools.cron_pause
    registry.get("cron_resume").handler = cron_tools.cron_resume
    registry.get("history_search").handler = history_tools.history_search
    registry.get("history_browse").handler = history_tools.history_browse
    registry.get("history_read").handler = history_tools.history_read
    return registry
