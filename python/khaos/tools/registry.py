"""Declarative tool registry and JSON Schema validation."""

from __future__ import annotations

import hashlib
import inspect
import json
import os
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from khaos.agent.approval import StepExecutionAuthority
from khaos.exceptions import ToolNotFoundError
from khaos.permissions.resource import (
    ResourceResolver,
    resolve_copy_or_move,
    resolve_network_origin,
    resolve_process_control,
    resolve_single_workspace_path,
    resolve_terminal_argv,
    resolve_terminal_shell,
    resolve_workspace_root,
)
from khaos.tools import schema as tool_schema

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
_INJECTED_CAPABILITY_FIELDS = frozenset({
    "execution_service", "workspace_manager", "approval_context",
    "principal_id", "project_id", "runtime_id", "network_guard",
    "network_lease",
    "credential_context", "process_supervisor", "process_authority",
    "browser_manager", "cron_engine",
})


def _local_principal_id() -> str:
    """Return the local interactive principal without importing runtime.

    ``registry`` is imported by the runtime factory, so importing the
    runtime package here would create a circular dependency.  Keep this
    tiny platform adapter local; the runtime context exposes the same
    contract to higher-level callers.
    """
    try:
        uid: int | str = os.getuid()
    except AttributeError:
        uid = "windows"
    return f"local-uid:{uid}"

# Effect classification is an explicit reviewed declaration, never derived
# from ``permission_level``.  Tools omitted from these sets remain
# ``unknown`` and therefore cannot invite a blind retry after a handler has
# started.  This map is intentionally kept here, next to the tool contracts,
# so adding a side-effecting tool requires an explicit security decision.
_EFFECT_NOT_APPLIED = "not_applied"
_EFFECT_APPLIED = "applied"
_EFFECT_UNKNOWN = "unknown"
_EFFECT_PARTIAL = "partial"
_BUILTIN_EFFECT_STATUS: dict[str, str] = {
    **{
        name: _EFFECT_NOT_APPLIED
        for name in (
            "channel_list", "channel_health", "github_read_issue",
            "browser_snapshot", "browser_screenshot", "browser_vision",
            "read_file", "search_files", "list_directory", "file_info",
            "tree_view", "file_search_content", "search_notes", "list_notes",
            "markdown_to_text", "extract_headings", "count_words",
            "format_markdown_table", "clipboard_read", "git_diff", "git_log",
            "git_status", "git_pr_body", "todo_read", "history_browse",
            "history_read", "cron_list", "collect_results", "subagent_status",
            "list_permission_rules", "query_audit_logs", "security_status",
        )
    },
    **{
        name: _EFFECT_APPLIED
        for name in (
            "channel_enable", "channel_disable", "github_create_pr",
            "github_comment_issue", "github_request_review", "write_file",
            "multi_edit", "patch", "copy_file", "move_file", "quick_note",
            "delete_note", "clipboard_write", "sandbox_build", "git_commit",
            "git_branch", "git_status_write", "git_smart_commit", "git_undo",
            "git_create_branch", "git_push", "todo_write", "todo_update",
            "cron_create", "cron_remove", "cron_pause", "cron_resume",
            "spawn_subagent", "execute_plan", "grant_permission",
            "revoke_permission",
            "browser_launch", "browser_close",
        )
    },
    **{
        name: _EFFECT_UNKNOWN
        for name in (
            "browser_navigate", "browser_click", "browser_type",
            "browser_scroll", "browser_evaluate", "browser_file_upload",
        )
    },
}

class CapabilityName(str, Enum):
    COMPUTE_LOCAL = "compute.local"
    FILESYSTEM_READ = "filesystem.read"
    FILESYSTEM_WRITE = "filesystem.write"
    PROCESS_EXECUTE = "process.execute"
    NETWORK_ACCESS = "network.access"
    CREDENTIAL_ACCESS = "credential.access"
    VCS_READ = "vcs.read"
    VCS_WRITE = "vcs.write"
    VCS_REMOTE_WRITE = "vcs.remote-write"
    REMOTE_READ = "remote.read"
    REMOTE_WRITE = "remote.write"
    REMOTE_DESTRUCTIVE_WRITE = "remote.destructive-write"
    HOST_INTEGRATION = "host.integration"
    HOST_NOTES_READ = "host.notes.read"
    HOST_NOTES_WRITE = "host.notes.write"
    HOST_CLIPBOARD_READ = "host.clipboard.read"
    HOST_CLIPBOARD_WRITE = "host.clipboard.write"
    TASK_STATE_READ = "task.state.read"
    TASK_STATE_WRITE = "task.state.write"
    SUBAGENT_SPAWN = "subagent.spawn"
    PERMISSION_READ = "permission.read"
    PERMISSION_MANAGE = "permission.manage"
    CRON_MANAGE = "cron.manage"
    HISTORY_READ = "history.read"
    CHANNEL_READ = "channel.read"
    CHANNEL_MANAGE = "channel.manage"


@dataclass(frozen=True)
class ToolCapability:
    # ``name`` accepts a string literal at construction sites (e.g.
    # ``ToolCapability("process.execute", ...)``); ``__post_init__`` normalises
    # it to ``CapabilityName`` at runtime.  Pyright strict mode requires the
    # field type to admit both.
    name: CapabilityName | str
    modes: frozenset[str]
    scopes: frozenset[str]

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", CapabilityName(self.name))


def _capability(
    name: CapabilityName | str,
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
    "terminal_argv": _capability("process.execute", {"coding"}, {"task-workspace"}),
    "terminal_shell": _capability("process.execute", {"coding"}, {"task-workspace"}),
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

# The resolver is part of each ToolDefinition's security contract.  This
# manifest only supplies the reviewed built-ins during registration; custom
# production tools must declare their own resolver and cannot silently fall
# back to a name/argument heuristic in the scheduler.
_BUILTIN_RESOURCE_RESOLVERS: dict[str, ResourceResolver] = {
    **{name: resolve_single_workspace_path for name in (
        "read_file", "search_files", "list_directory", "file_info", "tree_view",
        "file_search_content", "write_file", "patch", "multi_edit", "code_search",
        "code_symbols",
    )},
    "copy_file": resolve_copy_or_move,
    "move_file": resolve_copy_or_move,
    "terminal_argv": resolve_terminal_argv,
    "terminal_shell": resolve_terminal_shell,
    "terminal": resolve_terminal_shell,
    "process": resolve_process_control,
    "test_run": resolve_terminal_shell,
    **{name: resolve_workspace_root for name in (
        "git_diff", "git_log", "git_status", "git_pr_body", "git_commit",
        "git_branch", "git_smart_commit", "git_undo", "git_create_branch",
        "git_push", "github_create_pr", "github_read_issue", "github_comment_issue",
        "github_request_review",
    )},
    **{name: resolve_network_origin for name in (
        "browser_navigate", "web_fetch", "web_extract_tables", "web_metadata",
    )},
    **{name: resolve_workspace_root for name in (
        "sandbox_exec", "browser_launch", "browser_close", "browser_click",
        "browser_snapshot", "browser_screenshot", "browser_scroll", "browser_vision",
        "browser_type", "browser_evaluate",
    )},
    "browser_file_upload": resolve_single_workspace_path,
}


# Batch 15.6 (round-15 review §三十一–§三十四): the set of ToolDefinition
# fields that constitute the *security contract*.  After ``register()`` calls
# ``freeze()``, these fields cannot be mutated — the tool's security
# semantics are immutable for the lifetime of the registry.  ``handler`` is
# intentionally excluded: it is runtime wiring, not a security property.
# Round-17 review §十: ``implementation_id`` is also excluded from the
# frozen set (it must be settable after registration via
# :meth:`ToolDefinition.bind_handler`), but it IS included in
# :attr:`security_digest` so the handler binding is part of the approval
# contract — swapping the handler changes the digest and invalidates old
# approvals.
_SECURITY_FIELDS: frozenset[str] = frozenset({
    "name", "parameters", "modes", "permission_level",
    "parallel", "timeout", "capabilities", "resource_resolver",
    "effect_status", "reconciliation_hint", "execution_kind",
})


class _FrozenDict(dict):
    """Batch 16.5: a dict subclass that rejects mutations after freezing.

    Round-16 review §二十–§二十二: ``ToolDefinition.__setattr__`` only
    prevents top-level reassignment (``tool.parameters = ...``), but
    nested mutations (``tool.parameters["properties"]["x"] = ...``) bypass
    ``__setattr__`` entirely.  ``_FrozenDict`` overrides every mutator to
    raise ``TypeError``, and ``_deep_freeze`` recursively converts nested
    dicts and lists so the entire security contract is deeply immutable.

    ``_FrozenDict`` IS a ``dict`` subclass, so ``isinstance(x, dict)`` and
    ``json.dumps(x)`` continue to work — only writes are rejected.
    """

    def __setitem__(self, key: Any, value: Any) -> None:
        raise TypeError(
            f"frozen security contract: cannot set {key!r}"
        )

    def __delitem__(self, key: Any) -> None:
        raise TypeError(
            f"frozen security contract: cannot delete {key!r}"
        )

    def pop(self, *args: Any, **kwargs: Any) -> Any:  # type: ignore[override]
        raise TypeError("frozen security contract: cannot pop")

    def popitem(self, *args: Any, **kwargs: Any) -> Any:  # type: ignore[override]
        raise TypeError("frozen security contract: cannot popitem")

    def clear(self) -> None:
        raise TypeError("frozen security contract: cannot clear")

    def update(self, *args: Any, **kwargs: Any) -> None:  # type: ignore[override]
        raise TypeError("frozen security contract: cannot update")

    def setdefault(self, *args: Any, **kwargs: Any) -> Any:  # type: ignore[override]
        raise TypeError("frozen security contract: cannot setdefault")


class _FrozenList(list):
    """Batch 16.5: a list subclass that rejects mutations after freezing.

    Unlike converting lists to tuples (which breaks ``isinstance(x, list)``
    and equality checks like ``["path"] == ("path",)``), ``_FrozenList``
    IS a ``list`` subclass so JSON serialization, ``isinstance`` checks,
    and equality comparisons with regular lists all work correctly.
    Only writes (``append``, ``__setitem__``, ``extend``, etc.) are
    rejected.
    """

    def __setitem__(self, index: Any, value: Any) -> None:  # type: ignore[override]
        raise TypeError("frozen security contract: cannot set list item")

    def __delitem__(self, index: Any) -> None:  # type: ignore[override]
        raise TypeError("frozen security contract: cannot delete list item")

    def append(self, *args: Any, **kwargs: Any) -> None:  # type: ignore[override]
        raise TypeError("frozen security contract: cannot append")

    def extend(self, *args: Any, **kwargs: Any) -> None:  # type: ignore[override]
        raise TypeError("frozen security contract: cannot extend")

    def insert(self, *args: Any, **kwargs: Any) -> None:  # type: ignore[override]
        raise TypeError("frozen security contract: cannot insert")

    def remove(self, *args: Any, **kwargs: Any) -> None:  # type: ignore[override]
        raise TypeError("frozen security contract: cannot remove")

    def pop(self, *args: Any, **kwargs: Any) -> Any:  # type: ignore[override]
        raise TypeError("frozen security contract: cannot pop")

    def clear(self) -> None:  # type: ignore[override]
        raise TypeError("frozen security contract: cannot clear")

    def sort(self, *args: Any, **kwargs: Any) -> None:  # type: ignore[override]
        raise TypeError("frozen security contract: cannot sort")

    def reverse(self) -> None:  # type: ignore[override]
        raise TypeError("frozen security contract: cannot reverse")


def _deep_freeze(obj: Any) -> Any:
    """Recursively convert mutable containers to frozen subclasses.

    dict → ``_FrozenDict`` (dict subclass, rejects writes)
    list → ``_FrozenList`` (list subclass, rejects writes)
    Other types → as-is

    This prevents nested mutations like
    ``tool.parameters["properties"]["x"] = ...`` or
    ``tool.parameters["required"].append("secret")`` after the
    ``ToolDefinition`` is frozen.  Both ``_FrozenDict`` and
    ``_FrozenList`` are subclasses of their respective base types, so
    ``isinstance`` checks, ``json.dumps``, and equality comparisons with
    regular dicts/lists all work correctly — only writes are rejected.
    """
    if isinstance(obj, dict):
        return _FrozenDict({k: _deep_freeze(v) for k, v in obj.items()})
    if isinstance(obj, list):
        return _FrozenList(_deep_freeze(item) for item in obj)
    return obj


@dataclass
class ToolDefinition:
    """Declarative tool definition.

    Batch 15.6: security-relevant fields (see ``_SECURITY_FIELDS``) are
    frozen after :meth:`freeze` is called (typically at the end of
    :meth:`ToolRegistry.register`).  The ``handler`` field remains mutable
    so ``create_runtime_registry`` can wire up runtime callables after
    registration.  The :attr:`security_digest` property covers ALL security
    fields and is cached at freeze time so post-registration mutations are
    both prevented (``__setattr__``) and detectable (digest mismatch).

    Batch 16.5 (round-16 review §二十–§二十二): the freeze is now DEEP.
    Previously ``__setattr__`` only prevented top-level reassignment
    (``tool.modes = ...``), but nested mutations
    (``tool.modes.append("office")``, ``tool.parameters["properties"]["x"]
    = ...``) bypassed ``__setattr__`` entirely because they operate on the
    mutable container object, not the attribute slot.  Now ``freeze()``
    converts ``modes`` to ``tuple`` (no ``.append``) and ``parameters`` to
    a recursively frozen ``_FrozenDict`` (every mutator raises
    ``TypeError``).  This makes the cached ``security_digest`` genuinely
    tamper-proof: no post-registration mutation can change the live
    security semantics without going through ``__setattr__`` (which is
    blocked) or the frozen containers (which reject writes).
    """

    name: str
    description: str
    parameters: dict
    modes: list[str]
    permission_level: str
    parallel: bool
    timeout: int = 60
    handler: Callable[..., Awaitable[Any]] | None = None
    capabilities: tuple[ToolCapability, ...] = ()
    resource_resolver: ResourceResolver | None = None
    effect_status: str = ""
    reconciliation_hint: str = ""
    # Concrete dispatch authority used by the execution resolver.  This is a
    # security field: a tool approved for a host sandbox must never silently
    # dispatch through Docker (or vice versa).
    execution_kind: str = "host-sandbox"
    # Round-17 review §十: implementation identity.  Set via
    # :meth:`bind_handler` when the runtime handler is wired.  This field
    # is NOT a frozen security field (it must be settable after
    # registration), but it IS included in :attr:`security_digest` so the
    # handler binding is part of the approval contract.  Swapping the
    # handler without updating ``implementation_id`` is a same-process
    # mutation (out of threat model); the digest ensures that using
    # :meth:`bind_handler` to change implementations invalidates old
    # approval bindings.
    implementation_id: str = ""
    # Round-18: production bindings additionally carry a reviewed
    # implementation generation and the build/commit identity that produced
    # the callable.  These remain runtime-wiring fields but are included in
    # the approval security digest below.
    implementation_generation: str = ""
    build_identity: str = ""
    # Batch 15.6: internal freeze state — not part of the public contract.
    _frozen: bool = field(default=False, repr=False, compare=False)
    _security_digest: str | None = field(default=None, repr=False, compare=False)

    def __setattr__(self, name: str, value: Any) -> None:
        # Allow internal fields (starting with ``_``) and non-security fields
        # (notably ``handler``) to be set freely.  Security fields are
        # rejected once ``_frozen`` is True.  During ``__init__`` the
        # ``_frozen`` attribute may not exist yet, so ``getattr`` with a
        # default is used.
        if (
            not name.startswith("_")
            and getattr(self, "_frozen", False)
            and name in _SECURITY_FIELDS
        ):
            raise PermissionError(
                f"cannot mutate frozen security field '{name}' after "
                f"registration; the tool security contract is immutable"
            )
        object.__setattr__(self, name, value)

    def freeze(self) -> None:
        """Freeze security fields and cache the security digest.

        Called by :meth:`ToolRegistry.register` after all register-time
        mutations (effect_status, capabilities, resource_resolver,
        parameters) are complete.  After this call, any attempt to set a
        security field raises :class:`PermissionError`.  The
        :attr:`security_digest` is cached so subsequent reads are O(1)
        and reflect the frozen snapshot.

        Batch 16.5: the freeze is now DEEP.  ``modes`` is converted to
        ``tuple`` (``.append`` / ``.extend`` / ``__setitem__`` all fail
        on tuples) and ``parameters`` is recursively converted to
        ``_FrozenDict`` (every dict mutator raises ``TypeError``).  This
        prevents nested mutations that bypass ``__setattr__`` and would
        otherwise change the live security semantics without invalidating
        the cached ``security_digest``.
        """
        if self._frozen:
            return
        # Batch 16.5: deep-freeze mutable security containers BEFORE
        # computing the digest so the cached digest reflects the frozen
        # (immutable) structure, not the pre-freeze mutable one.
        object.__setattr__(self, "modes", tuple(self.modes))
        object.__setattr__(self, "parameters", _deep_freeze(self.parameters))
        object.__setattr__(self, "_security_digest", self._compute_security_digest())
        object.__setattr__(self, "_frozen", True)

    def bind_handler(
        self,
        handler: Callable[..., Awaitable[Any]],
        implementation_id: str,
        *,
        implementation_generation: str = "",
        build_identity: str = "",
    ) -> None:
        """Wire up the runtime handler AND record its implementation identity.

        Round-17 review §十: ``handler`` is not a frozen security field
        (it must be settable after registration via
        :meth:`create_runtime_registry`), but the ``implementation_id``
        IS included in :attr:`security_digest`.  This method sets both
        atomically and recomputes the cached digest so the handler
        binding becomes part of the approval contract.

        After this call, ``security_digest`` reflects the specific
        implementation that will execute the tool.  Swapping the handler
        via a subsequent ``bind_handler`` call changes the digest and
        invalidates approval bindings that referenced the old digest.
        Direct ``tool.handler = ...`` assignment remains possible for
        backward compatibility but does NOT update the digest —
        :meth:`bind_handler` is the contract-aware way to wire handlers.
        """
        object.__setattr__(self, "handler", handler)
        object.__setattr__(self, "implementation_id", implementation_id)
        object.__setattr__(self, "implementation_generation", implementation_generation)
        object.__setattr__(self, "build_identity", build_identity)
        # Recompute the cached digest so it includes the complete binding.
        object.__setattr__(self, "_security_digest", self._compute_security_digest())

    @property
    def schema_digest(self) -> str:
        """Stable digest of the model-visible tool contract (name + parameters).

        Kept for backward compatibility with the Go Gateway ``/api/tools``
        handshake and existing approval bindings.  For the full security
        contract digest, use :attr:`security_digest`.
        """
        payload = {
            "name": self.name,
            "parameters": self.parameters,
        }
        encoded = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    @property
    def security_digest(self) -> str:
        """Stable digest of the COMPLETE tool security contract.

        Batch 15.6: unlike :attr:`schema_digest` (which covers only
        ``name`` + ``parameters``), this digest covers ALL
        security-relevant fields: capabilities, permission_level,
        resource_resolver, effect_status, modes, parallel, timeout, and
        reconciliation_hint.  If the definition has been frozen, the
        cached value is returned; otherwise the digest is computed live
        (for pre-registration inspection).
        """
        if self._security_digest is not None:
            return self._security_digest
        return self._compute_security_digest()

    def _compute_security_digest(self) -> str:
        """Compute the security digest over all security-relevant fields.

        Round-17 review §十: ``implementation_id`` is included so the
        handler binding is part of the approval contract.  When
        :meth:`bind_handler` is used to wire (or swap) a handler, the
        digest changes and old approval bindings that referenced the
        previous digest are invalidated.
        """
        resolver_id = ""
        if self.resource_resolver is not None:
            resolver_id = (
                getattr(self.resource_resolver, "__qualname__", "")
                or getattr(self.resource_resolver, "__name__", "")
                or repr(self.resource_resolver)
            )
        payload = {
            "name": self.name,
            "parameters": self.parameters,
            "modes": sorted(self.modes),
            "permission_level": self.permission_level,
            "parallel": self.parallel,
            "timeout": self.timeout,
            "capabilities": [
                {
                    "name": str(cap.name),
                    "modes": sorted(cap.modes),
                    "scopes": sorted(cap.scopes),
                }
                for cap in self.capabilities
            ],
            "resource_resolver": resolver_id,
            "effect_status": self.effect_status,
            "reconciliation_hint": self.reconciliation_hint,
            "execution_kind": self.execution_kind,
            # Round-17 review §十: bind the implementation identity into
            # the security contract so swapping the handler invalidates
            # old approval bindings.
            "implementation_id": self.implementation_id,
            "implementation_generation": self.implementation_generation,
            "build_identity": self.build_identity,
        }
        encoded = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


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
        if not definition.effect_status:
            definition.effect_status = _BUILTIN_EFFECT_STATUS.get(
                definition.name, _EFFECT_UNKNOWN
            )
        if definition.effect_status not in {
            _EFFECT_NOT_APPLIED,
            _EFFECT_APPLIED,
            _EFFECT_UNKNOWN,
            _EFFECT_PARTIAL,
        }:
            raise ValueError(
                f"tool {definition.name} has invalid effect_status "
                f"{definition.effect_status!r}"
            )
        if self.enforce_capabilities and not definition.capabilities:
            declared = self._capability_manifest.get(definition.name)
            if not declared:
                raise ValueError(
                    f"tool {definition.name} must declare explicit capabilities"
                )
            definition.capabilities = declared
        if definition.resource_resolver is None:
            definition.resource_resolver = _BUILTIN_RESOURCE_RESOLVERS.get(
                definition.name
            )
        if self.enforce_capabilities and any(
            capability.name.startswith(("filesystem.", "process.", "network."))
            for capability in definition.capabilities
        ) and definition.resource_resolver is None:
            raise ValueError(
                f"tool {definition.name} must declare an authorization resource resolver"
            )
        if self.enforce_capabilities:
            tool_schema.validate_schema_definition(
                definition.parameters, path=f"tool:{definition.name}"
            )
            definition.parameters = tool_schema.production_schema(
                definition.parameters
            )
        # Batch 15.6: freeze security fields and cache the security digest
        # AFTER all register-time mutations are complete.  Subsequent
        # attempts to mutate security fields (name, parameters, modes,
        # permission_level, parallel, timeout, capabilities,
        # resource_resolver, effect_status, reconciliation_hint) raise
        # PermissionError.  ``handler`` remains mutable for runtime wiring.
        definition.freeze()
        self._tools[definition.name] = definition

    def get(self, name: str) -> ToolDefinition:
        """Return a registered tool or raise ToolNotFoundError."""
        try:
            return self._tools[name]
        except KeyError as exc:
            raise ToolNotFoundError(name) from exc

    def names(self) -> tuple[str, ...]:
        """Return registered model-visible tool names in stable order."""
        return tuple(sorted(self._tools))

    def exec_tool_names(self) -> frozenset[str]:
        """Return the names of tools that can invoke a shell command.

        Round-14 §7: derived from ``permission_level == "execute"`` so the
        ``PermissionEngine`` commands_require_approval gate covers every
        exec-style tool the registry knows about, not a hard-coded literal
        that silently misses newly registered ones.
        """
        return frozenset(
            name for name, tool in self._tools.items()
            if tool.permission_level == "execute"
        )

    def list_by_mode(self, mode: str) -> list[ToolDefinition]:
        """List tools available to a mode."""
        return [
            tool
            for tool in self._tools.values()
            if "all" in tool.modes or mode in tool.modes
        ]

    def gateway_view(self) -> list[dict]:
        """Export the model-visible tool catalogue for the Go Gateway.

        P1-2 (tool descriptor drift): the Go ``/api/tools`` endpoint
        previously hard-coded three tools (read_file, write_file, terminal)
        while the Python production registry registers ~59.  This method is
        the single Python-side source the Gateway reads at startup (via the
        ``Bootstrap.GetToolSchemas`` RPC handshake) so the two never drift.

        Each entry carries the tool name, modes, permission level and a
        schema digest so the Gateway can also detect drift on the wire.
        """
        return [
            {
                "name": tool.name,
                "modes": list(tool.modes),
                "permission_level": tool.permission_level,
                "schema_digest": tool.schema_digest,
                # Batch 15.6: export the full security contract digest so
                # the Gateway can detect drift on security-relevant fields
                # (capabilities, resource_resolver, effect_status, etc.)
                # that schema_digest (name + parameters only) does not cover.
                "security_digest": tool.security_digest,
            }
            for tool in sorted(self._tools.values(), key=lambda t: t.name)
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
        if any(field in params for field in _INJECTED_CAPABILITY_FIELDS):
            return False
        schema = self.get(name).parameters
        return self._validate_schema_value(schema, params)

    def capabilities_for(self, name: str) -> tuple[ToolCapability, ...]:
        return self.get(name).capabilities

    def prune(self, tool_names: list[str]) -> ToolRegistry:
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
        return tool_schema.validate_json_schema(schema, value)


class ToolInvocationBroker:
    """Uniform capability gate before any public tool handler is invoked."""

    def __init__(self, registry: ToolRegistry) -> None:
        self.registry = registry

    async def invoke(self, name: str, *, mode: str, context: dict[str, Any], **params: Any) -> Any:
        definition = self.registry.get(name)
        if context.get("step_authority_required"):
            authority = context.get("step_execution_authority")
            if not isinstance(authority, StepExecutionAuthority):
                raise PermissionError(
                    "tool invocation requires immutable StepExecutionAuthority"
                )
            if context.get("step_execution_digest") != authority.digest():
                raise PermissionError(
                    "tool invocation received a modified StepExecutionAuthority"
                )
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
            if (
                capability.name == "filesystem.write"
                and mode == "coding"
                and (
                    context.get("workspace_id") is None
                    or context.get("task_id") is None
                    or context.get("workspace_manager") is None
                )
            ):
                raise PermissionError("filesystem.write requires active TaskWorkspace")
            if (
                capability.name == "filesystem.read"
                and mode == "coding"
                and name in _WORKSPACE_FILE_TOOLS
            ) and (
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
                local_uid = _local_principal_id()
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
            handler_params["workspace_manager"] = context.get("workspace_manager")
            handler_params["process_authority"] = context.get("process_authority")
            handler_params["principal_id"] = context.get("principal_id", "")
            handler_params["project_id"] = context.get("project_id", "")
            handler_params["runtime_id"] = context.get("runtime_id", "")
            handler_params["sandbox_decision"] = context.get("sandbox_decision")
            handler_params["executable_identity"] = context.get(
                "executable_identity"
            )
            handler_params["spawn_plan"] = context.get("spawn_plan")
            handler_params["execution_authority"] = context.get(
                "execution_authority"
            )
            handler_params["network_lease"] = context.get("network_lease")
        if any(capability.name.startswith("vcs.") for capability in capabilities):
            handler_params["execution_service"] = context.get("execution_service")
            handler_params["task_id"] = context.get("task_id")
            handler_params["workspace_id"] = context.get("workspace_id")
            handler_params["approval_context"] = context.get("approval_context")
            handler_params["network_policy"] = context.get("network_policy", "none")
            handler_params["principal_id"] = context.get("principal_id")
            handler_params["requester"] = context.get("requester")
            handler_params["network_lease"] = context.get("network_lease")
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
        # cookies to another. ``browser_close`` remains a lifecycle operation;
        # every launch/page operation receives the exact runtime authority.
        # B2 + H5: also propagate ``session_id`` + ``runtime_id`` +
        # ``network_guard`` so browser tools key their BrowserContext by
        # (principal, session, runtime) AND install a Playwright
        # ``context.route("**/*")`` interceptor that gates every request,
        # redirect and subresource against the NetworkGuard's domain check
        # (closing the bypass where click / type / evaluate / upload could
        # reach a blocked domain because they don't carry a ``url`` arg).
        if (
            name.startswith("browser_")
            and name != "browser_close"
        ):
            if "principal_id" not in handler_params:
                handler_params["principal_id"] = context.get("principal_id", "")
            handler_params.setdefault("session_id", context.get("session_id", ""))
            handler_params.setdefault("runtime_id", context.get("runtime_id", ""))
            handler_params.setdefault("project_id", context.get("project_id", ""))
            handler_params.setdefault("task_id", context.get("task_id", ""))
            handler_params.setdefault("browser_manager", context.get("browser_manager"))
            handler_params.setdefault(
                "network_guard", context.get("network_guard")
            )
        if name == "browser_close":
            handler_params["browser_manager"] = context.get("browser_manager")
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
            handler_params["subagent_spawner"] = context.get("subagent_spawner")
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
            handler_params["cron_engine"] = context.get("cron_engine")
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
            handler_params["source_transport"] = context.get("source_transport")
            handler_params["session_id"] = context.get("session_id", "")
            handler_params["task_id"] = context.get("task_id", "")
            handler_params["workspace_id"] = context.get("workspace_id", "")
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
            handler_params["project_id"] = context.get("project_id", "")
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
            manager = context.get("workspace_manager")
            if manager is not None:
                manager.require(
                    str(context.get("workspace_id") or ""),
                    task_id=str(context.get("task_id") or ""),
                    principal_id=str(context.get("principal_id") or ""),
                    project_id=str(context.get("project_id") or ""),
                    runtime_id=str(context.get("runtime_id") or ""),
                )
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
        return tool_schema.validate_json_schema(schema, value)


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
            name="terminal_argv",
            description="Execute an argv vector without a shell.",
            parameters={
                "type": "object",
                "properties": {
                    "argv": {"type": "array", "items": {"type": "string"}},
                    "cwd": {"type": "string"},
                    "background": {"type": "boolean"},
                    "timeout_seconds": {"type": "integer"},
                },
                "required": ["argv"],
            },
            modes=["coding"],
            permission_level="execute",
            parallel=False,
        )
    )
    registry.register(
        ToolDefinition(
            name="terminal_shell",
            description="Execute a script with an explicitly selected shell.",
            parameters={
                "type": "object",
                "properties": {
                    "shell": {"type": "string", "enum": ["/bin/sh", "/bin/bash", "/bin/zsh"]},
                    "script": {"type": "string"},
                    "cwd": {"type": "string"},
                    "background": {"type": "boolean"},
                    "timeout_seconds": {"type": "integer"},
                },
                "required": ["shell", "script"],
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
                    "action": {"type": "string", "enum": ["poll", "wait", "kill", "log"]},
                    "id": {"type": "string"},
                    "timeout_seconds": {"type": "integer"},
                },
                "required": ["action", "id"],
            },
            modes=["coding"],
            permission_level="execute",
            parallel=False,
            execution_kind="process-control",
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
            execution_kind="docker",
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
            description="List all permission rules (typed resources, approval modes, scopes).",
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
            description="Grant a typed resource permission; generic patterns are restricted to deny/ask rules.",
            parameters={
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "Legacy glob for deny/ask rules or display text for typed rules",
                    },
                    "resource_type": {
                        "type": "string",
                        "enum": ["filesystem", "exec", "network", "process", "workspace"],
                        "description": "Typed resource family for auto-approve/suggest",
                    },
                    "resource_spec": {
                        "type": "object",
                        "description": "Canonical typed resource selector",
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


def _handler_source_digest(handler: Callable[..., Awaitable[Any]]) -> str:
    """Hash the reviewed callable source/code for runtime binding identity."""
    try:
        payload = inspect.getsource(handler).encode("utf-8")
    except (OSError, TypeError):
        code = getattr(handler, "__code__", None)
        payload = repr(
            (
                getattr(code, "co_code", b""),
                getattr(code, "co_consts", ()),
                getattr(code, "co_names", ()),
            )
        ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def create_runtime_registry() -> ToolRegistry:
    """Create a built-in registry with concrete P0-B tool handlers.

    Round-17 review §十: handlers are wired via :meth:`bind_handler` so
    the ``implementation_id`` is recorded in the security digest.  This
    binds approval contracts to the specific implementation that will
    execute the tool.
    """
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

    def _bind(name: str, handler: Callable[..., Awaitable[Any]], module: str) -> None:
        """Bind a handler to source, generation, and build identity."""
        qualname = getattr(handler, "__qualname__", handler.__name__)
        generation = os.environ.get("KHAOS_IMPLEMENTATION_GENERATION", "round18")
        build_identity = (
            os.environ.get("KHAOS_BUILD_ID")
            or os.environ.get("GITHUB_SHA")
            or "unattested-source"
        )
        impl_id = (
            f"{module}.{qualname};generation={generation};"
            f"build={build_identity};source=sha256:{_handler_source_digest(handler)}"
        )
        registry.get(name).bind_handler(
            handler,
            impl_id,
            implementation_generation=generation,
            build_identity=build_identity,
        )

    _bind("channel_list", channel_tools.channel_list, "khaos.tools.channel_tools")
    _bind("channel_health", channel_tools.channel_health, "khaos.tools.channel_tools")
    _bind("channel_enable", channel_tools.channel_enable, "khaos.tools.channel_tools")
    _bind("channel_disable", channel_tools.channel_disable, "khaos.tools.channel_tools")
    _bind("github_create_pr", github_tools.github_create_pr, "khaos.tools.github_tools")
    _bind("github_read_issue", github_tools.github_read_issue, "khaos.tools.github_tools")
    _bind("github_comment_issue", github_tools.github_comment_issue, "khaos.tools.github_tools")
    _bind("github_request_review", github_tools.github_request_review, "khaos.tools.github_tools")
    _bind("read_file", file_tools.read_file, "khaos.tools.file_tools")
    _bind("write_file", file_tools.write_file, "khaos.tools.file_tools")
    _bind("patch", file_tools.patch, "khaos.tools.file_tools")
    _bind("multi_edit", file_tools.multi_edit, "khaos.tools.file_tools")
    _bind("search_files", file_tools.search_files, "khaos.tools.file_tools")
    _bind("list_directory", file_tools.list_directory, "khaos.tools.file_tools")
    _bind("file_info", file_tools.file_info, "khaos.tools.file_tools")
    _bind("tree_view", file_tools.tree_view, "khaos.tools.file_tools")
    _bind("copy_file", file_tools.copy_file, "khaos.tools.file_tools")
    _bind("move_file", file_tools.move_file, "khaos.tools.file_tools")
    _bind("file_search_content", file_tools.file_search_content, "khaos.tools.file_tools")
    _bind("quick_note", note_tools.quick_note, "khaos.tools.note_tools")
    _bind("search_notes", note_tools.search_notes, "khaos.tools.note_tools")
    _bind("list_notes", note_tools.list_notes, "khaos.tools.note_tools")
    _bind("delete_note", note_tools.delete_note, "khaos.tools.note_tools")
    _bind("markdown_to_text", markdown_tools.markdown_to_text, "khaos.tools.markdown_tools")
    _bind("extract_headings", markdown_tools.extract_headings, "khaos.tools.markdown_tools")
    _bind("count_words", markdown_tools.count_words, "khaos.tools.markdown_tools")
    _bind("format_markdown_table", markdown_tools.format_markdown_table, "khaos.tools.markdown_tools")
    _bind("clipboard_read", clipboard_tools.clipboard_read, "khaos.tools.clipboard_tools")
    _bind("clipboard_write", clipboard_tools.clipboard_write, "khaos.tools.clipboard_tools")
    _bind("terminal_argv", terminal_tools.terminal_argv, "khaos.tools.terminal_tools")
    _bind("terminal_shell", terminal_tools.terminal_shell, "khaos.tools.terminal_tools")
    _bind("process", terminal_tools.process, "khaos.tools.terminal_tools")
    _bind("sandbox_exec", sandbox_tools.sandbox_exec, "khaos.tools.sandbox_tools")
    _bind("sandbox_build", sandbox_tools.sandbox_build, "khaos.tools.sandbox_tools")
    _bind("git_diff", git_tools.git_diff, "khaos.tools.git_tools")
    _bind("git_commit", git_tools.git_commit, "khaos.tools.git_tools")
    _bind("git_branch", git_tools.git_branch, "khaos.tools.git_tools")
    _bind("git_log", git_tools.git_log, "khaos.tools.git_tools")
    _bind("git_status", git_tools.git_status, "khaos.tools.git_tools")
    _bind("git_smart_commit", git_tools.git_smart_commit, "khaos.tools.git_tools")
    _bind("git_undo", git_tools.git_undo, "khaos.tools.git_tools")
    _bind("git_create_branch", git_tools.git_create_branch, "khaos.tools.git_tools")
    _bind("git_push", git_tools.git_push, "khaos.tools.git_tools")
    _bind("git_pr_body", git_tools.git_pr_body, "khaos.tools.git_tools")
    _bind("test_run", test_tools.test_run, "khaos.tools.test_tools")
    # Phase 6 browser tools — all backed by browser_tools (Playwright or mock)
    _bind("browser_launch", browser_tools.browser_launch, "khaos.tools.browser_tools")
    _bind("browser_close", browser_tools.browser_close, "khaos.tools.browser_tools")
    _bind("browser_navigate", browser_tools.browser_navigate, "khaos.tools.browser_tools")
    _bind("browser_click", browser_tools.browser_click, "khaos.tools.browser_tools")
    _bind("browser_type", browser_tools.browser_type, "khaos.tools.browser_tools")
    _bind("browser_snapshot", browser_tools.browser_snapshot, "khaos.tools.browser_tools")
    _bind("browser_screenshot", browser_tools.browser_screenshot, "khaos.tools.browser_tools")
    _bind("browser_scroll", browser_tools.browser_scroll, "khaos.tools.browser_tools")
    _bind("browser_vision", browser_tools.browser_vision, "khaos.tools.browser_tools")
    _bind("browser_evaluate", browser_tools.browser_evaluate, "khaos.tools.browser_tools")
    _bind("browser_file_upload", browser_tools.browser_file_upload, "khaos.tools.browser_tools")
    # Phase 6 web content tools
    _bind("web_fetch", web_tools.web_fetch, "khaos.tools.web_tools")
    _bind("web_extract_tables", web_tools.web_extract_tables, "khaos.tools.web_tools")
    _bind("web_metadata", web_tools.web_metadata, "khaos.tools.web_tools")
    _bind("code_search", code_search_tools.code_search, "khaos.tools.code_search_tools")
    _bind("code_symbols", code_search_tools.code_symbols, "khaos.tools.code_search_tools")
    _bind("todo_write", todo_tools.todo_write, "khaos.tools.todo_tools")
    _bind("todo_read", todo_tools.todo_read, "khaos.tools.todo_tools")
    _bind("todo_update", todo_tools.todo_update, "khaos.tools.todo_tools")
    # Phase 8.3 orchestrator tools
    from khaos.tools import orchestrator_tools

    _bind("spawn_subagent", orchestrator_tools.spawn_subagent, "khaos.tools.orchestrator_tools")
    _bind("collect_results", orchestrator_tools.collect_results, "khaos.tools.orchestrator_tools")
    _bind("execute_plan", orchestrator_tools.execute_plan, "khaos.tools.orchestrator_tools")
    _bind("subagent_status", orchestrator_tools.subagent_status, "khaos.tools.orchestrator_tools")
    _bind("list_permission_rules", permission_tools.list_permission_rules, "khaos.tools.permission_tools")
    _bind("grant_permission", permission_tools.grant_permission, "khaos.tools.permission_tools")
    _bind("revoke_permission", permission_tools.revoke_permission, "khaos.tools.permission_tools")
    _bind("query_audit_logs", permission_tools.query_audit_logs, "khaos.tools.permission_tools")
    _bind("security_status", permission_tools.security_status, "khaos.tools.permission_tools")
    # Hermes batch 5: cron + history tool handlers.
    _bind("cron_create", cron_tools.cron_create, "khaos.tools.cron_tools")
    _bind("cron_list", cron_tools.cron_list, "khaos.tools.cron_tools")
    _bind("cron_remove", cron_tools.cron_remove, "khaos.tools.cron_tools")
    _bind("cron_pause", cron_tools.cron_pause, "khaos.tools.cron_tools")
    _bind("cron_resume", cron_tools.cron_resume, "khaos.tools.cron_tools")
    _bind("history_search", history_tools.history_search, "khaos.tools.history_tools")
    _bind("history_browse", history_tools.history_browse, "khaos.tools.history_tools")
    _bind("history_read", history_tools.history_read, "khaos.tools.history_tools")
    return registry
