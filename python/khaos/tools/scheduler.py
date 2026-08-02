"""Permission-aware tool scheduling."""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import logging
import time
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Any

from khaos.agent.approval import ApprovalBinding
from khaos.exceptions import PermissionDeniedError
from khaos.permissions import (
    ApprovalMode,
    GrantLifetime,
    PermissionRule,
    TransportClass,
    is_interactive_transport,
)
from khaos.permissions.resource import (
    AuthorizationResource,
    resolve_authorization_resource,
)
from khaos.permissions.rules import typed_rule_from_authorization_resource
from khaos.security.middleware import SecurityMiddleware
from khaos.tools.registry import ToolInvocationBroker, ToolRegistry
from khaos.tools.terminal_tools import BackgroundProcessAuthority

ConfirmCallback = Callable[[dict], Awaitable[dict | bool] | dict | bool]

logger = logging.getLogger(__name__)

EFFECT_NOT_STARTED = "not_started"
EFFECT_NOT_APPLIED = "not_applied"
EFFECT_APPLIED = "applied"
EFFECT_PARTIAL = "partial"
EFFECT_UNKNOWN = "unknown"
# Public spelling for callers that prefer outcome terminology.  Keep the
# historical value for wire compatibility with existing ToolResult clients.
EFFECT_NO_EFFECT = EFFECT_NOT_APPLIED

DELIVERY_COMPLETE = "complete"
DELIVERY_DEGRADED = "degraded"
DELIVERY_AUDIT_DEGRADED = "audit_degraded"

_IDEMPOTENCY_CACHE_LIMIT = 1024
_CONFIRM_ALLOWED_KEYS = frozenset({
    "approved", "remember", "pattern", "reason",
})
_CONFIRM_PATTERN_MAX_LENGTH = 4096
_CONFIRM_REASON_MAX_LENGTH = 1024


def _normalize_confirmation(value: object) -> dict[str, Any]:
    """Normalize an untrusted approval-adapter result fail-closed.

    Confirmation adapters sit outside the scheduler's trust boundary (UI,
    gateway, or an integration plugin).  Treating ``dict(value)`` as a valid
    response used to let strings, lists, non-bool values, and unexpected
    fields reach the approval broker.  The scheduler now accepts one strict
    schema and converts every malformed response into an explicit denial.
    """
    if type(value) is bool:
        return {"approved": value}
    if type(value) is not dict:
        return {
            "approved": False,
            "remember": False,
            "reason": "invalid_confirmation_response",
        }
    unknown = set(value) - _CONFIRM_ALLOWED_KEYS
    if unknown:
        return {
            "approved": False,
            "remember": False,
            "reason": "invalid_confirmation_response",
        }
    if type(value.get("approved")) is not bool:
        return {
            "approved": False,
            "remember": False,
            "reason": "invalid_confirmation_response",
        }
    remember = value.get("remember", False)
    if type(remember) is not bool:
        return {
            "approved": False,
            "remember": False,
            "reason": "invalid_confirmation_response",
        }
    pattern = value.get("pattern")
    if pattern is not None and (
        type(pattern) is not str
        or not pattern
        or len(pattern) > _CONFIRM_PATTERN_MAX_LENGTH
        or any(char in pattern for char in "\x00\r\n")
    ):
        return {
            "approved": False,
            "remember": False,
            "reason": "invalid_confirmation_response",
        }
    reason = value.get("reason")
    if reason is not None and (
        type(reason) is not str
        or len(reason) > _CONFIRM_REASON_MAX_LENGTH
        or any(char in reason for char in "\x00\r\n")
    ):
        return {
            "approved": False,
            "remember": False,
            "reason": "invalid_confirmation_response",
        }
    normalized: dict[str, Any] = {
        "approved": value["approved"],
    }
    if "remember" in value:
        normalized["remember"] = remember
    if pattern is not None:
        normalized["pattern"] = pattern
    if reason is not None:
        normalized["reason"] = reason
    return normalized


@dataclass
class EffectOutcome:
    """Explicit post-dispatch effect classification.

    The scheduler never derives this from a permission level.  Tool
    definitions declare the normal outcome, while exceptions/cancellation
    downgrade side-effecting operations to ``unknown`` and retain the
    reconciliation hint.
    """

    status: str
    effect_id: str = ""
    reconciliation_hint: str = ""
    output: Any = ""


@dataclass
class ToolResult:
    """Normalized result for one tool call."""

    tool_call_id: str
    name: str
    success: bool
    output: Any = ""
    error: str = ""
    duration_ms: int = 0
    arguments: dict[str, Any] | None = None
    # Effect and delivery are deliberately separate.  A handler may have
    # completed a mutation even when projection, auditing, budget accounting,
    # or remember-rule persistence fails afterwards.  Callers must not turn
    # such a result into an ordinary retryable failure.
    effect_status: str = EFFECT_NOT_STARTED
    delivery_status: str = DELIVERY_COMPLETE
    warning: str = ""
    effect_id: str = ""
    reconciliation_hint: str = ""
    retry_safe: bool = True


@dataclass
class _IdempotencyRecord:
    """Runtime-scoped result retained for an explicit idempotency key."""

    arguments_digest: str
    result: ToolResult
    stored_at: float = field(default_factory=time.monotonic)


@dataclass
class _OperationClaim:
    """In-process view of a durable tool-operation claim."""

    operation_id: str
    owner_token: str
    effect_id: str
    arguments_digest: str = ""
    result: ToolResult | None = None
    wait_event: asyncio.Event | None = None


@dataclass
class PermissionRequest:
    """Permission request emitted before an ask-every call can execute."""

    tool_call_id: str
    name: str
    arguments: dict
    level: str
    target: str
    reason: str
    binding_digest: str = ""
    expires_at: float = 0.0
    principal_id: str = ""
    session_id: str = ""
    task_id: str = ""
    workspace_id: str = ""
    arguments_digest: str = ""
    profile_digest: str = ""
    project_id: str = ""
    workspace_generation: int = 0
    authorization_resource_digest: str = ""
    authorization_epoch: int = 0
    policy_digest: str = ""
    tool_schema_digest: str = ""
    approval_id: str = ""


@dataclass
class SchedulerEvent:
    """Streaming scheduler event."""

    event: str
    result: ToolResult | None = None
    permission_request: PermissionRequest | None = None


@dataclass
class ToolBudget:
    """Atomic hard budget shared by serial and parallel tool dispatch."""

    max_calls: int = 50
    max_output_chars: int = 100000
    max_batch_calls: int = 16
    max_parallel_calls: int = 8
    max_output_per_tool: int = 65536
    max_total_output: int = 100000
    max_background_processes: int = 4
    max_processes_per_workspace: int = 2
    max_browser_contexts: int = 4
    _call_count: int = 0
    _output_chars: int = 0
    _reserved_calls: int = 0
    _reserved_output: int = 0
    _parallel_active: int = 0
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock, repr=False)

    @property
    def is_exhausted(self) -> bool:
        """Return true once call or output budget is exhausted."""
        return (
            self._call_count + self._reserved_calls >= self.max_calls
            or self._output_chars + self._reserved_output >= self._total_output_limit
        )

    @property
    def _total_output_limit(self) -> int:
        return min(self.max_output_chars, self.max_total_output)

    def validate_batch(self, size: int) -> bool:
        return 0 <= size <= self.max_batch_calls

    async def reserve(self, *, parallel: bool = False) -> ToolBudgetReservation | None:
        async with self._lock:
            if self._call_count + self._reserved_calls >= self.max_calls:
                return None
            if parallel and self._parallel_active >= self.max_parallel_calls:
                return None
            remaining = (
                self._total_output_limit
                - self._output_chars
                - self._reserved_output
            )
            if remaining <= 0:
                return None
            output_limit = min(self.max_output_per_tool, remaining)
            self._reserved_calls += 1
            self._reserved_output += output_limit
            if parallel:
                self._parallel_active += 1
            return ToolBudgetReservation(self, output_limit, parallel)

    async def _finish(
        self, reservation: ToolBudgetReservation, *, output_chars: int | None
    ) -> None:
        async with self._lock:
            if not reservation.active:
                return
            reservation.active = False
            self._reserved_calls -= 1
            self._reserved_output -= reservation.output_limit
            if reservation.parallel:
                self._parallel_active -= 1
            if output_chars is not None:
                if output_chars > reservation.output_limit:
                    raise RuntimeError("tool output exceeded reserved hard budget")
                self._call_count += 1
                self._output_chars += output_chars

    def record(self, output_chars: int) -> None:
        """Compatibility hook for trusted single-threaded callers."""
        self._call_count += 1
        self._output_chars += output_chars


@dataclass
class ToolBudgetReservation:
    budget: ToolBudget
    output_limit: int
    parallel: bool
    active: bool = True

    async def commit(self, output_chars: int) -> None:
        await self.budget._finish(self, output_chars=output_chars)

    async def release(self) -> None:
        await self.budget._finish(self, output_chars=None)


class ToolOutputBudgetExceeded(RuntimeError):
    """Raised without materializing an output larger than its reservation."""


def _measure_tool_output(
    value: Any,
    limit: int,
    *,
    _depth: int = 0,
    _seen: set[int] | None = None,
) -> int:
    """Measure JSON-compatible output incrementally and stop at ``limit``."""
    if _depth > 64:
        raise ToolOutputBudgetExceeded("tool output nesting exceeds 64 levels")
    if value is None:
        size = 4
    elif isinstance(value, bool):
        size = 4 if value else 5
    elif isinstance(value, (int, float)):
        size = len(json.dumps(value, allow_nan=False))
    elif isinstance(value, str):
        # json.dumps would allocate an escaped copy.  Reject obviously large
        # strings first; accepted strings are at most one reservation.
        if len(value) > limit:
            raise ToolOutputBudgetExceeded(
                "tool output exceeded reserved hard budget"
            )
        size = len(json.dumps(value, ensure_ascii=False))
    elif isinstance(value, Path):
        path_text = str(value)
        if len(path_text) > limit:
            raise ToolOutputBudgetExceeded(
                "tool output exceeded reserved hard budget"
            )
        size = len(json.dumps(path_text, ensure_ascii=False))
    elif isinstance(value, (list, tuple, dict)):
        seen = _seen if _seen is not None else set()
        identity = id(value)
        if identity in seen:
            raise ToolOutputBudgetExceeded("tool output contains a cycle")
        seen.add(identity)
        try:
            size = 2
            if isinstance(value, dict):
                iterator = value.items()
                for index, (key, item) in enumerate(iterator):
                    if not isinstance(key, str):
                        raise ToolOutputBudgetExceeded(
                            "tool output object keys must be strings"
                        )
                    size += (1 if index else 0) + len(
                        json.dumps(key, ensure_ascii=False)
                    ) + 1
                    if size > limit:
                        raise ToolOutputBudgetExceeded(
                            "tool output exceeded reserved hard budget"
                        )
                    size += _measure_tool_output(
                        item,
                        limit - size,
                        _depth=_depth + 1,
                        _seen=seen,
                    )
            else:
                for index, item in enumerate(value):
                    size += 1 if index else 0
                    if size > limit:
                        raise ToolOutputBudgetExceeded(
                            "tool output exceeded reserved hard budget"
                        )
                    size += _measure_tool_output(
                        item,
                        limit - size,
                        _depth=_depth + 1,
                        _seen=seen,
                    )
        finally:
            seen.remove(identity)
    else:
        raise ToolOutputBudgetExceeded(
            f"tool output type is not JSON-compatible: {type(value).__name__}"
        )
    if size > limit:
        raise ToolOutputBudgetExceeded("tool output exceeded reserved hard budget")
    return size


class ToolScheduler:
    """Split, authorize, and execute tool calls."""

    def __init__(
        self,
        registry: ToolRegistry,
        permission_engine,
        budget: ToolBudget | None = None,
        use_rust_executor: bool = False,
        security_middleware: SecurityMiddleware | None = None,
        # H5: identifies this scheduler's runtime to the BrowserManager so
        # two concurrent local sessions under the same UID get independent
        # BrowserContexts (keyed by principal_id + session_id + runtime_id).
        runtime_id: str = "",
    ):
        self.registry = registry
        self.permission_engine = permission_engine
        self.budget = budget or ToolBudget()
        self.security_middleware = security_middleware or SecurityMiddleware()
        # H5: per-runtime identifier propagated to the broker so browser
        # tools can key their BrowserContext by (principal, session, runtime).
        self.runtime_id = runtime_id
        # When True and the Rust bridge is importable, read-only file reads in
        # the parallel group are offloaded to the Rust executor for the bulk
        # I/O; the result still flows through the normal Python handler so
        # output formatting (line numbers, truncation) is unchanged. Writes and
        # any tool without a Rust fast path keep using the asyncio handler.
        self.use_rust_executor = use_rust_executor
        self.invocation_broker = ToolInvocationBroker(registry)
        self.process_authority = BackgroundProcessAuthority(
            max_background_processes=self.budget.max_background_processes,
            max_processes_per_workspace=self.budget.max_processes_per_workspace,
            output_limit=self.budget.max_output_per_tool,
        )
        # H1: optional shared OfficeMutationAuthority. Set by the runtime
        # factory so Office copy/move are fenced against cancellation/timeout.
        self.office_authority: Any = None
        # Idempotency is intentionally explicit and runtime-scoped.  Model
        # tool-call IDs are not stable authority, so callers that need
        # at-most-once replay semantics must provide a separate
        # ``idempotency_key`` at the tool-call envelope level.
        self._idempotency_lock = asyncio.Lock()
        self._idempotency_results: dict[str, _IdempotencyRecord] = {}
        # A durable row is the authority; these maps only coordinate
        # duplicate callers in this process.  A missing in-process owner on a
        # restart is treated as UNKNOWN and is never replayed automatically.
        self._operation_events: dict[str, asyncio.Event] = {}
        self._operation_claims: dict[str, _OperationClaim] = {}
        self._operation_claim_lock = asyncio.Lock()

    def set_office_authority(self, authority: Any) -> None:
        """Register the shared OfficeMutationAuthority (called at startup)."""
        self.office_authority = authority

    async def execute_batch(
        self,
        tool_calls: list[dict],
        mode: str,
        session_id: str | None = None,
        confirm_callback: ConfirmCallback | None = None,
        tool_context: dict[str, Any] | None = None,
    ) -> list[ToolResult]:
        """Execute a batch and return final tool results."""
        results: list[ToolResult] = []
        async for event in self.stream_batch(tool_calls, mode, session_id, confirm_callback, tool_context):
            if event.result is not None:
                results.append(event.result)
        return results

    async def stream_batch(
        self,
        tool_calls: list[dict],
        mode: str,
        session_id: str | None = None,
        confirm_callback: ConfirmCallback | None = None,
        tool_context: dict[str, Any] | None = None,
    ):
        """Execute a batch while yielding permission and result events."""
        if not self.budget.validate_batch(len(tool_calls)):
            for call in tool_calls:
                normalized = self._normalize_call(call)
                yield SchedulerEvent(
                    event="tool_result",
                    result=ToolResult(
                        tool_call_id=normalized["id"],
                        name=normalized["name"],
                        success=False,
                        error="Tool batch exceeds max_batch_calls",
                        arguments=normalized["arguments"],
                    ),
                )
            return
        if self.budget.is_exhausted:
            return
        tool_context = dict(tool_context or {})
        network_guard = getattr(self.security_middleware, "network_guard", None)
        tool_context["network_policy"] = (
            "unrestricted-with-approval"
            if network_guard is not None and network_guard.network_enabled
            else "none"
        )
        # B2 + H5: propagate the NetworkGuard + session_id + runtime_id so
        # the broker can inject them into browser tools.  ``network_guard``
        # is installed on every BrowserContext via ``context.route("**/*")``
        # to gate EVERY request, redirect and subresource — not just the
        # initial URL passed to ``browser_navigate``.  ``session_id`` +
        # ``runtime_id`` extend the per-session context key so two
        # concurrent local sessions under the same UID get independent
        # BrowserContexts (closing one runtime's context does NOT close a
        # concurrent runtime's page).
        if network_guard is not None and "network_guard" not in tool_context:
            tool_context["network_guard"] = network_guard
        if session_id and "session_id" not in tool_context:
            tool_context["session_id"] = session_id
        if self.runtime_id and "runtime_id" not in tool_context:
            tool_context["runtime_id"] = self.runtime_id
        # M1: propagate the effective policy digest so the approval
        # ``profile_digest`` can bind the decision to the exact policy under
        # which it was made.  Without this, two runtimes with different
        # ``allowed_paths`` / ``commands_require_approval`` would produce
        # identical ``profile_digest`` for the same (permission_level,
        # target, network_policy) tuple, contradicting the claim that an
        # approval was issued "under exactly this policy".
        if "effective_policy_digest" not in tool_context:
            # ``effective_policy_digest`` is a @property on the middleware;
            # getattr returns the string digest (or "" if no effective
            # policy was installed).
            tool_context["effective_policy_digest"] = getattr(
                self.security_middleware, "effective_policy_digest", ""
            ) or ""

        approved_calls: list[dict] = []
        for call in tool_calls:
            normalized = self._normalize_call(call)
            tool = self.registry.get(normalized["name"])
            if not self.registry.validate_call(tool.name, normalized["arguments"]):
                yield SchedulerEvent(
                    event="tool_result",
                    result=ToolResult(
                        tool_call_id=normalized["id"],
                        name=tool.name,
                        success=False,
                        error="Invalid tool arguments",
                        arguments=normalized["arguments"],
                    ),
                )
                continue

            resource: AuthorizationResource | None = None
            if tool_context.get("coding_workspace_enforced"):
                try:
                    resource = resolve_authorization_resource(
                        tool.name,
                        normalized["arguments"],
                        principal_id=str(tool_context.get("principal_id") or ""),
                        project_id=str(tool_context.get("project_id") or ""),
                        runtime_id=str(tool_context.get("runtime_id") or ""),
                        task_id=str(tool_context.get("task_id") or ""),
                        workspace_id=str(tool_context.get("workspace_id") or ""),
                        workspace_manager=tool_context.get("workspace_manager"),
                        resource_resolver=tool.resource_resolver,
                    )
                except (OSError, PermissionError, ValueError) as exc:
                    yield SchedulerEvent(
                        event="tool_result",
                        result=ToolResult(
                            tool_call_id=normalized["id"],
                            name=tool.name,
                            success=False,
                            error=f"Authorization resource rejected: {exc}",
                            arguments=normalized["arguments"],
                        ),
                    )
                    continue
                normalized["_authorization_resource"] = resource

            execution_error = self._execution_preflight_error(
                tool.name, mode, tool_context
            )
            if execution_error:
                target = self._resolve_target(
                    tool.name, normalized["arguments"], resource
                )
                audit_error = await self._audit_best_effort(
                    tool.name,
                    target,
                    "denied",
                    {
                        "tool_call_id": normalized["id"],
                        "reason": execution_error,
                        "check_type": "execution_backend",
                    },
                    session_id,
                )
                yield SchedulerEvent(
                    event="tool_result",
                    result=ToolResult(
                        tool_call_id=normalized["id"],
                        name=tool.name,
                        success=False,
                        error=execution_error,
                        arguments=normalized["arguments"],
                        delivery_status=(
                            DELIVERY_AUDIT_DEGRADED
                            if audit_error
                            else DELIVERY_COMPLETE
                        ),
                        warning=(
                            f"audit persistence failed: {audit_error}"
                            if audit_error
                            else ""
                        ),
                    ),
                )
                continue

            source_transport = str(tool_context.get("source_transport") or "")
            decision = await self.permission_engine.check(
                tool_name=tool.name,
                params=normalized["arguments"],
                permission_level=tool.permission_level,
                mode=mode,
                resource=resource,
                # Round-15 B-2: gate the read-only terminal auto-approve
                # shortcut on an interactive transport so an unattended
                # webhook/cron/rpc turn cannot auto-approve ``cat ~/.ssh/id_rsa``.
                source_transport=source_transport,
                session_id=str(tool_context.get("session_id") or session_id or ""),
                task_id=str(tool_context.get("task_id") or ""),
                workspace_id=str(tool_context.get("workspace_id") or ""),
            )
            if decision.approved == ApprovalMode.DENY:
                await self._audit_best_effort(
                    tool.name,
                    decision.target,
                    "denied",
                    {"reason": decision.reason},
                    session_id,
                )
                yield SchedulerEvent(
                    event="tool_result",
                    result=ToolResult(
                        tool_call_id=normalized["id"],
                        name=tool.name,
                        success=False,
                        error=f"Permission denied: {decision.reason}",
                        arguments=normalized["arguments"],
                    ),
                )
                continue

            destructive_context = None
            if mode == "coding":
                from khaos.tools.git_tools import (
                    prepare_destructive_git_approval,
                    prepare_remote_git_approval,
                )

                try:
                    destructive_context = await prepare_destructive_git_approval(
                        tool.name,
                        normalized["arguments"],
                        tool_context or {},
                        requester=session_id or "",
                        approval_id=normalized["id"],
                    )
                    if destructive_context is None:
                        destructive_context = await prepare_remote_git_approval(
                            tool.name,
                            normalized["arguments"],
                            tool_context,
                            requester=session_id or "",
                            approval_id=normalized["id"],
                        )
                    if destructive_context is None:
                        from khaos.tools.github_tools import prepare_github_approval

                        destructive_context = await prepare_github_approval(
                            tool.name,
                            normalized["arguments"],
                            tool_context,
                            requester=session_id or "",
                            approval_id=normalized["id"],
                        )
                except (PermissionError, ValueError) as exc:
                    yield SchedulerEvent(
                        event="tool_result",
                        result=ToolResult(
                            tool_call_id=normalized["id"],
                            name=tool.name,
                            success=False,
                            error=str(exc),
                            arguments=normalized["arguments"],
                        ),
                    )
                    continue

            if decision.requires_user_confirm or destructive_context is not None:
                approval_target = decision.target
                if destructive_context is not None:
                    binding = destructive_context["binding"]
                    approval_target = (
                        f"{binding['operation']}:{binding['target']} "
                        f"head={binding['head']} diff={binding['diff_hash']}"
                    )
                principal_id = str(tool_context.get("principal_id") or "")
                current_session = str(session_id or "")
                if not principal_id or not current_session:
                    yield SchedulerEvent(
                        event="tool_result",
                        result=ToolResult(
                            tool_call_id=normalized["id"],
                            name=tool.name,
                            success=False,
                            error=(
                                "Approval requires authenticated principal "
                                "and session binding"
                            ),
                            arguments=normalized["arguments"],
                        ),
                    )
                    continue
                expires_at = time.time() + 120.0
                authorization_epoch = await self.permission_engine.authorization_snapshot()
                project_id = str(tool_context.get("project_id") or "")
                if resource is None and tool_context.get("coding_workspace_enforced"):
                    raise PermissionDeniedError("workspace authorization resource is missing")
                binding = ApprovalBinding(
                    principal_id=principal_id,
                    session_id=current_session,
                    task_id=str(
                        tool_context.get("task_id")
                        or f"session:{current_session}"
                    ),
                    turn_id=str(
                        tool_context.get("turn_id")
                        or f"turn:{normalized['id']}"
                    ),
                    tool_call_id=normalized["id"],
                    tool_name=tool.name,
                    arguments_digest=_canonical_digest(
                        normalized["arguments"]
                    ),
                    workspace_id=str(
                        tool_context.get("workspace_id")
                        or f"session:{current_session}"
                    ),
                    profile_digest=_canonical_digest(
                        {
                            "permission_level": tool.permission_level,
                            "target": approval_target,
                            "network_policy": tool_context["network_policy"],
                            # M1: bind the approval to the exact effective
                            # policy under which it was issued.  A different
                            # policy (different allowed_paths, commands_require_
                            # approval, network_allowed_domains, …) yields a
                            # different digest, so an approval cannot be
                            # replayed under a loosened policy.
                            "effective_policy_digest": tool_context.get(
                                "effective_policy_digest", ""
                            ),
                        }
                    ),
                    expires_at=expires_at,
                    project_id=project_id,
                    workspace_generation=(resource.workspace_generation if resource else 0),
                    authorization_resource_digest=(resource.digest() if resource else ""),
                    authorization_epoch=authorization_epoch,
                    policy_digest=self.permission_engine.policy_digest,
                    tool_schema_digest=tool.schema_digest,
                )
                broker = tool_context.get("approval_broker")
                if broker is None:
                    yield SchedulerEvent(
                        event="tool_result",
                        result=ToolResult(
                            tool_call_id=normalized["id"],
                            name=tool.name,
                            success=False,
                            error="ApprovalBroker is required",
                            arguments=normalized["arguments"],
                        ),
                    )
                    continue
                approval_handle = await broker.register_tool_approval(binding)
                binding_digest = str(approval_handle)
                normalized["_approval_id"] = getattr(
                    approval_handle, "approval_id", ""
                )
                normalized["_approval_schema_digest"] = binding.tool_schema_digest
                normalized["_approval_policy_digest"] = binding.policy_digest
                normalized["_approval_authorization_epoch"] = binding.authorization_epoch
                # Round-14 §5: stash the approved arguments digest so dispatch
                # can recompute the live arguments digest and refuse to run if
                # they diverge.  Previously this digest was computed and stored
                # on the binding/PermissionRequest but never re-verified at
                # dispatch (unlike schema/policy/resource digests), so a caller
                # able to mutate the arguments between approval and dispatch
                # would not be caught by an arguments-digest mismatch.
                normalized["_approval_arguments_digest"] = binding.arguments_digest
                request = PermissionRequest(
                    tool_call_id=normalized["id"],
                    approval_id=normalized.get("_approval_id", ""),
                    name=tool.name,
                    arguments=normalized["arguments"],
                    level=tool.permission_level,
                    target=approval_target,
                    reason=decision.reason,
                    binding_digest=binding_digest,
                    expires_at=expires_at,
                    principal_id=binding.principal_id,
                    session_id=binding.session_id,
                    task_id=binding.task_id,
                    workspace_id=binding.workspace_id,
                    arguments_digest=binding.arguments_digest,
                    profile_digest=binding.profile_digest,
                    project_id=binding.project_id,
                    workspace_generation=binding.workspace_generation,
                    authorization_resource_digest=binding.authorization_resource_digest,
                    authorization_epoch=binding.authorization_epoch,
                    policy_digest=binding.policy_digest,
                    tool_schema_digest=binding.tool_schema_digest,
                )
                yield SchedulerEvent(event="permission_request", permission_request=request)
                confirmation = await self._confirm(request, confirm_callback)
                confirmation = await broker.consume_for_dispatch(
                    normalized["id"],
                    bool(confirmation.get("approved", False)),
                    bool(confirmation.get("remember", False)),
                    principal_id=principal_id,
                    session_id=current_session,
                    binding_digest=binding_digest,
                )
                if not confirmation.get("approved", False):
                    if destructive_context is not None:
                        await destructive_context["approval_broker"].cancel_operation(normalized["id"])
                    await self._audit_best_effort(
                        tool.name,
                        decision.target,
                        "denied",
                        {"reason": "user denied"},
                        session_id,
                    )
                    yield SchedulerEvent(
                        event="tool_result",
                        result=ToolResult(
                            tool_call_id=normalized["id"],
                            name=tool.name,
                            success=False,
                            error="User denied permission",
                            arguments=normalized["arguments"],
                        ),
                    )
                    continue
                if destructive_context is not None:
                    approved = await destructive_context["approval_broker"].approve_operation(
                        normalized["id"], session_id or "",
                        principal_id=principal_id,
                    )
                    if not approved:
                        yield SchedulerEvent(
                            event="tool_result",
                            result=ToolResult(
                                tool_call_id=normalized["id"],
                                name=tool.name,
                                success=False,
                                error="Destructive Git approval is stale or invalid",
                                arguments=normalized["arguments"],
                            ),
                        )
                        continue
                    normalized["_approval_context"] = destructive_context
                if confirmation.get("remember") and is_interactive_transport(
                    source_transport
                ):
                    try:
                        if resource is not None:
                            resource_type, resource_spec = (
                                typed_rule_from_authorization_resource(
                                    resource, tool.permission_level
                                )
                            )
                            remember_pattern = decision.target
                        else:
                            resource_type, resource_spec = "", None
                            remember_pattern = confirmation.get(
                                "pattern", decision.target
                            )
                        normalized["_remember_rule"] = PermissionRule(
                            id=None,
                            pattern=remember_pattern,
                            permission_level=tool.permission_level,
                            approval=ApprovalMode.AUTO_APPROVE,
                            mode=mode,
                            transport_class=TransportClass.INTERACTIVE.value,
                            grant_lifetime=GrantLifetime.PROJECT_INTERACTIVE.value,
                            session_id=session_id or "",
                            task_id=str(tool_context.get("task_id") or ""),
                            workspace_id=str(tool_context.get("workspace_id") or ""),
                            created_by=f"approval:{source_transport}",
                            resource_type=resource_type,
                            resource_spec=resource_spec,
                        )
                    except (TypeError, ValueError) as exc:
                        normalized["_remember_warning"] = (
                            f"remember-rule rejected: typed resource invalid ({exc})"
                        )
                elif confirmation.get("remember"):
                    normalized["_remember_warning"] = (
                        "remember request ignored for unattended or unknown "
                        "transport"
                    )
            approved_calls.append(normalized)

        # Bind this dispatch batch to the latest database-authoritative epoch
        # after all interactive grants have completed.  Each handler validates
        # the snapshot again immediately before its security pre-check.
        if approved_calls:
            try:
                dispatch_epoch = await self.permission_engine.authorization_snapshot()
            except PermissionDeniedError as exc:
                for call in approved_calls:
                    yield SchedulerEvent(
                        event="tool_result",
                        result=ToolResult(
                            tool_call_id=call["id"],
                            name=call["name"],
                            success=False,
                            error=f"Permission denied: {exc}",
                            arguments=call["arguments"],
                        ),
                    )
                return
            for call in approved_calls:
                call["_authorization_epoch"] = dispatch_epoch

        parallel_calls, serial_calls = self.registry.get_parallel_tools(approved_calls)
        if parallel_calls:
            tasks = []
            task_calls: list[dict] = []
            for call in parallel_calls:
                reservation = await self.budget.reserve(parallel=True)
                if reservation is None:
                    yield SchedulerEvent(
                        event="tool_result",
                        result=ToolResult(
                            tool_call_id=call["id"], name=call["name"],
                            success=False, error="Tool budget reservation denied",
                            arguments=call["arguments"],
                        ),
                    )
                    continue
                tasks.append(
                    self._execute_one(
                        call, session_id, mode, tool_context or {}, reservation
                    )
                )
                task_calls.append(call)
            gathered = await asyncio.gather(*tasks, return_exceptions=True)
            for call, result in zip(task_calls, gathered):
                if isinstance(result, BaseException):
                    # _execute_one normally converts failures into a
                    # ToolResult.  Keep the batch isolated even if an
                    # adapter/extension raises outside that boundary.
                    logger.error(
                        "parallel tool task escaped scheduler: tool=%s error=%s",
                        call["name"],
                        result,
                        exc_info=(type(result), result, result.__traceback__),
                    )
                    yield SchedulerEvent(
                        event="tool_result",
                        result=ToolResult(
                            tool_call_id=call["id"],
                            name=call["name"],
                            success=False,
                            error=str(result),
                            arguments=call["arguments"],
                            effect_status=EFFECT_UNKNOWN,
                            delivery_status=DELIVERY_DEGRADED,
                            warning="parallel scheduler task escaped its result boundary",
                            retry_safe=False,
                        ),
                    )
                    continue
                yield SchedulerEvent(event="tool_result", result=result)
        for call in serial_calls:
            reservation = await self.budget.reserve(parallel=False)
            if reservation is None:
                yield SchedulerEvent(
                    event="tool_result",
                    result=ToolResult(
                        tool_call_id=call["id"],
                        name=call["name"],
                        success=False,
                        error="Tool budget exhausted",
                        arguments=call["arguments"],
                    ),
                )
                continue
            yield SchedulerEvent(
                event="tool_result",
                result=await self._execute_one(
                    call, session_id, mode, tool_context or {}, reservation
                ),
            )

    async def _execute_one(
        self,
        call: dict,
        session_id: str | None,
        mode: str,
        tool_context: dict[str, Any],
        reservation: ToolBudgetReservation,
    ) -> ToolResult:
        start = time.monotonic()
        tool = self.registry.get(call["name"])
        resource: AuthorizationResource | None = call.get("_authorization_resource")
        target = self._resolve_target(tool.name, call.get("arguments", {}), resource)
        if tool.handler is None:
            await self._release_best_effort(reservation)
            return ToolResult(
                tool_call_id=call["id"],
                name=call["name"],
                success=False,
                error="Tool has no handler",
                arguments=call["arguments"],
            )

        handler_started = False
        effect_id = ""
        effect_status = EFFECT_NOT_STARTED
        reconciliation_hint = str(getattr(tool, "reconciliation_hint", "") or "")
        operation_claim: _OperationClaim | None = None
        try:
            await self.permission_engine.validate_dispatch_epoch(
                int(call.get("_authorization_epoch", 0))
            )
            expected_schema = call.get("_approval_schema_digest")
            if expected_schema and expected_schema != tool.schema_digest:
                raise PermissionDeniedError(
                    "Tool schema changed before dispatch; re-approval required"
                )
            expected_policy = call.get("_approval_policy_digest")
            if expected_policy and expected_policy != self.permission_engine.policy_digest:
                raise PermissionDeniedError(
                    "Policy changed before dispatch; re-approval required"
                )
            # Round-14 §5: recompute the live arguments digest and refuse
            # dispatch if it differs from the approved one.  This closes the
            # asymmetry where schema/policy/resource digests were re-verified
            # at dispatch but the arguments digest (the payload most directly
            # controlled by the model) was only stored, never re-checked.
            expected_arguments = call.get("_approval_arguments_digest")
            if expected_arguments:
                live_arguments = _canonical_digest(call.get("arguments", {}))
                if live_arguments != expected_arguments:
                    raise PermissionDeniedError(
                        "Tool arguments changed before dispatch; re-approval required"
                    )
            expected_approval_epoch = call.get("_approval_authorization_epoch")
            if expected_approval_epoch is not None:
                await self.permission_engine.validate_dispatch_epoch(
                    int(expected_approval_epoch)
                )
            if resource is not None:
                current_resource = resolve_authorization_resource(
                    tool.name,
                    call.get("arguments", {}),
                    principal_id=str(tool_context.get("principal_id") or ""),
                    project_id=str(tool_context.get("project_id") or ""),
                    runtime_id=str(tool_context.get("runtime_id") or ""),
                    task_id=str(tool_context.get("task_id") or ""),
                    workspace_id=str(tool_context.get("workspace_id") or ""),
                    workspace_manager=tool_context.get("workspace_manager"),
                    resource_resolver=tool.resource_resolver,
                )
                if current_resource.digest() != resource.digest():
                    raise PermissionDeniedError(
                        "Authorization resource changed before dispatch; re-approval required"
                    )
            security = await self.security_middleware.pre_check(
                tool.name,
                call.get("arguments", {}),
            )
            if not security.allowed:
                await self._release_best_effort(reservation)
                audit_error = await self._audit_best_effort(
                    tool.name,
                    target,
                    "denied",
                    {
                        "tool_call_id": call["id"],
                        "reason": security.reason,
                        "risk_level": security.risk_level,
                        "check_type": security.check_type,
                    },
                    session_id,
                )
                warning = (
                    f"security check blocked: {security.reason}"
                    if not audit_error
                    else (
                        f"security check blocked: {security.reason}; "
                        f"audit persistence failed: {audit_error}"
                    )
                )
                return ToolResult(
                    tool_call_id=call["id"],
                    name=tool.name,
                    success=False,
                    error=f"Security check blocked: {security.reason}",
                    duration_ms=int((time.monotonic() - start) * 1000),
                    arguments=call["arguments"],
                    delivery_status=(
                        DELIVERY_AUDIT_DEGRADED if audit_error else DELIVERY_COMPLETE
                    ),
                    warning=warning if audit_error else "",
                )

            operation_claim = await self._claim_operation(
                call,
                tool=tool,
                session_id=session_id,
                tool_context=tool_context,
            )
            if operation_claim is not None and operation_claim.result is not None:
                await self._release_best_effort(reservation)
                return replace(
                    operation_claim.result,
                    tool_call_id=call["id"],
                    name=tool.name,
                    arguments=call["arguments"],
                    duration_ms=int((time.monotonic() - start) * 1000),
                )
            if operation_claim is not None and operation_claim.wait_event is not None:
                await self._release_best_effort(reservation)
                waited = await self._wait_for_operation(
                    operation_claim,
                    call=call,
                    tool=tool,
                    timeout=float(tool.timeout) + 5.0,
                )
                return replace(
                    waited,
                    tool_call_id=call["id"],
                    name=tool.name,
                    arguments=call["arguments"],
                    duration_ms=int((time.monotonic() - start) * 1000),
                )

            # The effect ID is allocated immediately before entering the
            # handler.  If the handler times out or raises after a partial
            # mutation, the caller still receives an identifier that must not
            # be treated as a retryable ordinary failure.
            effect_id = (
                operation_claim.effect_id
                if operation_claim is not None
                else uuid.uuid4().hex
            )
            handler_started = True
            invocation_context = dict(tool_context)
            invocation_context["process_authority"] = self.process_authority
            sandbox = self.security_middleware.sandbox
            if mode == "office" and sandbox is not None:
                # Internal capability: never sourced from model arguments.
                invocation_context["office_workspace_root"] = sandbox.workspace_root
            # H1: the OfficeMutationAuthority (registered at startup) fences
            # office mutations against cancellation/timeout side effects.
            office_authority = getattr(self, "office_authority", None)
            if mode == "office" and office_authority is not None:
                invocation_context["office_authority"] = office_authority
            if call.get("_approval_context") is not None:
                invocation_context["approval_context"] = call["_approval_context"]
            invocation_context["effect_id"] = effect_id
            output = await asyncio.wait_for(
                self.invocation_broker.invoke(tool.name, mode=mode, context=invocation_context, **call.get("arguments", {})),
                timeout=tool.timeout,
            )
            output, effect_status, effect_id, reconciliation_hint = (
                self._normalize_effect_outcome(
                    output,
                    default_status=self._declared_effect_status(tool),
                    default_effect_id=effect_id,
                    default_reconciliation_hint=reconciliation_hint,
                )
            )
            if operation_claim is not None:
                await self._update_operation_effect_id(operation_claim, effect_id)
        except asyncio.CancelledError:
            await self._release_best_effort(reservation)
            if handler_started:
                effect_status = self._interrupted_effect_status(tool)
                audit_error = await self._audit_best_effort(
                    tool.name,
                    target,
                    "cancelled",
                    {
                        "tool_call_id": call["id"],
                        "effect_id": effect_id,
                        "effect_status": effect_status,
                        "reconciliation_hint": reconciliation_hint,
                    },
                    session_id,
                )
                result = ToolResult(
                    tool_call_id=call["id"],
                    name=tool.name,
                    success=False,
                    error="tool execution cancelled after dispatch",
                    duration_ms=int((time.monotonic() - start) * 1000),
                    arguments=call["arguments"],
                    effect_status=effect_status,
                    delivery_status=(
                        DELIVERY_AUDIT_DEGRADED
                        if audit_error else DELIVERY_COMPLETE
                    ),
                    warning=(
                        "audit persistence failed: " + audit_error
                        if audit_error else
                        "effect outcome is uncertain; reconcile before retry"
                    ),
                    effect_id=effect_id,
                    reconciliation_hint=reconciliation_hint,
                    retry_safe=False,
                )
                await self._finish_operation(
                    operation_claim,
                    result,
                    terminal_status="unknown",
                )
                await self._store_idempotent_result(
                    call,
                    session_id=session_id,
                    tool_context=tool_context,
                    result=result,
                )
                logger.error(
                    "tool execution cancelled after handler dispatch: tool=%s effect_id=%s",
                    tool.name,
                    effect_id,
                )
                return result
            return ToolResult(
                tool_call_id=call["id"],
                name=tool.name,
                success=False,
                error="tool execution cancelled before dispatch",
                arguments=call["arguments"],
                effect_status=EFFECT_NOT_STARTED,
                retry_safe=True,
            )
        except Exception as exc:  # noqa: BLE001 - tool execution is an error result boundary
            await self._release_best_effort(reservation)
            if handler_started:
                effect_status = self._exception_effect_status(tool)
            audit_error = await self._audit_best_effort(
                tool.name,
                target,
                "error",
                {
                    "error": str(exc),
                    "tool_call_id": call["id"],
                    "effect_id": effect_id,
                    "effect_status": effect_status,
                    "reconciliation_hint": reconciliation_hint,
                },
                session_id,
            )
            warning = (
                f"error audit persistence failed: {audit_error}"
                if audit_error
                else ""
            )
            result = ToolResult(
                tool_call_id=call["id"],
                name=tool.name,
                success=False,
                error=str(exc),
                duration_ms=int((time.monotonic() - start) * 1000),
                arguments=call["arguments"],
                effect_status=effect_status,
                delivery_status=(
                    DELIVERY_AUDIT_DEGRADED if audit_error else DELIVERY_COMPLETE
                ),
                warning=warning,
                effect_id=effect_id,
                reconciliation_hint=reconciliation_hint,
                retry_safe=not handler_started,
            )
            await self._finish_operation(
                operation_claim,
                result,
                terminal_status=(
                    "unknown"
                    if effect_status in {EFFECT_UNKNOWN, EFFECT_PARTIAL}
                    else "completed"
                ),
            )
            if handler_started:
                await self._store_idempotent_result(
                    call, session_id=session_id, tool_context=tool_context, result=result
                )
            return result

        # From this point onward the handler has returned.  Any failure is a
        # delivery/recording failure, not an execution failure: the effect
        # status must remain visible and the result must not invite a blind
        # replay of a mutation.
        try:
            # Bound the structure before secret scanning.  This traversal
            # stops as soon as the reservation is consumed and never calls an
            # arbitrary result object's __str__/__repr__ method.
            _measure_tool_output(output, reservation.output_limit)
            secret_scan, output = await self.security_middleware.post_check(
                tool.name, output
            )
            # Redaction can change length, so commit the post-redaction size.
            output_chars = _measure_tool_output(output, reservation.output_limit)
        except Exception as exc:  # noqa: BLE001 - delivery failure is reported separately
            await self._release_best_effort(reservation)
            delivery_status = DELIVERY_DEGRADED
            warning = f"effect completed but result delivery failed: {exc}"
            audit_error = await self._audit_best_effort(
                tool.name,
                target,
                "success_degraded",
                {
                    "tool_call_id": call["id"],
                    "effect_id": effect_id,
                    "effect_status": effect_status,
                    "delivery_status": delivery_status,
                    "reconciliation_hint": reconciliation_hint,
                },
                session_id,
            )
            if audit_error:
                delivery_status = DELIVERY_AUDIT_DEGRADED
                warning += f"; audit persistence failed: {audit_error}"
            effect_applied = effect_status in {EFFECT_APPLIED, EFFECT_PARTIAL}
            result = ToolResult(
                tool_call_id=call["id"],
                name=tool.name,
                # A read-only handler has no external effect to preserve, so
                # keep the historical failure contract for an unprojectable
                # result.  A completed mutation remains successful from the
                # caller's perspective and carries the degraded delivery
                # state instead of inviting a blind replay.
                success=effect_applied,
                output="",
                error="" if effect_applied else str(exc),
                duration_ms=int((time.monotonic() - start) * 1000),
                arguments=call["arguments"],
                effect_status=effect_status,
                delivery_status=delivery_status,
                warning=warning,
                effect_id=effect_id,
                reconciliation_hint=reconciliation_hint,
                retry_safe=effect_status == EFFECT_NOT_APPLIED,
            )
            await self._finish_operation(
                operation_claim,
                result,
                terminal_status=(
                    "unknown"
                    if effect_status in {EFFECT_UNKNOWN, EFFECT_PARTIAL}
                    else "completed"
                ),
            )
            await self._store_idempotent_result(
                call, session_id=session_id, tool_context=tool_context, result=result
            )
            return result

        detail: dict[str, Any] = {
            "tool_call_id": call["id"],
            "effect_id": effect_id,
            "effect_status": effect_status,
            "reconciliation_hint": reconciliation_hint,
            "delivery_status": DELIVERY_COMPLETE,
        }
        if resource is not None:
            detail["authorization_resource_digest"] = resource.digest()
        if secret_scan.has_secrets:
            detail["secrets_detected"] = True
            detail["secret_categories"] = [
                secret.category for secret in secret_scan.secrets
            ]

        warnings: list[str] = []
        delivery_status = DELIVERY_COMPLETE
        if call.get("_remember_warning"):
            warnings.append(str(call["_remember_warning"]))
        try:
            await reservation.commit(output_chars)
        except Exception as exc:  # noqa: BLE001 - budget accounting degrades delivery
            await self._release_best_effort(reservation)
            delivery_status = DELIVERY_DEGRADED
            warnings.append(f"budget accounting failed: {exc}")

        detail["delivery_status"] = delivery_status
        audit_error = await self._audit_best_effort(
            tool.name,
            target,
            "success",
            detail,
            session_id,
        )
        if audit_error:
            delivery_status = DELIVERY_AUDIT_DEGRADED
            warnings.append(f"audit persistence failed: {audit_error}")

        remember_rule = call.get("_remember_rule")
        if remember_rule is not None:
            try:
                await self.permission_engine.grant_rule(remember_rule)
            except Exception as exc:  # noqa: BLE001 - permission persistence degrades delivery
                delivery_status = (
                    DELIVERY_AUDIT_DEGRADED
                    if delivery_status == DELIVERY_AUDIT_DEGRADED
                    else DELIVERY_DEGRADED
                )
                warnings.append(f"remember-rule persistence failed: {exc}")

        result = ToolResult(
            tool_call_id=call["id"],
            name=tool.name,
            success=True,
            output=output,
            duration_ms=int((time.monotonic() - start) * 1000),
            arguments=call["arguments"],
            effect_status=effect_status,
            delivery_status=delivery_status,
            warning="; ".join(warnings),
            effect_id=effect_id,
            reconciliation_hint=reconciliation_hint,
            retry_safe=effect_status == EFFECT_NOT_APPLIED,
        )
        await self._finish_operation(
            operation_claim,
            result,
            terminal_status=(
                "unknown"
                if effect_status in {EFFECT_UNKNOWN, EFFECT_PARTIAL}
                else "completed"
            ),
        )
        await self._store_idempotent_result(
            call, session_id=session_id, tool_context=tool_context, result=result
        )
        return result

    @staticmethod
    def _declared_effect_status(tool: Any) -> str:
        """Read the explicit tool contract; never infer from permission."""
        status = str(getattr(tool, "effect_status", "") or EFFECT_UNKNOWN)
        if status not in {
            EFFECT_NOT_APPLIED, EFFECT_APPLIED, EFFECT_PARTIAL, EFFECT_UNKNOWN
        }:
            return EFFECT_UNKNOWN
        return status

    @classmethod
    def _exception_effect_status(cls, tool: Any) -> str:
        """A failed side-effecting handler is unresolved, not retryable."""
        declared = cls._declared_effect_status(tool)
        return EFFECT_NOT_APPLIED if declared == EFFECT_NOT_APPLIED else EFFECT_UNKNOWN

    @classmethod
    def _interrupted_effect_status(cls, tool: Any) -> str:
        """Classify cancellation after dispatch conservatively."""
        return cls._exception_effect_status(tool)

    @staticmethod
    def _normalize_effect_outcome(
        value: Any,
        *,
        default_status: str,
        default_effect_id: str,
        default_reconciliation_hint: str,
    ) -> tuple[Any, str, str, str]:
        """Accept an explicit handler outcome without guessing its effect.

        Legacy handlers may still return their payload directly and use the
        registered normal effect declaration.  New mutation handlers can
        return ``EffectOutcome`` to report a more precise status after the
        external operation has actually run.
        """
        if not isinstance(value, EffectOutcome):
            return (
                value,
                default_status,
                default_effect_id,
                default_reconciliation_hint,
            )
        status = str(value.status or EFFECT_UNKNOWN)
        if status not in {
            EFFECT_NOT_APPLIED,
            EFFECT_APPLIED,
            EFFECT_PARTIAL,
            EFFECT_UNKNOWN,
        }:
            raise ValueError(f"invalid EffectOutcome status: {status!r}")
        effect_id = str(value.effect_id or default_effect_id)
        if len(effect_id) > 256 or any(char in effect_id for char in "\x00\r\n"):
            raise ValueError("invalid EffectOutcome effect_id")
        reconciliation_hint = str(
            value.reconciliation_hint or default_reconciliation_hint
        )
        if len(reconciliation_hint) > 4096 or any(
            char in reconciliation_hint for char in "\x00\r\n"
        ):
            raise ValueError("invalid EffectOutcome reconciliation_hint")
        return value.output, status, effect_id, reconciliation_hint

    @staticmethod
    def _serialize_operation_result(result: ToolResult) -> str:
        return json.dumps(asdict(result), ensure_ascii=False, sort_keys=True)

    @staticmethod
    def _deserialize_operation_result(
        row: dict[str, Any],
        *,
        call: dict,
        tool: Any,
    ) -> ToolResult:
        payload = str(row.get("result_json") or "")
        if payload:
            try:
                value = json.loads(payload)
                if isinstance(value, dict):
                    fields = set(ToolResult.__dataclass_fields__)
                    values = {key: item for key, item in value.items() if key in fields}
                    return ToolResult(
                        tool_call_id=str(values.get("tool_call_id") or call["id"]),
                        name=str(values.get("name") or tool.name),
                        success=bool(values.get("success", False)),
                        output=values.get("output", ""),
                        error=str(values.get("error") or ""),
                        duration_ms=int(values.get("duration_ms") or 0),
                        arguments=values.get("arguments") or call.get("arguments", {}),
                        effect_status=str(
                            values.get("effect_status")
                            or row.get("effect_status")
                            or EFFECT_UNKNOWN
                        ),
                        delivery_status=str(
                            values.get("delivery_status") or DELIVERY_COMPLETE
                        ),
                        warning=str(values.get("warning") or ""),
                        effect_id=str(
                            values.get("effect_id") or row.get("effect_id") or ""
                        ),
                        reconciliation_hint=str(
                            values.get("reconciliation_hint")
                            or row.get("reconciliation_hint")
                            or ""
                        ),
                        retry_safe=bool(values.get("retry_safe", False)),
                    )
            except (TypeError, ValueError, json.JSONDecodeError):
                logger.error(
                    "durable tool operation result is malformed: operation_id=%s",
                    row.get("operation_id"),
                )
        effect_status = str(row.get("effect_status") or EFFECT_UNKNOWN)
        return ToolResult(
            tool_call_id=call["id"],
            name=tool.name,
            success=False,
            error="durable operation is unresolved; reconcile before retry",
            arguments=call.get("arguments", {}),
            effect_status=effect_status,
            delivery_status=DELIVERY_DEGRADED,
            warning=(
                str(row.get("reconciliation_hint") or "")
                or "the previous process may have stopped after dispatch"
            ),
            effect_id=str(row.get("effect_id") or ""),
            reconciliation_hint=str(row.get("reconciliation_hint") or ""),
            retry_safe=False,
        )

    async def _claim_operation(
        self,
        call: dict,
        *,
        tool: Any,
        session_id: str | None,
        tool_context: dict[str, Any],
    ) -> _OperationClaim | None:
        """Serialize durable claims with local owner registration."""
        async with self._operation_claim_lock:
            return await self._claim_operation_locked(
                call,
                tool=tool,
                session_id=session_id,
                tool_context=tool_context,
            )

    async def _claim_operation_locked(
        self,
        call: dict,
        *,
        tool: Any,
        session_id: str | None,
        tool_context: dict[str, Any],
    ) -> _OperationClaim | None:
        """Claim an idempotent operation in SQLite before handler entry."""
        operation_id = self._idempotency_scope(
            call, session_id=session_id, tool_context=tool_context
        )
        if not operation_id:
            return None
        arguments_digest = _canonical_digest(call.get("arguments", {}))
        active_event = self._operation_events.get(operation_id)
        if active_event is not None:
            active_claim = self._operation_claims.get(operation_id)
            if (
                active_claim is not None
                and active_claim.arguments_digest != arguments_digest
            ):
                raise PermissionDeniedError(
                    "idempotency key was reused with different tool arguments"
                )
            return _OperationClaim(
                operation_id=operation_id,
                owner_token="",
                effect_id=(active_claim.effect_id if active_claim else ""),
                arguments_digest=arguments_digest,
                wait_event=active_event,
            )

        owner_token = uuid.uuid4().hex
        effect_id = uuid.uuid4().hex
        db = getattr(self.permission_engine, "db", None)
        claim_method = getattr(db, "claim_tool_operation", None)
        if callable(claim_method):
            row = await claim_method(
                operation_id=operation_id,
                tool_name=tool.name,
                arguments_digest=arguments_digest,
                effect_id=effect_id,
                owner_token=owner_token,
                principal_id=str(tool_context.get("principal_id") or ""),
                project_id=str(tool_context.get("project_id") or ""),
                session_id=str(session_id or tool_context.get("session_id") or ""),
                task_id=str(tool_context.get("task_id") or ""),
                workspace_id=str(tool_context.get("workspace_id") or ""),
            )
            if row.get("state") == "conflict":
                raise PermissionDeniedError(
                    "idempotency key was reused with different tool arguments"
                )
            if row.get("state") == "claimed":
                event = asyncio.Event()
                self._operation_events[operation_id] = event
                claim = _OperationClaim(
                    operation_id=operation_id,
                    owner_token=owner_token,
                    effect_id=str(row["effect_id"]),
                    arguments_digest=arguments_digest,
                    wait_event=None,
                )
                self._operation_claims[operation_id] = claim
                return claim
            if row.get("status") != "running":
                return _OperationClaim(
                    operation_id=operation_id,
                    owner_token="",
                    effect_id=str(row.get("effect_id") or ""),
                    arguments_digest=arguments_digest,
                    result=self._deserialize_operation_result(
                        row, call=call, tool=tool
                    ),
                )
            # A running row without a local owner is an orphan from another
            # process or a prior crash.  Quarantine it instead of invoking
            # the handler a second time.
            orphan = self._deserialize_operation_result(row, call=call, tool=tool)
            orphan = replace(
                orphan,
                effect_status=EFFECT_UNKNOWN,
                success=False,
                error="durable operation was running without a live owner",
                retry_safe=False,
                warning=(
                    "previous execution ownership was lost; reconcile before retry"
                ),
                reconciliation_hint=(
                    str(row.get("reconciliation_hint") or "")
                    or "inspect the external side effect using effect_id"
                ),
            )
            await db.mark_tool_operation_unknown(
                operation_id=operation_id,
                reconciliation_hint=orphan.reconciliation_hint,
                result_json=self._serialize_operation_result(orphan),
            )
            return _OperationClaim(
                operation_id=operation_id,
                owner_token="",
                effect_id=str(row.get("effect_id") or ""),
                arguments_digest=arguments_digest,
                result=orphan,
            )

        # Direct unit/library schedulers may use a small fake DB.  Preserve
        # local usability, but close the old concurrent duplicate race with
        # the same claim/event protocol.  Production runtimes always use the
        # durable branch above.
        async with self._idempotency_lock:
            record = self._idempotency_results.get(operation_id)
            if record is not None:
                if record.arguments_digest != arguments_digest:
                    raise PermissionDeniedError(
                        "idempotency key was reused with different tool arguments"
                    )
                return _OperationClaim(
                    operation_id=operation_id,
                    owner_token="",
                    effect_id=record.result.effect_id,
                    arguments_digest=arguments_digest,
                    result=record.result,
                )
            event = self._operation_events.get(operation_id)
            if event is not None:
                active_claim = self._operation_claims.get(operation_id)
                if (
                    active_claim is not None
                    and active_claim.arguments_digest != arguments_digest
                ):
                    raise PermissionDeniedError(
                        "idempotency key was reused with different tool arguments"
                    )
                return _OperationClaim(
                    operation_id=operation_id,
                    owner_token="",
                    effect_id=(active_claim.effect_id if active_claim else ""),
                    arguments_digest=arguments_digest,
                    wait_event=event,
                )
            event = asyncio.Event()
            self._operation_events[operation_id] = event
            claim = _OperationClaim(
                operation_id=operation_id,
                owner_token=owner_token,
                effect_id=effect_id,
                arguments_digest=arguments_digest,
            )
            self._operation_claims[operation_id] = claim
            return claim

    async def _wait_for_operation(
        self,
        claim: _OperationClaim,
        *,
        call: dict,
        tool: Any,
        timeout: float,
    ) -> ToolResult:
        """Wait for an in-process owner, then disclose if it did not finish."""
        event = claim.wait_event
        if event is not None:
            try:
                await asyncio.wait_for(event.wait(), timeout=max(1.0, timeout))
            except TimeoutError:
                return ToolResult(
                    tool_call_id=call["id"],
                    name=tool.name,
                    success=False,
                    error="idempotent operation did not finish before the wait deadline",
                    arguments=call.get("arguments", {}),
                    effect_status=EFFECT_UNKNOWN,
                    delivery_status=DELIVERY_DEGRADED,
                    warning="reconcile effect_id before retry",
                    effect_id=claim.effect_id,
                    reconciliation_hint="the original handler may still be running",
                    retry_safe=False,
                )
        operation_id = claim.operation_id
        result = self._idempotency_results.get(operation_id)
        if result is not None:
            return result.result
        db = getattr(self.permission_engine, "db", None)
        claim_method = getattr(db, "claim_tool_operation", None)
        if callable(claim_method):
            row = await claim_method(
                operation_id=operation_id,
                tool_name=tool.name,
                arguments_digest=_canonical_digest(call.get("arguments", {})),
                effect_id=uuid.uuid4().hex,
                owner_token=uuid.uuid4().hex,
            )
            if row.get("status") != "running":
                return self._deserialize_operation_result(row, call=call, tool=tool)
        return ToolResult(
            tool_call_id=call["id"],
            name=tool.name,
            success=False,
            error="idempotent operation completed without a durable result",
            arguments=call.get("arguments", {}),
            effect_status=EFFECT_UNKNOWN,
            delivery_status=DELIVERY_DEGRADED,
            warning="reconcile effect_id before retry",
            effect_id=claim.effect_id,
            reconciliation_hint="durable result missing",
            retry_safe=False,
        )

    async def _finish_operation(
        self,
        claim: _OperationClaim | None,
        result: ToolResult,
        *,
        terminal_status: str,
    ) -> None:
        """Persist a terminal result and wake duplicate callers."""
        if claim is None:
            return
        db = getattr(self.permission_engine, "db", None)
        complete_method = getattr(db, "complete_tool_operation", None)
        if callable(complete_method) and claim.owner_token:
            updated = await complete_method(
                operation_id=claim.operation_id,
                owner_token=claim.owner_token,
                status=terminal_status,
                effect_status=result.effect_status,
                reconciliation_hint=result.reconciliation_hint,
                result_json=self._serialize_operation_result(result),
            )
            if not updated:
                logger.error(
                    "durable tool operation lost ownership before finalize: %s",
                    claim.operation_id,
                )
        async with self._idempotency_lock:
            if (
                claim.operation_id not in self._idempotency_results
                and len(self._idempotency_results) >= _IDEMPOTENCY_CACHE_LIMIT
            ):
                oldest = min(
                    self._idempotency_results,
                    key=lambda item: self._idempotency_results[item].stored_at,
                )
                self._idempotency_results.pop(oldest, None)
            self._idempotency_results[claim.operation_id] = _IdempotencyRecord(
                arguments_digest=_canonical_digest(result.arguments or {}),
                result=result,
            )
            event = self._operation_events.pop(claim.operation_id, None)
            self._operation_claims.pop(claim.operation_id, None)
            if event is not None:
                event.set()

    async def _update_operation_effect_id(
        self, claim: _OperationClaim, effect_id: str
    ) -> None:
        """Keep a handler-provided external effect ID durable before finalize."""
        if not claim.owner_token or not effect_id:
            return
        db = getattr(self.permission_engine, "db", None)
        update_method = getattr(db, "update_tool_operation_effect_id", None)
        if callable(update_method):
            updated = await update_method(
                operation_id=claim.operation_id,
                owner_token=claim.owner_token,
                effect_id=effect_id,
            )
            if not updated:
                raise RuntimeError("durable tool operation lost ownership")

    def _resolve_target(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        resource: AuthorizationResource | None,
    ) -> str:
        if resource is not None:
            return resource.canonical_target
        try:
            return str(self.permission_engine.normalize_target(tool_name, arguments))
        except Exception:  # noqa: BLE001 - target normalization must fall back safely
            return tool_name

    @staticmethod
    def _execution_preflight_error(
        tool_name: str, mode: str, tool_context: dict[str, Any]
    ) -> str:
        """Reject coding execution before approval when no safe backend exists."""
        if mode != "coding" or tool_name not in {
            "terminal",
            "terminal_argv",
            "terminal_shell",
            "test_run",
        }:
            return ""
        # Small library/test schedulers may intentionally provide a recording
        # handler without an AgentLoop execution authority.  Enforce this
        # preflight only when the runtime has supplied the authority slot;
        # the production AgentLoop always supplies it, including its explicit
        # UnsupportedBackend fail-closed sentinel.
        if "execution_service" not in tool_context:
            return ""
        execution_service = tool_context.get("execution_service")
        if execution_service is None:
            return (
                "ExecutionService unavailable: Coding mode requires sandboxed "
                "execution; direct subprocess fallback is disabled"
            )
        backend = getattr(execution_service, "backend", None)
        if backend is not None and backend.__class__.__name__ == "UnsupportedBackend":
            reason = str(getattr(backend, "reason", "no supported sandbox backend"))
            return (
                "execution refused: no safe execution backend "
                f"(infrastructure unsupported: {reason})"
            )
        if (
            backend is None
            and getattr(execution_service, "backend_selector", None) is None
            and getattr(execution_service, "docker_backend", None) is None
        ):
            return "execution refused: no execution backend configured"
        return ""

    async def _audit_best_effort(
        self,
        tool_name: str,
        target: str,
        result: str,
        detail: dict[str, Any],
        session_id: str | None,
    ) -> str:
        """Attempt an audit without converting a completed effect to failure."""
        try:
            row_id = await self.permission_engine.audit(
                tool_name,
                target,
                result,
                detail,
                session_id,
            )
            if isinstance(row_id, int) and row_id < 0:
                return "audit repository rejected the event"
        except Exception as exc:
            logger.exception(
                "tool audit persistence failed: tool=%s result=%s",
                tool_name,
                result,
            )
            return str(exc)
        return ""

    async def _release_best_effort(self, reservation: ToolBudgetReservation) -> None:
        try:
            await reservation.release()
        except Exception:
            logger.exception("tool budget release failed")

    @staticmethod
    def _idempotency_key(call: dict) -> str:
        return str(call.get("_idempotency_key") or "").strip()

    def _idempotency_scope(
        self,
        call: dict,
        *,
        session_id: str | None,
        tool_context: dict[str, Any],
    ) -> str:
        key = self._idempotency_key(call)
        if not key:
            return ""
        return _canonical_digest(
            {
                "idempotency_key": key,
                "tool_name": call["name"],
                "principal_id": str(tool_context.get("principal_id") or ""),
                "project_id": str(tool_context.get("project_id") or ""),
                "session_id": str(session_id or tool_context.get("session_id") or ""),
                "task_id": str(tool_context.get("task_id") or ""),
                "workspace_id": str(tool_context.get("workspace_id") or ""),
            }
        )

    async def _get_idempotent_result(
        self,
        call: dict,
        *,
        session_id: str | None,
        tool_context: dict[str, Any],
    ) -> ToolResult | None:
        scope = self._idempotency_scope(
            call, session_id=session_id, tool_context=tool_context
        )
        if not scope:
            return None
        arguments_digest = _canonical_digest(call.get("arguments", {}))
        async with self._idempotency_lock:
            record = self._idempotency_results.get(scope)
            if record is None:
                return None
            if record.arguments_digest != arguments_digest:
                raise PermissionDeniedError(
                    "idempotency key was reused with different tool arguments"
                )
            return record.result

    async def _store_idempotent_result(
        self,
        call: dict,
        *,
        session_id: str | None,
        tool_context: dict[str, Any],
        result: ToolResult,
    ) -> None:
        scope = self._idempotency_scope(
            call, session_id=session_id, tool_context=tool_context
        )
        if not scope:
            return
        async with self._idempotency_lock:
            if len(self._idempotency_results) >= _IDEMPOTENCY_CACHE_LIMIT:
                oldest = min(
                    self._idempotency_results,
                    key=lambda item: self._idempotency_results[item].stored_at,
                )
                self._idempotency_results.pop(oldest, None)
            self._idempotency_results[scope] = _IdempotencyRecord(
                arguments_digest=_canonical_digest(call.get("arguments", {})),
                result=result,
            )

    async def _confirm(
        self,
        request: PermissionRequest,
        confirm_callback: ConfirmCallback | None,
    ) -> dict:
        if confirm_callback is None:
            return {"approved": False}
        remaining = request.expires_at - time.time()
        if remaining <= 0:
            return {"approved": False, "reason": "approval_expired_before_callback"}
        payload = {
            "id": request.tool_call_id,
            "name": request.name,
            "arguments": request.arguments,
            "level": request.level,
            "target": request.target,
            "reason": request.reason,
            "binding_digest": request.binding_digest,
            "expires_at": request.expires_at,
            "principal_id": request.principal_id,
            "session_id": request.session_id,
            "task_id": request.task_id,
            "workspace_id": request.workspace_id,
            "arguments_digest": request.arguments_digest,
            "profile_digest": request.profile_digest,
            "project_id": request.project_id,
            "workspace_generation": request.workspace_generation,
            "authorization_resource_digest": request.authorization_resource_digest,
            "authorization_epoch": request.authorization_epoch,
            "policy_digest": request.policy_digest,
            "tool_schema_digest": request.tool_schema_digest,
        }
        try:
            if inspect.iscoroutinefunction(confirm_callback):
                value = await asyncio.wait_for(
                    confirm_callback(payload), timeout=remaining
                )
            else:
                # UI and gateway integrations may supply a synchronous
                # callback.  It is untrusted with respect to latency, so run
                # it off-loop and apply the same approval deadline as an
                # asynchronous callback.  A timed-out worker cannot be
                # force-killed, but it no longer starves scheduling or
                # shutdown and its late result is discarded.
                value = await asyncio.wait_for(
                    asyncio.to_thread(confirm_callback, payload),
                    timeout=remaining,
                )
        except TimeoutError:
            return {"approved": False, "reason": "approval_callback_timeout"}
        if inspect.isawaitable(value):
            # A synchronous adapter may return an awaitable.  Preserve the
            # same fixed approval deadline across both execution phases.
            remaining = request.expires_at - time.time()
            if remaining <= 0:
                return {"approved": False, "reason": "approval_expired_before_callback"}
            try:
                value = await asyncio.wait_for(value, timeout=remaining)
            except TimeoutError:
                return {"approved": False, "reason": "approval_callback_timeout"}
        normalized = _normalize_confirmation(value)
        if normalized.get("reason") == "invalid_confirmation_response":
            logger.warning(
                "approval callback returned a malformed response; denying request"
            )
        return normalized

    async def aclose(self) -> None:
        """Close every runtime-owned background process handle."""
        await self.process_authority.shutdown()

    @staticmethod
    def _normalize_call(call: dict) -> dict:
        normalized = {
            "id": str(call.get("id") or call.get("tool_call_id") or call.get("name")),
            "name": str(call["name"]),
            "arguments": dict(call.get("arguments") or {}),
        }
        idempotency_key = call.get("idempotency_key") or call.get("_idempotency_key")
        if idempotency_key:
            normalized["_idempotency_key"] = str(idempotency_key)
        return normalized


def _canonical_digest(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
