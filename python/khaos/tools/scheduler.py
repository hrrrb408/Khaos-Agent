"""Permission-aware tool scheduling."""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import logging
import os
import shlex
import time
import uuid
from collections.abc import Awaitable, Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Any, cast

from khaos.agent.approval import ApprovalBinding, StepExecutionAuthority
from khaos.coding.execution.authority import ExecutionAuthority
from khaos.coding.execution.capability import DockerSandboxDecision, SandboxDecision
from khaos.coding.execution.environment import is_non_inheritable_secret_key
from khaos.coding.execution.identity import (
    container_command_identity,
    executable_identity,
)
from khaos.coding.execution.models import (
    FileSystemAccess,
    NetworkPolicy,
    PermissionProfile,
    ResolvedSpawnPlan,
    ResourceBudget,
)
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
from khaos.security.credential_broker import CredentialBroker
from khaos.security.middleware import SecurityMiddleware
from khaos.security.network_broker import (
    NetworkBroker,
    NetworkBrokerFactory,
    NetworkLease,
)
from khaos.security.orchestration_components import ToolPhaseCoordinator
from khaos.security.orchestration_phases import (
    OrchestrationPhaseError,
    ToolPhase,
    ToolPhaseSnapshot,
    digest_phase_payload,
)
from khaos.tools.registry import ToolInvocationBroker, ToolRegistry
from khaos.tools.terminal_tools import (
    BackgroundProcessAuthority,
    evaluate_command_safety,
)

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
class ToolExecutionOutcome:
    """Complete handler outcome used at the scheduler boundary.

    A normal Python value is still treated as a successful payload for
    backwards compatibility.  Mutation handlers that can report a handled
    business failure must return this type instead of an error-shaped dict;
    otherwise the scheduler cannot distinguish ``forbidden`` from a
    successful mutation response.
    """

    ok: bool = True
    output: Any = ""
    error: str = ""
    error_code: str = ""
    effect_status: str = ""
    effect_id: str = ""
    reconciliation_hint: str = ""
    retry_safe: bool = True

    def _legacy_payload(self) -> dict[str, Any]:
        """Expose the old JSON-shaped payload to direct tool callers.

        Handlers are migrated independently of callers that invoke them in
        tests or integrations without a Scheduler.  Mapping-like access
        keeps that compatibility while the scheduler consumes the typed
        fields above.
        """
        payload = dict(self.output) if isinstance(self.output, dict) else {}
        payload.setdefault("ok", self.ok)
        if self.error:
            payload.setdefault("error", self.error)
        return payload

    def __getitem__(self, key: str) -> Any:
        return self._legacy_payload()[key]

    def get(self, key: str, default: Any = None) -> Any:
        return self._legacy_payload().get(key, default)

    def __contains__(self, key: object) -> bool:
        return key in self._legacy_payload()

    def __eq__(self, other: object) -> bool:
        if isinstance(other, dict):
            return self._legacy_payload() == other
        return super().__eq__(other)


@dataclass
class EffectOutcome:
    """Backward-compatible effect-only outcome.

    Existing handlers use ``status=...``.  New handlers should prefer
    :class:`ToolExecutionOutcome`, which also carries explicit business
    failure state and an error code.
    """

    status: str
    effect_id: str = ""
    reconciliation_hint: str = ""
    output: Any = ""
    ok: bool = True
    error: str = ""
    error_code: str = ""
    retry_safe: bool = True


@dataclass
class ToolResult:
    """Normalized result for one tool call."""

    tool_call_id: str
    name: str
    success: bool
    output: Any = ""
    error: str = ""
    error_code: str = ""
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
    # Immutable ToolScheduler phase evidence.  Empty is retained only for
    # direct legacy helper calls that bypass ``stream_batch``.
    phase_digest: str = ""


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
    tool_security_digest: str = ""
    approval_id: str = ""
    # Final digest of the immutable authority consumed by execution.  The
    # binding itself carries the pre-receipt scope digest.
    step_execution_digest: str = ""


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
        network_broker_factory: NetworkBrokerFactory | None = None,
        credential_broker: CredentialBroker | None = None,
    ):
        self.registry = registry
        self.permission_engine = permission_engine
        self.budget = budget or ToolBudget()
        self.security_middleware = security_middleware or SecurityMiddleware()
        # H5: per-runtime identifier propagated to the broker so browser
        # tools can key their BrowserContext by (principal, session, runtime).
        self.runtime_id = runtime_id
        self.network_broker_factory: NetworkBrokerFactory = (
            network_broker_factory or NetworkBrokerFactory()
        )
        self.credential_broker = credential_broker
        self._network_brokers: set[NetworkBroker] = set()
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
        # Idempotency is server-owned and runtime-scoped.  Model tool-call
        # IDs are only one input to the server binding; a model or plugin
        # supplied top-level ``idempotency_key`` is never trusted.
        self._idempotency_lock = asyncio.Lock()
        self._idempotency_results: dict[str, _IdempotencyRecord] = {}
        # A durable row is the authority; these maps only coordinate
        # duplicate callers in this process.  A missing in-process owner on a
        # restart is treated as UNKNOWN and is never replayed automatically.
        self._operation_events: dict[str, asyncio.Event] = {}
        self._operation_claims: dict[str, _OperationClaim] = {}
        self._operation_claim_lock = asyncio.Lock()
        # Synchronous confirm callbacks (UI/gateway adapters) run here,
        # never on the loop's default executor: a hanging callback may
        # occupy one of the bounded workers forever — that later approvals
        # then fail closed on their own deadline is the intended bound,
        # where before they accumulated leaked default-executor threads
        # and eventually starved unrelated asyncio.to_thread users.
        self._approval_executor = ThreadPoolExecutor(
            max_workers=4, thread_name_prefix="khaos-approval-callback"
        )

    def set_office_authority(self, authority: Any) -> None:
        """Register the shared OfficeMutationAuthority (called at startup)."""
        self.office_authority = authority

    def bind_server_operation_key(
        self,
        call: dict[str, Any],
        *,
        session_id: str | None,
        turn_id: str,
        attempt_id: str,
        tool_context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Bind a model tool call to a server-owned durable operation key.

        The model never supplies this value.  The key is derived from the
        authenticated execution scope and the durable turn/attempt identity;
        arguments are deliberately excluded and are stored separately as the
        operation conflict digest.
        """
        prepared = dict(call)
        prepared.pop("idempotency_key", None)
        prepared.pop("_idempotency_key", None)
        name = str(prepared.get("name") or "")
        tool = self.registry.get(name)
        if self._declared_effect_status(tool) != EFFECT_NOT_APPLIED:
            context = dict(tool_context or {})
            prepared["_idempotency_key"] = server_operation_key(
                principal_id=str(context.get("principal_id") or ""),
                project_id=str(context.get("project_id") or ""),
                session_id=str(session_id or context.get("session_id") or ""),
                turn_id=str(turn_id or ""),
                attempt_id=str(attempt_id or ""),
                tool_call_id=str(
                    prepared.get("id") or prepared.get("tool_call_id") or ""
                ),
                tool_name=name,
                workspace_id=str(context.get("workspace_id") or ""),
            )
            prepared["_server_operation_key"] = True
        return prepared

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

    @staticmethod
    def _advance_tool_phase(
        call: dict[str, Any],
        next_phase: ToolPhase,
        **evidence: Any,
    ) -> ToolPhaseSnapshot:
        """Advance the immutable phase evidence attached to one call."""
        return ToolPhaseCoordinator.advance(call, next_phase, **evidence)

    @staticmethod
    def _terminalize_tool_phase(
        call: dict[str, Any],
        result: ToolResult,
    ) -> ToolResult:
        """Close a dispatched call and expose its immutable phase digest."""
        return ToolPhaseCoordinator.terminalize(call, result)

    async def stream_batch(
        self,
        tool_calls: list[dict],
        mode: str,
        session_id: str | None = None,
        confirm_callback: ConfirmCallback | None = None,
        tool_context: dict[str, Any] | None = None,
    ):
        """Execute a batch and always reclaim any managed egress lease."""
        try:
            async for event in self._stream_batch_impl(
                tool_calls,
                mode,
                session_id,
                confirm_callback,
                tool_context,
            ):
                yield event
        finally:
            await self._close_all_network_brokers()

    async def _stream_batch_impl(
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
        if "credential_broker" not in tool_context:
            tool_context["credential_broker"] = self.credential_broker
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
            try:
                raw_phase = ToolPhaseSnapshot.raw(normalized)
            except OrchestrationPhaseError as exc:
                yield SchedulerEvent(
                    event="tool_result",
                    result=ToolResult(
                        tool_call_id=normalized["id"],
                        name=normalized["name"],
                        success=False,
                        error=f"Tool phase admission rejected: {exc}",
                        arguments=normalized["arguments"],
                    ),
                )
                continue
            normalized["_phase_snapshot"] = raw_phase
            normalized["_phase_digest"] = raw_phase.digest()
            tool = self.registry.get(normalized["name"])
            # Production AgentLoop calls are already bound to a server key.
            # Generate one here as a defense-in-depth boundary for direct
            # scheduler callers that do not provide an explicit key.  The
            # model-visible tool_call_id is not used as the key by itself.
            if (
                self._declared_effect_status(tool) != EFFECT_NOT_APPLIED
                and not self._idempotency_key(normalized)
            ):
                normalized["_idempotency_key"] = server_operation_key(
                    principal_id=str(tool_context.get("principal_id") or ""),
                    project_id=str(tool_context.get("project_id") or ""),
                    session_id=str(session_id or tool_context.get("session_id") or ""),
                    turn_id=str(
                        tool_context.get("turn_id") or f"session:{session_id or ''}"
                    ),
                    attempt_id=str(tool_context.get("attempt_id") or "legacy"),
                    tool_call_id=normalized["id"],
                    tool_name=tool.name,
                    workspace_id=str(tool_context.get("workspace_id") or ""),
                )
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
            self._advance_tool_phase(normalized, ToolPhase.VALIDATED)

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
            self._advance_tool_phase(
                normalized,
                ToolPhase.RESOURCE_RESOLVED,
                resource_digest=resource.digest() if resource is not None else "",
            )

            execution_error = self._execution_preflight_error(
                tool, mode, tool_context
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
            self._advance_tool_phase(
                normalized,
                ToolPhase.PERMISSION_DECIDED,
                permission_digest=digest_phase_payload(
                    {
                        "approved": decision.approved.value,
                        "requires_user_confirm": decision.requires_user_confirm,
                        "target": decision.target,
                        "reason": decision.reason,
                    }
                ),
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

            approval_target = decision.target
            if destructive_context is not None:
                binding = destructive_context["binding"]
                approval_target = (
                    f"{binding['operation']}:{binding['target']} "
                    f"head={binding['head']} diff={binding['diff_hash']}"
                )

            try:
                await self._prepare_network_authority_inputs(
                    tool=tool,
                    call=normalized,
                    tool_context=tool_context,
                    resource=resource,
                )
                await self._prepare_sandbox_authority_inputs(
                    tool=tool,
                    call=normalized,
                    tool_context=tool_context,
                )
            except (PermissionError, ValueError) as exc:
                await self._close_network_broker(normalized)
                yield SchedulerEvent(
                    event="tool_result",
                    result=ToolResult(
                        tool_call_id=normalized["id"],
                        name=tool.name,
                        success=False,
                        error=f"Execution authority rejected: {exc}",
                        arguments=normalized["arguments"],
                    ),
                )
                continue

            # Freeze the authority after all pre-approval target/resource
            # resolution has completed.  The same immutable object is carried
            # through the approval request and into the invocation broker.
            authorization_epoch = await self.permission_engine.authorization_snapshot()
            step_authority = self._build_step_authority(
                tool=tool,
                call=normalized,
                tool_context=tool_context,
                resource=resource,
                authorization_epoch=authorization_epoch,
                approval_target=approval_target,
            )
            normalized["_step_authority"] = step_authority
            normalized["_step_authority_required"] = True
            normalized["_step_authority_scope_digest"] = step_authority.scope_digest()
            normalized["_step_execution_digest"] = step_authority.digest()

            if decision.requires_user_confirm or destructive_context is not None:
                principal_id = str(tool_context.get("principal_id") or "")
                current_session = str(session_id or "")
                if not principal_id or not current_session:
                    await self._close_network_broker(normalized)
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
                    tool_security_digest=tool.security_digest,
                    step_authority_digest=step_authority.scope_digest(),
                )
                broker = tool_context.get("approval_broker")
                if broker is None:
                    await self._close_network_broker(normalized)
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
                step_authority = replace(
                    step_authority,
                    approval_receipt_digest=binding_digest,
                )
                normalized["_step_authority"] = step_authority
                normalized["_step_execution_digest"] = step_authority.digest()
                normalized["_approval_id"] = getattr(
                    approval_handle, "approval_id", ""
                )
                normalized["_approval_binding_digest"] = binding_digest
                normalized["_approval_schema_digest"] = binding.tool_schema_digest
                normalized["_approval_security_digest"] = binding.tool_security_digest
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
                    tool_security_digest=binding.tool_security_digest,
                    step_execution_digest=step_authority.digest(),
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
                    await self._close_network_broker(normalized)
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
                        await self._close_network_broker(normalized)
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
            self._advance_tool_phase(
                normalized,
                ToolPhase.APPROVAL_BOUND,
                approval_digest=str(
                    normalized.get("_approval_binding_digest") or ""
                ),
            )
            self._advance_tool_phase(
                normalized,
                ToolPhase.AUTHORIZED_EFFECT,
                authority_digest=str(
                    normalized.get("_step_execution_digest") or ""
                ),
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
                    await self._close_network_broker(call)
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
                    await self._close_network_broker(call)
                    yield SchedulerEvent(
                        event="tool_result",
                        result=ToolResult(
                            tool_call_id=call["id"], name=call["name"],
                            success=False, error="Tool budget reservation denied",
                            arguments=call["arguments"],
                        ),
                    )
                    continue
                self._advance_tool_phase(call, ToolPhase.DISPATCHING)
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
                await self._close_network_broker(call)
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
            self._advance_tool_phase(call, ToolPhase.DISPATCHING)
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
        try:
            result = await self._execute_one_impl(
                call, session_id, mode, tool_context, reservation
            )
            return self._terminalize_tool_phase(call, result)
        finally:
            await self._close_network_broker(call)

    async def _execute_one_impl(
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
        handler_ok = True
        handler_error = ""
        handler_error_code = ""
        handler_retry_safe = True
        effect_id = ""
        effect_status = EFFECT_NOT_STARTED
        reconciliation_hint = str(getattr(tool, "reconciliation_hint", "") or "")
        operation_claim: _OperationClaim | None = None
        step_authority = call.get("_step_authority")
        try:
            self._verify_step_authority(
                authority=step_authority,
                call=call,
                tool=tool,
                tool_context=tool_context,
                resource=resource,
            )
            await self.permission_engine.validate_dispatch_epoch(
                int(call.get("_authorization_epoch", 0))
            )
            expected_schema = call.get("_approval_schema_digest")
            if expected_schema and expected_schema != tool.schema_digest:
                raise PermissionDeniedError(
                    "Tool schema changed before dispatch; re-approval required"
                )
            # Batch 15.6: verify the COMPLETE security contract digest
            # (capabilities, permission_level, resource_resolver,
            # effect_status, modes, parallel, timeout) has not drifted
            # since approval.  This catches mutations that schema_digest
            # (name + parameters only) would miss.
            expected_security = call.get("_approval_security_digest")
            if expected_security and expected_security != tool.security_digest:
                raise PermissionDeniedError(
                    "Tool security contract changed before dispatch; "
                    "re-approval required"
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
                    session_id=session_id,
                    tool_context=tool_context,
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
            if isinstance(step_authority, StepExecutionAuthority):
                invocation_context["step_execution_authority"] = step_authority
                invocation_context["step_execution_digest"] = step_authority.digest()
                invocation_context["step_authority_required"] = bool(
                    call.get("_step_authority_required")
                )
            if call.get("_sandbox_decision") is not None:
                invocation_context["sandbox_decision"] = call["_sandbox_decision"]
            if call.get("_executable_identity"):
                invocation_context["executable_identity"] = call[
                    "_executable_identity"
                ]
            if call.get("_spawn_plan") is not None:
                invocation_context["spawn_plan"] = call["_spawn_plan"]
            if isinstance(step_authority, StepExecutionAuthority) and isinstance(
                call.get("_spawn_plan"), ResolvedSpawnPlan
            ):
                invocation_context["execution_authority"] = ExecutionAuthority(
                    step_authority=step_authority,
                    spawn_plan=call["_spawn_plan"],
                )
            if call.get("_network_lease") is not None:
                invocation_context["network_lease"] = call["_network_lease"]
            invocation_context["effect_id"] = effect_id
            output = await asyncio.wait_for(
                self.invocation_broker.invoke(tool.name, mode=mode, context=invocation_context, **call.get("arguments", {})),
                timeout=tool.timeout,
            )
            outcome = self._normalize_effect_outcome(
                output,
                default_status=self._declared_effect_status(tool),
                default_effect_id=effect_id,
                default_reconciliation_hint=reconciliation_hint,
            )
            output = outcome.output
            handler_ok = outcome.ok
            handler_error = outcome.error
            handler_error_code = outcome.error_code
            handler_retry_safe = outcome.retry_safe
            effect_status = outcome.effect_status
            effect_id = outcome.effect_id
            reconciliation_hint = outcome.reconciliation_hint
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
                    error_code="TOOL_CANCELLED",
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
                result = await self._finish_operation(
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
                error_code=type(exc).__name__.upper(),
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
            result = await self._finish_operation(
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

        if not handler_ok:
            # A handled business failure is not an infrastructure exception.
            # Preserve its structured error and classify the operation as
            # ``not_applied`` unless the handler explicitly reported a
            # partial/unknown external effect.
            await self._release_best_effort(reservation)
            safe_output = output
            delivery_status = DELIVERY_COMPLETE
            warning = ""
            try:
                _measure_tool_output(safe_output, reservation.output_limit)
                _secret_scan, safe_output = await self.security_middleware.post_check(
                    tool.name, safe_output
                )
            except Exception as exc:  # noqa: BLE001 - error projection is best effort
                safe_output = ""
                delivery_status = DELIVERY_DEGRADED
                warning = f"error result delivery failed: {exc}"
            detail = {
                "tool_call_id": call["id"],
                "error": handler_error or "tool handler reported failure",
                "error_code": handler_error_code or "TOOL_REPORTED_FAILURE",
                "effect_id": effect_id,
                "effect_status": effect_status,
                "reconciliation_hint": reconciliation_hint,
            }
            audit_error = await self._audit_best_effort(
                tool.name, target, "failure", detail, session_id
            )
            if audit_error:
                delivery_status = DELIVERY_AUDIT_DEGRADED
                warning = (
                    f"{warning}; " if warning else ""
                ) + f"audit persistence failed: {audit_error}"
            result = ToolResult(
                tool_call_id=call["id"],
                name=tool.name,
                success=False,
                output=safe_output,
                error=handler_error or "tool handler reported failure",
                error_code=handler_error_code or "TOOL_REPORTED_FAILURE",
                duration_ms=int((time.monotonic() - start) * 1000),
                arguments=call["arguments"],
                effect_status=effect_status,
                delivery_status=delivery_status,
                warning=warning,
                effect_id=effect_id,
                reconciliation_hint=reconciliation_hint,
                retry_safe=handler_retry_safe and effect_status == EFFECT_NOT_APPLIED,
            )
            result = await self._finish_operation(
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
            result = await self._finish_operation(
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
        result = await self._finish_operation(
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
    ) -> ToolExecutionOutcome:
        """Normalize explicit outcomes and legacy error-shaped payloads.

        Legacy handlers may still return their payload directly and use the
        registered normal effect declaration.  New mutation handlers can
        return ``ToolExecutionOutcome`` to report business failure without
        abusing exceptions.  During migration, common structured error
        dictionaries are also converted so ``forbidden``/``not_found`` can
        never be reported as a successful mutation.
        """
        if isinstance(value, ToolExecutionOutcome):
            ok = bool(value.ok)
            status = str(value.effect_status or "")
            output = value.output
            error = str(value.error or "")
            error_code = str(value.error_code or "")
            effect_id = str(value.effect_id or default_effect_id)
            reconciliation_hint = str(
                value.reconciliation_hint or default_reconciliation_hint
            )
            retry_safe = bool(value.retry_safe)
        elif isinstance(value, EffectOutcome):
            ok = bool(value.ok)
            status = str(value.status or "")
            output = value.output
            error = str(value.error or "")
            error_code = str(value.error_code or "")
            effect_id = str(value.effect_id or default_effect_id)
            reconciliation_hint = str(
                value.reconciliation_hint or default_reconciliation_hint
            )
            retry_safe = bool(value.retry_safe)
        else:
            output = value
            legacy_payload = value
            if isinstance(value, str):
                # GitHub and a few older remote adapters serialized their
                # result dictionaries before returning them.  Decode only a
                # JSON object for failure classification; preserve the
                # original string as the user-visible output.
                try:
                    decoded = json.loads(value)
                except (TypeError, ValueError, json.JSONDecodeError):
                    decoded = None
                if isinstance(decoded, dict):
                    legacy_payload = decoded
            status_marker = (
                str(legacy_payload.get("status") or "").strip().lower()
                if isinstance(legacy_payload, dict)
                else ""
            )
            failure_markers = {
                "error", "failed", "failure", "forbidden", "invalid",
                "invalid_state", "not_found", "not_initialized", "unavailable",
            }
            handled_failure = isinstance(legacy_payload, dict) and (
                legacy_payload.get("ok") is False
                or legacy_payload.get("success") is False
                or status_marker in failure_markers
                or bool(legacy_payload.get("error"))
                or legacy_payload.get("created") is False
            )
            ok = not handled_failure
            status = EFFECT_NOT_APPLIED if handled_failure else default_status
            error = ""
            error_code = ""
            if handled_failure:
                error = str(
                    legacy_payload.get("error")
                    or legacy_payload.get("message")
                    or status_marker
                    or "tool handler reported failure"
                )
                error_code = str(
                    legacy_payload.get("error_code")
                    or legacy_payload.get("code")
                    or (status_marker.upper() if status_marker else "TOOL_REPORTED_FAILURE")
                )
            effect_id = default_effect_id
            reconciliation_hint = default_reconciliation_hint
            retry_safe = handled_failure
        if not status:
            status = EFFECT_NOT_APPLIED if not ok else default_status
        if not ok and status == EFFECT_UNKNOWN and not effect_id:
            status = EFFECT_NOT_APPLIED
        if status not in {
            EFFECT_NOT_APPLIED,
            EFFECT_APPLIED,
            EFFECT_PARTIAL,
            EFFECT_UNKNOWN,
        }:
            raise ValueError(f"invalid ToolExecutionOutcome effect status: {status!r}")
        if len(effect_id) > 256 or any(char in effect_id for char in "\x00\r\n"):
            raise ValueError("invalid ToolExecutionOutcome effect_id")
        if len(reconciliation_hint) > 4096 or any(
            char in reconciliation_hint for char in "\x00\r\n"
        ):
            raise ValueError("invalid ToolExecutionOutcome reconciliation_hint")
        return ToolExecutionOutcome(
            ok=ok,
            output=output,
            error=error,
            error_code=error_code,
            effect_status=status,
            effect_id=effect_id,
            reconciliation_hint=reconciliation_hint,
            retry_safe=retry_safe,
        )

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
                        error_code=str(values.get("error_code") or ""),
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
        # The in-process result cache is authoritative for callers that are
        # already in this runtime, even when durable completion failed.  A
        # database row may still be ``running`` in that case; consulting it
        # first would misclassify a known completed effect as an orphan and
        # make the second caller lose the original effect facts.
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
            claim_operation = cast(
                Callable[..., Awaitable[dict[str, Any]]], claim_method
            )
            row = await claim_operation(
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
                    str(
                        row.get("conflict_reason")
                        or "idempotency operation identity conflict"
                    )
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
            mark_unknown = getattr(db, "mark_tool_operation_unknown", None)
            if callable(mark_unknown):
                mark_operation_unknown = cast(
                    Callable[..., Awaitable[object]], mark_unknown
                )
                await mark_operation_unknown(
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
        session_id: str | None,
        tool_context: dict[str, Any],
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
            claim_operation = cast(
                Callable[..., Awaitable[dict[str, Any]]], claim_method
            )
            row = await claim_operation(
                operation_id=operation_id,
                tool_name=tool.name,
                arguments_digest=_canonical_digest(call.get("arguments", {})),
                effect_id=uuid.uuid4().hex,
                owner_token=uuid.uuid4().hex,
                principal_id=str(tool_context.get("principal_id") or ""),
                project_id=str(tool_context.get("project_id") or ""),
                session_id=str(session_id or tool_context.get("session_id") or ""),
                task_id=str(tool_context.get("task_id") or ""),
                workspace_id=str(tool_context.get("workspace_id") or ""),
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
    ) -> ToolResult:
        """Persist a terminal result and wake duplicate callers.

        Finalization is a second failure boundary.  A handler may already
        have changed an external system when SQLite, audit storage, or a
        commit callback fails.  In that case the result is cached and all
        in-process waiters are released with a degraded, non-retryable
        result; the scheduler must never turn a journal failure into a blind
        second dispatch.
        """
        if claim is None:
            return result
        journal_error = ""
        db = getattr(self.permission_engine, "db", None)
        complete_method = getattr(db, "complete_tool_operation", None)
        if callable(complete_method) and claim.owner_token:
            try:
                result_json = self._serialize_operation_result(result)
                complete_operation = cast(
                    Callable[..., Awaitable[object]], complete_method
                )
                updated = await complete_operation(
                    operation_id=claim.operation_id,
                    owner_token=claim.owner_token,
                    status=terminal_status,
                    effect_status=result.effect_status,
                    reconciliation_hint=result.reconciliation_hint,
                    result_json=result_json,
                )
                if not updated:
                    journal_error = "durable tool operation lost ownership before finalize"
            except Exception as exc:
                journal_error = f"durable operation finalization failed: {exc}"
                logger.exception(
                    "durable tool operation finalization failed: operation_id=%s",
                    claim.operation_id,
                )
        try:
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
                cached_result = result
                if journal_error:
                    hint = result.reconciliation_hint or (
                        "durable operation finalization failed; reconcile effect_id "
                        "before retry"
                    )
                    warning = result.warning
                    warning = f"{warning}; " if warning else ""
                    warning += journal_error
                    cached_result = replace(
                        result,
                        delivery_status=(
                            result.delivery_status
                            if result.delivery_status == DELIVERY_AUDIT_DEGRADED
                            else DELIVERY_DEGRADED
                        ),
                        warning=warning,
                        reconciliation_hint=hint,
                        retry_safe=False,
                    )
                self._idempotency_results[claim.operation_id] = _IdempotencyRecord(
                    arguments_digest=_canonical_digest(
                        cached_result.arguments or {}
                    ),
                    result=cached_result,
                )
                event = self._operation_events.pop(claim.operation_id, None)
                self._operation_claims.pop(claim.operation_id, None)
                if event is not None:
                    event.set()
                return cached_result
        except Exception as exc:
            logger.exception(
                "in-process operation finalization failed: operation_id=%s",
                claim.operation_id,
            )
            warning = result.warning
            warning = f"{warning}; " if warning else ""
            warning += f"in-process operation finalization failed: {exc}"
            return replace(
                result,
                delivery_status=(
                    result.delivery_status
                    if result.delivery_status == DELIVERY_AUDIT_DEGRADED
                    else DELIVERY_DEGRADED
                ),
                warning=warning,
                reconciliation_hint=(
                    result.reconciliation_hint
                    or "operation finalization failed; reconcile effect_id before retry"
                ),
                retry_safe=False,
            )

    async def _update_operation_effect_id(
        self, claim: _OperationClaim, effect_id: str
    ) -> None:
        """Keep a handler-provided external effect ID durable before finalize."""
        if not claim.owner_token or not effect_id:
            return
        db = getattr(self.permission_engine, "db", None)
        update_method = getattr(db, "update_tool_operation_effect_id", None)
        if callable(update_method):
            update_effect_id = cast(Callable[..., Awaitable[object]], update_method)
            updated = await update_effect_id(
                operation_id=claim.operation_id,
                owner_token=claim.owner_token,
                effect_id=effect_id,
            )
            if not updated:
                raise RuntimeError("durable tool operation lost ownership")

    def _build_step_authority(
        self,
        *,
        tool,
        call: dict[str, Any],
        tool_context: dict[str, Any],
        resource: AuthorizationResource | None,
        authorization_epoch: int,
        approval_target: str,
        approval_receipt_digest: str = "",
    ) -> StepExecutionAuthority:
        """Freeze the exact authority scope used by one scheduler step.

        Production AgentLoop contexts provide every identity explicitly.  The
        namespaced legacy fallbacks keep direct library/test schedulers
        usable; ``build_runtime`` still rejects an empty production principal
        before a scheduler can be exposed.
        """
        principal_id = str(tool_context.get("principal_id") or "legacy-principal")
        principal_kind = str(tool_context.get("principal_kind") or "")
        parent_principal_id = str(tool_context.get("parent_principal_id") or "")
        delegation_digest = str(tool_context.get("delegation_digest") or "")
        if tool_context.get("production_runtime") and not all(
            (principal_kind, parent_principal_id, delegation_digest)
        ):
            raise PermissionDeniedError(
                "production execution requires a complete typed principal delegation"
            )
        project_id = str(tool_context.get("project_id") or "legacy-project")
        session_id = str(tool_context.get("session_id") or "legacy-session")
        task_id = str(tool_context.get("task_id") or f"session:{session_id}")
        turn_id = str(tool_context.get("turn_id") or f"turn:{call['id']}")
        step_id = str(tool_context.get("attempt_id") or f"step:{call['id']}")
        workspace_id = str(
            tool_context.get("workspace_id") or f"session:{session_id}"
        )
        workspace_generation = int(
            resource.workspace_generation
            if resource is not None
            else tool_context.get("workspace_generation", 0) or 0
        )
        cwd_identity = _authority_identity(
            tool_context.get(
                "cwd_identity",
                tool_context.get("workspace_cwd_identity", "cwd:unspecified"),
            )
        )
        requested_cwd = call.get("arguments", {}).get("cwd")
        if requested_cwd is not None:
            # The model controls the relative cwd argument.  Bind it into
            # the snapshot alongside the workspace identity; the execution
            # backend performs the final dirfd/inode verification later.
            cwd_identity = _authority_identity((cwd_identity, str(requested_cwd)))
        target = self._resolve_target(tool.name, call.get("arguments", {}), resource)
        effective_policy_digest = str(
            tool_context.get("effective_policy_digest") or ""
        )
        permission_profile_digest = str(
            tool_context.get("permission_profile_digest")
            or _canonical_digest(
                {
                    "permission_level": tool.permission_level,
                    "target": approval_target,
                    "network_policy": tool_context.get("network_policy", "none"),
                    "effective_policy_digest": effective_policy_digest,
                }
            )
        )
        environment_keys = tool_context.get("environment_keys")
        if environment_keys is None:
            environment_keys = tool_context.get("execution_environment_keys")
        if environment_keys is None:
            profile = tool_context.get("permission_profile")
            environment_keys = getattr(profile, "environment_keys", None)
        if isinstance(environment_keys, str):
            environment_keys = (environment_keys,)
        if environment_keys is None:
            environment_keys = ("LANG", "LC_ALL", "PATH", "TMPDIR")
        normalized_environment_keys = tuple(
            sorted(
                {
                    str(key)
                    for key in environment_keys
                    if not is_non_inheritable_secret_key(str(key))
                }
            )
        )
        if not normalized_environment_keys:
            normalized_environment_keys = ("LANG", "LC_ALL", "PATH", "TMPDIR")
        if getattr(tool, "execution_kind", "host-sandbox") == "docker":
            normalized_environment_keys = ("KHAOS_DOCKER_IMAGE",)

        execution_service = tool_context.get("execution_service")
        backend = call.get("_sandbox_backend") or tool_context.get("sandbox_backend")
        if backend is None:
            backend = tool_context.get("execution_backend")
        if backend is None and execution_service is not None:
            backend = getattr(execution_service, "backend", None)
            if backend is None:
                backend = getattr(execution_service, "backend_selector", None)
        sandbox_decision = call.get("_sandbox_decision")
        if sandbox_decision is None:
            sandbox_decision = tool_context.get("sandbox_decision")
        if sandbox_decision is not None and not isinstance(
            sandbox_decision, SandboxDecision
        ):
            raise PermissionDeniedError("sandbox decision is not immutable")
        if isinstance(sandbox_decision, SandboxDecision):
            sandbox_backend = sandbox_decision.backend_name
            sandbox_decision_digest = sandbox_decision.digest()
        else:
            sandbox_backend = _authority_identity(backend or "backend:unspecified")
            sandbox_decision_digest = _authority_identity(
                tool_context.get("sandbox_decision_digest")
                or "decision:unspecified"
            )

        environment_values = tool_context.get("environment")
        if getattr(tool, "execution_kind", "host-sandbox") == "docker":
            environment_values = {
                "KHAOS_DOCKER_IMAGE": str(
                    call.get("arguments", {}).get("image") or ""
                )
            }
        if isinstance(environment_values, dict):
            environment_payload = {
                str(key): str(environment_values[key])
                for key in normalized_environment_keys
                if key in environment_values
                and not is_non_inheritable_secret_key(str(key))
            }
        else:
            environment_payload = {
                key: os.environ.get(key, _default_environment_value(key))
                for key in normalized_environment_keys
            }
        environment_digest = _canonical_digest(environment_payload)
        executable_scope = call.get("_executable_identity") or tool_context.get(
            "executable_identity"
        )
        argv = _execution_argv_for_authority(tool.name, call.get("arguments", {}))
        execution_kind = str(getattr(tool, "execution_kind", "host-sandbox"))
        if execution_kind == "docker" and argv and not executable_scope:
            decision = call.get("_sandbox_decision") or tool_context.get(
                "sandbox_decision"
            )
            image = str(call.get("arguments", {}).get("image") or "image:unspecified")
            if isinstance(decision, DockerSandboxDecision):
                image = decision.image_digest
                executable_scope = container_command_identity(
                    image,
                    argv,
                    command_digest=decision.command_digest,
                )
            else:
                executable_scope = container_command_identity(image, argv)
        if not executable_scope:
            executable_scope = (
                executable_identity(argv, environment_payload)
                if argv
                else "executable:not-applicable"
            )

        network_guard = tool_context.get("network_guard")
        network_lease = call.get("_network_lease")
        network_authority = tool_context.get("network_authority")
        if network_authority is None:
            network_authority = tool_context.get("network_authority_digest")
        if network_authority is None:
            network_authority = _canonical_digest(
                {
                    "guard_type": (
                        type(network_guard).__qualname__
                        if network_guard is not None
                        else "none"
                    ),
                    "network_enabled": getattr(
                        network_guard, "network_enabled", False
                    ),
                    "allowed_domains": _authority_sequence(
                        getattr(network_guard, "allowed_domains", None)
                    ),
                    "blocked_domains": _authority_sequence(
                        getattr(network_guard, "blocked_domains", None)
                    ),
                    "network_policy": tool_context.get("network_policy", "none"),
                    "effective_policy_digest": effective_policy_digest,
                }
            )
        if network_lease is not None:
            network_authority = getattr(network_lease, "identity_digest", "")
            if not network_authority:
                raise PermissionDeniedError("managed network lease has no identity")
        network_authority = _authority_identity(network_authority)
        authorization_resource_digest = (
            resource.digest() if resource is not None else "resource:none"
        )
        spawn_plan = call.get("_spawn_plan")
        if spawn_plan is None:
            spawn_plan = _build_spawn_plan(
                tool=tool,
                call=call,
                tool_context=tool_context,
                workspace_generation=workspace_generation,
                permission_profile_digest=permission_profile_digest,
                sandbox_decision_digest=sandbox_decision_digest,
                network_authority=network_authority,
                environment_payload=environment_payload,
                executable_scope=str(executable_scope),
                argv=argv,
                network_lease=network_lease,
                principal_kind=principal_kind,
                parent_principal_id=parent_principal_id,
                delegation_digest=delegation_digest,
            )
            call["_spawn_plan"] = spawn_plan
        elif not isinstance(spawn_plan, ResolvedSpawnPlan):
            raise PermissionDeniedError("resolved spawn plan is not immutable")
        permission_profile_digest = spawn_plan.permission_profile_digest
        return StepExecutionAuthority(
            principal_id=principal_id,
            project_id=project_id,
            session_id=session_id,
            task_id=task_id,
            turn_id=turn_id,
            step_id=step_id,
            tool_call_id=str(call["id"]),
            tool_name=tool.name,
            workspace_id=workspace_id,
            workspace_generation=workspace_generation,
            cwd_identity=cwd_identity,
            permission_profile_digest=permission_profile_digest,
            environment_keys=normalized_environment_keys,
            environment_digest=environment_digest,
            sandbox_backend=sandbox_backend,
            sandbox_decision_digest=sandbox_decision_digest,
            executable_identity=str(executable_scope),
            network_authority=network_authority,
            target=target,
            approval_target=str(approval_target),
            arguments_digest=_canonical_digest(call.get("arguments", {})),
            authorization_resource_digest=authorization_resource_digest,
            authorization_epoch=int(authorization_epoch),
            policy_digest=str(
                self.permission_engine.policy_digest or "policy:unspecified"
            ),
            tool_schema_digest=tool.schema_digest,
            tool_security_digest=tool.security_digest,
            spawn_plan_digest=spawn_plan.digest(),
            approval_receipt_digest=str(approval_receipt_digest or ""),
            principal_kind=principal_kind,
            parent_principal_id=parent_principal_id,
            delegation_digest=delegation_digest,
        )

    async def _prepare_sandbox_authority_inputs(
        self,
        *,
        tool,
        call: dict[str, Any],
        tool_context: dict[str, Any],
    ) -> None:
        """Bind concrete sandbox evidence before the approval snapshot."""
        if not _tool_has_capability(tool, "process.execute"):
            return
        argv = _execution_argv_for_authority(tool.name, call.get("arguments", {}))
        execution_kind = str(getattr(tool, "execution_kind", "host-sandbox"))
        if execution_kind == "process-control":
            return
        service = tool_context.get("execution_service")
        if execution_kind == "docker":
            decision = call.get("_sandbox_decision") or tool_context.get(
                "sandbox_decision"
            )
            if decision is not None:
                if not isinstance(decision, DockerSandboxDecision):
                    raise PermissionError(
                        "Docker execution requires a concrete DockerSandboxDecision"
                    )
                call["_sandbox_decision"] = decision
                call["_sandbox_backend"] = decision.backend_name
                if argv:
                    call["_executable_identity"] = container_command_identity(
                        decision.image_digest,
                        argv,
                        command_digest=decision.command_digest,
                    )
                return
            resolver = getattr(service, "prepare_docker_decision", None)
            if not callable(resolver):
                if tool_context.get("production_runtime") or tool_context.get(
                    "coding_workspace_enforced"
                ):
                    raise PermissionError(
                        "Docker execution requires a preflight DockerSandboxDecision"
                    )
                return
            resolve_docker = cast(
                Callable[..., Awaitable[DockerSandboxDecision]], resolver
            )
            decision = await resolve_docker(
                tool_name=tool.name,
                arguments=call.get("arguments", {}),
                tool_context=tool_context,
            )
            if not isinstance(decision, DockerSandboxDecision):
                raise PermissionError(
                    "Docker decision resolver returned an invalid authority"
                )
            call["_sandbox_decision"] = decision
            call["_sandbox_backend"] = decision.backend_name
            if argv:
                call["_executable_identity"] = container_command_identity(
                    decision.image_digest,
                    argv,
                    command_digest=decision.command_digest,
                )
            return
        if argv:
            call["_executable_identity"] = executable_identity(
                argv, tool_context.get("environment") or os.environ
            )
        selector = getattr(service, "backend_selector", None)
        selector_method = getattr(selector, "select_async_with_decision", None)
        if selector is None:
            # Explicit test/development adapters may intentionally inject a
            # fixed backend (for example HostExecutionBackend in the
            # deterministic approval E2E).  Production construction always
            # supplies BackendSelector, so keep the fail-closed check on the
            # selector boundary instead of turning the test adapter into a
            # production sandbox claim.
            if tool_context.get("production_runtime"):
                raise PermissionError(
                    "production process execution requires an evidence-bound sandbox selector"
                )
            return
        if not callable(selector_method):
            if (
                tool_context.get("production_runtime")
                or tool_context.get("coding_workspace_enforced")
            ):
                raise PermissionError(
                    "production process execution requires an evidence-bound sandbox decision"
                )
            return
        decision = call.get("_sandbox_decision") or tool_context.get(
            "sandbox_decision"
        )
        if decision is not None:
            if not isinstance(decision, SandboxDecision):
                raise PermissionError("sandbox decision is not immutable")
            call["_sandbox_decision"] = decision
            call["_sandbox_backend"] = decision.backend_name
            return
        writable = _sandbox_writable_for_authority(tool.name, call.get("arguments", {}))
        backend, decision = await selector.select_async_with_decision(
            writable=writable,
            network_mode=str(tool_context.get("network_policy") or "none"),
        )
        call["_sandbox_decision"] = decision
        call["_sandbox_backend"] = backend

    async def _prepare_network_authority_inputs(
        self,
        *,
        tool,
        call: dict[str, Any],
        tool_context: dict[str, Any],
        resource: AuthorizationResource | None = None,
    ) -> None:
        """Start the managed egress broker before freezing step authority.

        NetworkGuard remains the policy/approval layer for tool calls.  Every
        process-capable coding tool additionally receives a concrete
        NetworkLease whenever the effective policy enables network access;
        there is no direct-host process path hidden behind the legacy
        ``unrestricted-with-approval`` label.
        """
        if not _tool_has_capability(tool, "process.execute"):
            return
        if str(getattr(tool, "execution_kind", "host-sandbox")) in {
            "process-control",
            "docker",
        }:
            return
        network_guard = tool_context.get("network_guard")
        if network_guard is None or not bool(
            getattr(network_guard, "network_enabled", False)
        ):
            return
        if call.get("_network_broker") is not None:
            return
        factory = self.network_broker_factory
        if factory is None:
            raise PermissionError(
                "network-enabled process execution requires NetworkBrokerFactory"
            )
        authorization_epoch = await self.permission_engine.authorization_snapshot()
        workspace_generation = int(
            resource.workspace_generation
            if resource is not None
            else tool_context.get("workspace_generation") or 0
        )
        if workspace_generation <= 0:
            raise PermissionError(
                "network-enabled process execution requires a live workspace generation"
            )
        allowed_domains = getattr(network_guard, "allowed_domains", None)
        blocked_domains = getattr(network_guard, "blocked_domains", frozenset())
        broker, lease = await factory.start(
            principal_id=str(tool_context.get("principal_id") or "legacy-principal"),
            project_id=str(tool_context.get("project_id") or "legacy-project"),
            runtime_id=str(tool_context.get("runtime_id") or self.runtime_id or "legacy-runtime"),
            task_id=str(tool_context.get("task_id") or "legacy-task"),
            workspace_id=str(tool_context.get("workspace_id") or "legacy-workspace"),
            workspace_generation=workspace_generation,
            policy_digest=str(
                tool_context.get("effective_policy_digest") or "policy:unspecified"
            ),
            authorization_epoch=authorization_epoch,
            allowed_domains=(
                frozenset(str(domain) for domain in allowed_domains)
                if allowed_domains is not None
                else None
            ),
            blocked_domains=frozenset(str(domain) for domain in blocked_domains),
        )
        call["_network_broker"] = broker
        call["_network_lease"] = lease
        call["_network_authorization_epoch"] = authorization_epoch
        self._network_brokers.add(broker)

    async def _close_network_broker(self, call: dict[str, Any]) -> None:
        """Close one step broker and retain failures as a hard boundary."""
        broker = call.pop("_network_broker", None)
        if broker is None:
            return
        try:
            await broker.close()
        except Exception:
            logger.exception("managed network broker cleanup failed")
            raise
        self._network_brokers.discard(broker)

    async def _close_all_network_brokers(self) -> None:
        """Close every tracked broker and retain failed cleanup ownership."""
        errors: list[BaseException] = []
        for broker in tuple(self._network_brokers):
            try:
                await broker.close()
            except BaseException as exc:  # noqa: BLE001 - cleanup must survive cancellation
                errors.append(exc)
            else:
                self._network_brokers.discard(broker)
        try:
            await self.network_broker_factory.close()
        except BaseException as exc:  # noqa: BLE001 - cleanup must survive cancellation
            errors.append(exc)
        if errors:
            raise RuntimeError("managed network broker cleanup was not proven") from errors[0]

    def _verify_step_authority(
        self,
        *,
        authority: StepExecutionAuthority | None,
        call: dict[str, Any],
        tool,
        tool_context: dict[str, Any],
        resource: AuthorizationResource | None,
    ) -> None:
        """Refuse execution if the approved authority no longer matches."""
        if call.get("_step_authority_required") and not isinstance(
            authority, StepExecutionAuthority
        ):
            raise PermissionDeniedError(
                "step execution authority is missing; re-authorization required"
            )
        if authority is None:
            return
        if call.get("_step_authority_scope_digest") != authority.scope_digest():
            raise PermissionDeniedError(
                "step execution authority scope was modified before dispatch"
            )
        if call.get("_step_execution_digest") != authority.digest():
            raise PermissionDeniedError(
                "step execution authority receipt was modified before dispatch"
            )
        current = self._build_step_authority(
            tool=tool,
            call=call,
            tool_context=tool_context,
            resource=resource,
            authorization_epoch=authority.authorization_epoch,
            approval_target=authority.approval_target,
            approval_receipt_digest=authority.approval_receipt_digest,
        )
        if current.digest() != authority.digest():
            raise PermissionDeniedError(
                "step execution environment or authorization changed before dispatch"
            )

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
        tool, mode: str, tool_context: dict[str, Any]
    ) -> str:
        """Reject coding execution before approval when no safe backend exists."""
        if mode != "coding" or not _tool_has_capability(tool, "process.execute"):
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
            "tool_security_digest": request.tool_security_digest,
        }
        try:
            if inspect.iscoroutinefunction(confirm_callback):
                value = await asyncio.wait_for(
                    confirm_callback(payload), timeout=remaining
                )
            else:
                # UI and gateway integrations may supply a synchronous
                # callback.  It is untrusted with respect to latency, so run
                # it off-loop on the dedicated bounded approval executor and
                # apply the same approval deadline as an asynchronous
                # callback.  A timed-out worker cannot be force-killed; the
                # bounded pool turns a hang into later fail-closed denials
                # instead of an unbounded thread leak.
                value = await asyncio.wait_for(
                    asyncio.get_running_loop().run_in_executor(
                        self._approval_executor, confirm_callback, payload
                    ),
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
        """Close every runtime-owned network and background-process handle."""
        await self._close_all_network_brokers()
        await self.process_authority.shutdown()

    @staticmethod
    def _normalize_call(call: dict) -> dict:
        normalized = {
            "id": str(call.get("id") or call.get("tool_call_id") or call.get("name")),
            "name": str(call["name"]),
            "arguments": dict(call.get("arguments") or {}),
        }
        # Only the server-side binding path may carry an operation key.
        # A top-level value supplied by a model, gateway caller, or plugin is
        # untrusted input and must not become durable idempotency authority.
        if call.get("_server_operation_key") is True:
            idempotency_key = call.get("_idempotency_key")
            if idempotency_key:
                normalized["_idempotency_key"] = str(idempotency_key)
                normalized["_server_operation_key"] = True
        return normalized


def _canonical_digest(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _execution_argv_for_authority(
    tool_name: str, arguments: dict[str, Any]
) -> tuple[str, ...]:
    """Extract the fixed executable argv used by process-backed tools."""
    try:
        if tool_name == "terminal_argv":
            value = arguments.get("argv")
            if isinstance(value, list) and all(
                isinstance(item, str) and item for item in value
            ):
                return tuple(value)
        if tool_name == "terminal_shell":
            shell = str(arguments.get("shell") or "")
            script = str(arguments.get("script") or "")
            return (shell, "-c", script) if shell and script else ()
        if tool_name == "test_run":
            command = str(arguments.get("command") or "")
            return tuple(shlex.split(command)) if command else ()
        if tool_name == "terminal":
            command = str(arguments.get("command") or "")
            return tuple(shlex.split(command)) if command else ()
        if tool_name == "sandbox_exec":
            command = str(arguments.get("command") or "")
            return tuple(shlex.split(command)) if command else ()
    except ValueError:
        return ()
    return ()


def _sandbox_writable_for_authority(
    tool_name: str, arguments: dict[str, Any]
) -> bool:
    """Mirror the handler's read-only classification for authority binding."""
    if tool_name == "test_run":
        return True
    argv = _execution_argv_for_authority(tool_name, arguments)
    if not argv:
        return True
    command = shlex.join(argv)
    safety = evaluate_command_safety(
        str(arguments.get("script"))
        if tool_name == "terminal_shell"
        else command
    )
    return not bool(safety.get("read_only"))


def _authority_identity(value: object) -> str:
    """Serialize a backend/identity value without invoking arbitrary repr."""
    if isinstance(value, str):
        return value or "identity:unspecified"
    if isinstance(value, (int, float, bool)):
        return str(value)
    if isinstance(value, (tuple, list)):
        return json.dumps(list(value), separators=(",", ":"), ensure_ascii=False)
    return f"{type(value).__module__}.{type(value).__qualname__}"


def _tool_has_capability(tool: object, capability_name: str) -> bool:
    """Check the declarative capability contract, never a tool-name list."""
    for capability in getattr(tool, "capabilities", ()):
        name = getattr(capability, "name", "")
        value = getattr(name, "value", name)
        if str(value) == capability_name:
            return True
    return False


def _default_environment_value(key: str) -> str:
    """Return the value used when a trusted runtime omitted an allowlisted key."""
    if key == "PATH":
        return os.defpath
    if key == "LANG":
        return "C.UTF-8"
    return ""


def _authority_identity_parts(value: object) -> tuple[int | None, int | None]:
    """Extract a filesystem device/inode pair without resolving untrusted paths."""
    if isinstance(value, (tuple, list)) and len(value) == 2:
        device, inode = value
        if isinstance(device, int) and isinstance(inode, int):
            return int(device), int(inode)
    return None, None


def _authority_budget(
    tool_name: str, arguments: dict[str, Any], tool_timeout: int = 120
) -> ResourceBudget:
    """Mirror the bounded budgets used by process-backed tool handlers."""
    timeout_value = arguments.get("timeout_seconds")
    if timeout_value is None:
        timeout_value = arguments.get("timeout")
    if timeout_value is None:
        if tool_name == "test_run":
            timeout_value = 120
        elif tool_name == "sandbox_exec":
            timeout_value = 30
        else:
            timeout_value = tool_timeout
    try:
        timeout = max(float(timeout_value), 0.001)
    except (TypeError, ValueError):
        timeout = float(tool_timeout)
    kwargs: dict[str, Any] = {"timeout_seconds": timeout}
    if tool_name == "sandbox_exec":
        try:
            kwargs["cpu_count"] = float(arguments.get("cpus", 1.0))
        except (TypeError, ValueError):
            kwargs["cpu_count"] = 1.0
        kwargs["memory_bytes"] = _authority_memory_bytes(arguments.get("memory", "512m"))
        kwargs["tmpfs_bytes"] = 256 * 1024 * 1024
    return ResourceBudget(**kwargs)


def _authority_memory_bytes(value: object) -> int:
    """Parse sandbox memory using the same units and bounds as sandbox_exec."""
    if not isinstance(value, str):
        return 512 * 1024 * 1024
    text = value.strip()
    if len(text) < 2 or text[-1].lower() not in {"k", "m", "g"}:
        return 512 * 1024 * 1024
    try:
        amount = int(text[:-1])
    except ValueError:
        return 512 * 1024 * 1024
    result = amount * {"k": 1024, "m": 1024**2, "g": 1024**3}[text[-1].lower()]
    return result if 64 * 1024**2 <= result <= 16 * 1024**3 else 512 * 1024 * 1024


def _authority_profile(
    *,
    tool,
    arguments: dict[str, Any],
    tool_context: dict[str, Any],
    environment_keys: tuple[str, ...],
    network_lease: NetworkLease | None = None,
) -> PermissionProfile | None:
    """Build the same profile projection consumed by ExecutionService."""
    root_value = tool_context.get("workspace_root")
    if not root_value:
        supplied = tool_context.get("permission_profile")
        return supplied if isinstance(supplied, PermissionProfile) else None
    try:
        root = Path(str(root_value)).expanduser().resolve()
        writable = _sandbox_writable_for_authority(tool.name, arguments)
        access_mode = (
            FileSystemAccess.WORKSPACE_WRITE
            if writable
            else FileSystemAccess.READ_ONLY
        )
        requested_network = NetworkPolicy(
            str(tool_context.get("network_policy") or NetworkPolicy.NONE.value)
        )
        network = (
            NetworkPolicy.BROKERED
            if network_lease is not None
            and requested_network is NetworkPolicy.UNRESTRICTED_WITH_APPROVAL
            else requested_network
        )
        profile = PermissionProfile.from_legacy(
            access_mode=access_mode.value,
            network_policy=network,
            network_broker=network_lease,
            roots=(root,),
            environment_keys=frozenset(environment_keys),
            resources=_authority_budget(tool.name, arguments, int(getattr(tool, "timeout", 120))),
        )
        return profile.bind_workspace(root)
    except (OSError, TypeError, ValueError, PermissionError):
        return None


def _build_spawn_plan(
    *,
    tool,
    call: dict[str, Any],
    tool_context: dict[str, Any],
    workspace_generation: int,
    permission_profile_digest: str,
    sandbox_decision_digest: str,
    network_authority: str,
    environment_payload: dict[str, str],
    executable_scope: str,
    argv: tuple[str, ...],
    network_lease: NetworkLease | None = None,
    principal_kind: str = "",
    parent_principal_id: str = "",
    delegation_digest: str = "",
) -> ResolvedSpawnPlan:
    """Create one immutable, pre-approval spawn authority."""
    arguments = call.get("arguments", {})
    session_id = str(tool_context.get("session_id") or "legacy-session")
    root_identity = _authority_identity_parts(
        tool_context.get("workspace_root_identity")
        or tool_context.get("cwd_identity")
    )
    cwd_identity = _authority_identity_parts(
        tool_context.get("workspace_cwd_identity")
        or tool_context.get("cwd_identity")
    )
    root_value = tool_context.get("workspace_root")
    requested_cwd = arguments.get("cwd")
    if root_value and requested_cwd:
        try:
            root = Path(str(root_value)).expanduser().resolve()
            requested = Path(str(requested_cwd)).expanduser()
            candidate = requested if requested.is_absolute() else root / requested
            info = candidate.stat()
            cwd_identity = (int(info.st_dev), int(info.st_ino))
        except (OSError, ValueError):
            # ExecutionService performs the authoritative lexical and inode
            # check; keep the pre-approval plan fail-closed if unavailable.
            cwd_identity = (None, None)
    profile = _authority_profile(
        tool=tool,
        arguments=arguments,
        tool_context=tool_context,
        environment_keys=tuple(sorted(environment_payload)),
        network_lease=network_lease,
    )
    if profile is not None:
        permission_profile_digest = profile.digest()
    plan_argv = argv or (tool.name,)
    budget = _authority_budget(tool.name, arguments, int(getattr(tool, "timeout", 120)))
    return ResolvedSpawnPlan(
        principal_id=str(tool_context.get("principal_id") or "legacy-principal"),
        project_id=str(tool_context.get("project_id") or "legacy-project"),
        session_id=session_id,
        # Keep the compatibility fallback identical to _build_step_authority.
        # Direct library/test schedulers do not have a TaskWorkspace, but the
        # step and spawn authorities must still bind to the same synthetic
        # task identity.
        task_id=str(tool_context.get("task_id") or f"session:{session_id}"),
        turn_id=str(tool_context.get("turn_id") or f"turn:{call['id']}"),
        step_id=str(tool_context.get("attempt_id") or f"step:{call['id']}"),
        workspace_generation=workspace_generation,
        workspace_root_device=root_identity[0],
        workspace_root_inode=root_identity[1],
        workspace_cwd_device=cwd_identity[0],
        workspace_cwd_inode=cwd_identity[1],
        permission_profile_digest=permission_profile_digest,
        sandbox_decision_digest=sandbox_decision_digest,
        network_authority=network_authority,
        environment=tuple(sorted(environment_payload.items())),
        executable_identity=executable_scope,
        argv=plan_argv,
        budget_digest=budget.digest(),
        principal_kind=principal_kind,
        parent_principal_id=parent_principal_id,
        delegation_digest=delegation_digest,
    )


def _authority_sequence(value: object) -> tuple[str, ...]:
    """Normalize an optional domain/key collection for authority hashing."""
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, (tuple, list, set, frozenset)):
        return tuple(sorted(str(item) for item in value))
    return (_authority_identity(value),)


def server_operation_key(
    *,
    principal_id: str,
    project_id: str,
    session_id: str,
    turn_id: str,
    attempt_id: str,
    tool_call_id: str,
    tool_name: str,
    workspace_id: str,
) -> str:
    """Return a stable server-owned identity for one tool operation.

    This is an identity digest, not an argument digest.  Keeping the two
    independent lets the database reject accidental or malicious reuse of an
    operation identity with different arguments while preserving replay
    semantics for the original durable turn/attempt.
    """
    return "srv-op-" + _canonical_digest(
        {
            "principal_id": principal_id,
            "project_id": project_id,
            "session_id": session_id,
            "turn_id": turn_id,
            "attempt_id": attempt_id,
            "tool_call_id": tool_call_id,
            "tool_name": tool_name,
            "workspace_id": workspace_id,
        }
    )
