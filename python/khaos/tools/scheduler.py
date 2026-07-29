"""Permission-aware tool scheduling."""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable

from khaos.permissions import ApprovalMode, PermissionRule
from khaos.permissions.resource import (
    AuthorizationResource,
    resolve_authorization_resource,
)
from khaos.agent.approval import ApprovalBinding
from khaos.exceptions import PermissionDeniedError
from khaos.security.middleware import SecurityMiddleware
from khaos.tools.registry import ToolInvocationBroker, ToolRegistry
from khaos.tools.terminal_tools import BackgroundProcessAuthority


ConfirmCallback = Callable[[dict], Awaitable[dict | bool] | dict | bool]


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

    async def reserve(self, *, parallel: bool = False) -> "ToolBudgetReservation | None":
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
        self, reservation: "ToolBudgetReservation", *, output_chars: int | None
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

            decision = await self.permission_engine.check(
                tool_name=tool.name,
                params=normalized["arguments"],
                permission_level=tool.permission_level,
                mode=mode,
                resource=resource,
            )
            if decision.approved == ApprovalMode.DENY:
                await self.permission_engine.audit(
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
                binding_digest = await broker.register_tool_approval(binding)
                normalized["_approval_schema_digest"] = binding.tool_schema_digest
                normalized["_approval_policy_digest"] = binding.policy_digest
                normalized["_approval_authorization_epoch"] = binding.authorization_epoch
                request = PermissionRequest(
                    tool_call_id=normalized["id"],
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
                    await self.permission_engine.audit(
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
                if confirmation.get("remember"):
                    normalized["_remember_rule"] = PermissionRule(
                        id=None,
                        pattern=confirmation.get("pattern", decision.target),
                        permission_level=tool.permission_level,
                        approval=ApprovalMode.AUTO_APPROVE,
                        mode=mode,
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
            for result in await asyncio.gather(*tasks):
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
        if tool.handler is None:
            await reservation.release()
            return ToolResult(
                tool_call_id=call["id"],
                name=call["name"],
                success=False,
                error="Tool has no handler",
                arguments=call["arguments"],
            )
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
                target = (
                    resource.canonical_target
                    if resource is not None
                    else self.permission_engine.normalize_target(
                        tool.name, call.get("arguments", {})
                    )
                )
                await self.permission_engine.audit(
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
                await reservation.release()
                return ToolResult(
                    tool_call_id=call["id"],
                    name=tool.name,
                    success=False,
                    error=f"Security check blocked: {security.reason}",
                    duration_ms=int((time.monotonic() - start) * 1000),
                    arguments=call["arguments"],
                )
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
            output = await asyncio.wait_for(
                self.invocation_broker.invoke(tool.name, mode=mode, context=invocation_context, **call.get("arguments", {})),
                timeout=tool.timeout,
            )
            target = (
                resource.canonical_target
                if resource is not None
                else self.permission_engine.normalize_target(tool.name, call.get("arguments", {}))
            )
            # Bound the structure before secret scanning.  This traversal
            # stops as soon as the reservation is consumed and never calls an
            # arbitrary result object's __str__/__repr__ method.
            _measure_tool_output(output, reservation.output_limit)
            secret_scan, output = await self.security_middleware.post_check(tool.name, output)
            # Redaction can change length, so commit the post-redaction size.
            output_chars = _measure_tool_output(output, reservation.output_limit)
            detail: dict[str, Any] = {"tool_call_id": call["id"]}
            if resource is not None:
                detail["authorization_resource_digest"] = resource.digest()
            if secret_scan.has_secrets:
                detail["secrets_detected"] = True
                detail["secret_categories"] = [
                    secret.category for secret in secret_scan.secrets
                ]
            await self.permission_engine.audit(
                tool.name,
                target,
                "success",
                detail,
                session_id,
            )
            await reservation.commit(output_chars)
            remember_rule = call.get("_remember_rule")
            if remember_rule is not None:
                await self.permission_engine.grant_rule(remember_rule)
            return ToolResult(
                tool_call_id=call["id"],
                name=tool.name,
                success=True,
                output=output,
                duration_ms=int((time.monotonic() - start) * 1000),
                arguments=call["arguments"],
            )
        except Exception as exc:
            await reservation.release()
            target = (
                resource.canonical_target
                if resource is not None
                else self.permission_engine.normalize_target(
                    tool.name, call.get("arguments", {})
                )
            )
            await self.permission_engine.audit(
                tool.name,
                target,
                "error",
                {"error": str(exc), "tool_call_id": call["id"]},
                session_id,
            )
            return ToolResult(
                tool_call_id=call["id"],
                name=tool.name,
                success=False,
                error=str(exc),
                duration_ms=int((time.monotonic() - start) * 1000),
                arguments=call["arguments"],
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
        except asyncio.TimeoutError:
            return {"approved": False, "reason": "approval_callback_timeout"}
        if inspect.isawaitable(value):
            # A synchronous adapter may return an awaitable.  Preserve the
            # same fixed approval deadline across both execution phases.
            remaining = request.expires_at - time.time()
            if remaining <= 0:
                return {"approved": False, "reason": "approval_expired_before_callback"}
            try:
                value = await asyncio.wait_for(value, timeout=remaining)
            except asyncio.TimeoutError:
                return {"approved": False, "reason": "approval_callback_timeout"}
        if isinstance(value, bool):
            return {"approved": value}
        return dict(value)

    async def aclose(self) -> None:
        """Close every runtime-owned background process handle."""
        await self.process_authority.shutdown()

    @staticmethod
    def _normalize_call(call: dict) -> dict:
        return {
            "id": str(call.get("id") or call.get("tool_call_id") or call.get("name")),
            "name": str(call["name"]),
            "arguments": dict(call.get("arguments") or {}),
        }


def _canonical_digest(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
