"""Permission-aware tool scheduling."""

from __future__ import annotations

import asyncio
import inspect
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable

from khaos.permissions import ApprovalMode, PermissionRule
from khaos.security.middleware import SecurityMiddleware
from khaos.tools.registry import ToolInvocationBroker, ToolRegistry


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


@dataclass
class SchedulerEvent:
    """Streaming scheduler event."""

    event: str
    result: ToolResult | None = None
    permission_request: PermissionRequest | None = None


@dataclass
class ToolBudget:
    """Tool execution budget."""

    max_calls: int = 50
    max_output_chars: int = 100000
    _call_count: int = 0
    _output_chars: int = 0

    @property
    def is_exhausted(self) -> bool:
        """Return true once call or output budget is exhausted."""
        return self._call_count >= self.max_calls or self._output_chars >= self.max_output_chars

    def record(self, output_chars: int) -> None:
        """Record one completed tool call."""
        self._call_count += 1
        self._output_chars += output_chars


class ToolScheduler:
    """Split, authorize, and execute tool calls."""

    def __init__(
        self,
        registry: ToolRegistry,
        permission_engine,
        budget: ToolBudget | None = None,
        use_rust_executor: bool = False,
        security_middleware: SecurityMiddleware | None = None,
    ):
        self.registry = registry
        self.permission_engine = permission_engine
        self.budget = budget or ToolBudget()
        self.security_middleware = security_middleware or SecurityMiddleware()
        # When True and the Rust bridge is importable, read-only file reads in
        # the parallel group are offloaded to the Rust executor for the bulk
        # I/O; the result still flows through the normal Python handler so
        # output formatting (line numbers, truncation) is unchanged. Writes and
        # any tool without a Rust fast path keep using the asyncio handler.
        self.use_rust_executor = use_rust_executor
        self.invocation_broker = ToolInvocationBroker(registry)

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
        if self.budget.is_exhausted:
            return

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

            decision = await self.permission_engine.check(
                tool_name=tool.name,
                params=normalized["arguments"],
                permission_level=tool.permission_level,
                mode=mode,
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

            if decision.requires_user_confirm:
                request = PermissionRequest(
                    tool_call_id=normalized["id"],
                    name=tool.name,
                    arguments=normalized["arguments"],
                    level=tool.permission_level,
                    target=decision.target,
                    reason=decision.reason,
                )
                yield SchedulerEvent(event="permission_request", permission_request=request)
                confirmation = await self._confirm(request, confirm_callback)
                if not confirmation.get("approved", False):
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
                if confirmation.get("remember"):
                    await self.permission_engine.grant_rule(
                        PermissionRule(
                            id=None,
                            pattern=confirmation.get("pattern", decision.target),
                            permission_level=tool.permission_level,
                            approval=ApprovalMode.AUTO_APPROVE,
                            mode=mode,
                        )
                    )
            approved_calls.append(normalized)

        parallel_calls, serial_calls = self.registry.get_parallel_tools(approved_calls)
        if parallel_calls:
            tasks = [self._execute_one(call, session_id, mode, tool_context or {}) for call in parallel_calls]
            for result in await asyncio.gather(*tasks):
                yield SchedulerEvent(event="tool_result", result=result)
        for call in serial_calls:
            if self.budget.is_exhausted:
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
                break
            yield SchedulerEvent(
                event="tool_result",
                result=await self._execute_one(call, session_id, mode, tool_context or {}),
            )

    async def _execute_one(self, call: dict, session_id: str | None, mode: str, tool_context: dict[str, Any]) -> ToolResult:
        start = time.monotonic()
        tool = self.registry.get(call["name"])
        if tool.handler is None:
            return ToolResult(
                tool_call_id=call["id"],
                name=call["name"],
                success=False,
                error="Tool has no handler",
                arguments=call["arguments"],
            )
        try:
            security = await self.security_middleware.pre_check(
                tool.name,
                call.get("arguments", {}),
            )
            if not security.allowed:
                target = self.permission_engine.normalize_target(tool.name, call.get("arguments", {}))
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
                return ToolResult(
                    tool_call_id=call["id"],
                    name=tool.name,
                    success=False,
                    error=f"Security check blocked: {security.reason}",
                    duration_ms=int((time.monotonic() - start) * 1000),
                    arguments=call["arguments"],
                )
            output = await asyncio.wait_for(
                self.invocation_broker.invoke(tool.name, mode=mode, context=tool_context, **call.get("arguments", {})),
                timeout=tool.timeout,
            )
            self.budget.record(len(str(output)))
            target = self.permission_engine.normalize_target(tool.name, call.get("arguments", {}))
            secret_scan, output = await self.security_middleware.post_check(tool.name, output)
            detail: dict[str, Any] = {"tool_call_id": call["id"]}
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
            return ToolResult(
                tool_call_id=call["id"],
                name=tool.name,
                success=True,
                output=output,
                duration_ms=int((time.monotonic() - start) * 1000),
                arguments=call["arguments"],
            )
        except Exception as exc:
            target = self.permission_engine.normalize_target(tool.name, call.get("arguments", {}))
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
        value = confirm_callback(
            {
                "id": request.tool_call_id,
                "name": request.name,
                "arguments": request.arguments,
                "level": request.level,
                "target": request.target,
                "reason": request.reason,
            }
        )
        if inspect.isawaitable(value):
            value = await value
        if isinstance(value, bool):
            return {"approved": value}
        return dict(value)

    @staticmethod
    def _normalize_call(call: dict) -> dict:
        return {
            "id": str(call.get("id") or call.get("tool_call_id") or call.get("name")),
            "name": str(call["name"]),
            "arguments": dict(call.get("arguments") or {}),
        }
