"""Authority-bound tool invocation coordinator.

This module owns the last Python-side step before a tool handler crosses the
effect boundary: it assembles the immutable execution context, invokes the
registered handler through ``ToolInvocationBroker``, applies the timeout, and
normalizes the handler's effect outcome.  Permission, operation claiming,
budget accounting, and result/audit projection remain separate owners.
"""
from __future__ import annotations

import asyncio
from typing import Any

from khaos.agent.approval import StepExecutionAuthority
from khaos.coding.execution.authority import ExecutionAuthority
from khaos.coding.execution.models import ResolvedSpawnPlan
from khaos.security.middleware import SecurityMiddleware
from khaos.tools.registry import ToolInvocationBroker
from khaos.tools.result_codec import ToolResultCodec
from khaos.tools.scheduler_models import ToolExecutionOutcome


class ToolExecutionCoordinator:
    """Prepare and invoke one already-authorized tool call."""

    def __init__(
        self,
        *,
        invocation_broker: ToolInvocationBroker,
        security_middleware: SecurityMiddleware,
        process_authority: Any,
        office_authority: Any = None,
    ) -> None:
        self._invocation_broker = invocation_broker
        self._security_middleware = security_middleware
        self._process_authority = process_authority
        self._office_authority = office_authority

    def set_office_authority(self, authority: Any) -> None:
        """Update the runtime-owned Office mutation authority."""
        self._office_authority = authority

    async def invoke(
        self,
        *,
        tool: Any,
        call: dict[str, Any],
        mode: str,
        tool_context: dict[str, Any],
        step_authority: Any,
        effect_id: str,
        timeout: float,
        default_effect_status: str,
        reconciliation_hint: str,
    ) -> ToolExecutionOutcome:
        """Invoke a handler with an authority-bound, bounded context."""
        invocation_context = dict(tool_context)
        invocation_context["process_authority"] = self._process_authority
        sandbox = self._security_middleware.sandbox
        if mode == "office" and sandbox is not None:
            invocation_context["office_workspace_root"] = sandbox.workspace_root
        if mode == "office" and self._office_authority is not None:
            invocation_context["office_authority"] = self._office_authority
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
            invocation_context["executable_identity"] = call["_executable_identity"]
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
            self._invocation_broker.invoke(
                tool.name,
                mode=mode,
                context=invocation_context,
                **call.get("arguments", {}),
            ),
            timeout=timeout,
        )
        return ToolResultCodec.normalize_effect_outcome(
            output,
            default_status=default_effect_status,
            default_effect_id=effect_id,
            default_reconciliation_hint=reconciliation_hint,
        )


__all__ = ["ToolExecutionCoordinator"]
