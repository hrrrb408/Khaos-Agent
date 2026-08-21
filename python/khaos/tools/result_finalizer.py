"""Terminal result projection for tool execution.

``ToolScheduler`` orchestrates admission and handler dispatch.  This module
owns the final boundary after dispatch: immutable phase terminalization,
best-effort audit projection, durable operation finalization, and the
runtime-scoped idempotent result hand-off.  Keeping those effects together
prevents one error branch from forgetting to persist or wake duplicate
callers.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any

from khaos.security.orchestration_components import ToolPhaseCoordinator
from khaos.tools.operation_store import OperationClaim, ToolOperationStore
from khaos.tools.scheduler_models import ToolResult

logger = logging.getLogger(__name__)


class ToolResultFinalizer:
    """Own terminal evidence and result delivery for one scheduler runtime."""

    def __init__(
        self,
        *,
        audit_writer: Any,
        operation_store: ToolOperationStore,
    ) -> None:
        self._audit_writer = audit_writer
        self._operation_store = operation_store

    @staticmethod
    def terminalize(call: dict[str, Any], result: ToolResult) -> ToolResult:
        """Close phase evidence after every dispatched call."""
        return ToolPhaseCoordinator.terminalize(call, result)

    async def audit_best_effort(
        self,
        tool_name: str,
        target: str,
        outcome: str,
        detail: Mapping[str, Any],
        session_id: str | None,
    ) -> str:
        """Persist an audit event without hiding the execution outcome."""
        try:
            row_id = await self._audit_writer.audit(
                tool_name,
                target,
                outcome,
                dict(detail),
                session_id,
            )
            if isinstance(row_id, int) and row_id < 0:
                return "audit repository rejected the event"
        except Exception as exc:
            logger.exception(
                "tool audit persistence failed: tool=%s result=%s",
                tool_name,
                outcome,
            )
            return str(exc)
        return ""

    async def finish_and_store(
        self,
        claim: OperationClaim | None,
        result: ToolResult,
        *,
        terminal_status: str,
        call: Mapping[str, Any],
        session_id: str | None,
        tool_context: Mapping[str, Any],
        store_result: bool = True,
    ) -> ToolResult:
        """Finalize durable ownership and publish the idempotent result."""
        finalized = await self._operation_store.finish(
            claim,
            result,
            terminal_status=terminal_status,
        )
        if store_result:
            await self._operation_store.put_result(
                call,
                session_id=session_id,
                tool_context=tool_context,
                result=finalized,
            )
        return finalized


__all__ = ["ToolResultFinalizer"]
