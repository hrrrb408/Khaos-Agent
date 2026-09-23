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
from dataclasses import replace
from typing import Any

from khaos.security.orchestration_components import ToolPhaseCoordinator
from khaos.security.secret_redaction import SecretRedactor
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
        secret_redactor: SecretRedactor | None = None,
    ) -> None:
        self._audit_writer = audit_writer
        self._operation_store = operation_store
        self._secret_redactor = secret_redactor

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
            safe_detail: object = dict(detail)
            safe_tool_name = tool_name
            safe_target = target
            safe_outcome = outcome
            if self._secret_redactor is not None:
                safe_detail = self._safe_mapping(safe_detail)
                safe_tool_name = self._secret_redactor.redact_text(tool_name)
                safe_target = self._secret_redactor.redact_text(target)
                safe_outcome = self._secret_redactor.redact_text(outcome)
            row_id = await self._audit_writer.audit(
                safe_tool_name,
                safe_target,
                safe_outcome,
                safe_detail,
                session_id,
            )
            if isinstance(row_id, int) and row_id < 0:
                return "audit repository rejected the event"
        except Exception as exc:
            logger.error(  # noqa: G201 - traceback would bypass the output firewall
                "tool audit persistence failed: tool_type=%s result_type=%s",
                type(tool_name).__name__,
                type(outcome).__name__,
                exc_info=True,
            )
            if self._secret_redactor is not None:
                return self._secret_redactor.safe_error(exc)
            return type(exc).__name__[:128]
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
        safe_result = self._sanitize_result(result)
        finalized = await self._operation_store.finish(
            claim,
            safe_result,
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

    def _sanitize_result(self, result: ToolResult) -> ToolResult:
        """Ensure durable and returned tool results cross one output firewall."""
        if self._secret_redactor is None:
            return result
        redactor = self._secret_redactor
        return replace(
            result,
            output=redactor.redact_fail_closed(result.output),
            error=redactor.redact_text(result.error),
            error_code=redactor.redact_text(result.error_code),
            arguments=self._safe_mapping(result.arguments),
            warning=redactor.redact_text(result.warning),
            reconciliation_hint=redactor.redact_text(result.reconciliation_hint),
            effect_receipt=self._safe_mapping(result.effect_receipt),
        )

    def _safe_mapping(self, value: object) -> dict[str, Any] | None:
        """Keep mapping-shaped scheduler contracts after fail-closed redaction."""
        if value is None:
            return None
        if self._secret_redactor is None:
            return dict(value) if isinstance(value, Mapping) else {"redacted": True}
        sanitized = self._secret_redactor.redact_fail_closed(value)
        if isinstance(sanitized, Mapping):
            return dict(sanitized)
        return {"redacted": True}


__all__ = ["ToolResultFinalizer"]
