"""Serialization and normalization for the tool-result protocol.

The scheduler owns ordering, authority and handler execution.  This module
owns the value-level contract at that boundary: legacy handler payloads are
classified, typed outcomes are validated, and durable operation rows are
decoded without allowing unknown fields to become executable state.
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict
from typing import Any

from khaos.tools.scheduler_models import (
    DELIVERY_COMPLETE,
    DELIVERY_DEGRADED,
    EFFECT_APPLIED,
    EFFECT_NOT_APPLIED,
    EFFECT_PARTIAL,
    EFFECT_UNKNOWN,
    EffectOutcome,
    ToolExecutionOutcome,
    ToolResult,
)

logger = logging.getLogger(__name__)

_VALID_EFFECT_STATUSES = frozenset(
    {EFFECT_NOT_APPLIED, EFFECT_APPLIED, EFFECT_PARTIAL, EFFECT_UNKNOWN}
)
_LEGACY_FAILURE_MARKERS = frozenset(
    {
        "error",
        "failed",
        "failure",
        "forbidden",
        "invalid",
        "invalid_state",
        "not_found",
        "not_initialized",
        "unavailable",
    }
)


class ToolResultCodec:
    """Pure codec for handler outcomes and durable ``ToolResult`` rows."""

    @staticmethod
    def normalize_effect_outcome(
        value: Any,
        *,
        default_status: str,
        default_effect_id: str,
        default_reconciliation_hint: str,
    ) -> ToolExecutionOutcome:
        """Normalize typed and legacy handler returns with fail-closed fields."""
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
            handled_failure = isinstance(legacy_payload, dict) and (
                legacy_payload.get("ok") is False
                or legacy_payload.get("success") is False
                or status_marker in _LEGACY_FAILURE_MARKERS
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
                    or (
                        status_marker.upper()
                        if status_marker
                        else "TOOL_REPORTED_FAILURE"
                    )
                )
            effect_id = default_effect_id
            reconciliation_hint = default_reconciliation_hint
            retry_safe = handled_failure

        if not status:
            status = EFFECT_NOT_APPLIED if not ok else default_status
        if not ok and status == EFFECT_UNKNOWN and not effect_id:
            status = EFFECT_NOT_APPLIED
        if status not in _VALID_EFFECT_STATUSES:
            raise ValueError(f"invalid ToolExecutionOutcome effect status: {status!r}")
        if status == EFFECT_UNKNOWN:
            # An unproven effect is never a safe retry, even when a legacy or
            # typed handler incorrectly marks its outcome retryable.  The
            # codec is the single value-level owner of this postcondition.
            retry_safe = False
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
    def serialize_operation_result(result: ToolResult) -> str:
        """Encode only the stable dataclass fields for a durable operation."""
        return json.dumps(asdict(result), ensure_ascii=False, sort_keys=True)

    @staticmethod
    def deserialize_operation_result(
        row: dict[str, Any],
        *,
        call: dict[str, Any],
        tool: Any,
    ) -> ToolResult:
        """Decode a durable row, quarantining malformed payloads."""
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


__all__ = ["ToolResultCodec"]
