"""Serialization and normalization for the tool-result protocol.

The scheduler owns ordering, authority and handler execution.  This module
owns the value-level contract at that boundary: legacy handler payloads are
classified, typed outcomes are validated, and durable operation rows are
decoded without allowing unknown fields to become executable state.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Mapping
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
_APPLIED_RECEIPT_OPERATION_KINDS = frozenset(
    {"create", "update", "delete", "rename"}
)
_MAX_APPLIED_RECEIPT_OPERATIONS = 64
_MAX_APPLIED_RECEIPT_TEXT = 512
_MAX_APPLIED_RECEIPT_BYTES = 128 * 1024


class ToolResultCodec:
    """Pure codec for handler outcomes and durable ``ToolResult`` rows."""

    @staticmethod
    def project_applied_effect_receipt(
        tool_name: str, output: object
    ) -> dict[str, Any] | None:
        """Project a canonical applied-edit result into bounded evidence.

        A mutation may have crossed its effect boundary before the ordinary
        model-facing output projection fails (for example, because the
        remaining aggregate tool-output budget is smaller than the handler's
        result).  The AgentLoop still needs the exact generation/digest facts
        to record the mutation before verification.  This method copies only
        the reviewed ``apply_edit_transaction`` result shape; it never
        coerces values or preserves source/replacement text.
        """
        if tool_name != "apply_edit_transaction" or not isinstance(output, Mapping):
            return None
        if output.get("status") != "applied":
            return None

        def text(value: object) -> str | None:
            if (
                type(value) is not str
                or not value
                or len(value) > _MAX_APPLIED_RECEIPT_TEXT
                or "\x00" in value
            ):
                return None
            return value

        def digest(value: object, *, optional: bool = False) -> str | None:
            if optional and value is None:
                return None
            if (
                type(value) is not str
                or len(value) != 64
                or any(character not in "0123456789abcdef" for character in value)
            ):
                return None
            return value

        def generation(value: object) -> int | None:
            if type(value) is not int or value <= 0:
                return None
            return value

        transaction_id = text(output.get("transaction_id"))
        workspace_id = text(output.get("workspace_id"))
        base_generation = generation(output.get("base_generation"))
        resulting_generation = generation(output.get("resulting_generation"))
        transaction_digest = digest(output.get("transaction_digest"))
        before_workspace_digest = digest(output.get("before_workspace_digest"))
        after_workspace_digest = digest(output.get("after_workspace_digest"))
        operations_value = output.get("operations")
        if (
            transaction_id is None
            or workspace_id is None
            or base_generation is None
            or resulting_generation is None
            or resulting_generation <= base_generation
            or transaction_digest is None
            or before_workspace_digest is None
            or after_workspace_digest is None
            or not isinstance(operations_value, list)
            or not operations_value
            or len(operations_value) > _MAX_APPLIED_RECEIPT_OPERATIONS
        ):
            return None

        operations: list[dict[str, Any]] = []
        for item in operations_value:
            if not isinstance(item, Mapping):
                return None
            index = item.get("index")
            operation = item.get("operation")
            path = text(item.get("path"))
            destination_path = item.get("destination_path")
            if destination_path is not None:
                destination_path = text(destination_path)
            before_exists = item.get("before_exists")
            after_exists = item.get("after_exists")
            before_digest = digest(item.get("before_digest"), optional=True)
            after_digest = digest(item.get("after_digest"), optional=True)
            if (
                type(index) is not int
                or index < 0
                or type(operation) is not str
                or operation not in _APPLIED_RECEIPT_OPERATION_KINDS
                or path is None
                or (item.get("destination_path") is not None and destination_path is None)
                or type(before_exists) is not bool
                or type(after_exists) is not bool
                or (item.get("before_digest") is not None and before_digest is None)
                or (item.get("after_digest") is not None and after_digest is None)
            ):
                return None
            operations.append(
                {
                    "index": index,
                    "operation": operation,
                    "path": path,
                    "destination_path": destination_path,
                    "before_exists": before_exists,
                    "after_exists": after_exists,
                    "before_digest": before_digest,
                    "after_digest": after_digest,
                }
            )
        if sorted(item["index"] for item in operations) != list(range(len(operations))):
            return None

        receipt = {
            "status": "applied",
            "transaction_id": transaction_id,
            "workspace_id": workspace_id,
            "base_generation": base_generation,
            "resulting_generation": resulting_generation,
            "transaction_digest": transaction_digest,
            "before_workspace_digest": before_workspace_digest,
            "after_workspace_digest": after_workspace_digest,
            "operations": operations,
        }
        try:
            encoded = json.dumps(
                receipt,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        except (TypeError, ValueError):
            return None
        if len(encoded) > _MAX_APPLIED_RECEIPT_BYTES:
            return None
        return receipt

    @staticmethod
    def compact_applied_effect_receipt(
        receipt: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        """Return a tiny model-facing acknowledgement for an applied edit."""
        if receipt is None:
            return {}
        return {
            "status": "applied",
            "transaction_id": receipt["transaction_id"],
            "workspace_id": receipt["workspace_id"],
            "base_generation": receipt["base_generation"],
            "resulting_generation": receipt["resulting_generation"],
            "transaction_digest": receipt["transaction_digest"],
            "after_workspace_digest": receipt["after_workspace_digest"],
            "operation_count": len(receipt["operations"]),
        }

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
                        effect_receipt=ToolResultCodec.project_applied_effect_receipt(
                            str(tool.name), values.get("effect_receipt")
                        ),
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
