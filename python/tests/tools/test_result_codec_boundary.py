"""Contract tests for the scheduler's value-level result boundary."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from khaos.tools.result_codec import ToolResultCodec
from khaos.tools.scheduler_models import (
    EFFECT_APPLIED,
    EFFECT_NOT_APPLIED,
    EFFECT_UNKNOWN,
    ToolExecutionOutcome,
    ToolResult,
)


def test_legacy_failure_payload_is_not_reported_as_success() -> None:
    outcome = ToolResultCodec.normalize_effect_outcome(
        {"status": "forbidden", "message": "outside workspace"},
        default_status=EFFECT_APPLIED,
        default_effect_id="effect-1",
        default_reconciliation_hint="",
    )

    assert outcome.ok is False
    assert outcome.effect_status == EFFECT_NOT_APPLIED
    assert outcome.error == "outside workspace"
    assert outcome.retry_safe is True


def test_typed_outcome_rejects_invalid_effect_metadata() -> None:
    with pytest.raises(ValueError, match="effect_id"):
        ToolResultCodec.normalize_effect_outcome(
            ToolExecutionOutcome(effect_status=EFFECT_APPLIED, effect_id="bad\nvalue"),
            default_status=EFFECT_APPLIED,
            default_effect_id="effect-1",
            default_reconciliation_hint="",
        )


def test_applied_effect_receipt_is_bounded_and_does_not_copy_verbose_output() -> None:
    output = {
        "status": "applied",
        "transaction_id": "tx-1",
        "workspace_id": "ws-1",
        "base_generation": 1,
        "resulting_generation": 2,
        "transaction_digest": "a" * 64,
        "before_workspace_digest": "b" * 64,
        "after_workspace_digest": "c" * 64,
        "operations": [
            {
                "index": 0,
                "operation": "update",
                "path": "src/app.py",
                "destination_path": None,
                "before_exists": True,
                "after_exists": True,
                "before_digest": "d" * 64,
                "after_digest": "e" * 64,
            }
        ],
        "verbose_diagnostic": "source text that must not enter the receipt" * 1000,
    }

    receipt = ToolResultCodec.project_applied_effect_receipt(
        "apply_edit_transaction", output
    )

    assert receipt is not None
    assert "verbose_diagnostic" not in receipt
    assert receipt["operations"][0]["path"] == "src/app.py"
    compact = ToolResultCodec.compact_applied_effect_receipt(receipt)
    assert compact["status"] == "applied"
    assert compact["operation_count"] == 1
    assert "verbose_diagnostic" not in compact


def test_applied_effect_receipt_rejects_malformed_identity() -> None:
    assert (
        ToolResultCodec.project_applied_effect_receipt(
            "apply_edit_transaction",
            {"status": "applied", "transaction_id": "not-enough-fields"},
        )
        is None
    )


def test_durable_result_codec_filters_unknown_fields_and_falls_back_closed() -> None:
    result = ToolResult(
        tool_call_id="call-1",
        name="write_file",
        success=True,
        output={"ok": True},
        arguments={"path": "a"},
        effect_status=EFFECT_APPLIED,
        effect_id="effect-1",
    )
    row = {"result_json": ToolResultCodec.serialize_operation_result(result)}
    restored = ToolResultCodec.deserialize_operation_result(
        row,
        call={"id": "call-1", "arguments": {"path": "a"}},
        tool=SimpleNamespace(name="write_file"),
    )
    assert restored == result

    malformed = ToolResultCodec.deserialize_operation_result(
        {"result_json": json.dumps({"success": True, "unknown": "ignored"})},
        call={"id": "call-2", "arguments": {}},
        tool=SimpleNamespace(name="write_file"),
    )
    assert malformed.success is True
    unresolved = ToolResultCodec.deserialize_operation_result(
        {"result_json": "not-json", "effect_status": EFFECT_UNKNOWN},
        call={"id": "call-3", "arguments": {}},
        tool=SimpleNamespace(name="write_file"),
    )
    assert unresolved.success is False
    assert unresolved.effect_status == EFFECT_UNKNOWN
    assert unresolved.retry_safe is False


def test_durable_codec_restores_an_applied_effect_receipt() -> None:
    receipt = {
        "status": "applied",
        "transaction_id": "tx-1",
        "workspace_id": "ws-1",
        "base_generation": 1,
        "resulting_generation": 2,
        "transaction_digest": "a" * 64,
        "before_workspace_digest": "b" * 64,
        "after_workspace_digest": "c" * 64,
        "operations": [
            {
                "index": 0,
                "operation": "update",
                "path": "src/app.py",
                "destination_path": None,
                "before_exists": True,
                "after_exists": True,
                "before_digest": "d" * 64,
                "after_digest": "e" * 64,
            }
        ],
    }
    result = ToolResult(
        tool_call_id="call-1",
        name="apply_edit_transaction",
        success=True,
        output={"status": "applied"},
        effect_status=EFFECT_APPLIED,
        effect_receipt=receipt,
    )

    restored = ToolResultCodec.deserialize_operation_result(
        {"result_json": ToolResultCodec.serialize_operation_result(result)},
        call={"id": "call-1", "arguments": {}},
        tool=SimpleNamespace(name="apply_edit_transaction"),
    )

    assert restored.effect_receipt == receipt
