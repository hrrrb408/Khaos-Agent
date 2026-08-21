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
