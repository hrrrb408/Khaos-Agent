"""Contract tests for the scheduler's extracted value and budget boundaries."""

import pytest
from khaos.security.orchestration_phases import OrchestrationPhaseError
from khaos.security.orchestration_phases import ToolPhase
from khaos.tools.admission import AdmittedToolCall, RejectedToolCall, ToolAdmission
from khaos.tools.budget import (
    ToolBudget,
    ToolOutputBudgetExceeded,
    measure_tool_output,
)
from khaos.tools.registry import ToolDefinition, ToolRegistry
from khaos.tools.scheduler import (
    EFFECT_APPLIED as legacy_effect_applied,
)
from khaos.tools.scheduler import (
    ToolBudget as legacy_tool_budget,
)
from khaos.tools.scheduler import (
    ToolResult as legacy_tool_result,
)
from khaos.tools.scheduler_models import (
    EFFECT_APPLIED,
    ToolExecutionOutcome,
    ToolResult,
)


def test_scheduler_compatibility_exports_use_canonical_boundary_types() -> None:
    """The old import path must not create a second protocol or budget type."""
    assert legacy_tool_budget is ToolBudget
    assert legacy_tool_result is ToolResult
    assert legacy_effect_applied is EFFECT_APPLIED


def test_tool_execution_outcome_keeps_legacy_mapping_projection() -> None:
    outcome = ToolExecutionOutcome(
        ok=False,
        output={"status": "forbidden"},
        error="principal is not allowed",
    )

    assert outcome["status"] == "forbidden"
    assert outcome["ok"] is False
    assert outcome["error"] == "principal is not allowed"
    assert outcome == {
        "status": "forbidden",
        "ok": False,
        "error": "principal is not allowed",
    }


def test_tool_admission_owns_normalization_and_validation() -> None:
    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            name="read",
            description="read",
            parameters={
                "type": "object",
                "properties": {"value": {"type": "string"}},
                "required": ["value"],
            },
            modes=["all"],
            permission_level="read",
            parallel=True,
        )
    )
    admission = ToolAdmission(registry)

    accepted = admission.admit(
        {
            "id": "call-1",
            "name": "read",
            "arguments": {"value": "ok"},
            "_idempotency_key": "model-controlled",
        }
    )
    assert isinstance(accepted, AdmittedToolCall)
    assert accepted.call["_phase_snapshot"].phase is ToolPhase.VALIDATED
    assert "_idempotency_key" not in accepted.call

    rejected = admission.admit(
        {"id": "call-2", "name": "read", "arguments": {"value": 1}}
    )
    assert isinstance(rejected, RejectedToolCall)
    assert rejected.error == "Invalid tool arguments"


def test_admitted_arguments_are_immutable_and_scheduler_drift_is_rejected() -> None:
    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            name="read",
            description="read",
            parameters={
                "type": "object",
                "properties": {"value": {"type": "string"}},
                "required": ["value"],
            },
            modes=["all"],
            permission_level="read",
            parallel=True,
        )
    )
    admitted = ToolAdmission(registry).admit(
        {"id": "call-immutable", "name": "read", "arguments": {"value": "ok"}}
    )
    assert isinstance(admitted, AdmittedToolCall)

    with pytest.raises(TypeError):
        admitted.call["arguments"]["value"] = "changed"  # type: ignore[index]

    state = admitted.scheduler_state()
    state["arguments"]["value"] = "changed"
    with pytest.raises(OrchestrationPhaseError, match="arguments changed"):
        admitted.assert_unchanged(state)


@pytest.mark.asyncio
async def test_budget_release_reclaims_all_reserved_capacity() -> None:
    budget = ToolBudget(
        max_calls=1,
        max_output_chars=32,
        max_total_output=32,
        max_output_per_tool=32,
    )

    reservation = await budget.reserve()
    assert reservation is not None
    assert budget.is_exhausted

    await reservation.release()

    replacement = await budget.reserve()
    assert replacement is not None
    await replacement.commit(4)
    assert budget.is_exhausted


def test_measure_tool_output_rejects_cycles_and_unsupported_values() -> None:
    cyclic: list[object] = []
    cyclic.append(cyclic)

    with pytest.raises(ToolOutputBudgetExceeded, match="cycle"):
        measure_tool_output(cyclic, 128)

    with pytest.raises(ToolOutputBudgetExceeded, match="JSON-compatible"):
        measure_tool_output(object(), 128)
