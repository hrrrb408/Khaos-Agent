"""Regression tests for the extracted orchestration boundary components."""

from __future__ import annotations

from khaos.security.orchestration_components import (
    ToolPhaseCoordinator,
    TurnAdmission,
    TurnFinalizer,
)
from khaos.security.orchestration_phases import (
    ToolPhase,
    ToolPhaseSnapshot,
    TurnPhase,
)
from khaos.tools.scheduler import ToolResult


def test_turn_components_admit_and_finalize_with_immutable_evidence() -> None:
    phase = TurnAdmission.admit(
        session_id="session-1",
        turn_id="turn-1",
        attempt_id="attempt-1",
        task_id="task-1",
    )
    phase = phase.transition(TurnPhase.CONTEXT_ASSEMBLED)
    phase = phase.transition(TurnPhase.MODEL_EXECUTING)
    finalized = TurnFinalizer.finalize(phase, terminal_status="completed")

    assert finalized.phase is TurnPhase.FINALIZED
    assert finalized.terminal_status == "completed"
    assert phase.phase is TurnPhase.MODEL_EXECUTING


def test_tool_phase_coordinator_preserves_phase_digest_on_terminal_result() -> None:
    call = {
        "id": "call-1",
        "name": "read_file",
        "arguments": {"path": "a"},
    }
    call["_phase_snapshot"] = ToolPhaseSnapshot.raw(call)
    ToolPhaseCoordinator.advance(call, ToolPhase.VALIDATED)
    ToolPhaseCoordinator.advance(call, ToolPhase.RESOURCE_RESOLVED)
    ToolPhaseCoordinator.advance(call, ToolPhase.PERMISSION_DECIDED)
    ToolPhaseCoordinator.advance(call, ToolPhase.APPROVAL_BOUND)
    ToolPhaseCoordinator.advance(call, ToolPhase.AUTHORIZED_EFFECT)
    ToolPhaseCoordinator.advance(call, ToolPhase.DISPATCHING)

    result = ToolResult(
        tool_call_id="call-1",
        name="read_file",
        success=True,
        output="contents",
        effect_status="not_started",
        effect_id="effect-1",
    )
    terminal = ToolPhaseCoordinator.terminalize(call, result)

    assert call["_phase_snapshot"].phase is ToolPhase.TERMINAL
    assert call["_phase_digest"]
    assert terminal.phase_digest == call["_phase_digest"]
    assert result.phase_digest == ""


def test_tool_phase_coordinator_leaves_legacy_result_without_snapshot_untouched() -> None:
    result = ToolResult(tool_call_id="call-1", name="read_file", success=True)

    assert ToolPhaseCoordinator.terminalize({}, result) is result
