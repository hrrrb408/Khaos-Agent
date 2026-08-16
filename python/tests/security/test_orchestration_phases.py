"""Regression tests for immutable AgentLoop/ToolScheduler phase evidence."""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest
from khaos.security.orchestration_phases import (
    OrchestrationPhaseError,
    ToolPhase,
    ToolPhaseSnapshot,
    TurnPhase,
    TurnPhaseSnapshot,
)


def test_turn_phase_requires_one_step_and_freezes_metadata() -> None:
    admitted = TurnPhaseSnapshot.admitted(
        session_id="session-1",
        turn_id="turn-1",
        attempt_id="attempt-1",
    )

    assembled = admitted.transition(
        TurnPhase.CONTEXT_ASSEMBLED,
        context_digest="context-digest",
        metadata={"source": "test"},
    )
    assert assembled.phase is TurnPhase.CONTEXT_ASSEMBLED
    assert assembled.metadata["source"] == "test"
    assert assembled.digest() != admitted.digest()

    with pytest.raises(TypeError):
        assembled.metadata["source"] = "mutated"  # type: ignore[index]
    with pytest.raises(OrchestrationPhaseError):
        admitted.transition(TurnPhase.MODEL_EXECUTING)
    with pytest.raises(FrozenInstanceError):
        assembled.phase = TurnPhase.MODEL_EXECUTING  # type: ignore[misc]


def test_turn_phase_allows_tool_verification_cycle_and_terminal_close() -> None:
    phase = TurnPhaseSnapshot.admitted(
        session_id="session-1",
        turn_id="turn-1",
        attempt_id="attempt-1",
    )
    phase = phase.transition(TurnPhase.CONTEXT_ASSEMBLED)
    phase = phase.transition(TurnPhase.MODEL_EXECUTING)
    phase = phase.transition(
        TurnPhase.TOOL_EXECUTING,
        tool_batch_digest="tools-digest",
    )
    phase = phase.transition(
        TurnPhase.VERIFYING,
        verification_digest="verification-digest",
    )
    phase = phase.transition(TurnPhase.MODEL_EXECUTING)
    phase = phase.transition(TurnPhase.FINALIZING, terminal_status="completed")
    phase = phase.transition(TurnPhase.FINALIZED, terminal_status="completed")
    assert phase.phase is TurnPhase.FINALIZED


def test_tool_phase_snapshots_reject_argument_drift_and_skips() -> None:
    call = {"id": "call-1", "name": "read_file", "arguments": {"path": "a"}}
    phase = ToolPhaseSnapshot.raw(call)
    call["arguments"] = {"path": "b"}
    with pytest.raises(OrchestrationPhaseError):
        phase.assert_call(call)

    call["arguments"] = {"path": "a"}
    phase = phase.transition(ToolPhase.VALIDATED)
    with pytest.raises(OrchestrationPhaseError):
        phase.transition(ToolPhase.AUTHORIZED_EFFECT)


def test_tool_phase_digest_changes_only_with_new_immutable_evidence() -> None:
    call = {"id": "call-1", "name": "read_file", "arguments": {"path": "a"}}
    phase = ToolPhaseSnapshot.raw(call)
    raw_digest = phase.digest()
    phase = phase.transition(ToolPhase.VALIDATED)
    phase = phase.transition(ToolPhase.RESOURCE_RESOLVED, resource_digest="resource")
    phase = phase.transition(
        ToolPhase.PERMISSION_DECIDED,
        permission_digest="permission",
    )
    phase = phase.transition(ToolPhase.APPROVAL_BOUND, approval_digest="approval")
    phase = phase.transition(ToolPhase.AUTHORIZED_EFFECT, authority_digest="authority")
    phase = phase.transition(ToolPhase.DISPATCHING)
    terminal = phase.transition(
        ToolPhase.TERMINAL,
        effect_digest="effect",
        result_digest="result",
    )

    assert terminal.phase is ToolPhase.TERMINAL
    assert terminal.digest() != raw_digest
    assert phase.phase is ToolPhase.DISPATCHING
