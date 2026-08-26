"""Machine regression contracts for the existing typed scheduler boundary."""

from __future__ import annotations

from dataclasses import is_dataclass

from khaos.agent.approval import ApprovalBinding, StepExecutionAuthority
from khaos.coding.execution.models import ResolvedExecutionContext
from khaos.security.orchestration_phases import ToolPhaseSnapshot
from khaos.tools.admission import AdmittedToolCall


def test_security_state_owners_are_frozen_dataclasses() -> None:
    owners = (
        AdmittedToolCall,
        ToolPhaseSnapshot,
        ApprovalBinding,
        StepExecutionAuthority,
        ResolvedExecutionContext,
    )
    for owner in owners:
        assert is_dataclass(owner)
        assert owner.__dataclass_params__.frozen is True


def test_scheduler_state_machine_has_one_ordered_phase_path() -> None:
    from khaos.security.orchestration_phases import ToolPhase

    phase = ToolPhaseSnapshot.raw(
        {"id": "call-1", "name": "read_file", "arguments": {"path": "a"}}
    )
    for next_phase in (
        ToolPhase.VALIDATED,
        ToolPhase.RESOURCE_RESOLVED,
        ToolPhase.PERMISSION_DECIDED,
        ToolPhase.APPROVAL_BOUND,
        ToolPhase.AUTHORIZED_EFFECT,
        ToolPhase.DISPATCHING,
        ToolPhase.TERMINAL,
    ):
        phase = phase.transition(next_phase)
    assert phase.phase is ToolPhase.TERMINAL


def test_scheduler_unknown_effect_is_not_retryable() -> None:
    from khaos.tools.result_codec import ToolResultCodec
    from khaos.tools.scheduler_models import ToolExecutionOutcome

    result = ToolResultCodec.normalize_effect_outcome(
        ToolExecutionOutcome(
            ok=False,
            effect_status="unknown",
            effect_id="effect-1",
            retry_safe=True,
        ),
        default_status="not_applied",
        default_effect_id="effect-1",
        default_reconciliation_hint="reconcile before retry",
    )
    assert result.effect_status == "unknown"
    assert result.retry_safe is False
