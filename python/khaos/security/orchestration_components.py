"""Small phase-boundary components extracted from the orchestration owners.

These components deliberately own only immutable phase evidence.  They keep
the AgentLoop and ToolScheduler domain state separate from the security proof
that crosses each boundary, which makes the next physical extraction steps
incremental instead of requiring a risky rewrite of either loop.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from khaos.exceptions import PermissionDeniedError
from khaos.security.orchestration_phases import (
    OrchestrationPhaseError,
    ToolPhase,
    ToolPhaseSnapshot,
    TurnPhase,
    TurnPhaseSnapshot,
    digest_phase_payload,
)


class TurnAdmission:
    """Create the immutable admission evidence for one turn."""

    @staticmethod
    def admit(
        *,
        session_id: str,
        turn_id: str,
        attempt_id: str,
        task_id: str = "",
    ) -> TurnPhaseSnapshot:
        return TurnPhaseSnapshot.admitted(
            session_id=session_id,
            turn_id=turn_id,
            attempt_id=attempt_id,
            task_id=task_id,
        )


class TurnFinalizer:
    """Own the final two edges of the turn phase graph."""

    @staticmethod
    def finalize(
        phase: TurnPhaseSnapshot,
        *,
        terminal_status: str,
    ) -> TurnPhaseSnapshot:
        if phase.phase is not TurnPhase.FINALIZING:
            phase = phase.transition(
                TurnPhase.FINALIZING,
                terminal_status=terminal_status,
            )
        return phase.transition(
            TurnPhase.FINALIZED,
            terminal_status=terminal_status,
        )


class ToolPhaseCoordinator:
    """Advance and close one tool call without owning its execution state."""

    @staticmethod
    def advance(
        call: dict[str, Any],
        next_phase: ToolPhase,
        **evidence: Any,
    ) -> ToolPhaseSnapshot:
        snapshot = call.get("_phase_snapshot")
        if not isinstance(snapshot, ToolPhaseSnapshot):
            raise PermissionDeniedError(
                "tool phase evidence is missing at the scheduler boundary"
            )
        try:
            snapshot.assert_call(call)
            next_snapshot = snapshot.transition(next_phase, **evidence)
        except OrchestrationPhaseError as exc:
            raise PermissionDeniedError(str(exc)) from exc
        call["_phase_snapshot"] = next_snapshot
        call["_phase_digest"] = next_snapshot.digest()
        return next_snapshot

    @staticmethod
    def terminalize(call: dict[str, Any], result: Any) -> Any:
        snapshot = call.get("_phase_snapshot")
        if not isinstance(snapshot, ToolPhaseSnapshot):
            return result
        try:
            snapshot.assert_call(call)
            terminal = snapshot.transition(
                ToolPhase.TERMINAL,
                effect_digest=digest_phase_payload(
                    {
                        "effect_id": result.effect_id,
                        "effect_status": result.effect_status,
                    }
                ),
                result_digest=digest_phase_payload(
                    {
                        "success": result.success,
                        "error_code": result.error_code,
                        "delivery_status": result.delivery_status,
                    }
                ),
            )
        except OrchestrationPhaseError as exc:
            raise PermissionDeniedError(str(exc)) from exc
        call["_phase_snapshot"] = terminal
        call["_phase_digest"] = terminal.digest()
        return replace(result, phase_digest=terminal.digest())


__all__ = ["ToolPhaseCoordinator", "TurnAdmission", "TurnFinalizer"]
