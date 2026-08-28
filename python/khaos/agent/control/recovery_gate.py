"""Public Recovery Gate service for durable M7.5 control decisions.

``RecoveryDecision`` is passive history.  ``RecoveryGate`` is the only public
service that can ask the specialized repository to apply a recovery cognitive
projection.  The repository performs the owner, history-head, source-snapshot,
and SQL CAS checks; this service only maps that result into the public typed
contract.

No recovery action completes a task, approves an operation, or grants any
execution capability.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum

from khaos.agent.control.recovery import RecoveryAction
from khaos.agent.control.recovery_gate_repository import (
    _RECOVERY_GATE_TOKEN,
    RecoveryGateRepository,
    RecoveryProjectionResult,
    RecoveryProjectionStatus,
)
from khaos.agent.control.recovery_repository import (
    RecoveryDecisionRepositoryError,
)
from khaos.agent.control.state import AgentCognitiveState

logger = logging.getLogger(__name__)

_MAX_REASON_LENGTH = 512


class RecoveryGateStatus(str, Enum):
    """Public result vocabulary for one recovery-gate attempt."""

    APPLIED = "applied"
    ALREADY_APPLIED = "already_applied"
    NO_ACTION = "no_action"
    BLOCKED = "blocked"
    STALE = "stale"
    TERMINAL = "terminal"
    NOT_FOUND = "not_found"
    REJECTED = "rejected"
    INVALID = "invalid"
    INTEGRITY_ERROR = "integrity_error"
    CONFLICT = "conflict"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class RecoveryGateResult:
    """Bounded passive result of applying one recovery decision."""

    status: RecoveryGateStatus
    recovery_decision_id: str
    recovery_sequence: int | None = None
    task_id: str | None = None
    action: RecoveryAction | None = None
    cognitive_state: AgentCognitiveState | None = None
    control_state_version: int | None = None
    task_status: str | None = None
    published_plan_revision_id: str | None = None
    reason: str = ""

    def __post_init__(self) -> None:
        if type(self.status) is not RecoveryGateStatus:
            raise ValueError("status must be a RecoveryGateStatus")
        if type(self.recovery_decision_id) is not str or not self.recovery_decision_id:
            raise ValueError("recovery_decision_id must be a non-empty string")
        if self.recovery_sequence is not None and (
            type(self.recovery_sequence) is not int or self.recovery_sequence < 1
        ):
            raise ValueError("recovery_sequence must be positive or None")
        if self.task_id is not None and (
            type(self.task_id) is not str or not self.task_id
        ):
            raise ValueError("task_id must be non-empty or None")
        if self.action is not None and type(self.action) is not RecoveryAction:
            raise ValueError("action must be a RecoveryAction or None")
        if self.cognitive_state is not None and type(self.cognitive_state) is not AgentCognitiveState:
            raise ValueError("cognitive_state must be an AgentCognitiveState or None")
        if self.control_state_version is not None and (
            type(self.control_state_version) is not int
            or self.control_state_version < 0
        ):
            raise ValueError("control_state_version must be non-negative or None")
        if self.task_status is not None and (
            type(self.task_status) is not str or not self.task_status
        ):
            raise ValueError("task_status must be non-empty or None")
        if self.published_plan_revision_id is not None and (
            type(self.published_plan_revision_id) is not str
            or not self.published_plan_revision_id
        ):
            raise ValueError("published_plan_revision_id must be non-empty or None")
        if type(self.reason) is not str or len(self.reason) > _MAX_REASON_LENGTH:
            raise ValueError("reason exceeds its bound")


class RecoveryGate:
    """Apply owner-scoped recovery control decisions through the SQL gate."""

    def __init__(
        self,
        *,
        gate_repository: RecoveryGateRepository,
        principal_id: str,
        project_id: str,
    ) -> None:
        if type(principal_id) is not str or not principal_id:
            raise ValueError("principal_id must be a non-empty string")
        if type(project_id) is not str:
            raise ValueError("project_id must be a string")
        self._gate_repository = gate_repository
        self._principal_id = principal_id
        self._project_id = project_id

    @property
    def principal_id(self) -> str:
        """Return the authenticated owner bound to this gate."""
        return self._principal_id

    @property
    def project_id(self) -> str:
        """Return the project identity bound to this gate."""
        return self._project_id

    async def apply(self, recovery_decision_id: str) -> RecoveryGateResult:
        """Reload and atomically apply one server-selected decision."""
        if type(recovery_decision_id) is not str or not recovery_decision_id:
            raise ValueError("recovery_decision_id must be a non-empty string")
        try:
            projection = await self._gate_repository.apply_decision(
                recovery_decision_id,
                principal_id=self._principal_id,
                project_id=self._project_id,
                gate_token=_RECOVERY_GATE_TOKEN,
            )
        except RecoveryDecisionRepositoryError as exc:
            logger.warning(
                "recovery gate rejected decision %s: %s",
                recovery_decision_id,
                type(exc).__name__,
            )
            return RecoveryGateResult(
                status=RecoveryGateStatus.ERROR,
                recovery_decision_id=recovery_decision_id,
                reason=type(exc).__name__,
            )
        except Exception as exc:
            logger.exception("recovery gate application failed")
            return RecoveryGateResult(
                status=RecoveryGateStatus.ERROR,
                recovery_decision_id=recovery_decision_id,
                reason=type(exc).__name__,
            )
        return _map_projection(projection)

    async def evaluate(self, recovery_decision_id: str) -> RecoveryGateResult:
        """Compatibility alias with explicit evaluation wording."""
        return await self.apply(recovery_decision_id)


def _map_projection(projection: RecoveryProjectionResult) -> RecoveryGateResult:
    status = {
        RecoveryProjectionStatus.APPLIED: RecoveryGateStatus.APPLIED,
        RecoveryProjectionStatus.ALREADY_APPLIED: RecoveryGateStatus.ALREADY_APPLIED,
        RecoveryProjectionStatus.NO_ACTION: RecoveryGateStatus.NO_ACTION,
        RecoveryProjectionStatus.BLOCKED: RecoveryGateStatus.BLOCKED,
        RecoveryProjectionStatus.STALE: RecoveryGateStatus.STALE,
        RecoveryProjectionStatus.TERMINAL: RecoveryGateStatus.TERMINAL,
        RecoveryProjectionStatus.NOT_FOUND: RecoveryGateStatus.NOT_FOUND,
        RecoveryProjectionStatus.REJECTED: RecoveryGateStatus.REJECTED,
        RecoveryProjectionStatus.INVALID: RecoveryGateStatus.INVALID,
        RecoveryProjectionStatus.INTEGRITY_ERROR: RecoveryGateStatus.INTEGRITY_ERROR,
        RecoveryProjectionStatus.CONFLICT: RecoveryGateStatus.CONFLICT,
        RecoveryProjectionStatus.ERROR: RecoveryGateStatus.ERROR,
    }.get(projection.status, RecoveryGateStatus.ERROR)
    return RecoveryGateResult(
        status=status,
        recovery_decision_id=projection.recovery_decision_id,
        recovery_sequence=projection.recovery_sequence,
        task_id=projection.task_id,
        action=projection.action,
        cognitive_state=projection.cognitive_state,
        control_state_version=projection.control_state_version,
        task_status=projection.task_status,
        published_plan_revision_id=projection.published_plan_revision_id,
        reason=projection.reason,
    )


__all__ = [
    "RecoveryGate",
    "RecoveryGateResult",
    "RecoveryGateStatus",
]
