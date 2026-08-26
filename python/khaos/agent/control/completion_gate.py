"""Completion Gate contracts and owner-scoped lifecycle orchestration.

The gate is the only M7 control-plane component that may project a validated
``CompletionOutcome.COMPLETE`` onto a coding task's lifecycle.  The decision
ledger remains passive: this module reloads the immutable decision, obtains a
separately produced authority result, and delegates the final atomic stale
check and projection to ``CompletionGateRepository``.

The default authority policy is deliberately fail-closed.  A COMPLETE
decision or a SATISFIED assessment is an evaluation record, not permission to
complete a task.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Protocol

from khaos.agent.control.completion import CompletionDecision, CompletionOutcome
from khaos.agent.control.completion_repository import (
    CompletionDecisionRepositoryError,
    StoredCompletionDecision,
)
from khaos.agent.control.goal import GoalSpec

if TYPE_CHECKING:
    from khaos.agent.control.completion_gate_repository import (
        CompletionGateRepository,
        CompletionProjectionResult,
    )

logger = logging.getLogger(__name__)

_MAX_REASON_LENGTH = 512


class CompletionGateStatus(str, Enum):
    """Typed result of a completion-gate attempt."""

    COMPLETED = "completed"
    NOT_COMPLETE = "not_complete"
    STALE = "stale"
    AUTHORITY_INSUFFICIENT = "authority_insufficient"
    ALREADY_TERMINAL = "already_terminal"
    REJECTED = "rejected"
    ERROR = "error"


class CompletionAuthorityStatus(str, Enum):
    """Authority-policy result vocabulary.

    ``AUTHORIZED`` is only meaningful when returned by an explicitly
    composed authority policy.  It is never inferred from a decision,
    assessment, evidence kind, or model output.
    """

    AUTHORIZED = "authorized"
    INSUFFICIENT = "insufficient"
    REJECTED = "rejected"


@dataclass(frozen=True, slots=True)
class CompletionAuthorityResult:
    """Immutable, decision-bound result from a completion authority policy."""

    task_id: str
    goal_spec_id: str
    goal_spec_digest: str
    decision_id: str
    decision_digest: str
    status: CompletionAuthorityStatus
    reason: str = ""

    def __post_init__(self) -> None:
        _require_text(self.task_id, label="task_id")
        _require_text(self.goal_spec_id, label="goal_spec_id")
        _require_text(self.goal_spec_digest, label="goal_spec_digest")
        _require_text(self.decision_id, label="decision_id")
        _require_text(self.decision_digest, label="decision_digest")
        if type(self.status) is not CompletionAuthorityStatus:
            raise ValueError("status must be a CompletionAuthorityStatus")
        _require_reason(self.reason)

    @property
    def authorized(self) -> bool:
        """Return whether this typed policy result permits gate evaluation."""
        return self.status is CompletionAuthorityStatus.AUTHORIZED


@dataclass(frozen=True, slots=True)
class CompletionGateResult:
    """Passive result of one owner-scoped gate attempt."""

    status: CompletionGateStatus
    decision_id: str
    decision_digest: str | None
    task_status: str | None
    reason: str = ""

    def __post_init__(self) -> None:
        if type(self.status) is not CompletionGateStatus:
            raise ValueError("status must be a CompletionGateStatus")
        _require_text(self.decision_id, label="decision_id")
        if self.decision_digest is not None:
            _require_text(self.decision_digest, label="decision_digest")
        if self.task_status is not None:
            _require_text(self.task_status, label="task_status")
        _require_reason(self.reason)


class CompletionGateAuthorityPolicy(Protocol):
    """Port for a real, separately-owned completion authority."""

    async def authorize(
        self,
        *,
        goal_spec: GoalSpec,
        decision: CompletionDecision,
        principal_id: str,
        project_id: str,
    ) -> CompletionAuthorityResult:
        """Return a decision-bound authority result without mutating state."""
        raise NotImplementedError


class CompletionTaskProjection(Protocol):
    """Optional in-memory projection sink after the DB projection commits."""

    async def reflect_gate_completion(self, task_id: str) -> None:
        """Reflect a database-confirmed completion without writing the DB."""
        raise NotImplementedError


class FailClosedCompletionAuthorityPolicy:
    """Production default: no arbitrary completion claim is authoritative."""

    async def authorize(
        self,
        *,
        goal_spec: GoalSpec,
        decision: CompletionDecision,
        principal_id: str,
        project_id: str,
    ) -> CompletionAuthorityResult:
        """Deny lifecycle projection until a trusted authority is composed."""
        del goal_spec, principal_id, project_id
        return CompletionAuthorityResult(
            task_id=decision.task_id,
            goal_spec_id=decision.goal_spec_id,
            goal_spec_digest=decision.goal_spec_digest,
            decision_id=decision.decision_id,
            decision_digest=decision.decision_digest,
            status=CompletionAuthorityStatus.INSUFFICIENT,
            reason="no production completion authority is configured",
        )


class CompletionDecisionReader(Protocol):
    """Owner-scoped decision lookup required by the gate."""

    async def get_by_id(
        self,
        decision_id: str,
        *,
        principal_id: str,
        project_id: str,
    ) -> StoredCompletionDecision | None:
        """Reload one immutable decision in the supplied owner scope."""
        raise NotImplementedError


class CompletionGoalSpecReader(Protocol):
    """Owner-scoped canonical GoalSpec lookup required by the gate."""

    async def get_for_task(
        self,
        task_id: str,
        *,
        principal_id: str,
        project_id: str,
    ) -> GoalSpec | None:
        """Reload the canonical GoalSpec bound to a task."""
        raise NotImplementedError


class CompletionGate:
    """Reload, authorize, and atomically project one COMPLETE decision."""

    def __init__(
        self,
        *,
        decision_repository: CompletionDecisionReader,
        goal_spec_repository: CompletionGoalSpecReader,
        principal_id: str,
        project_id: str,
        authority_policy: CompletionGateAuthorityPolicy | None = None,
        gate_repository: CompletionGateRepository | None = None,
        task_projection: CompletionTaskProjection | None = None,
    ) -> None:
        _require_text(principal_id, label="principal_id")
        if type(project_id) is not str:
            raise ValueError("project_id must be a string")
        self._decision_repository = decision_repository
        self._goal_spec_repository = goal_spec_repository
        self._principal_id = principal_id
        self._project_id = project_id
        self._authority_policy = (
            FailClosedCompletionAuthorityPolicy()
            if authority_policy is None
            else authority_policy
        )
        self._task_projection = task_projection
        if gate_repository is None:
            database = getattr(decision_repository, "database", None)
            if database is None:
                raise ValueError(
                    "a gate repository is required when the decision reader "
                    "does not expose its database"
                )
            from khaos.agent.control.completion_gate_repository import (
                CompletionGateRepository,
            )

            gate_repository = CompletionGateRepository(database)
        self._gate_repository = gate_repository

    async def evaluate(self, decision_id: str) -> CompletionGateResult:
        """Evaluate one server-selected decision for lifecycle projection.

        The immutable decision is first reloaded for the authenticated owner.
        The final repository operation reloads it again and performs all
        snapshot comparison and the status CAS inside one writer transaction.
        """
        _require_text(decision_id, label="decision_id")
        try:
            stored = await self._decision_repository.get_by_id(
                decision_id,
                principal_id=self._principal_id,
                project_id=self._project_id,
            )
        except CompletionDecisionRepositoryError as exc:
            return _gate_error(decision_id, reason=type(exc).__name__)
        except Exception as exc:
            logger.exception("completion decision lookup failed")
            return _gate_error(decision_id, reason=type(exc).__name__)

        if stored is None:
            return CompletionGateResult(
                status=CompletionGateStatus.REJECTED,
                decision_id=decision_id,
                decision_digest=None,
                task_status=None,
                reason="decision is unavailable in the supplied owner scope",
            )
        if type(stored) is not StoredCompletionDecision:
            return _gate_error(decision_id, reason="invalid stored decision type")
        if (
            stored.decision_id != decision_id
            or stored.principal_id != self._principal_id
            or stored.project_id != self._project_id
        ):
            return CompletionGateResult(
                status=CompletionGateStatus.REJECTED,
                decision_id=decision_id,
                decision_digest=None,
                task_status=None,
                reason="decision owner or identity binding is invalid",
            )
        decision = stored.decision
        if type(decision) is not CompletionDecision:
            return _gate_error(decision_id, reason="invalid stored decision")
        decision_digest = decision.decision_digest

        if decision.outcome is not CompletionOutcome.COMPLETE:
            return CompletionGateResult(
                status=CompletionGateStatus.NOT_COMPLETE,
                decision_id=decision_id,
                decision_digest=decision_digest,
                task_status=decision.task_status_at_evaluation,
                reason="only a COMPLETE decision is eligible for projection",
            )

        try:
            goal_spec = await self._goal_spec_repository.get_for_task(
                decision.task_id,
                principal_id=self._principal_id,
                project_id=self._project_id,
            )
        except Exception as exc:
            logger.exception("canonical GoalSpec lookup failed")
            return _gate_error(
                decision_id,
                decision_digest=decision_digest,
                reason=type(exc).__name__,
            )
        if goal_spec is None or type(goal_spec) is not GoalSpec:
            return CompletionGateResult(
                status=CompletionGateStatus.REJECTED,
                decision_id=decision_id,
                decision_digest=decision_digest,
                task_status=decision.task_status_at_evaluation,
                reason="canonical GoalSpec is unavailable in the owner scope",
            )
        if (
            decision.goal_spec_id != goal_spec.goal_spec_id
            or decision.goal_spec_digest != goal_spec.semantic_digest
        ):
            return CompletionGateResult(
                status=CompletionGateStatus.STALE,
                decision_id=decision_id,
                decision_digest=decision_digest,
                task_status=decision.task_status_at_evaluation,
                reason="decision GoalSpec binding is stale or mismatched",
            )

        try:
            authority = await self._authority_policy.authorize(
                goal_spec=goal_spec,
                decision=decision,
                principal_id=self._principal_id,
                project_id=self._project_id,
            )
        except Exception as exc:
            logger.exception("completion authority policy failed")
            return _gate_error(
                decision_id,
                decision_digest=decision_digest,
                task_status=decision.task_status_at_evaluation,
                reason=type(exc).__name__,
            )
        if type(authority) is not CompletionAuthorityResult:
            return _gate_error(
                decision_id,
                decision_digest=decision_digest,
                task_status=decision.task_status_at_evaluation,
                reason="invalid completion authority result",
            )
        if not _authority_matches(authority, decision):
            return CompletionGateResult(
                status=CompletionGateStatus.REJECTED,
                decision_id=decision_id,
                decision_digest=decision_digest,
                task_status=decision.task_status_at_evaluation,
                reason="completion authority result is not bound to the decision",
            )
        if not authority.authorized:
            return CompletionGateResult(
                status=(
                    CompletionGateStatus.AUTHORITY_INSUFFICIENT
                    if authority.status is CompletionAuthorityStatus.INSUFFICIENT
                    else CompletionGateStatus.REJECTED
                ),
                decision_id=decision_id,
                decision_digest=decision_digest,
                task_status=decision.task_status_at_evaluation,
                reason=authority.reason or "completion authority is insufficient",
            )

        try:
            from khaos.agent.control.completion_gate_repository import (
                _COMPLETION_GATE_TOKEN,
            )

            projection = await self._gate_repository.project_completion(
                decision_id,
                principal_id=self._principal_id,
                project_id=self._project_id,
                authority=authority,
                gate_token=_COMPLETION_GATE_TOKEN,
            )
        except Exception as exc:
            logger.exception("completion projection failed")
            return _gate_error(
                decision_id,
                decision_digest=decision_digest,
                task_status=decision.task_status_at_evaluation,
                reason=type(exc).__name__,
            )
        result = _map_projection_result(
            projection,
            decision_id=decision_id,
            decision_digest=decision_digest,
        )
        if (
            result.status is CompletionGateStatus.COMPLETED
            and self._task_projection is not None
        ):
            try:
                await self._task_projection.reflect_gate_completion(decision.task_id)
            except Exception:
                logger.exception(
                    "in-memory task projection failed after durable completion"
                )
        return result


def _authority_matches(
    authority: CompletionAuthorityResult,
    decision: CompletionDecision,
) -> bool:
    return (
        authority.task_id == decision.task_id
        and authority.goal_spec_id == decision.goal_spec_id
        and authority.goal_spec_digest == decision.goal_spec_digest
        and authority.decision_id == decision.decision_id
        and authority.decision_digest == decision.decision_digest
    )


def _map_projection_result(
    projection: CompletionProjectionResult,
    *,
    decision_id: str,
    decision_digest: str,
) -> CompletionGateResult:
    from khaos.agent.control.completion_gate_repository import (
        CompletionProjectionStatus,
    )

    status_map = {
        CompletionProjectionStatus.PROJECTED: CompletionGateStatus.COMPLETED,
        CompletionProjectionStatus.NOT_COMPLETE: CompletionGateStatus.NOT_COMPLETE,
        CompletionProjectionStatus.STALE: CompletionGateStatus.STALE,
        CompletionProjectionStatus.AUTHORITY_INSUFFICIENT: CompletionGateStatus.AUTHORITY_INSUFFICIENT,
        CompletionProjectionStatus.REJECTED: CompletionGateStatus.REJECTED,
        CompletionProjectionStatus.ALREADY_TERMINAL: CompletionGateStatus.ALREADY_TERMINAL,
        CompletionProjectionStatus.NOT_FOUND: CompletionGateStatus.REJECTED,
        CompletionProjectionStatus.INTEGRITY_ERROR: CompletionGateStatus.ERROR,
        CompletionProjectionStatus.ERROR: CompletionGateStatus.ERROR,
    }
    gate_status = status_map.get(
        projection.status,
        CompletionGateStatus.ERROR,
    )
    return CompletionGateResult(
        status=gate_status,
        decision_id=decision_id,
        decision_digest=projection.decision_digest or decision_digest,
        task_status=projection.task_status,
        reason=projection.reason,
    )


def _gate_error(
    decision_id: str,
    *,
    decision_digest: str | None = None,
    task_status: str | None = None,
    reason: str,
) -> CompletionGateResult:
    return CompletionGateResult(
        status=CompletionGateStatus.ERROR,
        decision_id=decision_id,
        decision_digest=decision_digest,
        task_status=task_status,
        reason=reason,
    )


def _require_text(value: object, *, label: str) -> str:
    if type(value) is not str or not value:
        raise ValueError(f"{label} must be a non-empty string")
    return value


def _require_reason(value: object) -> None:
    if type(value) is not str or len(value) > _MAX_REASON_LENGTH:
        raise ValueError(
            f"reason must be a string no longer than {_MAX_REASON_LENGTH} characters"
        )


__all__ = [
    "CompletionAuthorityResult",
    "CompletionAuthorityStatus",
    "CompletionDecisionReader",
    "CompletionGate",
    "CompletionGateAuthorityPolicy",
    "CompletionGateResult",
    "CompletionGateStatus",
    "CompletionGoalSpecReader",
    "CompletionTaskProjection",
    "FailClosedCompletionAuthorityPolicy",
]
