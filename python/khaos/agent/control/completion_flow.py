"""Typed control flow for a coding-task completion proposal.

This module is the small orchestration seam between ``AgentLoop`` and the
pure ``CompletionEvaluator``.  It loads canonical durable facts, captures a
current task snapshot, collects only structured completion facts, evaluates
them, and appends the resulting passive decision.  It does not project any
outcome onto ``TaskStatus`` and it does not grant execution or verification
authority.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from enum import Enum
from typing import Protocol

from khaos.agent.control.completion import (
    CompletionDecision,
    CompletionEvidenceRef,
    CriterionAssessment,
    RequirementAssessment,
)
from khaos.agent.control.completion_evaluator import (
    CompletionConstraint,
    CompletionEvaluationInputError,
    CompletionEvaluationSnapshot,
    CompletionEvaluator,
)
from khaos.agent.control.completion_repository import (
    CompletionDecisionBindingError,
    CompletionDecisionConflictError,
    CompletionDecisionIntegrityError,
    CompletionDecisionRepositoryError,
    StoredCompletionDecision,
)
from khaos.agent.control.goal import GoalSpec
from khaos.agent.control.goal_repository import GoalSpecRepositoryError

logger = logging.getLogger(__name__)

_MAX_ID_LENGTH = 512
_MAX_REASON_LENGTH = 512


class CompletionProposalTrigger(str, Enum):
    """Closed set of control events that can request evaluation."""

    MODEL_END_TURN = "model_end_turn"


class CompletionProposalStatus(str, Enum):
    """Durable-flow result for one completion proposal."""

    RECORDED = "recorded"
    STALE = "stale"
    REJECTED = "rejected"
    ERROR = "error"


class VerificationFactStatus(str, Enum):
    """Projection status for one trusted-verification assessment.

    This is a data projection only.  It is not a verification authority
    result, a completion capability, or a TaskStatus transition.
    """

    SATISFIED = "satisfied"
    UNSATISFIED = "unsatisfied"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class VerificationCompletionFact:
    """Bounded completion input projected from current verification history."""

    assessment_id: str
    assessment_digest: str
    status: VerificationFactStatus
    evidence: tuple[CompletionEvidenceRef, ...] = ()

    def __post_init__(self) -> None:
        _require_id(self.assessment_id, label="assessment_id")
        _require_id(self.assessment_digest, label="assessment_digest")
        if type(self.status) is not VerificationFactStatus:
            raise ValueError("status must be a VerificationFactStatus")
        _require_typed_tuple(
            self.evidence,
            label="evidence",
            item_type=CompletionEvidenceRef,
        )


def _require_text(value: object, *, label: str, allow_empty: bool = False) -> str:
    if type(value) is not str or (not allow_empty and not value):
        suffix = "" if allow_empty else " and must not be empty"
        raise ValueError(f"{label} must be a string{suffix}")
    if len(value) > _MAX_REASON_LENGTH:
        raise ValueError(f"{label} exceeds the maximum length")
    return value


def _require_id(value: object, *, label: str) -> str:
    if type(value) is not str or not value:
        raise ValueError(f"{label} must be a non-empty string")
    if len(value) > _MAX_ID_LENGTH:
        raise ValueError(f"{label} exceeds the maximum length")
    return value


def _require_typed_tuple(
    value: object,
    *,
    label: str,
    item_type: type[object],
) -> None:
    if type(value) is not tuple:
        raise ValueError(f"{label} must be a tuple")
    if any(type(item) is not item_type for item in value):
        raise ValueError(f"{label} contains an invalid typed value")


@dataclass(frozen=True, slots=True)
class CompletionProposal:
    """One model turn request to evaluate the current coding task."""

    task_id: str
    turn_id: str
    attempt_id: str
    trigger: CompletionProposalTrigger

    def __post_init__(self) -> None:
        _require_id(self.task_id, label="task_id")
        _require_id(self.turn_id, label="turn_id")
        _require_id(self.attempt_id, label="attempt_id")
        if type(self.trigger) is not CompletionProposalTrigger:
            raise ValueError("trigger must be a CompletionProposalTrigger")


@dataclass(frozen=True, slots=True)
class CompletionFactBundle:
    """Structured facts supplied to the evaluator for one proposal.

    The default bundle is intentionally empty.  No assistant prose or model
    confidence is converted into a positive assessment by this contract.
    """

    requirement_assessments: tuple[RequirementAssessment, ...] = ()
    criterion_assessments: tuple[CriterionAssessment, ...] = ()
    evidence: tuple[CompletionEvidenceRef, ...] = ()
    constraints: tuple[CompletionConstraint, ...] = ()
    verification_facts: tuple[VerificationCompletionFact, ...] = ()

    def __post_init__(self) -> None:
        _require_typed_tuple(
            self.requirement_assessments,
            label="requirement_assessments",
            item_type=RequirementAssessment,
        )
        _require_typed_tuple(
            self.criterion_assessments,
            label="criterion_assessments",
            item_type=CriterionAssessment,
        )
        _require_typed_tuple(
            self.evidence,
            label="evidence",
            item_type=CompletionEvidenceRef,
        )
        _require_typed_tuple(
            self.constraints,
            label="constraints",
            item_type=CompletionConstraint,
        )
        _require_typed_tuple(
            self.verification_facts,
            label="verification_facts",
            item_type=VerificationCompletionFact,
        )


@dataclass(frozen=True, slots=True)
class CompletionProposalResult:
    """Passive result of evaluating and, when possible, appending a proposal."""

    status: CompletionProposalStatus
    decision: CompletionDecision | None
    decision_sequence: int | None
    reason: str = ""

    def __post_init__(self) -> None:
        if type(self.status) is not CompletionProposalStatus:
            raise ValueError("status must be a CompletionProposalStatus")
        if self.decision_sequence is not None and (
            type(self.decision_sequence) is not int or self.decision_sequence < 1
        ):
            raise ValueError("decision_sequence must be a positive integer or None")
        if self.status is CompletionProposalStatus.RECORDED:
            if type(self.decision) is not CompletionDecision:
                raise ValueError("recorded result requires a CompletionDecision")
            if self.decision_sequence is None:
                raise ValueError("recorded result requires a decision sequence")
        elif self.decision is not None or self.decision_sequence is not None:
            raise ValueError("non-recorded result cannot expose a decision")
        _require_text(self.reason, label="reason", allow_empty=True)


class CompletionFactProvider(Protocol):
    """Port for collecting typed facts without model-based interpretation."""

    async def collect(
        self,
        *,
        proposal: CompletionProposal,
        goal_spec: GoalSpec,
        snapshot: CompletionEvaluationSnapshot,
    ) -> CompletionFactBundle:
        """Return structured facts; never derive authority from assistant prose."""
        raise NotImplementedError


class EmptyCompletionFactProvider:
    """Conservative default provider that supplies no positive facts."""

    async def collect(
        self,
        *,
        proposal: CompletionProposal,
        goal_spec: GoalSpec,
        snapshot: CompletionEvaluationSnapshot,
    ) -> CompletionFactBundle:
        """Return an empty bundle so required facts become ``UNKNOWN``."""
        del proposal, goal_spec, snapshot
        return CompletionFactBundle()


class GoalSpecLoader(Protocol):
    """Owner-scoped canonical GoalSpec read required by the controller."""

    async def get_for_task(
        self,
        task_id: str,
        *,
        principal_id: str,
        project_id: str,
    ) -> GoalSpec | None:
        """Load a GoalSpec without falling back to task text or history."""
        raise NotImplementedError


class CompletionTaskSnapshotReader(Protocol):
    """Owner-scoped current task snapshot read required by the controller."""

    async def read_current_task_snapshot(
        self,
        task_id: str,
        *,
        principal_id: str,
        project_id: str,
        goal_spec: GoalSpec,
    ) -> CompletionEvaluationSnapshot | None:
        """Read physical task state and the existing workspace projection."""
        raise NotImplementedError


class CompletionDecisionStore(CompletionTaskSnapshotReader, Protocol):
    """Combined append/read port used by the default production composition."""

    async def append(
        self,
        decision: CompletionDecision,
        *,
        principal_id: str,
        project_id: str,
    ) -> StoredCompletionDecision:
        """Recheck the current binding and append the immutable decision."""
        raise NotImplementedError


class CompletionProposalController:
    """Orchestrate one owner-bound proposal without lifecycle projection."""

    def __init__(
        self,
        *,
        goal_spec_repository: GoalSpecLoader,
        decision_repository: CompletionDecisionStore,
        principal_id: str,
        project_id: str,
        fact_provider: CompletionFactProvider | None = None,
        evaluator: CompletionEvaluator | None = None,
        snapshot_reader: CompletionTaskSnapshotReader | None = None,
    ) -> None:
        _require_id(principal_id, label="principal_id")
        if type(project_id) is not str:
            raise ValueError("project_id must be a string")
        self._goal_spec_repository = goal_spec_repository
        self._decision_repository = decision_repository
        self._snapshot_reader = (
            decision_repository if snapshot_reader is None else snapshot_reader
        )
        self._fact_provider = (
            EmptyCompletionFactProvider() if fact_provider is None else fact_provider
        )
        self._evaluator = CompletionEvaluator() if evaluator is None else evaluator
        self._principal_id = principal_id
        self._project_id = project_id

    async def propose(
        self,
        proposal: CompletionProposal,
    ) -> CompletionProposalResult:
        """Load, evaluate, and append one fresh proposal attempt.

        A stale append is returned as ``STALE``.  The controller never
        reuses stale facts, retries with the same decision, or projects any
        evaluator outcome onto ``TaskStatus``.
        """
        if type(proposal) is not CompletionProposal:
            raise TypeError("proposal must be a CompletionProposal")

        try:
            goal_spec = await self._goal_spec_repository.get_for_task(
                proposal.task_id,
                principal_id=self._principal_id,
                project_id=self._project_id,
            )
        except GoalSpecRepositoryError:
            logger.warning("completion proposal GoalSpec read failed")
            return _result(
                CompletionProposalStatus.ERROR,
                "canonical GoalSpec could not be loaded.",
            )
        except Exception as exc:  # noqa: BLE001 - control flow fails closed
            logger.warning(
                "completion proposal GoalSpec read failed: %s", type(exc).__name__
            )
            return _result(
                CompletionProposalStatus.ERROR,
                "canonical GoalSpec could not be loaded.",
            )
        if goal_spec is None:
            return _result(
                CompletionProposalStatus.REJECTED,
                "task or GoalSpec is unavailable in the owner scope.",
            )
        if type(goal_spec) is not GoalSpec:
            logger.error("completion proposal loader returned an invalid GoalSpec")
            return _result(
                CompletionProposalStatus.ERROR,
                "canonical GoalSpec failed type validation.",
            )

        try:
            snapshot = await self._snapshot_reader.read_current_task_snapshot(
                proposal.task_id,
                principal_id=self._principal_id,
                project_id=self._project_id,
                goal_spec=goal_spec,
            )
        except CompletionDecisionIntegrityError:
            logger.warning("completion proposal task snapshot failed integrity")
            return _result(
                CompletionProposalStatus.ERROR,
                "current task snapshot failed integrity validation.",
            )
        except Exception as exc:  # noqa: BLE001 - control flow fails closed
            logger.warning(
                "completion proposal task snapshot failed: %s", type(exc).__name__
            )
            return _result(
                CompletionProposalStatus.ERROR,
                "current task snapshot could not be read.",
            )
        if snapshot is None:
            return _result(
                CompletionProposalStatus.REJECTED,
                "task is unavailable in the owner scope.",
            )
        if type(snapshot) is not CompletionEvaluationSnapshot:
            logger.error("completion proposal reader returned an invalid snapshot")
            return _result(
                CompletionProposalStatus.ERROR,
                "current task snapshot failed type validation.",
            )

        try:
            facts = await self._fact_provider.collect(
                proposal=proposal,
                goal_spec=goal_spec,
                snapshot=snapshot,
            )
        except Exception as exc:  # noqa: BLE001 - provider failures are non-authoritative
            logger.warning(
                "completion fact provider failed: %s", type(exc).__name__
            )
            return _result(
                CompletionProposalStatus.ERROR,
                "completion facts could not be collected.",
            )
        if type(facts) is not CompletionFactBundle:
            return _result(
                CompletionProposalStatus.ERROR,
                "completion fact provider returned an invalid bundle.",
            )

        try:
            decision = self._evaluator.evaluate(
                decision_id=uuid.uuid4().hex,
                goal_spec=goal_spec,
                snapshot=snapshot,
                requirement_assessments=facts.requirement_assessments,
                criterion_assessments=facts.criterion_assessments,
                evidence=facts.evidence,
                constraints=facts.constraints,
            )
        except CompletionEvaluationInputError:
            logger.warning("completion proposal facts failed evaluator validation")
            return _result(
                CompletionProposalStatus.REJECTED,
                "completion facts failed validation.",
            )
        except Exception as exc:  # noqa: BLE001 - evaluator failures fail closed
            logger.warning(
                "completion evaluator failed: %s", type(exc).__name__
            )
            return _result(
                CompletionProposalStatus.ERROR,
                "completion evaluation could not be produced.",
            )

        try:
            stored = await self._decision_repository.append(
                decision,
                principal_id=self._principal_id,
                project_id=self._project_id,
            )
        except CompletionDecisionBindingError:
            logger.info("completion proposal append rejected as stale")
            return _result(
                CompletionProposalStatus.STALE,
                "current task snapshot changed before append.",
            )
        except CompletionDecisionConflictError:
            logger.warning("completion proposal decision identity conflicted")
            return _result(
                CompletionProposalStatus.ERROR,
                "completion decision identity conflicted.",
            )
        except CompletionDecisionIntegrityError:
            logger.warning("completion proposal append failed integrity")
            return _result(
                CompletionProposalStatus.ERROR,
                "completion decision failed integrity validation.",
            )
        except CompletionDecisionRepositoryError:
            logger.warning("completion proposal append failed repository validation")
            return _result(
                CompletionProposalStatus.ERROR,
                "completion decision could not be recorded.",
            )
        except Exception as exc:  # noqa: BLE001 - append failures fail closed
            logger.warning(
                "completion proposal append failed: %s", type(exc).__name__
            )
            return _result(
                CompletionProposalStatus.ERROR,
                "completion decision could not be recorded.",
            )

        if (
            type(stored) is not StoredCompletionDecision
            or type(stored.decision) is not CompletionDecision
            or stored.decision.decision_id != decision.decision_id
            or stored.decision.decision_digest != decision.decision_digest
            or stored.decision.task_id != proposal.task_id
            or stored.principal_id != self._principal_id
            or stored.project_id != self._project_id
            or type(stored.decision_sequence) is not int
            or stored.decision_sequence < 1
        ):
            logger.error("completion repository returned an inconsistent append result")
            return _result(
                CompletionProposalStatus.ERROR,
                "completion decision append result failed integrity validation.",
            )
        return CompletionProposalResult(
            status=CompletionProposalStatus.RECORDED,
            decision=decision,
            decision_sequence=stored.decision_sequence,
        )


def _result(status: CompletionProposalStatus, reason: str) -> CompletionProposalResult:
    return CompletionProposalResult(
        status=status,
        decision=None,
        decision_sequence=None,
        reason=reason,
    )


__all__ = [
    "CompletionDecisionStore",
    "CompletionFactBundle",
    "CompletionFactProvider",
    "CompletionProposal",
    "CompletionProposalController",
    "CompletionProposalResult",
    "CompletionProposalStatus",
    "CompletionProposalTrigger",
    "CompletionTaskSnapshotReader",
    "EmptyCompletionFactProvider",
    "GoalSpecLoader",
    "VerificationCompletionFact",
    "VerificationFactStatus",
]
