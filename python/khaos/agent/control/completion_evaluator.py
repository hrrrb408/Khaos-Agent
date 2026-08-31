"""Pure deterministic evaluation of structured completion facts.

M7.1.5 turns a validated GoalSpec and structured assessment facts into one
immutable ``CompletionDecision``.  This module deliberately has no database,
AgentLoop, TaskStatus projection, verification authority, or model dependency.
The later Completion Gate owns lifecycle and authority decisions.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Final

from khaos.agent.control.completion import (
    AssessmentStatus,
    CompletionDecision,
    CompletionDecisionValidationError,
    CompletionEvidenceRef,
    CompletionIssue,
    CompletionIssueCode,
    CompletionOutcome,
    CriterionAssessment,
    RequirementAssessment,
)
from khaos.agent.control.goal import GoalSpec
from khaos.agent.control.state import AgentCognitiveState

_MAX_ID_LENGTH = 512


class CompletionEvaluationInputError(ValueError):
    """Raised when evaluator input is malformed, stale, or inconsistent."""


class CompletionConstraintCode(str, Enum):
    """Negative-only external signals that can narrow completion outcomes."""

    PLAN_INCOMPLETE = "plan_incomplete"
    VERIFICATION_MISSING = "verification_missing"
    VERIFICATION_FAILED = "verification_failed"
    EXTERNAL_BLOCKER = "external_blocker"
    UNRECOVERABLE_FAILURE = "unrecoverable_failure"


@dataclass(frozen=True, slots=True)
class CompletionEvaluationSnapshot:
    """Immutable task facts captured for one evaluation attempt.

    The snapshot binds a decision to the GoalSpec identity, cognitive CAS
    version, task lifecycle status, and optional workspace projection that
    were observed by the caller.  It is input data, not lifecycle authority.
    """

    task_id: str
    goal_spec_id: str
    goal_spec_digest: str
    cognitive_state: AgentCognitiveState
    control_state_version: int
    task_status: str
    workspace_id: str | None

    def __post_init__(self) -> None:
        _require_text(self.task_id, label="task_id")
        _require_text(self.goal_spec_id, label="goal_spec_id")
        _require_text(self.goal_spec_digest, label="goal_spec_digest")
        if type(self.cognitive_state) is not AgentCognitiveState:
            raise CompletionEvaluationInputError(
                "cognitive_state must be an AgentCognitiveState value"
            )
        if (
            type(self.control_state_version) is not int
            or self.control_state_version < 0
        ):
            raise CompletionEvaluationInputError(
                "control_state_version must be a non-negative integer"
            )
        _require_text(self.task_status, label="task_status")
        if self.workspace_id is not None:
            _require_text(self.workspace_id, label="workspace_id")


@dataclass(frozen=True, slots=True)
class CompletionConstraint:
    """One typed negative signal supplied by a downstream control service.

    There are intentionally no positive constraint codes.  A constraint may
    only add a blocking/replanning issue; it cannot grant completion
    authority or make an evidence reference trusted.
    """

    code: CompletionConstraintCode
    subject_id: str | None = None
    evidence: tuple[CompletionEvidenceRef, ...] = ()

    def __post_init__(self) -> None:
        if type(self.code) is not CompletionConstraintCode:
            raise CompletionEvaluationInputError(
                "code must be a CompletionConstraintCode value"
            )
        if self.subject_id is not None:
            _require_text(self.subject_id, label="subject_id")
        _require_evidence_tuple(self.evidence, label="evidence")


_CONSTRAINT_ISSUE_CODES: Final[
    Mapping[CompletionConstraintCode, CompletionIssueCode]
] = MappingProxyType(
    {
        CompletionConstraintCode.PLAN_INCOMPLETE: CompletionIssueCode.PLAN_INCOMPLETE,
        CompletionConstraintCode.VERIFICATION_MISSING: CompletionIssueCode.VERIFICATION_MISSING,
        CompletionConstraintCode.VERIFICATION_FAILED: CompletionIssueCode.VERIFICATION_FAILED,
        CompletionConstraintCode.EXTERNAL_BLOCKER: CompletionIssueCode.EXTERNAL_BLOCKER,
        CompletionConstraintCode.UNRECOVERABLE_FAILURE: CompletionIssueCode.UNRECOVERABLE_FAILURE,
    }
)

_CONSTRAINT_SUMMARIES: Final[
    Mapping[CompletionConstraintCode, str]
] = MappingProxyType(
    {
        CompletionConstraintCode.PLAN_INCOMPLETE: "Required plan work is incomplete.",
        CompletionConstraintCode.VERIFICATION_MISSING: "Required verification evidence is missing.",
        CompletionConstraintCode.VERIFICATION_FAILED: "Required verification has failed.",
        CompletionConstraintCode.EXTERNAL_BLOCKER: "An external blocker remains unresolved.",
        CompletionConstraintCode.UNRECOVERABLE_FAILURE: "An unrecoverable failure remains unresolved.",
    }
)

_REPLAN_CONSTRAINTS: Final[frozenset[CompletionConstraintCode]] = frozenset(
    {
        CompletionConstraintCode.PLAN_INCOMPLETE,
        CompletionConstraintCode.VERIFICATION_MISSING,
        CompletionConstraintCode.VERIFICATION_FAILED,
    }
)


def _require_text(value: object, *, label: str) -> str:
    if type(value) is not str or not value:
        raise CompletionEvaluationInputError(
            f"{label} must be a non-empty string"
        )
    if len(value) > _MAX_ID_LENGTH:
        raise CompletionEvaluationInputError(
            f"{label} exceeds the maximum length of {_MAX_ID_LENGTH}"
        )
    return value


def _require_evidence_tuple(
    value: object, *, label: str
) -> tuple[CompletionEvidenceRef, ...]:
    if type(value) is not tuple:
        raise CompletionEvaluationInputError(f"{label} must be a tuple")
    if any(type(item) is not CompletionEvidenceRef for item in value):
        raise CompletionEvaluationInputError(
            f"{label} must contain only CompletionEvidenceRef values"
        )
    return value


def _evidence_sort_key(ref: CompletionEvidenceRef) -> tuple[str, str, str]:
    return (ref.kind.value, ref.ref_id, ref.digest or "")


def _normalize_evidence(
    value: tuple[CompletionEvidenceRef, ...],
) -> tuple[CompletionEvidenceRef, ...]:
    _require_evidence_tuple(value, label="evidence")
    return tuple(sorted(value, key=_evidence_sort_key))


def _normalize_requirement_assessments(
    values: tuple[RequirementAssessment, ...],
    *,
    goal_spec: GoalSpec,
) -> dict[str, RequirementAssessment]:
    if type(values) is not tuple:
        raise CompletionEvaluationInputError(
            "requirement_assessments must be a tuple"
        )
    known_ids = {item.requirement_id for item in goal_spec.requirements}
    normalized: dict[str, RequirementAssessment] = {}
    for item in values:
        if type(item) is not RequirementAssessment:
            raise CompletionEvaluationInputError(
                "requirement_assessments must contain only RequirementAssessment values"
            )
        if item.requirement_id not in known_ids:
            raise CompletionEvaluationInputError(
                f"unknown requirement_id: {item.requirement_id!r}"
            )
        if item.requirement_id in normalized:
            raise CompletionEvaluationInputError(
                f"duplicate requirement_id: {item.requirement_id!r}"
            )
        normalized[item.requirement_id] = RequirementAssessment(
            requirement_id=item.requirement_id,
            status=item.status,
            evidence=_normalize_evidence(item.evidence),
        )
    return normalized


def _normalize_criterion_assessments(
    values: tuple[CriterionAssessment, ...],
    *,
    goal_spec: GoalSpec,
) -> dict[str, CriterionAssessment]:
    if type(values) is not tuple:
        raise CompletionEvaluationInputError(
            "criterion_assessments must be a tuple"
        )
    known_ids = {item.criterion_id for item in goal_spec.acceptance_criteria}
    normalized: dict[str, CriterionAssessment] = {}
    for item in values:
        if type(item) is not CriterionAssessment:
            raise CompletionEvaluationInputError(
                "criterion_assessments must contain only CriterionAssessment values"
            )
        if item.criterion_id not in known_ids:
            raise CompletionEvaluationInputError(
                f"unknown criterion_id: {item.criterion_id!r}"
            )
        if item.criterion_id in normalized:
            raise CompletionEvaluationInputError(
                f"duplicate criterion_id: {item.criterion_id!r}"
            )
        normalized[item.criterion_id] = CriterionAssessment(
            criterion_id=item.criterion_id,
            status=item.status,
            evidence=_normalize_evidence(item.evidence),
        )
    return normalized


def _normalize_constraints(
    values: tuple[CompletionConstraint, ...],
) -> tuple[CompletionConstraint, ...]:
    if type(values) is not tuple:
        raise CompletionEvaluationInputError("constraints must be a tuple")
    normalized_values: list[CompletionConstraint] = []
    for item in values:
        if type(item) is not CompletionConstraint:
            raise CompletionEvaluationInputError(
                "constraints must contain only CompletionConstraint values"
            )
        normalized_values.append(
            CompletionConstraint(
                code=item.code,
                subject_id=item.subject_id,
                evidence=_normalize_evidence(item.evidence),
            )
        )
    normalized = tuple(normalized_values)
    return tuple(sorted(normalized, key=_constraint_sort_key))


def _constraint_sort_key(
    constraint: CompletionConstraint,
) -> tuple[str, str, tuple[tuple[str, str, str], ...]]:
    return (
        constraint.code.value,
        constraint.subject_id or "",
        tuple(_evidence_sort_key(ref) for ref in constraint.evidence),
    )


def _issue_sort_key(
    issue: CompletionIssue,
) -> tuple[str, str, str, tuple[tuple[str, str, str], ...]]:
    return (
        issue.code.value,
        issue.subject_id or "",
        issue.summary,
        tuple(_evidence_sort_key(ref) for ref in issue.evidence),
    )


def _assessment_issue(
    *,
    code: CompletionIssueCode,
    subject_id: str,
    evidence: tuple[CompletionEvidenceRef, ...],
    summary: str,
) -> CompletionIssue:
    return CompletionIssue(
        code=code,
        subject_id=subject_id,
        evidence=_normalize_evidence(evidence),
        summary=summary,
    )


class CompletionEvaluator:
    """Evaluate structured completion facts without persistence or authority."""

    @staticmethod
    def evaluate(
        *,
        decision_id: str,
        goal_spec: GoalSpec,
        snapshot: CompletionEvaluationSnapshot,
        requirement_assessments: tuple[RequirementAssessment, ...] = (),
        criterion_assessments: tuple[CriterionAssessment, ...] = (),
        evidence: tuple[CompletionEvidenceRef, ...] = (),
        constraints: tuple[CompletionConstraint, ...] = (),
    ) -> CompletionDecision:
        """Create a deterministic CompletionDecision from structured facts.

        Required declarations come only from ``goal_spec``.  Missing required
        assessments are synthesized as ``UNKNOWN``; optional missing
        assessments remain omitted.  External constraints are negative-only,
        and outcome precedence is ``FAILED > BLOCKED > REPLAN > COMPLETE``.
        The returned ``COMPLETE`` value is a semantic evaluation result, not a
        task-lifecycle transition or execution authorization.
        """
        if type(goal_spec) is not GoalSpec:
            raise CompletionEvaluationInputError(
                "goal_spec must be a GoalSpec value"
            )
        if type(snapshot) is not CompletionEvaluationSnapshot:
            raise CompletionEvaluationInputError(
                "snapshot must be a CompletionEvaluationSnapshot value"
            )
        _require_text(decision_id, label="decision_id")
        if snapshot.goal_spec_id != goal_spec.goal_spec_id:
            raise CompletionEvaluationInputError(
                "snapshot GoalSpec identity does not match goal_spec"
            )
        if snapshot.goal_spec_digest != goal_spec.semantic_digest:
            raise CompletionEvaluationInputError(
                "snapshot GoalSpec digest does not match goal_spec"
            )

        normalized_requirements = _normalize_requirement_assessments(
            requirement_assessments,
            goal_spec=goal_spec,
        )
        normalized_criteria = _normalize_criterion_assessments(
            criterion_assessments,
            goal_spec=goal_spec,
        )
        normalized_evidence = _normalize_evidence(evidence)
        normalized_constraints = _normalize_constraints(constraints)

        output_requirements: list[RequirementAssessment] = []
        output_criteria: list[CriterionAssessment] = []
        issues: list[CompletionIssue] = []
        required_gap = False

        for requirement in sorted(
            goal_spec.requirements,
            key=lambda item: item.requirement_id,
        ):
            assessment = normalized_requirements.get(requirement.requirement_id)
            if assessment is None:
                if not requirement.required:
                    continue
                assessment = RequirementAssessment(
                    requirement_id=requirement.requirement_id,
                    status=AssessmentStatus.UNKNOWN,
                )
                issues.append(
                    _assessment_issue(
                        code=CompletionIssueCode.REQUIREMENT_UNKNOWN,
                        subject_id=requirement.requirement_id,
                        evidence=(),
                        summary="Required requirement has no assessment.",
                    )
                )
            output_requirements.append(assessment)
            if requirement.required and assessment.status is not AssessmentStatus.SATISFIED:
                required_gap = True
                if assessment.status is AssessmentStatus.UNSATISFIED:
                    issues.append(
                        _assessment_issue(
                            code=CompletionIssueCode.REQUIREMENT_UNSATISFIED,
                            subject_id=requirement.requirement_id,
                            evidence=assessment.evidence,
                            summary="Required requirement is unsatisfied.",
                        )
                    )
                elif assessment.status is AssessmentStatus.UNKNOWN and (
                    normalized_requirements.get(requirement.requirement_id)
                    is not None
                ):
                    issues.append(
                        _assessment_issue(
                            code=CompletionIssueCode.REQUIREMENT_UNKNOWN,
                            subject_id=requirement.requirement_id,
                            evidence=assessment.evidence,
                            summary="Required requirement assessment is unknown.",
                        )
                    )

        for criterion in sorted(
            goal_spec.acceptance_criteria,
            key=lambda item: item.criterion_id,
        ):
            assessment = normalized_criteria.get(criterion.criterion_id)
            if assessment is None:
                if not criterion.required:
                    continue
                assessment = CriterionAssessment(
                    criterion_id=criterion.criterion_id,
                    status=AssessmentStatus.UNKNOWN,
                )
                issues.append(
                    _assessment_issue(
                        code=CompletionIssueCode.CRITERION_UNKNOWN,
                        subject_id=criterion.criterion_id,
                        evidence=(),
                        summary="Required acceptance criterion has no assessment.",
                    )
                )
            output_criteria.append(assessment)
            if criterion.required and assessment.status is not AssessmentStatus.SATISFIED:
                required_gap = True
                if assessment.status is AssessmentStatus.UNSATISFIED:
                    issues.append(
                        _assessment_issue(
                            code=CompletionIssueCode.CRITERION_UNSATISFIED,
                            subject_id=criterion.criterion_id,
                            evidence=assessment.evidence,
                            summary="Required acceptance criterion is unsatisfied.",
                        )
                    )
                elif assessment.status is AssessmentStatus.UNKNOWN and (
                    normalized_criteria.get(criterion.criterion_id) is not None
                ):
                    issues.append(
                        _assessment_issue(
                            code=CompletionIssueCode.CRITERION_UNKNOWN,
                            subject_id=criterion.criterion_id,
                            evidence=assessment.evidence,
                            summary="Required acceptance criterion assessment is unknown.",
                        )
                    )

        for constraint in normalized_constraints:
            issues.append(
                CompletionIssue(
                    code=_CONSTRAINT_ISSUE_CODES[constraint.code],
                    subject_id=constraint.subject_id,
                    evidence=constraint.evidence,
                    summary=_CONSTRAINT_SUMMARIES[constraint.code],
                )
            )

        if any(
            item.code is CompletionConstraintCode.UNRECOVERABLE_FAILURE
            for item in normalized_constraints
        ):
            outcome = CompletionOutcome.FAILED
        elif any(
            item.code is CompletionConstraintCode.EXTERNAL_BLOCKER
            for item in normalized_constraints
        ):
            outcome = CompletionOutcome.BLOCKED
        elif required_gap or any(
            item.code in _REPLAN_CONSTRAINTS for item in normalized_constraints
        ):
            outcome = CompletionOutcome.REPLAN
        else:
            outcome = CompletionOutcome.COMPLETE

        try:
            return CompletionDecision.from_parts(
                decision_id=decision_id,
                task_id=snapshot.task_id,
                goal_spec_id=snapshot.goal_spec_id,
                goal_spec_digest=snapshot.goal_spec_digest,
                cognitive_state=snapshot.cognitive_state,
                control_state_version=snapshot.control_state_version,
                task_status_at_evaluation=snapshot.task_status,
                workspace_id=snapshot.workspace_id,
                outcome=outcome,
                requirement_assessments=tuple(output_requirements),
                criterion_assessments=tuple(output_criteria),
                evidence=normalized_evidence,
                issues=tuple(sorted(issues, key=_issue_sort_key)),
            )
        except (CompletionDecisionValidationError, TypeError, ValueError) as exc:
            raise CompletionEvaluationInputError(
                "evaluation facts cannot produce a valid CompletionDecision"
            ) from exc


__all__ = [
    "CompletionConstraint",
    "CompletionConstraintCode",
    "CompletionEvaluationInputError",
    "CompletionEvaluationSnapshot",
    "CompletionEvaluator",
]
