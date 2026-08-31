"""M7.1.5 deterministic CompletionEvaluator contract tests."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest
from khaos.agent.control.completion import (
    AssessmentStatus,
    CompletionEvidenceKind,
    CompletionEvidenceRef,
    CompletionIssueCode,
    CompletionOutcome,
    CriterionAssessment,
    RequirementAssessment,
)
from khaos.agent.control.completion_evaluator import (
    CompletionConstraint,
    CompletionConstraintCode,
    CompletionEvaluationInputError,
    CompletionEvaluationSnapshot,
    CompletionEvaluator,
)
from khaos.agent.control.goal import (
    AcceptanceCriterion,
    GoalRequirement,
    GoalSource,
    GoalSpec,
)
from khaos.agent.control.state import AgentCognitiveState


def _goal_spec(
    *,
    requirements: tuple[GoalRequirement, ...] = (),
    criteria: tuple[AcceptanceCriterion, ...] = (),
) -> GoalSpec:
    return GoalSpec.from_parts(
        goal_spec_id="goal-1",
        raw_goal="完成结构化目标",
        requirements=requirements,
        acceptance_criteria=criteria,
    )


def _requirement(
    requirement_id: str,
    *,
    required: bool = True,
) -> GoalRequirement:
    return GoalRequirement(
        requirement_id=requirement_id,
        description=f"要求 {requirement_id}",
        required=required,
        source=GoalSource.EXPLICIT_USER,
    )


def _criterion(
    criterion_id: str,
    *,
    required: bool = True,
) -> AcceptanceCriterion:
    return AcceptanceCriterion(
        criterion_id=criterion_id,
        description=f"验收 {criterion_id}",
        required=required,
        source=GoalSource.EXPLICIT_USER,
    )


def _snapshot(spec: GoalSpec, **overrides: object) -> CompletionEvaluationSnapshot:
    values: dict[str, object] = {
        "task_id": "task-1",
        "goal_spec_id": spec.goal_spec_id,
        "goal_spec_digest": spec.semantic_digest,
        "cognitive_state": AgentCognitiveState.REVIEWING,
        "control_state_version": 4,
        "task_status": "running",
        "workspace_id": "workspace-1",
    }
    values.update(overrides)
    return CompletionEvaluationSnapshot(**values)  # type: ignore[arg-type]


def _satisfied(requirement_id: str) -> RequirementAssessment:
    return RequirementAssessment(requirement_id, AssessmentStatus.SATISFIED)


def _criterion_satisfied(criterion_id: str) -> CriterionAssessment:
    return CriterionAssessment(criterion_id, AssessmentStatus.SATISFIED)


def _evaluate(
    spec: GoalSpec,
    *,
    decision_id: str = "decision-1",
    snapshot: CompletionEvaluationSnapshot | None = None,
    requirement_assessments: tuple[RequirementAssessment, ...] = (),
    criterion_assessments: tuple[CriterionAssessment, ...] = (),
    evidence: tuple[CompletionEvidenceRef, ...] = (),
    constraints: tuple[CompletionConstraint, ...] = (),
):
    return CompletionEvaluator.evaluate(
        decision_id=decision_id,
        goal_spec=spec,
        snapshot=_snapshot(spec) if snapshot is None else snapshot,
        requirement_assessments=requirement_assessments,
        criterion_assessments=criterion_assessments,
        evidence=evidence,
        constraints=constraints,
    )


def test_required_satisfied_yields_complete_from_goal_spec_semantics() -> None:
    spec = _goal_spec(
        requirements=(_requirement("r-2"), _requirement("r-1")),
        criteria=(_criterion("c-1"),),
    )

    decision = _evaluate(
        spec,
        requirement_assessments=(_satisfied("r-1"), _satisfied("r-2")),
        criterion_assessments=(_criterion_satisfied("c-1"),),
    )

    assert decision.outcome is CompletionOutcome.COMPLETE
    assert [item.requirement_id for item in decision.requirement_assessments] == [
        "r-1",
        "r-2",
    ]
    assert [item.criterion_id for item in decision.criterion_assessments] == ["c-1"]
    assert decision.issues == ()
    assert decision.task_status_at_evaluation == "running"


def test_missing_required_assessment_is_synthesized_as_unknown() -> None:
    spec = _goal_spec(
        requirements=(
            _requirement("r-1"),
            _requirement("r-2"),
            _requirement("optional", required=False),
        )
    )

    decision = _evaluate(spec, requirement_assessments=(_satisfied("r-1"),))

    assert decision.outcome is CompletionOutcome.REPLAN
    assert [item.requirement_id for item in decision.requirement_assessments] == [
        "r-1",
        "r-2",
    ]
    synthesized = decision.requirement_assessments[1]
    assert synthesized.status is AssessmentStatus.UNKNOWN
    assert [issue.code for issue in decision.issues] == [
        CompletionIssueCode.REQUIREMENT_UNKNOWN
    ]
    assert decision.issues[0].subject_id == "r-2"


@pytest.mark.parametrize(
    ("status", "issue_code"),
    [
        (AssessmentStatus.UNSATISFIED, CompletionIssueCode.REQUIREMENT_UNSATISFIED),
        (AssessmentStatus.UNKNOWN, CompletionIssueCode.REQUIREMENT_UNKNOWN),
    ],
)
def test_required_non_satisfied_assessment_replans(
    status: AssessmentStatus,
    issue_code: CompletionIssueCode,
) -> None:
    spec = _goal_spec(requirements=(_requirement("r-1"),))

    decision = _evaluate(
        spec,
        requirement_assessments=(RequirementAssessment("r-1", status),),
    )

    assert decision.outcome is CompletionOutcome.REPLAN
    assert decision.requirement_assessments[0].status is status
    assert [issue.code for issue in decision.issues] == [issue_code]


def test_missing_required_criterion_is_synthesized_as_unknown() -> None:
    spec = _goal_spec(criteria=(_criterion("c-1"),))

    decision = _evaluate(spec)

    assert decision.outcome is CompletionOutcome.REPLAN
    assert decision.criterion_assessments == (
        CriterionAssessment("c-1", AssessmentStatus.UNKNOWN),
    )
    assert decision.issues[0].code is CompletionIssueCode.CRITERION_UNKNOWN
    assert decision.issues[0].subject_id == "c-1"


def test_optional_missing_or_unsatisfied_does_not_block_completion() -> None:
    spec = _goal_spec(
        requirements=(_requirement("required"), _requirement("optional", required=False)),
        criteria=(_criterion("optional-criterion", required=False),),
    )

    missing = _evaluate(
        spec,
        requirement_assessments=(_satisfied("required"),),
    )
    unsatisfied = _evaluate(
        spec,
        requirement_assessments=(
            _satisfied("required"),
            RequirementAssessment("optional", AssessmentStatus.UNSATISFIED),
        ),
        criterion_assessments=(
            CriterionAssessment("optional-criterion", AssessmentStatus.UNSATISFIED),
        ),
    )

    assert missing.outcome is CompletionOutcome.COMPLETE
    assert missing.requirement_assessments == (_satisfied("required"),)
    assert unsatisfied.outcome is CompletionOutcome.COMPLETE
    assert unsatisfied.issues == ()
    assert next(
        item
        for item in unsatisfied.requirement_assessments
        if item.requirement_id == "optional"
    ).status is AssessmentStatus.UNSATISFIED


def test_unknown_requirement_id_is_input_error() -> None:
    spec = _goal_spec(requirements=(_requirement("known"),))

    with pytest.raises(CompletionEvaluationInputError, match="unknown requirement_id"):
        _evaluate(
            spec,
            requirement_assessments=(
                RequirementAssessment("unknown", AssessmentStatus.SATISFIED),
            ),
        )


def test_unknown_criterion_id_is_input_error() -> None:
    spec = _goal_spec(criteria=(_criterion("known"),))

    with pytest.raises(CompletionEvaluationInputError, match="unknown criterion_id"):
        _evaluate(
            spec,
            criterion_assessments=(
                CriterionAssessment("unknown", AssessmentStatus.SATISFIED),
            ),
        )


@pytest.mark.parametrize(
    ("constraint_code", "expected_outcome", "expected_issue"),
    [
        (
            CompletionConstraintCode.PLAN_INCOMPLETE,
            CompletionOutcome.REPLAN,
            CompletionIssueCode.PLAN_INCOMPLETE,
        ),
        (
            CompletionConstraintCode.VERIFICATION_MISSING,
            CompletionOutcome.REPLAN,
            CompletionIssueCode.VERIFICATION_MISSING,
        ),
        (
            CompletionConstraintCode.VERIFICATION_FAILED,
            CompletionOutcome.REPLAN,
            CompletionIssueCode.VERIFICATION_FAILED,
        ),
        (
            CompletionConstraintCode.EXTERNAL_BLOCKER,
            CompletionOutcome.BLOCKED,
            CompletionIssueCode.EXTERNAL_BLOCKER,
        ),
        (
            CompletionConstraintCode.UNRECOVERABLE_FAILURE,
            CompletionOutcome.FAILED,
            CompletionIssueCode.UNRECOVERABLE_FAILURE,
        ),
    ],
)
def test_negative_constraint_maps_to_issue_and_narrows_outcome(
    constraint_code: CompletionConstraintCode,
    expected_outcome: CompletionOutcome,
    expected_issue: CompletionIssueCode,
) -> None:
    spec = _goal_spec(requirements=(_requirement("r-1"),))
    reference = CompletionEvidenceRef(CompletionEvidenceKind.VERIFICATION_RUN, "run-1")

    decision = _evaluate(
        spec,
        requirement_assessments=(_satisfied("r-1"),),
        constraints=(
            CompletionConstraint(
                code=constraint_code,
                subject_id="subject-1",
                evidence=(reference,),
            ),
        ),
    )

    assert decision.outcome is expected_outcome
    assert [issue.code for issue in decision.issues] == [expected_issue]
    assert decision.issues[0].evidence == (reference,)


def test_constraint_precedence_keeps_all_issues() -> None:
    spec = _goal_spec(requirements=(_requirement("r-1"),))
    decision = _evaluate(
        spec,
        requirement_assessments=(
            RequirementAssessment("r-1", AssessmentStatus.UNSATISFIED),
        ),
        constraints=(
            CompletionConstraint(CompletionConstraintCode.PLAN_INCOMPLETE),
            CompletionConstraint(CompletionConstraintCode.EXTERNAL_BLOCKER),
            CompletionConstraint(CompletionConstraintCode.UNRECOVERABLE_FAILURE),
        ),
    )

    assert decision.outcome is CompletionOutcome.FAILED
    assert {
        issue.code for issue in decision.issues
    } == {
        CompletionIssueCode.REQUIREMENT_UNSATISFIED,
        CompletionIssueCode.PLAN_INCOMPLETE,
        CompletionIssueCode.EXTERNAL_BLOCKER,
        CompletionIssueCode.UNRECOVERABLE_FAILURE,
    }


def test_blocker_precedes_replan_but_replan_issues_are_retained() -> None:
    spec = _goal_spec(requirements=(_requirement("r-1"),))
    decision = _evaluate(
        spec,
        requirement_assessments=(
            RequirementAssessment("r-1", AssessmentStatus.UNKNOWN),
        ),
        constraints=(
            CompletionConstraint(CompletionConstraintCode.PLAN_INCOMPLETE),
            CompletionConstraint(CompletionConstraintCode.EXTERNAL_BLOCKER),
        ),
    )

    assert decision.outcome is CompletionOutcome.BLOCKED
    assert {
        issue.code for issue in decision.issues
    } == {
        CompletionIssueCode.REQUIREMENT_UNKNOWN,
        CompletionIssueCode.PLAN_INCOMPLETE,
        CompletionIssueCode.EXTERNAL_BLOCKER,
    }


def test_constraint_vocabulary_is_negative_only() -> None:
    assert {code.value for code in CompletionConstraintCode} == {
        "plan_incomplete",
        "verification_missing",
        "verification_failed",
        "external_blocker",
        "unrecoverable_failure",
    }
    assert not hasattr(CompletionConstraintCode, "VERIFICATION_PASSED")
    assert not hasattr(CompletionConstraintCode, "CAN_COMPLETE")


def test_reordered_inputs_and_decision_identity_preserve_semantics() -> None:
    spec = _goal_spec(
        requirements=(_requirement("r-2"), _requirement("r-1")),
        criteria=(_criterion("c-2"), _criterion("c-1")),
    )
    first_ref = CompletionEvidenceRef(CompletionEvidenceKind.TOOL_RESULT, "tool-1")
    second_ref = CompletionEvidenceRef(CompletionEvidenceKind.GOAL_SPEC, "goal-1")
    first = _evaluate(
        spec,
        decision_id="decision-a",
        requirement_assessments=(
            RequirementAssessment("r-2", AssessmentStatus.SATISFIED, (first_ref,)),
            RequirementAssessment("r-1", AssessmentStatus.SATISFIED, (second_ref,)),
        ),
        criterion_assessments=(
            _criterion_satisfied("c-2"),
            _criterion_satisfied("c-1"),
        ),
        evidence=(first_ref, second_ref),
        constraints=(
            CompletionConstraint(CompletionConstraintCode.VERIFICATION_MISSING),
            CompletionConstraint(CompletionConstraintCode.PLAN_INCOMPLETE),
        ),
    )
    second = _evaluate(
        spec,
        decision_id="decision-b",
        requirement_assessments=(
            RequirementAssessment("r-1", AssessmentStatus.SATISFIED, (second_ref,)),
            RequirementAssessment("r-2", AssessmentStatus.SATISFIED, (first_ref,)),
        ),
        criterion_assessments=(
            _criterion_satisfied("c-1"),
            _criterion_satisfied("c-2"),
        ),
        evidence=(second_ref, first_ref),
        constraints=(
            CompletionConstraint(CompletionConstraintCode.PLAN_INCOMPLETE),
            CompletionConstraint(CompletionConstraintCode.VERIFICATION_MISSING),
        ),
    )

    assert first.decision_digest == second.decision_digest
    assert first.decision_id != second.decision_id
    assert first.requirement_assessments == second.requirement_assessments
    assert first.criterion_assessments == second.criterion_assessments
    assert first.evidence == second.evidence
    assert first.issues == second.issues


def test_goal_spec_snapshot_identity_and_digest_are_required() -> None:
    spec = _goal_spec(requirements=(_requirement("r-1"),))
    with pytest.raises(CompletionEvaluationInputError, match="identity"):
        _evaluate(spec, snapshot=_snapshot(spec, goal_spec_id="other-goal"))
    with pytest.raises(CompletionEvaluationInputError, match="digest"):
        _evaluate(spec, snapshot=_snapshot(spec, goal_spec_digest="f" * 64))


def test_snapshot_version_and_workspace_are_semantic_decision_inputs() -> None:
    spec = _goal_spec(requirements=(_requirement("r-1"),))
    base = _evaluate(
        spec,
        requirement_assessments=(_satisfied("r-1"),),
    )
    changed_version = _evaluate(
        spec,
        snapshot=_snapshot(spec, control_state_version=5),
        requirement_assessments=(_satisfied("r-1"),),
    )
    changed_workspace = _evaluate(
        spec,
        snapshot=_snapshot(spec, workspace_id="workspace-2"),
        requirement_assessments=(_satisfied("r-1"),),
    )

    assert changed_version.decision_digest != base.decision_digest
    assert changed_workspace.decision_digest != base.decision_digest


def test_positive_verification_reference_does_not_replace_required_assessment() -> None:
    spec = _goal_spec(requirements=(_requirement("r-1"),))
    decision = _evaluate(
        spec,
        evidence=(CompletionEvidenceRef(CompletionEvidenceKind.VERIFICATION_RUN, "run-1"),),
    )

    assert decision.outcome is CompletionOutcome.REPLAN
    assert decision.issues[0].code is CompletionIssueCode.REQUIREMENT_UNKNOWN


def test_evaluator_is_pure_and_does_not_import_repository_or_database() -> None:
    source = Path(__file__).resolve().parents[2] / "khaos" / "agent" / "control" / "completion_evaluator.py"
    text = source.read_text(encoding="utf-8")
    assert "completion_repository" not in text
    assert "Database" not in text

    spec = _goal_spec(requirements=(_requirement("r-1"),))
    decision = _evaluate(
        spec,
        requirement_assessments=(_satisfied("r-1"),),
    )
    assert decision.outcome is CompletionOutcome.COMPLETE
    assert _snapshot(spec).task_status == "running"


def test_evaluation_snapshot_and_constraint_are_deeply_immutable() -> None:
    spec = _goal_spec()
    snapshot = _snapshot(spec)
    constraint = CompletionConstraint(CompletionConstraintCode.PLAN_INCOMPLETE)

    with pytest.raises(FrozenInstanceError):
        snapshot.task_status = "completed"  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        constraint.code = CompletionConstraintCode.EXTERNAL_BLOCKER  # type: ignore[misc]
