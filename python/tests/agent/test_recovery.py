"""Unit and durable-integration tests for the M7.5 recovery control plane."""

from __future__ import annotations

import hashlib
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from khaos.agent.control.completion import CompletionOutcome
from khaos.agent.control.completion_recovery import (
    CompletionContinuationState,
    CompletionRecoveryService,
    DatabaseCompletionGateHistoryReader,
)
from khaos.agent.control.recovery import (
    NormalizedFailureCase,
    NormalizedFailureSignature,
    PlanningRecoveryStatus,
    RecoveryAction,
    RecoveryContractError,
    RecoveryEvaluator,
    RecoveryFailureSource,
    RecoveryInput,
    RecoveryPolicy,
    RecoveryReasonCode,
)
from khaos.agent.control.recovery_control import (
    RecoveryControlContinuation,
    RecoveryControlCoordinator,
    RecoveryControlStatus,
)
from khaos.agent.control.recovery_gate import RecoveryGate, RecoveryGateStatus
from khaos.agent.control.recovery_repository import RecoveryDecisionIntegrityError
from khaos.agent.control.state import AgentCognitiveState
from khaos.agent.control.state_repository import (
    CognitiveTransitionStatus,
    CognitiveWorkspaceBinding,
)
from khaos.coding.intelligence.context import (
    ContextBundle,
    ContextDocument,
    ContextFreshness,
    ContextRequest,
    ContextSourceKind,
)
from khaos.coding.planning.coordinator import PlanningControlCoordinator
from khaos.coding.planning.service import DeterministicPlanningService
from khaos.coding.planning.verification_assessment import (
    VerificationAssessmentDisposition,
)
from khaos.coding.task_manager import TaskManager, TaskStatus, TransitionResult
from khaos.db import Database

OWNER = "m7-owner"
PROJECT = "m7-project"
WORKSPACE = "workspace-a"
REPOSITORY = "repository-a"
BASE_REVISION = "base-a"


def _failure_signature() -> NormalizedFailureSignature:
    return NormalizedFailureSignature.from_cases(
        source=RecoveryFailureSource.TRUSTED_VERIFICATION,
        failed_count=1,
        error_count=0,
        failed_cases=(
            NormalizedFailureCase(
                subject_id="test_payment",
                file_identity="tests/test_payment.py",
                line=17,
                error_digest="a" * 64,
            ),
        ),
        verification_requirement_ids=("unit",),
        verification_check_ids=("unit-payment",),
        command_digests=("b" * 64,),
        result_statuses=("failed",),
        published_plan_revision_id="plan-1",
        published_plan_revision_digest="c" * 64,
    )


def _input(**updates: object) -> RecoveryInput:
    value = RecoveryInput(
        principal_id="principal-a",
        project_id="project-a",
        task_id="task-a",
        goal_spec_id="goal-a",
        goal_spec_digest="d" * 64,
        cognitive_state=AgentCognitiveState.DIAGNOSING,
        control_state_version=4,
        task_status="running",
        workspace_id="workspace-a",
        repository_id="repository-a",
        base_revision="base-a",
        published_plan_revision_id="plan-1",
        published_plan_revision_digest="c" * 64,
        policy=RecoveryPolicy(),
    )
    if "verification_disposition" in updates:
        updates.setdefault("verification_assessment_id", "assessment-a")
        updates.setdefault("verification_assessment_digest", "e" * 64)
    if "completion_continuation_state" in updates:
        continuation = updates["completion_continuation_state"]
        outcome_by_continuation = {
            CompletionContinuationState.REPLAN_REQUIRED: CompletionOutcome.REPLAN,
            CompletionContinuationState.EXTERNAL_BLOCKED: CompletionOutcome.BLOCKED,
            CompletionContinuationState.FAILURE_REVIEW_REQUIRED: CompletionOutcome.FAILED,
            CompletionContinuationState.INTEGRITY_ERROR: CompletionOutcome.FAILED,
        }
        updates.setdefault("completion_decision_id", "completion-a")
        updates.setdefault("completion_decision_digest", "f" * 64)
        updates.setdefault("completion_decision_sequence", 1)
        updates.setdefault("completion_outcome", outcome_by_continuation[continuation])
    return replace(value, **updates)


def test_normalized_failure_signature_is_deeply_immutable_and_bounded() -> None:
    signature = _failure_signature()

    with pytest.raises(FrozenInstanceError):
        signature.failed_count = 2  # type: ignore[misc]
    assert signature.failure_signature_digest == signature.signature_digest
    assert "raw stack" not in signature.canonical_json()
    assert signature.semantic_payload["failed_cases"][0]["error_digest"] == "a" * 64


def test_normalized_failure_signature_is_deterministic_and_changes_on_semantic_change() -> None:
    first = _failure_signature()
    second = NormalizedFailureSignature.from_cases(
        source=RecoveryFailureSource.TRUSTED_VERIFICATION,
        failed_count=1,
        error_count=0,
        failed_cases=tuple(reversed(first.failed_cases)),
        verification_requirement_ids=("unit",),
        verification_check_ids=("unit-payment",),
        command_digests=("b" * 64,),
        result_statuses=("failed",),
        published_plan_revision_id="plan-1",
        published_plan_revision_digest="c" * 64,
    )
    changed = replace(first, failed_count=2, signature_digest="")

    assert first.signature_digest == second.signature_digest
    assert first.signature_digest != changed.signature_digest


def test_overflow_is_explicitly_represented() -> None:
    cases = tuple(
        NormalizedFailureCase(subject_id=f"test-{index}")
        for index in range(40)
    )
    signature = NormalizedFailureSignature.from_cases(
        source=RecoveryFailureSource.VERIFY_FIX,
        failed_count=40,
        error_count=0,
        failed_cases=cases,
    )

    assert len(signature.failed_cases) == 32
    assert signature.overflow_count == 8
    assert signature.overflow_digest is not None


def test_recovery_policy_is_bounded_and_immutable() -> None:
    policy = RecoveryPolicy()
    assert policy.max_recovery_attempts_per_plan == 3
    assert policy.policy_digest
    with pytest.raises(FrozenInstanceError):
        policy.max_replans_per_task = 0  # type: ignore[misc]
    with pytest.raises(RecoveryContractError):
        RecoveryPolicy(max_replans_per_task=9)


def test_first_trusted_failure_recovers_current_plan() -> None:
    decision = RecoveryEvaluator.evaluate(
        _input(
            verification_disposition=VerificationAssessmentDisposition.FAILED,
            failure_signature=_failure_signature(),
        ),
        recovery_decision_id="recovery-1",
    )

    assert decision.action is RecoveryAction.RECOVER_CURRENT_PLAN
    assert decision.reason_code is RecoveryReasonCode.VERIFICATION_FAILED
    assert decision.input_digest
    assert decision.decision_digest


def test_recovery_decision_canonical_round_trip_preserves_semantics() -> None:
    decision = RecoveryEvaluator.evaluate(
        _input(
            verification_disposition=VerificationAssessmentDisposition.FAILED,
            failure_signature=_failure_signature(),
        ),
        recovery_decision_id="recovery-round-trip",
    )

    decoded = decision.from_canonical_json(
        decision.canonical_json(),
        expected_digest=decision.decision_digest,
        expected_decision_id=decision.recovery_decision_id,
    )

    assert decoded.semantic_payload == decision.semantic_payload
    assert decoded.decision_digest == decision.decision_digest


def test_repeated_failure_replans_then_blocks_when_replan_budget_is_exhausted() -> None:
    signature = _failure_signature()
    replanning = RecoveryEvaluator.evaluate(
        _input(
            verification_disposition=VerificationAssessmentDisposition.FAILED,
            failure_signature=signature,
            identical_failure_streak=2,
            replan_count=0,
        ),
        recovery_decision_id="recovery-2",
    )
    blocked = RecoveryEvaluator.evaluate(
        _input(
            verification_disposition=VerificationAssessmentDisposition.FAILED,
            failure_signature=signature,
            identical_failure_streak=2,
            replan_count=3,
        ),
        recovery_decision_id="recovery-3",
    )

    assert replanning.action is RecoveryAction.REPLAN
    assert replanning.reason_code is RecoveryReasonCode.IDENTICAL_FAILURE_SIGNATURE
    assert blocked.action is RecoveryAction.BLOCK
    assert blocked.reason_code is RecoveryReasonCode.REPLAN_BUDGET_EXHAUSTED


def test_no_progress_signal_replans_without_consuming_repair_attempts() -> None:
    signature = _failure_signature()
    decision = RecoveryEvaluator.evaluate(
        _input(
            failure_signature=signature,
            no_progress_detected=True,
            recovery_attempt_count=0,
            replan_count=0,
        ),
        recovery_decision_id="recovery-no-progress",
    )

    assert decision.action is RecoveryAction.REPLAN
    assert decision.reason_code is RecoveryReasonCode.IDENTICAL_FAILURE_SIGNATURE
    assert decision.input.no_progress_detected
    assert decision.input.recovery_attempt_count == 0


def test_no_progress_is_blocked_after_replan_budget_is_exhausted() -> None:
    decision = RecoveryEvaluator.evaluate(
        _input(
            failure_signature=_failure_signature(),
            no_progress_detected=True,
            replan_count=3,
        ),
        recovery_decision_id="recovery-no-progress-budget",
    )

    assert decision.action is RecoveryAction.BLOCK
    assert decision.reason_code is RecoveryReasonCode.REPLAN_BUDGET_EXHAUSTED


def test_no_progress_canonical_round_trip_retains_negative_signal() -> None:
    decision = RecoveryEvaluator.evaluate(
        _input(
            failure_signature=_failure_signature(),
            no_progress_detected=True,
        ),
        recovery_decision_id="recovery-no-progress-round-trip",
    )

    decoded = decision.from_canonical_json(
        decision.canonical_json(),
        expected_digest=decision.decision_digest,
        expected_decision_id=decision.recovery_decision_id,
    )

    assert decoded.input.no_progress_detected
    assert decoded.input.failure_signature_digest == decision.input.failure_signature_digest


@pytest.mark.parametrize(
    ("continuation", "action", "reason"),
    (
        (
            CompletionContinuationState.REPLAN_REQUIRED,
            RecoveryAction.REPLAN,
            RecoveryReasonCode.COMPLETION_REPLAN_REQUIRED,
        ),
        (
            CompletionContinuationState.EXTERNAL_BLOCKED,
            RecoveryAction.BLOCK,
            RecoveryReasonCode.COMPLETION_EXTERNAL_BLOCKED,
        ),
        (
            CompletionContinuationState.FAILURE_REVIEW_REQUIRED,
            RecoveryAction.BLOCK,
            RecoveryReasonCode.COMPLETION_FAILURE_REVIEW_REQUIRED,
        ),
        (
            CompletionContinuationState.INTEGRITY_ERROR,
            RecoveryAction.BLOCK,
            RecoveryReasonCode.DURABLE_HISTORY_INTEGRITY_ERROR,
        ),
    ),
)
def test_completion_continuation_is_consumed_as_a_negative_recovery_signal(
    continuation: CompletionContinuationState,
    action: RecoveryAction,
    reason: RecoveryReasonCode,
) -> None:
    decision = RecoveryEvaluator.evaluate(
        _input(completion_continuation_state=continuation),
        recovery_decision_id=f"recovery-{continuation.value}",
    )

    assert decision.action is action
    assert decision.reason_code is reason


def test_terminal_task_has_no_recovery_action() -> None:
    decision = RecoveryEvaluator.evaluate(
        _input(task_status="completed"),
        recovery_decision_id="recovery-terminal",
    )
    assert decision.action is RecoveryAction.NO_ACTION
    assert decision.reason_code is RecoveryReasonCode.TASK_TERMINAL


def test_planning_negative_signals_block_without_expanding_authority() -> None:
    decision = RecoveryEvaluator.evaluate(
        _input(planning_status=PlanningRecoveryStatus.INVALID),
        recovery_decision_id="recovery-invalid-plan",
    )
    assert decision.action is RecoveryAction.BLOCK
    assert decision.reason_code is RecoveryReasonCode.PLANNING_INVALID
    assert decision.input.completion_outcome is not CompletionOutcome.COMPLETE


def test_stale_or_unavailable_verification_never_becomes_recovery_success() -> None:
    for disposition, reason in (
        (
            VerificationAssessmentDisposition.STALE,
            RecoveryReasonCode.VERIFICATION_STALE,
        ),
        (
            VerificationAssessmentDisposition.UNAVAILABLE,
            RecoveryReasonCode.VERIFICATION_UNAVAILABLE,
        ),
    ):
        decision = RecoveryEvaluator.evaluate(
            _input(verification_disposition=disposition),
            recovery_decision_id=f"recovery-{disposition.value}",
        )
        assert decision.action is RecoveryAction.BLOCK
        assert decision.reason_code is reason


def _content_digest(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _context_document(path: str, content: str) -> ContextDocument:
    return ContextDocument(
        relative_path=path,
        language="python",
        content=content,
        content_digest=_content_digest(content),
        file_size=len(content.encode("utf-8")),
        source_kind=ContextSourceKind.WORKSPACE_SNAPSHOT,
        workspace_id=WORKSPACE,
        repository_id=REPOSITORY,
        base_revision=BASE_REVISION,
        repository_generation="repository-generation-1",
        index_generation="index-generation-1",
        excerpt_end=len(content.encode("utf-8")),
        relevance_score=1,
    )


def _context_bundle(
    request: ContextRequest,
    goal_spec: object,
) -> ContextBundle:
    return ContextBundle(
        bundle_id=f"bundle-{request.task_id}",
        task_id=request.task_id,
        principal_id=request.principal_id,
        project_id=request.project_id,
        goal_spec_id=request.goal_spec_id,
        goal_spec_digest=request.goal_spec_digest,
        workspace_id=request.workspace_id,
        repository_id=request.repository_id,
        base_revision=request.base_revision,
        request_digest=request.request_digest,
        repository_generation="repository-generation-1",
        index_generation="index-generation-1",
        freshness=ContextFreshness.FRESH,
        documents=(_context_document("foo.py", "def target():\n    return 1\n"),),
    )


class _RecoveryContextIntelligence:
    """Small deterministic M7.2 adapter for the real planning coordinator."""

    def repository_id_for_workspace(self, workspace: object) -> str:
        del workspace
        return REPOSITORY

    async def retrieve(
        self,
        request: ContextRequest,
        goal_spec: object,
    ) -> ContextBundle:
        return _context_bundle(request, goal_spec)


async def _make_recovery_database(
    path: Path,
) -> tuple[Database, TaskManager, object]:
    database = Database(path)
    await database.connect()
    await database.run_migrations()
    manager = TaskManager(
        db=database,
        principal_id=OWNER,
        project_id=PROJECT,
    )
    task = await manager.create("修复 foo.py")
    assert (
        await manager.update_status(task.id, TaskStatus.RUNNING)
        is TransitionResult.UPDATED
    )
    initialized = await manager.initialize_cognitive_state(task.id)
    assert initialized.status is CognitiveTransitionStatus.UPDATED
    assert (
        await manager.update_status(
            task.id,
            TaskStatus.RUNNING,
            workspace_id=WORKSPACE,
            base_sha=BASE_REVISION,
            repository_id=REPOSITORY,
        )
        is TransitionResult.UNCHANGED
    )
    return database, manager, task


def _recovery_planner(database: Database) -> PlanningControlCoordinator:
    return PlanningControlCoordinator(
        planning_service=DeterministicPlanningService(None, repositories={}),
        context_intelligence=_RecoveryContextIntelligence(),
        goal_spec_repository=database.goal_spec_repository,
        plan_revision_repository=database.plan_revision_repository,
        control_state_repository=database.agent_control_state_repository,
        principal_id=OWNER,
        project_id=PROJECT,
    )


def _recovery_coordinator(
    database: Database,
    *,
    planning_coordinator: PlanningControlCoordinator | None = None,
) -> RecoveryControlCoordinator:
    completion_recovery = CompletionRecoveryService(
        decision_repository=database.completion_decision_repository,
        goal_spec_repository=database.goal_spec_repository,
        gate_history_reader=DatabaseCompletionGateHistoryReader(database),
        principal_id=OWNER,
        project_id=PROJECT,
    )
    return RecoveryControlCoordinator(
        recovery_repository=database.recovery_decision_repository,
        recovery_gate=RecoveryGate(
            gate_repository=database.recovery_gate_repository,
            principal_id=OWNER,
            project_id=PROJECT,
        ),
        principal_id=OWNER,
        project_id=PROJECT,
        policy=RecoveryPolicy.production_default(),
        goal_spec_repository=database.goal_spec_repository,
        plan_revision_repository=database.plan_revision_repository,
        verification_assessment_repository=database.verification_assessment_repository,
        completion_recovery=completion_recovery,
        planning_coordinator=planning_coordinator,
        control_state_repository=database.agent_control_state_repository,
    )


def _failure_signature_for_plan(
    plan_id: str,
    plan_digest: str,
) -> NormalizedFailureSignature:
    return NormalizedFailureSignature.from_cases(
        source=RecoveryFailureSource.TRUSTED_VERIFICATION,
        failed_count=1,
        error_count=0,
        failed_cases=(
            NormalizedFailureCase(
                subject_id="test_foo",
                check_id="test_foo",
                file_identity="tests/test_foo.py",
            ),
        ),
        verification_check_ids=("test_foo",),
        result_statuses=("failed",),
        published_plan_revision_id=plan_id,
        published_plan_revision_digest=plan_digest,
    )


async def _publish_initial_plan(
    database: Database,
    task: object,
    manager: TaskManager,
) -> object:
    planner = _recovery_planner(database)
    result = await planner.plan(
        task.id,  # type: ignore[attr-defined]
        workspace=SimpleNamespace(id=WORKSPACE),
        query="修复 foo.py",
        target_files=("foo.py",),
    )
    assert result.status.value == "implementing"
    assert result.revision is not None
    assert result.publication is not None
    assert result.publication.published_plan_revision_id == result.revision.plan_revision_id
    del manager
    return result.revision


async def _move_to_diagnosing(
    database: Database,
    task_id: str,
) -> None:
    snapshot = await database.recovery_decision_repository.read_current_task_snapshot(
        task_id,
        principal_id=OWNER,
        project_id=PROJECT,
    )
    assert snapshot is not None
    if snapshot.cognitive_state is AgentCognitiveState.UNDERSTANDING:
        transition = await database.agent_control_state_repository.compare_and_transition(
            task_id,
            principal_id=OWNER,
            project_id=PROJECT,
            expected_state=snapshot.cognitive_state,
            expected_version=snapshot.control_state_version,
            target_state=AgentCognitiveState.EXPLORING,
            expected_task_status=snapshot.task_status,
            expected_workspace_binding=CognitiveWorkspaceBinding(
                workspace_id=snapshot.workspace_id,
                base_revision=snapshot.base_revision,
                repository_id=snapshot.repository_id,
            ),
        )
        assert transition.status is CognitiveTransitionStatus.UPDATED
        snapshot = await database.recovery_decision_repository.read_current_task_snapshot(
            task_id,
            principal_id=OWNER,
            project_id=PROJECT,
        )
        assert snapshot is not None
    transition = await database.agent_control_state_repository.compare_and_transition(
        task_id,
        principal_id=OWNER,
        project_id=PROJECT,
        expected_state=snapshot.cognitive_state,
        expected_version=snapshot.control_state_version,
        target_state=AgentCognitiveState.DIAGNOSING,
        expected_task_status=snapshot.task_status,
        expected_workspace_binding=CognitiveWorkspaceBinding(
            workspace_id=snapshot.workspace_id,
            base_revision=snapshot.base_revision,
            repository_id=snapshot.repository_id,
        ),
    )
    assert transition.status is CognitiveTransitionStatus.UPDATED


@pytest.mark.asyncio
async def test_recovery_replans_from_published_plan_and_retains_history(
    tmp_path: Path,
) -> None:
    database, manager, task = await _make_recovery_database(tmp_path / "replan.db")
    try:
        first_revision = await _publish_initial_plan(database, task, manager)
        signature = _failure_signature_for_plan(
            first_revision.plan_revision_id,
            first_revision.plan_semantic_digest,
        )
        coordinator = _recovery_coordinator(
            database,
            planning_coordinator=_recovery_planner(database),
        )

        result = await coordinator.evaluate_current(
            task.id,
            failure_signature=signature,
            no_progress_detected=True,
            workspace=SimpleNamespace(id=WORKSPACE),
            query="修复 foo.py",
            target_files=("foo.py",),
        )

        assert result.status is RecoveryControlStatus.APPLIED
        assert result.gate_status is RecoveryGateStatus.APPLIED
        assert result.action is RecoveryAction.REPLAN
        assert result.planning_status == "implementing"
        assert result.planning_revision_id is not None
        assert result.planning_revision_id != first_revision.plan_revision_id
        assert result.cognitive_state == AgentCognitiveState.IMPLEMENTING.value
        assert result.published_plan_revision_id == result.planning_revision_id
        assert result.control_state_version is not None

        history = await database.recovery_decision_repository.list_for_task(
            task.id,
            principal_id=OWNER,
            project_id=PROJECT,
        )
        assert len(history) == 1
        assert history[0].action is RecoveryAction.REPLAN
        current = await database.recovery_decision_repository.read_current_task_snapshot(
            task.id,
            principal_id=OWNER,
            project_id=PROJECT,
        )
        assert current is not None
        assert current.cognitive_state is AgentCognitiveState.IMPLEMENTING
        assert current.published_plan_revision_id == result.planning_revision_id
        assert current.last_applied_recovery_decision_id == result.recovery_decision_id

        plans = await database.plan_revision_repository.list_for_task(
            task.id,
            principal_id=OWNER,
            project_id=PROJECT,
        )
        assert [item.plan_revision_id for item in plans] == [
            first_revision.plan_revision_id,
            result.planning_revision_id,
        ]
        assert (
            await coordinator.recover(task.id)
        ).continuation is RecoveryControlContinuation.APPLIED
    finally:
        await database.close()


@pytest.mark.asyncio
async def test_recovery_head_race_rejects_old_decision_and_applies_new_head(
    tmp_path: Path,
) -> None:
    database, manager, task = await _make_recovery_database(tmp_path / "head-race.db")
    try:
        first_revision = await _publish_initial_plan(database, task, manager)
        await _move_to_diagnosing(database, task.id)
        coordinator = _recovery_coordinator(database)
        signature = _failure_signature_for_plan(
            first_revision.plan_revision_id,
            first_revision.plan_semantic_digest,
        )
        first_input = await coordinator._build_input(
            task.id,
            failure_signature=signature,
            no_progress_detected=True,
            planning_status=PlanningRecoveryStatus.NONE,
        )
        first_decision = RecoveryEvaluator.evaluate(
            first_input,
            recovery_decision_id="recovery-race-1",
        )
        first_stored = await database.recovery_decision_repository.append(
            first_decision,
            principal_id=OWNER,
            project_id=PROJECT,
        )
        second_input = replace(
            first_input,
            identical_failure_streak=1,
            recovery_attempt_count=0,
            replan_count=1,
            total_recovery_count=1,
        )
        second_decision = RecoveryEvaluator.evaluate(
            second_input,
            recovery_decision_id="recovery-race-2",
        )
        second_stored = await database.recovery_decision_repository.append(
            second_decision,
            principal_id=OWNER,
            project_id=PROJECT,
        )
        gate = RecoveryGate(
            gate_repository=database.recovery_gate_repository,
            principal_id=OWNER,
            project_id=PROJECT,
        )

        first_result = await gate.apply(first_stored.recovery_decision_id)
        assert first_result.status is RecoveryGateStatus.STALE
        second_result = await gate.apply(second_stored.recovery_decision_id)
        assert second_result.status is RecoveryGateStatus.APPLIED
        current = await database.recovery_decision_repository.read_current_task_snapshot(
            task.id,
            principal_id=OWNER,
            project_id=PROJECT,
        )
        assert current is not None
        assert current.cognitive_state is AgentCognitiveState.REPLANNING
        assert current.published_plan_revision_id is None
        assert current.last_applied_recovery_decision_id == second_stored.recovery_decision_id
    finally:
        await database.close()


@pytest.mark.asyncio
async def test_recovery_restart_marks_decision_stale_without_replay(
    tmp_path: Path,
) -> None:
    database, _manager, task = await _make_recovery_database(tmp_path / "restart.db")
    try:
        await _move_to_diagnosing(database, task.id)
        coordinator = _recovery_coordinator(database)
        passive_input = await coordinator._build_input(
            task.id,
            failure_signature=None,
            no_progress_detected=False,
            planning_status=PlanningRecoveryStatus.NONE,
        )
        decision = RecoveryEvaluator.evaluate(
            passive_input,
            recovery_decision_id="recovery-before-restart",
        )
        # This is deliberately a passive NO_ACTION input with no plan.  It
        # still proves that restart recovery reads the durable head rather
        # than replaying it or appending another decision.
        stored = await database.recovery_decision_repository.append(
            decision,
            principal_id=OWNER,
            project_id=PROJECT,
        )
        before = await database.recovery_decision_repository.read_current_task_snapshot(
            task.id,
            principal_id=OWNER,
            project_id=PROJECT,
        )
        assert before is not None
        restarted = TaskManager(db=database, principal_id=OWNER, project_id=PROJECT)
        await restarted.load()
        after = await database.recovery_decision_repository.read_current_task_snapshot(
            task.id,
            principal_id=OWNER,
            project_id=PROJECT,
        )
        assert after is not None
        assert after.task_status == TaskStatus.BLOCKED.value
        assert after.cognitive_state is before.cognitive_state
        assert after.control_state_version == before.control_state_version
        recovered = await coordinator.recover(task.id)
        assert recovered is not None
        assert recovered.continuation is RecoveryControlContinuation.STALE
        latest = await database.recovery_decision_repository.get_latest_for_task(
            task.id,
            principal_id=OWNER,
            project_id=PROJECT,
        )
        assert latest is not None
        assert latest.recovery_decision_id == stored.recovery_decision_id
    finally:
        await database.close()


@pytest.mark.asyncio
async def test_malformed_latest_recovery_decision_does_not_fallback(
    tmp_path: Path,
) -> None:
    database, _manager, task = await _make_recovery_database(tmp_path / "malformed.db")
    try:
        await _move_to_diagnosing(database, task.id)
        coordinator = _recovery_coordinator(database)
        base_input = await coordinator._build_input(
            task.id,
            failure_signature=None,
            no_progress_detected=False,
            planning_status=PlanningRecoveryStatus.NONE,
        )
        first = RecoveryEvaluator.evaluate(base_input, recovery_decision_id="recovery-old")
        await database.recovery_decision_repository.append(
            first,
            principal_id=OWNER,
            project_id=PROJECT,
        )
        second_input = replace(
            base_input,
            total_recovery_count=1,
        )
        second = RecoveryEvaluator.evaluate(
            second_input,
            recovery_decision_id="recovery-new",
        )
        await database.recovery_decision_repository.append(
            second,
            principal_id=OWNER,
            project_id=PROJECT,
        )
        async with database.transaction() as conn:
            await conn.execute(
                "DROP TRIGGER trg_agent_recovery_decisions_immutable_update"
            )
            await conn.execute(
                "UPDATE agent_recovery_decisions SET canonical_json = ? "
                "WHERE recovery_decision_id = ?",
                ("{", "recovery-new"),
            )
            await conn.execute(
                """
                CREATE TRIGGER trg_agent_recovery_decisions_immutable_update
                BEFORE UPDATE ON agent_recovery_decisions
                BEGIN
                    SELECT RAISE(
                        ABORT,
                        'agent_recovery_decisions is append-only: updates are forbidden'
                    );
                END
                """
            )

        recovered = await coordinator.recover(task.id)
        assert recovered is not None
        assert recovered.continuation is RecoveryControlContinuation.INTEGRITY_ERROR
        with pytest.raises(RecoveryDecisionIntegrityError):
            await database.recovery_decision_repository.get_latest_for_task(
                task.id,
                principal_id=OWNER,
                project_id=PROJECT,
            )
    finally:
        await database.close()


@pytest.mark.asyncio
async def test_recovery_history_sequence_gap_fails_closed_without_fallback(
    tmp_path: Path,
) -> None:
    database, _manager, task = await _make_recovery_database(tmp_path / "sequence-gap.db")
    try:
        await _move_to_diagnosing(database, task.id)
        coordinator = _recovery_coordinator(database)
        first_input = await coordinator._build_input(
            task.id,
            failure_signature=None,
            no_progress_detected=False,
            planning_status=PlanningRecoveryStatus.NONE,
        )
        first = RecoveryEvaluator.evaluate(
            first_input,
            recovery_decision_id="recovery-sequence-old",
        )
        await database.recovery_decision_repository.append(
            first,
            principal_id=OWNER,
            project_id=PROJECT,
        )
        second = RecoveryEvaluator.evaluate(
            replace(first_input, total_recovery_count=1),
            recovery_decision_id="recovery-sequence-new",
        )
        await database.recovery_decision_repository.append(
            second,
            principal_id=OWNER,
            project_id=PROJECT,
        )

        async with database.transaction() as conn:
            await conn.execute(
                "DROP TRIGGER trg_agent_recovery_decisions_immutable_update"
            )
            await conn.execute(
                "UPDATE agent_recovery_decisions SET recovery_sequence = ? "
                "WHERE recovery_decision_id = ?",
                (3, "recovery-sequence-new"),
            )
            await conn.execute(
                """
                CREATE TRIGGER trg_agent_recovery_decisions_immutable_update
                BEFORE UPDATE ON agent_recovery_decisions
                BEGIN
                    SELECT RAISE(
                        ABORT,
                        'agent_recovery_decisions is append-only: updates are forbidden'
                    );
                END
                """
            )

        with pytest.raises(RecoveryDecisionIntegrityError):
            await database.recovery_decision_repository.get_latest_for_task(
                task.id,
                principal_id=OWNER,
                project_id=PROJECT,
            )
        recovered = await coordinator.recover(task.id)
        assert recovered is not None
        assert recovered.continuation is RecoveryControlContinuation.INTEGRITY_ERROR
    finally:
        await database.close()
