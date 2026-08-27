"""M7.4 trusted-verification authority, binding, and durability tests."""

from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from khaos.agent.control.completion_evaluator import CompletionEvaluationSnapshot
from khaos.agent.control.goal import GoalSpec
from khaos.agent.control.state import AgentCognitiveState
from khaos.coding.planning.trusted_verification_authority import (
    M4VerificationEvidenceValidator,
    StructuralVerificationEvidenceValidator,
    TrustedVerificationAuthority,
    VerificationEvidenceValidationStatus,
)
from khaos.coding.planning.trusted_verification_service import (
    TrustedVerificationFactProvider,
    TrustedVerificationService,
    VerificationEventType,
)
from khaos.coding.planning.verification_assessment import (
    TrustedVerificationInput,
    VerificationAssessment,
    VerificationAssessmentDisposition,
    VerificationEvidenceKind,
    VerificationEvidenceRef,
    VerificationExecutionEvidence,
    VerificationExecutionStatus,
    VerificationRequirement,
    VerificationTermination,
)
from khaos.coding.planning.verification_assessment_repository import (
    VerificationAssessmentBindingError,
    VerificationAssessmentConflictError,
    VerificationAssessmentRepository,
    VerificationCurrentSnapshot,
)
from khaos.coding.task_manager import TaskManager, TaskStatus
from khaos.db import Database
from khaos.security.protocol_boundary import canonical_digest

OWNER = "m7-4-owner"
PROJECT = "m7-4-project"
WORKSPACE = "m7-4-workspace"
REPOSITORY = "m7-4-repository"
BASE_REVISION = "m7-4-base"
GENERATION = "m7-4-generation"
CHANGE_IDENTITY = "m7-4-change"


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _verification_input(
    *,
    task_id: str = "task-m7-4",
    goal_spec_id: str = "goal-m7-4",
    goal_spec_digest: str | None = None,
    workspace_id: str = WORKSPACE,
    repository_id: str = REPOSITORY,
    base_revision: str | None = BASE_REVISION,
    repository_generation: str | None = GENERATION,
    change_identity: str | None = CHANGE_IDENTITY,
    cognitive_state: AgentCognitiveState = AgentCognitiveState.IMPLEMENTING,
    control_state_version: int = 4,
    task_status: str = "running",
    published_plan_revision_id: str | None = "plan-1",
    evidence: tuple[VerificationExecutionEvidence, ...] = (),
    requirements: tuple[VerificationRequirement, ...] | None = None,
) -> TrustedVerificationInput:
    requirement = VerificationRequirement(
        requirement_id="check-1",
        verification_type="unit",
        scope="tests/test_target.py",
        required=True,
        command_digest=_digest("pytest tests/test_target.py"),
        plan_step_id="step-1",
        source_intent_id="intent-1",
    )
    return TrustedVerificationInput(
        schema_version=1,
        principal_id=OWNER,
        project_id=PROJECT,
        task_id=task_id,
        goal_spec_id=goal_spec_id,
        goal_spec_digest=goal_spec_digest or _digest("goal"),
        cognitive_state=cognitive_state,
        control_state_version=control_state_version,
        task_status=task_status,
        workspace_id=workspace_id,
        repository_id=repository_id,
        base_revision=base_revision,
        published_plan_revision_id=published_plan_revision_id,
        published_plan_revision_digest=(
            None
            if published_plan_revision_id is None
            else _digest(published_plan_revision_id)
        ),
        repository_generation=repository_generation,
        change_identity=change_identity,
        policy_digest=_digest("policy"),
        catalog_fingerprint=_digest("catalog"),
        requirements=requirements or (requirement,),
        evidence=evidence,
    )


def _evidence(
    verification_input: TrustedVerificationInput,
    *,
    status: VerificationExecutionStatus = VerificationExecutionStatus.PASSED,
    exit_code: int | None = 0,
    termination: VerificationTermination = VerificationTermination.COMPLETED,
    output_truncated: bool = False,
    requirement_id: str = "check-1",
) -> VerificationExecutionEvidence:
    requirement = next(
        item
        for item in verification_input.requirements
        if item.requirement_id == requirement_id
    )
    return VerificationExecutionEvidence(
        evidence_id="evidence-1",
        requirement_id=requirement_id,
        execution_run_id="execution-1",
        verification_run_id="verification-1",
        verification_step_id="step-run-1",
        workspace_id=verification_input.workspace_id,
        repository_id=verification_input.repository_id,
        base_revision=verification_input.base_revision,
        repository_generation=verification_input.repository_generation or GENERATION,
        change_identity=verification_input.change_identity or CHANGE_IDENTITY,
        command_digest=requirement.command_digest or _digest("command"),
        authority_id="authority-1",
        authority_digest=_digest("authority-1"),
        status=status,
        exit_code=exit_code,
        termination=termination,
        stdout_digest=_digest("stdout"),
        stderr_digest=_digest("stderr"),
        output_truncated=output_truncated,
        evidence_digest=_digest("evidence-1"),
        references=(
            VerificationEvidenceRef(
                kind=VerificationEvidenceKind.FINAL_MUTATION_ATTESTATION,
                ref_id="attestation-1",
                digest=_digest("attestation-1"),
            ),
        ),
    )


def _positive_assessment(assessment: VerificationAssessment) -> VerificationAssessment:
    payload = dict(assessment.semantic_payload)
    payload["disposition"] = VerificationAssessmentDisposition.SATISFIED.value
    return replace(
        assessment,
        disposition=VerificationAssessmentDisposition.SATISFIED,
        assessment_digest=canonical_digest(payload),
    )


async def _make_db(path: Path) -> Database:
    database = Database(path)
    await database.connect()
    await database.run_migrations()
    return database


async def _make_task(
    database: Database,
    *,
    principal_id: str = OWNER,
    project_id: str = PROJECT,
) -> tuple[TaskManager, object, GoalSpec]:
    manager = TaskManager(
        db=database,
        principal_id=principal_id,
        project_id=project_id,
    )
    task = await manager.create("验证可信测试证据")
    await manager.update_status(
        task.id,
        TaskStatus.RUNNING,
        workspace_id=WORKSPACE,
        repository_id=REPOSITORY,
        base_sha=BASE_REVISION,
    )
    assert task.goal_spec is not None
    return manager, task, task.goal_spec


def test_trusted_verification_contracts_are_immutable_and_bounded() -> None:
    verification_input = _verification_input()
    evidence = _evidence(verification_input)
    verification_input = replace(
        verification_input,
        evidence=(evidence,),
        input_digest="",
    )

    assert isinstance(verification_input, TrustedVerificationInput)
    assert isinstance(evidence, VerificationExecutionEvidence)
    assert type(verification_input.requirements) is tuple
    assert type(verification_input.evidence) is tuple
    assert "raw stdout" not in verification_input.canonical_json()
    assert "raw stderr" not in verification_input.canonical_json()
    with pytest.raises((AttributeError, TypeError)):
        verification_input.requirements += ()  # type: ignore[misc]
    with pytest.raises((AttributeError, TypeError)):
        evidence.status = VerificationExecutionStatus.FAILED  # type: ignore[misc]


def test_authority_default_is_fail_closed_and_structural_adapter_is_explicit() -> None:
    verification_input = _verification_input()
    successful = _evidence(verification_input)
    verification_input = replace(
        verification_input,
        evidence=(successful,),
        input_digest="",
    )

    unavailable = TrustedVerificationAuthority().assess(
        verification_input,
        assessment_id="assessment-default",
    )
    assert unavailable.disposition is VerificationAssessmentDisposition.UNAVAILABLE

    accepted = TrustedVerificationAuthority(
        StructuralVerificationEvidenceValidator()
    ).assess(verification_input, assessment_id="assessment-structural")
    assert accepted.disposition is VerificationAssessmentDisposition.SATISFIED
    assert accepted.assessment_digest != unavailable.assessment_digest


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("workspace_id", "other-workspace"),
        ("repository_id", "other-repository"),
        ("base_revision", "other-base"),
        ("repository_generation", "other-generation"),
        ("change_identity", "other-change"),
    ),
)
def test_structural_authority_rejects_stale_evidence_snapshot(
    field: str, value: str
) -> None:
    verification_input = _verification_input()
    evidence = _evidence(verification_input)
    changed_input = replace(verification_input, **{field: value}, input_digest="")
    changed_input = replace(changed_input, evidence=(evidence,), input_digest="")

    assessment = TrustedVerificationAuthority(
        StructuralVerificationEvidenceValidator()
    ).assess(changed_input, assessment_id="assessment-stale")
    assert assessment.disposition is VerificationAssessmentDisposition.STALE


@pytest.mark.parametrize(
    ("status", "exit_code", "termination", "truncated", "expected"),
    (
        (
            VerificationExecutionStatus.FAILED,
            1,
            VerificationTermination.FAILED,
            False,
            VerificationAssessmentDisposition.FAILED,
        ),
        (
            VerificationExecutionStatus.TIMED_OUT,
            None,
            VerificationTermination.TIMED_OUT,
            False,
            VerificationAssessmentDisposition.INCONCLUSIVE,
        ),
        (
            VerificationExecutionStatus.PASSED,
            1,
            VerificationTermination.COMPLETED,
            False,
            VerificationAssessmentDisposition.STALE,
        ),
        (
            VerificationExecutionStatus.PASSED,
            0,
            VerificationTermination.COMPLETED,
            True,
            VerificationAssessmentDisposition.STALE,
        ),
    ),
)
def test_authority_never_treats_incomplete_success_shape_as_pass(
    status: VerificationExecutionStatus,
    exit_code: int | None,
    termination: VerificationTermination,
    truncated: bool,
    expected: VerificationAssessmentDisposition,
) -> None:
    verification_input = _verification_input()
    evidence = _evidence(
        verification_input,
        status=status,
        exit_code=exit_code,
        termination=termination,
        output_truncated=truncated,
    )
    verification_input = replace(
        verification_input,
        evidence=(evidence,),
        input_digest="",
    )

    assessment = TrustedVerificationAuthority(
        StructuralVerificationEvidenceValidator()
    ).assess(verification_input, assessment_id="assessment-shape")
    assert assessment.disposition is expected


class _FakeVerificationReadHandle:
    def __init__(self, *, authority_id: str = "authority-1") -> None:
        self.authority_id = authority_id

    def verification_status(self, verification_run_id: str) -> str:
        assert verification_run_id == "verification-1"
        return "passed"

    def verification_for_execution(self, execution_run_id: str) -> str:
        assert execution_run_id == "execution-1"
        return "verification-1"

    def success_binding(
        self, verification_run_id: str, *, execution_run_id: str | None = None
    ) -> tuple[str, str]:
        assert verification_run_id == "verification-1"
        assert execution_run_id == "execution-1"
        return self.authority_id, _digest("authority-1")

    def execution_status(self, execution_run_id: str) -> str:
        assert execution_run_id == "execution-1"
        return "verified"


class _FakeExecutionReadModel:
    def __init__(self, *, step_command_digest: str | None = None) -> None:
        self.step_command_digest = step_command_digest

    def get_execution_run(
        self,
        execution_run_id: str,
        *,
        authoritative_verification_reads_required: bool = False,
    ) -> object:
        assert execution_run_id == "execution-1"
        assert authoritative_verification_reads_required is True
        return SimpleNamespace(
            execution_run_id="execution-1",
            task_id="task-m7-4",
            plan_id="plan-1",
            plan_content_hash=_digest("plan-1"),
            workspace_id=WORKSPACE,
            repository_id=REPOSITORY,
            base_sha=BASE_REVISION,
            repository_generation=GENERATION,
            final_mutation_attestation_digest=_digest("attestation-1"),
            trusted_catalog_fingerprint=_digest("catalog"),
        )

    def get_final_mutation_attestation(self, execution_run_id: str) -> object:
        assert execution_run_id == "execution-1"
        return SimpleNamespace(
            generation=GENERATION,
            attestation_digest=_digest("attestation-1"),
        )

    def get_verification_step(self, step_run_id: str) -> object:
        assert step_run_id == "step-run-1"
        return SimpleNamespace(
            step_run_id="step-run-1",
            verification_run_id="verification-1",
            requirement_id="check-1",
            command_digest=(
                self.step_command_digest or _digest("pytest tests/test_target.py")
            ),
            status="passed",
            exit_code=0,
            stdout_digest=_digest("stdout"),
            stderr_digest=_digest("stderr"),
            output_truncated=False,
            completed_at=1.0,
        )


def test_m4_adapter_requires_the_existing_authority_identity_and_snapshot() -> None:
    verification_input = _verification_input()
    evidence = _evidence(verification_input)
    adapter = M4VerificationEvidenceValidator(
        verification_read_handle=_FakeVerificationReadHandle(),
        execution_read_model=_FakeExecutionReadModel(),
    )

    accepted = adapter.validate(
        verification_input=verification_input,
        evidence=evidence,
    )
    assert accepted.status is VerificationEvidenceValidationStatus.ACCEPTED

    rejected = M4VerificationEvidenceValidator(
        verification_read_handle=_FakeVerificationReadHandle(
            authority_id="wrong-authority"
        ),
        execution_read_model=_FakeExecutionReadModel(),
    ).validate(verification_input=verification_input, evidence=evidence)
    assert rejected.status is VerificationEvidenceValidationStatus.REJECTED

    rejected_step = M4VerificationEvidenceValidator(
        verification_read_handle=_FakeVerificationReadHandle(),
        execution_read_model=_FakeExecutionReadModel(
            step_command_digest=_digest("pytest tests/other_target.py")
        ),
    ).validate(verification_input=verification_input, evidence=evidence)
    assert rejected_step.status is VerificationEvidenceValidationStatus.REJECTED


@pytest.mark.asyncio
async def test_assessment_repository_binds_goal_task_scope_and_is_append_only(
    tmp_path: Path,
) -> None:
    database = await _make_db(tmp_path / "assessment-ledger.db")
    try:
        _manager, task, goal_spec = await _make_task(database)
        verification_input = _verification_input(
            task_id=task.id,
            goal_spec_id=goal_spec.goal_spec_id,
            goal_spec_digest=goal_spec.semantic_digest,
            cognitive_state=AgentCognitiveState.UNINITIALIZED,
            control_state_version=0,
            task_status=TaskStatus.RUNNING.value,
            published_plan_revision_id=None,
        )
        evidence = _evidence(verification_input)
        verification_input = replace(
            verification_input,
            evidence=(evidence,),
            input_digest="",
        )
        assessment = TrustedVerificationAuthority().assess(
            verification_input,
            assessment_id="assessment-1",
        )
        repository = database.verification_assessment_repository
        stored = await repository.append(
            assessment,
            principal_id=OWNER,
            project_id=PROJECT,
            created_at="2026-08-28T00:00:00",
        )
        assert stored.assessment_sequence == 1
        assert (
            await repository.get_by_id(
                "assessment-1", principal_id=OWNER, project_id=PROJECT
            )
        ) == stored
        assert (
            await repository.get_by_id(
                "assessment-1", principal_id="foreign", project_id=PROJECT
            )
        ) is None

        with pytest.raises(VerificationAssessmentConflictError):
            await repository.append(
                assessment,
                principal_id=OWNER,
                project_id=PROJECT,
                created_at="2026-08-28T00:00:01",
            )
        with pytest.raises(VerificationAssessmentBindingError):
            await repository.append(
                assessment,
                principal_id="foreign",
                project_id=PROJECT,
            )

        with pytest.raises(sqlite3.IntegrityError):
            async with database.transaction() as connection:
                await connection.execute(
                    "UPDATE agent_verification_assessments SET disposition='failed' "
                    "WHERE assessment_id=?",
                    ("assessment-1",),
                )
        with pytest.raises(sqlite3.IntegrityError):
            async with database.transaction() as connection:
                await connection.execute(
                    "DELETE FROM agent_verification_assessments "
                    "WHERE assessment_id=?",
                    ("assessment-1",),
                )
    finally:
        await database.close()


@pytest.mark.asyncio
async def test_positive_assessment_requires_current_snapshot_reader_and_rejects_stale(
    tmp_path: Path,
) -> None:
    database = await _make_db(tmp_path / "assessment-currentness.db")
    try:
        _manager, task, goal_spec = await _make_task(database)
        verification_input = _verification_input(
            task_id=task.id,
            goal_spec_id=goal_spec.goal_spec_id,
            goal_spec_digest=goal_spec.semantic_digest,
            cognitive_state=AgentCognitiveState.UNINITIALIZED,
            control_state_version=0,
            task_status=TaskStatus.RUNNING.value,
            published_plan_revision_id=None,
        )
        stale = TrustedVerificationAuthority().assess(
            verification_input,
            assessment_id="assessment-stale-source",
        )
        positive = _positive_assessment(stale)
        await database.verification_assessment_repository.append(
            positive,
            principal_id=OWNER,
            project_id=PROJECT,
        )
        assert (
            await database.verification_assessment_repository.get_current_for_task(
                task.id, principal_id=OWNER, project_id=PROJECT
            )
        ) is None

        current = VerificationCurrentSnapshot(
            task_id=task.id,
            principal_id=OWNER,
            project_id=PROJECT,
            goal_spec_id=goal_spec.goal_spec_id,
            goal_spec_digest=goal_spec.semantic_digest,
            cognitive_state=AgentCognitiveState.UNINITIALIZED,
            control_state_version=0,
            task_status=TaskStatus.RUNNING.value,
            workspace_id=WORKSPACE,
            repository_id=REPOSITORY,
            base_revision=BASE_REVISION,
            published_plan_revision_id=None,
            published_plan_revision_digest=None,
            repository_generation=GENERATION,
            change_identity=CHANGE_IDENTITY,
            policy_digest=positive.policy_digest,
            catalog_fingerprint=positive.catalog_fingerprint,
        )

        class _Reader:
            async def read_current_snapshot(
                self, *, connection: object, assessment: VerificationAssessment
            ) -> VerificationCurrentSnapshot:
                del connection, assessment
                return current

        repository = VerificationAssessmentRepository(
            database,
            current_snapshot_reader=_Reader(),
        )
        positive = replace(positive, assessment_id="assessment-current")
        stored = await repository.append(
            positive,
            principal_id=OWNER,
            project_id=PROJECT,
        )
        assert (
            await repository.get_current_for_task(
                task.id, principal_id=OWNER, project_id=PROJECT
            )
        ) == stored

        class _StaleReader(_Reader):
            async def read_current_snapshot(
                self, *, connection: object, assessment: VerificationAssessment
            ) -> VerificationCurrentSnapshot:
                del connection, assessment
                return replace(current, change_identity="different-change")

        stale_repository = VerificationAssessmentRepository(
            database,
            current_snapshot_reader=_StaleReader(),
        )
        assert (
            await stale_repository.get_current_for_task(
                task.id, principal_id=OWNER, project_id=PROJECT
            )
        ) is None
    finally:
        await database.close()


@pytest.mark.asyncio
async def test_trusted_fact_provider_only_projects_current_assessment(
    tmp_path: Path,
) -> None:
    database = await _make_db(tmp_path / "fact-provider.db")
    try:
        _manager, task, goal_spec = await _make_task(database)
        verification_input = _verification_input(
            task_id=task.id,
            goal_spec_id=goal_spec.goal_spec_id,
            goal_spec_digest=goal_spec.semantic_digest,
            cognitive_state=AgentCognitiveState.UNINITIALIZED,
            control_state_version=0,
            task_status=TaskStatus.RUNNING.value,
            published_plan_revision_id=None,
        )
        stale = TrustedVerificationAuthority().assess(
            verification_input,
            assessment_id="assessment-facts",
        )
        await database.verification_assessment_repository.append(
            stale,
            principal_id=OWNER,
            project_id=PROJECT,
        )
        provider = TrustedVerificationFactProvider(
            repository=database.verification_assessment_repository,
            principal_id=OWNER,
            project_id=PROJECT,
        )
        # The proposal object is not needed to prove the repository projection
        # boundary here; the provider rejects no-argument model claims by
        # requiring the typed proposal contract at runtime.
        from khaos.agent.control.completion_flow import (
            CompletionProposal,
            CompletionProposalTrigger,
        )

        facts = await provider.collect(
            proposal=CompletionProposal(
                task_id=task.id,
                turn_id="turn-1",
                attempt_id="attempt-1",
                trigger=CompletionProposalTrigger.MODEL_END_TURN,
            ),
            goal_spec=goal_spec,
            snapshot=CompletionEvaluationSnapshot(
                task_id=task.id,
                goal_spec_id=goal_spec.goal_spec_id,
                goal_spec_digest=goal_spec.semantic_digest,
                cognitive_state=AgentCognitiveState.UNINITIALIZED,
                control_state_version=0,
                task_status=TaskStatus.RUNNING.value,
                workspace_id=WORKSPACE,
            ),
        )
        assert facts.constraints
        assert len(facts.verification_facts) == 1
        assert facts.verification_facts[0].status.value == "unknown"
    finally:
        await database.close()


@pytest.mark.asyncio
async def test_v21_fresh_database_has_no_historical_assessment_backfill(
    tmp_path: Path,
) -> None:
    database = await _make_db(tmp_path / "fresh-v21.db")
    try:
        _manager, _task, _goal_spec = await _make_task(database)
        async with database.read_connection() as connection:
            row = await (
                await connection.execute(
                    "SELECT COUNT(*) AS count FROM agent_verification_assessments"
                )
            ).fetchone()
        assert row["count"] == 0
    finally:
        await database.close()


@pytest.mark.asyncio
async def test_assessment_service_emits_bounded_observability_events_only(
    tmp_path: Path,
) -> None:
    database = await _make_db(tmp_path / "assessment-events.db")
    try:
        _manager, task, goal_spec = await _make_task(database)
        verification_input = _verification_input(
            task_id=task.id,
            goal_spec_id=goal_spec.goal_spec_id,
            goal_spec_digest=goal_spec.semantic_digest,
            cognitive_state=AgentCognitiveState.UNINITIALIZED,
            control_state_version=0,
            task_status=TaskStatus.RUNNING.value,
            published_plan_revision_id=None,
        )

        class _Sink:
            def __init__(self) -> None:
                self.events = []

            async def emit_verification_event(self, event: object) -> None:
                self.events.append(event)

        sink = _Sink()
        publication = await TrustedVerificationService(
            authority=TrustedVerificationAuthority(),
            repository=database.verification_assessment_repository,
        ).assess_and_append(
            verification_input,
            principal_id=OWNER,
            project_id=PROJECT,
            assessment_id="assessment-events",
            event_sink=sink,  # type: ignore[arg-type]
        )
        assert publication.assessment.disposition is VerificationAssessmentDisposition.STALE
        assert [event.event_type for event in sink.events] == [
            VerificationEventType.STARTED,
            VerificationEventType.ASSESSED,
            VerificationEventType.STALE,
        ]
        assert all(
            "stdout" not in event.to_payload()
            and "stderr" not in event.to_payload()
            and "canonical_json" not in event.to_payload()
            for event in sink.events
        )
    finally:
        await database.close()


def test_current_snapshot_rejects_malformed_authority_digests() -> None:
    with pytest.raises(ValueError):
        VerificationCurrentSnapshot(
            task_id="task",
            principal_id=OWNER,
            project_id=PROJECT,
            goal_spec_id="goal",
            goal_spec_digest="not-a-digest",
            cognitive_state=AgentCognitiveState.UNINITIALIZED,
            control_state_version=0,
            task_status=TaskStatus.RUNNING.value,
            workspace_id=WORKSPACE,
            repository_id=REPOSITORY,
            base_revision=BASE_REVISION,
            published_plan_revision_id=None,
            published_plan_revision_digest=None,
            repository_generation=GENERATION,
            change_identity=CHANGE_IDENTITY,
            policy_digest=_digest("policy"),
            catalog_fingerprint=_digest("catalog"),
        )
