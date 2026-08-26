"""M7.1.4 immutable CompletionDecision and durable-ledger tests."""

from __future__ import annotations

import asyncio
import json
import sqlite3
from dataclasses import FrozenInstanceError, fields
from pathlib import Path
from typing import Any

import pytest
from khaos.agent.control.completion import (
    AssessmentStatus,
    CompletionDecision,
    CompletionDecisionValidationError,
    CompletionEvidenceKind,
    CompletionEvidenceRef,
    CompletionIssue,
    CompletionIssueCode,
    CompletionOutcome,
    CriterionAssessment,
    RequirementAssessment,
)
from khaos.agent.control.completion_repository import (
    CompletionDecisionBindingError,
    CompletionDecisionConflictError,
    CompletionDecisionIntegrityError,
)
from khaos.agent.control.goal import GoalSpec
from khaos.agent.control.state import AgentCognitiveState
from khaos.coding.task_manager import TaskManager, TaskStatus
from khaos.db import Database
from khaos.db.database import SCHEMA_MIGRATION_VERSION
from khaos.db.migrations._registry import (
    REGISTRY_BY_VERSION,
    compute_manifest_checksum,
    verify_source_integrity,
)

GOAL_DIGEST = "a" * 64


def _contract_decision(**overrides: Any) -> CompletionDecision:
    values: dict[str, Any] = {
        "decision_id": "decision-1",
        "task_id": "task-1",
        "goal_spec_id": "goal-1",
        "goal_spec_digest": GOAL_DIGEST,
        "cognitive_state": AgentCognitiveState.UNDERSTANDING,
        "control_state_version": 7,
        "task_status_at_evaluation": "running",
        "workspace_id": "workspace-1",
        "outcome": CompletionOutcome.REPLAN,
        "requirement_assessments": (
            RequirementAssessment(
                requirement_id="r-1",
                status=AssessmentStatus.UNKNOWN,
                evidence=(
                    CompletionEvidenceRef(
                        kind=CompletionEvidenceKind.TOOL_RESULT,
                        ref_id="tool-1",
                        digest="b" * 64,
                    ),
                ),
            ),
        ),
        "criterion_assessments": (
            CriterionAssessment(
                criterion_id="c-1",
                status=AssessmentStatus.UNSATISFIED,
            ),
        ),
        "evidence": (
            CompletionEvidenceRef(
                kind=CompletionEvidenceKind.TASK_STATE,
                ref_id="task-snapshot-1",
            ),
        ),
        "issues": (
            CompletionIssue(
                code=CompletionIssueCode.VERIFICATION_MISSING,
                subject_id="c-1",
                summary="尚未有可信验证记录",
            ),
        ),
    }
    values.update(overrides)
    return CompletionDecision.from_parts(**values)


async def _make_db(path: Path) -> Database:
    db = Database(path)
    await db.connect()
    await db.run_migrations()
    return db


async def _create_task(
    db: Database,
    *,
    principal_id: str = "alice",
    project_id: str = "project-a",
    goal: str = "完成一个中文目标",
):
    manager = TaskManager(
        db=db,
        principal_id=principal_id,
        project_id=project_id,
    )
    task = await manager.create(goal)
    assert task.goal_spec is not None
    return manager, task, task.goal_spec


async def _bind_workspace(manager: TaskManager, task: Any, workspace_id: str) -> None:
    """Persist the same task-level workspace projection used by AgentLoop."""
    await manager.update_status(task.id, task.status, workspace_id=workspace_id)
    assert task.metadata["workspace_id"] == workspace_id


def _task_decision(
    task: Any,
    spec: GoalSpec,
    *,
    decision_id: str = "decision-1",
    cognitive_state: AgentCognitiveState | None = None,
    control_state_version: int | None = None,
    task_status: str | None = None,
    goal_spec_id: str | None = None,
    goal_spec_digest: str | None = None,
    workspace_id: str | None = None,
    outcome: CompletionOutcome = CompletionOutcome.REPLAN,
) -> CompletionDecision:
    return CompletionDecision.from_parts(
        decision_id=decision_id,
        task_id=task.id,
        goal_spec_id=spec.goal_spec_id if goal_spec_id is None else goal_spec_id,
        goal_spec_digest=(
            spec.semantic_digest if goal_spec_digest is None else goal_spec_digest
        ),
        cognitive_state=(
            task.cognitive_state if cognitive_state is None else cognitive_state
        ),
        control_state_version=(
            task.control_state_version
            if control_state_version is None
            else control_state_version
        ),
        task_status_at_evaluation=(
            task.status.value if task_status is None else task_status
        ),
        workspace_id=workspace_id,
        outcome=outcome,
    )


def test_completion_vocab_and_derived_continuation_semantics() -> None:
    assert {outcome.value for outcome in CompletionOutcome} == {
        "complete",
        "replan",
        "blocked",
        "failed",
    }
    assert CompletionOutcome.COMPLETE.continuation_possible is False
    assert CompletionOutcome.FAILED.continuation_possible is False
    assert CompletionOutcome.REPLAN.continuation_possible is True
    assert CompletionOutcome.BLOCKED.continuation_possible is True
    assert not hasattr(CompletionDecision, "recoverable")


def test_contracts_are_deeply_immutable_and_typed() -> None:
    evidence = CompletionEvidenceRef(
        kind=CompletionEvidenceKind.VERIFICATION_RUN,
        ref_id="run-1",
    )
    assessment = RequirementAssessment(
        requirement_id="r-1",
        status=AssessmentStatus.SATISFIED,
        evidence=(evidence,),
    )
    decision = _contract_decision(
        requirement_assessments=(assessment,),
        evidence=(evidence,),
    )

    with pytest.raises(FrozenInstanceError):
        evidence.ref_id = "changed"  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        decision.outcome = CompletionOutcome.COMPLETE  # type: ignore[misc]
    with pytest.raises(AttributeError):
        decision.evidence.append(evidence)  # type: ignore[attr-defined]
    assert isinstance(decision.requirement_assessments[0], RequirementAssessment)
    assert isinstance(decision.criterion_assessments[0], CriterionAssessment)
    assert all(field.name != "recoverable" for field in fields(CompletionDecision))
    assert all(
        field.name not in {"trusted", "authoritative", "verified"}
        for field in fields(CompletionEvidenceRef)
    )
    with pytest.raises(CompletionDecisionValidationError):
        CompletionDecision.from_parts(
            decision_id="bad",
            task_id="task-1",
            goal_spec_id="goal-1",
            goal_spec_digest=GOAL_DIGEST,
            cognitive_state=AgentCognitiveState.UNDERSTANDING,
            control_state_version=0,
            task_status_at_evaluation="pending",
            workspace_id=None,
            outcome=CompletionOutcome.REPLAN,
            evidence=[],
        )


def test_deterministic_unicode_round_trip_and_digest_ordering() -> None:
    first = _contract_decision(
        decision_id="decision-a",
        requirement_assessments=(
            RequirementAssessment("r-2", AssessmentStatus.UNKNOWN),
            RequirementAssessment("r-1", AssessmentStatus.SATISFIED),
        ),
        evidence=(
            CompletionEvidenceRef(CompletionEvidenceKind.TOOL_RESULT, "z"),
            CompletionEvidenceRef(CompletionEvidenceKind.GOAL_SPEC, "a"),
        ),
    )
    reordered = _contract_decision(
        decision_id="decision-b",
        requirement_assessments=(
            RequirementAssessment("r-1", AssessmentStatus.SATISFIED),
            RequirementAssessment("r-2", AssessmentStatus.UNKNOWN),
        ),
        evidence=(
            CompletionEvidenceRef(CompletionEvidenceKind.GOAL_SPEC, "a"),
            CompletionEvidenceRef(CompletionEvidenceKind.TOOL_RESULT, "z"),
        ),
    )
    assert first.decision_digest == reordered.decision_digest
    assert "尚未有可信验证记录" in first.canonical_json()
    decoded = CompletionDecision.from_canonical_json(first.canonical_json())
    assert decoded.canonical_json() == first.canonical_json()
    assert decoded.decision_digest == first.decision_digest

    changed_version = _contract_decision(control_state_version=8)
    changed_goal = _contract_decision(goal_spec_digest="c" * 64)
    changed_outcome = _contract_decision(outcome=CompletionOutcome.COMPLETE)
    changed_assessment = _contract_decision(
        requirement_assessments=(
            RequirementAssessment("r-1", AssessmentStatus.SATISFIED),
        )
    )
    changed_evidence = _contract_decision(
        evidence=(CompletionEvidenceRef(CompletionEvidenceKind.REVIEW, "review-1"),)
    )
    assert changed_version.decision_digest != first.decision_digest
    assert changed_goal.decision_digest != first.decision_digest
    assert changed_outcome.decision_digest != first.decision_digest
    assert changed_assessment.decision_digest != first.decision_digest
    assert changed_evidence.decision_digest != first.decision_digest


def test_storage_identity_is_excluded_but_semantic_changes_are_bound() -> None:
    first = _contract_decision(decision_id="one")
    second = _contract_decision(decision_id="two")
    assert first.decision_digest == second.decision_digest
    assert "decision_id" not in first.semantic_payload
    assert "decision_digest" not in first.semantic_payload
    assert "principal_id" not in first.semantic_payload
    assert "project_id" not in first.semantic_payload
    assert "created_at" not in first.semantic_payload
    assert "decision_sequence" not in first.semantic_payload


@pytest.mark.asyncio
async def test_append_and_owner_scoped_readback(tmp_path: Path) -> None:
    db = await _make_db(tmp_path / "append.db")
    try:
        _, task, spec = await _create_task(db)
        decision = _task_decision(task, spec, outcome=CompletionOutcome.COMPLETE)
        stored = await db.completion_decision_repository.append(
            decision,
            principal_id="alice",
            project_id="project-a",
            created_at="2026-08-26T00:00:00",
        )
        assert stored.decision == decision
        assert stored.decision_sequence == 1
        assert stored.created_at == "2026-08-26T00:00:00"
        assert stored.outcome is CompletionOutcome.COMPLETE
        assert stored.continuation_possible is False
        assert (
            await db.completion_decision_repository.get_by_id(
                decision.decision_id,
                principal_id="alice",
                project_id="project-a",
            )
            == stored
        )
        assert (
            await db.completion_decision_repository.get_by_id(
                decision.decision_id,
                principal_id="bob",
                project_id="project-a",
            )
            is None
        )
        assert (
            await db.completion_decision_repository.list_for_task(
                task.id,
                principal_id="alice",
                project_id="project-b",
            )
            == []
        )
    finally:
        await db.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("task_workspace_id", "decision_workspace_id", "expected_sequence"),
    [
        ("workspace-1", "workspace-1", 1),
        ("workspace-1", "workspace-2", None),
        ("workspace-1", None, None),
        (None, "workspace-1", None),
        (None, None, 1),
    ],
    ids=[
        "matching-workspace",
        "different-workspace",
        "missing-decision-workspace",
        "unexpected-decision-workspace",
        "both-unbound",
    ],
)
async def test_append_validates_workspace_snapshot_binding(
    tmp_path: Path,
    task_workspace_id: str | None,
    decision_workspace_id: str | None,
    expected_sequence: int | None,
) -> None:
    db = await _make_db(tmp_path / "workspace-binding.db")
    try:
        manager, task, spec = await _create_task(db)
        if task_workspace_id is not None:
            await _bind_workspace(manager, task, task_workspace_id)
        decision = _task_decision(
            task,
            spec,
            decision_id=f"workspace-{task_workspace_id}-{decision_workspace_id}",
            workspace_id=decision_workspace_id,
        )
        if expected_sequence is None:
            with pytest.raises(CompletionDecisionBindingError, match="workspace"):
                await db.completion_decision_repository.append(
                    decision,
                    principal_id="alice",
                    project_id="project-a",
                )
        else:
            stored = await db.completion_decision_repository.append(
                decision,
                principal_id="alice",
                project_id="project-a",
            )
            assert stored.decision.workspace_id == task_workspace_id
            assert stored.decision_sequence == expected_sequence
    finally:
        await db.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "malformed_state_json",
    [
        "{not-json",
        "[]",
        json.dumps({"metadata": []}),
        json.dumps({"metadata": {"workspace_id": ""}}),
        json.dumps({"metadata": {"workspace_id": 42}}),
    ],
    ids=[
        "invalid-json",
        "non-object-root",
        "non-object-metadata",
        "empty-workspace-id",
        "non-string-workspace-id",
    ],
)
async def test_malformed_durable_workspace_projection_fails_closed(
    tmp_path: Path,
    malformed_state_json: str,
) -> None:
    db = await _make_db(tmp_path / "malformed-workspace.db")
    try:
        _, task, spec = await _create_task(db)
        async with db.transaction() as conn:
            await conn.execute(
                "UPDATE coding_tasks SET state_json = ? WHERE id = ?",
                (malformed_state_json, task.id),
            )
        with pytest.raises(CompletionDecisionIntegrityError, match="workspace|state_json|metadata"):
            await db.completion_decision_repository.append(
                _task_decision(task, spec, decision_id="malformed-workspace"),
                principal_id="alice",
                project_id="project-a",
            )
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_sequence_is_repository_allocated_and_latest_is_durable(
    tmp_path: Path,
) -> None:
    db = await _make_db(tmp_path / "sequence.db")
    try:
        _, task, spec = await _create_task(db)
        first = await db.completion_decision_repository.append(
            _task_decision(task, spec, decision_id="decision-1"),
            principal_id="alice",
            project_id="project-a",
        )
        second = await db.completion_decision_repository.append(
            _task_decision(
                task,
                spec,
                decision_id="decision-2",
                outcome=CompletionOutcome.BLOCKED,
            ),
            principal_id="alice",
            project_id="project-a",
        )
        assert (first.decision_sequence, second.decision_sequence) == (1, 2)
        assert [
            item.decision_id
            for item in await db.completion_decision_repository.list_for_task(
                task.id,
                principal_id="alice",
                project_id="project-a",
            )
        ] == ["decision-1", "decision-2"]
        latest = await db.completion_decision_repository.get_latest_for_task(
            task.id,
            principal_id="alice",
            project_id="project-a",
        )
        assert latest is not None
        assert latest.decision_id == "decision-2"
        with pytest.raises(CompletionDecisionConflictError):
            await db.completion_decision_repository.append(
                _task_decision(task, spec, decision_id="decision-1"),
                principal_id="alice",
                project_id="project-a",
            )
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_concurrent_appends_allocate_distinct_monotonic_sequences(
    tmp_path: Path,
) -> None:
    db = await _make_db(tmp_path / "concurrent-sequence.db")
    try:
        _, task, spec = await _create_task(db)
        decisions = [
            _task_decision(task, spec, decision_id="concurrent-1"),
            _task_decision(task, spec, decision_id="concurrent-2"),
        ]
        stored = await asyncio.gather(
            *(
                db.completion_decision_repository.append(
                    decision,
                    principal_id="alice",
                    project_id="project-a",
                )
                for decision in decisions
            )
        )
        assert sorted(item.decision_sequence for item in stored) == [1, 2]
        rows = await db.completion_decision_repository.list_for_task(
            task.id,
            principal_id="alice",
            project_id="project-a",
        )
        assert [item.decision_sequence for item in rows] == [1, 2]
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_database_ledger_is_append_only(tmp_path: Path) -> None:
    db = await _make_db(tmp_path / "immutable.db")
    try:
        _, task, spec = await _create_task(db)
        decision = _task_decision(task, spec)
        await db.completion_decision_repository.append(
            decision,
            principal_id="alice",
            project_id="project-a",
        )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            async with db.transaction() as conn:
                await conn.execute(
                    "UPDATE agent_completion_decisions SET canonical_json = ? "
                    "WHERE decision_id = ?",
                    ("tampered", decision.decision_id),
                )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            async with db.transaction() as conn:
                await conn.execute(
                    "DELETE FROM agent_completion_decisions WHERE decision_id = ?",
                    (decision.decision_id,),
                )
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_append_rejects_task_goal_and_cognitive_binding_mismatches(
    tmp_path: Path,
) -> None:
    db = await _make_db(tmp_path / "binding.db")
    try:
        _, task, spec = await _create_task(db)
        repo = db.completion_decision_repository
        with pytest.raises(CompletionDecisionBindingError):
            await repo.append(
                _task_decision(task, spec, decision_id="missing-goal"),
                principal_id="bob",
                project_id="project-a",
            )
        with pytest.raises(CompletionDecisionBindingError):
            await repo.append(
                _task_decision(
                    task,
                    spec,
                    decision_id="wrong-goal-id",
                    goal_spec_id="other-goal",
                ),
                principal_id="alice",
                project_id="project-a",
            )
        with pytest.raises(CompletionDecisionBindingError):
            await repo.append(
                _task_decision(
                    task,
                    spec,
                    decision_id="wrong-goal-digest",
                    goal_spec_digest="f" * 64,
                ),
                principal_id="alice",
                project_id="project-a",
            )
        with pytest.raises(CompletionDecisionBindingError):
            await repo.append(
                _task_decision(
                    task,
                    spec,
                    decision_id="wrong-state",
                    cognitive_state=AgentCognitiveState.UNDERSTANDING,
                ),
                principal_id="alice",
                project_id="project-a",
            )
        with pytest.raises(CompletionDecisionBindingError):
            await repo.append(
                _task_decision(
                    task,
                    spec,
                    decision_id="wrong-version",
                    control_state_version=1,
                ),
                principal_id="alice",
                project_id="project-a",
            )
        with pytest.raises(CompletionDecisionBindingError):
            await repo.append(
                CompletionDecision.from_parts(
                    decision_id="wrong-task",
                    task_id="other-task",
                    goal_spec_id=spec.goal_spec_id,
                    goal_spec_digest=spec.semantic_digest,
                    cognitive_state=task.cognitive_state,
                    control_state_version=task.control_state_version,
                    task_status_at_evaluation=task.status.value,
                    workspace_id=None,
                    outcome=CompletionOutcome.REPLAN,
                ),
                principal_id="alice",
                project_id="project-a",
            )
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_append_rejects_nonexistent_task_and_terminal_projection_is_passive(
    tmp_path: Path,
) -> None:
    db = await _make_db(tmp_path / "nonexistent.db")
    try:
        _, task, spec = await _create_task(db)
        decision = _task_decision(task, spec)
        nonexistent = CompletionDecision.from_parts(
            decision_id="nonexistent",
            task_id="not-a-task",
            goal_spec_id=spec.goal_spec_id,
            goal_spec_digest=spec.semantic_digest,
            cognitive_state=task.cognitive_state,
            control_state_version=task.control_state_version,
            task_status_at_evaluation=task.status.value,
            workspace_id=None,
            outcome=CompletionOutcome.COMPLETE,
        )
        with pytest.raises(CompletionDecisionBindingError):
            await db.completion_decision_repository.append(
                nonexistent,
                principal_id="alice",
                project_id="project-a",
            )
        await db.completion_decision_repository.append(
            decision,
            principal_id="alice",
            project_id="project-a",
        )
        assert task.status is TaskStatus.PENDING
        assert task.status is not TaskStatus.COMPLETED
    finally:
        await db.close()


async def _drop_decision_update_trigger(db: Database) -> None:
    async with db.transaction() as conn:
        await conn.execute(
            "DROP TRIGGER trg_agent_completion_decisions_immutable_update"
        )


@pytest.mark.asyncio
async def test_malformed_digest_schema_and_task_binding_rows_fail_closed(
    tmp_path: Path,
) -> None:
    db = await _make_db(tmp_path / "integrity.db")
    try:
        _, task, spec = await _create_task(db)
        decision = _task_decision(task, spec)
        await db.completion_decision_repository.append(
            decision,
            principal_id="alice",
            project_id="project-a",
        )
        await _drop_decision_update_trigger(db)
        async with db.transaction() as conn:
            await conn.execute(
                "UPDATE agent_completion_decisions SET canonical_json = ? "
                "WHERE decision_id = ?",
                ("{not-json", decision.decision_id),
            )
        with pytest.raises(CompletionDecisionIntegrityError):
            await db.completion_decision_repository.get_by_id(
                decision.decision_id,
                principal_id="alice",
                project_id="project-a",
            )
    finally:
        await db.close()

    db = await _make_db(tmp_path / "integrity-digest.db")
    try:
        _, task, spec = await _create_task(db)
        decision = _task_decision(task, spec)
        await db.completion_decision_repository.append(
            decision,
            principal_id="alice",
            project_id="project-a",
        )
        await _drop_decision_update_trigger(db)
        async with db.transaction() as conn:
            await conn.execute(
                "UPDATE agent_completion_decisions SET decision_digest = ? "
                "WHERE decision_id = ?",
                ("f" * 64, decision.decision_id),
            )
        with pytest.raises(CompletionDecisionIntegrityError):
            await db.completion_decision_repository.get_latest_for_task(
                task.id,
                principal_id="alice",
                project_id="project-a",
            )
    finally:
        await db.close()

    db = await _make_db(tmp_path / "integrity-schema.db")
    try:
        _, task, spec = await _create_task(db)
        decision = _task_decision(task, spec)
        await db.completion_decision_repository.append(
            decision,
            principal_id="alice",
            project_id="project-a",
        )
        await _drop_decision_update_trigger(db)
        async with db.transaction() as conn:
            await conn.execute(
                "UPDATE agent_completion_decisions SET schema_version = 99 "
                "WHERE decision_id = ?",
                (decision.decision_id,),
            )
        with pytest.raises(CompletionDecisionIntegrityError):
            await db.completion_decision_repository.get_by_id(
                decision.decision_id,
                principal_id="alice",
                project_id="project-a",
            )
    finally:
        await db.close()

    db = await _make_db(tmp_path / "integrity-task.db")
    try:
        _, task, spec = await _create_task(db)
        decision = _task_decision(task, spec)
        await db.completion_decision_repository.append(
            decision,
            principal_id="alice",
            project_id="project-a",
        )
        await _drop_decision_update_trigger(db)
        async with db.transaction() as conn:
            await conn.execute(
                "UPDATE agent_completion_decisions SET task_id = ? "
                "WHERE decision_id = ?",
                ("different-task", decision.decision_id),
            )
        with pytest.raises(CompletionDecisionIntegrityError):
            await db.completion_decision_repository.get_by_id(
                decision.decision_id,
                principal_id="alice",
                project_id="project-a",
            )
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_restart_preserves_decision_and_existing_blocked_semantics(
    tmp_path: Path,
) -> None:
    path = tmp_path / "restart.db"
    db = await _make_db(path)
    _, task, spec = await _create_task(db, goal="重启后仍能读取完成评估快照")
    manager = TaskManager(db=db, principal_id="alice", project_id="project-a")
    loaded_before = await manager.get(task.id)
    assert loaded_before is None
    await manager.load()
    task = await manager.get(task.id)
    assert task is not None
    await manager.initialize_cognitive_state(task.id)
    await manager.update_status(
        task.id,
        TaskStatus.RUNNING,
        workspace_id="workspace-restart",
    )
    decision = _task_decision(task, spec, workspace_id="workspace-restart")
    await db.completion_decision_repository.append(
        decision,
        principal_id="alice",
        project_id="project-a",
    )
    await db.close()

    reopened = await _make_db(path)
    try:
        restored_manager = TaskManager(
            db=reopened,
            principal_id="alice",
            project_id="project-a",
        )
        await restored_manager.load()
        restored = await restored_manager.get(task.id)
        assert restored is not None
        assert restored.status is TaskStatus.BLOCKED
        assert restored.cognitive_state is AgentCognitiveState.UNDERSTANDING
        assert restored.control_state_version == 1
        assert restored.metadata["workspace_id"] == "workspace-restart"
        stored = await reopened.completion_decision_repository.get_latest_for_task(
            task.id,
            principal_id="alice",
            project_id="project-a",
        )
        assert stored is not None
        assert stored.decision_id == decision.decision_id
        assert stored.decision_digest == decision.decision_digest
        assert stored.decision.task_status_at_evaluation == "running"
        assert restored.status is not TaskStatus.COMPLETED
    finally:
        await reopened.close()


@pytest.mark.asyncio
async def test_fresh_v18_and_v17_to_v18_upgrade_do_not_backfill_decisions(
    tmp_path: Path,
) -> None:
    fresh = await _make_db(tmp_path / "fresh.db")
    try:
        async with fresh.read_connection() as conn:
            table = await (
                await conn.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table' "
                    "AND name = 'agent_completion_decisions'"
                )
            ).fetchone()
            assert table["name"] == "agent_completion_decisions"
        assert SCHEMA_MIGRATION_VERSION == 18
    finally:
        await fresh.close()

    path = tmp_path / "upgrade.db"
    db = await _make_db(path)
    manager = TaskManager(db=db, principal_id="alice", project_id="project-a")
    completed = await manager.create("历史完成任务")
    failed = await manager.create("历史失败任务")
    await manager.update_status(completed.id, TaskStatus.COMPLETED)
    await manager.update_status(failed.id, TaskStatus.FAILED)
    await db.close()

    raw = sqlite3.connect(path)
    try:
        raw.execute("DROP TRIGGER trg_agent_completion_decisions_immutable_update")
        raw.execute("DROP TRIGGER trg_agent_completion_decisions_immutable_delete")
        raw.execute("DROP INDEX idx_agent_completion_decisions_owner_task_sequence")
        raw.execute("DROP TABLE agent_completion_decisions")
        raw.execute("DELETE FROM schema_migrations WHERE version = 18")
        raw.commit()
    finally:
        raw.close()

    upgraded = await _make_db(path)
    try:
        async with upgraded.read_connection() as conn:
            rows = await (
                await conn.execute(
                    "SELECT COUNT(*) AS count FROM agent_completion_decisions"
                )
            ).fetchone()
            assert rows["count"] == 0
        await upgraded.run_migrations()
        async with upgraded.read_connection() as conn:
            row = await (
                await conn.execute(
                    "SELECT version FROM schema_migrations ORDER BY version DESC LIMIT 1"
                )
            ).fetchone()
            assert row["version"] == SCHEMA_MIGRATION_VERSION
    finally:
        await upgraded.close()


def test_v18_migration_source_integrity() -> None:
    verify_source_integrity()
    spec = REGISTRY_BY_VERSION[18]
    assert spec.sha256 == compute_manifest_checksum(spec)
    assert spec.sql_files == ("0018_completion_decisions.sql",)
    assert spec.migrator_symbols == ("_apply_v18_upgrades",)


def test_malformed_canonical_contract_is_rejected() -> None:
    decision = _contract_decision()
    payload = json.loads(decision.canonical_json())
    payload["unexpected"] = True
    with pytest.raises(CompletionDecisionValidationError):
        CompletionDecision.from_canonical_json(json.dumps(payload))
