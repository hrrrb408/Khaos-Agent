"""M7.1.7 closure amendment: durable task lifecycle CAS regressions."""

from __future__ import annotations

import asyncio
import copy
import json
import uuid
from pathlib import Path

import pytest
from khaos.agent.control.completion import (
    AssessmentStatus,
    CompletionDecision,
    RequirementAssessment,
)
from khaos.agent.control.completion_evaluator import (
    CompletionEvaluator,
)
from khaos.agent.control.completion_gate import (
    CompletionAuthorityResult,
    CompletionAuthorityStatus,
    CompletionGate,
    CompletionGateStatus,
)
from khaos.agent.control.state import AgentCognitiveState
from khaos.coding.task_manager import (
    CodingTask,
    TaskManager,
    TaskStatus,
    TransitionResult,
)
from khaos.db import Database, TaskLifecycleConflictError
from khaos.db.database import OwnerMismatchError


class _AllowCompletionAuthority:
    """Test-only policy bound to the exact decision being projected."""

    async def authorize(
        self,
        *,
        goal_spec,
        decision,
        principal_id,
        project_id,
    ) -> CompletionAuthorityResult:
        del principal_id, project_id
        return CompletionAuthorityResult(
            task_id=decision.task_id,
            goal_spec_id=goal_spec.goal_spec_id,
            goal_spec_digest=goal_spec.semantic_digest,
            decision_id=decision.decision_id,
            decision_digest=decision.decision_digest,
            status=CompletionAuthorityStatus.AUTHORIZED,
        )


async def _make_db(path: Path) -> Database:
    database = Database(path)
    await database.connect()
    await database.run_migrations()
    return database


async def _create_running_task(
    database: Database,
    *,
    principal_id: str = "alice",
    project_id: str = "project-a",
) -> tuple[TaskManager, CodingTask]:
    manager = TaskManager(
        db=database,
        principal_id=principal_id,
        project_id=project_id,
    )
    task = await manager.create("修复任务并保留终端状态")
    assert await manager.update_status(task.id, TaskStatus.RUNNING) is TransitionResult.UPDATED
    initialized = await manager.initialize_cognitive_state(task.id)
    assert initialized.updated
    return manager, task


async def _append_complete_decision(
    database: Database,
    task: CodingTask,
    *,
    principal_id: str = "alice",
    project_id: str = "project-a",
) -> CompletionDecision:
    goal_spec = await database.goal_spec_repository.get_for_task(
        task.id,
        principal_id=principal_id,
        project_id=project_id,
    )
    assert goal_spec is not None
    snapshot = await database.completion_decision_repository.read_current_task_snapshot(
        task.id,
        principal_id=principal_id,
        project_id=project_id,
        goal_spec=goal_spec,
    )
    assert snapshot is not None
    decision = CompletionEvaluator.evaluate(
        decision_id=f"decision-{uuid.uuid4().hex}",
        goal_spec=goal_spec,
        snapshot=snapshot,
        requirement_assessments=tuple(
            RequirementAssessment(
                requirement_id=requirement.requirement_id,
                status=AssessmentStatus.SATISFIED,
            )
            for requirement in goal_spec.requirements
            if requirement.required
        ),
    )
    await database.completion_decision_repository.append(
        decision,
        principal_id=principal_id,
        project_id=project_id,
    )
    return decision


async def _read_physical_task_state(
    database: Database, task_id: str
) -> tuple[str, dict[str, object]]:
    async with database.read_connection() as connection:
        cursor = await connection.execute(
            "SELECT status, state_json FROM coding_tasks WHERE id = ?",
            (task_id,),
        )
        row = await cursor.fetchone()
    assert row is not None
    return row["status"], json.loads(row["state_json"])


def _gate(database: Database, *, task_projection=None) -> CompletionGate:
    return CompletionGate(
        decision_repository=database.completion_decision_repository,
        goal_spec_repository=database.goal_spec_repository,
        principal_id="alice",
        project_id="project-a",
        authority_policy=_AllowCompletionAuthority(),
        task_projection=task_projection,
    )


@pytest.mark.asyncio
async def test_generic_task_manager_completion_is_rejected(tmp_path: Path) -> None:
    database = await _make_db(tmp_path / "generic-completion.db")
    try:
        manager, task = await _create_running_task(database)

        assert (
            await manager.update_status(task.id, TaskStatus.COMPLETED)
            is TransitionResult.INVALID_TRANSITION
        )
        assert (
            await manager.transition(
                task.id,
                expected={TaskStatus.RUNNING},
                target=TaskStatus.COMPLETED,
            )
            is TransitionResult.INVALID_TRANSITION
        )
        rows = await database.list_coding_tasks(
            principal_id="alice", project_id="project-a"
        )
        assert rows[0]["status"] == TaskStatus.RUNNING.value
    finally:
        await database.close()


@pytest.mark.asyncio
async def test_database_generic_path_rejects_active_to_completed(tmp_path: Path) -> None:
    database = await _make_db(tmp_path / "database-completion.db")
    try:
        _manager, task = await _create_running_task(database)
        task_dict = task.to_dict(include_internal=True)
        task_dict["status"] = TaskStatus.COMPLETED.value

        with pytest.raises(TaskLifecycleConflictError):
            await database.update_coding_task(
                task_dict,
                principal_id="alice",
                project_id="project-a",
                expected_status=TaskStatus.RUNNING.value,
            )
        rows = await database.list_coding_tasks(
            principal_id="alice", project_id="project-a"
        )
        assert rows[0]["status"] == TaskStatus.RUNNING.value
    finally:
        await database.close()


@pytest.mark.asyncio
async def test_terminal_status_cannot_move_back_through_generic_database_path(
    tmp_path: Path,
) -> None:
    database = await _make_db(tmp_path / "terminal-monotonic.db")
    try:
        manager, task = await _create_running_task(database)
        assert await manager.update_status(task.id, TaskStatus.FAILED) is TransitionResult.UPDATED
        stale = task.to_dict(include_internal=True)
        stale["status"] = TaskStatus.RUNNING.value

        with pytest.raises(TaskLifecycleConflictError):
            await database.update_coding_task(
                stale,
                principal_id="alice",
                project_id="project-a",
                expected_status=TaskStatus.FAILED.value,
            )
        rows = await database.list_coding_tasks(
            principal_id="alice", project_id="project-a"
        )
        assert rows[0]["status"] == TaskStatus.FAILED.value
    finally:
        await database.close()


@pytest.mark.asyncio
async def test_stale_lifecycle_write_restores_task_manager_status_projection(
    tmp_path: Path,
) -> None:
    database = await _make_db(tmp_path / "stale-projection.db")
    try:
        manager, task = await _create_running_task(database)
        decision = await _append_complete_decision(database, task)
        gate_result = await _gate(database).evaluate(decision.decision_id)
        assert gate_result.status is CompletionGateStatus.COMPLETED

        with pytest.raises(TaskLifecycleConflictError):
            await manager.update_status(task.id, TaskStatus.BLOCKED)
        assert (await manager.get(task.id)).status is TaskStatus.RUNNING
        physical_status, state = await _read_physical_task_state(database, task.id)
        assert physical_status == TaskStatus.COMPLETED.value
        assert state["status"] == TaskStatus.COMPLETED.value
    finally:
        await database.close()


@pytest.mark.asyncio
async def test_same_runtime_stale_activity_write_cannot_restore_completed(
    tmp_path: Path,
) -> None:
    database = await _make_db(tmp_path / "same-runtime-race.db")
    stale_write: asyncio.Task[None] | None = None
    release_persist = asyncio.Event()
    persist_entered = asyncio.Event()
    original_update = database.update_coding_task

    async def blocked_update(
        task_data,
        *,
        principal_id: str,
        project_id: str,
        expected_status: str,
    ) -> None:
        persist_entered.set()
        await release_persist.wait()
        await original_update(
            task_data,
            principal_id=principal_id,
            project_id=project_id,
            expected_status=expected_status,
        )

    try:
        manager, task = await _create_running_task(database)
        decision = await _append_complete_decision(database, task)
        database.update_coding_task = blocked_update  # type: ignore[method-assign]

        # The manager lock is held while the stale activity snapshot waits
        # immediately before its database write.  Gate uses its own writer
        # transaction and does not depend on that cache lock.
        stale_write = asyncio.create_task(
            manager.track_file_viewed(task.id, "stale.py")
        )
        await asyncio.wait_for(persist_entered.wait(), timeout=1)
        gate_result = await _gate(database).evaluate(decision.decision_id)
        assert gate_result.status is CompletionGateStatus.COMPLETED

        release_persist.set()
        with pytest.raises(TaskLifecycleConflictError):
            await stale_write
        stale_write = None

        rows = await database.list_coding_tasks(
            principal_id="alice", project_id="project-a"
        )
        assert rows[0]["status"] == TaskStatus.COMPLETED.value
        physical_status, state = await _read_physical_task_state(database, task.id)
        assert physical_status == TaskStatus.COMPLETED.value
        assert state["status"] == "completed"
    finally:
        release_persist.set()
        if stale_write is not None:
            try:
                await stale_write
            except TaskLifecycleConflictError:
                pass
        database.update_coding_task = original_update  # type: ignore[method-assign]
        await database.close()


@pytest.mark.asyncio
async def test_cross_manager_stale_activity_write_is_rejected(tmp_path: Path) -> None:
    database = await _make_db(tmp_path / "cross-manager-race.db")
    try:
        manager_a, task = await _create_running_task(database)
        manager_b = TaskManager(
            db=database,
            principal_id="alice",
            project_id="project-a",
        )
        # Independent stale cache setup; TaskManager.load() is intentionally
        # not used as a refresh or race-resolution primitive.
        manager_b._tasks[task.id] = copy.deepcopy(task)
        manager_b._tasks[task.id]._persisted = True
        decision = await _append_complete_decision(database, task)

        result = await _gate(database).evaluate(decision.decision_id)
        assert result.status is CompletionGateStatus.COMPLETED

        with pytest.raises(TaskLifecycleConflictError):
            await manager_b.track_file_viewed(task.id, "stale-manager.py")
        rows = await database.list_coding_tasks(
            principal_id="alice", project_id="project-a"
        )
        assert rows[0]["status"] == TaskStatus.COMPLETED.value
        physical_status, state = await _read_physical_task_state(database, task.id)
        assert physical_status == TaskStatus.COMPLETED.value
        assert state["status"] == "completed"
        assert (await manager_a.get(task.id)).status is TaskStatus.RUNNING
    finally:
        await database.close()


@pytest.mark.asyncio
async def test_completed_task_allows_same_status_metadata_persistence(
    tmp_path: Path,
) -> None:
    database = await _make_db(tmp_path / "post-gate-metadata.db")
    try:
        manager, task = await _create_running_task(database)
        decision = await _append_complete_decision(database, task)
        result = await _gate(database, task_projection=manager).evaluate(
            decision.decision_id
        )
        assert result.status is CompletionGateStatus.COMPLETED
        assert (await manager.get(task.id)).status is TaskStatus.COMPLETED

        assert (
            await manager.update_status(
                task.id,
                TaskStatus.COMPLETED,
                error="post-gate observation",
            )
            is TransitionResult.UNCHANGED
        )
        rows = await database.list_coding_tasks(
            principal_id="alice", project_id="project-a"
        )
        assert rows[0]["status"] == TaskStatus.COMPLETED.value
        _physical_status, state = await _read_physical_task_state(database, task.id)
        assert state["status"] == TaskStatus.COMPLETED.value
        assert state["error"] == "post-gate observation"
    finally:
        await database.close()


@pytest.mark.asyncio
async def test_owner_mismatch_remains_distinct_from_lifecycle_conflict(
    tmp_path: Path,
) -> None:
    database = await _make_db(tmp_path / "typed-conflicts.db")
    try:
        _manager, task = await _create_running_task(database)
        task_dict = task.to_dict(include_internal=True)
        with pytest.raises(TaskLifecycleConflictError):
            await database.update_coding_task(
                task_dict,
                principal_id="alice",
                project_id="project-a",
                expected_status=TaskStatus.PENDING.value,
            )
        with pytest.raises(OwnerMismatchError):
            await database.update_coding_task(
                task_dict,
                principal_id="mallory",
                project_id="project-a",
                expected_status=TaskStatus.RUNNING.value,
            )
    finally:
        await database.close()


def test_cognitive_state_contract_remains_independent() -> None:
    assert AgentCognitiveState.COMPLETION_CHECK.value == "completion_check"
    assert "completed" not in {state.value for state in AgentCognitiveState}
