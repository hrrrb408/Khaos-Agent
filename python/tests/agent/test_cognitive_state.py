"""M7.1.3 Agent Cognitive State contract and CAS regression tests."""

from __future__ import annotations

import asyncio
import json
import sqlite3
from pathlib import Path

import pytest
from khaos.agent.control.state import (
    LEGAL_COGNITIVE_TRANSITIONS,
    AgentCognitiveState,
    AgentCognitiveStateMachine,
    CognitiveTransitionValidation,
)
from khaos.agent.control.state_repository import (
    CognitiveStateIntegrityError,
    CognitiveTransitionStatus,
)
from khaos.coding.task_manager import TaskManager, TaskStatus
from khaos.db import Database
from khaos.db.database import SCHEMA_MIGRATION_VERSION
from khaos.db.migrations._registry import verify_source_integrity


async def _make_db(path: Path) -> Database:
    db = Database(path)
    await db.connect()
    await db.run_migrations()
    return db


def test_cognitive_state_enum_and_closed_transition_graph() -> None:
    assert AgentCognitiveState("understanding") is AgentCognitiveState.UNDERSTANDING
    assert AgentCognitiveState.parse("completion_check") is AgentCognitiveState.COMPLETION_CHECK
    with pytest.raises(ValueError):
        AgentCognitiveState.parse("completed")

    expected = {
        AgentCognitiveState.UNINITIALIZED: {
            AgentCognitiveState.UNDERSTANDING,
        },
        AgentCognitiveState.UNDERSTANDING: {
            AgentCognitiveState.EXPLORING,
            AgentCognitiveState.PLANNING,
            AgentCognitiveState.IMPLEMENTING,
        },
        AgentCognitiveState.EXPLORING: {
            AgentCognitiveState.PLANNING,
            AgentCognitiveState.IMPLEMENTING,
            AgentCognitiveState.DIAGNOSING,
        },
        AgentCognitiveState.PLANNING: {
            AgentCognitiveState.EXPLORING,
            AgentCognitiveState.IMPLEMENTING,
            AgentCognitiveState.REPLANNING,
        },
        AgentCognitiveState.IMPLEMENTING: {
            AgentCognitiveState.EXPLORING,
            AgentCognitiveState.VERIFYING,
            AgentCognitiveState.DIAGNOSING,
        },
        AgentCognitiveState.VERIFYING: {
            AgentCognitiveState.REVIEWING,
            AgentCognitiveState.DIAGNOSING,
            AgentCognitiveState.RECOVERING,
        },
        AgentCognitiveState.DIAGNOSING: {
            AgentCognitiveState.EXPLORING,
            AgentCognitiveState.RECOVERING,
            AgentCognitiveState.REPLANNING,
        },
        AgentCognitiveState.RECOVERING: {
            AgentCognitiveState.IMPLEMENTING,
            AgentCognitiveState.VERIFYING,
            AgentCognitiveState.REPLANNING,
        },
        AgentCognitiveState.REPLANNING: {
            AgentCognitiveState.EXPLORING,
            AgentCognitiveState.PLANNING,
        },
        AgentCognitiveState.REVIEWING: {
            AgentCognitiveState.COMPLETION_CHECK,
            AgentCognitiveState.DIAGNOSING,
            AgentCognitiveState.REPLANNING,
        },
        AgentCognitiveState.COMPLETION_CHECK: {
            AgentCognitiveState.REPLANNING,
            AgentCognitiveState.REVIEWING,
        },
    }
    assert {
        state: set(targets)
        for state, targets in LEGAL_COGNITIVE_TRANSITIONS.items()
    } == expected
    with pytest.raises(TypeError):
        LEGAL_COGNITIVE_TRANSITIONS[AgentCognitiveState.UNINITIALIZED] = frozenset()  # type: ignore[index]
    assert AgentCognitiveStateMachine.validate_transition(
        AgentCognitiveState.IMPLEMENTING,
        AgentCognitiveState.IMPLEMENTING,
    ) is CognitiveTransitionValidation.UNCHANGED
    assert not AgentCognitiveStateMachine.can_transition(
        AgentCognitiveState.UNINITIALIZED,
        AgentCognitiveState.PLANNING,
    )
    assert "completed" not in {state.value for state in AgentCognitiveState}
    assert "failed" not in {state.value for state in AgentCognitiveState}
    assert "cancelled" not in {state.value for state in AgentCognitiveState}
    assert "blocked" not in {state.value for state in AgentCognitiveState}


@pytest.mark.asyncio
async def test_cas_initialization_version_and_self_transition(tmp_path: Path) -> None:
    db = await _make_db(tmp_path / "cas.db")
    try:
        manager = TaskManager(db=db, principal_id="alice", project_id="project-a")
        task = await manager.create("initialize cognitive state")
        assert task.cognitive_state is AgentCognitiveState.UNINITIALIZED
        assert task.control_state_version == 0

        initialized = await manager.initialize_cognitive_state(task.id)
        assert initialized.status is CognitiveTransitionStatus.UPDATED
        assert initialized.current_state is AgentCognitiveState.UNDERSTANDING
        assert initialized.control_state_version == 1
        assert task.cognitive_state is AgentCognitiveState.UNDERSTANDING
        assert task.control_state_version == 1

        unchanged = await manager.transition_cognitive_state(
            task.id,
            target=AgentCognitiveState.UNDERSTANDING,
        )
        assert unchanged.status is CognitiveTransitionStatus.UNCHANGED
        assert unchanged.control_state_version == 1
        assert task.control_state_version == 1

        async with db.read_connection() as conn:
            row = await (
                await conn.execute(
                    "SELECT cognitive_state, control_state_version "
                    "FROM coding_tasks WHERE id = ?",
                    (task.id,),
                )
            ).fetchone()
        assert row["cognitive_state"] == "understanding"
        assert row["control_state_version"] == 1
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_illegal_and_stale_cognitive_transitions_are_typed(tmp_path: Path) -> None:
    db = await _make_db(tmp_path / "stale.db")
    try:
        manager = TaskManager(db=db, principal_id="alice", project_id="project-a")
        task = await manager.create("state transition")

        illegal = await manager.transition_cognitive_state(
            task.id,
            target=AgentCognitiveState.PLANNING,
        )
        assert illegal.status is CognitiveTransitionStatus.ILLEGAL_TRANSITION
        assert task.cognitive_state is AgentCognitiveState.UNINITIALIZED

        assert (await manager.initialize_cognitive_state(task.id)).updated
        stale_version = await manager.transition_cognitive_state(
            task.id,
            target=AgentCognitiveState.EXPLORING,
            expected_state=AgentCognitiveState.UNDERSTANDING,
            expected_version=0,
        )
        assert stale_version.status is CognitiveTransitionStatus.STALE_VERSION
        assert task.cognitive_state is AgentCognitiveState.UNDERSTANDING
        assert task.control_state_version == 1

        stale_state = await manager.transition_cognitive_state(
            task.id,
            target=AgentCognitiveState.PLANNING,
            expected_state=AgentCognitiveState.EXPLORING,
            expected_version=1,
        )
        assert stale_state.status is CognitiveTransitionStatus.STALE_STATE
        assert stale_state.current_state is AgentCognitiveState.UNDERSTANDING
        assert task.cognitive_state is AgentCognitiveState.UNDERSTANDING
        assert task.control_state_version == 1
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_owner_project_and_terminal_boundaries_fail_closed(tmp_path: Path) -> None:
    db = await _make_db(tmp_path / "owners.db")
    try:
        manager = TaskManager(db=db, principal_id="alice", project_id="project-a")
        task = await manager.create("owner boundary")
        await manager.initialize_cognitive_state(task.id)
        repository = db.agent_control_state_repository

        foreign = await repository.compare_and_transition(
            task.id,
            principal_id="bob",
            project_id="project-a",
            expected_state=AgentCognitiveState.UNINITIALIZED,
            expected_version=0,
            target_state=AgentCognitiveState.UNDERSTANDING,
        )
        assert foreign.status is CognitiveTransitionStatus.NOT_FOUND
        foreign_project = await repository.get_snapshot(
            task.id,
            principal_id="alice",
            project_id="project-b",
        )
        assert foreign_project is None

        await manager.update_status(task.id, TaskStatus.FAILED)
        terminal = await manager.transition_cognitive_state(
            task.id,
            target=AgentCognitiveState.EXPLORING,
            expected_state=AgentCognitiveState.UNDERSTANDING,
            expected_version=1,
        )
        assert terminal.status is CognitiveTransitionStatus.TERMINAL_TASK
        assert task.cognitive_state is AgentCognitiveState.UNDERSTANDING
        assert task.control_state_version == 1
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_ordinary_task_persistence_does_not_overwrite_control_state(
    tmp_path: Path,
) -> None:
    db = await _make_db(tmp_path / "projection.db")
    try:
        manager = TaskManager(db=db, principal_id="alice", project_id="project-a")
        task = await manager.create("projection boundary")
        await manager.initialize_cognitive_state(task.id)
        await manager.add_test_result(task.id, {"passed": 1})
        await manager.track_file_modified(task.id, "src/example.py")
        await manager.update_status(task.id, TaskStatus.RUNNING)
        with pytest.raises(ValueError, match="cognitive-state CAS owner"):
            await manager.update_status(
                task.id,
                TaskStatus.RUNNING,
                cognitive_state=AgentCognitiveState.PLANNING,
            )
        raw = sqlite3.connect(tmp_path / "projection.db")
        try:
            state_row = raw.execute(
                "SELECT state_json FROM coding_tasks WHERE id = ?",
                (task.id,),
            ).fetchone()
            state_projection = json.loads(state_row[0])
            state_projection["cognitive_state"] = "planning"
            state_projection["control_state_version"] = 999
            raw.execute(
                "UPDATE coding_tasks SET state_json = ? WHERE id = ?",
                (json.dumps(state_projection), task.id),
            )
            raw.commit()
        finally:
            raw.close()

        projected = await db.list_coding_tasks(
            principal_id="alice", project_id="project-a"
        )
        assert projected[0]["cognitive_state"] == "understanding"
        assert projected[0]["control_state_version"] == 1
        async with db.read_connection() as conn:
            row = await (
                await conn.execute(
                    "SELECT cognitive_state, control_state_version, status "
                    "FROM coding_tasks WHERE id = ?",
                    (task.id,),
                )
            ).fetchone()
        assert row["cognitive_state"] == "understanding"
        assert row["control_state_version"] == 1
        assert row["status"] == TaskStatus.RUNNING.value
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_two_managers_one_cas_winner(tmp_path: Path) -> None:
    db = await _make_db(tmp_path / "concurrency.db")
    try:
        creator = TaskManager(db=db, principal_id="alice", project_id="project-a")
        task = await creator.create("concurrent transition")
        first = TaskManager(db=db, principal_id="alice", project_id="project-a")
        second = TaskManager(db=db, principal_id="alice", project_id="project-a")
        await first.load()
        await second.load()

        results = await asyncio.gather(
            first.initialize_cognitive_state(task.id),
            second.initialize_cognitive_state(task.id),
        )
        assert sorted(result.status.value for result in results) == [
            "stale_version",
            "updated",
        ]
        snapshot = await db.agent_control_state_repository.get_snapshot(
            task.id,
            principal_id="alice",
            project_id="project-a",
        )
        assert snapshot is not None
        assert snapshot.cognitive_state is AgentCognitiveState.UNDERSTANDING
        assert snapshot.control_state_version == 1
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_restart_preserves_cognitive_projection_and_goal_spec(
    tmp_path: Path,
) -> None:
    path = tmp_path / "restart.db"
    db = await _make_db(path)
    manager = TaskManager(db=db, principal_id="alice", project_id="project-a")
    task = await manager.create("restart preserves state")
    await manager.initialize_cognitive_state(task.id)
    transitioned = await manager.transition_cognitive_state(
        task.id,
        target=AgentCognitiveState.IMPLEMENTING,
    )
    assert transitioned.updated
    original_goal_id = task.goal_spec_id
    original_digest = task.goal_spec_digest
    await manager.update_status(task.id, TaskStatus.RUNNING)
    await db.close()

    reopened = await _make_db(path)
    try:
        restored = TaskManager(
            db=reopened,
            principal_id="alice",
            project_id="project-a",
        )
        await restored.load()
        loaded = await restored.get(task.id)
        assert loaded is not None
        assert loaded.status is TaskStatus.BLOCKED
        assert loaded.cognitive_state is AgentCognitiveState.IMPLEMENTING
        assert loaded.control_state_version == 2
        assert loaded.goal_spec_id == original_goal_id
        assert loaded.goal_spec_digest == original_digest
    finally:
        await reopened.close()


@pytest.mark.asyncio
async def test_malformed_cognitive_state_is_rejected_by_typed_repository(
    tmp_path: Path,
) -> None:
    db = await _make_db(tmp_path / "malformed.db")
    try:
        manager = TaskManager(db=db, principal_id="alice", project_id="project-a")
        task = await manager.create("malformed state")
        raw = sqlite3.connect(tmp_path / "malformed.db")
        try:
            raw.execute("PRAGMA ignore_check_constraints = ON")
            raw.execute(
                "UPDATE coding_tasks SET cognitive_state = ? WHERE id = ?",
                ("completed", task.id),
            )
            raw.commit()
        finally:
            raw.close()
        with pytest.raises(CognitiveStateIntegrityError):
            await db.agent_control_state_repository.get_snapshot(
                task.id,
                principal_id="alice",
                project_id="project-a",
            )
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_v16_to_v17_migration_is_conservative_and_idempotent(
    tmp_path: Path,
) -> None:
    path = tmp_path / "v16.db"
    db = await _make_db(path)
    manager = TaskManager(db=db, principal_id="alice", project_id="project-a")
    task = await manager.create("legacy cognitive migration")
    await db.close()

    raw = sqlite3.connect(path)
    try:
        # Historical terminal rows are fixture data for the migration test.
        # Generic TaskManager persistence is intentionally not a completion
        # authority after M7.1.7.
        state_row = raw.execute(
            "SELECT state_json FROM coding_tasks WHERE id = ?",
            (task.id,),
        ).fetchone()
        state = json.loads(state_row[0])
        state["status"] = TaskStatus.COMPLETED.value
        raw.execute(
            "UPDATE coding_tasks SET status = ?, state_json = ? WHERE id = ?",
            (TaskStatus.COMPLETED.value, json.dumps(state), task.id),
        )
        raw.execute(
            "DELETE FROM schema_migrations WHERE version = ?",
            (SCHEMA_MIGRATION_VERSION,),
        )
        raw.execute("ALTER TABLE coding_tasks DROP COLUMN cognitive_state")
        raw.execute(
            "ALTER TABLE coding_tasks DROP COLUMN control_state_version"
        )
        raw.commit()
    finally:
        raw.close()

    upgraded = await _make_db(path)
    try:
        snapshot = await upgraded.agent_control_state_repository.get_snapshot(
            task.id,
            principal_id="alice",
            project_id="project-a",
        )
        assert snapshot is not None
        assert snapshot.cognitive_state is AgentCognitiveState.UNINITIALIZED
        assert snapshot.control_state_version == 0
        assert snapshot.task_status == TaskStatus.COMPLETED.value

        await upgraded.run_migrations()
        async with upgraded.read_connection() as conn:
            columns = {
                row["name"]
                for row in await (
                    await conn.execute("PRAGMA table_info(coding_tasks)")
                ).fetchall()
            }
            ledger = await (
                await conn.execute(
                    "SELECT COUNT(*) AS count, MAX(version) AS version "
                    "FROM schema_migrations"
                )
            ).fetchone()
        assert {"cognitive_state", "control_state_version"} <= columns
        assert ledger["count"] == SCHEMA_MIGRATION_VERSION
        assert ledger["version"] == SCHEMA_MIGRATION_VERSION
    finally:
        await upgraded.close()


def test_migration_source_integrity_includes_v17() -> None:
    verify_source_integrity()
