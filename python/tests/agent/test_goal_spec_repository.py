"""Durable owner/integrity tests for GoalSpecRepository."""

from __future__ import annotations

import sqlite3

import pytest
from khaos.agent.control.goal import GoalSpec
from khaos.agent.control.goal_repository import (
    GoalSpecConflictError,
    GoalSpecIntegrityError,
)
from khaos.db import Database


@pytest.fixture
async def db(tmp_path):
    database = Database(tmp_path / "goal-spec.db")
    await database.connect()
    await database.run_migrations()
    yield database
    await database.close()


async def test_insert_read_and_owner_scoped_lookup(db: Database) -> None:
    spec = GoalSpec.from_user_goal("修复并保留中文原文", goal_spec_id="goal-1")
    repo = db.goal_spec_repository

    await repo.insert(
        spec,
        task_id="task-1",
        principal_id="alice",
        project_id="project-a",
        created_at="2026-08-26T00:00:00",
    )

    assert await repo.get_by_id(
        "goal-1", principal_id="alice", project_id="project-a"
    ) == spec
    assert await repo.get_for_task(
        "task-1", principal_id="alice", project_id="project-a"
    ) == spec
    assert await repo.get_by_id(
        "goal-1", principal_id="bob", project_id="project-a"
    ) is None
    assert await repo.get_for_task(
        "task-1", principal_id="alice", project_id="project-b"
    ) is None


async def test_duplicate_task_or_identity_is_explicit_conflict(db: Database) -> None:
    repo = db.goal_spec_repository
    first = GoalSpec.from_user_goal("first", goal_spec_id="goal-1")
    second = GoalSpec.from_user_goal("second", goal_spec_id="goal-2")
    await repo.insert(
        first,
        task_id="task-1",
        principal_id="alice",
        project_id="project-a",
    )

    with pytest.raises(GoalSpecConflictError):
        await repo.insert(
            first,
            task_id="task-1",
            principal_id="alice",
            project_id="project-a",
        )
    with pytest.raises(GoalSpecConflictError):
        await repo.insert(
            second,
            task_id="task-1",
            principal_id="bob",
            project_id="project-b",
        )
    assert await repo.get_for_task(
        "task-1", principal_id="alice", project_id="project-a"
    ) == first
    assert not hasattr(repo, "update")


async def test_malformed_and_digest_mismatched_rows_fail_closed(db: Database) -> None:
    async with db.transaction() as conn:
        await conn.execute(
            """
            INSERT INTO agent_goal_specs
                (goal_spec_id, task_id, principal_id, project_id,
                 schema_version, semantic_digest, canonical_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "malformed",
                "task-malformed",
                "alice",
                "project-a",
                1,
                "0" * 64,
                "{not-json",
                "2026-08-26T00:00:00",
            ),
        )
    with pytest.raises(GoalSpecIntegrityError):
        await db.goal_spec_repository.get_for_task(
            "task-malformed", principal_id="alice", project_id="project-a"
        )

    valid = GoalSpec.from_user_goal("digest row", goal_spec_id="digest-goal")
    async with db.transaction() as conn:
        await conn.execute(
            """
            INSERT INTO agent_goal_specs
                (goal_spec_id, task_id, principal_id, project_id,
                 schema_version, semantic_digest, canonical_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                valid.goal_spec_id,
                "task-digest",
                "alice",
                "project-a",
                valid.schema_version,
                "f" * 64,
                valid.canonical_json(),
                "2026-08-26T00:00:00",
            ),
        )
    with pytest.raises(GoalSpecIntegrityError):
        await db.goal_spec_repository.get_for_task(
            "task-digest", principal_id="alice", project_id="project-a"
        )


async def test_database_immutability_triggers_reject_update_and_delete(
    db: Database,
) -> None:
    spec = GoalSpec.from_user_goal("immutable", goal_spec_id="goal-immutable")
    await db.goal_spec_repository.insert(
        spec,
        task_id="task-immutable",
        principal_id="alice",
        project_id="project-a",
    )
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        async with db.transaction() as conn:
            await conn.execute(
                "UPDATE agent_goal_specs SET canonical_json = ? WHERE goal_spec_id = ?",
                ("tampered", spec.goal_spec_id),
            )
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        async with db.transaction() as conn:
            await conn.execute(
                "DELETE FROM agent_goal_specs WHERE goal_spec_id = ?",
                (spec.goal_spec_id,),
            )
