"""M7.1.2 TaskManager atomicity, recovery, and migration tests."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from khaos.agent.control.goal_repository import GoalSpecIntegrityError
from khaos.coding.task_manager import TaskManager, TaskStatus
from khaos.db import Database
from khaos.db.database import SCHEMA_MIGRATION_VERSION


async def _make_db(path: Path) -> Database:
    db = Database(path)
    await db.connect()
    await db.run_migrations()
    return db


async def _count(db: Database, table: str) -> int:
    async with db.read_connection() as conn:
        row = await (
            await conn.execute(f"SELECT COUNT(*) AS n FROM {table}")
        ).fetchone()
    return int(row["n"])


async def test_task_creation_persists_one_canonical_goal_spec(tmp_path: Path) -> None:
    db = await _make_db(tmp_path / "create.db")
    try:
        manager = TaskManager(
            db=db, principal_id="alice", project_id="project-a"
        )
        task = await manager.create("  修复审批重复消费，并补充回归测试  ")
        spec = await db.goal_spec_repository.get_for_task(
            task.id, principal_id="alice", project_id="project-a"
        )

        assert spec is not None
        assert task.goal == spec.raw_goal
        assert task.goal_spec_id == spec.goal_spec_id
        assert task.goal_spec_digest == spec.semantic_digest
        assert spec.requirements[0].description == spec.normalized_goal
        assert spec.acceptance_criteria == ()
        assert spec.constraints == ()
        assert spec.requested_artifacts == ()
        assert spec.verification_expectations == ()
        assert await _count(db, "coding_tasks") == 1
        assert await _count(db, "agent_goal_specs") == 1
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_task_manager_rejects_repository_from_another_database(
    tmp_path: Path,
) -> None:
    db = await _make_db(tmp_path / "primary.db")
    other = await _make_db(tmp_path / "other.db")
    try:
        with pytest.raises(ValueError, match="share the TaskManager database"):
            TaskManager(
                db=db,
                principal_id="alice",
                project_id="project-a",
                goal_spec_repository=other.goal_spec_repository,
            )
    finally:
        await db.close()
        await other.close()


@pytest.mark.asyncio
async def test_goal_spec_insert_failure_rolls_back_task_and_event(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db = await _make_db(tmp_path / "goal-failure.db")
    try:
        manager = TaskManager(
            db=db, principal_id="alice", project_id="project-a"
        )
        published: list[dict] = []
        monkeypatch.setattr(
            manager,
            "_publish_task_event",
            lambda task: published.append(task.to_dict()),
        )

        async def fail_insert(*args: object, **kwargs: object) -> None:
            del args, kwargs
            raise RuntimeError("injected GoalSpec failure")

        monkeypatch.setattr(manager.goal_spec_repository, "insert", fail_insert)
        with pytest.raises(RuntimeError, match="injected GoalSpec failure"):
            await manager.create("atomic goal")

        assert await manager.list_all() == []
        assert published == []
        assert await _count(db, "coding_tasks") == 0
        assert await _count(db, "agent_goal_specs") == 0
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_coding_task_insert_failure_rolls_back_without_goal_spec(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db = await _make_db(tmp_path / "task-failure.db")
    try:
        manager = TaskManager(
            db=db, principal_id="alice", project_id="project-a"
        )

        async def fail_insert(*args: object, **kwargs: object) -> None:
            del args, kwargs
            raise RuntimeError("injected task failure")

        monkeypatch.setattr(db, "insert_coding_task", fail_insert)
        with pytest.raises(RuntimeError, match="injected task failure"):
            await manager.create("atomic task")

        assert await manager.list_all() == []
        assert await _count(db, "coding_tasks") == 0
        assert await _count(db, "agent_goal_specs") == 0
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_restart_resolves_same_goal_spec_and_preserves_blocked_semantics(
    tmp_path: Path,
) -> None:
    path = tmp_path / "restart.db"
    db = await _make_db(path)
    manager = TaskManager(
        db=db, principal_id="alice", project_id="project-a"
    )
    task = await manager.create("long running goal")
    await manager.update_status(task.id, TaskStatus.RUNNING)
    original_id = task.goal_spec_id
    original_digest = task.goal_spec_digest
    await db.close()

    reopened = await _make_db(path)
    try:
        restored = TaskManager(
            db=reopened, principal_id="alice", project_id="project-a"
        )
        await restored.load()
        loaded = await restored.get(task.id)
        assert loaded is not None
        assert loaded.goal == "long running goal"
        assert loaded.goal_spec_id == original_id
        assert loaded.goal_spec_digest == original_digest
        assert loaded.goal_spec is not None
        assert loaded.goal_spec.raw_goal == "long running goal"
        assert loaded.status is TaskStatus.BLOCKED
        assert loaded.error == "interrupted by process restart"
    finally:
        await reopened.close()


@pytest.mark.asyncio
async def test_task_updates_cannot_rewrite_or_drift_goal_spec_projection(
    tmp_path: Path,
) -> None:
    db = await _make_db(tmp_path / "projection.db")
    try:
        manager = TaskManager(
            db=db, principal_id="alice", project_id="project-a"
        )
        task = await manager.create("canonical goal")
        original_id = task.goal_spec_id
        original_digest = task.goal_spec_digest

        with pytest.raises(ValueError, match="GoalSpec.raw_goal"):
            await manager.update_status(
                task.id, TaskStatus.PENDING, goal="rewritten goal"
            )
        with pytest.raises(ValueError, match="immutable"):
            await manager.update_status(
                task.id, TaskStatus.PENDING, goal_spec_id="other"
            )

        task.goal = "directly drifted"
        with pytest.raises(ValueError, match="GoalSpec.raw_goal"):
            await manager.update_status(task.id, TaskStatus.PENDING, error="x")
        task.goal = "canonical goal"

        restored = TaskManager(
            db=db, principal_id="alice", project_id="project-a"
        )
        await restored.load()
        loaded = await restored.get(task.id)
        assert loaded is not None
        assert loaded.goal == "canonical goal"
        assert loaded.goal_spec_id == original_id
        assert loaded.goal_spec_digest == original_digest
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_task_manager_load_fails_closed_when_goal_spec_is_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    db = await _make_db(tmp_path / "missing.db")
    try:
        manager = TaskManager(
            db=db, principal_id="alice", project_id="project-a"
        )
        await manager.create("missing canonical declaration")
        restored = TaskManager(
            db=db, principal_id="alice", project_id="project-a"
        )

        async def missing_goal_spec(*args: object, **kwargs: object):
            del args, kwargs

        monkeypatch.setattr(
            restored.goal_spec_repository,
            "get_for_task",
            missing_goal_spec,
        )
        with pytest.raises(GoalSpecIntegrityError):
            await restored.load()
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_v15_to_v16_backfill_is_conservative_and_idempotent(
    tmp_path: Path,
) -> None:
    path = tmp_path / "v15-upgrade.db"
    db = await _make_db(path)
    await db.close()

    raw = sqlite3.connect(path)
    try:
        raw.execute(
            "INSERT INTO coding_tasks "
            "(id, goal, status, state_json, created_at, updated_at, principal_id, project_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "legacy-en",
                "preserve exact goal",
                "completed",
                json.dumps({"legacy": True}),
                "2026-08-26T00:00:00",
                "2026-08-26T00:00:00",
                "alice",
                "project-a",
            ),
        )
        raw.execute(
            "INSERT INTO coding_tasks "
            "(id, goal, status, state_json, created_at, updated_at, principal_id, project_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "legacy-zh",
                "修复中文目标并保留路径 /src/审批.py",
                "failed",
                json.dumps({"legacy": "中文"}, ensure_ascii=False),
                "2026-08-26T00:00:01",
                "2026-08-26T00:00:01",
                "bob",
                "project-b",
            ),
        )
        raw.execute(
            "DELETE FROM schema_migrations WHERE version = ?",
            (SCHEMA_MIGRATION_VERSION,),
        )
        raw.execute("DROP TABLE agent_goal_specs")
        raw.commit()
    finally:
        raw.close()

    upgraded = await _make_db(path)
    try:
        rows = await upgraded.list_coding_tasks(principal_id=None)
        assert {row["id"] for row in rows} == {"legacy-en", "legacy-zh"}
        for task_id, principal_id, project_id, expected_goal in (
            ("legacy-en", "alice", "project-a", "preserve exact goal"),
            (
                "legacy-zh",
                "bob",
                "project-b",
                "修复中文目标并保留路径 /src/审批.py",
            ),
        ):
            spec = await upgraded.goal_spec_repository.get_for_task(
                task_id,
                principal_id=principal_id,
                project_id=project_id,
            )
            assert spec is not None
            assert spec.raw_goal == expected_goal
            assert spec.requirements[0].source.value == "explicit_user"
            assert spec.acceptance_criteria == ()
            assert spec.verification_expectations == ()
            row = next(item for item in rows if item["id"] == task_id)
            assert row["goal_spec_id"] == spec.goal_spec_id
            assert row["goal_spec_digest"] == spec.semantic_digest

        before = await upgraded.goal_spec_repository.get_for_task(
            "legacy-zh", principal_id="bob", project_id="project-b"
        )
        await upgraded.run_migrations()
        after = await upgraded.goal_spec_repository.get_for_task(
            "legacy-zh", principal_id="bob", project_id="project-b"
        )
        assert before == after
        assert await _count(upgraded, "agent_goal_specs") == 2
    finally:
        await upgraded.close()


@pytest.mark.asyncio
async def test_malformed_legacy_task_rolls_back_v16_backfill(
    tmp_path: Path,
) -> None:
    path = tmp_path / "malformed-upgrade.db"
    db = await _make_db(path)
    await db.close()

    raw = sqlite3.connect(path)
    try:
        raw.execute(
            "INSERT INTO coding_tasks "
            "(id, goal, status, state_json, created_at, updated_at, principal_id, project_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "malformed",
                "cannot safely backfill",
                "failed",
                "not-json",
                "2026-08-26T00:00:00",
                "2026-08-26T00:00:00",
                "alice",
                "project-a",
            ),
        )
        raw.execute(
            "DELETE FROM schema_migrations WHERE version = ?",
            (SCHEMA_MIGRATION_VERSION,),
        )
        raw.execute("DROP TABLE agent_goal_specs")
        raw.commit()
    finally:
        raw.close()

    failed = Database(path)
    await failed.connect()
    try:
        with pytest.raises(RuntimeError, match="malformed state_json"):
            await failed.run_migrations()
        async with failed.read_connection() as conn:
            table = await (
                await conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' "
                    "AND name='agent_goal_specs'"
                )
            ).fetchone()
            ledger = await (
                await conn.execute(
                    "SELECT 1 FROM schema_migrations WHERE version = ?",
                    (SCHEMA_MIGRATION_VERSION,),
                )
            ).fetchone()
        assert table is None
        assert ledger is None
    finally:
        await failed.close()
