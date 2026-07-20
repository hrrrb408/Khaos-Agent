"""M4 Batch 3.1.16B-1 — Scheduler Generation Schema and State Root Wiring.

Acceptance tests for the security-context snapshot columns added to
``scheduled_tasks``:

  1.  ``policy_digest`` column exists after migration.
  2.  ``project_id`` column exists after migration.
  3.  Migration is idempotent (re-running doesn't error).
  4.  ``CronEngine`` constructed with ``policy_digest`` stamps it on
      every newly created task.
  5.  ``CronEngine`` constructed with ``project_id`` stamps it on
      every newly created task.
  6.  Engine without ``policy_digest`` stamps empty string (fail-closed
      default — B-2 will quarantine such tasks at enforcement time).
  7.  ``_task_from_row`` restores ``policy_digest`` and ``project_id``
      after a restart.
  8.  Tasks created under different ``policy_digest`` values are both
      loadable by their respective engines (no cross-contamination at
      the schema level — B-2 adds enforcement).
  9.  ``insert_scheduled_task`` persists ``policy_digest`` and
      ``project_id`` atomically with the row.
  10. The ``idx_scheduled_tasks_policy`` index exists for efficient
      policy-scoped lookups.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from khaos.db import Database
from khaos.scheduler import CronEngine, ScheduleConfig, TaskStatus


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


async def _make_db(path) -> Database:
    p = Path(path)
    if p.is_dir() or (not p.exists() and not p.name.endswith(".db")):
        p = p / "khaos.db"
    db = Database(p)
    await db.connect()
    await db.run_migrations()
    return db


async def _execute_noop(task_id: str, prompt: str, principal_id: str = "") -> str:
    """No-op executor for testing — returns the prompt unchanged."""
    return prompt


def _make_engine(
    db, *, project_id: str = "", policy_digest: str = "", tick_interval: float = 999.0
) -> CronEngine:
    """Construct a CronEngine with a long tick interval to avoid the
    tick loop firing during tests (we only test create/load, not
    scheduling)."""
    return CronEngine(
        db=db,
        executor=_execute_noop,
        tick_interval=tick_interval,
        project_id=project_id,
        policy_digest=policy_digest,
    )


# ---------------------------------------------------------------------------
# 1-3. Schema migration
# ---------------------------------------------------------------------------


async def test_acceptance_1_policy_digest_column_exists(tmp_path):
    """B1-1: ``policy_digest`` column exists after migration."""
    db = await _make_db(tmp_path)
    conn = await db._require_conn()
    cursor = await conn.execute("PRAGMA table_info(scheduled_tasks)")
    columns = {row[1] for row in await cursor.fetchall()}
    assert "policy_digest" in columns, (
        "policy_digest column must exist on scheduled_tasks after migration"
    )
    await db.close()


async def test_acceptance_2_project_id_column_exists(tmp_path):
    """B1-1: ``project_id`` column exists after migration."""
    db = await _make_db(tmp_path)
    conn = await db._require_conn()
    cursor = await conn.execute("PRAGMA table_info(scheduled_tasks)")
    columns = {row[1] for row in await cursor.fetchall()}
    assert "project_id" in columns, (
        "project_id column must exist on scheduled_tasks after migration"
    )
    await db.close()


async def test_acceptance_3_migration_is_idempotent(tmp_path):
    """B1-1: re-running ``run_migrations`` doesn't error and columns
    still exist."""
    db = await _make_db(tmp_path)
    # Re-run migrations — should not raise.
    await db.run_migrations()
    await db.run_migrations()
    conn = await db._require_conn()
    cursor = await conn.execute("PRAGMA table_info(scheduled_tasks)")
    columns = {row[1] for row in await cursor.fetchall()}
    assert "policy_digest" in columns
    assert "project_id" in columns
    await db.close()


# ---------------------------------------------------------------------------
# 4-6. CronEngine stamps security-context snapshot at creation
# ---------------------------------------------------------------------------


async def test_acceptance_4_engine_stamps_policy_digest_on_create(tmp_path):
    """B1-3: ``CronEngine`` constructed with ``policy_digest`` stamps
    it on every newly created task."""
    db = await _make_db(tmp_path)
    engine = _make_engine(db, project_id="proj-123", policy_digest="sha256:abc123")
    task = await engine.create(
        "test task", "hello", ScheduleConfig(cron="0 9"),
        principal_id="alice",
    )
    assert task.policy_digest == "sha256:abc123", (
        "task must carry the engine's bound policy_digest"
    )
    await db.close()


async def test_acceptance_5_engine_stamps_project_id_on_create(tmp_path):
    """B1-3: ``CronEngine`` constructed with ``project_id`` stamps it
    on every newly created task."""
    db = await _make_db(tmp_path)
    engine = _make_engine(db, project_id="proj-456", policy_digest="sha256:def456")
    task = await engine.create(
        "test task", "hello", ScheduleConfig(cron="0 9"),
        principal_id="alice",
    )
    assert task.project_id == "proj-456", (
        "task must carry the engine's bound project_id"
    )
    await db.close()


async def test_acceptance_6_engine_without_policy_digest_stamps_empty(tmp_path):
    """B1-3: engine constructed without ``policy_digest`` stamps empty
    string — fail-closed default.  B-2 will quarantine such tasks at
    enforcement time; B-1 only provides the schema."""
    db = await _make_db(tmp_path)
    engine = _make_engine(db)
    task = await engine.create(
        "test task", "hello", ScheduleConfig(cron="0 9"),
        principal_id="alice",
    )
    assert task.policy_digest == ""
    assert task.project_id == ""
    await db.close()


# ---------------------------------------------------------------------------
# 7. _task_from_row restores snapshot after restart
# ---------------------------------------------------------------------------


async def test_acceptance_7_task_from_row_restores_snapshot(tmp_path):
    """B1-3: ``_task_from_row`` restores ``policy_digest`` and
    ``project_id`` after a restart so B-2 drift detection can compare
    against the live values.

    Uses the same DB connection for both engines — the test verifies
    that ``_load_tasks`` reads the snapshot from the DB row, not from
    engine1's in-memory cache.  engine2 starts with an empty
    ``_tasks`` dict and must populate it from ``list_scheduled_tasks``.
    """
    db = await _make_db(tmp_path)
    engine1 = _make_engine(
        db, project_id="proj-restart", policy_digest="sha256:restart-test"
    )
    task = await engine1.create(
        "restart test", "hello", ScheduleConfig(cron="0 9"),
        principal_id="alice",
    )
    task_id = task.id

    # Construct a fresh engine with the SAME db.  Its ``_tasks`` dict
    # is empty — ``_load_tasks`` must read from the DB.
    engine2 = _make_engine(
        db, project_id="proj-restart", policy_digest="sha256:restart-test"
    )
    assert task_id not in engine2._tasks, (
        "engine2 must start with an empty _tasks dict"
    )
    await engine2._load_tasks()
    loaded = engine2._tasks.get(task_id)
    assert loaded is not None, "task must be loaded from DB"
    assert loaded.policy_digest == "sha256:restart-test", (
        "policy_digest must be restored from DB row"
    )
    assert loaded.project_id == "proj-restart", (
        "project_id must be restored from DB row"
    )
    await db.close()


# ---------------------------------------------------------------------------
# 8. No cross-contamination at schema level
# ---------------------------------------------------------------------------


async def test_acceptance_8_different_policy_digests_coexist(tmp_path):
    """B1-3: tasks created under different ``policy_digest`` values
    coexist in the same DB.  B-2 will add enforcement (drift detection);
    B-1 only ensures the schema can store different snapshots without
    collision."""
    db = await _make_db(tmp_path)

    # Engine A creates a task under policy A.
    engine_a = _make_engine(
        db, project_id="proj-shared", policy_digest="sha256:policy-a"
    )
    task_a = await engine_a.create(
        "task under policy A", "hello", ScheduleConfig(cron="0 9"),
        principal_id="alice",
    )

    # Engine B creates a task under policy B (same DB, same project).
    engine_b = _make_engine(
        db, project_id="proj-shared", policy_digest="sha256:policy-b"
    )
    task_b = await engine_b.create(
        "task under policy B", "hello", ScheduleConfig(cron="0 9"),
        principal_id="alice",
    )

    # Both tasks exist with their respective snapshots.
    assert task_a.policy_digest == "sha256:policy-a"
    assert task_b.policy_digest == "sha256:policy-b"
    assert task_a.id != task_b.id
    await db.close()


# ---------------------------------------------------------------------------
# 9. insert_scheduled_task persists atomically
# ---------------------------------------------------------------------------


async def test_acceptance_9_insert_persists_snapshot_atomically(tmp_path):
    """B1-4: ``insert_scheduled_task`` persists ``policy_digest`` and
    ``project_id`` atomically with the row — no separate UPDATE
    needed."""
    db = await _make_db(tmp_path)
    task_id = await db.insert_scheduled_task(
        name="atomic test",
        prompt="hello",
        status="pending",
        schedule=ScheduleConfig(cron="0 9"),
        deliver_to="local",
        meta={},
        principal_id="alice",
        next_run="2026-07-20T09:00:00",
        project_id="proj-atomic",
        policy_digest="sha256:atomic",
    )
    conn = await db._require_conn()
    cursor = await conn.execute(
        "SELECT policy_digest, project_id FROM scheduled_tasks WHERE id = ?",
        (task_id,),
    )
    row = await cursor.fetchone()
    assert row is not None
    assert row["policy_digest"] == "sha256:atomic", (
        "policy_digest must be persisted atomically with the INSERT"
    )
    assert row["project_id"] == "proj-atomic", (
        "project_id must be persisted atomically with the INSERT"
    )
    await db.close()


# ---------------------------------------------------------------------------
# 10. Policy-scoped index exists
# ---------------------------------------------------------------------------


async def test_acceptance_10_policy_index_exists(tmp_path):
    """B1-1: ``idx_scheduled_tasks_policy`` index exists for efficient
    policy-scoped lookups (B-2 will use this for drift detection
    queries)."""
    db = await _make_db(tmp_path)
    conn = await db._require_conn()
    cursor = await conn.execute(
        "SELECT name FROM sqlite_master WHERE type='index' "
        "AND tbl_name='scheduled_tasks'"
    )
    index_names = {row[0] for row in await cursor.fetchall()}
    assert "idx_scheduled_tasks_policy" in index_names, (
        "idx_scheduled_tasks_policy index must exist for policy-scoped lookups"
    )
    await db.close()
