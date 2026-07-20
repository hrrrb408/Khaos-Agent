"""M4 Batch 3.1.16B-2 — Generation-Fenced Lifecycle + Drift Detection.

Acceptance tests for the security-context drift detection added to
``CronEngine.start()`` and ``_execute_task``:

  1.  ``_check_snapshot_drift`` returns ``None`` when the task's
      snapshot matches the engine's bound values.
  2.  ``_check_snapshot_drift`` returns a reason when ``policy_digest``
      differs.
  3.  ``_check_snapshot_drift`` returns a reason when ``project_id``
      differs.
  4.  ``_check_snapshot_drift`` returns ``None`` when the engine has
      no bound digest (test mode — enforcement disabled).
  5.  ``_check_snapshot_drift`` returns a reason for a legacy task
      (empty ``policy_digest``) on a production engine.
  6.  ``start()`` quarantines drifted tasks (status=failed) so the
      tick loop skips them.
  7.  ``start()`` leaves matching tasks alone (status stays pending).
  8.  ``start()`` with empty engine digest (test mode) doesn't
      quarantine legacy tasks.
  9.  ``_execute_task`` quarantines a drifted task at claim time
      (defense-in-depth — even if ``start()`` missed it).
  10. A task created under policy A then loaded by an engine under
      policy B is quarantined at ``start()`` (the canonical drift
      scenario: ``khaos_policy.yaml`` edited between runs).
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from khaos.db import Database
from khaos.scheduler import CronEngine, ScheduleConfig, TaskStatus
from khaos.scheduler.engine import CronEngineState


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


async def _force_cleanup_engine(engine: CronEngine) -> None:
    """Force-stop an engine that may be in QUARANTINED state."""
    engine._running = False
    engine._lifecycle_state = CronEngineState.STOPPED
    if engine._loop_task and not engine._loop_task.done():
        engine._loop_task.cancel()
        try:
            await engine._loop_task
        except asyncio.CancelledError:
            pass
    for task in list(engine._execute_tasks.values()):
        if not task.done():
            task.cancel()
            try:
                await asyncio.wait_for(task, timeout=1.0)
            except (asyncio.CancelledError, asyncio.TimeoutError, Exception):
                pass
    engine._execute_tasks.clear()
    engine._pending_persistence.clear()
    engine._persistence_owners.clear()


# ---------------------------------------------------------------------------
# 1-5. _check_snapshot_drift unit tests
# ---------------------------------------------------------------------------


async def test_acceptance_1_no_drift_returns_none(tmp_path):
    """B2-1: ``_check_snapshot_drift`` returns ``None`` when the task's
    snapshot matches the engine's bound values."""
    db = await _make_db(tmp_path)
    engine = _make_engine(
        db, project_id="proj-match", policy_digest="sha256:match"
    )
    task = await engine.create(
        "match test", "hello", ScheduleConfig(cron="0 9"),
        principal_id="alice",
    )
    assert engine._check_snapshot_drift(task) is None, (
        "no drift when task snapshot matches engine bound values"
    )
    await db.close()


async def test_acceptance_2_policy_digest_drift_returns_reason(tmp_path):
    """B2-1: ``_check_snapshot_drift`` returns a reason when
    ``policy_digest`` differs."""
    db = await _make_db(tmp_path)
    engine = _make_engine(
        db, project_id="proj-x", policy_digest="sha256:engine-digest"
    )
    # Create a task under a DIFFERENT policy digest by stamping it
    # directly via insert_scheduled_task.
    task_id = await db.insert_scheduled_task(
        name="drifted task", prompt="hello", status="pending",
        schedule=ScheduleConfig(cron="0 9"), deliver_to="local", meta={},
        principal_id="alice",
        project_id="proj-x",  # matching project_id
        policy_digest="sha256:task-digest",  # DIFFERENT policy_digest
    )
    # Load the task into the engine's _tasks dict via _load_tasks.
    await engine._load_tasks()
    task = engine._tasks.get(task_id)
    assert task is not None, "task must be loaded"
    drift_reason = engine._check_snapshot_drift(task)
    assert drift_reason is not None, "drift must be detected"
    assert "policy_digest" in drift_reason, (
        "drift reason must mention policy_digest"
    )
    await db.close()


async def test_acceptance_3_project_id_drift_returns_reason(tmp_path):
    """B2-1: ``_check_snapshot_drift`` returns a reason when
    ``project_id`` differs."""
    db = await _make_db(tmp_path)
    engine = _make_engine(
        db, project_id="proj-engine", policy_digest="sha256:same"
    )
    task_id = await db.insert_scheduled_task(
        name="drifted task", prompt="hello", status="pending",
        schedule=ScheduleConfig(cron="0 9"), deliver_to="local", meta={},
        principal_id="alice",
        project_id="proj-different",  # DIFFERENT project_id
        policy_digest="sha256:same",  # matching policy_digest
    )
    await engine._load_tasks()
    task = engine._tasks.get(task_id)
    assert task is not None
    drift_reason = engine._check_snapshot_drift(task)
    assert drift_reason is not None, "drift must be detected"
    assert "project_id" in drift_reason, (
        "drift reason must mention project_id"
    )
    await db.close()


async def test_acceptance_4_test_mode_skips_enforcement(tmp_path):
    """B2-1: when the engine has no bound digest (test mode), drift
    detection is DISABLED — every task passes the check."""
    db = await _make_db(tmp_path)
    # Test engine: empty policy_digest and project_id.
    engine = _make_engine(db, project_id="", policy_digest="")
    # Create a task with a non-empty digest (simulating a task
    # created by a production engine).
    task_id = await db.insert_scheduled_task(
        name="prod task", prompt="hello", status="pending",
        schedule=ScheduleConfig(cron="0 9"), deliver_to="local", meta={},
        principal_id="alice",
        project_id="proj-prod", policy_digest="sha256:prod",
    )
    await engine._load_tasks()
    task = engine._tasks.get(task_id)
    assert task is not None
    # Test mode → no drift detected, even though snapshots differ.
    assert engine._check_snapshot_drift(task) is None, (
        "test mode (empty engine digest) must skip drift enforcement"
    )
    await db.close()


async def test_acceptance_5_legacy_task_drift_on_production_engine(tmp_path):
    """B2-1: a legacy task (empty ``policy_digest``) on a production
    engine (non-empty digest) is detected as drift."""
    db = await _make_db(tmp_path)
    engine = _make_engine(
        db, project_id="proj-prod", policy_digest="sha256:prod"
    )
    # Legacy task: empty policy_digest and project_id (e.g. created
    # before B-1 migration).
    task_id = await db.insert_scheduled_task(
        name="legacy task", prompt="hello", status="pending",
        schedule=ScheduleConfig(cron="0 9"), deliver_to="local", meta={},
        principal_id="alice",
        project_id="",  # legacy
        policy_digest="",  # legacy
    )
    await engine._load_tasks()
    task = engine._tasks.get(task_id)
    assert task is not None
    drift_reason = engine._check_snapshot_drift(task)
    assert drift_reason is not None, (
        "legacy task on production engine must be detected as drift"
    )
    assert "policy_digest" in drift_reason
    await db.close()


# ---------------------------------------------------------------------------
# 6-8. start() drift detection
# ---------------------------------------------------------------------------


async def test_acceptance_6_start_quarantines_drifted_tasks(tmp_path):
    """B2-2: ``start()`` quarantines drifted tasks (status=failed) so
    the tick loop skips them."""
    db = await _make_db(tmp_path)
    # Create a task under policy A.
    task_id = await db.insert_scheduled_task(
        name="drifted task", prompt="hello", status="pending",
        schedule=ScheduleConfig(cron="0 9"), deliver_to="local", meta={},
        principal_id="alice",
        project_id="proj-x", policy_digest="sha256:policy-a",
    )
    # Start an engine under policy B — the task should be quarantined.
    engine = _make_engine(
        db, project_id="proj-x", policy_digest="sha256:policy-b",
        tick_interval=999.0,
    )
    try:
        await engine.start()
        # Task must be quarantined to failed.
        task = engine._tasks.get(task_id)
        assert task is not None, "task must be loaded"
        assert task.status == TaskStatus.FAILED, (
            f"drifted task must be quarantined to failed, got {task.status}"
        )
        assert task.error is not None
        assert "drift" in task.error.lower(), (
            f"error must mention drift, got {task.error!r}"
        )
        # Verify the DB row is also failed (durable quarantine).
        row = await db.get_scheduled_task(task_id)
        assert row is not None
        assert row["status"] == "failed", (
            "DB row must be durably quarantined to failed"
        )
    finally:
        await _force_cleanup_engine(engine)
        await db.close()


async def test_acceptance_7_start_leaves_matching_tasks_alone(tmp_path):
    """B2-2: ``start()`` leaves matching tasks alone (status stays
    pending)."""
    db = await _make_db(tmp_path)
    # Create a task under policy A.
    task_id = await db.insert_scheduled_task(
        name="matching task", prompt="hello", status="pending",
        schedule=ScheduleConfig(cron="0 9"), deliver_to="local", meta={},
        principal_id="alice",
        project_id="proj-x", policy_digest="sha256:policy-a",
    )
    # Start an engine under the SAME policy — task should NOT be
    # quarantined.
    engine = _make_engine(
        db, project_id="proj-x", policy_digest="sha256:policy-a",
        tick_interval=999.0,
    )
    try:
        await engine.start()
        task = engine._tasks.get(task_id)
        assert task is not None
        assert task.status == TaskStatus.PENDING, (
            f"matching task must stay pending, got {task.status}"
        )
        assert task.error is None or "drift" not in (task.error or "").lower()
    finally:
        await _force_cleanup_engine(engine)
        await db.close()


async def test_acceptance_8_test_engine_doesnt_quarantine_legacy(tmp_path):
    """B2-2: ``start()`` with empty engine digest (test mode) doesn't
    quarantine legacy tasks."""
    db = await _make_db(tmp_path)
    # Legacy task: empty policy_digest.
    task_id = await db.insert_scheduled_task(
        name="legacy task", prompt="hello", status="pending",
        schedule=ScheduleConfig(cron="0 9"), deliver_to="local", meta={},
        principal_id="alice",
        project_id="", policy_digest="",
    )
    # Test engine: empty policy_digest.
    engine = _make_engine(
        db, project_id="", policy_digest="", tick_interval=999.0,
    )
    try:
        await engine.start()
        task = engine._tasks.get(task_id)
        assert task is not None
        assert task.status == TaskStatus.PENDING, (
            f"test engine must not quarantine legacy tasks, got {task.status}"
        )
    finally:
        await _force_cleanup_engine(engine)
        await db.close()


# ---------------------------------------------------------------------------
# 9. _execute_task claim-time drift detection (defense-in-depth)
# ---------------------------------------------------------------------------


async def test_acceptance_9_execute_task_quarantines_drifted_at_claim(tmp_path):
    """B2-3: ``_execute_task`` quarantines a drifted task at claim
    time (defense-in-depth — even if ``start()`` missed it).

    Scenario: a task is created under policy A, then the engine's
    in-memory task object is mutated to have a different digest
    (simulating a stale reload).  ``_execute_task`` must catch the
    drift at claim time and quarantine the task.
    """
    db = await _make_db(tmp_path)
    engine = _make_engine(
        db, project_id="proj-x", policy_digest="sha256:engine-digest",
        tick_interval=999.0,
    )
    try:
        await engine.start()
        # Create a task under the engine's current digest.
        task = await engine.create(
            "drift test", "hello", ScheduleConfig(cron="0 9"),
            principal_id="alice",
        )
        # Mutate the in-memory task's policy_digest to simulate drift
        # (e.g. a stale reload that didn't preserve the snapshot).
        task.policy_digest = "sha256:different-digest"
        task.status = TaskStatus.PENDING  # ensure tick would fire it
        # Call _execute_task directly — it should quarantine the task.
        await engine._execute_task(task)
        assert task.status == TaskStatus.FAILED, (
            f"drifted task must be quarantined at claim time, got {task.status}"
        )
        assert task.error is not None
        assert "drift" in task.error.lower()
    finally:
        await _force_cleanup_engine(engine)
        await db.close()


# ---------------------------------------------------------------------------
# 10. Canonical drift scenario: policy edited between runs
# ---------------------------------------------------------------------------


async def test_acceptance_10_canonical_drift_policy_edited_between_runs(tmp_path):
    """B2-2: a task created under policy A then loaded by an engine
    under policy B is quarantined at ``start()``.

    This is the canonical drift scenario: ``khaos_policy.yaml`` is
    edited between runs, so the effective policy digest changes.  The
    task was created under the old policy and must NOT silently
    execute under the new policy.
    """
    db = await _make_db(tmp_path)
    # Run 1: create a task under policy A.
    engine_a = _make_engine(
        db, project_id="proj-x", policy_digest="sha256:policy-a-v1",
        tick_interval=999.0,
    )
    try:
        await engine_a.start()
        task = await engine_a.create(
            "canonical drift", "hello", ScheduleConfig(cron="0 9"),
            principal_id="alice",
        )
        task_id = task.id
        assert task.policy_digest == "sha256:policy-a-v1"
    finally:
        await _force_cleanup_engine(engine_a)

    # Run 2: start a NEW engine under policy B (policy edited between
    # runs).  The task from run 1 must be quarantined.
    engine_b = _make_engine(
        db, project_id="proj-x", policy_digest="sha256:policy-b-v2",
        tick_interval=999.0,
    )
    try:
        await engine_b.start()
        task = engine_b._tasks.get(task_id)
        assert task is not None, "task must be loaded by engine_b"
        assert task.status == TaskStatus.FAILED, (
            f"task created under policy A must be quarantined when "
            f"loaded by engine under policy B, got {task.status}"
        )
        assert "drift" in (task.error or "").lower()
        # Verify durable quarantine.
        row = await db.get_scheduled_task(task_id)
        assert row is not None
        assert row["status"] == "failed"
    finally:
        await _force_cleanup_engine(engine_b)
        await db.close()
