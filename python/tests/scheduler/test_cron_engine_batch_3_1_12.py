"""M4 Batch 3.1.12 — Durable Control Supersession and Restart Lease
Reconciliation Closure.

Acceptance tests for the 10 criteria specified in the batch review:

  1.  Pause fail then remove does not return ok (DB still at pending).
  2.  Remove success — no resurrection on restart.
  3.  New control op supersedes old marker.
  4.  No running + NULL lease after control fail + executor complete.
  5.  ``control_finalize_scheduled_task`` clears the lease atomically.
  6.  Restart before lease expiry recovers as FAILED (single-instance).
  7.  Recovery sweeps ALL abnormal leases (expired, unexpired, orphaned).
  8.  Legacy ``principal_id='legacy'`` rows are quarantined at migration.
  9.  ``_load_tasks`` failure enters degraded mode (refuses execution).
  10. Crash-point injection (commit-then-raise) — no version drift.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from khaos.db import Database
from khaos.exceptions import ServiceShutdownError
from khaos.scheduler import CronEngine, ScheduleConfig, ScheduledTask, TaskStatus
from khaos.scheduler.engine import PendingPersistence
import khaos.scheduler.engine as _engine_mod


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


async def _make_db(path) -> Database:
    """Create a Database at ``path``.

    ``path`` may be either a directory (a ``tmp_path`` fixture) or a
    full file path.  If it's a directory, ``khaos.db`` is appended.
    """
    p = Path(path)
    if p.is_dir() or (not p.exists() and not p.name.endswith(".db")):
        p = p / "khaos.db"
    db = Database(p)
    await db.connect()
    await db.run_migrations()
    return db


async def _recording_executor_3arg(task_id: str, prompt: str, principal_id: str) -> str:
    """3-arg executor that records the principal_id it was called with."""
    return f"executed:{prompt}:by:{principal_id}"


# ---------------------------------------------------------------------------
# Acceptance 1: pause fail then remove does not return ok
# ---------------------------------------------------------------------------


async def test_acceptance_1_pause_fail_then_remove_does_not_return_ok(
    tmp_path,
) -> None:
    """Criterion 1: if ``pause()``'s DB persist fails (returning
    ``persistence_pending``), a subsequent ``remove()`` MUST also
    return ``persistence_pending`` (NOT ``ok``) — the DB is still at
    ``pending`` (pause's persist failed), so remove's CAS still has
    to write ``cancelled`` and that write must also fail.

    Without the CRITICAL-1 supersession fix, ``remove()`` would see
    the pause's marker in ``_pending_persistence``, skip the DB write
    (treating the marker as "already handled"), return True, and pop
    the task — leaving the DB at ``pending`` so the task resurrected
    on restart.

    Sequence:
      1. Create a PENDING task with future ISO time (not immediately due).
      2. Patch ``control_finalize_scheduled_task`` to fail.
      3. ``pause()`` → ``persistence_pending`` (persist failed).
      4. ``remove()`` → ALSO ``persistence_pending`` (DB still at pending).
      5. Task is STILL in ``_tasks`` (not popped).
      6. ``_pending_persistence`` has a marker for this task.
      7. Restore ``control_finalize_scheduled_task``.
      8. ``stop()`` succeeds (reconcile persists the cancelled state).
    """
    db = await _make_db(tmp_path)
    try:
        engine = CronEngine(db=db)
        # Future ISO time → not immediately due (tick won't fire).
        iso = (datetime.utcnow() + timedelta(hours=1)).isoformat()
        task = await engine.create(
            "pause-fail-remove", "p", ScheduleConfig(iso_time=iso),
            principal_id="alice",
        )
        task_id = task.id

        # Patch control_finalize_scheduled_task to fail.
        original_control = db.control_finalize_scheduled_task

        async def failing_control(*args, **kwargs):
            raise RuntimeError("DB wedged for control op")

        db.control_finalize_scheduled_task = failing_control

        # pause() → persistence_pending (persist failed).
        pause_result = await engine.pause(task_id, principal_id="alice")
        assert pause_result == "persistence_pending", (
            f"expected persistence_pending, got {pause_result}"
        )

        # remove() → ALSO persistence_pending (DB still at pending).
        remove_result = await engine.remove(task_id, principal_id="alice")
        assert remove_result == "persistence_pending", (
            f"expected persistence_pending (DB still at pending), got "
            f"{remove_result} — remove() returned ok despite pause's "
            "persist failing; the task would be popped and resurrect "
            "on restart"
        )

        # Task is STILL in _tasks (not popped).
        assert task_id in engine._tasks, (
            "task was popped from _tasks despite persist failing — "
            "the task would resurrect on restart"
        )

        # _pending_persistence has a marker for this task.
        assert task_id in engine._pending_persistence, (
            "no persistence marker for task — reconcile won't retry "
            "the cancelled state"
        )
        marker = engine._pending_persistence[task_id]
        assert marker.is_control_op is True
        assert marker.desired_status == TaskStatus.CANCELLED.value, (
            f"marker desired_status={marker.desired_status!r}, "
            f"expected {TaskStatus.CANCELLED.value!r}"
        )

        # Restore control_finalize_scheduled_task.
        db.control_finalize_scheduled_task = original_control

        # stop() succeeds (reconcile persists the cancelled state).
        await engine.stop(timeout=5.0)

        # After stop, the DB should be 'cancelled'.
        row = await db.get_scheduled_task(task_id)
        assert row["status"] == "cancelled", (
            f"expected cancelled after reconcile, got {row['status']}"
        )
    finally:
        await db.close()


# ---------------------------------------------------------------------------
# Acceptance 2: remove success — no resurrection on restart
# ---------------------------------------------------------------------------


async def test_acceptance_2_remove_success_no_resurrection_on_restart(
    tmp_path,
) -> None:
    """Criterion 2: after ``remove()`` returns ``ok``, the DB row is
    ``cancelled`` and a restart MUST NOT resurrect the task.

    Without the CRITICAL-1 fix, a task popped from ``_tasks`` but
    whose DB row was never actually written as ``cancelled`` (e.g.
    the in-memory pop happened before the persist committed) would
    reappear in ``_load_tasks`` on restart — the user's "removed"
    contract was silently violated.

    Sequence:
      1. Create a PENDING task with future ISO time.
      2. ``remove()`` → ``ok``.
      3. Close DB, reopen, create new engine, ``start()``.
      4. Task is NOT in ``_tasks`` (DB status is ``cancelled``).
      5. DB row status is ``cancelled``.
    """
    db_path = tmp_path / "khaos.db"
    db = await _make_db(db_path)
    try:
        engine = CronEngine(db=db)
        iso = (datetime.utcnow() + timedelta(hours=1)).isoformat()
        task = await engine.create(
            "no-resurrect", "p", ScheduleConfig(iso_time=iso),
            principal_id="alice",
        )
        task_id = task.id

        remove_result = await engine.remove(task_id, principal_id="alice")
        assert remove_result == "ok", (
            f"expected ok, got {remove_result}"
        )
    finally:
        await db.close()

    # Restart: reopen DB, create new engine, start().
    db2 = await _make_db(db_path)
    try:
        engine2 = CronEngine(db=db2)
        await engine2.start()

        # DB row status is 'cancelled' (the user's "removed" contract
        # was durable across the restart).
        row = await db2.get_scheduled_task(task_id)
        assert row is not None, "task row disappeared from DB"
        assert row["status"] == "cancelled", (
            f"expected cancelled, got {row['status']}"
        )

        # The task is NOT resurrected as PENDING — it's either absent
        # from _tasks or present as CANCELLED (the tick loop only fires
        # PENDING tasks, so a CANCELLED task will never be re-fired).
        loaded = engine2._tasks.get(task_id)
        if loaded is not None:
            assert loaded.status != TaskStatus.PENDING, (
                f"task was resurrected as PENDING (status={loaded.status}) — "
                "the DB row's 'cancelled' status was not respected; the tick "
                "loop would re-fire it"
            )
            assert loaded.status == TaskStatus.CANCELLED, (
                f"task status={loaded.status}, expected CANCELLED"
            )

        await engine2.stop(timeout=2.0)
    finally:
        await db2.close()


# ---------------------------------------------------------------------------
# Acceptance 3: new control op supersedes old marker
# ---------------------------------------------------------------------------


async def test_acceptance_3_new_control_op_supersedes_old_marker(
    tmp_path,
) -> None:
    """Criterion 3: a new control op (``remove``) supersedes an old
    failed control op's marker (``pause``).  The new op reads the
    DB's CURRENT ``lifecycle_version`` (not the in-memory version,
    which may be stale from a prior failed bump) and writes the new
    desired state.

    Without the CRITICAL-1 supersession fix, the new op would see
    the old marker, skip the DB write ("already handled"), and
    return True — leaving the DB at the old state.

    Sequence:
      1. Create a PENDING task with future ISO time.
      2. Patch ``control_finalize_scheduled_task`` to fail.
      3. ``pause()`` → ``persistence_pending``, marker placed (op A).
      4. Verify marker exists with ``desired_status='paused'``.
      5. Restore ``control_finalize_scheduled_task``.
      6. ``remove()`` → ``ok`` (new op supersedes old marker).
      7. Verify marker is cleared.
      8. Verify DB status is ``cancelled``.
    """
    db = await _make_db(tmp_path)
    try:
        engine = CronEngine(db=db)
        iso = (datetime.utcnow() + timedelta(hours=1)).isoformat()
        task = await engine.create(
            "supersede", "p", ScheduleConfig(iso_time=iso),
            principal_id="alice",
        )
        task_id = task.id

        # Patch control_finalize to fail.
        original_control = db.control_finalize_scheduled_task

        async def failing_control(*args, **kwargs):
            raise RuntimeError("DB wedged for control op")

        db.control_finalize_scheduled_task = failing_control

        # pause() → persistence_pending, marker placed.
        pause_result = await engine.pause(task_id, principal_id="alice")
        assert pause_result == "persistence_pending", (
            f"expected persistence_pending, got {pause_result}"
        )

        # Verify marker exists with desired_status='paused'.
        assert task_id in engine._pending_persistence, (
            "pause did not place a persistence marker"
        )
        pause_marker = engine._pending_persistence[task_id]
        assert pause_marker.desired_status == TaskStatus.PAUSED.value, (
            f"marker desired_status={pause_marker.desired_status!r}, "
            f"expected {TaskStatus.PAUSED.value!r}"
        )

        # Restore control_finalize.
        db.control_finalize_scheduled_task = original_control

        # remove() → ok (new op supersedes old marker).
        remove_result = await engine.remove(task_id, principal_id="alice")
        assert remove_result == "ok", (
            f"expected ok (new op supersedes old marker), got "
            f"{remove_result} — remove() saw the pause's marker and "
            "skipped the DB write"
        )

        # Verify marker is cleared.
        assert task_id not in engine._pending_persistence, (
            "marker was not cleared after remove succeeded"
        )

        # Verify DB status is 'cancelled'.
        row = await db.get_scheduled_task(task_id)
        assert row["status"] == "cancelled", (
            f"expected cancelled, got {row['status']}"
        )
    finally:
        await db.close()


# ---------------------------------------------------------------------------
# Acceptance 4: no running + NULL lease after control fail + executor complete
# ---------------------------------------------------------------------------


async def test_acceptance_4_no_running_null_lease_after_control_fail_and_executor_complete(
    tmp_path,
) -> None:
    """Criterion 4: when a control op (``pause``) wins the epoch race
    but its DB persist FAILS, and then the stale executor completes
    and hits the epoch-changed path, the DB MUST NOT end up at
    ``status='running' + execution_id=NULL + lease_until=NULL``
    (permanently stuck, unrecoverable).

    The epoch-changed path does NOT independently clear the lease
    (CRITICAL-2) — it only clears the in-memory fields.  The DB lease
    stays intact so ``recover_expired_leases`` or
    ``recover_all_running_tasks`` can disclose the crash on restart.

    Sequence:
      1. Create a task with past ISO time (immediately due) and a
         stalling executor that swallows CancelledError.
      2. Start engine, wait for executor to start.
      3. Patch ``control_finalize_scheduled_task`` to fail.
      4. ``pause()`` → ``cancellation_pending`` or ``persistence_pending``.
      5. Patch ``clear_scheduled_task_lease`` to track calls.
      6. Release the executor (let it complete).
      7. Wait for the executor's epoch-changed path to run.
      8. Verify DB does NOT have ``running + NULL lease + NULL exec_id``.
      9. Verify ``clear_scheduled_task_lease`` was NOT called.
    """
    # Shrink the cancel budget so pause() doesn't wait 10s.
    original_cancel_timeout = _engine_mod._CANCEL_IN_FLIGHT_TIMEOUT
    _engine_mod._CANCEL_IN_FLIGHT_TIMEOUT = 0.3

    db = await _make_db(tmp_path)
    try:
        started = asyncio.Event()
        release_exec = asyncio.Event()

        async def stalling_executor(task_id: str, prompt: str, principal_id: str) -> str:
            started.set()
            # Swallow CancelledError — stay alive past the cancel budget.
            while not release_exec.is_set():
                try:
                    await release_exec.wait()
                except asyncio.CancelledError:
                    if release_exec.is_set():
                        raise
            return "stale-result"

        engine = CronEngine(
            db=db, executor=stalling_executor, tick_interval=0.01,
        )
        await engine.start()

        iso = (datetime.utcnow() - timedelta(seconds=10)).isoformat()
        task = await engine.create(
            "no-null-lease", "p", ScheduleConfig(iso_time=iso),
            principal_id="alice",
        )
        task_id = task.id
        await asyncio.wait_for(started.wait(), timeout=2.0)

        # Patch control_finalize to fail.
        original_control = db.control_finalize_scheduled_task

        async def failing_control(*args, **kwargs):
            raise RuntimeError("DB wedged for control op")

        db.control_finalize_scheduled_task = failing_control

        # pause() → cancellation_pending or persistence_pending.
        pause_result = await engine.pause(task_id, principal_id="alice")
        assert pause_result in (
            "persistence_pending", "cancellation_pending",
        ), f"expected persistence_pending or cancellation_pending, got {pause_result}"

        # Patch clear_scheduled_task_lease to track calls.
        original_clear_lease = db.clear_scheduled_task_lease
        clear_lease_calls: list[str] = []

        async def tracking_clear_lease(task_id_arg, *, execution_id):
            clear_lease_calls.append(task_id_arg)
            return await original_clear_lease(task_id_arg, execution_id=execution_id)

        db.clear_scheduled_task_lease = tracking_clear_lease

        # Release the executor — it completes and hits the epoch-changed path.
        release_exec.set()
        await asyncio.sleep(0.3)

        # The DB MUST NOT be at running + NULL lease + NULL exec_id.
        row = await db.get_scheduled_task(task_id)
        is_stuck = (
            row["status"] == "running"
            and row["execution_id"] is None
            and row["lease_until"] is None
        )
        assert not is_stuck, (
            "DB is at running + NULL execution_id + NULL lease_until — "
            "permanently stuck; recover_expired_leases cannot match "
            "this row (lease_until IS NULL)"
        )

        # clear_scheduled_task_lease was NOT called (epoch-changed path
        # does not independently clear the lease).
        assert len(clear_lease_calls) == 0, (
            f"clear_scheduled_task_lease was called {len(clear_lease_calls)} "
            "time(s) — the epoch-changed path must NOT independently clear "
            "the lease when the control op's persist failed"
        )

        # Restore control_finalize so stop() can reconcile.
        db.control_finalize_scheduled_task = original_control
        await engine.stop(timeout=5.0)
    finally:
        _engine_mod._CANCEL_IN_FLIGHT_TIMEOUT = original_cancel_timeout
        release_exec.set()
        await db.close()


# ---------------------------------------------------------------------------
# Acceptance 5: control_finalize clears the lease atomically
# ---------------------------------------------------------------------------


async def test_acceptance_5_control_finalize_clears_lease_atomically(
    tmp_path,
) -> None:
    """Criterion 5: ``control_finalize_scheduled_task`` atomically
    clears the execution lease (``execution_id`` / ``lease_until``)
    in the SAME CAS that writes the desired state.

    Without atomicity, a control op could persist the desired state
    but leave the lease in the DB — then a stale executor's
    ``_clear_lease`` could clear the lease independently while the
    control op's persist had actually FAILED, leaving
    ``status='running' + NULL lease`` (permanently stuck).

    Sequence:
      1. Create a task, manually claim it (set execution_id + lease_until).
      2. Call ``control_finalize_scheduled_task`` directly with
         expected_version = current, target_version = current + 1,
         status = 'paused'.
      3. Verify DB row has status='paused' AND execution_id IS NULL
         AND lease_until IS NULL (atomic clear).
    """
    db = await _make_db(tmp_path)
    try:
        engine = CronEngine(db=db)
        task = await engine.create(
            "atomic-clear", "p", ScheduleConfig(interval_seconds=60),
            principal_id="alice",
        )

        # Manually claim the task (set execution_id + lease_until).
        started_at = datetime.utcnow().isoformat()
        lease_until = (datetime.utcnow() + timedelta(minutes=10)).isoformat()
        rowcount = await db.claim_scheduled_task(
            task.id,
            execution_id="test-exec-5",
            started_at=started_at,
            lease_until=lease_until,
            expected_version=task.lifecycle_version,
        )
        assert rowcount == 1, "claim should succeed — task is PENDING"

        # Verify the lease was set.
        row_before = await db.get_scheduled_task(task.id)
        assert row_before["execution_id"] == "test-exec-5"
        assert row_before["lease_until"] is not None

        # Call control_finalize_scheduled_task directly.
        expected = task.lifecycle_version
        target = expected + 1
        rowcount = await db.control_finalize_scheduled_task(
            task.id,
            expected_version=expected,
            target_version=target,
            status=TaskStatus.PAUSED.value,
        )
        assert rowcount == 1, (
            f"control_finalize should succeed (expected_version={expected}), "
            f"got rowcount={rowcount}"
        )

        # Verify atomic clear: status='paused' AND lease cleared.
        row_after = await db.get_scheduled_task(task.id)
        assert row_after["status"] == TaskStatus.PAUSED.value, (
            f"expected paused, got {row_after['status']}"
        )
        assert row_after["execution_id"] is None, (
            "execution_id was not cleared atomically — a stale executor "
            "could later clear it independently, leaving running + NULL lease"
        )
        assert row_after["lease_until"] is None, (
            "lease_until was not cleared atomically — a stale executor "
            "could later clear it independently, leaving running + NULL lease"
        )
        assert int(row_after["lifecycle_version"]) == target, (
            f"lifecycle_version={row_after['lifecycle_version']}, "
            f"expected {target}"
        )
    finally:
        await db.close()


# ---------------------------------------------------------------------------
# Acceptance 6: restart before lease expiry recovers as FAILED
# ---------------------------------------------------------------------------


async def test_acceptance_6_restart_before_lease_expiry_recovers_as_failed(
    tmp_path,
) -> None:
    """Criterion 6: if the process crashes during execution (the
    terminal state was never persisted), a restart MUST recover the
    task as FAILED — even if the lease hasn't expired yet.

    The single-instance model (``recover_all_running_tasks``) treats
    ALL ``status='running'`` rows at startup as crashed (the process
    crash is why we're starting).  Without this, a task with an
    unexpired lease would stay RUNNING forever —
    ``recover_expired_leases`` only matches ``lease_until < now``,
    and the tick loop only fires PENDING tasks.

    Sequence:
      1. Create a task, manually claim it with a 10-minute lease.
      2. Close DB WITHOUT finalizing (simulate crash).
      3. Reopen DB, run migrations, create new engine, ``start()``.
      4. Task recovered as FAILED.
      5. Error message contains 'process restart detected' or 'single-instance'.
      6. Task is NOT in ``_tasks`` as PENDING.
    """
    db_path = tmp_path / "khaos.db"
    db = await _make_db(db_path)
    try:
        engine = CronEngine(db=db)
        task = await engine.create(
            "restart-recover", "p", ScheduleConfig(interval_seconds=60),
            principal_id="alice",
        )

        # Manually claim with a 10-minute lease (unexpired at restart).
        started_at = datetime.utcnow().isoformat()
        lease_until = (datetime.utcnow() + timedelta(minutes=10)).isoformat()
        rowcount = await db.claim_scheduled_task(
            task.id,
            execution_id="test-exec-6",
            started_at=started_at,
            lease_until=lease_until,
            expected_version=task.lifecycle_version,
        )
        assert rowcount == 1, "claim should succeed — task is PENDING"
    finally:
        await db.close()

    # Restart: reopen DB, create new engine, start().
    db2 = await _make_db(db_path)
    try:
        engine2 = CronEngine(db=db2)
        await engine2.start()

        row = await db2.get_scheduled_task(task.id)
        assert row["status"] == "failed", (
            f"expected failed (single-instance recovery), got {row['status']} — "
            "an unexpired RUNNING row was not recovered at startup"
        )
        error = row["error"] or ""
        assert (
            "process restart detected" in error
            or "single-instance" in error
        ), (
            f"error should mention process restart or single-instance, "
            f"got: {error!r}"
        )
        assert row["execution_id"] is None, (
            "execution_id should be cleared after recovery"
        )
        assert row["lease_until"] is None, (
            "lease_until should be cleared after recovery"
        )

        # Task is NOT in _tasks as PENDING (it's FAILED).
        loaded_task = engine2._tasks.get(task.id)
        assert loaded_task is not None, (
            "task should be loaded into _tasks (as FAILED)"
        )
        assert loaded_task.status != TaskStatus.PENDING, (
            f"task status={loaded_task.status}, expected NOT PENDING — "
            "a FAILED task should not be fired by the tick loop"
        )
        assert loaded_task.status == TaskStatus.FAILED, (
            f"task status={loaded_task.status}, expected FAILED"
        )

        await engine2.stop(timeout=2.0)
    finally:
        await db2.close()


# ---------------------------------------------------------------------------
# Acceptance 7: recovery sweeps all abnormal leases
# ---------------------------------------------------------------------------


async def test_acceptance_7_recovery_sweeps_all_abnormal_leases(
    tmp_path,
) -> None:
    """Criterion 7: ``recover_all_running_tasks`` at startup catches
    ALL ``status='running'`` rows regardless of lease state:
      - expired lease (``lease_until < now``)
      - unexpired lease (``lease_until > now``)
      - orphaned (``lease_until IS NULL`` + ``execution_id IS NULL``)

    Without the single-instance model, only expired leases were
    recovered — unexpired and orphaned rows stayed RUNNING forever.

    Sequence:
      1. Create 3 tasks (A, B, C).
      2. Via raw SQL, set them to ``running`` with abnormal leases.
      3. Close DB, reopen, create new engine, ``start()``.
      4. ALL THREE recovered as FAILED.
    """
    db_path = tmp_path / "khaos.db"
    db = await _make_db(db_path)
    try:
        engine = CronEngine(db=db)
        task_a = await engine.create(
            "expired-lease", "p", ScheduleConfig(interval_seconds=3600),
            principal_id="alice",
        )
        task_b = await engine.create(
            "unexpired-lease", "p", ScheduleConfig(interval_seconds=3600),
            principal_id="alice",
        )
        task_c = await engine.create(
            "orphaned-lease", "p", ScheduleConfig(interval_seconds=3600),
            principal_id="alice",
        )

        # Set abnormal states via raw SQL.
        conn = await db._require_conn()
        # Task A: running + expired lease.
        await conn.execute(
            "UPDATE scheduled_tasks SET status='running', "
            "execution_id=?, lease_until=? WHERE id=?",
            (
                "exec-a",
                (datetime.utcnow() - timedelta(minutes=5)).isoformat(),
                task_a.id,
            ),
        )
        # Task B: running + unexpired lease.
        await conn.execute(
            "UPDATE scheduled_tasks SET status='running', "
            "execution_id=?, lease_until=? WHERE id=?",
            (
                "exec-b",
                (datetime.utcnow() + timedelta(minutes=10)).isoformat(),
                task_b.id,
            ),
        )
        # Task C: running + NULL lease + NULL execution_id (orphaned).
        await conn.execute(
            "UPDATE scheduled_tasks SET status='running', "
            "execution_id=NULL, lease_until=NULL WHERE id=?",
            (task_c.id,),
        )
        await conn.commit()
    finally:
        await db.close()

    # Restart: reopen DB, create new engine, start().
    db2 = await _make_db(db_path)
    try:
        engine2 = CronEngine(db=db2)
        await engine2.start()

        for task_id, label in [
            (task_a.id, "expired lease"),
            (task_b.id, "unexpired lease"),
            (task_c.id, "orphaned (NULL lease)"),
        ]:
            row = await db2.get_scheduled_task(task_id)
            assert row["status"] == "failed", (
                f"task with {label}: expected failed (single-instance "
                f"recovery), got {row['status']}"
            )
            assert row["execution_id"] is None, (
                f"task with {label}: execution_id should be cleared"
            )
            assert row["lease_until"] is None, (
                f"task with {label}: lease_until should be cleared"
            )

        await engine2.stop(timeout=2.0)
    finally:
        await db2.close()


# ---------------------------------------------------------------------------
# Acceptance 8: legacy principal_id quarantined at migration
# ---------------------------------------------------------------------------


async def test_acceptance_8_legacy_cron_quarantined(tmp_path) -> None:
    """Criterion 8: legacy tasks (``principal_id='legacy'``) are
    QUARANTINED at migration time — ``status`` is set to ``failed``
    and ``error`` records the quarantine reason.

    Previously the migration comment claimed legacy tasks were
    "hidden", but ``CronEngine`` loads ALL tasks and the executor
    only rejected EMPTY principal — so ``'legacy'`` (non-empty) tasks
    would execute as a synthetic principal with no real owner.

    Sequence:
      1. Create a DB, run migrations.
      2. Manually insert a task with ``principal_id='legacy'`` via raw SQL.
      3. Close DB, reopen, run migrations again (triggers quarantine UPDATE).
      4. Verify the legacy task has ``status='failed'`` and error
         contains 'quarantined'.
      5. Create an engine, ``start()``, verify loaded as FAILED.
      6. Verify tick loop does NOT fire it.
    """
    db_path = tmp_path / "khaos.db"
    db = await _make_db(db_path)
    legacy_task_id = uuid.uuid4().hex
    try:
        # Insert a legacy task via raw SQL (bypasses engine.create's
        # principal_id validation).
        conn = await db._require_conn()
        await conn.execute(
            "INSERT INTO scheduled_tasks (id, name, prompt, status, "
            "schedule_config, principal_id) VALUES (?, ?, ?, ?, ?, ?)",
            (
                legacy_task_id,
                "legacy-task",
                "p",
                "pending",
                '{"interval_seconds": 60}',
                "legacy",
            ),
        )
        await conn.commit()
    finally:
        await db.close()

    # Reopen and re-run migrations → quarantine UPDATE triggers.
    db2 = await _make_db(db_path)
    try:
        row = await db2.get_scheduled_task(legacy_task_id)
        assert row is not None, "legacy task row disappeared"
        assert row["status"] == "failed", (
            f"expected failed (quarantined), got {row['status']}"
        )
        error = row["error"] or ""
        assert "quarantined" in error, (
            f"error should mention 'quarantined', got: {error!r}"
        )
    finally:
        await db2.close()

    # Create an engine, start(), verify loaded as FAILED.
    db3 = await _make_db(db_path)
    try:
        executor_calls: list[str] = []

        async def recording_executor(task_id: str, prompt: str, principal_id: str) -> str:
            executor_calls.append(task_id)
            return "should-not-reach"

        engine3 = CronEngine(
            db=db3, executor=recording_executor, tick_interval=0.01,
        )
        await engine3.start()

        # The legacy task is loaded as FAILED (not PENDING).
        loaded_task = engine3._tasks.get(legacy_task_id)
        assert loaded_task is not None, (
            "legacy task should be loaded into _tasks"
        )
        assert loaded_task.status == TaskStatus.FAILED, (
            f"legacy task status={loaded_task.status}, expected FAILED"
        )

        # Let the tick loop run a few times.
        await asyncio.sleep(0.3)

        # The tick loop does NOT fire it (it's FAILED, not PENDING).
        assert len(executor_calls) == 0, (
            f"executor was called {len(executor_calls)} time(s) — "
            "the quarantined legacy task was fired by the tick loop"
        )

        await engine3.stop(timeout=2.0)
    finally:
        await db3.close()


# ---------------------------------------------------------------------------
# Acceptance 9: _load_tasks failure enters degraded mode
# ---------------------------------------------------------------------------


async def test_acceptance_9_load_tasks_failure_enters_degraded_mode(
    tmp_path,
) -> None:
    """Criterion 9: if ``_load_tasks`` fails (e.g. ``list_scheduled_tasks``
    raises), the engine enters ``_degraded`` mode — the tick loop runs
    (so pause/resume/remove still work) but ``_execute_task`` refuses
    to fire new executions.

    Without this, a load failure left the engine with an empty
    ``_tasks`` dict but ``_running=True`` — the tick loop accepted
    new creations and fired them, while pre-existing DB tasks were
    invisible (and could be re-created with the same name, racing
    the hidden rows).

    M4 batch 3.1.16B-5 (CRITICAL): ``create()`` now refuses degraded
    mode (raises ``RuntimeError("engine_degraded")``) — a stricter
    form of the same safety guarantee.  Previously ``create()``
    succeeded but the tick loop refused to fire; now the refusal
    happens at creation time, giving the caller an immediate signal.

    Sequence:
      1. Create a DB with a task.
      2. Patch ``list_scheduled_tasks`` to raise ``RuntimeError``.
      3. Create an engine, ``start()``.
      4. ``engine._degraded == True``.
      5. ``engine._running == True`` (tick loop active for control ops).
      6. ``create()`` MUST raise ``RuntimeError("engine_degraded")``.
      7. Restore ``list_scheduled_tasks``, ``stop()``.
    """
    db = await _make_db(tmp_path)
    try:
        # Pre-create a task so the DB is non-empty.
        engine_pre = CronEngine(db=db)
        await engine_pre.create(
            "pre-existing", "p", ScheduleConfig(interval_seconds=3600),
            principal_id="alice",
        )

        executor_calls: list[str] = []

        async def recording_executor(task_id: str, prompt: str, principal_id: str) -> str:
            executor_calls.append(task_id)
            return "should-not-reach"

        # Patch list_scheduled_tasks to raise.
        original_list = db.list_scheduled_tasks

        async def failing_list(*args, **kwargs):
            raise RuntimeError("DB unreadable")

        db.list_scheduled_tasks = failing_list

        engine = CronEngine(
            db=db, executor=recording_executor, tick_interval=0.01,
        )
        await engine.start()

        # The engine MUST be in degraded mode.
        assert engine._degraded is True, (
            "engine is NOT in degraded mode despite _load_tasks failing — "
            "new executions would be accepted with unknown DB state"
        )
        # The tick loop is active (for control ops).
        assert engine._running is True, (
            "engine is NOT running — control ops (pause/resume/remove) "
            "would not work"
        )

        # M4 batch 3.1.16B-5: create() MUST raise in degraded mode.
        iso = (datetime.utcnow() - timedelta(seconds=10)).isoformat()
        with pytest.raises(RuntimeError, match="engine_degraded"):
            await engine.create(
                "degraded-fire", "p", ScheduleConfig(iso_time=iso),
                principal_id="alice",
            )

        # The executor MUST NOT have been called (no task was created).
        assert len(executor_calls) == 0

        # Restore list_scheduled_tasks for clean shutdown.
        db.list_scheduled_tasks = original_list
        await engine.stop(timeout=2.0)
    finally:
        await db.close()


# ---------------------------------------------------------------------------
# Acceptance 10: crash-point injection (commit-then-raise)
# ---------------------------------------------------------------------------


async def test_acceptance_10_crash_point_injection(tmp_path) -> None:
    """Criterion 10: if ``control_finalize_scheduled_task`` commits
    the CAS UPDATE but raises (ambiguous commit — e.g. network error
    between commit and response), the engine reads back the row to
    verify the commit actually took effect (target version + desired
    status).  Only if verification succeeds does the control op
    return ``ok`` — and the ``lifecycle_version`` is bumped EXACTLY
    once (no version drift from the retry).

    Without the read-back, a commit-then-raise would leave a marker
    in ``_pending_persistence`` and the next reconcile would retry
    the CAS — but the DB is already at the target version, so the
    retry matches 0 rows.  Without the idempotent read-back in
    retry, the reconcile would raise ``ServiceShutdownError`` even
    though the desired state was already durable.

    Sequence:
      1. Create a PENDING task with future ISO time.
      2. Patch ``control_finalize_scheduled_task`` with commit-then-raise
         on the first call; subsequent calls delegate to the original.
      3. ``pause()`` → ``ok`` (read-back confirms the commit-then-raise).
      4. DB status is ``paused`` and ``lifecycle_version`` bumped exactly once.
      5. ``_pending_persistence`` does NOT have a marker (read-back confirmed).
    """
    db = await _make_db(tmp_path)
    try:
        engine = CronEngine(db=db)
        iso = (datetime.utcnow() + timedelta(hours=1)).isoformat()
        task = await engine.create(
            "crash-point", "p", ScheduleConfig(iso_time=iso),
            principal_id="alice",
        )
        version_before = int(
            (await db.get_scheduled_task(task.id))["lifecycle_version"]
        )

        # Patch control_finalize with commit-then-raise on first call.
        original_control = db.control_finalize_scheduled_task
        call_count = {"n": 0}

        async def commit_then_raise(*args, **kwargs):
            call_count["n"] += 1
            if call_count["n"] == 1:
                # First call: commit the UPDATE, then raise.
                result = await original_control(*args, **kwargs)
                raise RuntimeError("ambiguous commit — network error")
            # Subsequent calls: delegate to the original.
            return await original_control(*args, **kwargs)

        db.control_finalize_scheduled_task = commit_then_raise

        # pause() → ok (read-back confirms the commit-then-raise).
        result = await engine.pause(task.id, principal_id="alice")
        assert result == "ok", (
            f"expected ok (commit-then-raise recovered via read-back), "
            f"got {result}"
        )

        # DB status is 'paused'.
        row_after = await db.get_scheduled_task(task.id)
        assert row_after["status"] == TaskStatus.PAUSED.value, (
            f"expected paused, got {row_after['status']}"
        )

        # lifecycle_version bumped exactly once (no drift).
        version_after = int(row_after["lifecycle_version"])
        assert version_after == version_before + 1, (
            f"lifecycle_version drifted: before={version_before}, "
            f"after={version_after} — expected exactly +1; the "
            "commit-then-raise read-back path bumped the version again"
        )

        # _pending_persistence does NOT have a marker (read-back confirmed).
        assert task.id not in engine._pending_persistence, (
            "a marker was left in _pending_persistence despite the "
            "read-back confirming success — reconcile would needlessly "
            "retry"
        )

        # The first call raised (commit-then-raise); no subsequent calls
        # should have been needed (read-back confirmed on the first).
        assert call_count["n"] == 1, (
            f"control_finalize was called {call_count['n']} time(s) — "
            "expected exactly 1 (the commit-then-raise); the read-back "
            "should have confirmed success without a retry"
        )

        db.control_finalize_scheduled_task = original_control
    finally:
        await db.close()
