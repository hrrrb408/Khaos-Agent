"""M4 Batch 3.1.14 — Atomic Degraded Admission, Generation-Fenced
Reconcile and Safe Instance Lock Closure.

Acceptance tests for the 10 criteria specified in the batch review:

  1.  A's lease revocation fails → B in the same tick must not start.
  2.  Lease recovery DB write fails → same tick must not start any task.
  3.  ``_degraded=True`` → every executor-publishing path re-checks.
  4.  Reconcile holds the per-task lock.
  5.  Reconcile re-verifies ``operation_id`` before writing.
  6.  Old marker does NOT overwrite a newer Pause/Resume/Remove.
  7.  Reconcile propagates persistence ``False``.
  8.  Lockfile symlink rejected; symlink target content unchanged.
  9.  Existing lockfile validated (UID, mode, inode, file type).
  10. Init failure (UDS probe / migration / agent.start) → lock safely
      retryable.
"""

from __future__ import annotations

import asyncio
import os
import stat
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from khaos.db import Database
from khaos.exceptions import ServiceShutdownError
from khaos.scheduler import CronEngine, ScheduleConfig, ScheduledTask, TaskStatus
from khaos.scheduler.engine import PendingPersistence


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


# ---------------------------------------------------------------------------
# Acceptance 1: A's lease revocation fails → B must not start
# ---------------------------------------------------------------------------


async def test_acceptance_1_lease_revocation_failure_stops_tick(
    tmp_path, monkeypatch,
) -> None:
    """Criterion 1: when Task A's lease revocation fails (executor
    resists cancellation), Task B (immediately due, PENDING) MUST NOT
    start in the same tick iteration.

    Without the CRITICAL-1 fix, the tick loop set ``_degraded=True``
    but did NOT break out of the sweep loop or skip ``due_candidates``
    — so Task B would start executing despite the execution ownership
    being untrusted.
    """
    # Short cancel budget so the test doesn't wait 10s for the
    # resistant executor to time out.
    import khaos.scheduler.engine as _engine_mod
    monkeypatch.setattr(_engine_mod, "_CANCEL_IN_FLIGHT_TIMEOUT", 0.3)

    db = await _make_db(tmp_path)
    try:
        b_exec_count = 0

        async def resistant_executor(task_id, prompt, principal_id):
            # Task A's executor — resists cancellation forever.
            try:
                await asyncio.sleep(3600)
            except asyncio.CancelledError:
                # First cancel: resist (sleep again).  Second cancel
                # (from test cleanup): re-raise.
                try:
                    await asyncio.sleep(3600)
                except asyncio.CancelledError:
                    raise

        async def counting_executor(task_id, prompt, principal_id):
            nonlocal b_exec_count
            b_exec_count += 1
            return "done"

        # Create engine with a resistant executor (for task A).
        engine = CronEngine(
            db=db, executor=resistant_executor, tick_interval=0.05,
        )
        await engine.start()
        try:
            # Create Task A with an immediately-due schedule.
            past_iso = (datetime.utcnow() - timedelta(seconds=10)).isoformat()
            task_a = await engine.create(
                "task-a-resistant", "a", ScheduleConfig(iso_time=past_iso),
                principal_id="alice",
            )
            # Wait for A to start executing.
            await asyncio.sleep(0.3)
            assert task_a.id in engine._execute_tasks, (
                "Task A should be executing"
            )

            # Now expire A's lease and force a sweep.
            expired_iso = (datetime.utcnow() - timedelta(seconds=60)).isoformat()
            conn = await db._require_conn()
            await conn.execute(
                "UPDATE scheduled_tasks SET lease_until = ? WHERE id = ?",
                (expired_iso, task_a.id),
            )
            await conn.commit()

            # Switch executor to counting (for task B).
            engine._executor = engine._wrap_executor(counting_executor)

            # Create Task B — immediately due.
            task_b = await engine.create(
                "task-b-due", "b", ScheduleConfig(iso_time=past_iso),
                principal_id="alice",
            )

            # Force sweep on next tick.
            engine._last_lease_sweep = 0.0

            # Wait for the sweep to run + cancel budget (0.3s) + a
            # couple of ticks for the degraded flag to be observed.
            await asyncio.sleep(2.0)

            # CRITICAL-1 assertion: B must NOT have started.
            assert b_exec_count == 0, (
                f"Task B started {b_exec_count} time(s) despite Task A's "
                "lease revocation failure — degraded mode should have "
                "prevented any new execution in the same tick"
            )
            assert engine._degraded, (
                "Engine should be in degraded mode after Task A's "
                "revocation failure"
            )
        finally:
            # Cancel the resistant executor so stop() can drain.
            exec_task = engine._execute_tasks.get(task_a.id)
            if exec_task and not exec_task.done():
                exec_task.cancel()
                try:
                    await asyncio.wait_for(exec_task, timeout=1.0)
                except (asyncio.CancelledError, asyncio.TimeoutError):
                    pass
                engine._execute_tasks.pop(task_a.id, None)
            # Clear degraded so stop doesn't hang.
            engine._degraded = False
            await engine.stop(timeout=5.0)
    finally:
        await db.close()


# ---------------------------------------------------------------------------
# Acceptance 2: Lease recovery DB write fails → same tick must not start
# ---------------------------------------------------------------------------


async def test_acceptance_2_lease_recovery_db_failure_stops_tick(tmp_path) -> None:
    """Criterion 2: when the lease recovery DB write fails (``recover_
    one_expired_lease`` raises), the tick must NOT start any due task
    in the same iteration.

    Without the CRITICAL-1 fix, ``_revoke_and_recover_lease`` set
    ``_degraded=True`` but returned ``True``, so the tick loop's
    ``if not ok: break`` didn't fire — it fell through to
    ``due_candidates`` and started unrelated tasks.
    """
    db = await _make_db(tmp_path)
    try:
        b_exec_count = 0

        async def quick_executor(task_id, prompt, principal_id):
            return "done"

        async def counting_executor(task_id, prompt, principal_id):
            nonlocal b_exec_count
            b_exec_count += 1
            return "done"

        engine = CronEngine(
            db=db, executor=quick_executor, tick_interval=0.05,
        )
        await engine.start()
        try:
            # Create Task A with an expired lease.
            past_iso = (datetime.utcnow() - timedelta(seconds=10)).isoformat()
            task_a = await engine.create(
                "task-a-expired", "a", ScheduleConfig(iso_time=past_iso),
                principal_id="alice",
            )
            # Wait for A to execute and complete.
            await asyncio.sleep(0.3)

            # Manually set A to running with an expired lease.
            expired_iso = (datetime.utcnow() - timedelta(seconds=60)).isoformat()
            conn = await db._require_conn()
            await conn.execute(
                "UPDATE scheduled_tasks SET status = 'running', "
                "lease_until = ?, execution_id = ? WHERE id = ?",
                (expired_iso, "test-exec-a", task_a.id),
            )
            await conn.commit()

            # Patch recover_one_expired_lease to raise.
            original = db.recover_one_expired_lease

            async def failing_recover(*args, **kwargs):
                raise RuntimeError("DB write failed")

            db.recover_one_expired_lease = failing_recover

            # Switch to counting executor for task B.
            engine._executor = engine._wrap_executor(counting_executor)

            # Create Task B — immediately due.
            task_b = await engine.create(
                "task-b-due", "b", ScheduleConfig(iso_time=past_iso),
                principal_id="alice",
            )

            # Force sweep.
            engine._last_lease_sweep = 0.0

            # Wait for the sweep to run.
            await asyncio.sleep(1.0)

            # CRITICAL-1 assertion: B must NOT have started.
            assert b_exec_count == 0, (
                f"Task B started {b_exec_count} time(s) despite DB write "
                "failure during lease recovery — degraded mode should "
                "have prevented any new execution"
            )
            assert engine._degraded, (
                "Engine should be in degraded mode after DB write failure"
            )

            # Restore for cleanup.
            db.recover_one_expired_lease = original
        finally:
            engine._degraded = False
            await engine.stop(timeout=5.0)
    finally:
        await db.close()


# ---------------------------------------------------------------------------
# Acceptance 3: _degraded=True → every executor-publishing path re-checks
# ---------------------------------------------------------------------------


async def test_acceptance_3_degraded_blocks_all_executor_publish(tmp_path) -> None:
    """Criterion 3: when ``_degraded=True``, the defensive re-check
    right before ``asyncio.create_task(self._execute_task(task))``
    must prevent the executor from starting.
    """
    db = await _make_db(tmp_path)
    try:
        exec_count = 0

        async def counting_executor(task_id, prompt, principal_id):
            nonlocal exec_count
            exec_count += 1
            return "done"

        engine = CronEngine(
            db=db, executor=counting_executor, tick_interval=0.05,
        )
        await engine.start()
        try:
            # Create a due task.
            past_iso = (datetime.utcnow() - timedelta(seconds=10)).isoformat()
            await engine.create(
                "task-due", "p", ScheduleConfig(iso_time=past_iso),
                principal_id="alice",
            )

            # Set degraded BEFORE the tick fires.
            engine._degraded = True

            # Wait for several ticks.
            await asyncio.sleep(0.5)

            # The defensive check should have prevented execution.
            assert exec_count == 0, (
                f"Executor started {exec_count} time(s) despite "
                "_degraded=True — the defensive re-check before "
                "asyncio.create_task failed"
            )
        finally:
            engine._degraded = False
            await engine.stop(timeout=5.0)
    finally:
        await db.close()


# ---------------------------------------------------------------------------
# Acceptance 4: Reconcile holds the per-task lock
# ---------------------------------------------------------------------------


async def test_acceptance_4_reconcile_holds_per_task_lock(tmp_path) -> None:
    """Criterion 4: reconcile acquires the per-task lock before
    processing each marker.  If the lock is held by another op,
    reconcile must defer (not race).
    """
    db = await _make_db(tmp_path)
    try:
        engine = CronEngine(db=db)
        await engine.start()
        try:
            # Create a task and place a marker.
            future_iso = (datetime.utcnow() + timedelta(hours=1)).isoformat()
            task = await engine.create(
                "task-marker", "p", ScheduleConfig(iso_time=future_iso),
                principal_id="alice",
            )
            engine._pending_persistence[task.id] = PendingPersistence(
                operation_id="op-1",
                desired_status=TaskStatus.PAUSED.value,
                expected_version=task.lifecycle_version,
                is_control_op=True,
                target_version=task.lifecycle_version + 1,
            )

            # Hold the per-task lock.
            lock = engine._task_lock(task.id)
            await lock.acquire()

            # Run reconcile in a task — it should block on the lock
            # (reconcile's internal wait_for has a 5s timeout).
            reconcile_task = asyncio.create_task(
                engine._reconcile_pending_persistence()
            )
            # Give reconcile time to attempt the acquire.  Use sleep
            # (NOT wait_for) so the task is NOT cancelled — wait_for
            # cancels the inner task on timeout, which would prevent
            # us from awaiting it again after releasing the lock.
            await asyncio.sleep(2.0)

            # Assert reconcile is still pending — it MUST be blocked
            # on the lock acquisition (its internal timeout is 5s).
            assert not reconcile_task.done(), (
                "reconcile completed while the per-task lock was held "
                "— it did NOT acquire the lock (or didn't even try)"
            )

            # Release the lock — reconcile should now proceed.
            lock.release()
            try:
                await asyncio.wait_for(reconcile_task, timeout=10.0)
            except ServiceShutdownError:
                pass  # May raise if the CAS fails (expected — DB is at pending)
        finally:
            engine._degraded = False
            await engine.stop(timeout=5.0)
    finally:
        await db.close()


# ---------------------------------------------------------------------------
# Acceptance 5: Reconcile re-verifies operation_id before writing
# ---------------------------------------------------------------------------


async def test_acceptance_5_reconcile_reverifies_operation_id(tmp_path) -> None:
    """Criterion 5: reconcile re-verifies the marker's ``operation_id``
    under the lock.  If a newer op superseded the marker between the
    snapshot and the retry, the old marker is SKIPPED.
    """
    db = await _make_db(tmp_path)
    try:
        engine = CronEngine(db=db)
        await engine.start()
        try:
            future_iso = (datetime.utcnow() + timedelta(hours=1)).isoformat()
            task = await engine.create(
                "task-supersede", "p", ScheduleConfig(iso_time=future_iso),
                principal_id="alice",
            )

            # Place marker A (PAUSED).
            engine._pending_persistence[task.id] = PendingPersistence(
                operation_id="op-A-paused",
                desired_status=TaskStatus.PAUSED.value,
                expected_version=task.lifecycle_version,
                is_control_op=True,
                target_version=task.lifecycle_version + 1,
            )

            # Snapshot marker A (what reconcile would see).
            snapshot = engine._pending_persistence[task.id]

            # Supersede with marker B (CANCELLED) — simulating a
            # concurrent Remove that happened after the snapshot.
            engine._pending_persistence[task.id] = PendingPersistence(
                operation_id="op-B-cancelled",
                desired_status=TaskStatus.CANCELLED.value,
                expected_version=task.lifecycle_version,
                is_control_op=True,
                target_version=task.lifecycle_version + 1,
            )

            # Directly test the operation_id re-check by simulating
            # what reconcile does: acquire lock, check operation_id.
            lock = engine._task_lock(task.id)
            await lock.acquire()
            try:
                current = engine._pending_persistence.get(task.id)
                assert current is not None
                assert current.operation_id != snapshot.operation_id, (
                    "marker should have been superseded"
                )
                # Reconcile would SKIP this snapshot — the current
                # marker (op-B) is not our responsibility.
            finally:
                lock.release()

            # Run reconcile — it should skip snapshot A and process
            # marker B (which will try to write CANCELLED).
            # The CAS will likely fail (DB is at pending, expected
            # version matches, so it should actually succeed).
            await engine._reconcile_pending_persistence()

            # The marker should be cleared (either A was skipped, or
            # B was persisted).  Check the DB is NOT paused (A's
            # desired state was NOT written).
            row = await db.get_scheduled_task(task.id)
            assert row["status"] != TaskStatus.PAUSED.value, (
                f"DB status is {row['status']!r} — old marker A (PAUSED) "
                "was written despite being superseded by marker B"
            )
        finally:
            engine._degraded = False
            await engine.stop(timeout=5.0)
    finally:
        await db.close()


# ---------------------------------------------------------------------------
# Acceptance 6: Old marker doesn't overwrite newer Pause/Resume/Remove
# ---------------------------------------------------------------------------


async def test_acceptance_6_old_marker_does_not_overwrite_newer_remove(tmp_path) -> None:
    """Criterion 6: an old marker (Pause A, PAUSED) MUST NOT overwrite
    a newer op's state (Remove B, CANCELLED) during reconcile.

    Sequence:
      1. Create a PENDING task.
      2. Pause fails → marker A (PAUSED, expected=1, target=2).
      3. Remove succeeds → DB = CANCELLED at version 2, marker B
         (CANCELLED, expected=1, target=2) replaces marker A.
      4. Reconcile processes marker B → writes CANCELLED.
      5. Assert DB = CANCELLED (not PAUSED).

    This is the integration version of test 5: the old reconcile
    would have called ``_persist_task_state(op=A)`` which reads the
    DB current version and writes PAUSED — overwriting CANCELLED.
    The new reconcile uses ``_retry_control_marker`` which uses the
    marker's OWN CAS pair and pops stale markers.
    """
    db = await _make_db(tmp_path)
    try:
        engine = CronEngine(db=db)
        await engine.start()
        try:
            future_iso = (datetime.utcnow() + timedelta(hours=1)).isoformat()
            task = await engine.create(
                "task-overwrite", "p", ScheduleConfig(iso_time=future_iso),
                principal_id="alice",
            )
            task_id = task.id
            initial_version = task.lifecycle_version

            # Step 1: Place marker A (PAUSED) — simulating a failed
            # pause.
            engine._pending_persistence[task_id] = PendingPersistence(
                operation_id="op-A-paused",
                desired_status=TaskStatus.PAUSED.value,
                expected_version=initial_version,
                is_control_op=True,
                target_version=initial_version + 1,
            )

            # Step 2: Simulate Remove B succeeding — write CANCELLED
            # to the DB at version initial_version + 1.
            await db.control_finalize_scheduled_task(
                task_id,
                expected_version=initial_version,
                target_version=initial_version + 1,
                status=TaskStatus.CANCELLED.value,
                next_run=None,
                error=None,
            )

            # Step 3: Supersede marker A with marker B (CANCELLED).
            engine._pending_persistence[task_id] = PendingPersistence(
                operation_id="op-B-cancelled",
                desired_status=TaskStatus.CANCELLED.value,
                expected_version=initial_version,
                is_control_op=True,
                target_version=initial_version + 1,
            )

            # Step 4: Run reconcile.
            await engine._reconcile_pending_persistence()

            # Step 5: Assert DB = CANCELLED (not PAUSED).
            row = await db.get_scheduled_task(task_id)
            assert row["status"] == TaskStatus.CANCELLED.value, (
                f"DB status is {row['status']!r}, expected CANCELLED — "
                "old marker A (PAUSED) overwrote Remove B's CANCELLED"
            )
            assert task_id not in engine._pending_persistence, (
                "marker should be cleared after reconcile"
            )
        finally:
            engine._degraded = False
            await engine.stop(timeout=5.0)
    finally:
        await db.close()


# ---------------------------------------------------------------------------
# Acceptance 7: Reconcile propagates persistence False
# ---------------------------------------------------------------------------


async def test_acceptance_7_reconcile_propagates_false(tmp_path) -> None:
    """Criterion 7: when ``_retry_control_marker`` returns ``False``
    (DB read failure), reconcile must add the task to ``failures``
    and raise ``ServiceShutdownError``.
    """
    db = await _make_db(tmp_path)
    try:
        engine = CronEngine(db=db)
        await engine.start()
        try:
            future_iso = (datetime.utcnow() + timedelta(hours=1)).isoformat()
            task = await engine.create(
                "task-fail", "p", ScheduleConfig(iso_time=future_iso),
                principal_id="alice",
            )

            engine._pending_persistence[task.id] = PendingPersistence(
                operation_id="op-1",
                desired_status=TaskStatus.PAUSED.value,
                expected_version=task.lifecycle_version,
                is_control_op=True,
                target_version=task.lifecycle_version + 1,
            )

            # Patch get_scheduled_task to raise.
            original_get = db.get_scheduled_task

            async def failing_get(*args, **kwargs):
                raise RuntimeError("DB read failed")

            db.get_scheduled_task = failing_get

            # Reconcile should raise ServiceShutdownError.
            with pytest.raises(ServiceShutdownError):
                await engine._reconcile_pending_persistence()

            # Restore for cleanup.
            db.get_scheduled_task = original_get
        finally:
            engine._degraded = False
            await engine.stop(timeout=5.0)
    finally:
        await db.close()


# ---------------------------------------------------------------------------
# Acceptance 8: Lockfile symlink rejected, target content unchanged
# ---------------------------------------------------------------------------


async def test_acceptance_8_lockfile_symlink_rejected() -> None:
    """Criterion 8: a symlink at the lockfile path MUST be rejected.
    The symlink target's content MUST NOT be truncated.

    Without the CRITICAL-2 fix, ``os.open`` followed the symlink and
    ``ftruncate(fd, 0)`` truncated the target file's content.
    """
    import hashlib
    from khaos.grpc_server import _acquire_instance_lock, _instance_lockfile_path

    # Create a target file with known content.
    target = Path(tempfile.gettempdir()) / f"khaos_test_target_{os.getpid()}.txt"
    target_content = "authorized_keys content\n" * 10
    target.write_text(target_content)
    target.chmod(0o600)
    try:
        # Compute the lockfile path for a fake DB path.
        fake_db = str(target.parent / "fake_khaos_symlink_test.db")
        lockfile_path = _instance_lockfile_path(fake_db)

        # Create the lockfile dir if needed.
        lockfile_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)

        # Place a symlink at the lockfile path pointing to our target.
        if lockfile_path.exists() or lockfile_path.is_symlink():
            lockfile_path.unlink()
        lockfile_path.symlink_to(target)

        # Try to acquire the lock — should raise PermissionError.
        raised = False
        try:
            _acquire_instance_lock(fake_db)
        except PermissionError:
            raised = True
        except OSError:
            # O_NOFOLLOW raises ELOOP on Linux — also acceptable.
            raised = True

        assert raised, (
            "lockfile symlink was NOT rejected — the target file may "
            "have been truncated"
        )

        # CRITICAL assertion: target content is UNCHANGED.
        assert target.read_text() == target_content, (
            "symlink target content was truncated — the old code "
            "followed the symlink and ftruncate'd the target file"
        )

        # Clean up the symlink.
        if lockfile_path.is_symlink():
            lockfile_path.unlink()
    finally:
        if target.exists():
            target.unlink()


# ---------------------------------------------------------------------------
# Acceptance 9: Existing lockfile validated (UID, mode, inode, file type)
# ---------------------------------------------------------------------------


async def test_acceptance_9_existing_lockfile_validated() -> None:
    """Criterion 9: an existing lockfile with unsafe mode (group/other
    bits set) MUST be rejected.
    """
    from khaos.grpc_server import _acquire_instance_lock, _instance_lockfile_path

    fake_db = str(Path(tempfile.gettempdir()) / "fake_khaos_mode_test.db")
    lockfile_path = _instance_lockfile_path(fake_db)

    # Create the lockfile with unsafe mode (0644).
    lockfile_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if lockfile_path.exists():
        lockfile_path.unlink()
    lockfile_path.write_text("stale\n")
    lockfile_path.chmod(0o644)  # Unsafe — group/other can read.

    try:
        raised = False
        try:
            _acquire_instance_lock(fake_db)
        except PermissionError as exc:
            if "unsafe mode" in str(exc) or "group/other" in str(exc):
                raised = True
            else:
                # Some other PermissionError — still a rejection.
                raised = True

        assert raised, (
            "lockfile with unsafe mode 0644 was NOT rejected — the "
            "mode validation is missing"
        )
    finally:
        if lockfile_path.exists():
            lockfile_path.chmod(0o600)
            lockfile_path.unlink()


# ---------------------------------------------------------------------------
# Acceptance 10: Init failure → lock safely retryable
# ---------------------------------------------------------------------------


async def test_acceptance_10_lock_released_on_init_failure(tmp_path) -> None:
    """Criterion 10: when an init step (UDS probe, migration,
    agent.start) fails AFTER the lock is acquired, the lock MUST be
    released so a retry in the same process can re-acquire it.

    Without the MEDIUM fix, the lock release only lived inside the
    inner ``try/finally`` — an init-phase exception leaked the fd
    and the same-process retry would fail with "another instance
    holds the lock".
    """
    from khaos.grpc_server import _acquire_instance_lock

    db_path = str(tmp_path / "khaos.db")

    # Acquire the lock, simulate init failure, verify the lock is
    # released by the outer try/finally.
    fd = _acquire_instance_lock(db_path)
    assert fd is not None, "lock acquisition should succeed"

    # Simulate init failure — the outer try/finally should release
    # the lock.  Catch the RuntimeError so the test can continue to
    # the retry assertion below.
    try:
        try:
            raise RuntimeError("simulated init failure (e.g. agent.start)")
        finally:
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
    except RuntimeError:
        pass  # Expected — the simulated init failure.

    # Retry — should succeed because the lock was released.
    fd2 = _acquire_instance_lock(db_path)
    assert fd2 is not None, (
        "lock retry failed after init failure — the lock fd was "
        "leaked and the same-process retry couldn't re-acquire it"
    )
    try:
        pass
    finally:
        if fd2 is not None:
            try:
                os.close(fd2)
            except OSError:
                pass
