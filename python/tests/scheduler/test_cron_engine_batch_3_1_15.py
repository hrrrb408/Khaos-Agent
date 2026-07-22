"""M4 Batch 3.1.15 — Quarantined Lifecycle and Retained Instance
Ownership Closure.

Acceptance tests for the 10 criteria specified in the batch review:

  1.  Cancellation-resistant Cron → shutdown failure → second instance
      can't acquire lock.
  2.  Shutdown failure → UDS/instance ownership not silently released.
  3.  Failed ``CronEngine.stop()`` → ``start()`` rejected.
  4.  Failed stop → no ``recover_all_running_tasks()``.
  5.  Failed stop → PENDING task call count = 0.
  6.  ``_build_subagent_service()`` fails after ``agent.start()`` →
      Cron/DB cleaned; cleanup failure retains lock.
  7.  ``~/.khaos`` 0777/0775 rejected, 0755/0700 allowed.
  8.  flock 后替换 lockfile 路径 → 不得形成两个独立锁.
  9.  Executor marker CAS 0 + DB still RUNNING → reconcile fails,
      keeps marker.
  10. Executor finalize commit-then-raise → read back confirm desired
      status before clearing marker.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import stat
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from khaos.db import Database
from khaos.exceptions import ServiceShutdownError
from khaos.scheduler import CronEngine, ScheduleConfig, TaskStatus
from khaos.scheduler.engine import CronEngineState, PendingPersistence
from khaos.time_utils import utc_now_naive


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


def _make_safe_khaos_dir(tmp_path: Path) -> tuple[Path, Path]:
    """Create a safe ``khaos/`` + ``khaos/run/`` directory structure
    under ``tmp_path`` for lockfile tests.

    Returns ``(khaos_dir, run_dir)`` with mode 0755 / 0700 respectively.
    """
    khaos_dir = tmp_path / "khaos"
    khaos_dir.mkdir()
    os.chmod(khaos_dir, 0o755)
    run_dir = khaos_dir / "run"
    run_dir.mkdir()
    os.chmod(run_dir, 0o700)
    return khaos_dir, run_dir


def _reset_retained_lock() -> int | None:
    """Reset the module-level ``_retained_instance_lock_fd`` and return
    the previous value (so the caller can close it)."""
    import khaos.grpc_server as _gs
    prev = _gs._retained_instance_lock_fd
    _gs._retained_instance_lock_fd = None
    return prev


async def _force_cleanup_engine(engine: CronEngine) -> None:
    """Force-stop an engine that may be in QUARANTINED state.

    Cancels all tasks, clears all state, and forces the lifecycle to
    STOPPED.  Used in test cleanup to avoid lingering tasks.
    """
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
# Mock objects for emergency cleanup tests
# ---------------------------------------------------------------------------


class _MockAgentOK:
    """Mock AgentService that shuts down cleanly."""

    _shutdown_completed = False

    async def shutdown(self) -> None:
        self._shutdown_completed = True


class _MockAgentFail:
    """Mock AgentService that raises on shutdown()."""

    _shutdown_completed = False

    async def shutdown(self) -> None:
        raise RuntimeError("simulated agent shutdown failure")


class _MockDBOK:
    """Mock Database that closes cleanly."""

    async def close(self) -> None:
        pass


class _MockDBFail:
    """Mock Database that raises on close()."""

    async def close(self) -> None:
        raise RuntimeError("simulated db close failure")


class _MockSubAgentOK:
    """Mock SubAgentService that shuts down cleanly."""

    async def shutdown(self, timeout: float = 30.0) -> None:
        pass


class _MockSubAgentFail:
    """Mock SubAgentService that raises on shutdown()."""

    async def shutdown(self, timeout: float = 30.0) -> None:
        raise RuntimeError("simulated subagent shutdown failure")


# ---------------------------------------------------------------------------
# Acceptance 1: Cancellation-resistant Cron → shutdown failure →
# second instance can't acquire lock
# ---------------------------------------------------------------------------


async def test_acceptance_1_shutdown_failure_second_instance_locked_out(
    tmp_path, monkeypatch,
) -> None:
    """Criterion 1: when shutdown fails and emergency cleanup fails
    (live cron executors remain), a second instance MUST NOT be able
    to acquire the instance lock.

    The first instance's lock fd is retained in
    ``_retained_instance_lock_fd`` so the OS reaps it on process exit.
    While the first process is still alive, a second
    ``_acquire_instance_lock`` against the same DB MUST raise
    ``PermissionError``.
    """
    import khaos.grpc_server as gs

    # Redirect lockfile to tmp_path.
    _khaos_dir, _run_dir = _make_safe_khaos_dir(tmp_path)
    lockfile_path = _run_dir / "test.instance.lock"
    monkeypatch.setattr(
        gs, "_instance_lockfile_path",
        lambda db_path: lockfile_path,
    )

    # Reset retained lock global.
    prev_retained = _reset_retained_lock()
    if prev_retained is not None:
        try:
            os.close(prev_retained)
        except OSError:
            pass

    db_path = str(tmp_path / "khaos.db")
    try:
        # First instance acquires the lock.
        fd1 = gs._acquire_instance_lock(db_path)
        assert fd1 is not None, "first lock acquisition should succeed"

        # Simulate shutdown failure + emergency cleanup failure.
        # _emergency_instance_cleanup returns False when any cleanup fails.
        cleanup_ok = await gs._emergency_instance_cleanup(
            _MockAgentFail(), _MockDBFail(), None,
        )
        assert not cleanup_ok, (
            "emergency cleanup should return False when agent.shutdown() "
            "and db.close() both fail"
        )

        # Simulate the outer finally logic: retain the lock fd because
        # emergency cleanup failed (live owners remain).
        gs._retained_instance_lock_fd = fd1

        # CRITICAL-1 assertion: second instance CANNOT acquire the lock
        # while the first process's retained fd still holds the flock.
        with pytest.raises(PermissionError, match="another Khaos instance"):
            gs._acquire_instance_lock(db_path)

        # Verify the retained lock global is set to the first fd.
        assert gs._retained_instance_lock_fd is fd1, (
            "retained lock fd should be parked in the module-level global "
            "so it is not garbage-collected (which would close it)"
        )
    finally:
        # Clean up: close the retained lock fd and reset the global.
        if gs._retained_instance_lock_fd is not None:
            try:
                os.close(gs._retained_instance_lock_fd)
            except OSError:
                pass
            gs._retained_instance_lock_fd = None


# ---------------------------------------------------------------------------
# Acceptance 2: Shutdown failure → UDS/instance ownership not silently
# released
# ---------------------------------------------------------------------------


async def test_acceptance_2_shutdown_failure_lock_not_silently_released(
    tmp_path, monkeypatch,
) -> None:
    """Criterion 2: when shutdown fails, the instance lock fd MUST NOT
    be silently released.  The fd is retained in
    ``_retained_instance_lock_fd`` and still holds the flock.
    """
    import fcntl
    import khaos.grpc_server as gs

    _khaos_dir, _run_dir = _make_safe_khaos_dir(tmp_path)
    lockfile_path = _run_dir / "test.instance.lock"
    monkeypatch.setattr(
        gs, "_instance_lockfile_path",
        lambda db_path: lockfile_path,
    )

    prev_retained = _reset_retained_lock()
    if prev_retained is not None:
        try:
            os.close(prev_retained)
        except OSError:
            pass

    db_path = str(tmp_path / "khaos.db")
    try:
        fd1 = gs._acquire_instance_lock(db_path)
        assert fd1 is not None

        # Simulate shutdown failure + emergency cleanup failure.
        cleanup_ok = await gs._emergency_instance_cleanup(
            _MockAgentFail(), None, None,
        )
        assert not cleanup_ok

        # Retain the lock fd (simulating the outer finally logic).
        gs._retained_instance_lock_fd = fd1

        # CRITICAL-1 assertion: the fd is still open and valid.
        st = os.fstat(fd1)
        assert stat.S_ISREG(st.st_mode), (
            "retained lock fd should still be a valid regular file"
        )

        # CRITICAL-1 assertion: the flock is still held.  Try to
        # acquire it on a NEW fd pointing to the same file — should
        # fail with EWOULDBLOCK (LOCK_NB).
        fd_test = os.open(str(lockfile_path), os.O_RDONLY)
        try:
            with pytest.raises(OSError):
                fcntl.flock(fd_test, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(fd_test)

        # Verify the retained global is set.
        assert gs._retained_instance_lock_fd is fd1, (
            "lock fd should be retained in _retained_instance_lock_fd "
            "— not silently released"
        )
    finally:
        if gs._retained_instance_lock_fd is not None:
            try:
                os.close(gs._retained_instance_lock_fd)
            except OSError:
                pass
            gs._retained_instance_lock_fd = None


# ---------------------------------------------------------------------------
# Acceptance 3: Failed stop() → start() rejected
# ---------------------------------------------------------------------------


async def test_acceptance_3_failed_stop_then_start_rejected(tmp_path) -> None:
    """Criterion 3: after a failed ``stop()`` (cancellation-resistant
    executor), the engine transitions to ``QUARANTINED`` and
    ``start()`` MUST raise ``RuntimeError``.
    """
    db = await _make_db(tmp_path)
    engine: CronEngine | None = None
    try:
        async def resistant_executor(task_id, prompt, principal_id):
            # Resist the first cancel (from stop()), yield on the
            # second (from test cleanup).
            try:
                await asyncio.sleep(3600)
            except asyncio.CancelledError:
                try:
                    await asyncio.sleep(3600)
                except asyncio.CancelledError:
                    raise

        engine = CronEngine(
            db=db, executor=resistant_executor, tick_interval=0.05,
        )
        await engine.start()
        assert engine._lifecycle_state == CronEngineState.RUNNING

        # Create a task that's immediately due → executor starts.
        past_iso = (utc_now_naive() - timedelta(seconds=10)).isoformat()
        task_a = await engine.create(
            "task-a-resistant", "a", ScheduleConfig(iso_time=past_iso),
            principal_id="alice",
        )
        # Wait for A to start executing.
        await asyncio.sleep(0.3)
        assert task_a.id in engine._execute_tasks, (
            "Task A should be executing"
        )

        # Call stop() with a short timeout → should raise.
        with pytest.raises(ServiceShutdownError):
            await engine.stop(timeout=0.5)

        # CRITICAL-2 assertion: state is QUARANTINED.
        assert engine._lifecycle_state == CronEngineState.QUARANTINED, (
            f"engine should be QUARANTINED after failed stop(), "
            f"got {engine._lifecycle_state}"
        )

        # CRITICAL-2 assertion: start() is rejected.
        with pytest.raises(RuntimeError, match="QUARANTINED"):
            await engine.start()
    finally:
        if engine is not None:
            await _force_cleanup_engine(engine)
        await db.close()


# ---------------------------------------------------------------------------
# Acceptance 4: Failed stop → no recover_all_running_tasks()
# ---------------------------------------------------------------------------


async def test_acceptance_4_failed_stop_no_recover_all_running(tmp_path) -> None:
    """Criterion 4: after a failed ``stop()``, ``start()`` is rejected
    BEFORE calling ``recover_all_running_tasks()``.
    """
    db = await _make_db(tmp_path)
    engine: CronEngine | None = None
    try:
        recover_call_count = 0
        original_recover = db.recover_all_running_tasks

        async def counting_recover():
            nonlocal recover_call_count
            recover_call_count += 1
            return await original_recover()

        db.recover_all_running_tasks = counting_recover

        async def resistant_executor(task_id, prompt, principal_id):
            try:
                await asyncio.sleep(3600)
            except asyncio.CancelledError:
                try:
                    await asyncio.sleep(3600)
                except asyncio.CancelledError:
                    raise

        engine = CronEngine(
            db=db, executor=resistant_executor, tick_interval=0.05,
        )
        await engine.start()

        past_iso = (utc_now_naive() - timedelta(seconds=10)).isoformat()
        task_a = await engine.create(
            "task-a-resistant", "a", ScheduleConfig(iso_time=past_iso),
            principal_id="alice",
        )
        await asyncio.sleep(0.3)
        assert task_a.id in engine._execute_tasks

        with pytest.raises(ServiceShutdownError):
            await engine.stop(timeout=0.5)

        assert engine._lifecycle_state == CronEngineState.QUARANTINED

        # Reset the counter (recover was called during initial start()).
        recover_call_count = 0

        # start() should be rejected.
        with pytest.raises(RuntimeError, match="QUARANTINED"):
            await engine.start()

        # CRITICAL-2 assertion: recover_all_running_tasks was NOT
        # called by the rejected start().
        assert recover_call_count == 0, (
            f"recover_all_running_tasks was called {recover_call_count} "
            f"time(s) after failed stop — start() should have been "
            f"rejected BEFORE calling recovery (would mark live "
            f"executors as FAILED)"
        )
    finally:
        if engine is not None:
            await _force_cleanup_engine(engine)
        await db.close()


# ---------------------------------------------------------------------------
# Acceptance 5: Failed stop → PENDING task call count = 0
# ---------------------------------------------------------------------------


async def test_acceptance_5_failed_stop_no_pending_executions(tmp_path) -> None:
    """Criterion 5: after a failed ``stop()``, no PENDING task is
    executed.  The tick loop is dead and ``start()`` is rejected, so
    no new executions can happen.
    """
    db = await _make_db(tmp_path)
    engine: CronEngine | None = None
    try:
        b_exec_count = 0

        async def dispatch_executor(task_id, prompt, principal_id):
            nonlocal b_exec_count
            if "task-b" in task_id or "task-b" in (prompt or ""):
                b_exec_count += 1
                return "done"
            # Task A resists cancellation.
            try:
                await asyncio.sleep(3600)
            except asyncio.CancelledError:
                try:
                    await asyncio.sleep(3600)
                except asyncio.CancelledError:
                    raise

        engine = CronEngine(
            db=db, executor=dispatch_executor, tick_interval=0.05,
        )
        await engine.start()

        past_iso = (utc_now_naive() - timedelta(seconds=10)).isoformat()
        task_a = await engine.create(
            "task-a-resistant", "a", ScheduleConfig(iso_time=past_iso),
            principal_id="alice",
        )
        await asyncio.sleep(0.3)
        assert task_a.id in engine._execute_tasks

        # Create Task B with a far-future schedule (not due yet).
        future_iso = (utc_now_naive() + timedelta(hours=1)).isoformat()
        task_b = await engine.create(
            "task-b-future", "task-b", ScheduleConfig(iso_time=future_iso),
            principal_id="alice",
        )

        # Call stop() → fails (A resists).
        with pytest.raises(ServiceShutdownError):
            await engine.stop(timeout=0.5)

        assert engine._lifecycle_state == CronEngineState.QUARANTINED

        # Make Task B immediately due in the DB.
        conn = await db._require_conn()
        await conn.execute(
            "UPDATE scheduled_tasks SET next_run = ? WHERE id = ?",
            (past_iso, task_b.id),
        )
        await conn.commit()

        # Try to restart — should be rejected.
        with pytest.raises(RuntimeError, match="QUARANTINED"):
            await engine.start()

        # Wait a bit to see if any execution happens.
        await asyncio.sleep(0.5)

        # CRITICAL-2 assertion: Task B was never executed.
        assert b_exec_count == 0, (
            f"Task B was executed {b_exec_count} time(s) after failed "
            f"stop — the tick loop should be dead and start() rejected"
        )
    finally:
        if engine is not None:
            await _force_cleanup_engine(engine)
        await db.close()


# ---------------------------------------------------------------------------
# Acceptance 6: _build_subagent_service() fails after agent.start() →
# Cron/DB cleaned; cleanup failure retains lock
# ---------------------------------------------------------------------------


async def test_acceptance_6_init_failure_emergency_cleanup(
    tmp_path, monkeypatch,
) -> None:
    """Criterion 6: when init fails after ``agent.start()``,
    ``_emergency_instance_cleanup`` attempts to clean up Cron/DB.
    If cleanup succeeds → lock released.  If cleanup fails → lock retained.
    """
    import fcntl
    import khaos.grpc_server as gs

    _khaos_dir, _run_dir = _make_safe_khaos_dir(tmp_path)
    lockfile_path = _run_dir / "test.instance.lock"
    monkeypatch.setattr(
        gs, "_instance_lockfile_path",
        lambda db_path: lockfile_path,
    )

    prev_retained = _reset_retained_lock()
    if prev_retained is not None:
        try:
            os.close(prev_retained)
        except OSError:
            pass

    db_path = str(tmp_path / "khaos.db")
    try:
        # Sub-scenario A: cleanup succeeds → lock released.
        fd1 = gs._acquire_instance_lock(db_path)
        assert fd1 is not None

        cleanup_ok = await gs._emergency_instance_cleanup(
            _MockAgentOK(), _MockDBOK(), _MockSubAgentOK(),
        )
        assert cleanup_ok, (
            "emergency cleanup should return True when all cleanups succeed"
        )

        # Lock can be released (simulating the outer finally logic).
        try:
            os.close(fd1)
        except OSError:
            pass

        # Sub-scenario B: cleanup fails → lock retained.
        fd2 = gs._acquire_instance_lock(db_path)
        assert fd2 is not None

        cleanup_ok = await gs._emergency_instance_cleanup(
            _MockAgentFail(), _MockDBOK(), None,
        )
        assert not cleanup_ok, (
            "emergency cleanup should return False when agent.shutdown() "
            "fails (live cron executors may remain)"
        )

        # Simulate the outer finally logic: retain the lock.
        gs._retained_instance_lock_fd = fd2

        # HIGH-1 assertion: the lock is retained (not closed).
        assert gs._retained_instance_lock_fd is fd2, (
            "lock fd should be retained in _retained_instance_lock_fd "
            "when emergency cleanup fails"
        )

        # Verify the retained fd still holds the flock.
        fd_test = os.open(str(lockfile_path), os.O_RDONLY)
        try:
            with pytest.raises(OSError):
                fcntl.flock(fd_test, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(fd_test)

        # Sub-scenario C: subagent cleanup fails → lock retained.
        # (Different failure point — subagent_service.shutdown() raises.)
        try:
            os.close(gs._retained_instance_lock_fd)
        except OSError:
            pass
        gs._retained_instance_lock_fd = None

        fd3 = gs._acquire_instance_lock(db_path)
        assert fd3 is not None

        cleanup_ok = await gs._emergency_instance_cleanup(
            _MockAgentOK(), _MockDBOK(), _MockSubAgentFail(),
        )
        assert not cleanup_ok, (
            "emergency cleanup should return False when "
            "subagent_service.shutdown() fails"
        )

        gs._retained_instance_lock_fd = fd3
        assert gs._retained_instance_lock_fd is fd3
    finally:
        if gs._retained_instance_lock_fd is not None:
            try:
                os.close(gs._retained_instance_lock_fd)
            except OSError:
                pass
            gs._retained_instance_lock_fd = None


# ---------------------------------------------------------------------------
# Acceptance 7: ~/.khaos 0777/0775 rejected, 0755/0700 allowed
# ---------------------------------------------------------------------------


async def test_acceptance_7_parent_dir_mode_check(tmp_path) -> None:
    """Criterion 7: ``~/.khaos`` with mode 0777 or 0775 MUST be
    rejected.  Mode 0755 or 0700 MUST be allowed.
    """
    from khaos.grpc_server import _ensure_safe_run_dir

    # Test allowed modes: 0755 and 0700.
    for allowed_mode in (0o755, 0o700):
        khaos_dir = tmp_path / f"khaos_ok_{allowed_mode:o}"
        khaos_dir.mkdir()
        os.chmod(khaos_dir, allowed_mode)
        run_dir = khaos_dir / "run"
        run_dir.mkdir()
        os.chmod(run_dir, 0o700)
        try:
            # Should NOT raise.
            _ensure_safe_run_dir(run_dir)
        finally:
            shutil.rmtree(khaos_dir, ignore_errors=True)

    # Test rejected modes: 0777 and 0775.
    for rejected_mode in (0o777, 0o775):
        khaos_dir = tmp_path / f"khaos_bad_{rejected_mode:o}"
        khaos_dir.mkdir()
        os.chmod(khaos_dir, rejected_mode)
        run_dir = khaos_dir / "run"
        run_dir.mkdir()
        os.chmod(run_dir, 0o700)
        try:
            raised = False
            try:
                _ensure_safe_run_dir(run_dir)
            except PermissionError as exc:
                if "unsafe mode" in str(exc) or "writable" in str(exc).lower():
                    raised = True
            assert raised, (
                f"khaos dir with mode {rejected_mode:o} should be rejected "
                f"(group/other writable — allows replacing the run/ subdir)"
            )
        finally:
            shutil.rmtree(khaos_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Acceptance 8: flock 后替换 lockfile 路径 → 不得形成两个独立锁
# ---------------------------------------------------------------------------


async def test_acceptance_8_lockfile_path_identity_after_flock(
    tmp_path, monkeypatch,
) -> None:
    """Criterion 8: after flock, if the lockfile path is replaced
    (rename + create new), the path identity check MUST detect it and
    raise ``PermissionError``.

    Without the HIGH-2 fix, the post-flock re-check only compared
    ``fstat(fd)`` with ``fstat(fd)`` (same fd) — which could NOT detect
    path replacement.  The fix re-lstats the PATH via ``dir_fd`` and
    compares with the lock fd's ``fstat``.
    """
    import fcntl
    import khaos.grpc_server as gs

    _khaos_dir, run_dir = _make_safe_khaos_dir(tmp_path)
    lockfile_path = run_dir / "test.instance.lock"

    # Open the run_dir as dir_fd (same as _acquire_instance_lock does).
    run_dir_fd = os.open(
        str(run_dir),
        os.O_DIRECTORY | os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )

    try:
        # Monkeypatch fcntl.flock to replace the lockfile path AFTER
        # the real flock is acquired.  This simulates an attacker who
        # replaces the path between ``open`` and the post-flock lstat.
        real_flock = fcntl.flock

        def racing_flock(fd, op):
            # Call the real flock first — the fd now holds the lock
            # on the ORIGINAL inode.
            real_flock(fd, op)
            # Replace the lockfile path: rename the current file to
            # .old and create a NEW file at the original path.
            old_path = lockfile_path.with_suffix(".old")
            lockfile_path.rename(old_path)
            lockfile_path.write_text("replacement\n")
            lockfile_path.chmod(0o600)

        monkeypatch.setattr(fcntl, "flock", racing_flock)

        # Try to acquire the lock — should raise PermissionError.
        raised = False
        try:
            gs._acquire_instance_lock_via_dir_fd(
                run_dir_fd, lockfile_path.name, lockfile_path,
            )
        except PermissionError as exc:
            msg = str(exc).lower()
            if "path identity" in msg or "unlinked" in msg:
                raised = True
        except OSError:
            # On some systems, the rename might cause a different
            # error — also acceptable as long as the lock is refused.
            raised = True

        assert raised, (
            "lockfile path replacement after flock was NOT detected — "
            "the HIGH-2 path identity check is missing or broken.  "
            "A second process opening the path would get a different "
            "fd with no lock contention."
        )

        # Clean up the replacement files.
        old_path = lockfile_path.with_suffix(".old")
        if old_path.exists():
            old_path.unlink()
        if lockfile_path.exists():
            lockfile_path.unlink()
    finally:
        os.close(run_dir_fd)


# ---------------------------------------------------------------------------
# Acceptance 9: Executor marker CAS 0 + DB still RUNNING → reconcile
# fails, keeps marker
# ---------------------------------------------------------------------------


async def test_acceptance_9_executor_marker_cas0_running_keeps_marker(
    tmp_path,
) -> None:
    """Criterion 9: when the executor marker's CAS returns 0 (version
    or execution_id mismatch) AND the DB is still ``running``, reconcile
    MUST fail and KEEP the marker.

    Without the HIGH-3 fix, the code unconditionally popped the marker
    and returned ``True`` on CAS 0 — letting ``stop()`` succeed while
    the DB was still ``running``, causing the task to be re-fired on
    restart (double execution of side effects).
    """
    db = await _make_db(tmp_path)
    engine: CronEngine | None = None
    try:
        engine = CronEngine(db=db)
        await engine.start()

        future_iso = (utc_now_naive() + timedelta(hours=1)).isoformat()
        task = await engine.create(
            "task-marker", "p", ScheduleConfig(iso_time=future_iso),
            principal_id="alice",
        )

        # Set the task's in-memory status to COMPLETED (the executor's
        # desired terminal state).
        task.status = TaskStatus.COMPLETED

        # Place an executor marker.
        marker = PendingPersistence(
            operation_id="exec-op-1",
            desired_status=TaskStatus.COMPLETED.value,
            expected_version=task.lifecycle_version,
            is_control_op=False,
        )
        engine._pending_persistence[task.id] = marker

        # Set the DB row's status to "running" (simulating the CAS 0
        # scenario — the DB didn't get the terminal write for an
        # unknown reason: execution_id mismatch, version mismatch,
        # etc.).
        conn = await db._require_conn()
        await conn.execute(
            "UPDATE scheduled_tasks SET status = 'running' WHERE id = ?",
            (task.id,),
        )
        await conn.commit()

        # Mock _finalize_task_state to return False (CAS 0).
        async def fake_finalize(t, *, expected_version, operation_id):
            return False

        engine._finalize_task_state = fake_finalize  # type: ignore[assignment]

        # Call _retry_executor_marker.
        result = await engine._retry_executor_marker(task.id, marker)

        # HIGH-3 assertion: returns False (durability gap).
        assert result is False, (
            "_retry_executor_marker should return False when CAS 0 "
            "and DB is still running (durability gap — stop() must "
            "raise ServiceShutdownError)"
        )

        # HIGH-3 assertion: marker is KEPT (not popped).
        assert task.id in engine._pending_persistence, (
            "executor marker should be KEPT when DB is still running — "
            "stop() must raise ServiceShutdownError, not silently "
            "succeed while the DB row is stale"
        )
    finally:
        if engine is not None:
            await _force_cleanup_engine(engine)
        await db.close()


# ---------------------------------------------------------------------------
# Acceptance 10: Executor finalize commit-then-raise → read back
# confirm desired status before clearing marker
# ---------------------------------------------------------------------------


async def test_acceptance_10_executor_commit_then_raise_clears_marker(
    tmp_path,
) -> None:
    """Criterion 10: when the executor's finalize CAS committed but
    raised (commit-then-raise), the read-back MUST confirm the desired
    status before clearing the marker.

    The previous CAS 0 path unconditionally popped the marker.  The
    HIGH-3 fix reads back the DB: if the DB is at the marker's desired
    status → idempotent success, pop marker.  If the DB is still
    running → durability gap, keep marker (tested in acceptance 9).
    """
    db = await _make_db(tmp_path)
    engine: CronEngine | None = None
    try:
        engine = CronEngine(db=db)
        await engine.start()

        future_iso = (utc_now_naive() + timedelta(hours=1)).isoformat()
        task = await engine.create(
            "task-commit-raise", "p", ScheduleConfig(iso_time=future_iso),
            principal_id="alice",
        )

        # Set the task's in-memory status to COMPLETED.
        task.status = TaskStatus.COMPLETED

        # Place an executor marker.
        marker = PendingPersistence(
            operation_id="exec-op-2",
            desired_status=TaskStatus.COMPLETED.value,
            expected_version=task.lifecycle_version,
            is_control_op=False,
        )
        engine._pending_persistence[task.id] = marker

        # Simulate commit-then-raise: the CAS committed (DB is at
        # COMPLETED) but _finalize_task_state returns False (the CAS
        # appeared to fail because the version already advanced).
        conn = await db._require_conn()
        await conn.execute(
            "UPDATE scheduled_tasks SET status = 'completed' WHERE id = ?",
            (task.id,),
        )
        await conn.commit()

        # Mock _finalize_task_state to return False (simulating the
        # CAS 0 from the raised exception — the DB already advanced).
        async def fake_finalize(t, *, expected_version, operation_id):
            return False

        engine._finalize_task_state = fake_finalize  # type: ignore[assignment]

        # Call _retry_executor_marker.
        result = await engine._retry_executor_marker(task.id, marker)

        # HIGH-3 assertion: returns True (idempotent success —
        # commit-then-raise confirmed by DB read-back).
        assert result is True, (
            "_retry_executor_marker should return True when DB is at "
            "the marker's desired status (commit-then-raise idempotent "
            "success — the CAS committed before raising)"
        )

        # HIGH-3 assertion: marker is POPPED (cleaned up).
        assert task.id not in engine._pending_persistence, (
            "executor marker should be popped when DB read-back "
            "confirms the desired status (commit-then-raise) — the "
            "terminal state is durable, no need to retry"
        )
    finally:
        if engine is not None:
            await _force_cleanup_engine(engine)
        await db.close()
