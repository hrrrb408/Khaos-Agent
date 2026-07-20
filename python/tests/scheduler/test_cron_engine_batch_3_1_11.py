"""M4 Batch 3.1.11 — Fail-Closed Lease Finalization and Idempotent
Control Generation Closure.

Acceptance tests for the 10 criteria specified in the batch review:

  1.  Claim 抛异常时 executor 调用次数必须为 0。
  2.  Claim commit-then-raise 时通过 execution ID 读回确认，只执行一次。
  3.  Terminal UPDATE 失败时 lease 必须继续保留。
  4.  Terminal UPDATE 失败、进程重启后任务必须被恢复为 FAILED。
  5.  Executor 内部 TypeError 不得触发二次执行。
  6.  空 principal 不得通过任何兼容路径进入 Scheduled Prompt。
  7.  cancellation-resistant executor 不得覆盖新 control marker。
  8.  Pause/Remove commit-then-raise 后重试不得多递增版本。
  9.  last_run 必须等于实际 started_at，而不是 lease deadline。
  10. Lease recovery 失败时 Cron Engine 不得进入 accepting/running 状态。
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from khaos.db import Database
from khaos.exceptions import ServiceShutdownError
from khaos.scheduler import CronEngine, ScheduleConfig, TaskStatus
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


# ---------------------------------------------------------------------------
# Acceptance 1: Claim 抛异常时 executor 调用次数必须为 0
# ---------------------------------------------------------------------------


async def test_acceptance_1_claim_exception_no_executor_call(tmp_path) -> None:
    """Criterion 1: if ``claim_scheduled_task`` raises, the executor
    MUST NOT be called.  Previously the code swallowed the exception
    with ``rowcount = 1  # proceed anyway`` and executed the task
    without a durable lease — violating the "durable execution
    ownership" invariant.

    Sequence:
      1. Create a task with a recording executor.
      2. Patch ``claim_scheduled_task`` to raise ``RuntimeError``.
      3. Let tick fire the task.
      4. The executor call count MUST be 0.
    """
    db = await _make_db(tmp_path)
    try:
        executor_calls: list[str] = []

        async def recording_executor(task_id: str, prompt: str, principal_id: str) -> str:
            executor_calls.append(task_id)
            return "should-not-reach"

        engine = CronEngine(
            db=db, executor=recording_executor, tick_interval=0.01,
        )
        await engine.start()

        # Patch claim to raise.
        async def failing_claim(*args, **kwargs):
            raise RuntimeError("DB connection lost during claim")

        db.claim_scheduled_task = failing_claim

        # Create a task that's immediately due.
        iso = datetime.utcnow().isoformat()
        task = await engine.create(
            "claim-fail", "p", ScheduleConfig(iso_time=iso),
            principal_id="alice",
        )

        # Let tick fire and the claim fail.
        await asyncio.sleep(0.3)

        # The executor MUST NOT have been called.
        assert len(executor_calls) == 0, (
            f"executor was called {len(executor_calls)} time(s) despite "
            "claim raising — fail-closed invariant violated"
        )

        # The task should still be PENDING (not RUNNING).
        row = await db.get_scheduled_task(task.id)
        assert row["status"] == "pending", (
            f"expected pending, got {row['status']} — claim failure "
            "should not transition the task to running"
        )

        await engine.stop(timeout=2.0)
    finally:
        await db.close()


# ---------------------------------------------------------------------------
# Acceptance 2: Claim commit-then-raise 时通过 execution ID 读回确认
# ---------------------------------------------------------------------------


async def test_acceptance_2_claim_commit_then_raise_read_back(tmp_path) -> None:
    """Criterion 2: if ``claim_scheduled_task`` commits the UPDATE but
    raises (ambiguous commit — e.g. network error between commit and
    response), the engine reads back the row to verify the claim
    actually committed (same ``execution_id`` + ``running`` status +
    expected ``lifecycle_version``).  Only if verification succeeds
    does execution proceed — and it executes EXACTLY ONCE.

    Sequence:
      1. Create a task with a recording executor.
      2. Patch ``claim_scheduled_task`` to commit then raise.
      3. Let tick fire the task.
      4. The executor MUST be called exactly once.
      5. The DB row must show the terminal state (completed/pending).
    """
    db = await _make_db(tmp_path)
    try:
        executor_calls: list[str] = []

        async def recording_executor(task_id: str, prompt: str, principal_id: str) -> str:
            executor_calls.append(task_id)
            return "executed-once"

        engine = CronEngine(
            db=db, executor=recording_executor, tick_interval=0.01,
        )
        await engine.start()

        # Patch claim to commit-then-raise (first call only).
        original_claim = db.claim_scheduled_task
        call_count = {"n": 0}

        async def commit_then_raise(*args, **kwargs):
            call_count["n"] += 1
            if call_count["n"] == 1:
                # Commit the UPDATE, then raise.
                result = await original_claim(*args, **kwargs)
                raise RuntimeError("ambiguous commit — network error")
            return await original_claim(*args, **kwargs)

        db.claim_scheduled_task = commit_then_raise

        # Create a task that's immediately due.
        iso = datetime.utcnow().isoformat()
        task = await engine.create(
            "commit-raise", "p", ScheduleConfig(iso_time=iso),
            principal_id="alice",
        )

        # Let tick fire and the executor complete.
        await asyncio.sleep(0.3)

        # The executor MUST have been called exactly once.
        assert len(executor_calls) == 1, (
            f"executor was called {len(executor_calls)} time(s) — "
            "expected exactly 1 (commit-then-raise recovered via read-back)"
        )

        # The DB row must show the terminal state (completed for one-shot).
        row = await db.get_scheduled_task(task.id)
        assert row["status"] == "completed", (
            f"expected completed, got {row['status']}"
        )
        assert row["execution_id"] is None, (
            "execution_id should be cleared after terminal write"
        )

        await engine.stop(timeout=2.0)
    finally:
        await db.close()


# ---------------------------------------------------------------------------
# Acceptance 3: Terminal UPDATE 失败时 lease 必须继续保留
# ---------------------------------------------------------------------------


async def test_acceptance_3_terminal_write_failure_retains_lease(tmp_path) -> None:
    """Criterion 3: if the terminal state UPDATE (``finalize_scheduled_task``)
    fails, the execution lease MUST be retained — NOT cleared.
    Previously the ``except`` branch called ``_clear_lease``
    unconditionally, leaving the DB row at
    ``status='running' + execution_id=NULL + lease_until=NULL`` —
    permanently stuck (``recover_expired_leases`` only matches rows
    with ``lease_until IS NOT NULL``).

    Sequence:
      1. Create a task with a stalling executor.
      2. Let tick fire and the executor complete.
      3. Patch ``finalize_scheduled_task`` to raise.
      4. The executor completes but the terminal write fails.
      5. The DB row MUST still have ``execution_id`` and ``lease_until``
         set (NOT NULL) — the lease is retained for restart recovery.
    """
    db = await _make_db(tmp_path)
    try:
        started = asyncio.Event()

        async def quick_executor(task_id: str, prompt: str, principal_id: str) -> str:
            started.set()
            return "done"

        engine = CronEngine(
            db=db, executor=quick_executor, tick_interval=0.01,
        )
        await engine.start()

        # Patch finalize to raise (simulating DB failure during
        # terminal write).
        async def failing_finalize(*args, **kwargs):
            raise RuntimeError("DB wedged during finalize")

        db.finalize_scheduled_task = failing_finalize

        # Create a task that's immediately due.
        iso = datetime.utcnow().isoformat()
        task = await engine.create(
            "lease-retain", "p", ScheduleConfig(iso_time=iso),
            principal_id="alice",
        )

        # Let the executor complete (but finalize fails).
        await asyncio.sleep(0.3)

        # The DB row MUST still have execution_id and lease_until set.
        row = await db.get_scheduled_task(task.id)
        assert row["status"] == "running", (
            f"expected running (terminal write failed), got {row['status']}"
        )
        assert row["execution_id"] is not None, (
            "execution_id is NULL despite terminal write failure — "
            "lease was cleared; the task is permanently stuck at "
            "RUNNING + NULL lease (unrecoverable)"
        )
        assert row["lease_until"] is not None, (
            "lease_until is NULL despite terminal write failure — "
            "lease was cleared; recover_expired_leases cannot match "
            "this row"
        )

        # ``stop()`` retries the failed finalize via reconcile — since
        # ``finalize_scheduled_task`` is still patched to fail,
        # ``stop()`` raises ``ServiceShutdownError``.  This is the
        # expected fail-closed behavior: the caller refuses to tear
        # down the DB while a row is still stale.  The lease is
        # retained in the DB (the whole point of CRITICAL-2).
        with pytest.raises(ServiceShutdownError):
            await engine.stop(timeout=2.0)
    finally:
        await db.close()


# ---------------------------------------------------------------------------
# Acceptance 4: Terminal UPDATE 失败、进程重启后任务必须被恢复为 FAILED
# ---------------------------------------------------------------------------


async def test_acceptance_4_terminal_write_failure_restart_recovers_as_failed(
    tmp_path,
) -> None:
    """Criterion 4: if the terminal write failed and the lease was
    retained, a process restart MUST recover the task as FAILED via
    ``recover_expired_leases``.  This is the "at-least-once disclosure"
    guarantee — the user is informed that the execution may have
    produced side effects, even though the terminal state was never
    durably recorded.

    Sequence:
      1. Create a task with a quick executor.
      2. Patch ``finalize_scheduled_task`` to fail.
      3. Let the executor complete (terminal write fails, lease retained).
      4. Stop the engine.
      5. Manually expire the lease (set ``lease_until`` to the past).
      6. Create a new engine and start it — ``recover_expired_leases``
         marks the task as FAILED.
    """
    db_path = tmp_path / "khaos.db"
    db = await _make_db(db_path)
    try:
        async def quick_executor(task_id: str, prompt: str, principal_id: str) -> str:
            return "done"

        engine = CronEngine(
            db=db, executor=quick_executor, tick_interval=0.01,
        )
        await engine.start()

        # Patch finalize to raise.
        async def failing_finalize(*args, **kwargs):
            raise RuntimeError("DB wedged")

        db.finalize_scheduled_task = failing_finalize

        # Create a task that's immediately due.
        iso = datetime.utcnow().isoformat()
        task = await engine.create(
            "restart-recover", "p", ScheduleConfig(iso_time=iso),
            principal_id="alice",
        )

        # Let the executor complete (terminal write fails).
        await asyncio.sleep(0.3)
        # ``stop()`` retries the failed finalize via reconcile — since
        # ``finalize_scheduled_task`` is still patched to fail,
        # ``stop()`` raises ``ServiceShutdownError``.  This simulates
        # a crash: the process tried to drain but couldn't persist the
        # terminal state, so the lease is RETAINED in the DB.  The
        # restart recovery test below depends on this lease being
        # present.
        with pytest.raises(ServiceShutdownError):
            await engine.stop(timeout=2.0)
    finally:
        await db.close()

    # Manually expire the lease (simulate time passing).
    db2 = await _make_db(db_path)
    try:
        conn = await db2._require_conn()
        await conn.execute(
            "UPDATE scheduled_tasks SET lease_until = ? WHERE id = ?",
            ((datetime.utcnow() - timedelta(seconds=1)).isoformat(), task.id),
        )
        await conn.commit()
    finally:
        await db2.close()

    # Restart — recover_expired_leases should mark the task as FAILED.
    db3 = await _make_db(db_path)
    try:
        engine2 = CronEngine(
            db=db3, executor=quick_executor, tick_interval=0.01,
        )
        await engine2.start()

        row = await db3.get_scheduled_task(task.id)
        assert row["status"] == "failed", (
            f"expected failed (crash recovery), got {row['status']} — "
            "the retained lease was not recovered"
        )
        assert (
            "lease expired" in (row["error"] or "")
            or "process restart detected" in (row["error"] or "")
            or "single-instance" in (row["error"] or "")
        ), (
            f"error message should mention lease expiry or process restart, got: {row['error']}"
        )
        assert row["execution_id"] is None, (
            "execution_id should be cleared after recovery"
        )
        assert row["lease_until"] is None, (
            "lease_until should be cleared after recovery"
        )

        await engine2.stop(timeout=2.0)
    finally:
        await db3.close()


# ---------------------------------------------------------------------------
# Acceptance 5: Executor 内部 TypeError 不得触发二次执行
# ---------------------------------------------------------------------------


async def test_acceptance_5_executor_typeerror_no_double_execution(tmp_path) -> None:
    """Criterion 5: if the executor raises ``TypeError`` from its body
    (e.g. ``1 + "x"``), the engine MUST NOT catch it and re-execute
    without ``principal_id``.  Previously the ``except TypeError``
    fallback caught internal TypeErrors (not just arity mismatches)
    and re-executed — causing double side effects and a silent
    identity downgrade to the server UID.

    Sequence:
      1. Create a task with an executor that raises ``TypeError``
         AFTER producing a side effect.
      2. Let tick fire the task.
      3. The executor MUST be called exactly once.
      4. The task MUST be marked FAILED (not retried without principal).
    """
    db = await _make_db(tmp_path)
    try:
        side_effects: list[str] = []

        async def typeerror_executor(task_id: str, prompt: str, principal_id: str) -> str:
            side_effects.append(f"called:{principal_id}")
            # Produce a side effect, THEN raise TypeError from the body.
            result = 1 + "x"  # TypeError — not an arity issue
            return result

        engine = CronEngine(
            db=db, executor=typeerror_executor, tick_interval=0.01,
        )
        await engine.start()

        iso = datetime.utcnow().isoformat()
        task = await engine.create(
            "typeerror", "p", ScheduleConfig(iso_time=iso),
            principal_id="alice",
        )

        # Let tick fire and the executor fail.
        await asyncio.sleep(0.3)

        # The executor MUST have been called exactly once.
        assert len(side_effects) == 1, (
            f"executor was called {len(side_effects)} time(s) — "
            "internal TypeError triggered a second execution (double "
            "side effects + identity downgrade)"
        )
        # The single call MUST have used the correct principal_id.
        assert side_effects[0] == "called:alice", (
            f"executor was called with wrong principal: {side_effects[0]} — "
            "the retry used the server UID instead of the task's principal"
        )

        # The task MUST be marked FAILED.
        row = await db.get_scheduled_task(task.id)
        assert row["status"] == "failed", (
            f"expected failed, got {row['status']} — internal TypeError "
            "should propagate as FAILED, not be swallowed"
        )

        await engine.stop(timeout=2.0)
    finally:
        await db.close()


# ---------------------------------------------------------------------------
# Acceptance 6: 空 principal 不得通过任何兼容路径进入 Scheduled Prompt
# ---------------------------------------------------------------------------


async def test_acceptance_6_empty_principal_rejected_in_execute(tmp_path) -> None:
    """Criterion 6: an empty ``principal_id`` MUST NOT reach the
    executor.  ``_execute_task`` rejects empty principal BEFORE calling
    the executor, marking the task as FAILED.  This is the last line
    of defense — ``cron_create`` already rejects empty principal, and
    the broker injects ``principal_id`` for every cron tool call.  But
    a corrupted DB row (legacy migration gone wrong) could still
    produce an empty principal here.

    Sequence:
      1. Create a task with a valid principal.
      2. Manually corrupt the DB row: set ``principal_id = ''``.
      3. Let tick fire the task.
      4. The executor MUST NOT be called.
      5. The task MUST be marked FAILED.
    """
    db = await _make_db(tmp_path)
    try:
        executor_calls: list[str] = []

        async def recording_executor(task_id: str, prompt: str, principal_id: str) -> str:
            executor_calls.append(task_id)
            return "should-not-reach"

        engine = CronEngine(
            db=db, executor=recording_executor, tick_interval=0.01,
        )
        await engine.start()

        iso = datetime.utcnow().isoformat()
        task = await engine.create(
            "empty-principal", "p", ScheduleConfig(iso_time=iso),
            principal_id="alice",
        )

        # Corrupt the DB row: set principal_id to empty.
        # ``Database`` doesn't expose a raw ``execute`` — use the
        # underlying connection via ``_require_conn()``.
        conn = await db._require_conn()
        await conn.execute(
            "UPDATE scheduled_tasks SET principal_id = '' WHERE id = ?",
            (task.id,),
        )
        await conn.commit()
        # Also corrupt the in-memory task.
        engine._tasks[task.id].principal_id = ""

        # Let tick fire.
        await asyncio.sleep(0.3)

        # The executor MUST NOT have been called.
        assert len(executor_calls) == 0, (
            "executor was called despite empty principal_id — "
            "the task would have executed as the server UID"
        )

        # The task MUST be marked FAILED.
        row = await db.get_scheduled_task(task.id)
        assert row["status"] == "failed", (
            f"expected failed, got {row['status']} — empty principal "
            "should fail-closed, not execute"
        )
        assert "principal_id" in (row["error"] or ""), (
            f"error should mention principal_id, got: {row['error']}"
        )

        await engine.stop(timeout=2.0)
    finally:
        await db.close()


# ---------------------------------------------------------------------------
# Acceptance 7: cancellation-resistant executor 不得覆盖新 control marker
# ---------------------------------------------------------------------------


async def test_acceptance_7_stale_executor_does_not_overwrite_control_marker(
    tmp_path,
) -> None:
    """Criterion 7: a cancellation-resistant executor (one that
    swallows ``CancelledError`` and keeps running) MUST NOT overwrite
    a NEWER control op's persistence marker.  The marker belongs to
    the control op; the stale executor's terminal-state path must
    not clear or replace it.

    Sequence:
      1. Create a task with a stalling executor that swallows cancel.
      2. Let tick fire and the executor stall.
      3. Patch ``control_finalize_scheduled_task`` to fail so pause's
         marker is left in ``_pending_persistence``.
      4. Call ``pause()`` — it bumps the epoch, sets PAUSED, persist
         fails, marker is placed (is_control_op=True).  Because the
         executor is cancellation-resistant, ``pause`` returns
         ``cancellation_pending`` (the executor didn't terminate within
         the cancel budget) — but the marker IS placed because
         ``_persist_task_state`` runs before the cancel-ok check.
      5. Restore ``control_finalize_scheduled_task``.
      6. Release the executor — it completes and tries to write its
         terminal state.  The epoch fence (pause bumped the epoch)
         redirects to ``_clear_lease``, which does NOT touch
         ``_pending_persistence``.  Even if it DID reach
         ``_finalize_task_state``, the HIGH-1 check would skip
         placement because a control-op marker exists.
      7. The marker in ``_pending_persistence`` MUST still be the
         pause op's marker (same operation_id).
    """
    # Speed up the test: shrink the cancel budget so ``pause()``
    # doesn't wait 10s for the cancellation-resistant executor.
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
            "stale-exec", "p", ScheduleConfig(iso_time=iso),
            principal_id="alice",
        )
        task_id = task.id
        await asyncio.wait_for(started.wait(), timeout=2.0)

        # Patch control_finalize_scheduled_task to fail so pause's marker
        # is left in _pending_persistence.
        original_control = db.control_finalize_scheduled_task

        async def failing_control(*args, **kwargs):
            raise RuntimeError("DB wedged for control op")

        db.control_finalize_scheduled_task = failing_control

        # Call pause — bumps epoch, sets PAUSED, persist fails.
        # The executor is cancellation-resistant, so pause returns
        # ``cancellation_pending``.  But the marker IS placed because
        # ``_persist_task_state`` runs before the cancel-ok check.
        pause_result = await engine.pause(task_id, principal_id="alice")
        assert pause_result in (
            "persistence_pending", "cancellation_pending",
        ), f"expected persistence_pending or cancellation_pending, got {pause_result}"
        assert task_id in engine._pending_persistence, (
            "pause did not place a persistence marker — the marker "
            "check below cannot verify HIGH-1"
        )
        pause_marker = engine._pending_persistence[task_id]
        assert pause_marker.is_control_op is True
        pause_operation_id = pause_marker.operation_id

        # Restore control_finalize_scheduled_task.
        db.control_finalize_scheduled_task = original_control

        # Release the executor — it completes and tries to write its
        # terminal state.  The epoch fence (pause bumped the epoch)
        # redirects to ``_clear_lease``, which does NOT touch
        # ``_pending_persistence``.  Even if it DID reach
        # ``_finalize_task_state``, the HIGH-1 check would skip
        # placement because a control-op marker exists.
        release_exec.set()
        await asyncio.sleep(0.3)

        # The pause op's marker MUST still be in _pending_persistence.
        assert task_id in engine._pending_persistence, (
            "stale executor cleared the NEWER pause op's persistence "
            "marker — the next pause() would return ok even though "
            "the DB still holds the old state"
        )
        current_marker = engine._pending_persistence[task_id]
        assert current_marker.operation_id == pause_operation_id, (
            "the marker in _pending_persistence is not the pause op's "
            "marker — the stale executor overwrote it with its own"
        )

        await engine.stop(timeout=5.0)
    finally:
        _engine_mod._CANCEL_IN_FLIGHT_TIMEOUT = original_cancel_timeout
        release_exec.set()
        await db.close()


# ---------------------------------------------------------------------------
# Acceptance 8: Pause/Remove commit-then-raise 后重试不得多递增版本
# ---------------------------------------------------------------------------


async def test_acceptance_8_control_op_commit_then_raise_no_version_drift(
    tmp_path,
) -> None:
    """Criterion 8: if a control op (pause/remove) commits the CAS
    UPDATE but the caller receives an exception (ambiguous commit),
    the retry MUST NOT bump the version again.  Previously the
    unconditional ``update_scheduled_task(bump_version=True)`` bumped
    the version on every retry — causing version drift between the
    in-memory epoch (still the first bump) and the DB (bumped twice).

    Sequence:
      1. Create a task and capture its lifecycle_version.
      2. Patch ``control_finalize_scheduled_task`` to commit-then-raise
         on the first call.
      3. Call ``pause()`` — it bumps the epoch (in-memory version = 1),
         commits the CAS (DB version = 1), then raises.
      4. The retry (via reconcile or second pause) calls
         ``control_finalize_scheduled_task`` again with the SAME
         expected/target version.  The CAS matches 0 rows (DB is
         already at target) — read-back confirms and treats as success.
      5. The DB version MUST be 1 (NOT 2 or higher).
    """
    db = await _make_db(tmp_path)
    try:
        engine = CronEngine(db=db)
        task = await engine.create(
            "version-drift", "p", ScheduleConfig(interval_seconds=60),
            principal_id="alice",
        )
        version_before = task.lifecycle_version
        db_version_before = int(
            (await db.get_scheduled_task(task.id))["lifecycle_version"]
        )

        # Patch control_finalize_scheduled_task to commit-then-raise
        # on the first call.
        original_control = db.control_finalize_scheduled_task
        call_count = {"n": 0}

        async def commit_then_raise(*args, **kwargs):
            call_count["n"] += 1
            if call_count["n"] == 1:
                # First call: commit, then raise.
                result = await original_control(*args, **kwargs)
                raise RuntimeError("ambiguous commit — network error")
            # Subsequent calls: return the real result.
            return await original_control(*args, **kwargs)

        db.control_finalize_scheduled_task = commit_then_raise

        # Call pause — it bumps the epoch (in-memory version = 1),
        # then calls _persist_task_state which calls
        # control_finalize_scheduled_task.  The CAS commits (DB version
        # = 1) but raises.  The read-back confirms (DB at target=1,
        # status=paused) and treats it as success.
        result = await engine.pause(task.id, principal_id="alice")
        assert result == "ok", (
            f"expected ok (commit-then-raise recovered via read-back), "
            f"got {result}"
        )

        # The DB version MUST be exactly 1 (not 2 or higher).
        row_after = await db.get_scheduled_task(task.id)
        db_version_after = int(row_after["lifecycle_version"])
        assert db_version_after == db_version_before + 1, (
            f"DB version drifted: before={db_version_before}, "
            f"after={db_version_after} — expected exactly +1; the "
            "commit-then-raise retry bumped the version again"
        )

        # The in-memory version MUST match the DB version.
        assert task.lifecycle_version == db_version_after, (
            f"in-memory version ({task.lifecycle_version}) != DB version "
            f"({db_version_after}) — version drift between memory and DB"
        )

        db.control_finalize_scheduled_task = original_control
    finally:
        await db.close()


# ---------------------------------------------------------------------------
# Acceptance 9: last_run 必须等于实际 started_at
# ---------------------------------------------------------------------------


async def test_acceptance_9_last_run_equals_started_at(tmp_path) -> None:
    """Criterion 9: ``last_run`` in the DB MUST equal the actual
    execution start time (``started_at``), NOT the lease deadline
    (``lease_until``).  Previously ``claim_scheduled_task`` set
    ``last_run = lease_until``, making the DB appear ~10 minutes
    behind the real start time during execution — corrupting audit
    timelines and crash-recovery forensics.

    Sequence:
      1. Create a task.
      2. Manually claim it via ``claim_scheduled_task`` with distinct
         ``started_at`` and ``lease_until``.
      3. Read back the DB row.
      4. ``last_run`` MUST equal ``started_at`` (NOT ``lease_until``).
    """
    db = await _make_db(tmp_path)
    try:
        engine = CronEngine(db=db)
        task = await engine.create(
            "last-run", "p", ScheduleConfig(interval_seconds=60),
            principal_id="alice",
        )

        # Claim with distinct started_at and lease_until.
        started_at = "2026-07-20T10:00:00"
        lease_until = "2026-07-20T10:10:00"  # 10 minutes later
        rowcount = await db.claim_scheduled_task(
            task.id,
            execution_id="test-exec-9",
            started_at=started_at,
            lease_until=lease_until,
            expected_version=task.lifecycle_version,
        )
        assert rowcount == 1, "claim should succeed — task is PENDING"

        row = await db.get_scheduled_task(task.id)
        assert row["last_run"] == started_at, (
            f"last_run should be {started_at} (the actual start time), "
            f"got {row['last_run']} — the old code set last_run = "
            f"lease_until ({lease_until}), corrupting audit timelines"
        )
        assert row["last_run"] != lease_until, (
            f"last_run ({row['last_run']}) equals lease_until "
            f"({lease_until}) — the bug is still present"
        )
        assert row["lease_until"] == lease_until, (
            f"lease_until should be {lease_until}, got {row['lease_until']}"
        )
    finally:
        await db.close()


# ---------------------------------------------------------------------------
# Acceptance 10: Lease recovery 失败时 Cron Engine 不得进入 accepting/running
# ---------------------------------------------------------------------------


async def test_acceptance_10_lease_recovery_failure_degraded_mode(tmp_path) -> None:
    """Criterion 10: if ``recover_expired_leases`` fails during
    ``start()``, the engine MUST enter ``_degraded`` mode — the tick
    loop runs (so pause/resume/remove still work) but
    ``_execute_task`` refuses to fire new executions.  Without this,
    a lease-recovery failure left crashed tasks un-recovered AND
    continued accepting new executions, compounding the inconsistency.

    Sequence:
      1. Create a DB with a task.
      2. Patch ``recover_expired_leases`` to raise.
      3. Create a CronEngine and start it.
      4. The engine MUST be in ``_degraded`` mode.
      5. Create a task that's immediately due.
      6. Let tick fire.
      7. The executor MUST NOT be called (degraded mode refuses).
    """
    db = await _make_db(tmp_path)
    try:
        executor_calls: list[str] = []

        async def recording_executor(task_id: str, prompt: str, principal_id: str) -> str:
            executor_calls.append(task_id)
            return "should-not-reach"

        # Patch recover_expired_leases to raise.
        async def failing_recovery(*args, **kwargs):
            raise RuntimeError("DB cannot recover leases — schema corrupt")

        db.recover_expired_leases = failing_recovery

        engine = CronEngine(
            db=db, executor=recording_executor, tick_interval=0.01,
        )
        await engine.start()

        # The engine MUST be in degraded mode.
        assert engine._degraded is True, (
            "engine is NOT in degraded mode despite lease recovery "
            "failure — new executions would be accepted with unknown "
            "crashed-task state"
        )

        # Create a task that's immediately due.
        iso = datetime.utcnow().isoformat()
        await engine.create(
            "degraded", "p", ScheduleConfig(iso_time=iso),
            principal_id="alice",
        )

        # Let tick fire a few times.
        await asyncio.sleep(0.3)

        # The executor MUST NOT have been called (degraded mode).
        assert len(executor_calls) == 0, (
            f"executor was called {len(executor_calls)} time(s) despite "
            "degraded mode — the engine accepted a new execution with "
            "unknown crashed-task state"
        )

        await engine.stop(timeout=2.0)
    finally:
        await db.close()
