"""M4 Batch 3.1.10 — Principal-Bound Durable Cron Ownership Closure.

Acceptance tests for the 10 criteria specified in the batch review:

  1.  Every Cron has a non-null principal owner.
  2.  Two principals cannot List / Pause / Resume / Remove each other's tasks.
  3.  Scheduled Prompt uses the creator principal, not the server UID.
  4.  Create and ``next_run`` are written in the same durable INSERT.
  5.  Create-then-restart-before-first-fire still triggers.
  6.  Atomic claim durable lease before execution.
  7.  Crash recovery has testable at-least-once semantics.
  8.  Old executor cannot clear a newer control op's persistence generation.
  9.  commit-then-raise retry must not cause version drift.
  10. ``cron_resume`` accurately propagates ``persistence_pending``.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta

import pytest

from khaos.db import Database
from khaos.scheduler import CronEngine, ScheduleConfig, ScheduledTask, TaskStatus
from khaos.scheduler.engine import PendingPersistence
from khaos.tools.cron_tools import (
    cron_create,
    cron_list,
    cron_pause,
    cron_remove,
    cron_resume,
    set_cron_engine,
)


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


async def _recording_executor_3arg(task_id: str, prompt: str, principal_id: str) -> str:
    """3-arg executor that records the principal_id it was called with."""
    return f"executed:{prompt}:by:{principal_id}"


async def _recording_executor_2arg(task_id: str, prompt: str) -> str:
    """2-arg executor for backwards-compat fallback verification."""
    return f"executed2:{prompt}"


async def _make_db(path) -> Database:
    """Create a Database at ``path``.

    ``path`` may be either a directory (a ``tmp_path`` fixture) or a
    full file path.  If it's a directory, ``khaos.db`` is appended.
    """
    from pathlib import Path
    p = Path(path)
    if p.is_dir() or (not p.exists() and not p.name.endswith(".db")):
        p = p / "khaos.db"
    db = Database(p)
    await db.connect()
    await db.run_migrations()
    return db


# ---------------------------------------------------------------------------
# Acceptance 1: Every Cron has a non-null principal owner
# ---------------------------------------------------------------------------


async def test_acceptance_1_every_task_has_non_empty_principal(tmp_path) -> None:
    """Criterion 1: every Cron has a non-null (non-empty) principal owner.

    ``engine.create`` raises ``ValueError`` for empty principal; the DB
    INSERT also rejects empty principal (the column is NOT NULL with a
    non-empty default of ``'legacy'`` for migrations, but new inserts
    must pass a real principal).
    """
    # Empty principal is rejected by the engine.
    engine = CronEngine(db=None)
    with pytest.raises(ValueError, match="principal_id is required"):
        await engine.create("t", "p", ScheduleConfig(interval_seconds=60))

    # DB layer also rejects empty principal.
    db = await _make_db(tmp_path)
    try:
        with pytest.raises(ValueError, match="principal_id is required"):
            await db.insert_scheduled_task(
                "t", "p", "pending", ScheduleConfig(interval_seconds=60),
                principal_id="",
            )
    finally:
        await db.close()

    # A real principal is persisted on the task and in the DB row.
    db = await _make_db(tmp_path)
    try:
        engine = CronEngine(db=db)
        task = await engine.create(
            "owner-check", "p", ScheduleConfig(interval_seconds=60),
            principal_id="user-alice",
        )
        assert task.principal_id == "user-alice"
        rows = await db.list_scheduled_tasks()
        row = next(r for r in rows if r["id"] == task.id)
        assert row["principal_id"] == "user-alice"
    finally:
        await db.close()


# ---------------------------------------------------------------------------
# Acceptance 2: Two principals cannot List/Pause/Resume/Remove each other
# ---------------------------------------------------------------------------


async def test_acceptance_2_principal_isolation(tmp_path) -> None:
    """Criterion 2: two principals cannot observe or mutate each other's tasks.

    ``cron_list`` returns only the caller's tasks; ``cron_pause`` /
    ``cron_resume`` / ``cron_remove`` return ``not_found`` for tasks
    owned by a different principal (fail-closed — does not reveal
    existence).
    """
    db = await _make_db(tmp_path)
    try:
        engine = CronEngine(db=db)
        alice_task = await engine.create(
            "alice-task", "p", ScheduleConfig(interval_seconds=60),
            principal_id="alice",
        )
        bob_task = await engine.create(
            "bob-task", "p", ScheduleConfig(interval_seconds=60),
            principal_id="bob",
        )

        # Alice's list contains only alice_task.
        alice_list = await engine.list_tasks(principal_id="alice")
        assert {t.id for t in alice_list} == {alice_task.id}

        # Bob's list contains only bob_task.
        bob_list = await engine.list_tasks(principal_id="bob")
        assert {t.id for t in bob_list} == {bob_task.id}

        # Alice cannot pause / resume / remove Bob's task — returns
        # ``not_found`` (does not reveal existence).
        assert await engine.pause(bob_task.id, principal_id="alice") == "not_found"
        assert await engine.resume(bob_task.id, principal_id="alice") == "not_found"
        assert await engine.remove(bob_task.id, principal_id="alice") == "not_found"

        # Bob's task is unchanged.
        assert (await engine.get(bob_task.id)).status == TaskStatus.PENDING

        # Bob CAN pause his own task.
        assert await engine.pause(bob_task.id, principal_id="bob") == "ok"
        assert (await engine.get(bob_task.id)).status == TaskStatus.PAUSED

        # Alice cannot resume Bob's paused task.
        assert await engine.resume(bob_task.id, principal_id="alice") == "not_found"
        assert (await engine.get(bob_task.id)).status == TaskStatus.PAUSED
    finally:
        await db.close()


async def test_acceptance_2_cron_tools_principal_isolation(tmp_path) -> None:
    """Criterion 2 (tool layer): the cron_* tool handlers enforce the
    same isolation via ``_require_principal`` + engine filtering.
    """
    db = await _make_db(tmp_path)
    try:
        engine = CronEngine(db=db)
        set_cron_engine(engine)
        try:
            # Alice creates a task via the tool layer.
            alice_result = await cron_create(
                "alice-tool-task", "p", "30m", principal_id="alice",
            )
            assert alice_result["status"] == "created"
            alice_task_id = alice_result["task_id"]

            # Bob creates a task via the tool layer.
            bob_result = await cron_create(
                "bob-tool-task", "p", "30m", principal_id="bob",
            )
            assert bob_result["status"] == "created"
            bob_task_id = bob_result["task_id"]

            # Alice's cron_list shows only her tasks.
            alice_list = await cron_list(principal_id="alice")
            alice_ids = {t["id"] for t in alice_list["tasks"]}
            assert alice_ids == {alice_task_id}

            # Bob's cron_list shows only his tasks.
            bob_list = await cron_list(principal_id="bob")
            bob_ids = {t["id"] for t in bob_list["tasks"]}
            assert bob_ids == {bob_task_id}

            # Alice cannot pause / remove Bob's task — ``not_found``.
            assert (await cron_pause(bob_task_id, principal_id="alice"))["status"] == "not_found"
            assert (await cron_remove(bob_task_id, principal_id="alice"))["status"] == "not_found"

            # Empty principal is rejected.
            assert (await cron_list(principal_id=""))["status"] == "error"
            assert (await cron_pause(bob_task_id, principal_id=""))["status"] == "error"
        finally:
            set_cron_engine(None)
    finally:
        await db.close()


# ---------------------------------------------------------------------------
# Acceptance 3: Scheduled Prompt uses creator principal, not server UID
# ---------------------------------------------------------------------------


async def test_acceptance_3_executor_receives_principal_id(tmp_path) -> None:
    """Criterion 3: the executor is called with the task's principal_id
    so the scheduled prompt runs as the creator (not the server UID).

    The engine tries a 3-arg executor first; if it raises ``TypeError``
    (older 2-arg signature), it falls back.  This test verifies the
    3-arg path is preferred and the principal_id is propagated.
    """
    db = await _make_db(tmp_path)
    try:
        captured: dict[str, str] = {}

        async def capturing_executor(task_id: str, prompt: str, principal_id: str) -> str:
            captured["principal_id"] = principal_id
            captured["task_id"] = task_id
            return "ok"

        engine = CronEngine(
            db=db, executor=capturing_executor, tick_interval=0.01,
        )
        await engine.start()
        # Use a one-shot ISO task in the past so it's immediately due.
        iso = (datetime.utcnow() - timedelta(seconds=10)).isoformat()
        task = await engine.create(
            "principal-exec", "p", ScheduleConfig(iso_time=iso),
            principal_id="creator-alice",
        )
        # Wait for the executor to be invoked.
        await asyncio.sleep(0.1)
        assert captured.get("principal_id") == "creator-alice", (
            "executor was not called with the task's principal_id — "
            "the scheduled prompt would run as the server UID"
        )
        assert captured.get("task_id") == task.id
        await engine.stop()
    finally:
        await db.close()


async def test_acceptance_3_executor_falls_back_to_2arg() -> None:
    """Criterion 3 (backwards compat): a 2-arg executor still works
    via the ``TypeError`` fallback.  This is for older test executors
    and any out-of-tree executor that hasn't been updated.
    """
    captured: dict[str, str] = {}

    async def legacy_2arg_executor(task_id: str, prompt: str) -> str:
        captured["called"] = "yes"
        return "ok"

    engine = CronEngine(executor=legacy_2arg_executor)
    task = await engine.create(
        "legacy-exec", "p", ScheduleConfig(iso_time=datetime.utcnow().isoformat()),
        principal_id="creator",
    )
    await engine._execute_task(task)
    assert captured.get("called") == "yes"


# ---------------------------------------------------------------------------
# Acceptance 4: Create and next_run in same durable INSERT
# ---------------------------------------------------------------------------


async def test_acceptance_4_next_run_persisted_atomically(tmp_path) -> None:
    """Criterion 4: ``next_run`` is persisted in the same INSERT as the
    task itself, so a restart before the first fire doesn't leave the
    task permanently stuck (tick skips tasks with ``next_run IS NULL``).
    """
    db = await _make_db(tmp_path)
    try:
        engine = CronEngine(db=db)
        before = datetime.utcnow()
        task = await engine.create(
            "atomic-next-run", "p",
            ScheduleConfig(interval_seconds=3600),
            principal_id="alice",
        )
        # The DB row MUST have next_run populated.
        rows = await db.list_scheduled_tasks()
        row = next(r for r in rows if r["id"] == task.id)
        assert row["next_run"] is not None, (
            "next_run was not persisted in the INSERT — restart before "
            "first fire would leave the task permanently stuck"
        )
        # The persisted next_run matches the in-memory value.
        assert task.next_run is not None
        persisted = datetime.fromisoformat(row["next_run"])
        assert abs((persisted - task.next_run).total_seconds()) < 1.0
        # And it's in the future (computed from now + interval).
        assert persisted >= before
    finally:
        await db.close()


# ---------------------------------------------------------------------------
# Acceptance 5: Create-then-restart-before-first-fire still triggers
# ---------------------------------------------------------------------------


async def test_acceptance_5_create_then_restart_still_fires(tmp_path) -> None:
    """Criterion 5: create a task, then immediately "restart" the engine
    (close + reopen the DB, create a new engine instance) BEFORE the
    first execution.  The task MUST still fire on schedule.
    """
    db_path = tmp_path / "khaos.db"
    db = await _make_db(db_path)
    try:
        engine = CronEngine(db=db)
        # Use a past ISO time so the task is immediately due after
        # restart.  The point of this test is that ``next_run`` is
        # persisted in the INSERT — without that, the task's
        # ``next_run`` would be NULL after restart and tick would
        # skip it (permanently stuck).
        iso = (datetime.utcnow() - timedelta(seconds=10)).isoformat()
        await engine.create(
            "restart-fire", "p", ScheduleConfig(iso_time=iso),
            principal_id="alice",
        )
        # The engine was NEVER started — so the task has not fired.
    finally:
        await db.close()

    # Simulate a process restart: new DB connection, new engine.
    db2 = Database(db_path)
    await db2.connect()
    await db2.run_migrations()
    try:
        fired: list[str] = []

        async def recording(task_id: str, prompt: str, principal_id: str) -> str:
            fired.append(task_id)
            return "ok"

        engine2 = CronEngine(
            db=db2, executor=recording, tick_interval=0.01,
        )
        await engine2.start()
        # Wait for the tick loop to pick up the due task.
        await asyncio.sleep(0.3)
        assert len(fired) == 1, (
            f"expected the task to fire once after restart, got {len(fired)} — "
            "next_run was not durable across the restart"
        )
        await engine2.stop()
    finally:
        await db2.close()


# ---------------------------------------------------------------------------
# Acceptance 6: Atomic claim durable lease before execution
# ---------------------------------------------------------------------------


async def test_acceptance_6_durable_lease_claimed_before_execution(tmp_path) -> None:
    """Criterion 6: before the executor runs, the engine atomically
    claims a durable lease (status=running + execution_id + lease_until)
    via ``claim_scheduled_task`` with a CAS on lifecycle_version.
    """
    db = await _make_db(tmp_path)
    try:
        async def quick_executor(task_id: str, prompt: str, principal_id: str) -> str:
            # Verify the lease was claimed BEFORE the executor ran.
            row = await db.get_scheduled_task(task_id)
            assert row is not None, "task row disappeared during execution"
            assert row["status"] == "running", (
                f"expected status=running during execution, got {row['status']} — "
                "the durable lease was not claimed before the executor ran"
            )
            assert row["execution_id"] is not None, (
                "execution_id was not set during execution — crash recovery "
                "cannot detect a crashed execution"
            )
            assert row["lease_until"] is not None, (
                "lease_until was not set during execution — crash recovery "
                "cannot detect an expired lease"
            )
            return "ok"

        engine = CronEngine(
            db=db, executor=quick_executor, tick_interval=0.01,
        )
        await engine.start()
        iso = (datetime.utcnow() - timedelta(seconds=10)).isoformat()
        task = await engine.create(
            "lease-claim", "p", ScheduleConfig(iso_time=iso),
            principal_id="alice",
        )
        await asyncio.sleep(0.2)
        # After execution, the lease is cleared.
        row = await db.get_scheduled_task(task.id)
        assert row["execution_id"] is None, (
            "execution_id was not cleared after successful execution"
        )
        assert row["lease_until"] is None
        assert row["status"] == "completed"
        await engine.stop()
    finally:
        await db.close()


async def test_acceptance_6_claim_fails_if_version_changed(tmp_path) -> None:
    """Criterion 6 (CAS): ``claim_scheduled_task`` returns 0 if the
    lifecycle_version changed (a control op happened between tick's
    readiness check and the claim).
    """
    db = await _make_db(tmp_path)
    try:
        engine = CronEngine(db=db)
        task = await engine.create(
            "cas-claim", "p", ScheduleConfig(interval_seconds=60),
            principal_id="alice",
        )
        # Bump the version via a control op (pause).
        await engine.pause(task.id, principal_id="alice")
        # Now try to claim with the OLD version (0).
        rowcount = await db.claim_scheduled_task(
            task.id,
            execution_id="test-exec-id",
            started_at="2026-01-01T00:00:00",
            lease_until="2099-01-01T00:00:00",
            expected_version=0,  # stale — pause bumped it to 1
        )
        assert rowcount == 0, (
            "claim_scheduled_task succeeded despite version mismatch — "
            "a stale tick could claim a task after a control op"
        )
        # The task is still paused (the claim did not overwrite it).
        row = await db.get_scheduled_task(task.id)
        assert row["status"] == "paused"
    finally:
        await db.close()


# ---------------------------------------------------------------------------
# Acceptance 7: Crash recovery has testable at-least-once semantics
# ---------------------------------------------------------------------------


async def test_acceptance_7_crashed_execution_recovered_as_failed(tmp_path) -> None:
    """Criterion 7: if the process crashes during execution (the
    terminal state was never persisted and the lease expired), restart
    recovery marks the task as FAILED — durable at-least-once disclosure.

    The task is NOT silently re-fired (which would duplicate side
    effects without the user knowing).
    """
    db_path = tmp_path / "khaos.db"
    db = await _make_db(db_path)
    try:
        started = asyncio.Event()
        release = asyncio.Event()

        async def stalling_executor(task_id: str, prompt: str, principal_id: str) -> str:
            started.set()
            await release.wait()
            return "should-not-reach"

        engine = CronEngine(
            db=db, executor=stalling_executor, tick_interval=0.01,
            execution_lease_seconds=0.1,  # short lease so it expires fast
        )
        await engine.start()
        iso = (datetime.utcnow() - timedelta(seconds=10)).isoformat()
        task = await engine.create(
            "crash-recovery", "p", ScheduleConfig(iso_time=iso),
            principal_id="alice",
        )
        await asyncio.wait_for(started.wait(), timeout=2.0)
        # Simulate a crash: close the DB WITHOUT calling stop() (so the
        # terminal state is never persisted and the lease is left
        # dangling).  release is never set.
    finally:
        await db.close()

    # Wait for the lease to expire.
    await asyncio.sleep(0.2)

    # Simulate a restart: new DB connection, new engine.
    db2 = Database(db_path)
    await db2.connect()
    await db2.run_migrations()
    try:
        fired: list[str] = []

        async def recording(task_id: str, prompt: str, principal_id: str) -> str:
            fired.append(task_id)
            return "ok"

        engine2 = CronEngine(
            db=db2, executor=recording, tick_interval=0.01,
        )
        await engine2.start()
        # Give recovery + tick a chance.
        await asyncio.sleep(0.3)
        # The crashed task was NOT re-fired — it was marked FAILED by
        # recover_expired_leases.
        assert len(fired) == 0, (
            f"crashed task was re-fired {len(fired)} time(s) — at-least-once "
            "disclosure was not applied"
        )
        # The task is now FAILED in the DB.
        row = await db2.get_scheduled_task(task.id)
        assert row["status"] == "failed", (
            f"expected status=failed after crash recovery, got {row['status']}"
        )
        assert "lease expired" in (row["error"] or ""), (
            f"expected error mentioning lease expiry, got {row['error']!r}"
        )
        await engine2.stop()
    finally:
        await db2.close()


# ---------------------------------------------------------------------------
# Acceptance 8: Old executor cannot clear newer control op's persistence generation
# ---------------------------------------------------------------------------


async def test_acceptance_8_stale_executor_cannot_clear_newer_control_marker(tmp_path) -> None:
    """Criterion 8: a stale executor whose conditional UPDATE succeeds
    (because a control op's DB write failed, leaving the DB version
    unchanged) MUST NOT clear the control op's pending persistence
    marker.

    Sequence:
      1. Start a task whose executor stalls.
      2. Patch ``update_scheduled_task_conditional`` to succeed for the
         stale executor's terminal write (simulating a control op's DB
         write having failed, leaving the DB version unchanged).
      3. Call ``pause`` — its DB write fails, so the PAUSED marker is
         left in ``_pending_persistence`` with a NEW operation_id.
      4. Release the executor — its conditional UPDATE succeeds, then
         it calls ``_persist_task_state`` which would normally clear
         the marker.  But the marker belongs to the NEWER pause op —
         the stale executor MUST NOT clear it.
      5. The marker is still in ``_pending_persistence`` with the
         pause op's operation_id.
    """
    db = await _make_db(tmp_path)
    try:
        started = asyncio.Event()
        release_exec = asyncio.Event()

        async def stalling_executor(task_id: str, prompt: str, principal_id: str) -> str:
            started.set()
            await release_exec.wait()
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

        # Capture the version at executor start (the executor captured
        # this for its conditional UPDATE).
        version_at_start = task.lifecycle_version

        # M4 batch 3.1.11 (HIGH-2): patch ``control_update_scheduled_task``
        # (the idempotent CAS used by pause) to fail, so the PAUSED
        # marker is left in _pending_persistence.  pause() no longer
        # uses the unconditional ``update_scheduled_task``.
        original_update = db.control_update_scheduled_task

        async def failing_update(*args, **kwargs):
            raise RuntimeError("DB wedged for control op")

        db.control_update_scheduled_task = failing_update

        # Call pause — it bumps the epoch, sets PAUSED in memory, and
        # tries to persist.  The persist fails, leaving a NEW marker
        # in _pending_persistence with a fresh operation_id.
        pause_result = await engine.pause(task_id, principal_id="alice")
        assert pause_result == "persistence_pending", (
            f"expected persistence_pending, got {pause_result}"
        )
        assert task_id in engine._pending_persistence
        pause_marker = engine._pending_persistence[task_id]
        assert pause_marker.is_control_op is True
        pause_operation_id = pause_marker.operation_id

        # Restore the control CAS.
        db.control_update_scheduled_task = original_update

        # Release the executor — it will try to write its terminal
        # state (PENDING for next run, since it's a one-shot ISO task
        # it would write COMPLETED).  Its conditional UPDATE checks
        # the version (still version_at_start, since pause's DB write
        # failed).  The conditional UPDATE succeeds — the stale
        # executor's _persist_task_state would normally clear the
        # marker, but the marker belongs to the NEWER pause op.
        release_exec.set()
        await asyncio.sleep(0.2)

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
        await engine.stop()
    finally:
        await db.close()


# ---------------------------------------------------------------------------
# Acceptance 9: commit-then-raise retry must not cause version drift
# ---------------------------------------------------------------------------


async def test_acceptance_9_commit_then_raise_no_version_drift(tmp_path) -> None:
    """Criterion 9 (batch 3.1.10): if the DB commits the conditional
    UPDATE but the caller receives an exception (ambiguous commit —
    e.g. a network error between commit and response), the retry MUST
    NOT bump the version again.

    M4 batch 3.1.11 (CRITICAL-2): the executor terminal write now uses
    ``finalize_scheduled_task`` (atomic terminal write + lease clear).
    The test patches THAT method (not ``update_scheduled_task_conditional``)
    and sets up a valid ``execution_id`` (via ``claim_scheduled_task``)
    so the CAS WHERE clause matches.

    Sequence:
      1. Create a task and capture its lifecycle_version.
      2. Claim the task (sets ``execution_id`` in the DB).
      3. Patch ``finalize_scheduled_task`` to commit the UPDATE
         (returning rowcount=1) but then raise (ambiguous commit).
      4. Call ``_persist_task_state`` — it commits, raises, the marker
         stays in _pending_persistence.
      5. Reconcile retries — the second call succeeds (no raise).
      6. The DB version MUST NOT have drifted (the executor write does
         not bump the version; only control ops do).
    """
    db = await _make_db(tmp_path)
    try:
        engine = CronEngine(db=db)
        task = await engine.create(
            "commit-raise", "p", ScheduleConfig(interval_seconds=60),
            principal_id="alice",
        )
        version_before = task.lifecycle_version
        # Read the DB version too.
        row_before = await db.get_scheduled_task(task.id)
        db_version_before = int(row_before["lifecycle_version"])

        # M4 batch 3.1.11: claim the task so the DB has a valid
        # execution_id — ``finalize_scheduled_task`` checks it in the
        # WHERE clause.  Mirror the execution_id on the in-memory task.
        execution_id = "test-exec-id-9"
        started_at = datetime.utcnow().isoformat()
        lease_until = (datetime.utcnow() + timedelta(seconds=600)).isoformat()
        rowcount = await db.claim_scheduled_task(
            task.id,
            execution_id=execution_id,
            started_at=started_at,
            lease_until=lease_until,
            expected_version=version_before,
        )
        assert rowcount == 1, "claim should succeed — task is PENDING"
        task.execution_id = execution_id
        task.lease_until = datetime.fromisoformat(lease_until)

        # Patch finalize_scheduled_task to commit (return 1) then raise.
        original_finalize = db.finalize_scheduled_task
        call_count = {"n": 0}

        async def commit_then_raise(*args, **kwargs):
            call_count["n"] += 1
            if call_count["n"] == 1:
                # First call: commit the UPDATE (call the real one),
                # then raise to simulate an ambiguous commit.
                result = await original_finalize(*args, **kwargs)
                raise RuntimeError("ambiguous commit — network error")
            # Subsequent calls: just return the real result (no raise).
            return await original_finalize(*args, **kwargs)

        db.finalize_scheduled_task = commit_then_raise

        # Set a terminal state and try to persist.
        task.status = TaskStatus.COMPLETED
        try:
            await engine._persist_task_state(
                task, expected_version=version_before,
                operation_id="test-op-1",
            )
        except RuntimeError:
            pass  # the ambiguous commit

        # The marker is in _pending_persistence (the persist raised).
        assert task.id in engine._pending_persistence, (
            "task.id is NOT in _pending_persistence after commit-then-raise"
        )

        # Reconcile retries — the second call succeeds (no raise).
        await engine._reconcile_pending_persistence()

        # The marker is cleared.
        assert task.id not in engine._pending_persistence, (
            "marker was not cleared after successful reconcile retry"
        )

        # The DB version MUST NOT have drifted — the executor write
        # does not bump the version (only control ops do).
        row_after = await db.get_scheduled_task(task.id)
        db_version_after = int(row_after["lifecycle_version"])
        assert db_version_after == db_version_before, (
            f"DB version drifted: before={db_version_before}, "
            f"after={db_version_after} — the commit-then-raise retry "
            "bumped the version, which would cause the next executor "
            "write to mismatch and be silently discarded"
        )

        db.finalize_scheduled_task = original_finalize
    finally:
        await db.close()


# ---------------------------------------------------------------------------
# Acceptance 10: cron_resume accurately propagates persistence_pending
# ---------------------------------------------------------------------------


async def test_acceptance_10_cron_resume_propagates_persistence_pending(tmp_path) -> None:
    """Criterion 10: ``cron_resume`` returns ``persistence_pending`` when
    the DB write fails — NOT ``execution_pending`` (which would
    mislead the user into thinking the old executor is still alive).

    The engine's ``resume()`` returns ``persistence_pending``; the
    tool layer must propagate it as-is, with a clear error message.
    """
    db = await _make_db(tmp_path)
    try:
        engine = CronEngine(db=db)
        task = await engine.create(
            "resume-pending", "p", ScheduleConfig(interval_seconds=60),
            principal_id="alice",
        )
        # Pause the task so it can be resumed.
        await engine.pause(task.id, principal_id="alice")

        # M4 batch 3.1.11 (HIGH-2): patch
        # ``control_update_scheduled_task`` (the idempotent CAS used by
        # resume) to fail.  resume() no longer uses the unconditional
        # ``update_scheduled_task`` with bump_version=True.
        original_update = db.control_update_scheduled_task

        async def failing_update(*args, **kwargs):
            raise RuntimeError("DB wedged on resume")

        db.control_update_scheduled_task = failing_update

        # Engine layer: resume returns persistence_pending.
        result = await engine.resume(task.id, principal_id="alice")
        assert result == "persistence_pending", (
            f"expected persistence_pending, got {result}"
        )

        # Tool layer: cron_resume also returns persistence_pending
        # (NOT execution_pending — that would mislead the user).
        set_cron_engine(engine)
        try:
            tool_result = await cron_resume(task.id, principal_id="alice")
            assert tool_result["status"] == "persistence_pending", (
                f"expected tool status=persistence_pending, got "
                f"{tool_result['status']} — the tool layer is not "
                "propagating the persistence_pending branch correctly"
            )
            # The error message must mention DB write failure, NOT
            # "old executor is still alive".
            assert "DB write failed" in tool_result["error"], (
                f"error message does not mention DB write failure: "
                f"{tool_result['error']!r}"
            )
            assert "executor is still" not in tool_result["error"], (
                f"error message misleadingly mentions executor: "
                f"{tool_result['error']!r}"
            )
        finally:
            set_cron_engine(None)

        db.control_update_scheduled_task = original_update
    finally:
        await db.close()


# ---------------------------------------------------------------------------
# Bonus: registry declares cron.manage capability + broker injects principal_id
# ---------------------------------------------------------------------------


async def test_cron_tools_declare_cron_manage_capability() -> None:
    """The 5 cron tools declare the ``cron.manage`` capability so the
    ``ToolInvocationBroker`` injects ``principal_id`` into the handler
    kwargs.  Without this, the handlers receive ``principal_id=""``
    even when the caller is authenticated.
    """
    from khaos.tools.registry import create_builtin_registry

    registry = create_builtin_registry()
    cron_tool_names = [
        "cron_create", "cron_list", "cron_remove",
        "cron_pause", "cron_resume",
    ]
    for name in cron_tool_names:
        definition = registry.get(name)
        cap_names = [c.name for c in definition.capabilities]
        assert "cron.manage" in cap_names, (
            f"tool {name} does not declare cron.manage capability — "
            "the broker will not inject principal_id"
        )


async def test_broker_injects_principal_id_for_cron_tools(tmp_path) -> None:
    """The ``ToolInvocationBroker`` injects ``principal_id`` into cron
    tool handler kwargs when the caller's context provides one.

    Uses ``cron_list`` (which has no ``name`` parameter — ``name`` would
    conflict with ``broker.invoke``'s first positional arg).  The
    principal injection is the same for all 5 cron tools because they
    all declare the ``cron.manage`` capability.
    """
    from khaos.tools.cron_tools import set_cron_engine
    from khaos.tools.registry import ToolInvocationBroker, create_runtime_registry

    db = await _make_db(tmp_path)
    try:
        engine = CronEngine(db=db)
        # Create a task directly via the engine so cron_list has
        # something to return.
        await engine.create(
            "broker-test", "p", ScheduleConfig(interval_seconds=60),
            principal_id="broker-alice",
        )
        set_cron_engine(engine)
        try:
            registry = create_runtime_registry()
            broker = ToolInvocationBroker(registry)
            # Invoke cron_list via the broker with a principal_id.
            result = await broker.invoke(
                "cron_list",
                mode="office",
                context={"principal_id": "broker-alice"},
            )
            assert "tasks" in result
            assert len(result["tasks"]) == 1
            assert result["tasks"][0]["name"] == "broker-test"
        finally:
            set_cron_engine(None)
    finally:
        await db.close()


async def test_broker_rejects_empty_principal_for_cron_tools(tmp_path) -> None:
    """If the caller's context has no ``principal_id``, the broker
    injects an empty string and the cron handler rejects it with an
    error — fail-closed (no fallback to a shared pseudo-principal).
    """
    from khaos.tools.cron_tools import set_cron_engine
    from khaos.tools.registry import ToolInvocationBroker, create_runtime_registry

    db = await _make_db(tmp_path)
    try:
        engine = CronEngine(db=db)
        set_cron_engine(engine)
        try:
            registry = create_runtime_registry()
            broker = ToolInvocationBroker(registry)
            # No principal_id in context — broker injects "".
            result = await broker.invoke(
                "cron_list",
                mode="office",
                context={},  # no principal_id
            )
            assert result["status"] == "error"
            assert "principal_id is required" in result["error"]
        finally:
            set_cron_engine(None)
    finally:
        await db.close()
