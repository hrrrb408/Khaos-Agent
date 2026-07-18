"""H1 regression: detached SubAgent shutdown ownership.

These tests pin the security boundary the M4 lifecycle audit reopened:
``SubAgentService.Spawn`` returns ``running`` while the Spawner keeps the
task on a detached background ``asyncio.Task``.  Server teardown previously
had no authority over those detached tasks and could dismantle Office /
Browser / Audit / DB under a live subagent run.

Covered contracts:

* ``SubAgentSpawner.shutdown`` cancels and awaits every active task.
* ``spawn`` is rejected once shutdown has begun.
* A cancelled ``_run_task`` persists an explicit ``failed/cancelled``
  terminal row instead of leaving the DB stuck at ``running``.

Round-2 additions (M1 + M2):

* M1 — ``shutdown`` uses ``asyncio.wait`` and raises
  ``ServiceShutdownError`` when a task that swallows ``CancelledError`` is
  still pending at the deadline.  This is the fail-closed fix for the
  ``wait_for(gather)`` variant, which on timeout left the swallowing task
  running while teardown continued.
* M2 — ``spawn`` and ``shutdown`` share ``_spawn_lock`` so a spawn that has
  passed its shutdown check and is mid-DB-await cannot be missed by a
  concurrent shutdown's ``_active_tasks`` snapshot.
"""

from __future__ import annotations

import asyncio

import pytest

from khaos.db import Database
from khaos.exceptions import ServiceShutdownError, SubAgentLimitError
from khaos.subagents.spawner import SubAgentConfig, SubAgentSpawner, SubAgentTask


_PRINCIPAL = "user1"


async def _spawner(tmp_path, runner=None, max_concurrent=3):
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    spawner = SubAgentSpawner(
        SubAgentConfig(max_concurrent=max_concurrent), db, runner=runner
    )
    return db, spawner


# ───────────────────── H1: shutdown cancels active tasks ────────────────────


async def test_spawner_shutdown_cancels_active_task(tmp_path):
    """A blocked subagent must be cancelled and awaited by shutdown()."""
    started = asyncio.Event()
    release = asyncio.Event()

    async def blocking_runner(task: SubAgentTask) -> str:
        started.set()
        await release.wait()
        return "should-not-reach"

    db, spawner = await _spawner(tmp_path, runner=blocking_runner)
    try:
        await spawner.spawn(
            SubAgentTask("t1", "block", "ctx", [], principal_id=_PRINCIPAL)
        )
        await asyncio.wait_for(started.wait(), timeout=2.0)
        assert len(spawner._active_tasks) == 1

        # shutdown() must cancel + await within the bounded timeout, then
        # drop the task from _active_tasks.
        await spawner.shutdown(timeout=2.0)

        assert spawner._active_tasks == {}
        # The DB row must carry an explicit cancelled terminal state.
        rows = await db.list_subagent_tasks()
        assert rows[0]["status"] == "failed"
        assert rows[0]["error"] == "cancelled"
        # Let the runner's never-reached branch stay unreachable cleanly.
        release.set()
    finally:
        await db.close()


async def test_spawner_rejects_spawn_after_shutdown(tmp_path):
    """Once shutdown has begun, further spawn() calls fail closed."""
    db, spawner = await _spawner(tmp_path)
    try:
        await spawner.shutdown(timeout=1.0)
        with pytest.raises(SubAgentLimitError, match="shutting down"):
            await spawner.spawn(
                SubAgentTask("t1", "g", "ctx", [], principal_id=_PRINCIPAL)
            )
    finally:
        await db.close()


async def test_spawner_shutdown_is_idempotent_and_handles_empty(tmp_path):
    """shutdown() with no active tasks is a no-op and can be re-invoked."""
    db, spawner = await _spawner(tmp_path)
    try:
        await spawner.shutdown(timeout=1.0)
        await spawner.shutdown(timeout=1.0)
        assert spawner._active_tasks == {}
        assert spawner._shutting_down is True
    finally:
        await db.close()


# ─────────── H1: cancelled _run_task persists failed terminal row ───────────


async def test_cancelled_run_task_persists_failed_state(tmp_path):
    """A cancelled ``_run_task`` must write ``failed/cancelled`` to the DB.

    Previously the ``CancelledError`` branch only re-raised, leaving the DB
    row stuck at ``running`` forever even though the runtime had been torn
    down.  This pins the contract that a cancellation is a terminal
    transition visible to any later ``collect`` / ``status`` query.
    """
    started = asyncio.Event()
    release = asyncio.Event()

    async def blocking_runner(task: SubAgentTask) -> str:
        started.set()
        await release.wait()
        return "should-not-reach"

    db, spawner = await _spawner(tmp_path, runner=blocking_runner)
    try:
        task = await spawner.spawn(
            SubAgentTask("t1", "block", "ctx", [], principal_id=_PRINCIPAL)
        )
        await asyncio.wait_for(started.wait(), timeout=2.0)
        active = spawner._active_tasks[task.id]
        # Cancel the in-flight _run_task; its CancelledError branch must
        # persist the failed/cancelled row BEFORE re-raising.
        active.cancel()
        with pytest.raises(asyncio.CancelledError):
            await active
        rows = await db.list_subagent_tasks()
        assert rows[0]["status"] == "failed"
        assert rows[0]["error"] == "cancelled"
        # In-memory task object reflects the same terminal transition.
        assert spawner._tasks[task.id].status == "failed"
        assert spawner._tasks[task.id].error == "cancelled"
        release.set()
    finally:
        await db.close()


# ─────────────────── M1: shutdown raises on swallowing tasks ────────────────


async def test_spawner_shutdown_raises_when_task_swallows_cancel(tmp_path):
    """M1: a task that swallows ``CancelledError`` must NOT be silently
    released — ``shutdown`` raises ``ServiceShutdownError`` so the caller
    refuses to dismantle shared authorities the task still borrows.

    The previous ``wait_for(gather)`` path caught ``TimeoutError`` and only
    logged it, then let teardown continue.  This test pins the fail-closed
    contract: pending at the deadline → raise.
    """
    started = asyncio.Event()
    force_stop = asyncio.Event()

    async def swallowing_runner(task: SubAgentTask) -> str:
        started.set()
        # Adversarial wedged task: swallow cancellation until ``force_stop``
        # is set, so shutdown's 0.3s deadline is exceeded by a wide margin
        # (forcing the ServiceShutdownError path) while still allowing the
        # test to terminate the task deterministically afterward.  Pure
        # infinite-swallow would hang pytest-asyncio's loop teardown on
        # Python 3.13 (``_cancel_all_tasks`` awaits every task), so we
        # gate the loop on a test-controlled event.
        while not force_stop.is_set():
            try:
                await asyncio.sleep(3600)
            except asyncio.CancelledError:
                # Swallow: stay pending past the deadline.
                if not force_stop.is_set():
                    continue
                raise
        return "force-stopped"

    db, spawner = await _spawner(tmp_path, runner=swallowing_runner)
    try:
        await spawner.spawn(
            SubAgentTask("t1", "wedge", "ctx", [], principal_id=_PRINCIPAL)
        )
        await asyncio.wait_for(started.wait(), timeout=2.0)

        with pytest.raises(ServiceShutdownError, match="did not terminate"):
            await spawner.shutdown(timeout=0.3)

        # The wedged task must still be pending — shutdown did not pretend
        # to drain it.  Its runtime ownership is preserved for the caller
        # (orphan registry / process-level escalation).
        assert spawner._active_tasks  # still registered
        assert not next(iter(spawner._active_tasks.values())).done()
    finally:
        # Signal the wedged task to stop swallowing, then drive its
        # cancellation so it terminates cleanly and pytest-asyncio's
        # loop teardown does not hang on Python 3.13.
        force_stop.set()
        for t in list(spawner._active_tasks.values()):
            t.cancel()
        # Yield control so the runner's ``except: continue`` re-checks
        # force_stop and exits the loop on the next iteration.
        for _ in range(20):
            if all(t.done() for t in spawner._active_tasks.values()):
                break
            await asyncio.sleep(0.01)
        await db.close()


# ─────────────── M2: spawn/shutdown critical section atomicity ──────────────


async def test_spawn_during_shutdown_is_rejected_or_tracked(tmp_path):
    """M2: a spawn concurrent with shutdown is either rejected or tracked.

    Sequence: spawn enters its critical section, awaits the DB, and pauses
    there.  shutdown acquires ``_spawn_lock`` (waiting for spawn to finish
    its critical section) — the spawn either completes registration BEFORE
    shutdown's snapshot (so the task is tracked) or, if shutdown got the
    lock first, spawn sees ``_shutting_down`` and aborts.

    The forbidden middle state — spawn passes its shutdown check, then
    shutdown snapshots and misses the new task — is what ``_spawn_lock``
    prevents.  We assert the invariant: after both operations complete,
    every spawned task is either rejected or present in the shutdown
    snapshot (cancelled + awaited).
    """
    spawn_entered_db = asyncio.Event()
    spawn_can_finish = asyncio.Event()
    real_create_session = None  # set below after db is built

    db, spawner = await _spawner(tmp_path)

    # Wrap db.create_session so spawn stalls inside the DB await, giving
    # shutdown the chance to race.
    original_create_session = db.create_session

    async def stalling_create_session(session_id):
        spawn_entered_db.set()
        await spawn_can_finish.wait()
        return await original_create_session(session_id)

    db.create_session = stalling_create_session
    spawner.db = db  # ensure spawner sees the wrapped method

    async def spawn_one():
        try:
            await spawner.spawn(
                SubAgentTask("t1", "race", "ctx", [], principal_id=_PRINCIPAL)
            )
            return ("spawned", None)
        except SubAgentLimitError as exc:
            return ("rejected", str(exc))

    spawn_task = asyncio.create_task(spawn_one())
    # Wait until spawn has entered its DB await (holding _spawn_lock).
    await asyncio.wait_for(spawn_entered_db.wait(), timeout=2.0)

    # shutdown must wait on _spawn_lock — it cannot snapshot until spawn
    # finishes its critical section.  Run it concurrently.
    shutdown_task = asyncio.create_task(spawner.shutdown(timeout=2.0))

    # Let spawn finish its critical section.  Now two outcomes are valid:
    #   (a) spawn finished registration → shutdown snapshot includes it →
    #       task gets cancelled and awaited (no pending) → shutdown returns.
    #   (b) [not reachable here because spawn entered first] spawn rejected.
    spawn_can_finish.set()

    outcome, err = await spawn_task
    await shutdown_task

    if outcome == "spawned":
        # The task must have been included in shutdown's snapshot — it is
        # cancelled and removed from _active_tasks.  This is the
        # invariant: nothing spawn registered escapes shutdown.
        assert spawner._active_tasks == {}, (
            f"spawn registered a task but shutdown did not drain it: "
            f"{set(spawner._active_tasks)}"
        )
    else:
        # Rejected — also valid: spawn saw _shutting_down and aborted
        # before registering anything.
        assert "shutting down" in err
        assert spawner._active_tasks == {}
    await db.close()
