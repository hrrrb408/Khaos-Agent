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


async def test_spawner_shutdown_raises_when_task_does_not_terminate(tmp_path):
    """M1: a task still pending at the drain deadline must NOT be silently
    released — ``shutdown`` raises ``ServiceShutdownError`` so the caller
    refuses to dismantle shared authorities the task still borrows.

    The previous ``wait_for(gather)`` path caught ``TimeoutError`` and only
    logged it, then let teardown continue.  This test pins the fail-closed
    contract: pending at the deadline → raise.

    Implementation note: we register a coroutine in ``_active_tasks`` that
    never terminates on cancel (an ``asyncio.Event.wait`` that the test
    never sets), instead of going through ``spawn`` + a swallowing runner.
    The round-1 / round-2 attempts to use a real swallowing runner hit an
    asyncio wart where ``wait_for``-cancelled coroutines leak their inner
    task even after the outer task completes — that leak wedged the CI
    container at process exit (25-minute job timeout).  Registering the
    pending task directly exercises the same ``shutdown`` contract (the
    ``asyncio.wait`` + pending-set branch) without the leak.
    """
    db, spawner = await _spawner(tmp_path)
    try:
        # Register a task that never completes on cancel.  We use a
        # never-set Event so the coroutine stays pending; cleanup uses
        # a separate force-quit Event that the coroutine DOES honour so
        # the test process can exit cleanly.
        release = asyncio.Event()

        async def never_terminate():
            # Swallow cancellation until ``release`` is set, so shutdown's
            # 0.3s deadline is exceeded by a wide margin.  Once release
            # is set, honour the next cancellation so cleanup can end
            # the coroutine deterministically.
            while not release.is_set():
                try:
                    await release.wait()
                except asyncio.CancelledError:
                    if release.is_set():
                        raise
                    # else swallow: stay pending past the deadline.

        # Inject directly into the spawner's tracking, bypassing spawn's
        # _run_task wrapper (the contract under test is shutdown's
        # behaviour given a pending task, not _run_task's).
        task_id = "wedged-direct"
        spawner._tasks[task_id] = SubAgentTask(
            task_id, "wedge", "ctx", [], principal_id=_PRINCIPAL,
        )
        async_task = asyncio.create_task(never_terminate())
        spawner._active_tasks[task_id] = async_task
        # Yield so the coroutine actually starts running before shutdown
        # cancels it — otherwise cancel-on-unstarted-task completes it
        # immediately without ever entering the swallow loop, and
        # shutdown sees an empty pending set.
        await asyncio.sleep(0)

        with pytest.raises(ServiceShutdownError, match="did not terminate"):
            await spawner.shutdown(timeout=0.3)

        # The wedged task must still be pending — shutdown did not pretend
        # to drain it.  Its ownership is preserved for the caller.
        assert not async_task.done()
    finally:
        # Cleanup: set release so the next cancel terminates the coroutine.
        release.set()
        async_task.cancel()
        try:
            await asyncio.wait_for(async_task, timeout=2.0)
        except (asyncio.TimeoutError, asyncio.CancelledError):
            pass
        await db.close()


# ──────── M1 (round-3): cancel-before-first-run DB reconciliation ──────────


async def test_shutdown_persists_cancelled_state_for_never_started_task(tmp_path):
    """M1 (round-3): a task cancelled BEFORE its first scheduling slot
    must still reach a terminal DB state.

    Spawn's sequence is: DB write ``running`` → ``asyncio.create_task`` →
    register in ``_active_tasks``.  Shutdown then calls ``task.cancel()``.
    If the Task is cancelled before its coroutine gets its first event-
    loop slot, Python never enters ``_run_task``'s body, so its
    ``except CancelledError`` DB-write branch never runs.  The DB row
    would stay ``running`` forever even though the asyncio Task is done.

    ``shutdown`` now runs a reconcile pass over the snapshot, persisting
    ``failed/cancelled`` for any task whose status is still non-terminal.
    """
    never_entered = asyncio.Event()

    async def never_starts_runner(task: SubAgentTask) -> str:
        never_entered.set()
        return "should-not-reach"

    db, spawner = await _spawner(tmp_path, runner=never_starts_runner)
    try:
        # Spawn a task whose runner yields immediately (so the spawner Task
        # is created but has not yet been scheduled by the loop).
        task = await spawner.spawn(
            SubAgentTask("t1", "race", "ctx", [], principal_id=_PRINCIPAL)
        )
        # Crucially do NOT await anything that would let the spawned
        # coroutine run before we shut it down — we want the cancel to
        # land before _run_task's body executes.  shutdown() will cancel
        # the asyncio Task and then reconcile.
        await spawner.shutdown(timeout=2.0)

        # The runner body must NOT have executed.
        assert not never_entered.is_set(), (
            "test setup failed: the runner coroutine actually ran"
        )
        # The asyncio Task is done (cancelled before first step).
        assert task.id not in spawner._active_tasks
        # The DB row must reflect a terminal state, not the stale
        # ``running`` value written by spawn().
        rows = await db.list_subagent_tasks()
        assert len(rows) == 1
        assert rows[0]["status"] == "failed"
        assert rows[0]["error"] == "cancelled"
        # In-memory state mirrors the DB row.
        assert spawner._tasks[task.id].status == "failed"
        assert spawner._tasks[task.id].error == "cancelled"
    finally:
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
