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
        # M1 (round-4): pending tasks must NOT be falsely written as a
        # terminal DB state.  The task is still alive and borrowing shared
        # authorities; marking it ``failed/cancelled`` would hide that.
        # The in-memory status stays at its pre-shutdown value, and the DB
        # row is NOT updated by the reconcile pass (which only touches
        # ``done`` tasks).
        wedged_subtask = spawner._tasks[task_id]
        assert wedged_subtask.status != "failed", (
            "pending task was falsely marked failed — its still-live "
            "ownership of shared authorities is now hidden"
        )
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
    """M2: a spawn concurrent with shutdown is either rejected, tracked,
    or cancelled.

    Sequence: spawn enters its critical section, awaits the DB, and pauses
    there.  shutdown acquires ``_spawn_lock`` (waiting for spawn to finish
    its critical section) — the spawn either:

      (a) completes registration BEFORE shutdown's snapshot (so the task
          is tracked → cancelled + awaited by shutdown), OR
      (b) sees ``_shutting_down`` and is rejected (if shutdown got the
          lock first), OR
      (c) is cancelled mid-DB-work by shutdown's M1 owner-cancellation
          (the spawn coroutine itself is cancelled and awaited).

    The forbidden middle state — spawn passes its shutdown check, then
    shutdown snapshots and misses the new task — is what ``_spawn_lock``
    prevents.  We assert the invariant: after both operations complete,
    every spawned task is either rejected, tracked (cancelled + awaited),
    or cancelled (spawn coroutine cancelled + awaited).  In ALL cases,
    ``_active_tasks`` and ``_initializing_owners`` are empty after
    shutdown — nothing escapes.
    """
    spawn_entered_db = asyncio.Event()
    spawn_can_finish = asyncio.Event()

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
        except asyncio.CancelledError:
            return ("cancelled", None)

    spawn_task = asyncio.create_task(spawn_one())
    # Wait until spawn has entered its DB await.
    await asyncio.wait_for(spawn_entered_db.wait(), timeout=2.0)

    # shutdown must wait on _spawn_lock — it cannot snapshot until spawn
    # finishes its critical section.  Run it concurrently.
    shutdown_task = asyncio.create_task(spawner.shutdown(timeout=2.0))

    # Let spawn finish its critical section.  Now three outcomes are valid:
    #   (a) spawn finished registration → shutdown snapshot includes it →
    #       task gets cancelled and awaited (no pending) → shutdown returns.
    #   (b) [not reachable here because spawn entered first] spawn rejected.
    #   (c) spawn's DB work is cancelled by shutdown's M1 owner-cancel.
    spawn_can_finish.set()

    outcome, err = await spawn_task
    await shutdown_task

    # In ALL outcomes, nothing escapes shutdown:
    assert spawner._active_tasks == {}, (
        f"spawn registered a task but shutdown did not drain it: "
        f"{set(spawner._active_tasks)}"
    )
    assert spawner._initializing_owners == {}, (
        f"initializing owner not cleaned up: "
        f"{set(spawner._initializing_owners)}"
    )
    if outcome == "rejected":
        assert err is not None and "shutting down" in err
    # "spawned" and "cancelled" are both valid — the invariant is that
    # shutdown drained everything, asserted above.
    await db.close()


# ──────────── H1b (round-4): spawn DB work outside _spawn_lock ──────────────


async def test_spawn_db_work_does_not_block_shutdown_lock(tmp_path):
    """H1b (round-4): ``spawn``'s DB awaits run OUTSIDE ``_spawn_lock`` so a
    slow DB call cannot block ``shutdown`` from acquiring the lock and
    starting its bounded drain.

    The round-3 fix held the lock across ``create_session`` /
    ``insert_subagent_task``; a wedged DB held the lock indefinitely and
    shutdown's deadline never started.  The round-4 fix uses a
    reservation pattern — validate under the lock, DB work outside,
    re-lock to publish.
    """
    from unittest.mock import AsyncMock

    db, spawner = await _spawner(tmp_path)
    try:
        spawn_in_db = asyncio.Event()
        release_db = asyncio.Event()
        lock_free_during_db: list[bool] = []

        original_create = db.create_session

        async def stalling_create(session_id):
            spawn_in_db.set()
            # Probe: can shutdown's lock be acquired while we're parked
            # here?  It MUST be (DB work is outside the lock now).
            try:
                await asyncio.wait_for(
                    spawner._spawn_lock.acquire(), timeout=0.3,
                )
                lock_free_during_db.append(True)
                spawner._spawn_lock.release()
            except asyncio.TimeoutError:
                lock_free_during_db.append(False)
            await release_db.wait()
            return await original_create(session_id)

        db.create_session = stalling_create
        spawner.db = db

        spawn_task = asyncio.create_task(spawner.spawn(
            SubAgentTask("t1", "g", "ctx", [], principal_id=_PRINCIPAL)
        ))
        await asyncio.wait_for(spawn_in_db.wait(), timeout=2.0)
        # The DB work is parked.  shutdown MUST be able to acquire
        # _spawn_lock (the round-3 design would have blocked here).
        # We verify by reading the probe result recorded by stalling_create.
        release_db.set()
        await spawn_task  # spawn completes
        assert lock_free_during_db == [True], (
            "_spawn_lock was held during spawn's DB work — a slow DB "
            "would block shutdown from reaching its bounded drain"
        )
    finally:
        await db.close()


async def test_spawn_aborts_when_shutdown_begins_during_db_work(tmp_path):
    """M1 (round-5): if shutdown begins while spawn's DB work is in
    flight, shutdown cancels the spawn coroutine (the initializing owner)
    and awaits it within the total deadline.

    Previously (round-4) shutdown treated initializing reservations as
    "done by definition" — but the spawn coroutine was still alive doing
    DB work and could complete (inserting a row / launching a runner)
    AFTER shutdown returned.  Round-5 closes this by tracking the spawn
    coroutine in ``_initializing_owners`` and cancelling + awaiting it.

    With M1, the spawn coroutine is cancelled during its DB await.  The
    ``except BaseException`` block in ``spawn`` cleans up the owner
    registry, marks the task ``failed/cancelled`` in memory, and adds
    it to ``_pending_persistence`` for reconcile retry.  No runner is
    launched.
    """
    db, spawner = await _spawner(tmp_path)
    try:
        spawn_in_db = asyncio.Event()
        release_db = asyncio.Event()
        original_create = db.create_session

        async def stalling_create(session_id):
            spawn_in_db.set()
            await release_db.wait()
            return await original_create(session_id)

        db.create_session = stalling_create
        spawner.db = db

        async def spawn_one():
            return await spawner.spawn(
                SubAgentTask("t1", "g", "ctx", [], principal_id=_PRINCIPAL)
            )

        spawn_task = asyncio.create_task(spawn_one())
        await asyncio.wait_for(spawn_in_db.wait(), timeout=2.0)
        # Shutdown while spawn's DB work is parked.  M1: shutdown cancels
        # the spawn coroutine (the initializing owner) and awaits it.
        await spawner.shutdown(timeout=2.0)
        # release_db is now irrelevant — the spawn coroutine was cancelled
        # before its DB await completed.  Set it so the stalling_create
        # wrapper (if it ever resumes) doesn't hang; the coroutine is
        # already done so this is just defensive.
        release_db.set()
        # The spawn coroutine was cancelled — awaiting it re-raises
        # CancelledError.  Catch it and verify the in-memory state.
        with pytest.raises(asyncio.CancelledError):
            await spawn_task

        # No runner was launched.
        assert spawner._active_tasks == {}
        # The initializing owner was cleaned up.
        assert spawner._initializing_owners == {}
        # The in-memory task reflects the cancelled terminal state.
        task = list(spawner._tasks.values())[0]
        assert task.status == "failed"
        assert task.error == "cancelled"
    finally:
        await db.close()


# ──────────── M2 (round-4): DB reconcile failure propagates ─────────────────


async def test_shutdown_raises_when_db_reconcile_fails(tmp_path):
    """M2 (round-4): if the DB update during reconcile fails, shutdown
    MUST raise ``ServiceShutdownError`` instead of silently logging and
    continuing.

    Silently swallowing would let shutdown close the DB while a row is
    still marked ``running`` — exactly the durability gap the reconcile
    pass exists to close.
    """
    from unittest.mock import AsyncMock

    db, spawner = await _spawner(tmp_path)
    try:
        # Spawn a task that never starts its runner (we'll cancel before
        # first step), so reconcile MUST persist its terminal state.
        never_entered = asyncio.Event()

        async def never_starts(task: SubAgentTask) -> str:
            never_entered.set()
            return "should-not-reach"

        spawner.runner = never_starts
        task = await spawner.spawn(
            SubAgentTask("t1", "g", "ctx", [], principal_id=_PRINCIPAL)
        )
        # Break the DB update so reconcile cannot persist terminal state.
        db.update_subagent_task = AsyncMock(
            side_effect=RuntimeError("DB is being torn down")
        )
        spawner.db = db

        with pytest.raises(ServiceShutdownError, match="could not persist"):
            await spawner.shutdown(timeout=2.0)
    finally:
        await db.close()


# ──────── H1 (round-5): max_concurrent counts initializing reservations ─────


async def test_max_concurrent_counts_initializing_reservations(tmp_path):
    """H1 (round-5): ``max_concurrent`` MUST count initializing
    reservations, not just published runners.

    The round-4 reservation pattern defers runner publication until after
    DB I/O.  Counting only ``_active_tasks`` opened a window where
    concurrent spawns could all see ``active_count=0`` during their DB
    work and bypass the limit:

        max_concurrent=1
        Spawn A: active_count=0 → reserve A (initializing)
        Spawn B: active_count=0 → reserve B (initializing)  ← BUG
        DB resumes: A and B both publish runners
        Final: 2 runners (limit was 1)

    With the round-5 fix, ``active_count`` counts ``initializing`` tasks
    too, so Spawn B's check sees ``active_count=1`` and is rejected with
    ``SubAgentLimitError`` BEFORE any DB work or runner launch.

    This test pins the contract: with ``max_concurrent=1`` and two
    concurrent spawns both stalled in DB work, exactly one runner is
    ever published; the second spawn is rejected.
    """
    db, spawner = await _spawner(tmp_path, max_concurrent=1)
    try:
        spawn_a_in_db = asyncio.Event()
        release_a = asyncio.Event()
        spawn_b_in_db = asyncio.Event()
        release_b = asyncio.Event()
        spawn_b_outcome: list[tuple[str, str | None]] = []

        original_create = db.create_session

        async def stalling_create_a(session_id):
            spawn_a_in_db.set()
            await release_a.wait()
            return await original_create(session_id)

        async def stalling_create_b(session_id):
            spawn_b_in_db.set()
            await release_b.wait()
            return await original_create(session_id)

        # Spawn A: stall inside DB work so its reservation is held.
        db.create_session = stalling_create_a
        spawner.db = db
        spawn_a_task = asyncio.create_task(spawner.spawn(
            SubAgentTask("a", "goal-a", "ctx", [], principal_id=_PRINCIPAL)
        ))
        await asyncio.wait_for(spawn_a_in_db.wait(), timeout=2.0)

        # While A is parked in DB work, swap to a different stalling
        # wrapper for B and start B concurrently.  B MUST be rejected
        # before reaching its own DB work — the concurrency check at
        # reservation time sees A's initializing reservation and refuses.
        db.create_session = stalling_create_b
        spawner.db = db

        async def spawn_b():
            try:
                await spawner.spawn(
                    SubAgentTask("b", "goal-b", "ctx", [], principal_id=_PRINCIPAL)
                )
                spawn_b_outcome.append(("spawned", None))
            except SubAgentLimitError as exc:
                spawn_b_outcome.append(("rejected", str(exc)))
            except asyncio.CancelledError:
                spawn_b_outcome.append(("cancelled", None))

        spawn_b_task = asyncio.create_task(spawn_b())
        # Let B's coroutine get a scheduling slot so its concurrency
        # check actually runs.  We do NOT wait on spawn_b_in_db — that
        # would only fire if B passed the check (the bug).
        await asyncio.sleep(0.05)

        # Release A so it completes its DB work and publishes its runner.
        release_a.set()
        await spawn_a_task  # A publishes a runner

        # B must NOT have entered DB work — the concurrency check at
        # reservation time rejected it (or it's still pending, which
        # would also be acceptable — but the bug would have let it
        # through).  Release B's stall in case it did enter (defensive —
        # the contract is "never two runners", asserted below).
        release_b.set()
        await spawn_b_task

        # Exactly one runner was published.
        assert len(spawner._active_tasks) <= 1, (
            f"max_concurrent=1 but multiple runners published: "
            f"{set(spawner._active_tasks)}"
        )
        # B was rejected (the contract we're pinning).  "cancelled" is
        # also acceptable if shutdown raced in; "spawned" is the bug.
        assert spawn_b_outcome, "spawn B never completed"
        outcome, _ = spawn_b_outcome[0]
        assert outcome == "rejected", (
            f"max_concurrent=1 should reject the second spawn, got {outcome}"
        )
        # And the second task never reached initializing (it was rejected
        # at the concurrency check, before reservation).
        assert "b" not in spawner._tasks, (
            "rejected spawn leaked a reservation into _tasks"
        )

        # Clean up A's runner.
        await spawner.shutdown(timeout=2.0)
    finally:
        await db.close()


# ──── H2 (round-5): second shutdown retries pending terminal persistence ────


async def test_second_shutdown_retries_pending_terminal_persistence(tmp_path):
    """H2 (round-5): if the first shutdown's reconcile DB write fails,
    the task stays in ``_pending_persistence`` and the next shutdown
    retries it.

    Previously reconcile changed memory status to ``failed`` BEFORE the
    DB write; if the write raised ``ServiceShutdownError``, the next
    shutdown saw a terminal memory status and skipped the task — the DB
    row stayed ``running`` forever.  The round-5 fix tracks
    ``_pending_persistence`` independently of business state so reconcile
    retries until the UPDATE succeeds.

    Sequence:
      1. Spawn a task whose runner never starts (cancel-before-first-run).
      2. Patch ``db.update_subagent_task`` to fail on the first call.
      3. First shutdown: reconcile tries to persist, fails, raises
         ``ServiceShutdownError``.  Task is in ``_pending_persistence``.
      4. Restore ``db.update_subagent_task`` to the real implementation.
      5. Second shutdown: reconcile sees the task still in
         ``_pending_persistence`` and retries — succeeds this time.
      6. DB row now carries the terminal ``failed/cancelled`` state.
    """
    from unittest.mock import AsyncMock

    db, spawner = await _spawner(tmp_path)
    try:
        async def never_starts(task: SubAgentTask) -> str:
            return "should-not-reach"

        spawner.runner = never_starts
        task = await spawner.spawn(
            SubAgentTask("t1", "g", "ctx", [], principal_id=_PRINCIPAL)
        )
        # Task is reserved as initializing; the runner hasn't been
        # scheduled yet.  Break the DB update so the first shutdown's
        # reconcile fails.
        original_update = db.update_subagent_task
        call_count = {"n": 0}

        async def failing_update(*args, **kwargs):
            call_count["n"] += 1
            if call_count["n"] == 1:
                raise RuntimeError("DB is being torn down")
            return await original_update(*args, **kwargs)

        db.update_subagent_task = failing_update
        spawner.db = db

        # First shutdown: reconcile fails, raises ServiceShutdownError.
        with pytest.raises(ServiceShutdownError, match="could not persist"):
            await spawner.shutdown(timeout=2.0)
        # The task is still pending persistence — the failed write did
        # NOT clear the flag.
        assert task.id in spawner._pending_persistence, (
            "failed persist must leave the task in _pending_persistence "
            "so the next shutdown retries"
        )

        # Second shutdown: the task is still in _pending_persistence, so
        # reconcile retries.  This time the UPDATE succeeds.
        await spawner.shutdown(timeout=2.0)

        # The terminal state is now durable.
        assert task.id not in spawner._pending_persistence
        rows = await db.list_subagent_tasks()
        assert len(rows) == 1
        assert rows[0]["status"] == "failed"
        assert rows[0]["error"] == "cancelled"
    finally:
        await db.close()


# ──────── H3 (round-5): _run_task DB failure recovered by reconcile ─────────


async def test_run_task_db_failure_recovered_by_reconcile(tmp_path):
    """H3 (round-5): if ``_run_task``'s terminal DB write fails, the
    task stays in ``_pending_persistence`` and the next shutdown's
    reconcile persists it.

    Previously the success path set ``status = "completed"`` then tried
    the DB write; on failure, the ``except Exception`` branch set
    ``status = "failed"`` and tried ANOTHER write — which could also
    fail and propagate unhandled through the fire-and-forget asyncio
    Task.  The cancel path was even worse: it swallowed the failure, so
    the row stayed ``running`` and reconcile (which saw terminal memory
    state) skipped it.

    The round-5 fix uses ``_persist_terminal`` for both paths so a
    failed write is tracked in ``_pending_persistence`` for retry.
    """
    from unittest.mock import AsyncMock

    db, spawner = await _spawner(tmp_path)
    try:
        async def quick_runner(task: SubAgentTask) -> str:
            return "done"

        spawner.runner = quick_runner
        task = await spawner.spawn(
            SubAgentTask("t1", "g", "ctx", [], principal_id=_PRINCIPAL)
        )
        # Let the runner complete.  _run_task will set status="completed"
        # and try to persist.  Break the persist so it fails.
        original_update = db.update_subagent_task
        call_count = {"n": 0}

        async def failing_update(*args, **kwargs):
            call_count["n"] += 1
            if call_count["n"] == 1:
                raise RuntimeError("DB write failed during _run_task")
            return await original_update(*args, **kwargs)

        db.update_subagent_task = failing_update
        spawner.db = db

        # Wait for the runner to finish and the failed persist to land.
        # _run_task swallows the persist failure (it's fire-and-forget),
        # leaving the task in _pending_persistence.
        active = spawner._active_tasks[task.id]
        await active
        assert task.status == "completed"  # memory state
        assert task.id in spawner._pending_persistence, (
            "_run_task's failed persist must leave the task in "
            "_pending_persistence for reconcile retry"
        )

        # The DB row is still stale (the persist failed).  Spawn inserts
        # the row as ``initializing`` and only the terminal persist
        # writes ``completed`` — so a failed persist leaves ``initializing``.
        rows = await db.list_subagent_tasks()
        assert rows[0]["status"] == "initializing"

        # Shutdown's reconcile retries the persist and succeeds.
        await spawner.shutdown(timeout=2.0)

        assert task.id not in spawner._pending_persistence
        rows = await db.list_subagent_tasks()
        assert rows[0]["status"] == "completed"
    finally:
        await db.close()


# ───── M2 (round-5): reconcile bounded by total shutdown deadline ───────────


async def test_reconcile_bounded_by_total_shutdown_deadline(tmp_path):
    """M2 (round-5): the shutdown ``timeout`` is a TOTAL deadline that
    covers BOTH the runner drain AND the reconcile DB writes.

    Previously ``timeout`` only bounded ``asyncio.wait``; each DB UPDATE
    in reconcile was an unbounded ``await``, so a wedged DB made
    shutdown hang forever even with a small ``timeout``:

        runner drain completes (within timeout)
        → reconcile DB await blocks forever
        → shutdown total deadline ignored

    The round-5 fix computes a single ``deadline = monotonic + timeout``
    and passes the remaining budget to reconcile via
    ``asyncio.wait_for``.  A wedged DB now raises
    ``ServiceShutdownError`` instead of hanging.
    """
    from unittest.mock import AsyncMock

    db, spawner = await _spawner(tmp_path)
    try:
        async def never_starts(task: SubAgentTask) -> str:
            return "should-not-reach"

        spawner.runner = never_starts
        await spawner.spawn(
            SubAgentTask("t1", "g", "ctx", [], principal_id=_PRINCIPAL)
        )

        # Wedge the DB: every update blocks forever.
        async def wedged_update(*args, **kwargs):
            await asyncio.Event().wait()  # never resolves
            raise RuntimeError("unreachable")

        db.update_subagent_task = wedged_update
        spawner.db = db

        # With a 0.5s total deadline, shutdown must raise within ~0.5s,
        # not hang forever.  The reconcile's per-UPDATE await is bounded
        # by the remaining budget.
        import time
        start = time.monotonic()
        with pytest.raises(ServiceShutdownError):
            await spawner.shutdown(timeout=0.5)
        elapsed = time.monotonic() - start
        # Allow generous slack for CI scheduling, but prove it didn't
        # hang for the full default 30s deadline.
        assert elapsed < 5.0, (
            f"shutdown took {elapsed:.2f}s with timeout=0.5s — reconcile "
            "is not bounded by the total deadline"
        )
    finally:
        await db.close()
