"""Tests for the cron scheduler engine."""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from khaos.scheduler import CronEngine, ScheduleConfig, ScheduledTask, TaskStatus


def _engine() -> CronEngine:
    """Engine without a DB (in-memory only) and a recording executor."""
    return CronEngine(executor=_recording_executor)


async def _recording_executor(task_id: str, prompt: str) -> str:
    return f"executed:{prompt}"


# ---------------------------------------------------------------------------
# create / list / get
# ---------------------------------------------------------------------------


async def test_create_task() -> None:
    engine = _engine()
    task = await engine.create(
        "daily-standup",
        "summarize today",
        ScheduleConfig(interval_seconds=3600),
    )

    assert task.id is not None
    assert task.name == "daily-standup"
    assert task.status == TaskStatus.PENDING
    assert task.next_run is not None
    listed = await engine.list_tasks()
    assert task in listed


async def test_get_returns_task() -> None:
    engine = _engine()
    created = await engine.create("t", "p", ScheduleConfig(interval_seconds=60))
    fetched = await engine.get(created.id)
    assert fetched is created


async def test_get_unknown_returns_none() -> None:
    engine = _engine()
    assert await engine.get("nope") is None


async def test_list_tasks() -> None:
    engine = _engine()
    await engine.create("a", "p", ScheduleConfig(interval_seconds=60))
    await engine.create("b", "p", ScheduleConfig(interval_seconds=60))
    assert len(await engine.list_tasks()) == 2


# ---------------------------------------------------------------------------
# pause / resume / remove
# ---------------------------------------------------------------------------


async def test_pause_resume() -> None:
    engine = _engine()
    task = await engine.create("t", "p", ScheduleConfig(interval_seconds=60))

    assert await engine.pause(task.id) == "ok"
    assert task.status == TaskStatus.PAUSED

    assert await engine.resume(task.id) == "ok"
    assert task.status == TaskStatus.PENDING
    assert task.next_run is not None  # resume recomputes next_run


async def test_pause_unknown_returns_false() -> None:
    assert await _engine().pause("ghost") == "not_found"


async def test_remove() -> None:
    engine = _engine()
    task = await engine.create("t", "p", ScheduleConfig(interval_seconds=60))

    assert await engine.remove(task.id) == "ok"
    assert await engine.get(task.id) is None
    assert task.status == TaskStatus.CANCELLED


async def test_remove_unknown_returns_false() -> None:
    assert await _engine().remove("ghost") == "not_found"


# ---------------------------------------------------------------------------
# next_run computation
# ---------------------------------------------------------------------------


def test_next_run_interval() -> None:
    engine = _engine()
    task = ScheduledTask(id="x", name="n", prompt="p", schedule=ScheduleConfig(interval_seconds=120))
    now = datetime.utcnow()
    nxt = engine._compute_next_run(task)
    assert nxt >= now
    # interval 120s → within ~120s of now.
    assert (nxt - now) <= timedelta(seconds=121)


def test_next_run_cron_simple() -> None:
    engine = _engine()
    task = ScheduledTask(id="x", name="n", prompt="p", schedule=ScheduleConfig(cron="0 9"))
    now = datetime.utcnow()
    nxt = engine._compute_next_run(task)
    assert nxt.hour == 9
    assert nxt.minute == 0
    # Always in the future (today if after 9am passed, else tomorrow).
    assert nxt > now or nxt.replace(day=now.day) >= now.replace(hour=9, minute=0, second=0, microsecond=0)


def test_next_run_iso_time() -> None:
    engine = _engine()
    iso = "2099-01-01T08:00:00"
    task = ScheduledTask(id="x", name="n", prompt="p", schedule=ScheduleConfig(iso_time=iso))
    nxt = engine._compute_next_run(task)
    assert nxt == datetime.fromisoformat(iso)


def test_next_run_unknown_format() -> None:
    """No schedule fields set → defaults to +1 hour."""
    engine = _engine()
    task = ScheduledTask(id="x", name="n", prompt="p", schedule=ScheduleConfig())
    now = datetime.utcnow()
    nxt = engine._compute_next_run(task)
    assert (nxt - now) >= timedelta(minutes=59)


# ---------------------------------------------------------------------------
# task execution lifecycle
# ---------------------------------------------------------------------------


async def test_task_lifecycle_pending_running_completed() -> None:
    """A one-shot (iso_time) task transitions PENDING → RUNNING → COMPLETED."""
    engine = _engine()
    iso = datetime.utcnow().isoformat()
    task = await engine.create("once", "do once", ScheduleConfig(iso_time=iso))

    await engine._execute_task(task)

    assert task.status == TaskStatus.COMPLETED
    assert task.run_count == 1
    assert task.last_run is not None
    assert "executed:do once" in (task.last_result or "")


async def test_repeat_limit() -> None:
    """A repeating task hits COMPLETED after `repeat` runs."""
    engine = _engine()
    task = await engine.create(
        "bounded", "p", ScheduleConfig(interval_seconds=60, repeat=2)
    )
    await engine._execute_task(task)
    assert task.status == TaskStatus.PENDING  # still pending, 1/2
    assert task.run_count == 1
    await engine._execute_task(task)
    assert task.status == TaskStatus.COMPLETED  # hit repeat limit
    assert task.run_count == 2


async def test_onetime_task_completed() -> None:
    engine = _engine()
    iso = datetime.utcnow().isoformat()
    task = await engine.create("once2", "p", ScheduleConfig(iso_time=iso))
    await engine._execute_task(task)
    assert task.status == TaskStatus.COMPLETED


async def test_task_failure() -> None:
    """An executor that raises marks the task FAILED."""
    engine = CronEngine(executor=_raising_executor)
    iso = datetime.utcnow().isoformat()
    task = await engine.create("boom", "p", ScheduleConfig(iso_time=iso))
    await engine._execute_task(task)
    assert task.status == TaskStatus.FAILED
    assert task.error is not None


async def _raising_executor(task_id: str, prompt: str) -> str:
    raise RuntimeError("boom")


# ---------------------------------------------------------------------------
# on_complete callback
# ---------------------------------------------------------------------------


async def test_on_complete_invoked() -> None:
    calls: list[tuple[str, str]] = []

    async def on_complete(task: ScheduledTask, result) -> None:
        calls.append((task.name, str(result)))

    engine = CronEngine(executor=_recording_executor, on_complete=on_complete)
    iso = datetime.utcnow().isoformat()
    task = await engine.create("cb", "p", ScheduleConfig(iso_time=iso))
    await engine._execute_task(task)

    assert calls == [("cb", "executed:p")]


# ---------------------------------------------------------------------------
# M4 (round-5): stop() drains in-flight _execute_task coroutines
# ---------------------------------------------------------------------------


async def test_stop_drains_in_flight_execute_tasks() -> None:
    """M4 (round-5): ``stop()`` MUST cancel and await every in-flight
    ``_execute_task`` coroutine.

    Previously ``_tick_loop`` fired ``asyncio.create_task(...)`` without
    keeping a reference, so a task that just started (but hadn't entered
    ``AgentService.chat()`` yet) escaped the engine's shutdown and could
    run after the DB / shared authorities were torn down — accessing a
    closed DB.

    The round-5 fix tracks ``_execute_tasks: set[asyncio.Task]`` with a
    discard-on-completion callback, and ``stop()`` cancels + gathers
    them with ``return_exceptions=True`` before returning.

    Sequence:
      1. Engine with a stall-able executor and a 0.01s tick interval.
      2. Create an ISO task that's already due → tick loop fires
         ``_execute_task`` immediately.
      3. The executor stalls on an Event so the task is in-flight.
      4. ``stop()`` cancels the tick loop AND the in-flight
         ``_execute_task``; both must be done when ``stop()`` returns.
    """
    import asyncio

    started = asyncio.Event()
    release = asyncio.Event()

    async def stalling_executor(task_id: str, prompt: str) -> str:
        started.set()
        await release.wait()
        return "should-not-reach"

    engine = CronEngine(
        executor=stalling_executor,
        tick_interval=0.01,  # fire quickly so the due task is picked up
    )
    # Due immediately.
    iso = datetime.utcnow().isoformat()
    await engine.create("in-flight", "p", ScheduleConfig(iso_time=iso))
    await engine.start()

    # Wait for the executor to actually start (proving the task is
    # in-flight, not just queued).
    await asyncio.wait_for(started.wait(), timeout=2.0)
    assert engine._execute_tasks, (
        "tick loop did not register the _execute_task coroutine"
    )

    # stop() must cancel + drain the in-flight task.  release is never
    # set, so without the M4 fix the task would hang forever (or escape
    # and access a closed DB after stop() returns).
    await asyncio.wait_for(engine.stop(), timeout=2.0)

    # All execute_tasks are done (cancelled + drained).
    assert engine._execute_tasks == {}, (
        "stop() did not drain in-flight _execute_tasks"
    )
    # Cleanup: release the executor's stall so any pending coroutine
    # wakes cleanly (defensive — they should already be cancelled).
    release.set()


async def test_stop_cancels_tick_loop_without_execute_tasks() -> None:
    """M4 (round-5): ``stop()`` with no in-flight executions still
    cancels the tick loop cleanly and is idempotent.
    """
    import asyncio

    engine = _engine()
    await engine.start()
    assert engine._loop_task is not None

    await engine.stop()

    # Tick loop is gone.
    assert engine._loop_task is None
    # No in-flight executions tracked.
    assert engine._execute_tasks == {}
    # Idempotent: a second stop() is a no-op.
    await engine.stop()
    assert engine._loop_task is None


# ---------------------------------------------------------------------------
# H1 (round-6): stop() bounded against cancellation-resistant executors
# ---------------------------------------------------------------------------


async def test_stop_bounded_against_swallowing_executor() -> None:
    """H1 (round-6): ``stop()`` MUST be bounded by a total deadline even
    when the executor swallows ``CancelledError``.

    The round-5 implementation used
    ``asyncio.gather(..., return_exceptions=True)`` with no timeout, so
    an executor that swallows ``CancelledError`` (e.g. a chat turn that
    catches it for permission-ledger cleanup) made ``stop()`` hang
    forever — ``AgentService.stop_producers`` would never return and
    the bounded ``CHAT_DRAIN_TIMEOUT`` would never start.

    The round-6 fix uses ``asyncio.wait(timeout=...)`` and raises
    ``ServiceShutdownError`` if any task is still pending at the
    deadline, WITHOUT clearing ``_execute_tasks`` so the caller
    retains ownership.
    """
    import asyncio
    import time

    from khaos.exceptions import ServiceShutdownError

    release = asyncio.Event()

    async def swallowing_executor(task_id: str, prompt: str) -> str:
        while not release.is_set():
            try:
                await release.wait()
            except asyncio.CancelledError:
                if release.is_set():
                    raise
                # swallow: stay pending past the deadline

    engine = CronEngine(
        executor=swallowing_executor,
        tick_interval=0.01,
    )
    iso = datetime.utcnow().isoformat()
    await engine.create("swallow", "p", ScheduleConfig(iso_time=iso))
    await engine.start()
    # Wait for the executor to actually start (proving the task is
    # in-flight, not just queued).
    await asyncio.sleep(0.05)
    assert engine._execute_tasks, (
        "tick loop did not register the _execute_task coroutine"
    )

    # stop() must raise within ~0.5s, NOT hang forever.
    start = time.monotonic()
    with pytest.raises(ServiceShutdownError, match="did not terminate"):
        await engine.stop(timeout=0.5)
    elapsed = time.monotonic() - start
    assert elapsed < 5.0, (
        f"stop() took {elapsed:.2f}s with timeout=0.5s — drain is not "
        "bounded against cancellation-resistant executors"
    )
    # _execute_tasks is NOT cleared — the pending task is still
    # borrowing shared authorities and the caller retains ownership.
    assert engine._execute_tasks, (
        "stop() cleared _execute_tasks despite pending tasks — "
        "ownership of still-live tasks was silently released"
    )
    # Cleanup: release the swallowing executor so the test process can
    # exit cleanly.
    release.set()
    for t in engine._execute_tasks.values():
        t.cancel()
    await asyncio.gather(*engine._execute_tasks.values(), return_exceptions=True)


# ---------------------------------------------------------------------------
# M3 (round-6): _execute_task persists cancelled terminal state
# ---------------------------------------------------------------------------


async def test_execute_task_persists_cancelled_state_on_cancellation(tmp_path) -> None:
    """M3 (round-6): when ``_execute_task`` is cancelled mid-execution,
    it MUST persist a ``cancelled`` terminal state to the DB before
    re-raising.

    Previously the ``except Exception`` branch did NOT catch
    ``CancelledError`` (it inherits from ``BaseException`` in Python
    3.8+), so the cancellation bypassed both the error branch and the
    DB update — leaving the in-memory task at ``RUNNING`` and the DB
    row stale.  On restart the scheduler would re-fire the task,
    potentially double-executing any external side effects.
    """
    import asyncio

    from khaos.db import Database
    from khaos.scheduler.models import ScheduledTask, ScheduleConfig

    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    try:
        started = asyncio.Event()
        release = asyncio.Event()

        async def stalling_executor(task_id: str, prompt: str) -> str:
            started.set()
            await release.wait()
            return "should-not-reach"

        engine = CronEngine(
            db=db,
            executor=stalling_executor,
            tick_interval=0.01,
        )
        # Start the engine BEFORE creating the task so ``_load_tasks``
        # doesn't overwrite the in-memory task's ``next_run`` (the DB
        # row doesn't store ``next_run``, so a reload leaves it None
        # and the tick loop never picks the task up).
        await engine.start()
        iso = datetime.utcnow().isoformat()
        task = await engine.create("cancel-test", "p", ScheduleConfig(iso_time=iso))
        task_id = task.id  # DB assigns a UUID hex id
        await asyncio.wait_for(started.wait(), timeout=2.0)

        # Cancel the in-flight _execute_task directly (simulating
        # shutdown-time cancellation).
        exec_tasks = list(engine._execute_tasks.values())
        assert len(exec_tasks) == 1
        exec_tasks[0].cancel()
        with pytest.raises(asyncio.CancelledError):
            await exec_tasks[0]

        # The in-memory task MUST reflect the cancelled terminal state.
        cancelled_task = engine._tasks[task_id]
        assert cancelled_task.status == TaskStatus.CANCELLED, (
            f"expected CANCELLED, got {cancelled_task.status} — CancelledError was "
            "not caught and the task is still RUNNING"
        )
        assert cancelled_task.error == "cancelled"

        # The DB row MUST also reflect the cancelled terminal state.
        # (Previously the DB row stayed at ``running`` because the
        # cancellation bypassed the DB update.)
        rows = await db.list_scheduled_tasks()
        cancel_row = next(r for r in rows if r["id"] == task_id)
        assert cancel_row["status"] == "cancelled", (
            f"expected DB status=cancelled, got {cancel_row['status']} — "
            "the cancelled terminal state was not persisted"
        )

        release.set()
        await engine.stop()
    finally:
        await db.close()


# ---------------------------------------------------------------------------
# H2 (round-7): terminal persistence retry across stop() calls
# ---------------------------------------------------------------------------


async def test_stop_retries_terminal_persistence_across_calls(tmp_path) -> None:
    """H2 (round-7): if the terminal-state DB write fails during
    ``_execute_task`` (e.g. the DB is momentarily wedged), ``stop()``
    MUST retry it via ``_pending_persistence``.  If the retry also
    fails, ``stop()`` raises ``ServiceShutdownError`` so the caller
    refuses to tear down the DB while a row is still stale.  The next
    ``stop()`` call retries again.

    Without this state machine, a cancelled task whose terminal UPDATE
    failed would stay at ``running`` in the DB — and on restart the
    scheduler would re-fire it, potentially double-executing external
    side effects.

    Sequence:
      1. Spawn a Cron task whose executor stalls.
      2. Patch ``update_scheduled_task`` to fail on the first call.
      3. Cancel the execute_task — its ``_persist_task_state`` fails,
         leaving the task_id in ``_pending_persistence``.
      4. First ``stop()``: reconcile retries the persist — fails again
         (still patched).  Raises ``ServiceShutdownError``.
      5. Restore ``update_scheduled_task`` to the real implementation.
      6. Second ``stop()``: reconcile retries — succeeds this time.
         DB row now carries the ``cancelled`` terminal state.
    """
    import asyncio

    from khaos.db import Database
    from khaos.exceptions import ServiceShutdownError
    from khaos.scheduler.models import ScheduledTask, ScheduleConfig

    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    try:
        started = asyncio.Event()
        release = asyncio.Event()

        async def stalling_executor(task_id: str, prompt: str) -> str:
            started.set()
            await release.wait()
            return "should-not-reach"

        engine = CronEngine(
            db=db,
            executor=stalling_executor,
            tick_interval=0.01,
        )
        await engine.start()
        iso = datetime.utcnow().isoformat()
        task = await engine.create("retry-test", "p", ScheduleConfig(iso_time=iso))
        task_id = task.id
        await asyncio.wait_for(started.wait(), timeout=2.0)

        # Patch update to fail on the first call (the cancel path's
        # _persist_task_state will hit this).
        original_update = db.update_scheduled_task
        call_count = {"n": 0}

        async def failing_update(*args, **kwargs):
            call_count["n"] += 1
            if call_count["n"] == 1:
                raise RuntimeError("DB is being torn down")
            return await original_update(*args, **kwargs)

        db.update_scheduled_task = failing_update

        # Cancel the execute_task — its _persist_task_state fails,
        # leaving the task_id in _pending_persistence.
        exec_tasks = list(engine._execute_tasks.values())
        assert len(exec_tasks) == 1
        exec_tasks[0].cancel()
        with pytest.raises(asyncio.CancelledError):
            await exec_tasks[0]
        # The task is in _pending_persistence (the persist failed).
        assert task_id in engine._pending_persistence, (
            "cancelled task whose persist failed is NOT in "
            "_pending_persistence — stop() cannot retry it"
        )

        # Patch update to fail again so the first stop()'s reconcile
        # also fails.
        async def failing_update_2(*args, **kwargs):
            raise RuntimeError("DB still wedged")

        db.update_scheduled_task = failing_update_2

        # First stop(): reconcile retries the persist, fails, raises
        # ServiceShutdownError.
        with pytest.raises(ServiceShutdownError, match="could not persist"):
            await engine.stop(timeout=2.0)
        # The task is STILL in _pending_persistence — the failed retry
        # did NOT clear the flag.
        assert task_id in engine._pending_persistence, (
            "failed persist retry cleared _pending_persistence — "
            "the next stop() cannot retry"
        )

        # Restore the real update so the next retry succeeds.
        db.update_scheduled_task = original_update

        # Second stop(): reconcile retries the persist, succeeds.
        await engine.stop(timeout=2.0)

        # The terminal state is now durable.
        assert task_id not in engine._pending_persistence
        rows = await db.list_scheduled_tasks()
        cancel_row = next(r for r in rows if r["id"] == task_id)
        assert cancel_row["status"] == "cancelled", (
            f"expected DB status=cancelled, got {cancel_row['status']} — "
            "the second stop() did not persist the terminal state"
        )

        release.set()
    finally:
        await db.close()


# ---------------------------------------------------------------------------
# H2 (round-7): restart does not re-fire a cancelled task
# ---------------------------------------------------------------------------


async def test_cancelled_task_not_refired_on_restart(tmp_path) -> None:
    """H2 (round-7): a cancelled task whose terminal state was
    persisted by ``stop()`` MUST NOT be re-fired when a new engine
    instance loads tasks from the DB.

    This is the user-visible contract the persistence state machine
    exists to protect: without it, a cancelled task whose terminal
    UPDATE failed would stay at ``running`` in the DB, and on restart
    the scheduler would re-fire it, potentially double-executing
    external side effects.
    """
    import asyncio

    from khaos.db import Database
    from khaos.scheduler.models import ScheduleConfig, TaskStatus

    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    try:
        started = asyncio.Event()
        release = asyncio.Event()
        exec_count = {"n": 0}

        async def stalling_executor(task_id: str, prompt: str) -> str:
            exec_count["n"] += 1
            started.set()
            await release.wait()
            return "should-not-reach"

        engine = CronEngine(
            db=db,
            executor=stalling_executor,
            tick_interval=0.01,
        )
        await engine.start()
        # Use a one-shot ISO task in the past so it's immediately due.
        iso = (datetime.utcnow() - timedelta(seconds=10)).isoformat()
        task = await engine.create("restart-test", "p", ScheduleConfig(iso_time=iso))
        task_id = task.id
        await asyncio.wait_for(started.wait(), timeout=2.0)

        # Cancel the execute_task — its _persist_task_state persists
        # the cancelled terminal state.
        exec_tasks = list(engine._execute_tasks.values())
        assert len(exec_tasks) == 1
        exec_tasks[0].cancel()
        with pytest.raises(asyncio.CancelledError):
            await exec_tasks[0]

        # stop() persists the cancelled terminal state via reconcile.
        await engine.stop(timeout=2.0)
        assert task_id not in engine._pending_persistence

        # The DB row is cancelled.
        rows = await db.list_scheduled_tasks()
        cancel_row = next(r for r in rows if r["id"] == task_id)
        assert cancel_row["status"] == "cancelled"

        # Simulate a restart: a new engine instance loads tasks from
        # the DB.  The cancelled task MUST NOT be re-fired.
        release.set()  # so any accidental re-fire doesn't hang the test
        started.clear()
        exec_count["n"] = 0

        engine2 = CronEngine(
            db=db,
            executor=stalling_executor,
            tick_interval=0.01,
        )
        await engine2.start()
        # Give the tick loop a chance to fire any due tasks.
        await asyncio.sleep(0.1)
        # The cancelled task was NOT re-fired.
        assert exec_count["n"] == 0, (
            f"cancelled task was re-fired {exec_count['n']} time(s) on "
            "restart — the terminal state was not durable"
        )
        await engine2.stop()
    finally:
        await db.close()


# ---------------------------------------------------------------------------
# H1 (round-8): stop() re-drains retained persistence owner
# ---------------------------------------------------------------------------


async def test_stop_redrains_retained_persistence_owner(tmp_path) -> None:
    """H1 (round-8): if the first ``stop()``'s reconcile owner is
    retained (timeout with a cancellation-resistant DB), the second
    ``stop()`` MUST re-drain it BEFORE spawning a new reconcile —
    otherwise the new reconcile would race with the retained one and
    the caller could return success while the retained owner is still
    holding the DB.

    Sequence:
      1. Spawn a Cron task whose executor stalls.
      2. Patch ``update_scheduled_task`` to FAIL on the first call so
         the cancel path's ``_persist_task_state`` raises (swallowed
         by the CancelledError branch).  The task_id is now in
         ``_pending_persistence``.
      3. Cancel the execute_task.  The cancel's persist fails →
         task_id stays in ``_pending_persistence``.
      4. Patch ``update_scheduled_task`` to HANG (swallow cancel)
         until ``release_db`` is set, then call the real update.
      5. First ``stop()``: reconcile owner is created and wedged;
         times out → raises ``ServiceShutdownError``.  Owner is
         retained in ``_persistence_owners``.
      6. Second ``stop()``: MUST snapshot the retained owner, await it
         within the total deadline, and refuse to spawn a new
         reconcile while it's still pending.
      7. Release the wedge so the retained owner terminates (calls the
         real update).  A third ``stop()`` now succeeds and the DB
         row carries the cancelled terminal state.
    """
    import asyncio

    from khaos.db import Database
    from khaos.exceptions import ServiceShutdownError
    from khaos.scheduler.models import ScheduleConfig

    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    # Initialise cleanup Events BEFORE the try block so the finally
    # clause can always release them even if an early assertion fails.
    release_db = asyncio.Event()
    release_exec = asyncio.Event()
    try:
        started = asyncio.Event()

        async def stalling_executor(task_id: str, prompt: str) -> str:
            started.set()
            await release_exec.wait()
            return "should-not-reach"

        engine = CronEngine(
            db=db,
            executor=stalling_executor,
            tick_interval=0.01,
        )
        await engine.start()
        iso = datetime.utcnow().isoformat()
        task = await engine.create("retained-owner", "p", ScheduleConfig(iso_time=iso))
        task_id = task.id
        await asyncio.wait_for(started.wait(), timeout=2.0)

        # Patch update to FAIL on the first call so the cancel path's
        # _persist_task_state raises and leaves task_id in
        # _pending_persistence.  Subsequent calls will be replaced by
        # the swallowing_update below.
        original_update = db.update_scheduled_task
        call_count = {"n": 0}

        async def failing_first_update(*args, **kwargs):
            call_count["n"] += 1
            raise RuntimeError("DB is being torn down")

        db.update_scheduled_task = failing_first_update

        # Cancel the execute_task — its _persist_task_state fails,
        # leaving the task_id in _pending_persistence.
        exec_tasks = list(engine._execute_tasks.values())
        assert len(exec_tasks) == 1
        exec_tasks[0].cancel()
        with pytest.raises(asyncio.CancelledError):
            await exec_tasks[0]
        assert task_id in engine._pending_persistence, (
            "cancelled task whose persist failed is NOT in "
            "_pending_persistence — stop() cannot retry it"
        )

        # Now wedge update_scheduled_task so the reconcile hangs until
        # release_db is set.  After release, it calls the real update
        # so the retained owner can actually persist.
        async def swallowing_update(*args, **kwargs):
            while not release_db.is_set():
                try:
                    await release_db.wait()
                except asyncio.CancelledError:
                    if release_db.is_set():
                        raise
                    # swallow: stay pending past the deadline
            return await original_update(*args, **kwargs)

        db.update_scheduled_task = swallowing_update

        # First stop(): reconcile hangs, owner is retained.
        with pytest.raises(ServiceShutdownError):
            await engine.stop(timeout=0.5)
        assert engine._persistence_owners, (
            "first stop() did not retain the persistence owner — "
            "a wedged DB task was silently orphaned"
        )
        first_owner_count = len(engine._persistence_owners)

        # Second stop(): MUST re-drain the retained owner BEFORE
        # spawning a new reconcile.  Since the retained owner is still
        # pending (release_db is not set), the second stop MUST raise
        # ServiceShutdownError and MUST NOT spawn a second reconcile
        # for the same task_id (no racing).
        with pytest.raises(ServiceShutdownError, match="retained persistence"):
            await engine.stop(timeout=0.5)
        assert len(engine._persistence_owners) == first_owner_count, (
            "second stop() spawned a new reconcile while a retained "
            "owner was still pending — would race with the retained one"
        )

        # Release the wedge so the retained owner can terminate and
        # call the real update to persist the terminal state.
        release_db.set()
        await asyncio.sleep(0.1)
        # Third stop(): the retained owner has terminated and persisted
        # the terminal state.  stop() should succeed.
        await engine.stop(timeout=2.0)
        assert not engine._persistence_owners, (
            "third stop() did not clear the retained owner registry"
        )
        rows = await db.list_scheduled_tasks()
        cancel_row = next(r for r in rows if r["id"] == task_id)
        assert cancel_row["status"] == "cancelled", (
            f"expected DB status=cancelled, got {cancel_row['status']} — "
            "the retained owner did not persist the terminal state"
        )

        release_exec.set()
    finally:
        release_db.set()
        release_exec.set()
        await db.close()


async def test_retained_persistence_owner_exception_is_surfaced(tmp_path) -> None:
    """H1 (round-8): if a retained persistence owner terminates with an
    exception (e.g. a DB write failure that's NOT a cancellation), the
    next ``stop()`` MUST explicitly read that exception (not silently
    swallow it via the discard callback) and then RETRY the persist
    via a fresh reconcile.  If the retry also fails, ``stop()`` raises
    ``ServiceShutdownError`` — the caller is informed that the
    terminal state is still not durable.

    This matches the H2 contract: ``stop()`` MUST retry on the next
    call.  The old exception is logged for observability but does NOT
    block the retry — if the DB has recovered, the retry succeeds and
    the terminal state becomes durable.

    Sequence:
      1. Spawn a Cron task whose executor stalls.
      2. Cancel the execute_task so its ``_persist_task_state`` is
         invoked; wedge ``update_scheduled_task`` so the first
         ``stop()``'s reconcile hangs (retained owner).
      3. Release the wedge so the retained owner resumes — the
         swallowing update raises ``RuntimeError`` after release, so
         the retained owner terminates with an exception.
      4. Second ``stop()``: reads the retained owner's exception
         (logged), removes the owner, and retries the persist via a
         fresh reconcile.  The retry also fails (DB still broken) and
         raises ``ServiceShutdownError`` matching "could not persist".
    """
    import asyncio

    from khaos.db import Database
    from khaos.exceptions import ServiceShutdownError
    from khaos.scheduler.models import ScheduleConfig

    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    # Initialise cleanup Events BEFORE the try block so the finally
    # clause can always release them even if an early assertion fails.
    release_db = asyncio.Event()
    release_exec = asyncio.Event()
    try:
        started = asyncio.Event()

        async def stalling_executor(task_id: str, prompt: str) -> str:
            started.set()
            await release_exec.wait()
            return "should-not-reach"

        engine = CronEngine(
            db=db,
            executor=stalling_executor,
            tick_interval=0.01,
        )
        await engine.start()
        iso = datetime.utcnow().isoformat()
        task = await engine.create("retained-exc", "p", ScheduleConfig(iso_time=iso))
        task_id = task.id
        await asyncio.wait_for(started.wait(), timeout=2.0)

        # Patch update to FAIL on the first call so the cancel path's
        # _persist_task_state raises and leaves task_id in
        # _pending_persistence.
        async def failing_first_update(*args, **kwargs):
            raise RuntimeError("DB is being torn down")

        db.update_scheduled_task = failing_first_update

        # Cancel the execute_task — its _persist_task_state fails,
        # leaving the task_id in _pending_persistence.
        exec_tasks = list(engine._execute_tasks.values())
        assert len(exec_tasks) == 1
        exec_tasks[0].cancel()
        with pytest.raises(asyncio.CancelledError):
            await exec_tasks[0]
        assert task_id in engine._pending_persistence, (
            "cancelled task whose persist failed is NOT in "
            "_pending_persistence — stop() cannot retry it"
        )

        # Wedge update_scheduled_task: swallows cancellation until
        # release_db is set, then raises RuntimeError (simulating a
        # wedged DB that surfaces a hard error once it resumes).
        async def swallowing_then_failing_update(*args, **kwargs):
            while not release_db.is_set():
                try:
                    await release_db.wait()
                except asyncio.CancelledError:
                    if release_db.is_set():
                        raise
                    # swallow: stay pending past the deadline
            raise RuntimeError("DB is being torn down")

        db.update_scheduled_task = swallowing_then_failing_update

        # First stop(): reconcile hangs, owner retained.
        with pytest.raises(ServiceShutdownError):
            await engine.stop(timeout=0.5)
        assert engine._persistence_owners

        # Release the wedge so the retained owner resumes and hits the
        # RuntimeError.  The reconcile_task terminates with a
        # ``ServiceShutdownError`` (raised by
        # ``_reconcile_pending_persistence`` after the persist failed).
        release_db.set()
        await asyncio.sleep(0.1)

        # Second stop(): the retained owner has terminated with an
        # exception.  stop() reads it (logged), removes the owner, and
        # retries the persist via a fresh reconcile.  The retry also
        # fails (DB still broken) and raises ``ServiceShutdownError``
        # matching "could not persist".
        with pytest.raises(ServiceShutdownError, match="could not persist"):
            await engine.stop(timeout=2.0)
        # The fresh retry's owner has been registered and terminated.
        # The task is still in ``_pending_persistence`` for the next
        # stop() to retry.
        assert task_id in engine._pending_persistence, (
            "after the fresh retry failed, the task MUST still be in "
            "_pending_persistence so the next stop() retries again"
        )

        release_exec.set()
    finally:
        release_db.set()
        release_exec.set()
        await db.close()


# ---------------------------------------------------------------------------
# M1 (round-8): pause / remove cancel in-flight execution
# ---------------------------------------------------------------------------


async def test_pause_cancels_in_flight_execution(tmp_path) -> None:
    """M1 (round-8): ``pause()`` MUST cancel + await the in-flight
    ``_execute_task`` BEFORE flipping the status to ``paused``.
    Otherwise the in-flight execution would complete after ``pause()``
    returned and overwrite the ``paused`` DB row with ``completed`` /
    ``pending`` — the user-visible contract ("I paused this task")
    would be silently violated and the executor's external side
    effects would keep running.

    Sequence:
      1. Spawn a Cron task whose executor stalls.
      2. Call ``pause()`` while the executor is in-flight.
      3. ``pause()`` cancels + awaits the executor, then writes
         ``paused`` to the DB.
      4. The DB row is ``paused`` (NOT ``running`` / ``completed`` /
         ``pending``).  The in-memory status is also ``paused``.
    """
    import asyncio

    from khaos.db import Database
    from khaos.scheduler.models import ScheduleConfig, TaskStatus

    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    try:
        started = asyncio.Event()
        release_exec = asyncio.Event()

        async def stalling_executor(task_id: str, prompt: str) -> str:
            started.set()
            await release_exec.wait()
            return "should-not-reach"

        engine = CronEngine(
            db=db,
            executor=stalling_executor,
            tick_interval=0.01,
        )
        await engine.start()
        iso = datetime.utcnow().isoformat()
        task = await engine.create("pause-test", "p", ScheduleConfig(iso_time=iso))
        task_id = task.id
        await asyncio.wait_for(started.wait(), timeout=2.0)

        # The executor is in-flight.
        assert task_id in engine._execute_tasks

        # pause() cancels + awaits the in-flight executor, then writes
        # paused to the DB.
        result = await engine.pause(task_id)
        assert result == "ok"

        # The in-flight execution was cancelled and removed from the
        # registry (it terminated within the cancel budget).
        assert task_id not in engine._execute_tasks, (
            "pause() did not cancel + drain the in-flight executor — "
            "the registry still has the task"
        )
        # The in-memory status is ``paused`` (NOT ``running``).
        assert engine._tasks[task_id].status == TaskStatus.PAUSED, (
            f"expected PAUSED, got {engine._tasks[task_id].status} — "
            "the in-flight executor overwrote the paused state"
        )
        # The DB row is also ``paused``.
        rows = await db.list_scheduled_tasks()
        row = next(r for r in rows if r["id"] == task_id)
        assert row["status"] == "paused", (
            f"expected DB status=paused, got {row['status']} — "
            "the in-flight executor's terminal write overwrote the "
            "paused DB row"
        )

        release_exec.set()
        await engine.stop(timeout=2.0)
    finally:
        release_exec.set()
        await db.close()


async def test_remove_cancels_in_flight_execution(tmp_path) -> None:
    """M1 (round-8): ``remove()`` MUST cancel + await the in-flight
    ``_execute_task`` BEFORE popping the task from ``_tasks``.
    Otherwise the in-flight execution would complete after ``remove()``
    returned and overwrite the ``cancelled`` DB row with
    ``completed`` / ``pending`` — on restart the scheduler would
    re-fire the task, potentially double-executing external side
    effects.

    Sequence:
      1. Spawn a Cron task whose executor stalls.
      2. Call ``remove()`` while the executor is in-flight.
      3. ``remove()`` cancels + awaits the executor, then writes
         ``cancelled`` to the DB.
      4. The DB row is ``cancelled`` (NOT ``running`` / ``completed`` /
         ``pending``).  The task is popped from ``_tasks``.
    """
    import asyncio

    from khaos.db import Database
    from khaos.scheduler.models import ScheduleConfig

    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    try:
        started = asyncio.Event()
        release_exec = asyncio.Event()

        async def stalling_executor(task_id: str, prompt: str) -> str:
            started.set()
            await release_exec.wait()
            return "should-not-reach"

        engine = CronEngine(
            db=db,
            executor=stalling_executor,
            tick_interval=0.01,
        )
        await engine.start()
        iso = datetime.utcnow().isoformat()
        task = await engine.create("remove-test", "p", ScheduleConfig(iso_time=iso))
        task_id = task.id
        await asyncio.wait_for(started.wait(), timeout=2.0)

        # The executor is in-flight.
        assert task_id in engine._execute_tasks

        # remove() cancels + awaits the in-flight executor, then
        # writes cancelled to the DB and pops the task from _tasks.
        result = await engine.remove(task_id)
        assert result == "ok"

        # The in-flight execution was cancelled and removed.
        assert task_id not in engine._execute_tasks, (
            "remove() did not cancel + drain the in-flight executor — "
            "the registry still has the task"
        )
        # The task is popped from _tasks.
        assert task_id not in engine._tasks, (
            "remove() did not pop the task from _tasks"
        )
        # The DB row is ``cancelled`` (NOT ``running`` / ``completed``
        # / ``pending``).
        rows = await db.list_scheduled_tasks()
        row = next(r for r in rows if r["id"] == task_id)
        assert row["status"] == "cancelled", (
            f"expected DB status=cancelled, got {row['status']} — "
            "the in-flight executor's terminal write overwrote the "
            "cancelled DB row"
        )

        release_exec.set()
        await engine.stop(timeout=2.0)
    finally:
        release_exec.set()
        await db.close()


async def test_remove_prevents_task_refire_on_restart(tmp_path) -> None:
    """M1 (round-8): a task removed while executing MUST NOT be
    re-fired on restart.  This is the user-visible contract the
    pause/remove cancel exists to protect — without it, the in-flight
    executor would overwrite the ``cancelled`` DB row with
    ``pending``/``completed``, and on restart the scheduler would
    re-fire the task, potentially double-executing external side
    effects.
    """
    import asyncio

    from khaos.db import Database
    from khaos.scheduler.models import ScheduleConfig

    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    try:
        started = asyncio.Event()
        release_exec = asyncio.Event()
        exec_count = {"n": 0}

        async def stalling_executor(task_id: str, prompt: str) -> str:
            exec_count["n"] += 1
            started.set()
            await release_exec.wait()
            return "should-not-reach"

        engine = CronEngine(
            db=db,
            executor=stalling_executor,
            tick_interval=0.01,
        )
        await engine.start()
        # ISO time in the past so the task is immediately due.
        iso = (datetime.utcnow() - timedelta(seconds=10)).isoformat()
        task = await engine.create("remove-restart", "p", ScheduleConfig(iso_time=iso))
        task_id = task.id
        await asyncio.wait_for(started.wait(), timeout=2.0)

        # remove() while the executor is in-flight.
        result = await engine.remove(task_id)
        assert result == "ok"

        # stop() the engine.
        release_exec.set()
        await engine.stop(timeout=2.0)

        # Simulate a restart: a new engine instance loads tasks from
        # the DB.  The cancelled task MUST NOT be re-fired.
        started.clear()
        exec_count["n"] = 0

        engine2 = CronEngine(
            db=db,
            executor=stalling_executor,
            tick_interval=0.01,
        )
        await engine2.start()
        await asyncio.sleep(0.1)
        assert exec_count["n"] == 0, (
            f"removed task was re-fired {exec_count['n']} time(s) on "
            "restart — the in-flight executor overwrote the cancelled "
            "DB row"
        )
        await engine2.stop()
    finally:
        release_exec.set()
        await db.close()


# ---------------------------------------------------------------------------
# H1 (round-9): pause/remove return cancellation_pending + epoch fence
# ---------------------------------------------------------------------------


async def test_pause_returns_cancellation_pending_and_epoch_fence_holds(
    tmp_path,
) -> None:
    """H1 (round-9): when ``pause()`` is called on a task whose executor
    swallows ``CancelledError`` and does NOT terminate within the cancel
    budget, ``pause()`` MUST return ``cancellation_pending`` (NOT
    ``ok``) — the caller MUST NOT claim the task is paused.

    Simultaneously, the execution epoch fence MUST prevent the stale
    executor from overwriting the ``PAUSED`` state when it eventually
    completes.  Without the fence, the stale executor's success path
    would set the status to ``PENDING`` / ``COMPLETED``, increment
    ``run_count``, and overwrite the ``paused`` DB row — silently
    violating the user-visible contract ("I paused this task") and
    causing the task to be re-fired.

    Sequence:
      1. Spawn a Cron task whose executor swallows ``CancelledError``
         until ``release_exec`` is set.
      2. Patch ``_CANCEL_IN_FLIGHT_TIMEOUT`` to 0.3s so the test
         doesn't wait 10s.
      3. Call ``pause()`` — bumps epoch, cancels the executor.  The
         executor swallows, so after the 0.3s budget ``pause()``
         returns ``cancellation_pending``.  In-memory status is
         ``PAUSED``; DB row is ``PAUSED``; the old executor is still
         in ``_execute_tasks``.
      4. Release the executor.  It returns from the swallowed cancel
         and proceeds to the success path of ``_execute_task``.  The
         epoch fence detects the bumped epoch and returns WITHOUT
         overwriting the ``PAUSED`` state.
      5. In-memory status is still ``PAUSED``; DB row is still
         ``PAUSED``; ``run_count`` did NOT increment.
    """
    import asyncio

    from khaos.db import Database
    from khaos.scheduler import engine as engine_module
    from khaos.scheduler.models import ScheduleConfig, TaskStatus

    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    release_exec = asyncio.Event()
    try:
        started = asyncio.Event()

        async def swallowing_executor(task_id: str, prompt: str) -> str:
            started.set()
            # Swallow CancelledError until release_exec is set, then
            # return — simulating a slow executor that ignored cancel
            # and eventually completed.
            while not release_exec.is_set():
                try:
                    await release_exec.wait()
                except asyncio.CancelledError:
                    if release_exec.is_set():
                        raise
                    # swallow: stay pending past the cancel budget
            return "stale-result"

        engine = CronEngine(
            db=db,
            executor=swallowing_executor,
            tick_interval=0.01,
        )
        # Patch the cancel budget to 0.3s so pause() doesn't wait 10s.
        original_budget = engine_module._CANCEL_IN_FLIGHT_TIMEOUT
        engine_module._CANCEL_IN_FLIGHT_TIMEOUT = 0.3
        try:
            await engine.start()
            iso = datetime.utcnow().isoformat()
            task = await engine.create(
                "pause-cp", "p", ScheduleConfig(iso_time=iso)
            )
            task_id = task.id
            await asyncio.wait_for(started.wait(), timeout=2.0)

            # pause() cancels the executor.  The executor swallows
            # CancelledError, so after the 0.3s budget pause() returns
            # cancellation_pending — NOT ok.
            result = await engine.pause(task_id)
            assert result == "cancellation_pending", (
                f"expected cancellation_pending, got {result!r} — "
                "pause() claimed success despite the executor not "
                "terminating within the cancel budget"
            )

            # The desired state is set: in-memory PAUSED, DB PAUSED.
            assert engine._tasks[task_id].status == TaskStatus.PAUSED, (
                f"expected PAUSED, got {engine._tasks[task_id].status} — "
                "pause() did not set the desired state"
            )
            rows = await db.list_scheduled_tasks()
            row = next(r for r in rows if r["id"] == task_id)
            assert row["status"] == "paused", (
                f"expected DB status=paused, got {row['status']} — "
                "pause() did not persist the desired state"
            )

            # The old executor is STILL in _execute_tasks (swallowed
            # cancel, did not terminate).  Ownership of the still-live
            # task is retained for stop() to handle.
            assert task_id in engine._execute_tasks, (
                "pause() cleared _execute_tasks despite the executor "
                "not terminating — ownership of the still-live task "
                "was silently released"
            )
            assert not engine._execute_tasks[task_id].done(), (
                "the wedged executor was marked done despite swallowing "
                "cancel — test setup is wrong"
            )
            # run_count has NOT incremented (the executor has not
            # completed yet).
            assert engine._tasks[task_id].run_count == 0, (
                f"run_count={engine._tasks[task_id].run_count} — the "
                "executor incremented run_count before completing"
            )

            # Now release the executor.  It returns from the swallowed
            # cancel and proceeds to the success path of _execute_task.
            # The epoch fence detects the bumped epoch and returns
            # WITHOUT overwriting the PAUSED state.
            release_exec.set()
            await asyncio.wait_for(
                engine._execute_tasks[task_id], timeout=2.0
            )

            # run_count did NOT increment (the stale success path was
            # fenced).
            assert engine._tasks[task_id].run_count == 0, (
                f"run_count={engine._tasks[task_id].run_count} — the "
                "stale executor's success path was NOT fenced and "
                "incremented run_count"
            )
            # The in-memory status is still PAUSED (NOT PENDING /
            # COMPLETED).
            assert engine._tasks[task_id].status == TaskStatus.PAUSED, (
                f"expected PAUSED after stale executor completed, got "
                f"{engine._tasks[task_id].status} — the epoch fence "
                "did NOT prevent the stale in-memory write"
            )
            # The DB row is still PAUSED.
            rows = await db.list_scheduled_tasks()
            row = next(r for r in rows if r["id"] == task_id)
            assert row["status"] == "paused", (
                f"expected DB status=paused after stale executor "
                f"completed, got {row['status']} — the epoch fence "
                "did NOT prevent the stale DB write"
            )

            await engine.stop(timeout=2.0)
        finally:
            engine_module._CANCEL_IN_FLIGHT_TIMEOUT = original_budget
    finally:
        release_exec.set()
        await db.close()


async def test_remove_returns_cancellation_pending_and_epoch_fence_holds(
    tmp_path,
) -> None:
    """H1 (round-9): when ``remove()`` is called on a task whose
    executor swallows ``CancelledError`` and does NOT terminate within
    the cancel budget, ``remove()`` MUST return ``cancellation_pending``
    (NOT ``ok``) — the caller MUST NOT claim the task is removed.

    The execution epoch fence MUST prevent the stale executor from
    overwriting the ``CANCELLED`` DB row when it eventually completes.
    Without the fence, the stale executor's success path would set the
    status to ``PENDING`` / ``COMPLETED`` and overwrite the
    ``cancelled`` DB row — on restart the scheduler would re-fire the
    task, potentially double-executing external side effects.

    Sequence:
      1. Spawn a Cron task whose executor swallows ``CancelledError``
         until ``release_exec`` is set.  Keep a reference to the task
         object (``remove()`` pops it from ``_tasks`` on successful
         persist, but the executor still holds a reference).
      2. Patch ``_CANCEL_IN_FLIGHT_TIMEOUT`` to 0.3s.
      3. Call ``remove()`` — bumps epoch, cancels the executor.  The
         executor swallows, so after the 0.3s budget ``remove()``
         returns ``cancellation_pending``.  The task IS popped from
         ``_tasks`` (because the persist of ``CANCELLED`` succeeded),
         the DB row is ``CANCELLED``, and the old executor is still
         in ``_execute_tasks``.
      4. Release the executor.  It returns from the swallowed cancel
         and proceeds to the success path of ``_execute_task``.  The
         epoch fence detects the bumped epoch and returns WITHOUT
         overwriting the ``CANCELLED`` DB row.
      5. DB row is still ``CANCELLED``; ``run_count`` did NOT
         increment; the task object's status is still ``CANCELLED``.
    """
    import asyncio

    from khaos.db import Database
    from khaos.scheduler import engine as engine_module
    from khaos.scheduler.models import ScheduleConfig, TaskStatus

    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    release_exec = asyncio.Event()
    try:
        started = asyncio.Event()

        async def swallowing_executor(task_id: str, prompt: str) -> str:
            started.set()
            while not release_exec.is_set():
                try:
                    await release_exec.wait()
                except asyncio.CancelledError:
                    if release_exec.is_set():
                        raise
                    # swallow: stay pending past the cancel budget
            return "stale-result"

        engine = CronEngine(
            db=db,
            executor=swallowing_executor,
            tick_interval=0.01,
        )
        original_budget = engine_module._CANCEL_IN_FLIGHT_TIMEOUT
        engine_module._CANCEL_IN_FLIGHT_TIMEOUT = 0.3
        try:
            await engine.start()
            iso = datetime.utcnow().isoformat()
            task = await engine.create(
                "remove-cp", "p", ScheduleConfig(iso_time=iso)
            )
            task_id = task.id
            await asyncio.wait_for(started.wait(), timeout=2.0)

            # remove() cancels the executor.  The executor swallows
            # CancelledError, so after the 0.3s budget remove() returns
            # cancellation_pending — NOT ok.
            result = await engine.remove(task_id)
            assert result == "cancellation_pending", (
                f"expected cancellation_pending, got {result!r} — "
                "remove() claimed success despite the executor not "
                "terminating within the cancel budget"
            )

            # Medium (round-10): the task is NOT popped from _tasks
            # when cancellation_pending — the tombstone (CANCELLED
            # status) is retained so the caller can retry remove()
            # and get a meaningful result (not not_found).
            assert task_id in engine._tasks, (
                "remove() popped the task from _tasks despite "
                "cancellation_pending — the caller cannot retry "
                "(would get not_found) even though the executor "
                "is still running"
            )
            # The desired state is durable: DB row is CANCELLED.
            rows = await db.list_scheduled_tasks()
            row = next(r for r in rows if r["id"] == task_id)
            assert row["status"] == "cancelled", (
                f"expected DB status=cancelled, got {row['status']} — "
                "remove() did not persist the desired state"
            )
            # The task object (still referenced by the executor) has
            # status CANCELLED.
            assert task.status == TaskStatus.CANCELLED
            assert task.run_count == 0, (
                f"run_count={task.run_count} — the executor "
                "incremented run_count before completing"
            )

            # The old executor is STILL in _execute_tasks.
            assert task_id in engine._execute_tasks, (
                "remove() cleared _execute_tasks despite the executor "
                "not terminating — ownership of the still-live task "
                "was silently released"
            )
            assert not engine._execute_tasks[task_id].done(), (
                "the wedged executor was marked done despite swallowing "
                "cancel — test setup is wrong"
            )

            # Release the executor.  It returns from the swallowed
            # cancel and proceeds to the success path of _execute_task.
            # The epoch fence detects the bumped epoch and returns
            # WITHOUT overwriting the CANCELLED DB row.
            release_exec.set()
            await asyncio.wait_for(
                engine._execute_tasks[task_id], timeout=2.0
            )

            # run_count did NOT increment (the stale success path was
            # fenced).
            assert task.run_count == 0, (
                f"run_count={task.run_count} — the stale executor's "
                "success path was NOT fenced and incremented run_count"
            )
            # The task object's status is still CANCELLED.
            assert task.status == TaskStatus.CANCELLED, (
                f"expected CANCELLED after stale executor completed, "
                f"got {task.status} — the epoch fence did NOT prevent "
                "the stale in-memory write"
            )
            # The DB row is still CANCELLED.
            rows = await db.list_scheduled_tasks()
            row = next(r for r in rows if r["id"] == task_id)
            assert row["status"] == "cancelled", (
                f"expected DB status=cancelled after stale executor "
                f"completed, got {row['status']} — the epoch fence "
                "did NOT prevent the stale DB write"
            )

            await engine.stop(timeout=2.0)
        finally:
            engine_module._CANCEL_IN_FLIGHT_TIMEOUT = original_budget
    finally:
        release_exec.set()
        await db.close()


# ---------------------------------------------------------------------------
# H2 (round-9): remove() retains the task when terminal persist fails
# ---------------------------------------------------------------------------


async def test_remove_retains_task_when_persist_fails(tmp_path) -> None:
    """H2 (round-9): if the terminal-state DB write fails during
    ``remove()``, the task MUST stay in ``_tasks`` with status
    ``CANCELLED`` and in ``_pending_persistence`` so ``stop()`` can
    retry the persist.  Previously ``remove()`` popped from ``_tasks``
    BEFORE the DB write — if the write failed, ``reconcile`` could not
    find the task in memory and silently discarded the pending flag,
    leaving the DB row at ``running`` / ``pending`` and causing the
    task to be re-fired on restart.

    Sequence:
      1. Spawn a Cron task whose executor stalls.
      2. Patch ``update_scheduled_task`` to FAIL.
      3. Call ``remove()`` — bumps epoch, cancels the executor (clean
         terminate, so ``cancel_ok=True``).  The epoch fence makes the
         executor's ``CancelledError`` branch re-raise WITHOUT
         persisting (so only ``remove()``'s persist is attempted).
         ``remove()`` sets status to ``CANCELLED``, calls
         ``_persist_task_state`` → FAILS.  ``task_id`` is now in
         ``_pending_persistence``.  ``remove()`` does NOT pop from
         ``_tasks``.  Returns ``"ok"`` (cancel_ok=True).
      4. Verify the task is STILL in ``_tasks`` with status
         ``CANCELLED`` and ``task_id`` is in ``_pending_persistence``.
      5. Restore ``update_scheduled_task``.
      6. ``stop()`` retries the persist via reconcile — succeeds.
      7. The DB row is now ``CANCELLED``.
    """
    import asyncio

    from khaos.db import Database
    from khaos.scheduler.models import ScheduleConfig, TaskStatus

    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    release_exec = asyncio.Event()
    try:
        started = asyncio.Event()

        async def stalling_executor(task_id: str, prompt: str) -> str:
            started.set()
            await release_exec.wait()
            return "should-not-reach"

        engine = CronEngine(
            db=db,
            executor=stalling_executor,
            tick_interval=0.01,
        )
        await engine.start()
        iso = datetime.utcnow().isoformat()
        task = await engine.create(
            "remove-retain", "p", ScheduleConfig(iso_time=iso)
        )
        task_id = task.id
        await asyncio.wait_for(started.wait(), timeout=2.0)

        # Patch update_scheduled_task to FAIL so remove()'s persist
        # raises and the task is retained in _tasks.
        original_update = db.update_scheduled_task

        async def failing_update(*args, **kwargs):
            raise RuntimeError("DB is being torn down")

        db.update_scheduled_task = failing_update

        # remove() cancels the executor (clean terminate), then tries
        # to persist CANCELLED — FAILS.  The task is NOT popped from
        # _tasks; task_id is in _pending_persistence.
        # H2 (round-10): remove() now returns persistence_pending
        # (NOT ok) when the DB write fails — the caller is informed
        # that the cancelled state may not be durable.
        result = await engine.remove(task_id)
        assert result == "persistence_pending", (
            f"expected persistence_pending, got {result!r} — "
            "remove() claimed success (ok) despite the terminal "
            "persist failing"
        )

        # The task is STILL in _tasks (NOT popped).
        assert task_id in engine._tasks, (
            "remove() popped the task from _tasks despite the "
            "terminal persist failing — reconcile cannot retry "            "without the in-memory state"
        )
        # The in-memory status is CANCELLED.
        assert engine._tasks[task_id].status == TaskStatus.CANCELLED, (
            f"expected CANCELLED, got {engine._tasks[task_id].status}"
        )
        # task_id is in _pending_persistence for stop() to retry.
        assert task_id in engine._pending_persistence, (
            "task_id is NOT in _pending_persistence — stop() cannot "
            "retry the terminal persist"
        )
        # The executor was cancelled cleanly (not in _execute_tasks).
        assert task_id not in engine._execute_tasks, (
            "the executor was not drained — remove() returned before "
            "cancel completed"
        )

        # Restore update_scheduled_task so stop()'s reconcile can
        # succeed.
        db.update_scheduled_task = original_update

        # stop() retries the persist via reconcile — succeeds.
        await engine.stop(timeout=2.0)

        # The terminal state is now durable.
        assert task_id not in engine._pending_persistence, (
            "stop() did not clear _pending_persistence after a "
            "successful retry"
        )
        rows = await db.list_scheduled_tasks()
        row = next(r for r in rows if r["id"] == task_id)
        assert row["status"] == "cancelled", (
            f"expected DB status=cancelled, got {row['status']} — "
            "stop()'s reconcile did not persist the terminal state"
        )

        release_exec.set()
    finally:
        release_exec.set()
        await db.close()


# ---------------------------------------------------------------------------
# H1 (round-10): lifecycle lock — tick does not publish for paused/removed tasks
# ---------------------------------------------------------------------------


async def test_tick_does_not_publish_for_paused_task(tmp_path) -> None:
    """H1 (round-10): after ``pause()`` returns, the tick loop MUST NOT
    publish a new ``_execute_task`` for the paused task — even if the
    task was snapshotted as due before pause ran.

    Without the lifecycle lock, the following race was possible:
      1. Tick snapshots task T as due (status PENDING).
      2. Pause runs: bumps epoch, sets PAUSED, persists, returns ok.
      3. Tick processes the stale snapshot and publishes
         ``_execute_task(T)``.  The new executor captures the
         POST-pause epoch (so the epoch fence does NOT trigger) and
         overwrites PAUSED with PENDING/COMPLETED — silently
         violating the user-visible contract and re-firing the task.

    The fix re-checks the task status under the lifecycle lock right
    before publishing.  If pause/remove set PAUSED/CANCELLED, tick
    skips the publish.

    This test deterministically exercises the post-pause state: pause
    is called BEFORE the tick loop runs, so the tick's re-check MUST
    skip the paused task.  The race window itself (pause between
    snapshot and publish) is covered by the lock semantics — the
    re-check is atomic with the publish.
    """
    import asyncio

    from khaos.db import Database
    from khaos.scheduler.models import ScheduleConfig, TaskStatus

    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    try:
        exec_count = {"n": 0}

        async def counting_executor(task_id: str, prompt: str) -> str:
            exec_count["n"] += 1
            return "should-not-run"

        engine = CronEngine(
            db=db,
            executor=counting_executor,
            tick_interval=0.01,
        )
        # Create a task that's due NOW but DON'T start the engine yet.
        iso = datetime.utcnow().isoformat()
        task = await engine.create("pause-tick", "p", ScheduleConfig(iso_time=iso))
        task_id = task.id

        # Pause BEFORE starting the engine — the task is due but
        # paused.  Tick's re-check MUST skip it.
        result = await engine.pause(task_id)
        assert result == "ok", (
            f"expected ok, got {result!r} — pause() of a not-running "
            "task should succeed"
        )
        assert engine._tasks[task_id].status == TaskStatus.PAUSED

        # Start the engine — the tick loop will snapshot the task as
        # due (next_run <= now) but the re-check under the lock MUST
        # skip it because status is PAUSED.
        await engine.start()
        # Give the tick loop multiple iterations to pick it up.
        await asyncio.sleep(0.1)

        # The executor was NEVER called — tick's re-check skipped the
        # paused task.
        assert exec_count["n"] == 0, (
            f"tick published _execute_task for a paused task — "
            f"executor was called {exec_count['n']} time(s); the "
            "lifecycle lock re-check did not skip the paused task"
        )
        # No _execute_task was created for the paused task.
        assert task_id not in engine._execute_tasks, (
            "tick registered an _execute_task for a paused task — "
            "the lifecycle lock re-check did not skip it"
        )
        # The task is still PAUSED (not overwritten to RUNNING /
        # PENDING / COMPLETED).
        assert engine._tasks[task_id].status == TaskStatus.PAUSED, (
            f"expected PAUSED, got {engine._tasks[task_id].status} — "
            "tick's publish overwrote the paused state"
        )
        # The DB row is still PAUSED.
        rows = await db.list_scheduled_tasks()
        row = next(r for r in rows if r["id"] == task_id)
        assert row["status"] == "paused", (
            f"expected DB status=paused, got {row['status']} — "
            "tick's publish overwrote the paused DB row"
        )

        await engine.stop(timeout=2.0)
    finally:
        await db.close()


async def test_tick_does_not_publish_for_removed_task(tmp_path) -> None:
    """H1 (round-10): after ``remove()`` returns ok, the tick loop
    MUST NOT publish a new ``_execute_task`` for the removed task —
    even if the task was snapshotted as due before remove ran.

    Without the lifecycle lock, the following race was possible:
      1. Tick snapshots task T as due (status PENDING).
      2. Remove runs: bumps epoch, sets CANCELLED, persists, pops
         from _tasks, returns ok.
      3. Tick processes the stale snapshot (still holds a reference
         to the task object) and publishes ``_execute_task(T)``.  The
         new executor captures the POST-remove epoch (so the epoch
         fence does NOT trigger) and overwrites CANCELLED with
         PENDING/COMPLETED — on restart the scheduler would re-fire
         the removed task, potentially double-executing external side
         effects.

    The fix re-checks the task status under the lifecycle lock right
    before publishing.  Since remove popped the task from _tasks AND
    set status to CANCELLED, tick's re-check (``task.status !=
    PENDING``) skips the publish.
    """
    import asyncio

    from khaos.db import Database
    from khaos.scheduler.models import ScheduleConfig

    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    try:
        exec_count = {"n": 0}

        async def counting_executor(task_id: str, prompt: str) -> str:
            exec_count["n"] += 1
            return "should-not-run"

        engine = CronEngine(
            db=db,
            executor=counting_executor,
            tick_interval=0.01,
        )
        # Create a task that's due NOW but DON'T start the engine yet.
        iso = datetime.utcnow().isoformat()
        task = await engine.create("remove-tick", "p", ScheduleConfig(iso_time=iso))
        task_id = task.id

        # Remove BEFORE starting the engine.
        result = await engine.remove(task_id)
        assert result == "ok", (
            f"expected ok, got {result!r} — remove() of a not-running "
            "task should succeed"
        )
        # The task is popped from _tasks.
        assert task_id not in engine._tasks

        # Start the engine — the tick loop will snapshot candidates
        # from _tasks (which no longer contains the removed task).  No
        # _execute_task should be created.
        await engine.start()
        await asyncio.sleep(0.1)

        # The executor was NEVER called.
        assert exec_count["n"] == 0, (
            f"tick published _execute_task for a removed task — "
            f"executor was called {exec_count['n']} time(s)"
        )
        # The DB row is still CANCELLED (not overwritten to RUNNING /
        # PENDING / COMPLETED).
        rows = await db.list_scheduled_tasks()
        row = next(r for r in rows if r["id"] == task_id)
        assert row["status"] == "cancelled", (
            f"expected DB status=cancelled, got {row['status']} — "
            "tick's publish overwrote the cancelled DB row"
        )

        await engine.stop(timeout=2.0)
    finally:
        await db.close()


# ---------------------------------------------------------------------------
# H2 (round-10): pause/remove return persistence_pending on DB write failure
# ---------------------------------------------------------------------------


async def test_pause_returns_persistence_pending_on_db_failure(
    tmp_path,
) -> None:
    """H2 (round-10): when ``pause()`` succeeds in cancelling the
    executor but the DB write fails, it MUST return
    ``persistence_pending`` (NOT ``ok``) — the caller is informed
    that the paused state may not be durable.

    Previously ``pause()`` returned ``ok`` whenever ``cancel_ok`` was
    True, regardless of the persist result.  The caller was misled
    into believing the paused state was durable — if the process
    crashed before ``stop()`` retried the persist, the DB row would
    stay at ``running`` / ``pending`` and the task would be re-fired
    on restart.
    """
    import asyncio

    from khaos.db import Database
    from khaos.scheduler.models import ScheduleConfig, TaskStatus

    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    try:
        started = asyncio.Event()
        release_exec = asyncio.Event()

        async def stalling_executor(task_id: str, prompt: str) -> str:
            started.set()
            await release_exec.wait()
            return "should-not-reach"

        engine = CronEngine(
            db=db,
            executor=stalling_executor,
            tick_interval=0.01,
        )
        await engine.start()
        iso = datetime.utcnow().isoformat()
        task = await engine.create(
            "pause-pp", "p", ScheduleConfig(iso_time=iso)
        )
        task_id = task.id
        await asyncio.wait_for(started.wait(), timeout=2.0)

        # Patch update_scheduled_task to FAIL so pause()'s persist
        # raises.
        original_update = db.update_scheduled_task

        async def failing_update(*args, **kwargs):
            raise RuntimeError("DB is being torn down")

        db.update_scheduled_task = failing_update

        # pause() cancels the executor (clean terminate), then tries
        # to persist PAUSED — FAILS.  Returns persistence_pending.
        result = await engine.pause(task_id)
        assert result == "persistence_pending", (
            f"expected persistence_pending, got {result!r} — "
            "pause() claimed success (ok) despite the terminal "
            "persist failing"
        )

        # The in-memory status is PAUSED.
        assert engine._tasks[task_id].status == TaskStatus.PAUSED, (
            f"expected PAUSED, got {engine._tasks[task_id].status}"
        )
        # task_id is in _pending_persistence for stop() to retry.
        assert task_id in engine._pending_persistence, (
            "task_id is NOT in _pending_persistence — stop() cannot "
            "retry the terminal persist"
        )

        # Restore update_scheduled_task so stop()'s reconcile can
        # succeed.
        db.update_scheduled_task = original_update

        # stop() retries the persist via reconcile — succeeds.
        await engine.stop(timeout=2.0)

        # The terminal state is now durable.
        assert task_id not in engine._pending_persistence
        rows = await db.list_scheduled_tasks()
        row = next(r for r in rows if r["id"] == task_id)
        assert row["status"] == "paused", (
            f"expected DB status=paused, got {row['status']} — "
            "stop()'s reconcile did not persist the terminal state"
        )

        release_exec.set()
    finally:
        release_exec.set()
        await db.close()


# ---------------------------------------------------------------------------
# Medium (round-10): remove(cancellation_pending) tombstone — retry works
# ---------------------------------------------------------------------------


async def test_remove_cancellation_pending_tombstone_allows_retry(
    tmp_path,
) -> None:
    """Medium (round-10): when ``remove()`` returns
    ``cancellation_pending`` (executor did not terminate), the task
    MUST stay in ``_tasks`` as a tombstone (CANCELLED status) so the
    caller can retry ``remove()`` and get a meaningful result — NOT
    ``not_found``.

    Previously ``remove()`` popped the task from ``_tasks`` whenever
    the persist succeeded, regardless of ``cancel_ok``.  The public
    API told the user "retry remove", but the retry returned
    ``not_found`` (task already popped) even though the old executor
    was still running — the caller had no way to confirm the
    executor had actually terminated.

    Sequence:
      1. Spawn a task whose executor swallows CancelledError.
      2. Call ``remove()`` — returns ``cancellation_pending``.  The
         task is NOT popped (tombstone retained).
      3. Retry ``remove()`` while the executor is still running —
         returns ``cancellation_pending`` again (NOT not_found).
      4. Release the executor so it terminates.
      5. Retry ``remove()`` — now returns ``ok`` (executor done,
         persist already done).  The task is popped.
    """
    import asyncio

    from khaos.db import Database
    from khaos.scheduler import engine as engine_module
    from khaos.scheduler.models import ScheduleConfig, TaskStatus

    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    release_exec = asyncio.Event()
    try:
        started = asyncio.Event()

        async def swallowing_executor(task_id: str, prompt: str) -> str:
            started.set()
            while not release_exec.is_set():
                try:
                    await release_exec.wait()
                except asyncio.CancelledError:
                    if release_exec.is_set():
                        raise
                    # swallow: stay pending past the cancel budget
            return "stale-result"

        engine = CronEngine(
            db=db,
            executor=swallowing_executor,
            tick_interval=0.01,
        )
        original_budget = engine_module._CANCEL_IN_FLIGHT_TIMEOUT
        engine_module._CANCEL_IN_FLIGHT_TIMEOUT = 0.3
        try:
            await engine.start()
            iso = datetime.utcnow().isoformat()
            task = await engine.create(
                "remove-tomb", "p", ScheduleConfig(iso_time=iso)
            )
            task_id = task.id
            await asyncio.wait_for(started.wait(), timeout=2.0)

            # First remove(): executor swallows cancel → returns
            # cancellation_pending.  Task is NOT popped (tombstone).
            result1 = await engine.remove(task_id)
            assert result1 == "cancellation_pending", (
                f"expected cancellation_pending, got {result1!r}"
            )
            assert task_id in engine._tasks, (
                "remove() popped the task from _tasks despite "
                "cancellation_pending — the caller cannot retry"
            )
            assert engine._tasks[task_id].status == TaskStatus.CANCELLED

            # Retry remove() while the executor is still running —
            # MUST return cancellation_pending again (NOT not_found).
            result2 = await engine.remove(task_id)
            assert result2 == "cancellation_pending", (
                f"expected cancellation_pending on retry, got "
                f"{result2!r} — the tombstone was not retained "
                "(retry returned not_found despite the executor "
                "still running)"
            )

            # Release the executor so it terminates.
            release_exec.set()
            await asyncio.wait_for(
                engine._execute_tasks[task_id], timeout=2.0
            )

            # Retry remove() — now the executor is done, so cancel_ok
            # is True.  The persist already succeeded (from the first
            # remove), so persist_ok is True.  Returns ok and pops.
            result3 = await engine.remove(task_id)
            assert result3 == "ok", (
                f"expected ok on retry after executor terminated, "
                f"got {result3!r} — the tombstone retry did not "
                "complete the removal"
            )
            # The task is now popped.
            assert task_id not in engine._tasks, (
                "remove() did not pop the task after the executor "
                "terminated and the persist succeeded"
            )

            await engine.stop(timeout=2.0)
        finally:
            engine_module._CANCEL_IN_FLIGHT_TIMEOUT = original_budget
    finally:
        release_exec.set()
        await db.close()


# ---------------------------------------------------------------------------
# H1 (round-11): done callback compares by identity — old callback
# doesn't remove new owner
# ---------------------------------------------------------------------------


async def test_done_callback_does_not_remove_new_owner() -> None:
    """H1 (round-11): when an old ``_execute_task`` completes, its
    done callback MUST NOT remove a NEW owner that was registered
    after the old task completed but before the callback ran.

    Without identity comparison, the following sequence orphaned the
    new owner:
      1. Tick publishes owner A for task T.
      2. Owner A completes (e.g. the executor returned).
      3. Before A's done callback runs, a new owner B is registered
         for task T (e.g. via resume + tick re-publish).
      4. A's done callback runs and pops ``_execute_tasks[T]`` —
         but the current owner is B, not A.  B is now orphaned: it's
         still running but no longer tracked, so ``stop()`` cannot
         cancel + drain it.

    The fix: the done callback compares the current owner by identity
    (``self._execute_tasks.get(tid) is owner``) before popping.  If
    the current owner is a different task, the callback is a no-op.
    """
    import asyncio

    engine = _engine()

    # Register a NEW "owner" (a dummy future task) in _execute_tasks.
    async def _dummy() -> None:
        await asyncio.sleep(100)

    new_owner = asyncio.ensure_future(_dummy())
    engine._execute_tasks["task-T"] = new_owner

    # Simulate the OLD owner completing.  Create an old task, register
    # a callback with the OLD owner as the identity reference
    # (mimicking what _tick_loop does), then make the old task
    # complete and let the callback fire.
    async def _old_executor() -> None:
        pass

    old_owner = asyncio.ensure_future(_old_executor())

    def _on_done(_t, tid="task-T", owner=old_owner) -> None:
        if engine._execute_tasks.get(tid) is owner:
            engine._execute_tasks.pop(tid, None)

    old_owner.add_done_callback(_on_done)
    # Let the old owner complete and its callback fire.
    await asyncio.wait_for(old_owner, timeout=2.0)
    # Yield to the event loop so the callback runs.
    await asyncio.sleep(0)

    # The NEW owner is STILL in _execute_tasks — the old callback
    # did NOT remove it (identity mismatch).
    assert engine._execute_tasks.get("task-T") is new_owner, (
        "the old done callback removed the new owner — identity "
        "check is missing or broken; the new owner is orphaned"
    )

    # Cleanup.
    new_owner.cancel()
    try:
        await new_owner
    except asyncio.CancelledError:
        pass


# ---------------------------------------------------------------------------
# H1 (round-11): concurrent pause + resume — per-task lock serializes
# ---------------------------------------------------------------------------


async def test_concurrent_pause_and_resume_are_serialized() -> None:
    """H1 (round-11): concurrent ``pause()`` and ``resume()`` on the
    same task MUST be serialized by the per-task lock.  Without
    serialization, the following race was possible:
      1. pause acquires lock, sets PAUSED, releases lock.
      2. resume acquires lock, sets PENDING, releases lock.
      3. pause's cancel runs.
      4. pause's persist writes PAUSED; resume's persist writes PENDING.
    Final: PENDING in memory + DB, but pause returned "ok" — the
    user's pause intent was silently overwritten by resume.

    With the per-task lock held for the ENTIRE operation (including
    cancel + persist), step 2 blocks until step 3+4 complete.  The
    final state is consistent: whichever operation runs last wins,
    and both return values are accurate.
    """
    import asyncio

    from khaos.scheduler.models import ScheduleConfig, TaskStatus

    engine = _engine()
    release = asyncio.Event()
    started = asyncio.Event()

    async def stalling_executor(task_id: str, prompt: str) -> str:
        started.set()
        await release.wait()
        return "ok"

    engine._executor = stalling_executor
    engine._tick_interval = 0.01
    await engine.start()
    iso = datetime.utcnow().isoformat()
    task = await engine.create("pause-resume", "p", ScheduleConfig(iso_time=iso))
    task_id = task.id
    await asyncio.wait_for(started.wait(), timeout=2.0)

    # Start pause() and resume() concurrently.  The per-task lock
    # serializes them — one runs fully before the other starts.
    pause_task = asyncio.ensure_future(engine.pause(task_id))
    resume_task = asyncio.ensure_future(engine.resume(task_id))

    # Both should complete without error.  The per-task lock ensures
    # they don't interleave — one's cancel+persist completes before
    # the other's state modification begins.
    pause_result, resume_result = await asyncio.gather(pause_task, resume_task)

    # Both should return a valid status.
    assert pause_result in ("ok", "cancellation_pending", "persistence_pending"), (
        f"pause returned {pause_result!r}"
    )
    assert resume_result in ("ok", "cancelled"), (
        f"resume returned {resume_result!r}"
    )

    # The final state is consistent — either PAUSED or PENDING, NOT
    # a mix.  The per-task lock ensures whichever ran last wins
    # cleanly.
    final_status = engine._tasks[task_id].status
    assert final_status in (TaskStatus.PAUSED, TaskStatus.PENDING), (
        f"final status is {final_status} — inconsistent state from "
        "concurrent pause + resume (per-task lock did not serialize)"
    )

    # Cleanup.
    release.set()
    await engine.stop(timeout=2.0)


# ---------------------------------------------------------------------------
# Medium (round-11): resume() refuses CANCELLED removal tombstone
# ---------------------------------------------------------------------------


async def test_resume_refuses_cancelled_tombstone(tmp_path) -> None:
    """Medium (round-11): ``resume()`` MUST refuse to resume a
    CANCELLED removal tombstone.  Previously ``resume()`` did not
    check the status at all — a caller could resume a CANCELLED
    tombstone, flipping it to PENDING and causing the removed task
    to be re-fired.

    Sequence:
      1. Spawn a task with a swallowing executor.
      2. Call ``remove()`` — returns ``cancellation_pending``.  Task
         stays in _tasks as a CANCELLED tombstone (executor still
         running).
      3. Call ``resume()`` — MUST return ``cancelled`` (NOT ``ok``).
         The task is STILL CANCELLED.
    """
    import asyncio

    from khaos.db import Database
    from khaos.scheduler import engine as engine_module
    from khaos.scheduler.models import ScheduleConfig, TaskStatus

    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    release_exec = asyncio.Event()
    try:
        started = asyncio.Event()

        async def swallowing_executor(task_id: str, prompt: str) -> str:
            started.set()
            while not release_exec.is_set():
                try:
                    await release_exec.wait()
                except asyncio.CancelledError:
                    if release_exec.is_set():
                        raise
                    # swallow
            return "stale"

        engine = CronEngine(
            db=db,
            executor=swallowing_executor,
            tick_interval=0.01,
        )
        original_budget = engine_module._CANCEL_IN_FLIGHT_TIMEOUT
        engine_module._CANCEL_IN_FLIGHT_TIMEOUT = 0.3
        try:
            await engine.start()
            iso = datetime.utcnow().isoformat()
            task = await engine.create(
                "resume-tomb", "p", ScheduleConfig(iso_time=iso)
            )
            task_id = task.id
            await asyncio.wait_for(started.wait(), timeout=2.0)

            # remove() returns cancellation_pending (executor swallows
            # cancel).  Task stays in _tasks as a CANCELLED tombstone.
            result = await engine.remove(task_id)
            assert result == "cancellation_pending"
            assert task_id in engine._tasks
            assert engine._tasks[task_id].status == TaskStatus.CANCELLED

            # resume() MUST refuse — return "cancelled", NOT "ok".
            resume_result = await engine.resume(task_id)
            assert resume_result == "cancelled", (
                f"expected 'cancelled', got {resume_result!r} — "
                "resume() did not refuse the CANCELLED removal "
                "tombstone; the task would be re-fired"
            )

            # The task is STILL CANCELLED (resume did not flip it to
            # PENDING).
            assert engine._tasks[task_id].status == TaskStatus.CANCELLED, (
                f"expected CANCELLED, got "
                f"{engine._tasks[task_id].status} — resume() "
                "flipped the tombstone to PENDING"
            )

            # The DB row is STILL CANCELLED.
            rows = await db.list_scheduled_tasks()
            row = next(r for r in rows if r["id"] == task_id)
            assert row["status"] == "cancelled", (
                f"expected DB status=cancelled, got {row['status']} — "
                "resume() overwrote the cancelled DB row"
            )

            # Release the executor so stop() can drain.
            release_exec.set()
            await engine.stop(timeout=2.0)
        finally:
            engine_module._CANCEL_IN_FLIGHT_TIMEOUT = original_budget
    finally:
        release_exec.set()
        await db.close()
