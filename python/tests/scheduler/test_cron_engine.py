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

    assert await engine.pause(task.id) is True
    assert task.status == TaskStatus.PAUSED

    assert await engine.resume(task.id) is True
    assert task.status == TaskStatus.PENDING
    assert task.next_run is not None  # resume recomputes next_run


async def test_pause_unknown_returns_false() -> None:
    assert await _engine().pause("ghost") is False


async def test_remove() -> None:
    engine = _engine()
    task = await engine.create("t", "p", ScheduleConfig(interval_seconds=60))

    assert await engine.remove(task.id) is True
    assert await engine.get(task.id) is None
    assert task.status == TaskStatus.CANCELLED


async def test_remove_unknown_returns_false() -> None:
    assert await _engine().remove("ghost") is False


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
        ok = await engine.pause(task_id)
        assert ok is True

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
        ok = await engine.remove(task_id)
        assert ok is True

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
        ok = await engine.remove(task_id)
        assert ok is True

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
