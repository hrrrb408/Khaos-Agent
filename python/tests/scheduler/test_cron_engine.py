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
    assert engine._execute_tasks == set(), (
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
    assert engine._execute_tasks == set()
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
    for t in engine._execute_tasks:
        t.cancel()
    await asyncio.gather(*engine._execute_tasks, return_exceptions=True)


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
        exec_tasks = list(engine._execute_tasks)
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
        exec_tasks = list(engine._execute_tasks)
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
        exec_tasks = list(engine._execute_tasks)
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
