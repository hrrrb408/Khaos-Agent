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
