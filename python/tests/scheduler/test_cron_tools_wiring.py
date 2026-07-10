"""Tests for cron_tools → CronEngine wiring.

Verifies the handlers actually delegate to an injected CronEngine (creating
real tasks) and honestly report "unavailable" when no engine is injected —
rather than faking success.
"""

from __future__ import annotations

import khaos.tools.cron_tools as cron_tools
from khaos.scheduler import CronEngine, ScheduleConfig
from khaos.tools.cron_tools import (
    cron_create,
    cron_list,
    cron_pause,
    cron_remove,
    cron_resume,
    set_cron_engine,
)


async def test_create_with_injected_engine_creates_real_task() -> None:
    """With an engine injected, cron_create actually creates a task."""
    engine = CronEngine(db=None)
    set_cron_engine(engine)

    try:
        result = await cron_create("standup", "summarize", "30m")
        assert result["status"] == "created"
        assert result["task_id"] is not None
        # The task really exists in the engine.
        tasks = await engine.list_tasks()
        assert any(t.id == result["task_id"] for t in tasks)
    finally:
        set_cron_engine(None)  # reset for other tests


async def test_list_with_injected_engine_returns_tasks() -> None:
    engine = CronEngine(db=None)
    await engine.create("a", "p", ScheduleConfig(interval_seconds=60))
    set_cron_engine(engine)

    try:
        result = await cron_list()
        assert len(result["tasks"]) == 1
        assert result["tasks"][0]["name"] == "a"
    finally:
        set_cron_engine(None)


async def test_pause_resume_remove_with_injected_engine() -> None:
    engine = CronEngine(db=None)
    task = await engine.create("t", "p", ScheduleConfig(interval_seconds=60))
    set_cron_engine(engine)

    try:
        assert (await cron_pause(task.id))["status"] == "paused"
        assert (await engine.get(task.id)).status.value == "paused"

        assert (await cron_resume(task.id))["status"] == "resumed"
        assert (await engine.get(task.id)).status.value == "pending"

        assert (await cron_remove(task.id))["status"] == "removed"
        assert await engine.get(task.id) is None
    finally:
        set_cron_engine(None)


async def test_pause_unknown_task_returns_not_found() -> None:
    engine = CronEngine(db=None)
    set_cron_engine(engine)
    try:
        assert (await cron_pause("ghost"))["status"] == "not_found"
    finally:
        set_cron_engine(None)


async def test_create_without_engine_reports_unavailable() -> None:
    """No engine injected → honest 'unavailable', not a fake 'created'."""
    set_cron_engine(None)
    result = await cron_create("x", "y", "30m")

    assert result["status"] == "unavailable"
    assert "not configured" in result["error"]


async def test_list_without_engine_reports_unavailable() -> None:
    set_cron_engine(None)
    result = await cron_list()

    assert result["status"] == "unavailable"
    assert result["tasks"] == []


async def test_remove_without_engine_reports_unavailable() -> None:
    set_cron_engine(None)
    result = await cron_remove("any")

    assert result["status"] == "unavailable"
