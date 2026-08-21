"""Contract tests for pure schedule calculation."""

from __future__ import annotations

from datetime import datetime, timedelta

from khaos.scheduler.calculator import ScheduleCalculator
from khaos.scheduler.models import ScheduleConfig, ScheduledTask


def _task(schedule: ScheduleConfig) -> ScheduledTask:
    return ScheduledTask(id="task", name="task", prompt="run", schedule=schedule)


def test_interval_calculation_is_pure_and_uses_supplied_clock() -> None:
    now = datetime.fromisoformat("2026-08-21T10:30:00")
    task = _task(ScheduleConfig(interval_seconds=90))

    assert ScheduleCalculator.compute(task, now=now) == now + timedelta(seconds=90)
    assert task.next_run is None


def test_cron_calculation_rolls_to_next_day() -> None:
    now = datetime.fromisoformat("2026-08-21T10:30:00")
    result = ScheduleCalculator.parse_simple_cron("0 9", now)

    assert result == datetime.fromisoformat("2026-08-22T09:00:00")


def test_invalid_schedule_falls_back_to_bounded_default() -> None:
    now = datetime.fromisoformat("2026-08-21T10:30:00")
    task = _task(ScheduleConfig(cron="not a cron"))

    assert ScheduleCalculator.compute(task, now=now) == now + timedelta(hours=1)


def test_iso_time_has_priority_over_other_schedule_fields() -> None:
    iso = "2026-08-22T09:00:00"
    task = _task(
        ScheduleConfig(iso_time=iso, interval_seconds=90, cron="0 8")
    )

    assert ScheduleCalculator.compute(task) == datetime.fromisoformat(iso)
