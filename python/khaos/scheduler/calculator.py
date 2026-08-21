"""Pure schedule calculation for the cron engine.

The engine owns task state, persistence, leases and execution.  This module
only translates a validated :class:`ScheduleConfig` into the next timestamp;
it has no database, asyncio or side-effect dependency and can therefore be
tested independently from the long-running scheduler.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from khaos.scheduler.models import ScheduledTask
from khaos.time_utils import utc_now_naive

_DEFAULT_INTERVAL = timedelta(hours=1)


class ScheduleCalculator:
    """Calculate next-run timestamps with conservative invalid-input handling."""

    @classmethod
    def compute(cls, task: ScheduledTask, *, now: datetime | None = None) -> datetime:
        """Return the next run for ``task`` without mutating it."""
        current = now or utc_now_naive()
        schedule = task.schedule
        if schedule.iso_time:
            try:
                return datetime.fromisoformat(schedule.iso_time)
            except (TypeError, ValueError):
                pass
        if schedule.interval_seconds:
            try:
                return current + timedelta(seconds=int(schedule.interval_seconds))
            except (TypeError, ValueError, OverflowError):
                pass
        if schedule.cron:
            return cls.parse_simple_cron(schedule.cron, current)
        return current + _DEFAULT_INTERVAL

    @staticmethod
    def parse_simple_cron(cron: str, now: datetime) -> datetime:
        """Parse the supported ``minute hour`` cron subset.

        Five-field expressions are accepted for compatibility, but only the
        first two fields are currently authoritative.  Unsupported or out of
        range values fail closed to the documented one-hour retry interval.
        """
        parts = str(cron).strip().split()
        if len(parts) < 2:
            return now + _DEFAULT_INTERVAL
        try:
            minute = int(parts[0])
            hour = int(parts[1])
            target = now.replace(
                minute=minute, hour=hour, second=0, microsecond=0
            )
        except (TypeError, ValueError, OverflowError):
            return now + _DEFAULT_INTERVAL
        if target <= now:
            target += timedelta(days=1)
        return target


__all__ = ["ScheduleCalculator"]
