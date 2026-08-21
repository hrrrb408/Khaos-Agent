"""Pure due-task selection for the cron tick."""

from __future__ import annotations

from collections.abc import Collection, Iterable
from datetime import datetime

from khaos.scheduler.models import ScheduledTask, TaskStatus


class DueTaskSelector:
    """Select executable tasks without changing scheduler state."""

    @staticmethod
    def select(
        tasks: Iterable[ScheduledTask],
        *,
        now: datetime,
        pending_persistence_ids: Collection[str],
        executing_ids: Collection[str] = (),
    ) -> tuple[ScheduledTask, ...]:
        """Return due, enabled pending tasks not fenced by another owner."""
        return tuple(
            task
            for task in tasks
            if task.id is not None
            and task.enabled
            and task.status == TaskStatus.PENDING
            and task.next_run is not None
            and task.next_run <= now
            and task.id not in pending_persistence_ids
            and task.id not in executing_ids
        )


__all__ = ["DueTaskSelector"]
