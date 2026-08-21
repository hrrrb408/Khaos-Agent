"""Contract tests for scheduler persistence and due-selection boundaries."""

from __future__ import annotations

from datetime import datetime, timedelta
from unittest.mock import AsyncMock

import pytest

from khaos.scheduler.due_selector import DueTaskSelector
from khaos.scheduler.models import ScheduleConfig, ScheduledTask, TaskStatus
from khaos.scheduler.repository import ScheduledTaskRepository


def _task(
    task_id: str,
    *,
    status: TaskStatus = TaskStatus.PENDING,
    next_run: datetime | None = None,
    enabled: bool = True,
) -> ScheduledTask:
    return ScheduledTask(
        id=task_id,
        name=task_id,
        prompt="run",
        status=status,
        schedule=ScheduleConfig(interval_seconds=60),
        next_run=next_run,
        enabled=enabled,
    )


def test_due_selector_applies_all_tick_gates_without_mutating_tasks() -> None:
    now = datetime.fromisoformat("2026-08-22T10:00:00")
    tasks = (
        _task("due", next_run=now - timedelta(seconds=1)),
        _task("future", next_run=now + timedelta(seconds=1)),
        _task("paused", status=TaskStatus.PAUSED, next_run=now),
        _task("disabled", next_run=now, enabled=False),
        _task("pending-marker", next_run=now),
        _task("already-running", next_run=now),
    )

    selected = DueTaskSelector.select(
        tasks,
        now=now,
        pending_persistence_ids={"pending-marker"},
        executing_ids={"already-running"},
    )

    assert selected == (tasks[0],)
    assert tasks[2].status == TaskStatus.PAUSED
    assert tasks[0].next_run == now - timedelta(seconds=1)


@pytest.mark.asyncio
async def test_scheduled_task_repository_keeps_project_scope_at_the_boundary() -> None:
    database = AsyncMock()
    database.list_scheduled_tasks.return_value = [{"id": "task-1"}]
    database.get_scheduled_task.return_value = {"id": "task-1"}
    repository = ScheduledTaskRepository(database, project_id="project-1")

    assert await repository.list_tasks() == [{"id": "task-1"}]
    assert await repository.get_task("task-1") == {"id": "task-1"}
    database.list_scheduled_tasks.assert_awaited_once_with(project_id="project-1")
    database.get_scheduled_task.assert_awaited_once_with(
        "task-1", project_id="project-1"
    )
