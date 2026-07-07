"""Single-layer subagent spawner."""

from __future__ import annotations

import asyncio
import json
import uuid
from dataclasses import dataclass
from typing import Awaitable, Callable, Optional

from khaos.exceptions import SubAgentLimitError


@dataclass
class SubAgentConfig:
    """Subagent concurrency and nesting limits."""

    max_concurrent: int = 3
    max_spawn_depth: int = 1


@dataclass
class SubAgentTask:
    """One subagent task."""

    id: str
    goal: str
    context: str
    tools: list[str]
    timeout: int = 300
    status: str = "pending"
    result: Optional[str] = None
    error: Optional[str] = None
    parent_session_id: str = "root"
    depth: int = 1


Runner = Callable[[SubAgentTask], Awaitable[str]]


class SubAgentSpawner:
    """Spawn and manage non-nesting subagents."""

    def __init__(self, config: SubAgentConfig, db, runner: Runner | None = None):
        self.config = config
        self.db = db
        self.runner = runner or self._default_runner
        self._active_tasks: dict[str, asyncio.Task] = {}
        self._tasks: dict[str, SubAgentTask] = {}

    @property
    def active_count(self) -> int:
        return len(self._active_tasks)

    async def spawn(self, task: SubAgentTask) -> SubAgentTask:
        """Start a single-layer subagent task."""
        if task.depth > self.config.max_spawn_depth:
            raise SubAgentLimitError("subagents cannot spawn nested subagents")
        if self.active_count >= self.config.max_concurrent:
            raise SubAgentLimitError(f"并发数已达上限 ({self.config.max_concurrent})")
        if not task.id:
            task.id = str(uuid.uuid4())
        task.status = "running"
        self._tasks[task.id] = task
        await self.db.create_session(task.parent_session_id)
        await self.db.insert_subagent_task(
            task.id,
            task.parent_session_id,
            task.goal,
            task.context,
            json.dumps(task.tools),
            task.status,
        )
        async_task = asyncio.create_task(self._run_task(task))
        self._active_tasks[task.id] = async_task
        async_task.add_done_callback(lambda _: self._active_tasks.pop(task.id, None))
        return task

    async def wait_all(self, timeout: int = 600) -> list[SubAgentTask]:
        """Wait for all active tasks."""
        if self._active_tasks:
            await asyncio.wait_for(asyncio.gather(*self._active_tasks.values()), timeout=timeout)
        return list(self._tasks.values())

    async def cancel(self, task_id: str) -> None:
        """Cancel one active task."""
        task = self._active_tasks.get(task_id)
        if task is not None:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                task.cancelled()
        subtask = self._tasks[task_id]
        subtask.status = "failed"
        subtask.error = "cancelled"
        await self.db.update_subagent_task(task_id, "failed", subtask.result, subtask.error, finished=True)

    async def collect_results(self) -> list[str]:
        """Collect completed task results."""
        return [task.result or "" for task in self._tasks.values() if task.status == "completed"]

    async def _run_task(self, task: SubAgentTask) -> None:
        try:
            task.result = await asyncio.wait_for(self.runner(task), timeout=task.timeout)
            task.status = "completed"
            await self.db.update_subagent_task(task.id, task.status, task.result, None, finished=True)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            task.status = "failed"
            task.error = str(exc)
            await self.db.update_subagent_task(task.id, task.status, task.result, task.error, finished=True)

    async def _default_runner(self, task: SubAgentTask) -> str:
        await asyncio.sleep(0)
        return f"completed: {task.goal}"
