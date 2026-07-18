"""Single-layer subagent spawner (Phase 8: batching + stats + nesting)."""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Optional

from khaos.exceptions import SubAgentLimitError, ToolNotFoundError

logger = logging.getLogger(__name__)


@dataclass
class SubAgentConfig:
    """Subagent concurrency and nesting limits."""

    max_concurrent: int = 3
    max_spawn_depth: int = 2
    allow_nesting: bool = False


@dataclass
class SubAgentTask:
    """One subagent task.

    B1: ``principal_id`` binds the task to the authenticated caller so
    ``collect`` / ``status`` only return the caller's own tasks — a
    different principal cannot observe another's goal / result / error.
    """

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
    # B1: the principal that owns this task.  Set by the service from
    # the authenticated RPC payload; used by ``wait_all`` / ``stats`` /
    # ``collect_results`` to filter results.
    principal_id: str = ""


Runner = Callable[[SubAgentTask], Awaitable[str]]


class SubAgentSpawner:
    """Spawn and manage subagents.

    Phase 8 enhancements:
    - ``registry`` 可选参数：传入后 spawn 会校验 task.tools 中的工具是否已注册。
    - ``spawn_batch``：批量 spawn，超过并发上限的跳过（不抛异常）。
    - ``stats``：返回 active/total/completed/failed/pending 统计。
    - 嵌套深度由 ``SubAgentConfig.max_spawn_depth`` 控制（Phase 8 默认提升到 2）。
    """

    def __init__(
        self,
        config: SubAgentConfig,
        db,
        runner: Runner | None = None,
        registry=None,  # ToolRegistry，可选
    ):
        self.config = config
        self.db = db
        self.runner = runner or self._default_runner
        self.registry = registry
        self._active_tasks: dict[str, asyncio.Task] = {}
        self._tasks: dict[str, SubAgentTask] = {}
        self._spawn_counter: int = 0

    @property
    def active_count(self) -> int:
        return len(self._active_tasks)

    def _ensure_task_id(self, task: SubAgentTask) -> None:
        """生成稳定的 task_id（task_N 形式）当为空时。"""
        if not task.id:
            self._spawn_counter += 1
            task.id = f"task_{self._spawn_counter}"

    def _validate_tools(self, task: SubAgentTask) -> None:
        """校验 task.tools 中的工具是否已注册（需要传入 registry）。"""
        if self.registry is None:
            return
        for name in task.tools:
            try:
                self.registry.get(name)
            except ToolNotFoundError as exc:
                raise SubAgentLimitError(
                    f"task {task.id} 引用了未注册的工具: {name}"
                ) from exc

    async def spawn(self, task: SubAgentTask) -> SubAgentTask:
        """Start a single subagent task.

        嵌套规则：
        - ``allow_nesting=False``（默认）：只允许 ``depth == 1``，任何 ``depth > 1``
          都被拒绝（沿用 ADR-002 的单层语义）。
        - ``allow_nesting=True``：允许嵌套，但仍受 ``max_spawn_depth`` 上限约束。
        """
        if task.depth > 1 and not self.config.allow_nesting:
            raise SubAgentLimitError(
                f"subagents cannot spawn nested subagents "
                f"(depth={task.depth}, nesting disabled)"
            )
        if task.depth > self.config.max_spawn_depth:
            raise SubAgentLimitError(
                f"subagent nesting exceeds configured depth "
                f"(depth={task.depth} > max={self.config.max_spawn_depth})"
            )
        if self.active_count >= self.config.max_concurrent:
            raise SubAgentLimitError(f"并发数已达上限 ({self.config.max_concurrent})")
        self._ensure_task_id(task)
        self._validate_tools(task)
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
            # B1: persist the principal so list_subagent_tasks(principal_id)
            # can filter rows on disk, not just in-memory.
            task.principal_id,
        )
        async_task = asyncio.create_task(self._run_task(task))
        self._active_tasks[task.id] = async_task
        async_task.add_done_callback(lambda _: self._active_tasks.pop(task.id, None))
        return task

    async def spawn_batch(self, tasks: list[SubAgentTask]) -> list[SubAgentTask]:
        """批量 spawn 多个子任务。

        逻辑：
        1. 检查批量数量不超过 max_concurrent（连同当前已 active 的）
        2. 依次 spawn 每个任务
        3. 如果某个 spawn 失败（并发超限 / 工具未注册 / 深度超限），
           跳过并记录错误，不中断其余任务
        4. 返回所有成功 spawn 的任务
        """
        spawned: list[SubAgentTask] = []
        available = self.config.max_concurrent - self.active_count
        if available <= 0:
            logger.warning(
                "spawn_batch skipped all %d tasks: concurrency full (%d/%d)",
                len(tasks),
                self.active_count,
                self.config.max_concurrent,
            )
            return spawned
        for task in tasks:
            if len(spawned) >= available:
                logger.warning(
                    "spawn_batch reached concurrency limit, skipping remaining %d tasks",
                    len(tasks) - len(spawned),
                )
                break
            try:
                await self.spawn(task)
                spawned.append(task)
            except SubAgentLimitError as exc:
                logger.warning("spawn_batch skipped task: %s", exc)
            except ToolNotFoundError as exc:
                logger.warning("spawn_batch skipped task due to unknown tool: %s", exc)
        return spawned

    def stats(self, principal_id: str = "") -> dict[str, int]:
        """返回当前统计：active/total/completed/failed/pending。

        B1: when ``principal_id`` is set, only tasks owned by that
        principal are counted — a different principal cannot observe
        another's task counts.
        """
        tasks = self._tasks_for_principal(principal_id)
        completed = sum(1 for t in tasks if t.status == "completed")
        failed = sum(1 for t in tasks if t.status == "failed")
        pending = sum(1 for t in tasks if t.status == "pending")
        active = sum(
            1 for t in tasks if t.id in self._active_tasks
        )
        return {
            "active": active,
            "total": len(tasks),
            "completed": completed,
            "failed": failed,
            "pending": pending,
        }

    def _tasks_for_principal(self, principal_id: str) -> list[SubAgentTask]:
        """B1: return tasks owned by ``principal_id``.

        When ``principal_id`` is empty (legacy / test callers), return
        ALL tasks — this preserves backward compatibility for callers
        that haven't been updated.  Production callers always pass a
        non-empty principal_id.
        """
        if not principal_id:
            return list(self._tasks.values())
        return [t for t in self._tasks.values() if t.principal_id == principal_id]

    async def wait_all(self, timeout: int = 600, principal_id: str = "") -> list[SubAgentTask]:
        """Wait for active tasks owned by ``principal_id`` (B1).

        When ``principal_id`` is empty, waits for ALL tasks (legacy
        behavior).  Production callers always pass a non-empty principal.
        """
        if not principal_id:
            # Legacy path — wait for all active tasks.
            if self._active_tasks:
                await asyncio.wait_for(asyncio.gather(*self._active_tasks.values()), timeout=timeout)
            return list(self._tasks.values())
        # B1: only wait for tasks owned by this principal.
        owned_active = {
            tid: task for tid, task in self._active_tasks.items()
            if tid in self._tasks and self._tasks[tid].principal_id == principal_id
        }
        if owned_active:
            await asyncio.wait_for(asyncio.gather(*owned_active.values()), timeout=timeout)
        return self._tasks_for_principal(principal_id)

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

    async def collect_results(self, principal_id: str = "") -> list[str]:
        """Collect completed task results (B1: filtered by principal)."""
        tasks = self._tasks_for_principal(principal_id)
        return [task.result or "" for task in tasks if task.status == "completed"]

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
