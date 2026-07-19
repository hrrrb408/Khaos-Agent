"""Single-layer subagent spawner (Phase 8: batching + stats + nesting)."""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Optional

from khaos.exceptions import ServiceShutdownError, SubAgentLimitError, ToolNotFoundError

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
        # H1: once shutdown begins, every subsequent spawn is rejected so a
        # detached RPC caller cannot keep the spawner alive while the server
        # is tearing shared authorities (Office / Browser / Audit / DB) down.
        self._shutting_down: bool = False
        # M2: serialize spawn vs shutdown so a spawn that has passed its
        # _shutting_down check and is mid-DB-await cannot be missed by a
        # concurrent shutdown's _active_tasks snapshot (which would leave
        # the spawned task as an untracked orphan still borrowing shared
        # authorities).  Both operations hold this lock across the whole
        # critical section: spawn from its shutdown-check through inserting
        # the new task into _active_tasks; shutdown from flipping
        # _shutting_down through snapshotting _active_tasks.
        self._spawn_lock: asyncio.Lock = asyncio.Lock()

    @property
    def active_count(self) -> int:
        return len(self._active_tasks)

    def _ensure_task_id(self, task: SubAgentTask) -> None:
        """生成稳定的 task_id（UUID4 形式）当为空时。

        M3: 旧的 ``task_N`` 计数器在进程重启后会重置为 0，``ON CONFLICT(id)
        DO UPDATE`` 会覆盖旧任务记录（包括其他 principal 的历史）。  UUID4
        保证全局唯一性，跨重启不会冲突。
        """
        if not task.id:
            task.id = f"task_{uuid.uuid4().hex}"

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

        M2: the whole critical section (shutdown check → depth/concurrency
        validation → DB insert → ``_active_tasks`` registration) is wrapped
        in ``_spawn_lock`` so a concurrent ``shutdown()`` cannot snapshot
        ``_active_tasks`` between this spawn's check and registration.  That
        race used to leak an orphan task that borrowed shared authorities
        (Office / Browser / Audit / DB) without any shutdown authority over
        it.
        """
        async with self._spawn_lock:
            # H1: reject new work the moment shutdown begins.  A detached RPC
            # caller (one whose ``Spawn`` handler already returned) cannot
            # keep registering new background tasks while the server is
            # dismantling shared authorities.
            if self._shutting_down:
                raise SubAgentLimitError("subagent spawner is shutting down")
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

        M2: when ``principal_id`` is empty, returns an EMPTY stats dict
        (NOT all tasks).  The only caller that could pass empty principal
        is the Python service, which now rejects it up-front.  If someone
        bypasses the service and calls the spawner directly with empty
        principal, they get NOTHING, not everything.
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

        M2: when ``principal_id`` is empty, return an EMPTY list (NOT
        all tasks).  The previous "legacy path — return all" behavior
        was a fail-open security boundary: a caller bypassing the
        Python service with an empty principal could observe every
        principal's tasks.  The only caller that could pass empty
        principal is the Python service, and we just made it reject
        empty principal.  If someone bypasses the service and calls
        the spawner directly with empty principal, they get NOTHING.
        """
        if not principal_id:
            return []
        return [t for t in self._tasks.values() if t.principal_id == principal_id]

    async def wait_all(self, timeout: int = 600, principal_id: str = "") -> list[SubAgentTask]:
        """Wait for active tasks owned by ``principal_id`` (B1).

        M2: when ``principal_id`` is empty, returns an EMPTY list
        immediately (NOT all tasks).  See ``_tasks_for_principal`` for
        the rationale.
        """
        if not principal_id:
            return []
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

    async def shutdown(self, *, timeout: float = 30.0) -> None:
        """Production shutdown authority for the spawner.

        H1: ``SubAgentService.Spawn`` returns ``running`` while the Spawner
        runs the task on a detached background ``asyncio.Task``.  Without
        this method, server shutdown dismantled Office / Browser / Audit /
        DB while detached subagent runs were still in-flight — those runs
        borrow exactly those shared authorities.

        M2: the ``_shutting_down`` flip and ``_active_tasks`` snapshot are
        performed while holding ``_spawn_lock``, so a concurrent ``spawn()``
        cannot register a new task after the snapshot is taken (leaking an
        orphan) — spawn either sees ``_shutting_down=True`` and aborts, or
        its registration precedes the snapshot and is included.

        M1 (round-3): after the bounded wait, every snapshot task's DB row
        is reconciled to a terminal state.  A task that was cancelled
        BEFORE its coroutine got its first scheduling slot never enters
        ``_run_task``'s body, so its ``except CancelledError`` DB-write
        branch never runs — the row would stay ``running`` forever even
        though the asyncio Task is ``done``.  This pass walks the snapshot
        and explicitly persists ``failed/cancelled`` for any task whose
        ``SubAgentTask.status`` is still non-terminal, independent of the
        coroutine's own exception handling.

        M1 (round-2): the bounded wait uses ``asyncio.wait`` to obtain the
        pending set.  If any task is still pending when the deadline
        expires (e.g. a task that swallows ``CancelledError``), this
        method raises ``ServiceShutdownError`` rather than silently
        returning — the caller must NOT proceed to dismantle shared
        authorities that the residual task still borrows.  This is the
        fail-closed fix for the ``wait_for(gather)`` variant, which on
        timeout left the swallowing task running while teardown continued.
        """
        async with self._spawn_lock:
            self._shutting_down = True
            snapshot_ids = list(self._active_tasks.keys())
            snapshot = list(self._active_tasks.values())
        for task in snapshot:
            task.cancel()
        if not snapshot:
            return
        done, pending = await asyncio.wait(snapshot, timeout=timeout)
        # M1 (round-3): reconcile DB state for every snapshotted task.
        # ``_run_task``'s CancelledError branch only runs if the coroutine
        # got at least one scheduling slot; a task cancelled before its
        # first step never enters the body, so we must persist the
        # terminal transition here as the authoritative owner.
        await self._reconcile_terminal_states(snapshot_ids)
        if pending:
            unfinished = len(pending)
            logger.error(
                "subagent spawner shutdown: %d task(s) did not terminate "
                "within %.2fs (swallowed cancellation or wedged); refusing "
                "to release shared authority ownership",
                unfinished,
                timeout,
            )
            raise ServiceShutdownError(
                f"{unfinished} subagent task(s) did not terminate within "
                f"{timeout}s; shared authorities cannot be torn down safely"
            )

    async def _reconcile_terminal_states(self, task_ids: list[str]) -> None:
        """M1 (round-3): persist terminal DB state for every shutdown task.

        Walks the given task IDs and, for any whose ``SubAgentTask.status``
        is still non-terminal (``running`` / ``pending``), writes
        ``failed/cancelled`` to the DB and updates the in-memory object.

        This is the authoritative safety net for the cancel-before-first-
        run case where ``_run_task``'s own ``except CancelledError``
        branch never executes (Python does not enter a coroutine body
        that is cancelled before its first scheduling slot).  Without
        this pass, such a task's DB row would stay ``running`` forever
        even though the asyncio Task is ``done``.

        Failures are logged and swallowed — the shutdown path must not
        abort because of a single row's update failure, and the in-memory
        ``SubAgentTask.status`` is updated regardless so observers see
        the terminal transition.
        """
        TERMINAL = {"completed", "failed"}
        for task_id in task_ids:
            subtask = self._tasks.get(task_id)
            if subtask is None or subtask.status in TERMINAL:
                continue
            subtask.status = "failed"
            subtask.error = "cancelled"
            try:
                await self.db.update_subagent_task(
                    task_id, subtask.status, subtask.result, subtask.error,
                    finished=True,
                )
            except Exception:  # noqa: BLE001 — best-effort DB persist
                logger.error(
                    "subagent shutdown: could not persist terminal state "
                    "for task %s (in-memory status still updated)",
                    task_id,
                    exc_info=True,
                )


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
            # H1: a cancelled subagent (server shutdown / explicit cancel)
            # must leave an explicit terminal state.  Previously this branch
            # only re-raised, so the DB row stayed ``running`` forever even
            # though the runtime had been torn down.  Persist
            # ``failed/cancelled`` BEFORE re-raising so observers see the
            # terminal transition.
            #
            # The DB write itself may be cancelled (e.g. the server is
            # tearing the DB down concurrently); swallow only that failure
            # and surface the original cancellation, matching the
            # ``close_runtime_or_register`` pattern.
            task.status = "failed"
            task.error = "cancelled"
            current = asyncio.current_task()
            if current is not None and hasattr(current, "uncancel"):
                current.uncancel()
            try:
                await self.db.update_subagent_task(
                    task.id, task.status, task.result, task.error, finished=True
                )
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                logger.error(
                    "subagent task %s cancelled but could not persist terminal state",
                    task.id,
                    exc_info=True,
                )
            raise
        except Exception as exc:
            task.status = "failed"
            task.error = str(exc)
            await self.db.update_subagent_task(task.id, task.status, task.result, task.error, finished=True)

    async def _default_runner(self, task: SubAgentTask) -> str:
        await asyncio.sleep(0)
        return f"completed: {task.goal}"
