"""Cron scheduler engine.

轻量级实现，不依赖外部库（如 APScheduler）。用 asyncio 后台循环检查 next_run。
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import datetime, timedelta
from typing import Any, Awaitable, Callable, Optional

from khaos.exceptions import ServiceShutdownError
from khaos.scheduler.models import ScheduleConfig, ScheduledTask, TaskStatus

logger = logging.getLogger(__name__)


# H1 (round-6): total deadline for ``stop()`` to drain in-flight
# ``_execute_task`` coroutines.  An executor that swallows
# ``CancelledError`` (e.g. an AgentService.chat that catches it for
# permission-ledger cleanup) used to make ``asyncio.gather`` hang
# forever — blocking ``AgentService.stop_producers`` and preventing the
# bounded ``CHAT_DRAIN_TIMEOUT`` from ever starting.  This ceiling
# converts that hang into a fail-closed ``ServiceShutdownError``.
CRON_STOP_DRAIN_TIMEOUT = 30.0


class CronEngine:
    """异步定时任务调度引擎。"""

    def __init__(
        self,
        db=None,
        executor: Callable[[str, str], Awaitable[Any]] | None = None,
        on_complete: Callable[[ScheduledTask, Any], Awaitable[None]] | None = None,
        tick_interval: float = 30.0,  # 每 30 秒检查一次
    ):
        """
        参数：
        - db: Database 实例（持久化任务）
        - executor: 实际执行函数，接收 (task_id, prompt)，返回结果
        - on_complete: 任务完成后的回调（推送结果等）
        - tick_interval: 检查间隔（秒）
        """
        self.db = db
        self._executor = executor
        self._on_complete = on_complete
        self._tick_interval = tick_interval
        self._tasks: dict[str, ScheduledTask] = {}
        self._running = False
        self._loop_task: asyncio.Task | None = None
        # M4 (round-5): track in-flight ``_execute_task`` coroutines so
        # ``stop()`` can cancel + await them.  Previously ``_tick_loop``
        # fired ``asyncio.create_task(self._execute_task(task))`` without
        # keeping a reference, so a task that just started (but hadn't
        # entered ``AgentService.chat()`` yet) escaped the engine's
        # shutdown and could run after the DB / shared authorities were
        # torn down.
        self._execute_tasks: set[asyncio.Task] = set()
        # H2 (round-7): terminal-state persistence state machine.
        # Tracks task_ids whose terminal state was set in memory but
        # NOT yet persisted to the DB.  ``stop()`` retries these on
        # every call until the UPDATE succeeds; if the DB is wedged,
        # ``stop()`` raises ``ServiceShutdownError`` so the caller
        # refuses to tear down the DB while a row is still stale.
        # Without this, a cancelled task whose terminal UPDATE failed
        # would stay at ``running`` in the DB — and on restart the
        # scheduler would re-fire it, potentially double-executing
        # external side effects.
        self._pending_persistence: set[str] = set()

    async def start(self) -> None:
        """启动调度循环。"""
        if self._running:
            return
        self._running = True
        await self._load_tasks()
        self._loop_task = asyncio.create_task(self._tick_loop())
        logger.info("cron engine started with %d tasks", len(self._tasks))

    async def stop(self, *, timeout: float = CRON_STOP_DRAIN_TIMEOUT) -> None:
        """停止调度循环。

        M4 (round-5): cancel and await every in-flight ``_execute_task``
        coroutine so they don't outlive the engine.  An ``_execute_task``
        calls ``self._executor(...)`` which (in production) is
        ``AgentService._execute_scheduled_prompt`` → ``AgentService.chat``.
        If the engine stops while such a task is running, it must be
        cancelled + drained BEFORE the engine's callers tear down the DB
        and shared authorities — otherwise the task accesses a closed DB.

        H1 (round-6): the drain is now bounded by a total deadline.
        The round-5 implementation used
        ``asyncio.gather(..., return_exceptions=True)`` with no timeout,
        so an executor that swallows ``CancelledError`` (e.g. a chat
        turn that catches it for permission-ledger cleanup) made
        ``stop()`` hang forever — ``AgentService.stop_producers`` would
        never return and the bounded ``CHAT_DRAIN_TIMEOUT`` would never
        start.  We now use ``asyncio.wait(timeout=...)`` and raise
        ``ServiceShutdownError`` if any task is still pending at the
        deadline, WITHOUT clearing ``_execute_tasks`` so the caller
        retains ownership of the still-live tasks.

        H2 (round-7): after the drain, retry any task whose terminal
        state was set in memory but NOT yet persisted to the DB
        (tracked in ``_pending_persistence``).  If the DB write fails,
        raise ``ServiceShutdownError`` so the caller refuses to tear
        down the DB while a row is still stale — without this, a
        cancelled task whose terminal UPDATE failed would stay at
        ``running`` in the DB, and on restart the scheduler would
        re-fire it, potentially double-executing external side effects.
        The retry uses the SAME total deadline (the drain and the
        reconcile share one budget).
        """
        import time
        deadline = time.monotonic() + timeout
        self._running = False
        if self._loop_task:
            self._loop_task.cancel()
            try:
                await self._loop_task
            except asyncio.CancelledError:
                pass
            self._loop_task = None
        # H1 (round-6): bounded drain.  Snapshot the in-flight tasks,
        # cancel them, then ``asyncio.wait`` with the total deadline.
        # If any task is still pending at the deadline, raise
        # ``ServiceShutdownError`` and DO NOT clear ``_execute_tasks``
        # — the caller must retain ownership of the still-live tasks
        # so they are not silently orphaned (the next owner / process
        # exit will reap them).
        if self._execute_tasks:
            snapshot = [t for t in self._execute_tasks if not t.done()]
            for t in snapshot:
                t.cancel()
            if snapshot:
                remaining = max(deadline - time.monotonic(), 0.0)
                done, pending = await asyncio.wait(
                    snapshot, timeout=remaining,
                )
                if pending:
                    # Leave ``_execute_tasks`` intact — the pending
                    # tasks are still borrowing shared authorities and
                    # must not be silently released.  The caller
                    # (AgentService.stop_producers → shutdown) raises
                    # ``ServiceShutdownError`` and refuses to tear down
                    # the DB / shared authorities.
                    logger.error(
                        "cron engine stop: %d execute_task(s) did not "
                        "terminate within %.2fs (swallowed cancellation "
                        "or wedged); refusing to release task ownership",
                        len(pending), remaining,
                    )
                    raise ServiceShutdownError(
                        f"{len(pending)} cron execute_task(s) did not "
                        f"terminate within {remaining:.2f}s; shared "
                        "authorities cannot be torn down safely"
                    )
            # All tasks drained — safe to clear the registry.
            self._execute_tasks.clear()
        # H2 (round-7): retry any task whose terminal state was set in
        # memory but NOT yet persisted.  ``_execute_task``'s
        # ``_persist_task_state`` may have failed (e.g. the DB was
        # momentarily wedged) and left the task_id in
        # ``_pending_persistence``.  Without this retry, the DB row
        # would stay stale and the task would be re-fired on restart.
        # Bounded by the remaining total deadline.
        if self._pending_persistence and self.db:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ServiceShutdownError(
                    f"no budget remaining for terminal state reconciliation; "
                    f"{len(self._pending_persistence)} cron task(s) "
                    "still pending persistence"
                )
            # Run the reconcile in its own owner task so we can bound
            # it with ``asyncio.wait`` (NOT ``wait_for`` — see the
            # spawner's M2 round-6 fix for the cancellation-resistant
            # rationale).
            reconcile_task = asyncio.create_task(
                self._reconcile_pending_persistence()
            )
            done_rec, pending_rec = await asyncio.wait(
                {reconcile_task}, timeout=remaining,
            )
            if pending_rec:
                logger.error(
                    "cron engine stop: terminal state reconciliation "
                    "did not complete within %.2fs budget; %d task(s) "
                    "still pending persistence",
                    remaining, len(self._pending_persistence),
                )
                raise ServiceShutdownError(
                    f"cron terminal state reconciliation did not complete "
                    f"within {remaining:.2f}s; "
                    f"{len(self._pending_persistence)} task(s) still pending"
                )
            exc = reconcile_task.exception()
            if exc is not None:
                raise exc
        logger.info("cron engine stopped")

    async def _reconcile_pending_persistence(self) -> None:
        """Retry terminal-state persistence for every task in
        ``_pending_persistence``.

        H2 (round-7): called by ``stop()`` after the execute_task drain.
        If ANY DB write fails, the task stays in ``_pending_persistence``
        and we raise ``ServiceShutdownError`` so the caller refuses to
        tear down the DB.  The next ``stop()`` call will retry.
        """
        if not self.db:
            return
        failures: list[str] = []
        for task_id in list(self._pending_persistence):
            task = self._tasks.get(task_id)
            if task is None:
                # Task not in memory — clear the flag (can't retry
                # without the in-memory state).
                self._pending_persistence.discard(task_id)
                continue
            try:
                await self._persist_task_state(task)
            except Exception:  # noqa: BLE001 — collect and raise
                logger.error(
                    "cron engine: could not persist terminal state for "
                    "task %s — durability gap, refusing to continue "
                    "teardown",
                    task_id, exc_info=True,
                )
                failures.append(task_id)
        if failures:
            raise ServiceShutdownError(
                f"could not persist terminal state for {len(failures)} "
                f"cron task(s): {failures}; DB may be closed under live rows"
            )

    async def create(
        self,
        name: str,
        prompt: str,
        schedule: ScheduleConfig,
        deliver_to: str = "local",
        meta: dict | None = None,
    ) -> ScheduledTask:
        """创建并注册一个新任务。"""
        task = ScheduledTask(
            id=None,
            name=name,
            prompt=prompt,
            schedule=schedule,
            deliver_to=deliver_to,
            meta=meta or {},
        )
        task.next_run = self._compute_next_run(task)
        if self.db:
            task.id = await self.db.insert_scheduled_task(
                name, prompt, task.status.value, schedule,
                deliver_to, meta,
            )
        else:
            task.id = f"task_{len(self._tasks)}"
        self._tasks[task.id] = task
        logger.info("scheduled task created: %s (%s)", name, task.id)
        return task

    async def pause(self, task_id: str) -> bool:
        task = self._tasks.get(task_id)
        if not task:
            return False
        task.status = TaskStatus.PAUSED
        if self.db:
            await self.db.update_scheduled_task_status(task_id, TaskStatus.PAUSED.value)
        return True

    async def resume(self, task_id: str) -> bool:
        task = self._tasks.get(task_id)
        if not task:
            return False
        task.status = TaskStatus.PENDING
        task.next_run = self._compute_next_run(task)
        if self.db:
            await self.db.update_scheduled_task_status(task_id, TaskStatus.PENDING.value)
        return True

    async def remove(self, task_id: str) -> bool:
        task = self._tasks.pop(task_id, None)
        if not task:
            return False
        task.status = TaskStatus.CANCELLED
        if self.db:
            await self.db.update_scheduled_task_status(task_id, TaskStatus.CANCELLED.value)
        return True

    async def list_tasks(self) -> list[ScheduledTask]:
        return list(self._tasks.values())

    async def get(self, task_id: str) -> ScheduledTask | None:
        return self._tasks.get(task_id)

    def _compute_next_run(self, task: ScheduledTask) -> datetime:
        """根据 ScheduleConfig 计算下次执行时间。

        简化实现：
        - iso_time: 直接返回（一次性）
        - interval_seconds: now + interval
        - cron: 简单解析分时日（仅支持基本格式，不支持高级 cron 语法）
        """
        now = datetime.utcnow()
        if task.schedule.iso_time:
            try:
                return datetime.fromisoformat(task.schedule.iso_time)
            except ValueError:
                pass
        if task.schedule.interval_seconds:
            return now + timedelta(seconds=task.schedule.interval_seconds)
        # 简单 cron 解析：仅支持 "分 时" 格式，如 "0 9" = 每天 9:00
        if task.schedule.cron:
            return self._parse_simple_cron(task.schedule.cron, now)
        return now + timedelta(hours=1)  # 默认每小时

    def _parse_simple_cron(self, cron: str, now: datetime) -> datetime:
        """解析简化的 cron 表达式。

        支持格式：
        - "分钟 小时"（如 "0 9" = 每天 9:00）
        - "分钟 小时 日 月 星期"（完整 cron，简化解析）
        """
        parts = cron.strip().split()
        if len(parts) < 2:
            return now + timedelta(hours=1)
        try:
            minute = int(parts[0])
            hour = int(parts[1])
        except ValueError:
            return now + timedelta(hours=1)
        # 计算今天的下一个目标时间
        target = now.replace(minute=minute, hour=hour, second=0, microsecond=0)
        if target <= now:
            target += timedelta(days=1)
        return target

    async def _tick_loop(self) -> None:
        """后台循环，检查到期的任务。"""
        while self._running:
            now = datetime.utcnow()
            due_tasks = [
                task for task in self._tasks.values()
                if task.enabled
                and task.status == TaskStatus.PENDING
                and task.next_run
                and task.next_run <= now
            ]
            for task in due_tasks:
                # M4 (round-5): track the execution task so ``stop()``
                # can cancel + await it.  Discard on completion so the
                # set doesn't grow without bound.
                exec_task = asyncio.create_task(self._execute_task(task))
                self._execute_tasks.add(exec_task)
                exec_task.add_done_callback(self._execute_tasks.discard)
            await asyncio.sleep(self._tick_interval)

    async def _execute_task(self, task: ScheduledTask) -> None:
        """执行单个任务。

        M3 (round-6): ``CancelledError`` is now caught explicitly so a
        shutdown-time cancellation persists a ``cancelled`` terminal
        state to the DB instead of leaving the row at ``running``.
        Previously the ``except Exception`` branch did NOT catch
        ``CancelledError`` (it inherits from ``BaseException`` in
        Python 3.8+), so the cancellation bypassed both the error
        branch and the DB update — leaving the in-memory task at
        ``RUNNING`` and the DB row stale.  On restart the scheduler
        would re-fire the task, potentially double-executing any
        external side effects.
        """
        task.status = TaskStatus.RUNNING
        task.last_run = datetime.utcnow()
        try:
            if self._executor:
                result = await self._executor(task.id, task.prompt)
            else:
                result = f"[no executor] prompt: {task.prompt[:100]}"
            task.last_result = str(result)[:2000] if result else ""
            task.run_count += 1

            # 检查是否是一次性任务或达到重复上限
            if task.schedule.iso_time:
                task.status = TaskStatus.COMPLETED
            elif task.schedule.repeat and task.run_count >= task.schedule.repeat:
                task.status = TaskStatus.COMPLETED
            else:
                task.status = TaskStatus.PENDING
                task.next_run = self._compute_next_run(task)

            if self._on_complete:
                await self._on_complete(task, result)

            logger.info("task %s executed successfully (run #%d)", task.name, task.run_count)
        except asyncio.CancelledError:
            # M3 (round-6): persist a cancelled terminal state before
            # re-raising so the DB row does not stay ``running`` and
            # the task is not re-scheduled on restart.
            # H2 (round-7): if the DB write fails, swallow the
            # secondary exception so the ``raise`` still fires — the
            # task stays in ``_pending_persistence`` for ``stop()`` to
            # retry.  Without this, a DB failure here would propagate
            # out of ``_persist_task_state`` and mask the
            # ``CancelledError``, leaving the caller (``stop()``'s
            # drain) without the cancellation signal.
            task.status = TaskStatus.CANCELLED
            task.error = "cancelled"
            logger.info("task %s cancelled during execution", task.name)
            try:
                await self._persist_task_state(task)
            except Exception:  # noqa: BLE001 — stop() will retry
                logger.error(
                    "cron task %s: could not persist cancelled terminal "
                    "state; will retry on stop()", task.name, exc_info=True,
                )
            raise
        except Exception as exc:
            task.status = TaskStatus.FAILED
            task.error = str(exc)
            logger.error("task %s failed: %s", task.name, exc)

        # H2 (round-7): the success / failure path's persist may also
        # fail; swallow it so the _execute_task coroutine terminates
        # cleanly.  ``stop()`` will retry the persist via its reconcile
        # pass (``_pending_persistence`` retains the task_id).
        try:
            await self._persist_task_state(task)
        except Exception:  # noqa: BLE001 — stop() will retry
            logger.error(
                "cron task %s: could not persist terminal state %s; "
                "will retry on stop()",
                task.name, task.status.value, exc_info=True,
            )

    async def _persist_task_state(self, task: ScheduledTask) -> None:
        """Persist the current task state to the DB.

        M3 (round-6): extracted so both the success / failure path and
        the ``CancelledError`` path share the same durable write.

        H2 (round-7): state-machine tracking.  The task is added to
        ``_pending_persistence`` BEFORE the DB write and only removed
        after a successful UPDATE.  If the write raises, the task stays
        in the set so ``stop()`` can retry it on the next call.
        Previously failures were logged but swallowed — so a cancelled
        task whose terminal UPDATE failed would stay at ``running`` in
        the DB, and on restart the scheduler would re-fire it,
        potentially double-executing external side effects.
        """
        if not self.db:
            return
        # H2 (round-7): mark pending BEFORE the write.  Idempotent if
        # the task is already in the set (e.g. a previous write failed
        # and stop() is retrying).
        self._pending_persistence.add(task.id)
        await self.db.update_scheduled_task(
            task.id,
            status=task.status.value,
            last_run=task.last_run.isoformat() if task.last_run else None,
            next_run=task.next_run.isoformat() if task.next_run else None,
            run_count=task.run_count,
            last_result=task.last_result,
            error=task.error,
        )
        # Only clear after a successful persist.  If the await above
        # raised, the flag stays set and ``stop()`` retries.
        self._pending_persistence.discard(task.id)

    async def _load_tasks(self) -> None:
        """从 DB 加载已持久化的任务。"""
        if not self.db:
            return
        try:
            rows = await self.db.list_scheduled_tasks()
        except Exception as exc:  # noqa: BLE001 — load must not crash start()
            logger.warning("failed to load scheduled tasks: %s", exc)
            return
        for row in rows:
            task = _task_from_row(row)
            if task is not None:
                self._tasks[task.id] = task


def _task_from_row(row: dict) -> ScheduledTask | None:
    """Reconstruct a ScheduledTask from a DB row dict."""
    task_id = row.get("id")
    if task_id is None:
        return None
    schedule_raw = row.get("schedule_config") or "{}"
    try:
        schedule_data = json.loads(schedule_raw) if isinstance(schedule_raw, str) else schedule_raw
    except (json.JSONDecodeError, TypeError):
        schedule_data = {}
    meta_raw = row.get("meta") or "{}"
    try:
        meta = json.loads(meta_raw) if isinstance(meta_raw, str) else meta_raw
    except (json.JSONDecodeError, TypeError):
        meta = {}
    schedule = ScheduleConfig(
        cron=schedule_data.get("cron"),
        iso_time=schedule_data.get("iso_time"),
        interval_seconds=schedule_data.get("interval_seconds"),
        repeat=schedule_data.get("repeat"),
    )
    try:
        status = TaskStatus(row.get("status", "pending"))
    except ValueError:
        status = TaskStatus.PENDING
    return ScheduledTask(
        id=str(task_id),
        name=str(row.get("name", "")),
        prompt=str(row.get("prompt", "")),
        status=status,
        schedule=schedule,
        deliver_to=str(row.get("deliver_to", "local")),
        meta=meta if isinstance(meta, dict) else {},
        run_count=int(row.get("run_count", 0) or 0),
        last_result=row.get("last_result"),
        error=row.get("error"),
        last_run=_parse_dt(row.get("last_run")),
        next_run=_parse_dt(row.get("next_run")),
    )


def _parse_dt(value) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value))
    except (ValueError, TypeError):
        return None
