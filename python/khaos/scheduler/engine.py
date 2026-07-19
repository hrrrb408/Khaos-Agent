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

# M1 (round-8): per-task cancel budget for ``pause()`` / ``remove()``
# when they cancel an in-flight ``_execute_task``.  Bounded so a
# cancellation-resistant executor cannot wedge user-facing RPCs.  If
# the executor does not terminate, the wedged task stays in
# ``_execute_tasks`` for ``stop()`` to handle (it will raise
# ``ServiceShutdownError`` on the next shutdown).
_CANCEL_IN_FLIGHT_TIMEOUT = 10.0


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
        # M1 (round-8): keyed by task_id so ``pause()`` / ``remove()``
        # can find and cancel the in-flight execution for a specific
        # task.  Previously this was a ``set[asyncio.Task]`` with no
        # task_id mapping, so pause/remove could not stop a running
        # execution — the executor kept running, completed, and
        # overwrote the paused/cancelled DB row with completed/pending.
        self._execute_tasks: dict[str, asyncio.Task] = {}
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
        # H1 (round-8): retained reconcile owner registry.  Keyed by
        # task_id so the next ``stop()`` can dedupe — if a retained
        # owner is already reconciling task T, we MUST NOT spawn a
        # second reconcile for T (that would race with the retained
        # one and could double-write).  Multiple task_ids may share
        # one owner (one reconcile pass covers a batch); each task_id
        # maps to the single owner task that is currently reconciling
        # it.  The done callback only READS the exception (to suppress
        # the asyncio "never retrieved" warning); removal is the next
        # ``stop()``'s job, AFTER it has explicitly read the exception.
        self._persistence_owners: dict[str, asyncio.Task] = {}

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

        H1 (round-8): BEFORE spawning a new reconcile, re-drain any
        retained owners from a previous shutdown.  The round-7
        implementation created a fresh reconcile task on every
        ``stop()`` call without checking for retained owners — so a
        retained owner from ``stop()`` #1 was never awaited by
        ``stop()`` #2, which could spawn a SECOND reconcile for the
        same task_ids (racing with the retained one) and then return
        success while the retained owner was still holding the DB.
        Now:
          1. Snapshot ALL existing ``_persistence_owners`` (BOTH done
             AND pending).  Done owners are included so their
             exceptions get explicitly read.
          2. Any still-pending owner → raise ``ServiceShutdownError``
             and keep the registry intact (do NOT clear it).  We MUST
             NOT spawn a new reconcile for the same task_id while a
             retained owner is still working on it (that would race).
          3. Any done owner → read its exception (log it for
             observability), remove the entry, and let the fresh
             reconcile below retry the persist.  We do NOT raise on
             the old exception — the H2 contract requires ``stop()``
             to RETRY on the next call.
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
            snapshot = [
                t for t in self._execute_tasks.values() if not t.done()
            ]
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
        # H1 (round-8): re-drain retained reconcile owners BEFORE
        # spawning a new reconcile.  See the method docstring for the
        # full rationale.
        if self._persistence_owners:
            retained_snapshot = dict(self._persistence_owners)
            remaining = max(deadline - time.monotonic(), 0.0)
            if remaining <= 0:
                raise ServiceShutdownError(
                    f"no budget remaining to re-drain "
                    f"{len(retained_snapshot)} retained persistence "
                    f"owner(s); {len(self._pending_persistence)} "
                    "task(s) still pending"
                )
            retained_done, retained_pending = await asyncio.wait(
                set(retained_snapshot.values()), timeout=remaining,
            )
            for tid, owner in retained_snapshot.items():
                if owner in retained_done:
                    self._persistence_owners.pop(tid, None)
                    exc = owner.exception()
                    if exc is not None:
                        logger.error(
                            "cron engine stop: retained persistence "
                            "owner for task %s terminated with exception: "
                            "%r; will retry persist via fresh reconcile",
                            tid, exc, exc_info=exc,
                        )
                # else: still pending — leave it registered.
            if retained_pending:
                logger.error(
                    "cron engine stop: %d retained persistence owner(s) "
                    "still pending after %.2fs budget; refusing to spawn "
                    "a new reconcile (would race with retained)",
                    len(retained_pending), remaining,
                )
                raise ServiceShutdownError(
                    f"{len(retained_pending)} retained persistence "
                    f"owner(s) still pending after {remaining:.2f}s; "
                    "cannot spawn a new reconcile without racing — "
                    "shared authorities cannot be torn down safely"
                )
            # All retained owners terminated (some may have had
            # exceptions, which we logged).  Tasks they were
            # reconciling may still be in ``_pending_persistence`` if
            # the DB write failed — the fresh reconcile below will
            # retry them.
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
            pending_ids = set(self._pending_persistence)
            reconcile_task = asyncio.create_task(
                self._reconcile_pending_persistence()
            )
            # H1 (round-8): register the reconcile owner keyed by
            # task_id so a subsequent ``stop()`` can dedupe.  All
            # task_ids in this batch share the same owner.
            for tid in pending_ids:
                self._persistence_owners[tid] = reconcile_task
            # The done callback only READS the exception (so asyncio
            # doesn't warn about "Task exception was never retrieved"
            # if ``stop()`` is never called again).  It does NOT
            # remove the owner — that is the next ``stop()``'s job,
            # AFTER it has surfaced the exception.
            def _read_owner_exception(
                _t, tids=frozenset(pending_ids),
            ) -> None:
                exc = _t.exception()
                if exc is not None:
                    logger.error(
                        "cron engine: retained persistence owner for "
                        "task(s) %s terminated with exception: %r",
                        sorted(tids), exc, exc_info=exc,
                    )
            reconcile_task.add_done_callback(_read_owner_exception)
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
        """Pause a task.

        M1 (round-8): if the task is currently executing (there is an
        in-flight ``_execute_task`` for it), cancel + await it BEFORE
        flipping the status.  Otherwise the in-flight execution would
        complete after ``pause()`` returned and overwrite the ``paused``
        DB row with ``completed`` / ``pending`` — the user-visible
        contract ("I paused this task") would be silently violated and
        the executor's external side effects would keep running.

        The cancelled ``_execute_task`` writes ``cancelled`` to the DB
        via its ``CancelledError`` branch; this method then overrides
        with ``paused``.  The net DB state is ``paused``.
        """
        task = self._tasks.get(task_id)
        if not task:
            return False
        await self._cancel_in_flight_execution(task_id)
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
        """Remove (cancel) a task.

        M1 (round-8): if the task is currently executing, cancel + await
        the in-flight ``_execute_task`` BEFORE popping the task from
        ``_tasks``.  Otherwise the in-flight execution would complete
        after ``remove()`` returned and overwrite the ``cancelled`` DB
        row with ``completed`` / ``pending`` — the user-visible contract
        ("I removed this task, it should not run again") would be
        silently violated and the executor's external side effects would
        keep running.  On restart the scheduler would also re-fire the
        task (DB row was overwritten back to ``pending``).

        The cancelled ``_execute_task`` writes ``cancelled`` to the DB
        via its ``CancelledError`` branch; this method then pops the
        task from ``_tasks`` and writes ``cancelled`` again (idempotent).
        """
        task = self._tasks.get(task_id)
        if not task:
            return False
        await self._cancel_in_flight_execution(task_id)
        self._tasks.pop(task_id, None)
        task.status = TaskStatus.CANCELLED
        if self.db:
            await self.db.update_scheduled_task_status(task_id, TaskStatus.CANCELLED.value)
        return True

    async def _cancel_in_flight_execution(self, task_id: str) -> None:
        """M1 (round-8): cancel + await the in-flight ``_execute_task``
        for ``task_id``, if any.

        If the task is not currently executing (no entry in
        ``_execute_tasks``, or the entry is already done), this is a
        no-op.  Otherwise the in-flight coroutine is cancelled; its
        ``CancelledError`` branch writes ``cancelled`` to the DB and
        re-raises.  The caller (``pause`` / ``remove``) then overrides
        the DB row with the desired final state.

        The wait is bounded by ``_CANCEL_IN_FLIGHT_TIMEOUT`` (10s) so
        a cancellation-resistant executor cannot wedge ``pause`` /
        ``remove`` forever — they are user-facing RPCs and must return
        in bounded time.  We use ``asyncio.wait`` (NOT ``wait_for``)
        so a cancellation-resistant executor that swallows
        ``CancelledError`` does NOT make the wait hang forever —
        ``wait_for`` cancels the inner coroutine on timeout and then
        WAITS for it to terminate, which would hang; ``wait`` returns
        immediately on timeout, leaving the inner task pending.

        If the executor does not terminate within the budget, the
        in-flight task remains in ``_execute_tasks`` (still borrowing
        shared authorities) for ``stop()`` to handle — ``stop()`` will
        raise ``ServiceShutdownError`` on the next shutdown.  The
        pause/remove proceeds anyway, writing the desired final state
        to the DB; the wedged executor's later DB write (if it ever
        terminates) will be a no-op stale-write that the next
        ``_tick_loop`` / ``stop()`` cycle reconciles.
        """
        exec_task = self._execute_tasks.get(task_id)
        if exec_task is None or exec_task.done():
            return
        exec_task.cancel()
        done, pending = await asyncio.wait(
            {exec_task}, timeout=_CANCEL_IN_FLIGHT_TIMEOUT,
        )
        if exec_task in done:
            # The coroutine terminated — read its exception so asyncio
            # doesn't warn about "Task exception was never retrieved".
            # ``CancelledError`` is expected (we just cancelled it);
            # any other exception is logged but does NOT propagate —
            # pause/remove must not crash on the executor's errors.
            #
            # NOTE: ``Task.exception()`` RAISES ``CancelledError`` on a
            # cancelled task (rather than returning it), so we must
            # catch it explicitly.  In Python 3.8+ ``CancelledError``
            # inherits from ``BaseException``, so a bare ``except`` is
            # required — ``except Exception`` would not catch it.
            try:
                exc = exec_task.exception()
            except asyncio.CancelledError:
                exc = None
            if exc is not None:
                logger.error(
                    "cron engine: in-flight execution for task %s raised "
                    "%r during cancel; proceeding with pause/remove anyway",
                    task_id, exc, exc_info=exc,
                )
            self._execute_tasks.pop(task_id, None)
        else:
            # The executor did not terminate within the budget.  Leave
            # it in ``_execute_tasks`` (still borrowing shared
            # authorities) for ``stop()`` to handle.  Proceed with
            # pause/remove anyway — the user-facing RPC must return.
            logger.error(
                "cron engine: in-flight execution for task %s did not "
                "terminate within %.1fs cancel budget; proceeding with "
                "pause/remove — wedged task remains in _execute_tasks "
                "for stop() to handle",
                task_id, _CANCEL_IN_FLIGHT_TIMEOUT,
            )

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
                # registry doesn't grow without bound.
                # M1 (round-8): keyed by task_id so ``pause()`` /
                # ``remove()`` can find and cancel the in-flight
                # execution for a specific task.
                # If there's already an in-flight execution for this
                # task_id (e.g. the previous tick fired it and it's
                # still running), do NOT start a second one — the
                # executor would race with the first and the second
                # ``_persist_task_state`` could overwrite the first's
                # terminal state.  Skip this tick; the next tick will
                # pick it up if the first one has finished.
                if task.id in self._execute_tasks and not self._execute_tasks[task.id].done():
                    continue
                exec_task = asyncio.create_task(self._execute_task(task))
                self._execute_tasks[task.id] = exec_task
                _tid = task.id
                exec_task.add_done_callback(
                    lambda _t, tid=_tid: self._execute_tasks.pop(tid, None)
                )
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
