"""Cron scheduler engine.

轻量级实现，不依赖外部库（如 APScheduler）。用 asyncio 后台循环检查 next_run。
"""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
import time
import uuid
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

# M4 batch 3.1.10: execution lease duration.  When the executor claims
# a task, it sets ``lease_until = now + EXECUTION_LEASE_SECONDS``.  If
# the process crashes during execution, ``recover_expired_leases``
# (called by ``start()`` on the next boot) marks the task as FAILED so
# the at-least-once disclosure is durable.  The lease must be long
# enough for the longest legitimate execution (an office-mode chat
# turn with tool calls) but short enough that restart recovery
# happens promptly.  10 minutes is a pragmatic default; callers can
# override via the ``CronEngine(execution_lease_seconds=...)`` kwarg.
EXECUTION_LEASE_SECONDS = 600.0


# M4 batch 3.1.10: generation-based pending persistence.  Replaces the
# old ``set[str]`` which only tracked task IDs and could be cleared by
# a stale executor that lost a version race — discarding a NEWER
# control operation's retry marker.  Each pending entry now carries
# the ``operation_id`` of the operation that placed it, so a stale
# executor only clears its OWN marker.
from dataclasses import dataclass as _dc


@_dc
class PendingPersistence:
    """A terminal state that has been set in memory but not yet persisted.

    M4 batch 3.1.10 (HIGH-2): the old ``set[str]`` only tracked task
    IDs.  When a stale executor's conditional UPDATE succeeded (because
    a control op's DB write had failed, leaving the DB version
    unchanged), the executor's ``discard(task.id)`` would clear the
    control op's retry marker — the next ``pause()`` / ``resume()``
    would return ``ok`` even though the DB still held the old state.

    The generation field fixes this: each operation that places a
    marker gets a unique ``operation_id``.  ``_persist_task_state``
    only clears the marker if the stored ``operation_id`` matches its
    own — so a stale executor cannot clear a newer control op's
    marker.
    """
    operation_id: str
    desired_status: str       # TaskStatus.value
    expected_version: int     # for CAS retry
    is_control_op: bool       # True = bumps version; False = executor write


class CronEngine:
    """异步定时任务调度引擎。"""

    def __init__(
        self,
        db=None,
        executor: Callable[[str, str], Awaitable[Any]] | None = None,
        on_complete: Callable[[ScheduledTask, Any], Awaitable[None]] | None = None,
        tick_interval: float = 30.0,  # 每 30 秒检查一次
        *,
        execution_lease_seconds: float = EXECUTION_LEASE_SECONDS,
    ):
        """
        参数：
        - db: Database 实例（持久化任务）
        - executor: 实际执行函数，接收 (task_id, prompt, principal_id)
        - on_complete: 任务完成后的回调（推送结果等）
        - tick_interval: 检查间隔（秒）
        - execution_lease_seconds: M4 batch 3.1.10 — durable execution
          lease duration.  See ``EXECUTION_LEASE_SECONDS``.

        M4 batch 3.1.11 (CRITICAL-3): the executor interface is now
        strictly 3-arg ``(task_id, prompt, principal_id)``.  Legacy
        2-arg executors ``(task_id, prompt)`` are detected via
        ``inspect.signature`` at construction time and wrapped — the
        wrapper accepts ``principal_id`` but does NOT forward it (so a
        legacy test executor never sees it).  The previous runtime
        ``except TypeError`` fallback is removed: it caught internal
        ``TypeError`` from the executor body (not just "wrong arity")
        and re-executed WITHOUT ``principal_id`` — causing double
        execution and a silent identity downgrade to the server UID.
        """
        self.db = db
        self._executor = self._wrap_executor(executor)
        self._on_complete = on_complete
        self._tick_interval = tick_interval
        self._execution_lease_seconds = execution_lease_seconds
        self._tasks: dict[str, ScheduledTask] = {}
        self._running = False
        self._loop_task: asyncio.Task | None = None
        # M4 batch 3.1.11 (MEDIUM-2): if ``start()`` cannot recover
        # expired leases, the engine enters ``_degraded`` mode and
        # refuses to fire new executions.  ``_running`` may be True
        # (tick loop active for state observation) but ``_degraded``
        # gates ``_execute_task``.  Without this, a lease-recovery
        # failure left crashed tasks un-recovered AND the engine
        # continued accepting new executions — compounding the
        # inconsistency.
        self._degraded: bool = False
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
        #
        # M4 batch 3.1.10 (HIGH-2): changed from ``set[str]`` to
        # ``dict[str, PendingPersistence]`` keyed by task_id.  Each
        # entry carries the ``operation_id`` of the operation that
        # placed it, so a stale executor that lost a version race
        # cannot clear a NEWER control op's retry marker — only its
        # own.  See ``PendingPersistence`` for the full rationale.
        self._pending_persistence: dict[str, PendingPersistence] = {}
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
        # H1 (round-9): execution epoch fence.  Bumped by ``pause()``
        # and ``remove()`` BEFORE they cancel the in-flight executor.
        # ``_execute_task`` captures the epoch at start and re-checks
        # it before writing any terminal state (PENDING / COMPLETED /
        # CANCELLED / FAILED).  If the epoch changed during execution,
        # the old executor MUST NOT overwrite the desired state set by
        # pause/remove — otherwise a slow executor that ignored cancel
        # could come back later and write ``pending`` / ``completed``,
        # silently violating the user-visible contract ("I paused /
        # removed this task").
        self._execution_epoch: dict[str, int] = {}
        # H1 (round-11): per-task transaction locks.  Replaces the
        # global ``_lifecycle_lock`` from round-10.  Each task gets
        # its own ``asyncio.Lock`` so that operations on DIFFERENT
        # tasks don't block each other, while operations on the SAME
        # task are fully serialized.
        # The lock is held for the ENTIRE operation — including
        # cancel + await + persist (I/O).  This is the per-task
        # transaction boundary: ``pause`` / ``remove`` / ``resume``
        # are atomic with respect to each other and to tick's
        # "re-check + publish".  Without holding the lock during
        # cancel + persist, the following race was possible:
        #   1. pause acquires lock, sets PAUSED, bumps epoch,
        #      snapshots owner, releases lock.
        #   2. resume acquires lock, sets PENDING, bumps epoch,
        #      releases lock.
        #   3. pause's cancel runs (against the old owner).
        #   4. tick's re-check sees PENDING and publishes a new
        #      owner.
        #   5. pause's persist writes PAUSED; resume's persist writes
        #      PENDING.
        # Final: PENDING in memory + DB, owner running, but pause
        # returned "ok" — the user's intent was silently violated.
        # With per-task locks held for the entire operation, step 2
        # blocks until step 3+5 complete, so resume sees the PAUSED
        # state and the user gets a consistent result.
        self._task_locks: dict[str, asyncio.Lock] = {}

    async def start(self) -> None:
        """启动调度循环。

        M4 batch 3.1.10 (HIGH-3): before starting the tick loop,
        recover any tasks with expired execution leases.  These
        represent crashed executions whose terminal state was never
        persisted.  Mark them as FAILED (durable at-least-once
        disclosure) so they are not silently re-fired.

        M4 batch 3.1.11 (MEDIUM-2): if lease recovery fails, the
        engine enters ``_degraded`` mode — the tick loop runs (so
        pause / resume / remove still work) but ``_execute_task``
        refuses to fire new executions.  Without this, a lease-recovery
        failure left crashed tasks un-recovered (potentially re-fired
        on the next tick) AND continued accepting new executions,
        compounding the inconsistency.  Fail-closed: an operator must
        explicitly resolve the recovery failure and restart.
        """
        if self._running:
            return
        self._running = True
        self._degraded = False
        await self._load_tasks()
        # M4 batch 3.1.10 (HIGH-3): recover expired leases.
        if self.db:
            try:
                recovered = await self.db.recover_expired_leases(
                    now_iso=datetime.utcnow().isoformat(),
                )
                if recovered > 0:
                    logger.warning(
                        "recovered %d expired execution lease(s) — "
                        "these tasks were crashed mid-execution and "
                        "are now marked FAILED (at-least-once disclosure)",
                        recovered,
                    )
                    # Reload to pick up the FAILED states.
                    await self._load_tasks()
            except Exception:  # noqa: BLE001 — recovery failure is fatal
                logger.error(
                    "could not recover expired execution leases; "
                    "entering DEGRADED mode — new executions are "
                    "refused until the DB is recovered and the engine "
                    "is restarted.  Crashed tasks may be in an "
                    "unknown state.",
                    exc_info=True,
                )
                self._degraded = True
        self._loop_task = asyncio.create_task(self._tick_loop())
        if self._degraded:
            logger.warning(
                "cron engine started in DEGRADED mode with %d tasks "
                "(lease recovery failed; new executions refused)",
                len(self._tasks),
            )
        else:
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
                    # H1 (round-9): ``Task.exception()`` RAISES
                    # ``CancelledError`` on a cancelled task (rather
                    # than returning it).  In Python 3.8+
                    # ``CancelledError`` inherits from ``BaseException``,
                    # so ``except Exception`` would NOT catch it.  Use
                    # a bare ``except`` for defensive safety even
                    # though we don't expect this owner to be cancelled
                    # — unify with the SubAgent owner state machine.
                    try:
                        exc = owner.exception()
                    except asyncio.CancelledError:
                        exc = None
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
                # H1 (round-9): catch CancelledError — see the re-drain
                # loop above for the rationale.
                try:
                    exc = _t.exception()
                except asyncio.CancelledError:
                    exc = None
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

        M4 batch 3.1.11:
          - Control op entries (``is_control_op=True``) retry via
            ``_persist_task_state`` which now uses the idempotent CAS
            (``control_update_scheduled_task``).  A retry after
            commit-then-raise matches 0 rows, reads back to confirm,
            and treats it as success — no version drift.
          - Executor entries (``is_control_op=False``) retry via
            ``_finalize_task_state`` (atomic terminal write + lease
            clear).  If the lease was already cleared by a prior
            finalize, the CAS matches 0 rows (execution_id mismatch)
            and we read back to confirm.
        """
        if not self.db:
            return
        failures: list[str] = []
        for task_id, pending in list(self._pending_persistence.items()):
            task = self._tasks.get(task_id)
            if task is None:
                # Task not in memory — clear the flag (can't retry
                # without the in-memory state).
                self._pending_persistence.pop(task_id, None)
                continue
            try:
                if pending.is_control_op:
                    # Control op retry — idempotent CAS.
                    await self._persist_task_state(
                        task, operation_id=pending.operation_id,
                    )
                else:
                    # Executor entry retry — atomic finalize.
                    await self._finalize_task_state(
                        task,
                        expected_version=pending.expected_version,
                        operation_id=pending.operation_id,
                    )
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
        *,
        principal_id: str = "",
    ) -> ScheduledTask:
        """创建并注册一个新任务。

        M4 batch 3.1.10:
          - ``principal_id`` is REQUIRED (non-empty).  Every task is
            bound to its creator; list / pause / resume / remove filter
            on it.  Empty principal is rejected.
          - ``next_run`` is now persisted atomically with the INSERT
            (HIGH-1).  Previously the engine computed ``next_run`` in
            memory but did NOT pass it to ``insert_scheduled_task``, so
            the DB row's ``next_run`` stayed NULL until the first
            execution — a restart before the first fire left the task
            permanently stuck.
        """
        if not principal_id:
            raise ValueError("principal_id is required for scheduled task creation")
        task = ScheduledTask(
            id=None,
            name=name,
            prompt=prompt,
            schedule=schedule,
            deliver_to=deliver_to,
            meta=meta or {},
            principal_id=principal_id,
        )
        task.next_run = self._compute_next_run(task)
        if self.db:
            task.id = await self.db.insert_scheduled_task(
                name, prompt, task.status.value, schedule,
                deliver_to, meta,
                principal_id=principal_id,
                next_run=task.next_run.isoformat() if task.next_run else None,
            )
        else:
            task.id = f"task_{len(self._tasks)}"
        self._tasks[task.id] = task
        self._execution_epoch[task.id] = task.lifecycle_version
        logger.info("scheduled task created: %s (%s) for principal %s", name, task.id, principal_id)
        return task

    async def list_tasks(
        self, *, principal_id: str | None = None,
    ) -> list[ScheduledTask]:
        """List tasks, optionally filtered by ``principal_id``.

        M4 batch 3.1.10 (CRITICAL): when ``principal_id`` is provided,
        only tasks belonging to that principal are returned.  ``None``
        returns all (internal use only — the tool layer always passes
        a principal).
        """
        if principal_id is None:
            return list(self._tasks.values())
        return [
            t for t in self._tasks.values()
            if t.principal_id == principal_id
        ]

    def _check_principal(
        self, task: ScheduledTask | None, principal_id: str,
    ) -> ScheduledTask | None:
        """M4 batch 3.1.10 (CRITICAL): return the task only if it
        exists AND belongs to ``principal_id``.  Returns ``None`` if
        the task doesn't exist OR belongs to a different principal —
        so the caller returns ``not_found`` (not ``forbidden``) to
        avoid revealing the task's existence.
        """
        if task is None:
            return None
        if task.principal_id != principal_id:
            return None
        return task

    async def pause(self, task_id: str, *, principal_id: str = "") -> str:
        """Pause a task.

        Returns one of:
          - ``"ok"``: task was paused — executor terminated (or was
            not running) AND the ``paused`` state was durably
            persisted (or there is no DB, or the persist was already
            complete from a prior successful pause).  For an
            already-PAUSED task, this is only returned after
            re-checking the executor and the persistence state (see
            H1 round-13).
          - ``"not_found"``: task_id is not registered OR does not
            belong to ``principal_id`` (M4 batch 3.1.10).
          - ``"invalid_state"``: the task is in a state that cannot
            be paused (``CANCELLED`` removal tombstone, or a terminal
            state ``COMPLETED`` / ``FAILED``).  The caller MUST NOT
            claim the task is paused — the state is unchanged.
          - ``"cancellation_pending"``: the in-flight executor did NOT
            terminate within the cancel budget.
          - ``"persistence_pending"``: the executor terminated but the
            DB write failed.

        M4 batch 3.1.10 (CRITICAL): ``principal_id`` is REQUIRED.
        Returns ``not_found`` if the task belongs to a different
        principal (fail-closed — does not reveal existence).

        H1 (round-11): the per-task lock is held for the ENTIRE
        operation — including cancel + persist.
        """
        async with self._task_lock(task_id):
            task = self._check_principal(
                self._tasks.get(task_id), principal_id,
            )
            if not task:
                return "not_found"
            # H1 (round-12): refuse terminal / removal states.
            if task.status in (
                TaskStatus.CANCELLED,
                TaskStatus.COMPLETED,
                TaskStatus.FAILED,
            ):
                return "invalid_state"
            # H1 (round-13): PAUSED is NOT an unconditional ok.  A
            # prior pause may have returned ``cancellation_pending``
            # (executor swallowed cancel and is still running) or
            # ``persistence_pending`` (DB write failed).  The caller
            # is expected to retry pause() to confirm the executor
            # has terminated and the state is durable.  Without this
            # re-check, the second pause would return ok and the
            # public API would report ``paused`` even though:
            #   - the executor is still producing side effects, OR
            #   - the DB row is still running/pending (crash → re-fire).
            if task.status == TaskStatus.PAUSED:
                # Re-check the live executor.  If still alive, try
                # to cancel it again (bounded by the cancel budget)
                # — the caller is explicitly retrying.
                cancel_ok = await self._cancel_in_flight_execution(task_id)
                # Re-check / retry persistence.  If task_id is in
                # _pending_persistence, the prior persist failed and
                # we MUST retry.  If not in _pending_persistence,
                # the prior persist succeeded — no-op.
                #
                # M4 batch 3.1.11 (HIGH-1): pass the EXISTING marker's
                # operation_id so the retry is recognized as the SAME
                # operation (not a new one).  Without this, the
                # ``_persist_task_state`` "skip if newer control-op
                # marker" check would see a different operation_id and
                # skip the retry — returning ``ok`` despite the DB
                # write still failing.
                persist_ok = True
                if self.db and task_id in self._pending_persistence:
                    existing_marker = self._pending_persistence[task_id]
                    try:
                        await self._persist_task_state(
                            task, operation_id=existing_marker.operation_id,
                        )
                    except Exception:  # noqa: BLE001 — stop() will retry
                        persist_ok = False
                        logger.error(
                            "cron task %s: could not persist paused "
                            "state on retry; will retry on stop()",
                            task.name, exc_info=True,
                        )
                # Prefer cancellation_pending (the live executor is
                # the more dangerous failure — it's still producing
                # side effects right now).
                if not cancel_ok:
                    return "cancellation_pending"
                if not persist_ok:
                    return "persistence_pending"
                return "ok"
            # Allowed: PENDING or RUNNING.
            # H1 (round-9): bump epoch BEFORE cancelling so the old
            # executor cannot overwrite the PAUSED state we're about
            # to set (epoch fence in _execute_task).
            self._bump_epoch(task_id)
            task.status = TaskStatus.PAUSED
            # Cancel the in-flight executor (I/O — but we hold the
            # per-task lock so no other operation can interfere).
            cancel_ok = await self._cancel_in_flight_execution(task_id)
            # Persist (I/O — but we hold the per-task lock).
            persist_ok = True
            if self.db:
                try:
                    await self._persist_task_state(task)
                except Exception:  # noqa: BLE001 — stop() will retry
                    persist_ok = False
                    logger.error(
                        "cron task %s: could not persist paused state; "
                        "will retry on stop()", task.name, exc_info=True,
                    )
            # H2 (round-10): return value reflects BOTH cancel and persist.
            if not cancel_ok:
                return "cancellation_pending"
            if not persist_ok:
                return "persistence_pending"
            return "ok"

    async def resume(self, task_id: str, *, principal_id: str = "") -> str:
        """Resume a paused task.

        Returns one of:
          - ``"ok"``: task was resumed — ``PENDING + next_run`` was
            durably persisted to the DB (or there is no DB) AND the
            in-memory state was flipped to PENDING.  Tick will fire
            the task on the next loop.
          - ``"not_found"``: task_id is not registered.
          - ``"invalid_state"``: the task is not in the ``PAUSED``
            state.  Only ``PAUSED`` tasks can be resumed.  This
            covers ``RUNNING`` (the executor is still producing side
            effects — wait for it to complete or pause it first),
            ``PENDING`` (already active — no-op), ``CANCELLED``
            (removal tombstone — retry ``remove``), ``COMPLETED`` /
            ``FAILED`` (terminal execution state — cannot be resumed).
          - ``"execution_pending"``: the task is ``PAUSED`` but the
            old executor is still alive (didn't respond to cancel
            during the prior ``pause``).  Resuming now would cause
            the old executor to race with the new execution when tick
            re-fires.  The caller should wait for the old executor to
            terminate (or call ``remove`` to force-cancel it).
          - ``"persistence_pending"``: the DB write failed (or matched
            0 rows because the task was removed concurrently).  The
            in-memory task is UNCHANGED — still ``PAUSED`` — and tick
            continues to ignore it.  The caller MUST NOT claim the
            task is resumed; retry ``resume()`` to confirm.

        H1 (round-12): strict state transition matrix.  ``resume`` is
        only allowed from ``PAUSED``.  Previously ``resume`` accepted
        any non-CANCELLED state, including ``RUNNING`` (the executor
        was still producing side effects — resuming caused tick to
        re-fire, producing two concurrent executions and double side
        effects) and terminal states ``COMPLETED`` / ``FAILED``
        (resurrecting a finished task).  Also refuses if a live
        executor still exists for the task (``execution_pending``) —
        without this, the old executor's epoch-fenced write would be
        discarded, but the old executor would still produce external
        side effects while the new execution ran concurrently.

        H1 (round-11): the per-task lock is held for the ENTIRE
        operation — including persist.

        HIGH-2 (batch 3.1.8): persist-first.  The desired
        ``PENDING + next_run`` state is written to the DB BEFORE the
        in-memory task is flipped.  If the DB write fails, the task
        stays ``PAUSED`` in memory and the caller receives
        ``persistence_pending`` — tick continues to ignore it (PAUSED
        is not in the "ready to fire" set), so no external side
        effects are produced.  Without this, a DB write failure left
        the task ``PENDING`` in memory but ``PAUSED`` in the DB —
        tick fired, produced side effects, and the next ``resume``
        call returned ``invalid_state`` (because the in-memory status
        was already PENDING).  The DB write uses ``bump_version=True``
        so the ``lifecycle_version`` is bumped (same as pause/remove);
        the in-memory ``_bump_epoch`` is applied only AFTER the persist
        succeeds so the in-memory ``task.lifecycle_version`` matches
        the post-write DB version.
        """
        async with self._task_lock(task_id):
            task = self._check_principal(
                self._tasks.get(task_id), principal_id,
            )
            if not task:
                return "not_found"
            # H1 (round-12): only PAUSED can be resumed.
            if task.status != TaskStatus.PAUSED:
                return "invalid_state"
            # H1 (round-12): refuse if a live executor still exists.
            # This happens when a prior ``pause`` returned
            # ``cancellation_pending`` (the executor swallowed cancel).
            # Resuming now would leave the old executor running while
            # tick re-publishes a new one — double side effects.
            exec_task = self._execute_tasks.get(task_id)
            if exec_task is not None and not exec_task.done():
                return "execution_pending"
            # HIGH-2 (batch 3.1.8): persist-first.  Compute the new
            # next_run WITHOUT applying it to the in-memory task.  If
            # the DB write fails, the task stays PAUSED in memory and
            # the caller gets ``persistence_pending`` to retry.
            new_next_run = self._compute_next_run(task)
            if self.db:
                # M4 batch 3.1.11 (HIGH-2): idempotent CAS.  Use
                # ``control_update_scheduled_task`` with the CURRENT
                # lifecycle_version as ``expected_version`` (the bump
                # has NOT happened yet — resume is persist-first).
                # ``target_version = expected + 1``.  On retry after
                # commit-then-raise, the DB is already at ``target``
                # — the CAS matches 0 rows and we read back to
                # confirm (idempotent).
                expected = task.lifecycle_version
                target = expected + 1
                try:
                    rowcount = await self.db.control_update_scheduled_task(
                        task.id,
                        expected_version=expected,
                        target_version=target,
                        status=TaskStatus.PENDING.value,
                        next_run=new_next_run.isoformat()
                        if new_next_run else None,
                    )
                except Exception:  # noqa: BLE001 — caller retries
                    # Could be commit-then-raise — read back to verify.
                    try:
                        row = await self.db.get_scheduled_task(task.id)
                    except Exception:  # noqa: BLE001 — DB unreadable
                        logger.error(
                            "cron task %s: could not persist resumed "
                            "state AND could not read back; task "
                            "remains paused in memory; caller should "
                            "retry resume()",
                            task.name, exc_info=True,
                        )
                        return "persistence_pending"
                    if (
                        row is not None
                        and int(row.get("lifecycle_version", 0)) == target
                        and row.get("status") == TaskStatus.PENDING.value
                    ):
                        # Commit-then-raise — the write DID commit.
                        logger.info(
                            "cron task %s: resume CAS raised but "
                            "read-back confirms target version + "
                            "status (commit-then-raise recovered)",
                            task.name,
                        )
                        rowcount = 1
                    else:
                        logger.error(
                            "cron task %s: could not persist resumed "
                            "state; task remains paused in memory; "
                            "caller should retry resume()",
                            task.name, exc_info=True,
                        )
                        return "persistence_pending"
                if rowcount == 0:
                    # Version mismatch — either a prior retry already
                    # committed (DB at ``target``) or a newer control
                    # op happened (DB at > ``target``).  Read back.
                    try:
                        row = await self.db.get_scheduled_task(task.id)
                    except Exception:  # noqa: BLE001 — treat as failure
                        row = None
                    if (
                        row is not None
                        and int(row.get("lifecycle_version", 0)) == target
                        and row.get("status") == TaskStatus.PENDING.value
                    ):
                        # Prior retry committed — idempotent success.
                        logger.info(
                            "cron task %s: resume CAS returned 0 but "
                            "read-back confirms target version + "
                            "status (prior retry committed)",
                            task.name,
                        )
                    elif row is None:
                        # No matching row — DB row was removed.
                        logger.error(
                            "cron task %s: resume persist matched 0 "
                            "rows and read-back returned None; task "
                            "may have been removed concurrently",
                            task.name,
                        )
                        return "persistence_pending"
                    else:
                        # A newer control op won.
                        logger.error(
                            "cron task %s: resume CAS returned 0 — "
                            "a newer control operation happened; not "
                            "overwriting",
                            task.name,
                        )
                        return "persistence_pending"
            # Persist succeeded (or no DB).  Now bump the in-memory
            # epoch (which also bumps task.lifecycle_version to match
            # the post-write DB version) and flip the in-memory state
            # to PENDING + new_next_run.  These updates are
            # synchronous — no further I/O — so they cannot fail.
            self._bump_epoch(task_id)
            task.status = TaskStatus.PENDING
            task.next_run = new_next_run
            return "ok"

    async def remove(self, task_id: str, *, principal_id: str = "") -> str:
        """Remove (cancel) a task.

        Returns one of:
          - ``"ok"``: task was removed — executor terminated (or was
            not running) AND the ``cancelled`` state was durably
            persisted (or there is no DB).  The task is popped from
            ``_tasks``.
          - ``"not_found"``: task_id is not registered OR does not
            belong to ``principal_id`` (M4 batch 3.1.10).
          - ``"invalid_state"``: the task is in a terminal execution
            state (``COMPLETED`` / ``FAILED``) — these are durable
            final states and should not be re-cancelled.
          - ``"cancellation_pending"``: the in-flight executor did NOT
            terminate within the cancel budget.
          - ``"persistence_pending"``: the executor terminated but the
            DB write failed.

        M4 batch 3.1.10 (CRITICAL): ``principal_id`` is REQUIRED.
        Returns ``not_found`` if the task belongs to a different
        principal (fail-closed).

        H1 (round-11): the per-task lock is held for the ENTIRE
        operation — including cancel + persist.
        """
        async with self._task_lock(task_id):
            task = self._check_principal(
                self._tasks.get(task_id), principal_id,
            )
            if not task:
                return "not_found"
            # H1 (round-12): refuse terminal execution states — these
            # are durable final states and should not be re-cancelled.
            if task.status in (TaskStatus.COMPLETED, TaskStatus.FAILED):
                return "invalid_state"
            # H1 (round-9): bump epoch BEFORE cancelling.
            self._bump_epoch(task_id)
            task.status = TaskStatus.CANCELLED
            # Cancel the in-flight executor (I/O — but we hold the
            # per-task lock so no other operation can interfere).
            cancel_ok = await self._cancel_in_flight_execution(task_id)
            # Persist (I/O — but we hold the per-task lock).
            persist_ok = True
            if self.db:
                try:
                    # H2 (round-9): use the state-machine persist path
                    # so a failure is tracked in _pending_persistence
                    # and retried by stop().
                    await self._persist_task_state(task)
                except Exception:  # noqa: BLE001 — stop() will retry
                    persist_ok = False
                    logger.error(
                        "cron task %s: could not persist cancelled state; "
                        "will retry on stop() — task retained in _tasks "
                        "for reconcile", task.name, exc_info=True,
                    )
            # Medium (round-10): do NOT pop if cancel failed — the
            # executor is still running.  Keep the tombstone (CANCELLED
            # status in _tasks) so the caller can retry remove() and
            # get a meaningful result (not not_found).
            if not cancel_ok:
                return "cancellation_pending"
            # H2 (round-9/10): do NOT pop if persist failed — the task
            # stays in _tasks with CANCELLED status for stop() to retry.
            if not persist_ok:
                return "persistence_pending"
            # Both succeeded — safe to pop.  Also clean up the
            # per-task lock (safe since we hold it — no one else can
            # be waiting on it).
            self._tasks.pop(task_id, None)
            self._task_locks.pop(task_id, None)
            return "ok"

    def _bump_epoch(self, task_id: str) -> int:
        """H1 (round-9): increment the execution epoch for ``task_id``.

        Called by ``pause()`` / ``remove()`` / ``resume()`` BEFORE
        cancelling the in-flight executor.  ``_execute_task`` captures
        the epoch at start and re-checks it before writing any terminal
        state; if the epoch changed, the old executor's write is
        discarded (the desired state set by pause/remove wins).

        HIGH-3 (batch 3.1.8): also increments ``task.lifecycle_version``
        so the durable DB fence works alongside the in-memory fence.
        The in-memory ``_execution_epoch`` prevents the executor from
        overwriting the in-memory desired state; ``lifecycle_version``
        prevents the executor's DB write from overwriting the DB desired
        state (via ``update_scheduled_task_conditional``).
        """
        new_epoch = self._execution_epoch.get(task_id, 0) + 1
        self._execution_epoch[task_id] = new_epoch
        task = self._tasks.get(task_id)
        if task is not None:
            task.lifecycle_version = new_epoch
        return new_epoch

    @staticmethod
    def _wrap_executor(
        executor: Callable[..., Awaitable[Any]] | None,
    ) -> Callable[[str, str, str], Awaitable[Any]] | None:
        """M4 batch 3.1.11 (CRITICAL-3): wrap legacy 2-arg executors.

        Detects the executor's arity via ``inspect.signature`` ONCE at
        construction time (not at every call).  If the executor accepts
        3+ positional params, it's used as-is.  If it accepts only 2,
        it's wrapped so the caller can always invoke
        ``(task_id, prompt, principal_id)`` — the wrapper drops
        ``principal_id`` (legacy executors don't need it; production
        executors must declare 3-arg).

        This replaces the runtime ``except TypeError`` fallback that
        caught internal ``TypeError`` from the executor body and
        re-executed without ``principal_id`` — causing double execution
        and a silent identity downgrade.
        """
        if executor is None:
            return None
        try:
            sig = inspect.signature(executor)
            positional = [
                p for p in sig.parameters.values()
                if p.kind in (
                    inspect.Parameter.POSITIONAL_ONLY,
                    inspect.Parameter.POSITIONAL_OR_KEYWORD,
                )
            ]
            # ``has_var_positional`` means the executor accepts *args —
            # treat as 3-arg compatible.
            has_var_positional = any(
                p.kind == inspect.Parameter.VAR_POSITIONAL
                for p in sig.parameters.values()
            )
        except (TypeError, ValueError):
            # Builtins / C-implemented callables — assume 3-arg.
            return executor
        if len(positional) >= 3 or has_var_positional:
            return executor

        # Legacy 2-arg executor — wrap it.  The wrapper accepts
        # ``principal_id`` but does NOT forward it.
        async def _wrapped(task_id: str, prompt: str, principal_id: str) -> Any:
            return await executor(task_id, prompt)

        return _wrapped

    async def _cancel_in_flight_execution(self, task_id: str) -> bool:
        """M1 (round-8): cancel + await the in-flight ``_execute_task``
        for ``task_id``, if any.

        Returns ``True`` if the executor was not running, or if it
        terminated (within the cancel budget).  Returns ``False`` if
        the executor did NOT terminate within the budget — the caller
        MUST NOT claim success in this case.

        H1 (round-11): the caller (``pause`` / ``remove``) holds the
        per-task lock, so the lookup is safe — no TOCTOU race.  The
        ``exec_task`` parameter from round-10 is no longer needed.

        H1 (round-9): the return value is now authoritative.  Previously
        this method returned ``None`` and the caller (``pause`` /
        ``remove``) always claimed success, even when the executor was
        still running — the user-visible contract was silently violated.

        The wait is bounded by ``_CANCEL_IN_FLIGHT_TIMEOUT`` (10s) so
        a cancellation-resistant executor cannot wedge ``pause`` /
        ``remove`` forever — they are user-facing RPCs and must return
        in bounded time.  We use ``asyncio.wait`` (NOT ``wait_for``)
        so a cancellation-resistant executor that swallows
        ``CancelledError`` does NOT make the wait hang forever.

        H1 (round-11): the done callback now compares by identity, so
        the ``pop`` here is also guarded — we only pop if the current
        owner is the one we cancelled.  This prevents popping a NEW
        owner that was registered after the old one completed.

        If the executor does not terminate within the budget, the
        in-flight task remains in ``_execute_tasks`` (still borrowing
        shared authorities) for ``stop()`` to handle — ``stop()`` will
        raise ``ServiceShutdownError`` on the next shutdown.
        """
        exec_task = self._execute_tasks.get(task_id)
        if exec_task is None or exec_task.done():
            # Already done — but the done callback may not have run
            # yet.  Pop only if the current owner is this task.
            if exec_task is not None and self._execute_tasks.get(task_id) is exec_task:
                self._execute_tasks.pop(task_id, None)
            return True
        exec_task.cancel()
        done, pending = await asyncio.wait(
            {exec_task}, timeout=_CANCEL_IN_FLIGHT_TIMEOUT,
        )
        if exec_task in done:
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
            # H1 (round-11): pop only if the current owner is still
            # the one we cancelled — a new owner may have been
            # registered (though with per-task locks held, this
            # shouldn't happen; defensive).
            if self._execute_tasks.get(task_id) is exec_task:
                self._execute_tasks.pop(task_id, None)
            return True
        else:
            logger.error(
                "cron engine: in-flight execution for task %s did not "
                "terminate within %.1fs cancel budget; returning "
                "cancellation_pending — wedged task remains in "
                "_execute_tasks for stop() to handle",
                task_id, _CANCEL_IN_FLIGHT_TIMEOUT,
            )
            return False

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

    def _task_lock(self, task_id: str) -> asyncio.Lock:
        """H1 (round-11): return (or create) the per-task lock.

        Each task gets its own ``asyncio.Lock`` so operations on
        different tasks don't block each other, while operations on
        the same task are fully serialized.  The lock is held for the
        entire pause/remove/resume operation (including cancel +
        persist) and for tick's re-check + publish.
        """
        lock = self._task_locks.get(task_id)
        if lock is None:
            lock = asyncio.Lock()
            self._task_locks[task_id] = lock
        return lock

    async def _tick_loop(self) -> None:
        """后台循环，检查到期的任务。"""
        while self._running:
            now = datetime.utcnow()
            # M4 batch 3.1.11 (MEDIUM-2): in DEGRADED mode, refuse to
            # fire new executions.  The tick loop still runs so
            # pause / resume / remove work (they don't go through
            # ``_execute_task``).  An operator must resolve the lease
            # recovery failure and restart the engine.
            if self._degraded:
                await asyncio.sleep(self._tick_interval)
                continue
            # Snapshot candidates without the lock — worst case we
            # consider a candidate that was just paused/removed, and
            # the re-check under the lock below skips it.
            due_candidates = [
                task for task in self._tasks.values()
                if task.enabled
                and task.status == TaskStatus.PENDING
                and task.next_run
                and task.next_run <= now
            ]
            for task in due_candidates:
                # H1 (round-11): acquire the per-task lock for the
                # re-check + publish.  If another operation
                # (pause/remove/resume) holds the lock, skip this
                # task — it will be picked up in the next tick.
                # Use a short timeout so a slow cancel (up to 10s)
                # doesn't wedge the tick loop for ALL tasks.
                lock = self._task_lock(task.id)
                try:
                    await asyncio.wait_for(lock.acquire(), timeout=0.1)
                except asyncio.TimeoutError:
                    continue
                try:
                    if task.status != TaskStatus.PENDING:
                        continue
                    if not task.enabled:
                        continue
                    # M1 (round-8): if there's already an in-flight
                    # execution for this task_id, do NOT start a
                    # second one.
                    if task.id in self._execute_tasks and not self._execute_tasks[task.id].done():
                        continue
                    # M4 (round-5): track the execution task so
                    # ``stop()`` can cancel + await it.
                    exec_task = asyncio.create_task(self._execute_task(task))
                    self._execute_tasks[task.id] = exec_task
                    # H1 (round-11): compare by identity in the done
                    # callback — a NEW owner may have been registered
                    # after this task completed but before the
                    # callback ran (e.g. pause cancelled it, then
                    # resume re-published).  Without identity check,
                    # the old callback would pop the new owner,
                    # orphaning the new executor.
                    _tid = task.id
                    _owner = exec_task

                    def _on_done(_t, tid=_tid, owner=_owner) -> None:
                        if self._execute_tasks.get(tid) is owner:
                            self._execute_tasks.pop(tid, None)

                    exec_task.add_done_callback(_on_done)
                finally:
                    lock.release()
            await asyncio.sleep(self._tick_interval)

    async def _execute_task(self, task: ScheduledTask) -> None:
        """执行单个任务。

        M3 (round-6): ``CancelledError`` is now caught explicitly so a
        shutdown-time cancellation persists a ``cancelled`` terminal
        state to the DB instead of leaving the row at ``running``.

        H1 (round-9): execution epoch fence.  The epoch is captured at
        start and re-checked before writing ANY terminal state.

        M4 batch 3.1.11 (CRITICAL-1): durable claim is now strictly
        fail-closed.  If ``claim_scheduled_task`` raises (DB error,
        commit-then-raise), the executor MUST NOT be called — we read
        back the row to verify whether the claim actually committed
        (same execution_id + RUNNING + expected version).  Only if
        verification succeeds does execution proceed.  Previously a
        claim exception was swallowed and ``rowcount = 1`` proceeded
        without a lease — violating the "durable execution ownership"
        invariant.

        M4 batch 3.1.11 (CRITICAL-2): terminal state + lease clear
        are now combined into a single ``finalize_scheduled_task`` CAS
        UPDATE.  Previously the terminal write and the lease clear
        were separate operations; if the terminal write raised, the
        ``except`` branch still cleared the lease — leaving the DB row
        at ``status='running' + execution_id=NULL + lease_until=NULL``
        (permanently stuck, unrecoverable).

        M4 batch 3.1.11 (CRITICAL-3): the ``except TypeError`` fallback
        is removed.  The executor interface is strictly 3-arg
        (``__init__`` wraps legacy 2-arg executors).  Internal
        ``TypeError`` from the executor body now propagates as FAILED
        — no double execution, no identity downgrade.

        M4 batch 3.1.11 (MEDIUM-1): ``claim_scheduled_task`` now takes
        ``started_at`` (the actual execution start time) for
        ``last_run``, NOT ``lease_until``.
        """
        # M4 batch 3.1.11 (CRITICAL-3): reject empty principal before
        # calling the executor.  An empty principal would cause
        # ``chat()`` to fall back to ``local-uid:{os.getuid()}``,
        # silently executing as the server UID.  This check is the
        # last line of defense — ``cron_create`` already rejects empty
        # principal, and the broker injects ``principal_id`` for every
        # cron tool call.  But a corrupted DB row (legacy migration
        # gone wrong) could still produce an empty principal here.
        if not task.principal_id:
            logger.error(
                "cron task %s: refusing to execute — task has no "
                "principal_id (data integrity error); marking FAILED",
                task.name,
            )
            # M4 batch 3.1.11 (CRITICAL-3 fix): bump the epoch BEFORE
            # persisting so the control-op CAS in
            # ``_persist_task_state`` uses the correct expected/target
            # versions.  Without this, ``task.lifecycle_version`` stays
            # at the DB value, ``expected = lifecycle_version - 1``
            # doesn't match the DB, and the FAILED state is never
            # durably written — the task stays at ``pending`` and tick
            # re-fires it on every loop, spamming the log.
            self._bump_epoch(task.id)
            task.status = TaskStatus.FAILED
            task.error = "task has no principal_id (data integrity error)"
            if self.db:
                try:
                    await self._persist_task_state(task)
                except Exception:  # noqa: BLE001 — stop() will retry
                    logger.error(
                        "cron task %s: could not persist FAILED state "
                        "for empty-principal task",
                        task.name, exc_info=True,
                    )
            return

        # H1 (round-9): capture epoch at start.
        epoch_at_start = self._execution_epoch.get(task.id, 0)
        # HIGH-3 (batch 3.1.8): capture lifecycle_version at start for
        # the conditional DB write.
        version_at_start = task.lifecycle_version
        # M4 batch 3.1.11 (MEDIUM-1): capture started_at for last_run.
        started_at_dt = datetime.utcnow()
        # M4 batch 3.1.10 (HIGH-3): durable execution claim.
        execution_id = uuid.uuid4().hex
        lease_until_dt = started_at_dt + timedelta(seconds=self._execution_lease_seconds)
        if self.db:
            # M4 batch 3.1.11 (CRITICAL-1): fail-closed on claim.
            claim_committed = False
            try:
                rowcount = await self.db.claim_scheduled_task(
                    task.id,
                    execution_id=execution_id,
                    started_at=started_at_dt.isoformat(),
                    lease_until=lease_until_dt.isoformat(),
                    expected_version=version_at_start,
                )
                if rowcount == 1:
                    claim_committed = True
                else:
                    # rowcount 0 — task was not PENDING or version
                    # changed.  This is a clean "skip" — NOT an error.
                    logger.info(
                        "cron task %s: durable claim returned 0 rows — "
                        "a control operation happened or task is not "
                        "pending; skipping execution",
                        task.name,
                    )
                    return
            except Exception:  # noqa: BLE001 — CRITICAL-1: fail-closed
                # Claim raised — could be DB error OR commit-then-raise.
                # Read back to verify whether the claim actually
                # committed.  Only proceed if the DB shows EXACTLY our
                # execution_id + RUNNING + expected version.
                logger.error(
                    "cron task %s: durable claim raised; verifying "
                    "whether the claim committed (commit-then-raise)",
                    task.name, exc_info=True,
                )
                try:
                    row = await self.db.get_scheduled_task(task.id)
                except Exception:  # noqa: BLE001 — DB unreadable
                    logger.error(
                        "cron task %s: could not read back row after "
                        "claim exception; FAIL-CLOSED — refusing to "
                        "execute without confirmed lease",
                        task.name, exc_info=True,
                    )
                    return
                if (
                    row is not None
                    and row.get("execution_id") == execution_id
                    and row.get("status") == "running"
                    and int(row.get("lifecycle_version", 0)) == version_at_start
                ):
                    # Commit-then-raise: the claim DID commit.  Safe
                    # to proceed — we own the lease.
                    logger.info(
                        "cron task %s: claim verified via read-back "
                        "(commit-then-raise recovered)",
                        task.name,
                    )
                    claim_committed = True
                else:
                    logger.error(
                        "cron task %s: claim exception + read-back "
                        "mismatch — FAIL-CLOSED; row state: %r",
                        task.name,
                        {
                            "execution_id": row.get("execution_id") if row else None,
                            "status": row.get("status") if row else None,
                            "lifecycle_version": row.get("lifecycle_version") if row else None,
                        },
                    )
                    return
            if not claim_committed:
                return
        task.status = TaskStatus.RUNNING
        task.last_run = started_at_dt  # MEDIUM-1: actual start time
        task.execution_id = execution_id
        task.lease_until = lease_until_dt
        try:
            if self._executor:
                # M4 batch 3.1.11 (CRITICAL-3): no more
                # ``except TypeError`` fallback.  The executor is
                # always 3-arg (``__init__`` wraps legacy 2-arg).
                # Internal ``TypeError`` propagates to the
                # ``except Exception`` branch → FAILED.
                result = await self._executor(task.id, task.prompt, task.principal_id)
            else:
                result = f"[no executor] prompt: {task.prompt[:100]}"

            # H1 (round-9): epoch fence on the success path.
            if self._epoch_changed(task, epoch_at_start):
                # M4 batch 3.1.11 (CRITICAL-2): control op won —
                # clear the lease (control op has taken over; the
                # lease is irrelevant).  Use ``_clear_lease`` because
                # we have no terminal state to finalize.
                await self._clear_lease(task, execution_id)
                return

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
            # H1 (round-9): epoch fence on the cancel path too.
            if self._epoch_changed(task, epoch_at_start):
                # M4 batch 3.1.11 (CRITICAL-2): control op won —
                # clear lease, don't finalize (control op owns state).
                await self._clear_lease(task, execution_id)
                raise
            task.status = TaskStatus.CANCELLED
            task.error = "cancelled"
            logger.info("task %s cancelled during execution", task.name)
            # M4 batch 3.1.11 (CRITICAL-2): atomic finalize — terminal
            # write + lease clear in one CAS.  If the write fails, the
            # lease is RETAINED (not cleared) so restart recovery can
            # disclose the crash.
            try:
                await self._finalize_task_state(
                    task,
                    expected_version=version_at_start,
                    operation_id=execution_id,
                )
            except Exception:  # noqa: BLE001 — stop() will retry
                logger.error(
                    "cron task %s: could not finalize cancelled "
                    "terminal state; lease RETAINED for restart "
                    "recovery; will retry on stop()",
                    task.name, exc_info=True,
                )
            raise
        except Exception as exc:
            # H1 (round-9): epoch fence on the failure path too.
            if self._epoch_changed(task, epoch_at_start):
                # M4 batch 3.1.11 (CRITICAL-2): control op won.
                await self._clear_lease(task, execution_id)
                return
            task.status = TaskStatus.FAILED
            task.error = str(exc)
            logger.error("task %s failed: %s", task.name, exc)

        # H2 (round-7): persist the terminal state.
        # H1 (round-9): re-check epoch before persisting.
        if self._epoch_changed(task, epoch_at_start):
            # M4 batch 3.1.11 (CRITICAL-2): control op won — clear
            # lease, don't finalize.
            await self._clear_lease(task, execution_id)
            return
        try:
            # M4 batch 3.1.11 (CRITICAL-2): atomic finalize.
            await self._finalize_task_state(
                task,
                expected_version=version_at_start,
                operation_id=execution_id,
            )
        except Exception:  # noqa: BLE001 — stop() will retry
            logger.error(
                "cron task %s: could not finalize terminal state %s; "
                "lease RETAINED for restart recovery; will retry on stop()",
                task.name, task.status.value, exc_info=True,
            )
            # M4 batch 3.1.11 (CRITICAL-2): DO NOT clear the lease
            # here — the terminal write failed, so the lease must
            # survive for ``recover_expired_leases`` to disclose the
            # crash on restart.  Previously this called
            # ``_clear_lease`` unconditionally, leaving the row
            # permanently stuck at RUNNING + NULL lease.

    async def _clear_lease(self, task: ScheduledTask, execution_id: str) -> None:
        """M4 batch 3.1.10 (HIGH-3): clear the durable execution lease.

        Only clears if the stored ``execution_id`` matches — so a stale
        executor that lost a lease race cannot clear a newer executor's
        lease.  Failures are logged but non-fatal (the lease will
        expire naturally if not cleared).

        M4 batch 3.1.11 (CRITICAL-2): this method is now ONLY called
        when a control operation won the epoch race (the executor's
        terminal state was discarded).  The normal success / failure /
        cancel path uses ``_finalize_task_state`` which combines the
        terminal write + lease clear into a single atomic CAS.
        """
        if not self.db:
            return
        try:
            await self.db.clear_scheduled_task_lease(
                task.id, execution_id=execution_id,
            )
        except Exception:  # noqa: BLE001 — lease cleanup is best-effort
            logger.debug(
                "cron task %s: could not clear execution lease "
                "(will expire naturally)",
                task.name, exc_info=True,
            )
        task.execution_id = None
        task.lease_until = None

    async def _finalize_task_state(
        self,
        task: ScheduledTask,
        *,
        expected_version: int,
        operation_id: str,
    ) -> bool:
        """M4 batch 3.1.11 (CRITICAL-2): atomic terminal write + lease clear.

        Wraps ``db.finalize_scheduled_task`` (single CAS UPDATE that
        sets the terminal status AND clears ``execution_id`` /
        ``lease_until``).  If the UPDATE raises, BOTH the terminal
        write and the lease clear are aborted — the lease survives so
        ``recover_expired_leases`` can disclose the crash on restart.

        Also places / clears the pending persistence marker (HIGH-1:
        does NOT overwrite an existing control-op marker).

        Returns ``True`` on success, ``False`` on version mismatch
        (rowcount 0 — a control op happened; the stale write is
        discarded, and the lease is NOT cleared because the control
        op owns the state now — ``_clear_lease`` is the caller's
        responsibility in that case).
        """
        if not self.db:
            return True
        # HIGH-1: don't overwrite an existing control-op marker.
        existing = self._pending_persistence.get(task.id)
        if (
            existing is not None
            and existing.is_control_op
            and existing.operation_id != operation_id
        ):
            logger.info(
                "cron task %s: executor finalize skipped — a newer "
                "control-op marker exists (operation_id=%s); the "
                "control op owns the state",
                task.name, existing.operation_id,
            )
            return False
        self._pending_persistence[task.id] = PendingPersistence(
            operation_id=operation_id,
            desired_status=task.status.value,
            expected_version=expected_version,
            is_control_op=False,
        )
        rowcount = await self.db.finalize_scheduled_task(
            task.id,
            execution_id=task.execution_id or "",
            expected_version=expected_version,
            status=task.status.value,
            last_run=task.last_run.isoformat() if task.last_run else None,
            next_run=task.next_run.isoformat() if task.next_run else None,
            run_count=task.run_count,
            last_result=task.last_result,
            error=task.error,
        )
        if rowcount == 0:
            # Version mismatch OR execution_id mismatch — a control
            # op or a newer executor won.  Discard the stale write.
            logger.info(
                "cron task %s: finalize returned 0 rows (version or "
                "execution_id mismatch); a control op or newer "
                "executor won — stale write discarded",
                task.name,
            )
            stored = self._pending_persistence.get(task.id)
            if stored is not None and stored.operation_id == operation_id:
                self._pending_persistence.pop(task.id, None)
            # Clear in-memory lease fields — the DB lease will be
            # cleared by the control op's persist or by restart
            # recovery.  We don't call ``_clear_lease`` here because
            # the execution_id in the DB might not be ours anymore.
            task.execution_id = None
            task.lease_until = None
            return False
        # Success — clear the marker if it's still ours.
        stored = self._pending_persistence.get(task.id)
        if stored is not None and stored.operation_id == operation_id:
            self._pending_persistence.pop(task.id, None)
        task.execution_id = None
        task.lease_until = None
        return True

    def _epoch_changed(self, task: ScheduledTask, epoch_at_start: int) -> bool:
        """H1 (round-9): return ``True`` if the execution epoch for
        ``task`` has changed since ``epoch_at_start``.

        Called by ``_execute_task`` before writing any terminal state.
        If the epoch changed, ``pause()`` / ``remove()`` / ``resume()``
        was called during execution — the desired state they set must
        NOT be overwritten by the stale executor.
        """
        current = self._execution_epoch.get(task.id, 0)
        if current != epoch_at_start:
            logger.info(
                "task %s: execution epoch changed (%d → %d); "
                "pause/remove/resume requested during execution — "
                "not overwriting the desired state",
                task.name, epoch_at_start, current,
            )
            return True
        return False

    async def _persist_task_state(
        self,
        task: ScheduledTask,
        *,
        expected_version: int | None = None,
        operation_id: str | None = None,
    ) -> bool:
        """Persist the current task state to the DB (control op path).

        M4 batch 3.1.11 (HIGH-2): control operations now use
        ``control_update_scheduled_task`` — an idempotent CAS that
        takes an explicit ``expected_version`` and ``target_version``
        (exactly ``expected_version + 1``).  A retry after
        commit-then-raise matches 0 rows (the DB is already at
        ``target_version``) — the caller reads back to confirm and
        treats it as success.  This replaces the unconditional
        ``update_scheduled_task(bump_version=True)`` which bumped the
        version on every retry, causing version drift.

        M4 batch 3.1.11 (HIGH-1): executor markers (``is_control_op
        = False``) are NOT placed if a newer control-op marker
        already exists.  Previously the unconditional
        ``self._pending_persistence[task.id] = ...`` let a stale
        executor overwrite a newer control op's retry marker — the
        control op's persist would then be lost.

        Executor terminal writes (``expected_version is not None``)
        go through ``_finalize_task_state`` (atomic + lease clear),
        NOT this method.  This method is now ONLY for control
        operations (``expected_version is None``).

        Returns ``True`` on success (or when there is no DB).
        """
        if not self.db:
            return True
        if operation_id is None:
            import uuid as _uuid
            operation_id = _uuid.uuid4().hex
        is_control_op = expected_version is None
        if not is_control_op:
            # Executor path — should use ``_finalize_task_state``.
            # Keep this branch for backwards compat with tests that
            # call ``_persist_task_state`` directly with
            # ``expected_version``.
            return await self._finalize_task_state(
                task,
                expected_version=expected_version,
                operation_id=operation_id,
            )
        # Control operation path — idempotent CAS.
        # HIGH-1: don't overwrite a newer control-op marker.
        existing = self._pending_persistence.get(task.id)
        if (
            existing is not None
            and existing.is_control_op
            and existing.operation_id != operation_id
        ):
            logger.info(
                "cron task %s: control persist skipped — a newer "
                "control-op marker exists (operation_id=%s)",
                task.name, existing.operation_id,
            )
            return True
        # Capture the expected / target version for the idempotent
        # CAS.  ``pause()`` / ``remove()`` call ``_bump_epoch``
        # BEFORE ``_persist_task_state``, which already incremented
        # ``task.lifecycle_version``.  So the pre-bump version (what
        # the DB currently has) is ``task.lifecycle_version - 1``.
        # The target is ``task.lifecycle_version`` (the bumped value).
        # On retry after commit-then-raise, the DB is already at
        # ``target`` — the CAS matches 0 rows and we read back to
        # confirm (idempotent).
        expected = task.lifecycle_version - 1  # pre-bump DB version
        target = task.lifecycle_version        # post-bump in-memory
        self._pending_persistence[task.id] = PendingPersistence(
            operation_id=operation_id,
            desired_status=task.status.value,
            expected_version=expected,
            is_control_op=True,
        )
        try:
            rowcount = await self.db.control_update_scheduled_task(
                task.id,
                expected_version=expected,
                target_version=target,
                status=task.status.value,
                next_run=task.next_run.isoformat() if task.next_run else None,
                error=task.error,
            )
        except Exception:
            # The CAS raised — could be commit-then-raise.  Read back
            # to verify.  If the DB is already at ``target_version``
            # with the desired status, treat as success.
            try:
                row = await self.db.get_scheduled_task(task.id)
            except Exception:  # noqa: BLE001 — DB unreadable
                raise
            if (
                row is not None
                and int(row.get("lifecycle_version", 0)) == target
                and row.get("status") == task.status.value
            ):
                logger.info(
                    "cron task %s: control CAS raised but read-back "
                    "confirms target version + status (commit-then-raise)",
                    task.name,
                )
                stored = self._pending_persistence.get(task.id)
                if stored is not None and stored.operation_id == operation_id:
                    self._pending_persistence.pop(task.id, None)
                task.lifecycle_version = target
                self._execution_epoch[task.id] = target
                return True
            raise
        if rowcount == 0:
            # Version mismatch — either a prior retry already
            # committed (DB at ``target``) or a newer control op
            # happened (DB at > ``target``).  Read back to
            # distinguish.
            try:
                row = await self.db.get_scheduled_task(task.id)
            except Exception:  # noqa: BLE001 — treat as failure
                row = None
            if (
                row is not None
                and int(row.get("lifecycle_version", 0)) == target
                and row.get("status") == task.status.value
            ):
                # Prior retry committed — idempotent success.
                logger.info(
                    "cron task %s: control CAS returned 0 but "
                    "read-back confirms target version + status "
                    "(prior retry committed)",
                    task.name,
                )
                stored = self._pending_persistence.get(task.id)
                if stored is not None and stored.operation_id == operation_id:
                    self._pending_persistence.pop(task.id, None)
                task.lifecycle_version = target
                self._execution_epoch[task.id] = target
                return True
            # A newer control op won — don't overwrite.
            logger.info(
                "cron task %s: control CAS returned 0 — a newer "
                "control operation happened; not overwriting",
                task.name,
            )
            stored = self._pending_persistence.get(task.id)
            if stored is not None and stored.operation_id == operation_id:
                self._pending_persistence.pop(task.id, None)
            return False
        # Success — update in-memory version + clear marker.
        task.lifecycle_version = target
        self._execution_epoch[task.id] = target
        stored = self._pending_persistence.get(task.id)
        if stored is not None and stored.operation_id == operation_id:
            self._pending_persistence.pop(task.id, None)
        return True

    async def _load_tasks(self) -> None:
        """从 DB 加载已持久化的任务。

        HIGH (batch 3.1.9): after loading each task, initialize the
        in-memory ``_execution_epoch`` from the task's
        ``lifecycle_version``.  Without this, the epoch defaulted to 0
        after restart, so the first ``_bump_epoch`` (from a control op)
        set the in-memory version to 1 while the DB version was already
        N — every subsequent executor write matched 0 rows and was
        discarded.  Synchronizing the epoch with the durable version
        at load time keeps the in-memory fence and the DB fence aligned
        across restarts.
        """
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
                # HIGH (batch 3.1.9): initialize the in-memory execution
                # epoch from the durable lifecycle version so control
                # operations and executor writes stay aligned after a
                # restart.
                self._execution_epoch[task.id] = task.lifecycle_version


def _task_from_row(row: dict) -> ScheduledTask | None:
    """Reconstruct a ScheduledTask from a DB row dict.

    HIGH (batch 3.1.9): loads ``lifecycle_version`` from the DB row so
    the in-memory ``task.lifecycle_version`` matches the durable version
    after a process restart.  Without this, every loaded task defaulted
    to version 0, so the first control operation's ``_bump_epoch`` set
    the in-memory version to 1 while the DB version was already N —
    every subsequent executor write matched 0 rows and was discarded.
    """
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
        # HIGH (batch 3.1.9): restore the durable lifecycle version so
        # the in-memory epoch fence and the DB conditional UPDATE both
        # work correctly after a restart.
        lifecycle_version=int(row.get("lifecycle_version", 0) or 0),
        # M4 batch 3.1.10: restore principal ownership + lease markers
        # so list / pause / resume / remove can filter by principal and
        # restart recovery can detect crashed executions.
        principal_id=str(row.get("principal_id") or ""),
        execution_id=row.get("execution_id"),
        lease_until=_parse_dt(row.get("lease_until")),
    )


def _parse_dt(value) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value))
    except (ValueError, TypeError):
        return None
