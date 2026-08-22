"""Cron scheduler engine.

轻量级实现，不依赖外部库（如 APScheduler）。用 asyncio 后台循环检查 next_run。
"""

from __future__ import annotations

import asyncio
import enum
import logging
import time
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any

from khaos.exceptions import ServiceShutdownError
from khaos.scheduler.execution import EXECUTION_LEASE_SECONDS, SchedulerExecution
from khaos.scheduler.models import ScheduleConfig, ScheduledTask, TaskStatus
from khaos.scheduler.repository import ScheduledTaskRepository
from khaos.scheduler.recovery import SchedulerRecovery
from khaos.time_utils import utc_now_naive

if TYPE_CHECKING:  # pragma: no cover - typing only
    from khaos.audit.logger import AuditLogger
    from khaos.scheduler.recovery import PendingPersistence

logger = logging.getLogger(__name__)


class CronEngineState(enum.Enum):
    """M4 batch 3.1.15 (CRITICAL-2): explicit lifecycle state machine.

    The previous design used a single ``_running: bool`` flag, which
    conflated "the tick loop is active" with "the engine is in a clean
    state for restart".  A failed ``stop()`` (cancellation-resistant
    executor) set ``_running = False`` but retained live owners in
    ``_execute_tasks`` — a subsequent ``start()`` saw ``_running ==
    False`` and proceeded to call ``recover_all_running_tasks()``,
    marking the STILL-RUNNING executors as FAILED in the DB.  This is
    not "previous-process crash recovery"; it is the SAME process
    mis-killing its own live owners.

    The state machine gates ``start()`` explicitly:

      NEW        → start() allowed; stop() is a no-op.
      RUNNING    → start() is a no-op; stop() proceeds.
      STOPPING   → start() rejected; stop() is a no-op (already in progress).
      STOPPED    → start() allowed (clean restart); stop() is a no-op.
      QUARANTINED → start() REJECTED (live owners retained); stop()
                    retries (may succeed if owners terminated).

    Only NEW and STOPPED allow ``start()``.  QUARANTINED requires the
    process to be restarted (or ``stop()`` to be retried until it
    reaches STOPPED).
    """

    NEW = "new"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"
    QUARANTINED = "quarantined"


# H1 (round-6): total deadline for ``stop()`` to drain in-flight
# ``_execute_task`` coroutines.  An executor that swallows
# ``CancelledError`` (e.g. an AgentService.chat that catches it for
# permission-ledger cleanup) used to make ``asyncio.gather`` hang
# forever — blocking ``AgentService.stop_producers`` and preventing the
# bounded ``CHAT_DRAIN_TIMEOUT`` from ever starting.  This ceiling
# converts that hang into a fail-closed ``ServiceShutdownError``.
CRON_STOP_DRAIN_TIMEOUT = 30.0
class CronEngine(SchedulerRecovery, SchedulerExecution):
    """异步定时任务调度引擎。"""

    def __init__(
        self,
        db=None,
        executor: Callable[[str, str], Awaitable[Any]] | None = None,
        on_complete: Callable[[ScheduledTask, Any], Awaitable[None]] | None = None,
        tick_interval: float = 30.0,  # 每 30 秒检查一次
        *,
        execution_lease_seconds: float = EXECUTION_LEASE_SECONDS,
        project_id: str = "",
        policy_digest: str = "",
        audit_logger: AuditLogger | None = None,
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

        M4 batch 3.1.16B-1 (CRITICAL): ``project_id`` and
        ``policy_digest`` are bound at construction time (matching the
        ``principal_id`` binding pattern from 3.1.10).  Every task
        created through this engine captures these values at creation
        time so B-2 can detect policy/project drift at ``start()`` and
        ``_execute_task`` claim time.  Empty ``policy_digest`` is the
        fail-closed default — an engine constructed without an
        authenticated policy snapshot stamps empty strings on new
        tasks, which are then quarantined by the migration helper.
        Production callers (``AgentService``) MUST pass the effective
        policy digest; tests that omit it accept the fail-closed
        behaviour.
        """
        self.db = db
        self._task_repository = ScheduledTaskRepository(
            db, project_id=project_id
        )
        self._executor = self._wrap_executor(executor)
        self._on_complete = on_complete
        self._tick_interval = tick_interval
        self._execution_lease_seconds = execution_lease_seconds
        # M4 batch 3.1.16B-1 (CRITICAL): bind the security-context
        # snapshot at construction time.  Every task created through
        # this engine captures these values; B-2 will compare them
        # against the live values to detect drift.  Empty
        # ``policy_digest`` is fail-closed — production callers MUST
        # pass the effective policy digest.
        self._project_id = project_id
        self._policy_digest = policy_digest
        # M4 batch 3.1.16B-3: optional AuditLogger for drift-quarantine
        # audit logging.  When None (test engines), quarantine events
        # are logged only via Python logging (not the audit trail).
        # Production engines receive the server-lifecycle AuditLogger
        # from AgentService (see grpc_server.py construction).
        self._audit_logger = audit_logger
        self._tasks: dict[str, ScheduledTask] = {}
        self._running = False
        self._loop_task: asyncio.Task | None = None
        # M4 batch 3.1.15 (CRITICAL-2): explicit lifecycle state.  See
        # ``CronEngineState`` for the full rationale.  ``_running``
        # remains the tick-loop gate (checked at the top of each tick
        # iteration); ``_lifecycle_state`` gates ``start()`` and
        # tracks whether the engine is in a clean state for restart.
        self._lifecycle_state: CronEngineState = CronEngineState.NEW
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
        # M4 batch 3.1.12 (HIGH-1): timestamp of the last
        # ``recover_expired_leases`` sweep inside the tick loop.
        # ``_tick_loop`` calls ``recover_expired_leases`` every
        # ``LEASE_SWEEP_INTERVAL_SECONDS`` seconds to catch in-process
        # executor hangs.  Without this, a task whose lease expires
        # while the process is alive (executor swallowed
        # CancelledError) would stay RUNNING forever — the tick loop
        # only fires PENDING tasks.
        self._last_lease_sweep: float = 0.0

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

        M4 batch 3.1.12 (HIGH-1): single-instance recovery — call
        ``recover_all_running_tasks`` BEFORE ``recover_expired_leases``.
        Any task with ``status='running'`` at startup belongs to a
        DEAD previous process (the crash is why we're starting).
        Without this, a task whose lease hasn't expired yet would
        stay RUNNING forever — ``recover_expired_leases`` only matches
        ``lease_until < now``, and the tick loop only fires PENDING
        tasks, so an unexpired RUNNING row is never re-evaluated.

        M4 batch 3.1.12 (HIGH-2 + acceptance 9): if ``_load_tasks``
        fails, the engine enters ``_degraded`` mode.  Without this,
        a load failure left the engine with an empty ``_tasks`` dict
        but ``_running=True`` — the tick loop accepted new creations
        and fired them, while pre-existing DB tasks were invisible
        (and could be re-created with the same name, racing the
        hidden rows).

        M4 batch 3.1.15 (CRITICAL-2): explicit lifecycle state machine.
        ``start()`` is rejected unless the state is ``NEW`` or
        ``STOPPED``.  A failed ``stop()`` transitions to
        ``QUARANTINED`` (live owners retained); ``start()`` from
        ``QUARANTINED`` raises ``RuntimeError`` so the caller cannot
        accidentally ``recover_all_running_tasks()`` its own live
        executors.  The caller must either retry ``stop()`` until it
        reaches ``STOPPED``, or restart the process.
        """
        if self._lifecycle_state in (CronEngineState.RUNNING, CronEngineState.STOPPING):
            return  # Already running or stopping — no-op.
        if self._lifecycle_state == CronEngineState.QUARANTINED:
            raise RuntimeError(
                "cron engine is QUARANTINED (previous stop() failed "
                "with live owners retained in _execute_tasks / "
                "_persistence_owners); refusing to start — calling "
                "recover_all_running_tasks() would mark the live "
                "executors as FAILED.  Retry stop() until it succeeds, "
                "or restart the process. (CRITICAL-2)"
            )
        # State is NEW or STOPPED — proceed.
        self._lifecycle_state = CronEngineState.RUNNING
        self._running = True
        self._degraded = False
        # M4 batch 3.1.12 (HIGH-2 + acceptance 9): _load_tasks failure
        # → degraded mode (not silent empty state).
        try:
            await self._load_tasks()
        except Exception:
            logger.exception(
                "could not load scheduled tasks; entering DEGRADED "
                "mode — new executions are refused until the DB is "
                "recovered and the engine is restarted"
            )
            self._degraded = True
            self._loop_task = asyncio.create_task(self._tick_loop())
            logger.warning(
                "cron engine started in DEGRADED mode (_load_tasks "
                "failed; new executions refused)",
            )
            return
        # M4 batch 3.1.16B-2 (CRITICAL): drift detection at start().
        # Compare each loaded task's stored snapshot against the
        # engine's bound values.  Drifted tasks are quarantined to
        # ``status='failed'`` so the tick loop (which only fires
        # ``pending`` tasks) skips them.  This is the primary
        # enforcement point — it catches:
        # - Legacy rows (empty ``policy_digest``) loaded by a
        #   production engine
        # - Tasks created under a previous policy version
        # - Tasks created under a different project root (DB moved)
        # Test engines (empty ``_policy_digest``) skip enforcement —
        # see ``_check_snapshot_drift`` for the rationale.
        if self._policy_digest:
            drifted_count = 0
            for task in list(self._tasks.values()):
                drift_reason = self._check_snapshot_drift(task)
                if drift_reason is not None:
                    await self._quarantine_drifted_task(task, drift_reason)
                    drifted_count += 1
            if drifted_count > 0:
                logger.warning(
                    "cron engine start: quarantined %d drifted task(s) "
                    "— these tasks were created under a different "
                    "security context and will not execute until "
                    "re-created under the current policy/project",
                    drifted_count,
                )
        # M4 batch 3.1.12 (HIGH-1): single-instance recovery — mark
        # ALL running tasks as FAILED (they belong to the dead
        # previous process).
        if self.db:
            try:
                # M4 batch 3.1.16B-5 (CRITICAL): replay pending journal
                # entries BEFORE the bulk FAILED sweep so the user's
                # pause / remove / quarantine intent wins over recovery.
                # Without this, a crash between journal INSERT and CAS
                # UPDATE would lose the intent — the task would be
                # marked FAILED by ``recover_all_running_tasks``,
                # silently violating the "I paused / removed this"
                # contract.  Replay runs AFTER drift detection so drift
                # quarantine (safety-critical) wins over pre-crash
                # user intents.
                await self._replay_pending_journal_entries()
                # M4 batch 3.1.13 (CRITICAL-2): query the task IDs
                # that will be recovered BEFORE the bulk UPDATE, so we
                # can per-task reload them afterwards (instead of the
                # full ``_load_tasks()`` that overwrites other tasks'
                # in-memory state).
                running_ids = await self._task_repository.query_running_task_ids()
                recovered_running = await self._task_repository.recover_all_running()
                if recovered_running > 0:
                    logger.warning(
                        "recovered %d running task(s) at startup — "
                        "single-instance model treats these as crashed "
                        "(at-least-once disclosure)",
                        recovered_running,
                    )
                # M4 batch 3.1.10 (HIGH-3): also sweep expired leases
                # (catches in-process hangs from a prior session that
                # were never cleaned up — idempotent with the above).
                expired_ids = await self._task_repository.query_expired_lease_task_ids(
                    now_iso=utc_now_naive().isoformat(),
                )
                recovered_expired = await self._task_repository.recover_expired(
                    now_iso=utc_now_naive().isoformat(),
                )
                if recovered_expired > 0:
                    logger.warning(
                        "recovered %d expired execution lease(s) — "
                        "these tasks were crashed mid-execution and "
                        "are now marked FAILED (at-least-once disclosure)",
                        recovered_expired,
                    )
                if recovered_running > 0 or recovered_expired > 0:
                    # M4 batch 3.1.13 (CRITICAL-2): per-task reload
                    # instead of full ``_load_tasks()``.  At startup
                    # there are no pending markers or live executors,
                    # so this is equivalent to a full reload — but it
                    # establishes the per-task reload path used by the
                    # periodic sweep (which MUST NOT full-reload).
                    recovered_ids = set(running_ids) | set(expired_ids)
                    for tid in recovered_ids:
                        await self._reload_one_task_from_db(tid)
            except Exception:
                logger.exception(
                    "could not recover running/expired tasks; "
                    "entering DEGRADED mode — new executions are "
                    "refused until the DB is recovered and the engine "
                    "is restarted.  Crashed tasks may be in an "
                    "unknown state."
                )
                self._degraded = True
        # M4 batch 3.1.12 (HIGH-1): initialize the lease-sweep timer.
        self._last_lease_sweep = time.monotonic()
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

        M4 batch 3.1.15 (CRITICAL-2): explicit lifecycle state machine.
        On entry, ``stop()`` transitions to ``STOPPING``.  On clean
        exit, it transitions to ``STOPPED``.  On ANY exception
        (``ServiceShutdownError`` or other), it transitions to
        ``QUARANTINED`` — ``start()`` will reject until the caller
        retries ``stop()`` to reach ``STOPPED``.  This prevents a
        failed stop (live owners retained) from being followed by a
        ``start()`` that calls ``recover_all_running_tasks()`` on the
        SAME process's live executors.
        """
        import time
        # M4 batch 3.1.15 (CRITICAL-2): state machine transitions.
        if self._lifecycle_state == CronEngineState.STOPPED:
            return  # Clean stop — no-op.
        # RUNNING, STOPPING, or QUARANTINED — proceed (retry path for
        # QUARANTINED is allowed: the live owners may have terminated
        # since the failed stop).
        self._lifecycle_state = CronEngineState.STOPPING
        deadline = time.monotonic() + timeout
        self._running = False
        try:
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
                    _done, pending = await asyncio.wait(
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
                _done_rec, pending_rec = await asyncio.wait(
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
        except BaseException:
            # M4 batch 3.1.15 (CRITICAL-2): ANY failure (ServiceShutdown
            # Error from drain/reconcile, or any other exception) trans-
            # tions the engine to QUARANTINED.  ``start()`` will reject
            # from this state, preventing ``recover_all_running_tasks()``
            # from mis-killing the retained live owners.
            self._lifecycle_state = CronEngineState.QUARANTINED
            raise
        else:
            self._lifecycle_state = CronEngineState.STOPPED

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

        M4 batch 3.1.16B-5 (CRITICAL): lifecycle lock — ``create``
        refuses if the engine is in ``STOPPING`` / ``QUARANTINED``
        state, or if ``_degraded`` is set (a degraded engine cannot
        fire new tasks, so it must not accept them either).  Raises
        ``RuntimeError`` with the lock error so cron_tools can convert
        it to a structured ``{"status": "error", ...}`` response.
        """
        # M4 batch 3.1.16B-5: lifecycle lock — refuse mutating ops
        # while the engine is shutting down / quarantined / degraded.
        lock_error = self._check_lifecycle_lock(refuse_degraded=True)
        if lock_error is not None:
            raise RuntimeError(lock_error)
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
            # M4 batch 3.1.16B-1: stamp the engine's bound security-
            # context snapshot so B-2 can detect drift at start() /
            # _execute_task claim time.  A task created under policy A
            # must NOT silently execute under policy B.
            project_id=self._project_id,
            policy_digest=self._policy_digest,
        )
        task.next_run = self._compute_next_run(task)
        if self.db:
            task.id = await self._task_repository.insert_task(
                name, prompt, task.status.value, schedule,
                deliver_to, meta,
                principal_id=principal_id,
                next_run=task.next_run.isoformat() if task.next_run else None,
                policy_digest=self._policy_digest,
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

        M4 batch 3.1.16B-5 (CRITICAL): lifecycle lock — ``pause``
        refuses if the engine is in ``STOPPING`` / ``QUARANTINED``
        state.  ``_degraded`` is allowed (the user needs to clean up
        existing tasks even when the engine can't fire new ones).
        Returns ``"engine_unavailable"`` so cron_tools can convert it
        to a structured ``{"status": "error", ...}`` response.
        """
        # M4 batch 3.1.16B-5: lifecycle lock — refuse mutating ops
        # while the engine is shutting down / quarantined.  Check
        # BEFORE acquiring the per-task lock so a STOPPING engine
        # does not block on a long-held lock.
        lock_error = self._check_lifecycle_lock(refuse_degraded=False)
        if lock_error is not None:
            return lock_error
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
                        # M4 batch 3.1.13 (HIGH): capture the return
                        # value — ``_persist_task_state`` returns
                        # ``False`` when a newer control op won with a
                        # DIFFERENT state.  Previously this path just
                        # ``await``-ed the call, so ``persist_ok``
                        # stayed ``True`` and ``pause`` returned ``ok``
                        # despite the DB NOT being at ``paused``.
                        persist_ok = await self._persist_task_state(
                            task,
                            operation_id=existing_marker.operation_id,
                            operation_type="pause",
                        )
                    except Exception:
                        persist_ok = False
                        logger.exception(
                            "cron task %s: could not persist paused "
                            "state on retry; will retry on stop()",
                            task.name,
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
                    # M4 batch 3.1.13 (HIGH): capture the return value.
                    # ``_persist_task_state`` returns ``False`` when a
                    # newer control op (e.g. a concurrent sweep or a
                    # second instance's recovery) won with a DIFFERENT
                    # state.  Previously this path just ``await``-ed
                    # the call, so ``persist_ok`` stayed ``True`` and
                    # ``pause`` returned ``ok`` despite the DB NOT
                    # being at ``paused`` — forming a user-visible vs
                    # durable-state inconsistency.
                    persist_ok = await self._persist_task_state(
                        task, operation_type="pause",
                    )
                except Exception:
                    persist_ok = False
                    logger.exception(
                        "cron task %s: could not persist paused state; "
                        "will retry on stop()", task.name,
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

        M4 batch 3.1.16B-5 (CRITICAL): lifecycle lock — ``resume``
        refuses if the engine is in ``STOPPING`` / ``QUARANTINED``
        state.  ``_degraded`` is allowed (the user needs to clean up
        existing tasks even when the engine can't fire new ones).
        Returns ``"engine_unavailable"`` so cron_tools can convert it
        to a structured ``{"status": "error", ...}`` response.
        """
        # M4 batch 3.1.16B-5: lifecycle lock — refuse mutating ops
        # while the engine is shutting down / quarantined.
        lock_error = self._check_lifecycle_lock(refuse_degraded=False)
        if lock_error is not None:
            return lock_error
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
                # ``control_finalize_scheduled_task`` (M4 batch 3.1.12
                # CRITICAL-2) with the CURRENT lifecycle_version as
                # ``expected_version`` (the bump has NOT happened yet
                # — resume is persist-first).  ``target_version =
                # expected + 1``.  On retry after commit-then-raise,
                # the DB is already at ``target`` — the CAS matches 0
                # rows and we read back to confirm (idempotent).
                #
                # M4 batch 3.1.12 (CRITICAL-2): use
                # ``control_finalize_scheduled_task`` (not
                # ``control_update_scheduled_task``) so any residual
                # lease from a failed pause is atomically cleared.
                # If pause's persist failed, the DB still has
                # ``status='running' + execution_id + lease_until``
                # while in-memory is PAUSED.  Resume writing PENDING
                # without clearing the lease would leave
                # ``status='pending' + execution_id + lease_until`` —
                # a stale lease that ``recover_expired_leases`` would
                # later "recover" as FAILED, undoing the resume.
                expected = task.lifecycle_version
                target = expected + 1
                try:
                    rowcount = await self._task_repository.control_finalize(
                        task.id,
                        expected_version=expected,
                        target_version=target,
                        status=TaskStatus.PENDING.value,
                        next_run=new_next_run.isoformat()
                        if new_next_run else None,
                    )
                except Exception:
                    # Could be commit-then-raise — read back to verify.
                    try:
                        row = await self._task_repository.get_task(task.id)
                    except Exception:
                        logger.exception(
                            "cron task %s: could not persist resumed "
                            "state AND could not read back; task "
                            "remains paused in memory; caller should "
                            "retry resume()",
                            task.name,
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
                        logger.exception(
                            "cron task %s: could not persist resumed "
                            "state; task remains paused in memory; "
                            "caller should retry resume()",
                            task.name,
                        )
                        return "persistence_pending"
                if rowcount == 0:
                    # Version mismatch — either a prior retry already
                    # committed (DB at ``target``) or a newer control
                    # op happened (DB at > ``target``).  Read back.
                    try:
                        row = await self._task_repository.get_task(task.id)
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
            state (``COMPLETED`` / naturally ``FAILED``) — these are
            durable final states and should not be re-cancelled.
          - ``"quarantined"``: M4 batch 3.1.16B-3 — the task is
            ``FAILED`` with an ``error`` starting ``"quarantined:"``
            (security-context drift).  Quarantined tasks CAN be
            removed by an admin to clear them from the list; the
            removal proceeds like a normal cancel (bump epoch +
            ``CANCELLED`` + persist + pop).
          - ``"cancellation_pending"``: the in-flight executor did NOT
            terminate within the cancel budget.
          - ``"persistence_pending"``: the executor terminated but the
            DB write failed.

        M4 batch 3.1.10 (CRITICAL): ``principal_id`` is REQUIRED.
        Returns ``not_found`` if the task belongs to a different
        principal (fail-closed).

        M4 batch 3.1.16B-3 (CRITICAL): quarantined tasks (FAILED with
        ``error.startswith("quarantined:")``) are removable.  Without
        this, a drift-quarantined task would be permanently stuck —
        neither ``pause`` (rejected for FAILED) nor ``resume`` (only
        accepts PAUSED) nor ``remove`` (rejected for FAILED) could
        clear it.  An admin can now ``remove`` a quarantined task and
        re-create it under the current policy via ``cron_create``.

        H1 (round-11): the per-task lock is held for the ENTIRE
        operation — including cancel + persist.

        M4 batch 3.1.16B-5 (CRITICAL): lifecycle lock — ``remove``
        refuses if the engine is in ``STOPPING`` / ``QUARANTINED``
        state.  ``_degraded`` is allowed (the user needs to clean up
        existing tasks even when the engine can't fire new ones).
        Returns ``"engine_unavailable"`` so cron_tools can convert it
        to a structured ``{"status": "error", ...}`` response.
        """
        # M4 batch 3.1.16B-5: lifecycle lock — refuse mutating ops
        # while the engine is shutting down / quarantined.
        lock_error = self._check_lifecycle_lock(refuse_degraded=False)
        if lock_error is not None:
            return lock_error
        async with self._task_lock(task_id):
            task = self._check_principal(
                self._tasks.get(task_id), principal_id,
            )
            if not task:
                return "not_found"
            # H1 (round-12): refuse terminal execution states — these
            # are durable final states and should not be re-cancelled.
            # M4 batch 3.1.16B-3 (CRITICAL): quarantined FAILED tasks
            # are an EXCEPTION — they can be removed to clear them
            # from the list.  The quarantine prefix ``"quarantined:"``
            # is set by ``_quarantine_drifted_task`` and is the only
            # way a FAILED task becomes removable.  Natural FAILED
            # tasks (executor exception, unauthenticated principal,
            # etc.) use a different error prefix and remain immutable.
            if task.status == TaskStatus.COMPLETED:
                return "invalid_state"
            if task.status == TaskStatus.FAILED:
                if task.error and task.error.startswith("quarantined:"):
                    # Quarantined — allow removal to proceed.
                    pass
                else:
                    return "invalid_state"
            # H1 (round-9): bump epoch BEFORE cancelling.
            self._bump_epoch(task_id)
            task.status = TaskStatus.CANCELLED
            # Cancel the in-flight executor (I/O — but we hold the
            # per-task lock so no other operation can interfere).
            cancel_ok = await self._cancel_in_flight_execution(task_id)
            # Persist (I/O — but we hold the per-task lock).
            # M4 batch 3.1.12 (CRITICAL-1): ``_persist_task_state``
            # returns False if a newer control op won with a DIFFERENT
            # state.  We must NOT pop the task in that case — the
            # desired ``cancelled`` state was not persisted, so the
            # task would resurrect on restart.
            persist_ok = True
            if self.db:
                try:
                    persist_ok = await self._persist_task_state(
                        task, operation_type="remove",
                    )
                except Exception:
                    persist_ok = False
                    logger.exception(
                        "cron task %s: could not persist cancelled state; "
                        "will retry on stop() — task retained in _tasks "
                        "for reconcile", task.name,
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

    def _check_lifecycle_lock(self, *, refuse_degraded: bool = False) -> str | None:
        """M4 batch 3.1.16B-5 (CRITICAL): lifecycle lock on mutating ops.

        Returns an error string if the engine is in a state that refuses
        mutating operations (create / pause / resume / remove), else
        ``None``.

        State matrix:
          - ``STOPPING`` / ``QUARANTINED`` → ``"engine_unavailable"`` —
            the engine is shutting down or has live owners retained
            from a failed stop(); accepting a new mutating op would
            compound inconsistency (the DB may be wedged, reconcile
            may be mid-flight, or live executors may still be producing
            side effects).  The caller MUST return this to the user
            so they retry against a fresh engine.
          - ``_degraded=True`` AND ``refuse_degraded=True`` →
            ``"engine_degraded"`` — only ``create`` refuses degraded
            mode (a degraded engine should not accept NEW tasks while
            it can't fire existing ones).  ``pause`` / ``resume`` /
            ``remove`` still accept (the user needs to clean up
            existing tasks even when the engine is degraded).
          - ``NEW`` / ``RUNNING`` / ``STOPPED`` → ``None`` — proceed.

        This closes Gap C: previously ``create`` / ``pause`` / ``resume``
        / ``remove`` did NOT check ``_lifecycle_state`` — a
        ``QUARANTINED`` engine (whose ``stop()`` failed with live
        owners retained) still accepted ``pause()`` calls, bumped the
        epoch, and attempted to persist — compounding the DB
        inconsistency that caused the quarantine in the first place.
        """
        if self._lifecycle_state in (
            CronEngineState.STOPPING, CronEngineState.QUARANTINED,
        ):
            return "engine_unavailable"
        if refuse_degraded and self._degraded:
            return "engine_degraded"
        return None

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

    async def get(self, task_id: str) -> ScheduledTask | None:
        return self._tasks.get(task_id)
