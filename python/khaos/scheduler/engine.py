"""Cron scheduler engine.

轻量级实现，不依赖外部库（如 APScheduler）。用 asyncio 后台循环检查 next_run。
"""

from __future__ import annotations

import asyncio
import enum
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

# M4 batch 3.1.12 (HIGH-1): periodic lease-sweep interval inside the
# tick loop.  ``recover_expired_leases`` is called every
# ``LEASE_SWEEP_INTERVAL_SECONDS`` ticks to catch executor hangs where
# the lease expires but the process is still alive (the executor
# swallowed CancelledError and is wedged).  ``recover_all_running_tasks``
# at startup handles the cross-process case; this handles the
# in-process case.
LEASE_SWEEP_INTERVAL_SECONDS = 60.0


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

    M4 batch 3.1.12 (CRITICAL-1): the marker now carries an IMMUTABLE
    snapshot of the desired state — ``desired_status``,
    ``expected_version``, ``target_version``.  Reconcile uses these
    fields instead of reading the (mutable) in-memory task object, so
    a ``remove()`` that pops the task from ``_tasks`` does NOT lose
    the retry state.  Previously reconcile saw ``task is None`` and
    silently dropped the marker — the next restart re-fired the task
    despite the user's "removed" contract.
    """
    operation_id: str
    desired_status: str       # TaskStatus.value
    expected_version: int     # for CAS retry
    is_control_op: bool       # True = bumps version; False = executor write
    target_version: int = 0   # M4 batch 3.1.12: target lifecycle_version for control ops


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
        project_id: str = "",
        policy_digest: str = "",
        audit_logger: "AuditLogger | None" = None,
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
        except Exception:  # noqa: BLE001 — load failure is fatal
            logger.error(
                "could not load scheduled tasks; entering DEGRADED "
                "mode — new executions are refused until the DB is "
                "recovered and the engine is restarted",
                exc_info=True,
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
                running_ids = await self.db.query_running_task_ids()
                recovered_running = await self.db.recover_all_running_tasks()
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
                expired_ids = await self.db.query_expired_lease_task_ids(
                    now_iso=datetime.utcnow().isoformat(),
                )
                recovered_expired = await self.db.recover_expired_leases(
                    now_iso=datetime.utcnow().isoformat(),
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
            except Exception:  # noqa: BLE001 — recovery failure is fatal
                logger.error(
                    "could not recover running/expired tasks; "
                    "entering DEGRADED mode — new executions are "
                    "refused until the DB is recovered and the engine "
                    "is restarted.  Crashed tasks may be in an "
                    "unknown state.",
                    exc_info=True,
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

        M4 batch 3.1.12 (CRITICAL-1): if the task is NOT in memory
        (e.g. ``remove()`` popped it), do NOT silently drop the
        marker.  Read back the DB:
          - If the DB is already at the marker's ``desired_status``
            → idempotent success, pop the marker.
          - Otherwise → the desired state was NEVER persisted.  This
            is a durability gap — raise ``ServiceShutdownError`` so
            the caller refuses to tear down.  The marker carries the
            immutable ``desired_status`` / ``target_version`` snapshot
            so reconcile doesn't need the (gone) in-memory task.

        M4 batch 3.1.14 (HIGH): generation-fenced reconcile.
          Previously reconcile iterated the marker snapshot WITHOUT
          the per-task lock and WITHOUT re-verifying ``operation_id``
          before writing.  A concurrent control op (Pause/Resume/
          Remove) called from an active Chat during shutdown could
          supersede the marker between the snapshot and the retry —
          and the old reconcile would call ``_persist_task_state``
          which READS THE DB CURRENT VERSION AND SUPERSEDES the
          marker, overwriting the newer op's state with the OLD
          marker's desired state.  Sequence:

            1. Pause A persist fails → marker A (PAUSED)
            2. shutdown begins → reconcile snapshots marker A
            3. active Chat calls Remove B → B persists CANCELLED,
               pops task, supersedes marker A with marker B
            4. old reconcile still holds snapshot of marker A →
               calls _persist_task_state(op=A) → reads DB version
               (now CANCELLED at version N+1) → writes PAUSED at
               version N+2 → Remove B's CANCELLED is overwritten

          The fix has three pillars:
            a. Each marker is retried under the per-task lock so a
               concurrent op cannot supersede it mid-retry.
            b. Before writing, re-verify ``operation_id`` under the
               lock — if a newer op superseded this marker, SKIP.
            c. Control-op retries use ``_retry_control_marker`` which
               uses the marker's OWN (expected, target) CAS pair —
               it does NOT call ``_persist_task_state`` (which reads
               the DB current version and superseds).  This means a
               stale marker CANNOT overwrite a newer op's state: the
               CAS expects the DB at ``expected_version`` and writes
               to ``target_version``; if the DB is already past
               ``target_version``, the CAS mismatches and we pop the
               stale marker without writing.
        """
        if not self.db:
            return
        failures: list[str] = []
        # M4 batch 3.1.14 (HIGH): snapshot the items first so we
        # don't iterate a dict that might be mutated by a concurrent
        # op.  The real protection is the per-task lock + operation_id
        # re-check below.
        for task_id, snapshot in list(self._pending_persistence.items()):
            # M4 batch 3.1.14 (HIGH): acquire the per-task lock so a
            # concurrent pause/resume/remove cannot supersede the
            # marker while we're retrying it.  Without this, reconcile
            # could read the marker, get scheduled out, a new op
            # superseded it, and reconcile would write the OLD desired
            # state — overwriting the new op's state.
            lock = self._task_lock(task_id)
            try:
                await asyncio.wait_for(lock.acquire(), timeout=5.0)
            except asyncio.TimeoutError:
                # Couldn't get the lock — a concurrent op is holding
                # it.  Skip this marker; stop() will retry.
                logger.warning(
                    "cron engine: reconcile could not acquire per-task "
                    "lock for task %s within 5s — deferring",
                    task_id,
                )
                failures.append(task_id)
                continue
            try:
                # M4 batch 3.1.14 (HIGH): re-verify the marker's
                # operation_id under the lock.  A newer op may have
                # superseded this marker between the snapshot and the
                # lock acquisition.  If so, SKIP — the newer op's
                # marker is not our responsibility.
                current = self._pending_persistence.get(task_id)
                if current is None:
                    continue  # Marker was cleared (op succeeded).
                if current.operation_id != snapshot.operation_id:
                    logger.info(
                        "cron task %s: reconcile skipped — marker "
                        "superseded (snapshot op=%s, current op=%s)",
                        task_id, snapshot.operation_id,
                        current.operation_id,
                    )
                    continue
                # M4 batch 3.1.14 (HIGH): use the marker's IMMUTABLE
                # fields, NOT the mutable task.status.  See the
                # method docstring for the full rationale.
                if snapshot.is_control_op:
                    ok = await self._retry_control_marker(
                        task_id, snapshot,
                    )
                else:
                    ok = await self._retry_executor_marker(
                        task_id, snapshot,
                    )
                if not ok:
                    failures.append(task_id)
            except Exception:  # noqa: BLE001 — collect and raise
                logger.error(
                    "cron engine: could not persist terminal state for "
                    "task %s — durability gap, refusing to continue "
                    "teardown",
                    task_id, exc_info=True,
                )
                failures.append(task_id)
            finally:
                lock.release()
        if failures:
            raise ServiceShutdownError(
                f"could not persist terminal state for {len(failures)} "
                f"cron task(s): {failures}; DB may be closed under live rows"
            )

    async def _retry_control_marker(
        self, task_id: str, marker: PendingPersistence,
    ) -> bool:
        """M4 batch 3.1.14 (HIGH): retry a control-op marker's
        persistence using the marker's OWN (expected_version,
        target_version, desired_status) CAS pair.

        This does NOT call ``_persist_task_state`` (which reads the
        DB's current version and SUPERSEDES any existing marker).
        Using the marker's own CAS pair means a stale marker CANNOT
        overwrite a newer op's state: if the DB is already past
        ``target_version``, the CAS mismatches and we pop the stale
        marker without writing.

        Returns ``True`` if:
          - The DB is already at the marker's ``desired_status``
            (idempotent success — a prior retry committed, or a newer
            op achieved the same state).
          - The CAS succeeded (possibly via commit-then-raise
            recovery).
          - The marker is stale (DB version > target) — the marker
            is popped so reconcile doesn't retry forever.  This is
            NOT a failure — the newer op's state wins.

        Returns ``False`` if:
          - The DB read or write raised an exception (durability gap
            — the caller raises ``ServiceShutdownError``).
        """
        try:
            row = await self.db.get_scheduled_task(task_id)
        except Exception:  # noqa: BLE001 — DB unreadable
            logger.error(
                "cron task %s: reconcile could not read DB — "
                "durability gap",
                task_id, exc_info=True,
            )
            return False
        if row is None:
            # Task was deleted out-of-band — treat as success.
            self._pending_persistence.pop(task_id, None)
            return True
        db_version = int(row.get("lifecycle_version", 0))
        db_status = row.get("status")
        if db_status == marker.desired_status:
            # Idempotent success — pop the marker and sync memory.
            stored = self._pending_persistence.get(task_id)
            if stored is not None and stored.operation_id == marker.operation_id:
                self._pending_persistence.pop(task_id, None)
            task = self._tasks.get(task_id)
            if task is not None:
                task.lifecycle_version = db_version
                self._execution_epoch[task_id] = db_version
            return True
        # DB is NOT at our desired state.  Check if a newer op won.
        if db_version >= marker.target_version:
            # A newer op won with a DIFFERENT state — do NOT
            # overwrite.  Pop our stale marker so reconcile doesn't
            # retry forever.
            stored = self._pending_persistence.get(task_id)
            if stored is not None and stored.operation_id == marker.operation_id:
                self._pending_persistence.pop(task_id, None)
            logger.info(
                "cron task %s: reconcile marker (op=%s, desired=%r, "
                "target=%d) is stale — DB at version %d status %r "
                "(newer op won); not overwriting",
                task_id, marker.operation_id, marker.desired_status,
                marker.target_version, db_version, db_status,
            )
            return True  # Stale marker resolved — not a failure.
        # DB version < target — our CAS might still succeed.  Try it
        # with the marker's own (expected, target) pair.
        try:
            rowcount = await self.db.control_finalize_scheduled_task(
                task_id,
                expected_version=marker.expected_version,
                target_version=marker.target_version,
                status=marker.desired_status,
                next_run=None,  # Don't modify next_run on retry.
                error=None,
            )
        except Exception:
            # Check commit-then-raise: the CAS may have committed
            # before raising.
            try:
                row2 = await self.db.get_scheduled_task(task_id)
            except Exception:  # noqa: BLE001 — DB unreadable
                logger.error(
                    "cron task %s: reconcile CAS raised and read-back "
                    "failed — durability gap",
                    task_id, exc_info=True,
                )
                return False
            if (
                row2 is not None
                and int(row2.get("lifecycle_version", 0)) == marker.target_version
                and row2.get("status") == marker.desired_status
            ):
                # commit-then-raise — success.
                stored = self._pending_persistence.get(task_id)
                if stored is not None and stored.operation_id == marker.operation_id:
                    self._pending_persistence.pop(task_id, None)
                task = self._tasks.get(task_id)
                if task is not None:
                    task.lifecycle_version = marker.target_version
                    self._execution_epoch[task_id] = marker.target_version
                return True
            logger.error(
                "cron task %s: reconcile CAS raised and read-back "
                "does not match target — durability gap",
                task_id, exc_info=True,
            )
            return False
        if rowcount == 0:
            # CAS mismatch — check if prior retry committed or a
            # newer op won.
            try:
                row2 = await self.db.get_scheduled_task(task_id)
            except Exception:  # noqa: BLE001 — treat as failure
                row2 = None
            if (
                row2 is not None
                and int(row2.get("lifecycle_version", 0)) == marker.target_version
                and row2.get("status") == marker.desired_status
            ):
                # Prior retry committed — idempotent success.
                stored = self._pending_persistence.get(task_id)
                if stored is not None and stored.operation_id == marker.operation_id:
                    self._pending_persistence.pop(task_id, None)
                task = self._tasks.get(task_id)
                if task is not None:
                    task.lifecycle_version = marker.target_version
                    self._execution_epoch[task_id] = marker.target_version
                return True
            # Newer op won — don't overwrite.  Pop the stale marker.
            stored = self._pending_persistence.get(task_id)
            if stored is not None and stored.operation_id == marker.operation_id:
                self._pending_persistence.pop(task_id, None)
            logger.info(
                "cron task %s: reconcile CAS returned 0 — newer op "
                "won with different state; not overwriting",
                task_id,
            )
            return True  # Stale marker resolved — not a failure.
        # CAS succeeded.
        stored = self._pending_persistence.get(task_id)
        if stored is not None and stored.operation_id == marker.operation_id:
            self._pending_persistence.pop(task_id, None)
        task = self._tasks.get(task_id)
        if task is not None:
            task.lifecycle_version = marker.target_version
            self._execution_epoch[task_id] = marker.target_version
        return True

    async def _retry_executor_marker(
        self, task_id: str, marker: PendingPersistence,
    ) -> bool:
        """M4 batch 3.1.14 (HIGH) + 3.1.15 (HIGH-3): retry an executor
        marker's persistence.

        Executor markers are placed by ``_finalize_task_state`` when
        the executor's terminal write fails.  The retry uses the
        marker's ``expected_version`` and ``operation_id`` — it does
        NOT supersede newer control-op markers (``_finalize_task_state``
        already checks for that at line ~1902).

        If the task was popped from ``_tasks`` (e.g. by a concurrent
        ``remove``), we can't finalize because we don't have the
        ``execution_id`` / ``last_run`` / etc.  In that case, read
        back the DB — if it's already at the marker's desired status,
        idempotent success; otherwise, durability gap.

        M4 batch 3.1.15 (HIGH-3): when ``_finalize_task_state`` returns
        ``False`` (CAS 0 rows — version or execution_id mismatch), we
        NO LONGER assume "newer op won" and pop the marker.  Instead,
        read back the DB and classify:

          a. DB at marker's ``desired_status`` → idempotent success
             (commit-then-raise on the previous attempt).  Pop marker.
          b. DB at a DIFFERENT terminal status (CANCELLED / PAUSED /
             FAILED by a newer control op) → stale marker, newer op
             won.  Pop marker.
          c. DB still ``running`` (or any non-terminal state) →
             durability gap.  The CAS failed for an unknown reason
             (e.g. execution_id mismatch because someone rewrote the
             row, or version mismatch from a failed concurrent
             control-op persist).  KEEP the marker (re-place it if
             ``_finalize_task_state`` already popped it) and return
             ``False`` — the caller (reconcile) raises
             ``ServiceShutdownError``.

        Previously the code unconditionally popped the marker and
        returned ``True`` on CAS 0, which let ``stop()`` succeed while
        the DB was still ``running`` — the task would be re-fired on
        restart, potentially double-executing side effects.

        Returns ``True`` on success, idempotent success, or stale
        marker (newer op won).
        Returns ``False`` on durability gap (caller raises
        ``ServiceShutdownError``).
        """
        task = self._tasks.get(task_id)
        if task is None:
            # Task was popped — read back the DB and classify.
            return await self._classify_executor_marker(task_id, marker)
        # Task is still in memory — call ``_finalize_task_state``
        # which already checks for newer control-op markers.
        try:
            ok = await self._finalize_task_state(
                task,
                expected_version=marker.expected_version,
                operation_id=marker.operation_id,
            )
        except Exception:  # noqa: BLE001 — DB error
            logger.error(
                "cron task %s: executor reconcile CAS raised — "
                "durability gap",
                task_id, exc_info=True,
            )
            return False
        if ok:
            return True  # Success — marker already popped by _finalize.
        # M4 batch 3.1.15 (HIGH-3): CAS returned 0 rows.  Do NOT
        # assume "newer op won" — read back the DB and classify.
        # ``_finalize_task_state`` may have already popped our marker;
        # ``_classify_executor_marker`` will re-place it if the DB
        # is still ``running`` (durability gap).
        return await self._classify_executor_marker(task_id, marker)

    async def _classify_executor_marker(
        self, task_id: str, marker: PendingPersistence,
    ) -> bool:
        """M4 batch 3.1.15 (HIGH-3): read back the DB and classify
        the marker's status.

        Called by ``_retry_executor_marker`` after a CAS 0 (or when
        the task was popped from ``_tasks``).  Returns ``True`` if
        the marker is resolved (idempotent success or stale), ``False``
        if there's a durability gap (marker must be kept).

        On durability gap, re-places the marker if it was popped by
        ``_finalize_task_state`` so the next reconcile retry can
        attempt it again.
        """
        try:
            row = await self.db.get_scheduled_task(task_id)
        except Exception:  # noqa: BLE001 — DB unreadable
            logger.error(
                "cron task %s: executor reconcile could not read "
                "DB — durability gap; keeping marker",
                task_id, exc_info=True,
            )
            # Re-place the marker if _finalize_task_state popped it.
            stored = self._pending_persistence.get(task_id)
            if stored is None or stored.operation_id != marker.operation_id:
                self._pending_persistence[task_id] = marker
            return False
        if row is None:
            # Task was removed from the DB — the remove op won.
            # Idempotent success — pop our marker if still present.
            stored = self._pending_persistence.get(task_id)
            if stored is not None and stored.operation_id == marker.operation_id:
                self._pending_persistence.pop(task_id, None)
            logger.info(
                "cron task %s: executor marker resolved — task removed "
                "from DB (newer remove op won)",
                task_id,
            )
            return True
        db_status = row.get("status")
        if db_status == marker.desired_status:
            # Idempotent success — the previous CAS committed but
            # raised (commit-then-raise).  Pop the marker.
            stored = self._pending_persistence.get(task_id)
            if stored is not None and stored.operation_id == marker.operation_id:
                self._pending_persistence.pop(task_id, None)
            logger.info(
                "cron task %s: executor marker resolved — DB already at "
                "desired status %r (commit-then-raise idempotent success)",
                task_id, db_status,
            )
            return True
        # DB is NOT at desired_status.  Check if a newer op won
        # (DB is at a different terminal / control state).
        terminal_or_control = {
            TaskStatus.COMPLETED.value,
            TaskStatus.FAILED.value,
            TaskStatus.CANCELLED.value,
            TaskStatus.PAUSED.value,
        }
        if db_status in terminal_or_control:
            # DB is at a different terminal / control state — a newer
            # control op won.  Stale marker; pop without writing.
            stored = self._pending_persistence.get(task_id)
            if stored is not None and stored.operation_id == marker.operation_id:
                self._pending_persistence.pop(task_id, None)
            logger.info(
                "cron task %s: executor marker stale — DB at %r, "
                "marker desired %r; newer control op won",
                task_id, db_status, marker.desired_status,
            )
            return True
        # DB is still ``running`` (or in an unexpected non-terminal
        # state) — durability gap.  KEEP the marker (re-place it if
        # _finalize_task_state popped it) and return False.
        stored = self._pending_persistence.get(task_id)
        if stored is None or stored.operation_id != marker.operation_id:
            self._pending_persistence[task_id] = marker
        logger.error(
            "cron task %s: executor marker CAS 0 but DB status=%r "
            "(expected %r) — durability gap; keeping marker for "
            "next reconcile retry",
            task_id, db_status, marker.desired_status,
        )
        return False

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
            task.id = await self.db.insert_scheduled_task(
                name, prompt, task.status.value, schedule,
                deliver_to, meta,
                principal_id=principal_id,
                next_run=task.next_run.isoformat() if task.next_run else None,
                project_id=self._project_id,
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
                    rowcount = await self.db.control_finalize_scheduled_task(
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

    async def _write_journal_entry(
        self,
        *,
        operation_id: str,
        task: ScheduledTask,
        operation_type: str,
        desired_status: str,
        expected_version: int,
        target_version: int,
    ) -> None:
        """M4 batch 3.1.16B-5 (CRITICAL): write a durable journal entry.

        Called BEFORE the CAS UPDATE so a crash (SIGKILL / power loss)
        between this INSERT and the CAS leaves the intent durable.
        ``start()`` scans ``applied_at IS NULL`` entries and replays
        them (roll-forward for pause / remove / resume; stale marking
        for entries superseded by a newer op or by recovery).

        The INSERT is atomic — if it fails, the caller MUST NOT proceed
        with the CAS.  A CAS without a journal entry would be
        unrecoverable on crash: ``recover_all_running_tasks`` would
        unconditionally mark the task FAILED, silently violating the
        user's "I paused / removed this" contract.  The caller raises
        on failure, leaving the in-memory marker in place so ``stop()``
        retries.

        ``operation_type`` is one of ``"pause"`` / ``"resume"`` /
        ``"remove"`` / ``"quarantine"``.  ``create`` is NOT journaled
        — the INSERT itself is atomic, so a crash either leaves the
        row created or not created, with no ambiguity to recover from.
        Executor finalize writes are also NOT journaled here — a
        crash mid-execution is correctly disclosed as FAILED by
        ``recover_all_running_tasks`` (at-least-once semantics), not
        silently rolled forward.
        """
        if not self.db:
            return
        await self.db.insert_scheduler_journal_entry(
            operation_id=operation_id,
            task_id=task.id,
            operation_type=operation_type,
            desired_status=desired_status,
            expected_version=expected_version,
            target_version=target_version,
            principal_id=task.principal_id,
            policy_digest=self._policy_digest,
            # M4 batch 3.1.16A-5-1b: stamp the engine's bound project
            # identity on the journal row so the durable operation
            # journal is cryptographically tied to the project that
            # produced it.  ``self._project_id`` is set at engine
            # construction from the AgentService's _bound_project_id
            # (which the RPC dispatcher has already verified against
            # ``ctx.project_id``).
            project_id=self._project_id,
        )

    async def _mark_journal_applied(self, operation_id: str) -> None:
        """M4 batch 3.1.16B-5: mark a journal entry as applied.

        Called after a CAS succeeds (or after replay confirms the entry
        is stale / idempotent).  Failures are swallowed — a stale
        ``applied_at IS NULL`` entry is harmless: the next ``start()``
        will re-scan it, see the DB is at the desired state, and mark
        it applied (idempotent).
        """
        if not self.db:
            return
        try:
            await self.db.mark_scheduler_journal_applied(operation_id)
        except Exception:  # noqa: BLE001 — stale NULL is harmless
            logger.warning(
                "could not mark journal entry %s as applied — "
                "next start() will re-scan and idempotently resolve",
                operation_id, exc_info=True,
            )

    async def _replay_pending_journal_entries(self) -> None:
        """M4 batch 3.1.16B-5 (CRITICAL): replay journal entries whose
        CAS was never confirmed (``applied_at IS NULL``).

        Called by ``start()`` BEFORE ``recover_all_running_tasks`` so
        the user's pause / remove / quarantine intent wins over the
        bulk FAILED sweep.  Without this, a crash between journal
        INSERT and CAS UPDATE would lose the user's intent — the task
        would be marked FAILED by recovery, silently violating the "I
        paused / removed this" contract.

        Replay strategy (per entry, in ``seq`` ASC order):
          1. Read the DB row for ``task_id``.
          2. Row is None (task deleted): mark applied (stale).
          3. DB status is ``running``: mark applied — recovery will
             achieve a terminal state.  Re-applying pause/remove on a
             ``running`` row would race with the recovery sweep; the
             recovery outcome (FAILED) is "close enough" to the user's
             intent (PAUSED / CANCELLED ≈ task inactive; FAILED = exact
             match for quarantine).
          4. DB status already matches ``desired_status``: mark applied
             (idempotent — prior CAS committed, or a newer op achieved
             the same state).
          5. DB status is terminal (``failed`` / ``cancelled``): mark
             applied (stale — a newer op or recovery already won).
          6. Otherwise (DB at ``pending`` / ``paused``): roll-forward
             via ``_persist_task_state`` with the entry's
             ``operation_id`` so the existing journal entry is marked
             applied (not a new one).

        Resume intents (``desired_status=pending``) are NOT rolled
        forward if the DB is at ``failed`` — a FAILED row from recovery
        must NOT be silently resurrected.  The user must explicitly
        ``resume`` again after inspecting the failure.  Step 5 handles
        this: ``failed`` is terminal, so the entry is marked stale.

        Replay failures (DB unreadable, CAS raises) leave the entry
        pending — the next ``start()`` will re-scan it.  This is the
        same fail-safe as the rest of the engine: a stuck entry is a
        loud signal (visible via ``list_pending_scheduler_journal_entries``),
        not a silent data loss.
        """
        if not self.db:
            return
        try:
            entries = await self.db.list_pending_scheduler_journal_entries()
        except Exception:  # noqa: BLE001 — journal unreadable
            logger.warning(
                "cron engine start: could not read pending journal "
                "entries — replay skipped; recovery will proceed",
                exc_info=True,
            )
            return
        if not entries:
            return
        replayed = 0
        skipped_stale = 0
        for entry in entries:
            op_id = entry["operation_id"]
            task_id = entry["task_id"]
            desired = entry["desired_status"]
            op_type = entry["operation_type"]
            try:
                row = await self.db.get_scheduled_task(task_id)
            except Exception:  # noqa: BLE001 — DB unreadable
                logger.warning(
                    "cron engine start: could not read task %s for "
                    "journal replay of op %s — leaving entry pending",
                    task_id, op_id, exc_info=True,
                )
                continue
            if row is None:
                # Task was deleted out-of-band.  Mark applied (stale).
                await self._mark_journal_applied(op_id)
                skipped_stale += 1
                continue
            db_status = row.get("status")
            if db_status == "running":
                # Recovery will achieve a terminal state — don't race.
                # Mark applied so the next start() doesn't re-scan.
                await self._mark_journal_applied(op_id)
                skipped_stale += 1
                continue
            if db_status == desired:
                # Idempotent — prior CAS committed or newer op matched.
                await self._mark_journal_applied(op_id)
                skipped_stale += 1
                continue
            if db_status in ("failed", "cancelled"):
                # Terminal DB state with a different status — stale
                # entry (a newer op or recovery already won).  Do NOT
                # roll forward: a ``failed`` row from recovery must not
                # be silently resurrected by a resume intent.
                await self._mark_journal_applied(op_id)
                skipped_stale += 1
                continue
            # Non-terminal, non-running, non-matching: roll forward.
            task = self._tasks.get(task_id)
            if task is None:
                # Task was removed from memory (e.g. ``remove()``
                # popped it before the crash).  Reconstruct a minimal
                # ScheduledTask from the DB row so _persist_task_state
                # can do its CAS.  The reconstructed task is NOT added
                # to ``_tasks`` — the caller (start()) will reload
                # tasks via the per-task reload path after recovery.
                task = _task_from_row(row)
                if task is None:
                    logger.warning(
                        "cron engine start: could not reconstruct task "
                        "%s from DB row for journal replay of op %s — "
                        "marking entry stale",
                        task_id, op_id,
                    )
                    await self._mark_journal_applied(op_id)
                    skipped_stale += 1
                    continue
            # Set the desired status on the in-memory task so
            # _persist_task_state reads it via ``task.status.value``.
            try:
                task.status = TaskStatus(desired)
            except ValueError:
                logger.warning(
                    "cron engine start: journal entry %s has unknown "
                    "desired_status %r — marking stale",
                    op_id, desired,
                )
                await self._mark_journal_applied(op_id)
                skipped_stale += 1
                continue
            try:
                await self._persist_task_state(
                    task,
                    operation_id=op_id,  # retry — skip journal write
                    operation_type=op_type,
                )
                replayed += 1
            except Exception:  # noqa: BLE001 — replay failure
                logger.error(
                    "cron engine start: could not roll-forward journal "
                    "entry %s for task %s — leaving entry pending for "
                    "next start()",
                    op_id, task_id, exc_info=True,
                )
        if replayed or skipped_stale:
            logger.info(
                "cron engine start: journal replay — %d rolled forward, "
                "%d marked stale",
                replayed, skipped_stale,
            )

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

    def _check_snapshot_drift(self, task: "ScheduledTask") -> str | None:
        """M4 batch 3.1.16B-2 (CRITICAL): detect security-context drift.

        Compares the task's stored snapshot (``policy_digest`` +
        ``project_id``, captured at creation time) against the engine's
        bound values (captured at construction time).  Any mismatch
        means the task was created under a DIFFERENT security context
        — executing it under the current context would violate the
        "a task created under policy A must NOT silently execute under
        policy B" invariant.

        Drift cases:
        - ``task.policy_digest != self._policy_digest``: the effective
          policy changed between task creation and engine start.  This
          happens when ``khaos_policy.yaml`` is edited, when the
          project root moves, or when a DB created by one project is
          opened by another.
        - ``task.project_id != self._project_id``: the project root
          changed.  ``project_id = sha256(realpath(project_root))[:32]``
          so this catches both directory moves and symlink redirects.
        - ``task.policy_digest == ""`` on a production engine (non-
          empty ``self._policy_digest``): legacy or test-created task
          loaded by a production engine.  The task has no authenticated
          snapshot — fail-closed.

        Test mode: when the engine's ``_policy_digest`` is empty (test
        engines that don't pass a digest), drift detection is DISABLED
        — otherwise every test-created task (which also has empty
        ``policy_digest``) would be quarantined.  Production engines
        ALWAYS have a non-empty digest (enforced by ``AgentService``
        construction in ``grpc_server.py``).

        Returns an error message string if drifted, or ``None`` if the
        snapshot matches.  The caller is responsible for quarantine
        (mark ``status=failed`` + persist).
        """
        # Test mode: engine has no bound digest → skip enforcement.
        # This is the same fail-closed default as B-1: an engine
        # constructed without an authenticated policy snapshot stamps
        # empty strings on new tasks; B-2 extends this to LOADED tasks
        # — but only when the engine actually has a digest to compare.
        if not self._policy_digest:
            return None
        # Production engine — enforce drift detection.
        if task.policy_digest != self._policy_digest:
            return (
                f"security-context drift: task policy_digest "
                f"{task.policy_digest!r} != engine policy_digest "
                f"{self._policy_digest!r} (task was created under a "
                f"different effective policy; refusing to execute "
                f"under the current policy — fail-closed)"
            )
        if task.project_id != self._project_id:
            return (
                f"security-context drift: task project_id "
                f"{task.project_id!r} != engine project_id "
                f"{self._project_id!r} (task was created under a "
                f"different project root; refusing to execute under "
                f"the current project — fail-closed)"
            )
        return None

    async def _quarantine_drifted_task(self, task: "ScheduledTask", reason: str) -> None:
        """M4 batch 3.1.16B-2 (CRITICAL): quarantine a drifted task.

        Marks the task as ``failed`` in memory and persists the state
        to the DB so the tick loop (which only fires ``pending``
        tasks) skips it.  The quarantine is durable — the task stays
        ``failed`` until an admin explicitly re-creates it under the
        current security context.

        M4 batch 3.1.16B-3 (CRITICAL): writes an audit log entry via
        ``log_security_event`` so drift quarantine is attributable.
        The audit write happens BEFORE ``_persist_task_state`` so even
        if the DB write fails, the audit trail already records the
        quarantine decision.  Audit write failures are swallowed
        (matching the SecurityMiddleware pattern) — audit must NEVER
        block the quarantine, which is a safety-critical operation.

        M4 batch 3.1.16B-5 (CRITICAL): the persist call now passes
        ``operation_type="quarantine"`` so a journal entry is written
        BEFORE the CAS.  A crash between the audit write and the CAS
        would otherwise leave the quarantine intent lost — the task
        would stay ``pending`` in the DB and re-fire on restart.  The
        journal entry ensures ``start()`` replay rolls the quarantine
        forward.  The audit write still happens FIRST (audit is the
        attributable record; journal is the durability record).
        """
        logger.error(
            "cron task %s (%s): QUARANTINED — %s",
            task.name, task.id, reason,
        )
        self._bump_epoch(task.id)
        task.status = TaskStatus.FAILED
        task.error = f"quarantined: {reason}"
        # M4 batch 3.1.16B-3: write audit log BEFORE persisting the
        # FAILED state so the audit trail captures the quarantine
        # decision even if the DB write fails.
        if self._audit_logger is not None:
            try:
                await self._audit_logger.log_security_event(
                    event_type="scheduler_drift_quarantine",
                    tool_name=f"cron:{task.name}",
                    reason=reason,
                    detail={
                        "task_id": task.id,
                        "task_name": task.name,
                        "task_policy_digest": task.policy_digest,
                        "engine_policy_digest": self._policy_digest,
                        "task_project_id": task.project_id,
                        "engine_project_id": self._project_id,
                        "principal_id": task.principal_id,
                    },
                    task_id=task.id,
                    source_transport="cron-engine",
                )
            except Exception:  # noqa: BLE001 — audit must not block quarantine
                logger.warning(
                    "cron task %s: audit log write failed for drift "
                    "quarantine — quarantine proceeds anyway",
                    task.name, exc_info=True,
                )
        if self.db:
            try:
                # M4 batch 3.1.16B-5: pass operation_type="quarantine"
                # so the journal records the quarantine intent.  A
                # crash between audit write and CAS would otherwise
                # leave the task re-fireable on restart.
                await self._persist_task_state(
                    task, operation_type="quarantine",
                )
            except Exception:  # noqa: BLE001 — stop() will retry
                logger.error(
                    "cron task %s: could not persist FAILED state for "
                    "drifted task; will be retried by stop()",
                    task.name, exc_info=True,
                )

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
            # M4 batch 3.1.12 (HIGH-1): periodic lease sweep.  Catches
            # executor hangs where the lease expires but the process
            # is still alive (executor swallowed CancelledError and is
            # wedged).  ``recover_all_running_tasks`` at startup
            # handles the cross-process case; this handles the
            # in-process case.  On failure, enter degraded mode —
            # we can't trust the DB state.
            #
            # M4 batch 3.1.13 (CRITICAL-1): the sweep must FIRST cancel
            # + bounded-await the live executor BEFORE writing FAILED.
            # Previously the sweep unconditionally wrote FAILED via
            # ``recover_expired_leases`` and then reloaded — the live
            # executor kept producing side effects after the DB said
            # FAILED, and ``pause``/``remove`` would refuse the FAILED
            # terminal state so the user couldn't stop it.  Now the
            # sweep queries expired-lease task IDs, revokes each
            # executor, and only then writes FAILED per-task.
            #
            # M4 batch 3.1.13 (CRITICAL-2): the sweep no longer calls
            # ``_load_tasks()`` (full reload).  Instead it reloads only
            # the recovered task IDs via ``_reload_one_task_from_db``,
            # which skips tasks with pending persistence markers or
            # live executors.  Previously the full reload overwrote
            # the in-memory state of a task whose ``pause`` persist
            # had failed (in-memory PAUSED, DB PENDING) — the reload
            # changed it to PENDING and the tick re-fired it.
            #
            # M4 batch 3.1.14 (CRITICAL-1): once any lease revocation
            # fails (executor didn't terminate) OR the sweep raises,
            # the tick MUST NOT start any other due task in the same
            # iteration.  Previously the sweep set ``_degraded=True``
            # but kept iterating ``expired_ids`` and then fell through
            # to ``due_candidates`` — so a Task B that was unrelated
            # but immediately due would start executing after Task A's
            # revocation failure, violating the degraded invariant
            # ("once execution ownership is untrusted, no new side-
            # effecting execution may start").  Now we break out of
            # the sweep loop on the first failure and re-check
            # ``_degraded`` before constructing ``due_candidates``.
            if (
                self.db
                and (time.monotonic() - self._last_lease_sweep)
                >= LEASE_SWEEP_INTERVAL_SECONDS
            ):
                self._last_lease_sweep = time.monotonic()
                try:
                    expired_ids = await self.db.query_expired_lease_task_ids(
                        now_iso=now.isoformat(),
                    )
                    if expired_ids:
                        logger.warning(
                            "periodic lease sweep: %d expired lease(s) "
                            "detected — revoking live executors before "
                            "writing FAILED",
                            len(expired_ids),
                        )
                        for tid in expired_ids:
                            ok = await self._revoke_and_recover_lease(
                                tid, now_iso=now.isoformat(),
                            )
                            if not ok:
                                # Executor did NOT terminate — enter
                                # degraded mode.  The wedged executor
                                # stays in ``_execute_tasks`` for
                                # ``stop()`` to handle.  The DB is NOT
                                # written as FAILED (the lease is still
                                # in the DB, and the next sweep will
                                # retry).
                                self._degraded = True
                                logger.error(
                                    "periodic lease sweep: executor for "
                                    "task %s did not terminate within "
                                    "%.1fs; entering DEGRADED mode — "
                                    "wedged executor remains in "
                                    "_execute_tasks for stop()",
                                    tid, _CANCEL_IN_FLIGHT_TIMEOUT,
                                )
                                # M4 batch 3.1.14 (CRITICAL-1): STOP
                                # the sweep — do NOT process any more
                                # expired IDs in this iteration, and
                                # do NOT fall through to due_candidates.
                                break
                except Exception:  # noqa: BLE001 — sweep failure is fatal
                    logger.error(
                        "periodic lease sweep failed; entering "
                        "DEGRADED mode",
                        exc_info=True,
                    )
                    self._degraded = True
                    continue
            # M4 batch 3.1.14 (CRITICAL-1): re-check degraded AFTER
            # the sweep.  Even if the sweep ran without raising, a
            # revocation failure inside it set ``_degraded=True`` and
            # broke out — we must NOT start any due task in this
            # iteration.  Previously this check only ran at the TOP of
            # the loop, so a degraded set mid-sweep still fell through
            # to due_candidates.
            if self._degraded:
                await asyncio.sleep(self._tick_interval)
                continue
            # M4 batch 3.1.13 (CRITICAL-2): tick MUST skip tasks with
            # pending persistence markers.  A task whose ``pause`` /
            # ``remove`` persist failed has its desired state in the
            # marker, NOT in the DB.  Re-firing it from the DB's stale
            # ``pending`` state would produce unwanted side effects.
            # Snapshot candidates without the lock — worst case we
            # consider a candidate that was just paused/removed, and
            # the re-check under the lock below skips it.
            due_candidates = [
                task for task in self._tasks.values()
                if task.enabled
                and task.status == TaskStatus.PENDING
                and task.next_run
                and task.next_run <= now
                and task.id not in self._pending_persistence
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
                    # M4 batch 3.1.14 (CRITICAL-1 criterion 3): defensive
                    # re-check of ``_degraded`` right before publishing a
                    # new executor.  The sweep sets ``_degraded`` and we
                    # re-check after it, but a long-running candidate
                    # iteration (e.g. contended per-task locks) could in
                    # principle let ``_degraded`` flip between the
                    # post-sweep check and here.  This is the final gate.
                    if self._degraded:
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
        #
        # M4 batch 3.1.12 (HIGH-2): also reject the synthetic
        # ``'legacy'`` principal.  Migration assigns ``'legacy'`` to
        # pre-existing rows and quarantines them (status=failed,
        # enabled=0), but a race between migration and tick could
        # surface a legacy row before the quarantine UPDATE commits.
        # Treat ``'legacy'`` the same as empty — fail-closed.
        if not task.principal_id or task.principal_id == "legacy":
            logger.error(
                "cron task %s: refusing to execute — task has no "
                "authenticated principal_id (got %r; data integrity "
                "error); marking FAILED",
                task.name, task.principal_id,
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
            task.error = (
                f"task has no authenticated principal_id "
                f"(got {task.principal_id!r}; data integrity error)"
            )
            if self.db:
                try:
                    await self._persist_task_state(
                        task, operation_type="quarantine",
                    )
                except Exception:  # noqa: BLE001 — stop() will retry
                    logger.error(
                        "cron task %s: could not persist FAILED state "
                        "for unauthenticated-principal task",
                        task.name, exc_info=True,
                    )
            return

        # M4 batch 3.1.16B-2 (CRITICAL): defense-in-depth drift check
        # at claim time.  ``start()`` already quarantines drifted tasks
        # after ``_load_tasks()``, but this re-check guards against:
        # - A task whose DB row was mutated between ``start()`` and
        #   the tick firing (e.g. by a future ``cron_migrate`` tool)
        # - A task whose in-memory snapshot is stale because the row
        #   was reloaded by ``_reload_one_task_from_db`` after a
        #   control op that didn't preserve the snapshot (shouldn't
        #   happen, but defense-in-depth)
        # - A task created by ``create()`` on an engine whose bound
        #   digest changed between construction and the first tick
        #   (shouldn't happen — digest is immutable after construction
        #   — but the check is cheap and the invariant is critical)
        drift_reason = self._check_snapshot_drift(task)
        if drift_reason is not None:
            await self._quarantine_drifted_task(task, drift_reason)
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
                # M4 batch 3.1.12 (CRITICAL-2): control op won — do
                # NOT independently clear the lease.  The control op
                # now uses ``control_finalize_scheduled_task`` which
                # atomically clears the lease in the SAME CAS that
                # writes the desired state.  If the control op's
                # persist FAILED, the lease is still in the DB —
                # clearing it here would leave ``status='running' +
                # NULL lease`` (permanently stuck, unrecoverable by
                # ``recover_expired_leases`` which matches
                # ``lease_until IS NOT NULL``).  Just clear the
                # in-memory lease fields and return; the control op
                # (or restart recovery) handles the DB.
                task.execution_id = None
                task.lease_until = None
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
                # M4 batch 3.1.12 (CRITICAL-2): control op won — do
                # NOT independently clear the lease (see success path
                # comment).  Just clear in-memory fields and re-raise.
                task.execution_id = None
                task.lease_until = None
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
                # M4 batch 3.1.12 (CRITICAL-2): control op won — do
                # NOT independently clear the lease (see success path
                # comment).
                task.execution_id = None
                task.lease_until = None
                return
            task.status = TaskStatus.FAILED
            task.error = str(exc)
            logger.error("task %s failed: %s", task.name, exc)

        # H2 (round-7): persist the terminal state.
        # H1 (round-9): re-check epoch before persisting.
        if self._epoch_changed(task, epoch_at_start):
            # M4 batch 3.1.12 (CRITICAL-2): control op won — do NOT
            # independently clear the lease (see success path comment).
            task.execution_id = None
            task.lease_until = None
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
        operation_type: str = "control",
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

        M4 batch 3.1.12 (CRITICAL-1): control operations now SUPERSEDE
        any existing marker — they do NOT skip when a different
        control-op marker exists.  The new op reads the DB's CURRENT
        lifecycle_version (not the in-memory task.lifecycle_version,
        which may be stale from a prior failed bump) and uses
        (db_version, db_version + 1) as (expected, target).  This
        closes the "假成功" hole where ``remove()`` after a failed
        ``pause()`` saw the pause's marker, skipped the DB write,
        returned True, and popped the task — leaving the DB at
        ``pending`` so the task resurrected on restart.

        M4 batch 3.1.12 (CRITICAL-2): control operations now use
        ``control_finalize_scheduled_task`` (not
        ``control_update_scheduled_task``) — the new method atomically
        clears the execution lease in the SAME CAS that writes the
        desired state.  This closes the hole where a control op
        persisted the desired state but left the lease in the DB —
        then a stale executor's ``_clear_lease`` cleared the lease
        independently while the control op's persist had actually
        FAILED, leaving ``status='running' + NULL lease``.

        M4 batch 3.1.16B-5 (CRITICAL): durable operation journal.
        For NEW control ops (``operation_id is None``), a journal
        entry is written BEFORE the CAS UPDATE so a crash leaves the
        intent durable.  ``start()`` replays pending entries
        (``applied_at IS NULL``) to roll forward pause / remove /
        quarantine intents.  Retries (``operation_id`` supplied) skip
        the journal write — the entry already exists from the first
        attempt.  On CAS success (or idempotent read-back), the entry
        is marked ``applied_at``.  ``operation_type`` is one of
        ``"pause"`` / ``"remove"`` / ``"quarantine"`` (default
        ``"control"`` for callers that don't care about replay
        semantics).

        Returns ``True`` on success (or when there is no DB).
        Returns ``False`` if a newer control op already won AND the
        DB does NOT match our desired state — the caller must NOT
        treat this as success (e.g. ``remove()`` must NOT pop the
        task from ``_tasks``).
        """
        if not self.db:
            return True
        is_new_op = operation_id is None
        if is_new_op:
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
        # M4 batch 3.1.12 (CRITICAL-1): read the DB's CURRENT
        # lifecycle_version.  The in-memory ``task.lifecycle_version``
        # may be stale (a prior failed bump left it ahead of the DB).
        # Using the stale value would cause expected = stale - 1 (too
        # high) and the CAS would permanently mismatch.  Reading the
        # DB gives us the ground truth.
        try:
            row = await self.db.get_scheduled_task(task.id)
        except Exception:  # noqa: BLE001 — DB unreadable
            # Can't read — can't supersede.  Place a marker so
            # ``stop()`` retries.  Use the in-memory version as a
            # best-effort (likely won't match, but the marker
            # preserves the desired state for reconcile).
            expected = task.lifecycle_version - 1
            target = task.lifecycle_version
            self._pending_persistence[task.id] = PendingPersistence(
                operation_id=operation_id,
                desired_status=task.status.value,
                expected_version=expected,
                is_control_op=True,
                target_version=target,
            )
            raise
        if row is None:
            # Task was deleted from the DB out-of-band.  Nothing to
            # persist — treat as success.
            self._pending_persistence.pop(task.id, None)
            # M4 batch 3.1.16B-5: mark any prior journal entry stale
            # so start() does not replay a no-op intent.
            if not is_new_op:
                await self._mark_journal_applied(operation_id)
            return True
        db_version = int(row.get("lifecycle_version", 0))
        db_status = row.get("status")
        desired = task.status.value
        # M4 batch 3.1.12 (CRITICAL-1): if the DB is ALREADY at the
        # desired status, the operation is satisfied — idempotent
        # success.  This covers:
        #   - A prior retry of THIS op already committed.
        #   - A NEWER control op achieved the same desired state
        #     (e.g. a pause followed by a remove — both want the
        #     task inactive; the remove sees the pause's DB state
        #     and treats it as success, BUT only if the desired
        #     state is compatible — see below).
        if db_status == desired:
            # Reconcile the in-memory version with the DB.
            task.lifecycle_version = db_version
            self._execution_epoch[task.id] = db_version
            self._pending_persistence.pop(task.id, None)
            # M4 batch 3.1.16B-5: mark journal applied — the op is
            # satisfied (either by this call's CAS or by a prior one).
            if not is_new_op:
                await self._mark_journal_applied(operation_id)
            return True
        # M4 batch 3.1.12 (CRITICAL-1): the DB is NOT at our desired
        # state.  We must persist.  Use (db_version, db_version + 1)
        # as (expected, target) — this SUPERSEDES any prior marker
        # (including a failed prior control op's marker).  Place the
        # marker BEFORE the CAS so ``stop()`` can retry if we crash.
        expected = db_version
        target = db_version + 1
        self._pending_persistence[task.id] = PendingPersistence(
            operation_id=operation_id,
            desired_status=desired,
            expected_version=expected,
            is_control_op=True,
            target_version=target,
        )
        # M4 batch 3.1.16B-5 (CRITICAL): write the durable journal
        # entry BEFORE the CAS.  If the CAS crashes (SIGKILL), the
        # journal entry survives and start() replays it.  Only write
        # for NEW ops — retries already have a journal entry from the
        # first attempt (matched by operation_id).  If the journal
        # write fails, raise WITHOUT popping the marker — stop() will
        # retry the marker, and the next _persist_task_state call for
        # this task will reuse the same operation_id (passed by the
        # retry path) and skip the journal write.
        if is_new_op:
            try:
                await self._write_journal_entry(
                    operation_id=operation_id,
                    task=task,
                    operation_type=operation_type,
                    desired_status=desired,
                    expected_version=expected,
                    target_version=target,
                )
            except Exception:
                logger.error(
                    "cron task %s: could not write journal entry for "
                    "op %s; keeping marker for stop() retry",
                    task.name, operation_id, exc_info=True,
                )
                raise
        try:
            rowcount = await self.db.control_finalize_scheduled_task(
                task.id,
                expected_version=expected,
                target_version=target,
                status=desired,
                next_run=task.next_run.isoformat() if task.next_run else None,
                error=task.error,
            )
        except Exception:
            # The CAS raised — could be commit-then-raise.  Read back
            # to verify.  If the DB is already at ``target_version``
            # with the desired status, treat as success.
            try:
                row2 = await self.db.get_scheduled_task(task.id)
            except Exception:  # noqa: BLE001 — DB unreadable
                raise
            if (
                row2 is not None
                and int(row2.get("lifecycle_version", 0)) == target
                and row2.get("status") == desired
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
                # M4 batch 3.1.16B-5: CAS committed (commit-then-raise)
                # — mark journal applied.
                await self._mark_journal_applied(operation_id)
                return True
            raise
        if rowcount == 0:
            # Version mismatch — either a prior retry already
            # committed (DB at ``target``) or a newer control op
            # happened (DB at > ``target``).  Read back to
            # distinguish.
            try:
                row2 = await self.db.get_scheduled_task(task.id)
            except Exception:  # noqa: BLE001 — treat as failure
                row2 = None
            if (
                row2 is not None
                and int(row2.get("lifecycle_version", 0)) == target
                and row2.get("status") == desired
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
                # M4 batch 3.1.16B-5: idempotent success — mark journal.
                await self._mark_journal_applied(operation_id)
                return True
            # A newer control op won AND achieved a DIFFERENT state.
            # Don't overwrite — but return False so the caller knows
            # the desired state was NOT persisted.  ``remove()`` must
            # NOT pop the task in this case.
            logger.info(
                "cron task %s: control CAS returned 0 — a newer "
                "control operation happened with different state; "
                "not overwriting (returning False)",
                task.name,
            )
            stored = self._pending_persistence.get(task.id)
            if stored is not None and stored.operation_id == operation_id:
                self._pending_persistence.pop(task.id, None)
            # M4 batch 3.1.16B-5: stale entry — mark applied so
            # start() does not replay a superseded intent.
            await self._mark_journal_applied(operation_id)
            return False
        # Success — update in-memory version + clear marker.
        task.lifecycle_version = target
        self._execution_epoch[task.id] = target
        stored = self._pending_persistence.get(task.id)
        if stored is not None and stored.operation_id == operation_id:
            self._pending_persistence.pop(task.id, None)
        # M4 batch 3.1.16B-5: CAS succeeded — mark journal applied.
        await self._mark_journal_applied(operation_id)
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

        M4 batch 3.1.12 (HIGH-2 + acceptance 9): errors now PROPAGATE
        instead of being swallowed.  ``start()`` catches them and
        enters degraded mode.  Previously a load failure left the
        engine with an empty ``_tasks`` dict but ``_running=True`` —
        the tick loop accepted new creations and fired them, while
        pre-existing DB tasks were invisible (and could be re-created
        with the same name, racing the hidden rows).
        """
        if not self.db:
            return
        rows = await self.db.list_scheduled_tasks()
        for row in rows:
            task = _task_from_row(row)
            if task is not None:
                self._tasks[task.id] = task
                # HIGH (batch 3.1.9): initialize the in-memory execution
                # epoch from the durable lifecycle version so control
                # operations and executor writes stay aligned after a
                # restart.
                self._execution_epoch[task.id] = task.lifecycle_version

    async def _reload_one_task_from_db(self, task_id: str) -> None:
        """M4 batch 3.1.13 (CRITICAL-2): per-task reload from the DB.

        Used by the periodic lease sweep to pick up the FAILED state
        for a recovered task WITHOUT overwriting other tasks' in-memory
        state.  Previously the sweep called ``_load_tasks()`` (full
        reload) which blew away the in-memory PAUSED state of a task
        whose ``pause`` persist had failed (in-memory PAUSED, DB
        PENDING) — the reload changed it to PENDING and the tick
        re-fired it.

        Skips the reload if:
          - The task has a pending persistence marker (the marker's
            desired state wins over the DB's recovered state).
          - The task has a live executor (the executor's terminal
            write will finalize the state).
        """
        if not self.db:
            return
        async with self._task_lock(task_id):
            # Don't overwrite a task that has a pending control
            # marker — the marker's desired state wins.
            if task_id in self._pending_persistence:
                return
            # Don't overwrite a task with a live executor.
            exec_task = self._execute_tasks.get(task_id)
            if exec_task is not None and not exec_task.done():
                return
            try:
                row = await self.db.get_scheduled_task(task_id)
            except Exception:  # noqa: BLE001 — DB unreadable
                self._degraded = True
                logger.error(
                    "cron engine: could not reload task %s from DB "
                    "during sweep; entering DEGRADED mode",
                    task_id, exc_info=True,
                )
                return
            if row is None:
                self._tasks.pop(task_id, None)
                return
            task = _task_from_row(row)
            if task is not None:
                self._tasks[task_id] = task
                self._execution_epoch[task_id] = task.lifecycle_version

    async def _revoke_and_recover_lease(
        self, task_id: str, *, now_iso: str,
    ) -> bool:
        """M4 batch 3.1.13 (CRITICAL-1): revoke a live executor whose
        lease has expired, then write FAILED to the DB and reload the
        in-memory task.

        Holds the per-task lock for the entire operation so the tick
        loop cannot publish a new executor for this task while we're
        revoking the old one.

        Returns ``True`` if:
          - The executor was not running, OR
          - The executor terminated within the cancel budget, OR
          - The task has a pending persistence marker (the marker's
            desired state wins — the lease is NOT written as FAILED;
            the marker will be retried by ``stop()`` / reconcile).

        Returns ``False`` if the executor did NOT terminate within the
        cancel budget — the caller must enter degraded mode.  The
        wedged executor stays in ``_execute_tasks`` for ``stop()`` to
        handle.  The DB is NOT written as FAILED in this case — the
        lease survives and the next sweep will retry.
        """
        async with self._task_lock(task_id):
            has_marker = task_id in self._pending_persistence
            exec_task = self._execute_tasks.get(task_id)
            if exec_task is not None and not exec_task.done():
                # Bump epoch so the executor's terminal write is
                # discarded (the lease sweep's FAILED state wins).
                self._bump_epoch(task_id)
                exec_task.cancel()
                done, pending = await asyncio.wait(
                    {exec_task}, timeout=_CANCEL_IN_FLIGHT_TIMEOUT,
                )
                if exec_task not in done:
                    # Executor did NOT terminate — return False so
                    # the caller enters degraded mode.  The wedged
                    # executor stays in ``_execute_tasks``.
                    return False
                # Executor terminated — pop it (identity check in
                # case a new owner was registered).
                if self._execute_tasks.get(task_id) is exec_task:
                    self._execute_tasks.pop(task_id, None)
            if has_marker:
                # The marker's desired state wins — don't write FAILED.
                # The marker will be retried by ``stop()`` or the
                # next reconcile.  The executor (if alive) was still
                # cancelled above — it should not keep producing side
                # effects.
                logger.info(
                    "cron task %s: lease sweep skipped FAILED write — "
                    "pending persistence marker present (desired %r); "
                    "marker will be retried",
                    task_id,
                    self._pending_persistence[task_id].desired_status,
                )
                return True
            # No marker — safe to write FAILED to the DB.
            try:
                recovered = await self.db.recover_one_expired_lease(
                    task_id, now_iso=now_iso,
                )
            except Exception:  # noqa: BLE001 — DB error
                self._degraded = True
                logger.error(
                    "cron task %s: lease sweep could not write FAILED; "
                    "entering DEGRADED mode",
                    task_id, exc_info=True,
                )
                # M4 batch 3.1.14 (CRITICAL-1): return False so the
                # tick loop's ``if not ok: break`` fires — no other
                # due task may start in this iteration.  Previously
                # this returned True, so the tick kept iterating
                # ``expired_ids`` and then fell through to
                # ``due_candidates``, starting unrelated tasks despite
                # the DB state being untrusted.
                return False
            if recovered:
                logger.warning(
                    "cron task %s: lease sweep wrote FAILED (executor "
                    "revoked + lease cleared)",
                    task_id,
                )
                # Reload the in-memory task to pick up the FAILED state.
                try:
                    row = await self.db.get_scheduled_task(task_id)
                except Exception:  # noqa: BLE001 — DB unreadable
                    self._degraded = True
                    return True
                if row is None:
                    self._tasks.pop(task_id, None)
                    return True
                task = _task_from_row(row)
                if task is not None:
                    self._tasks[task_id] = task
                    self._execution_epoch[task_id] = task.lifecycle_version
            return True


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
        # M4 batch 3.1.16B-1: restore the security-context snapshot
        # so B-2 drift detection can compare against the live values.
        # Legacy rows (empty policy_digest) are quarantined by the
        # migration helper, so they'd never reach here — but if a
        # row somehow reached here without a snapshot, defaulting to
        # empty strings keeps the invariant (B-2 will fail-closed).
        policy_digest=str(row.get("policy_digest") or ""),
        project_id=str(row.get("project_id") or ""),
    )


def _parse_dt(value) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value))
    except (ValueError, TypeError):
        return None
