"""Execution owner for the cron scheduler.

This module owns executor admission, tick scheduling, execution leases,
terminal-state publication, and the per-task execution fences. CronEngine
composes this owner with the lifecycle and recovery owners so the public
facade remains small without duplicating state-machine logic.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import time
import uuid
from collections.abc import Awaitable, Callable
from datetime import datetime, timedelta
from typing import Any

from khaos.exceptions import ServiceShutdownError
from khaos.scheduler.calculator import ScheduleCalculator
from khaos.scheduler.due_selector import DueTaskSelector
from khaos.scheduler.models import ScheduledTask, TaskStatus
from khaos.scheduler.recovery import PendingPersistence
from khaos.time_utils import utc_now_naive

logger = logging.getLogger(__name__)

# M1 (round-8): bounded cancellation budget for a single in-flight
# execution. Tests patch this owner constant deliberately so the
# cancellation boundary remains explicit.
_CANCEL_IN_FLIGHT_TIMEOUT = 10.0

# M4 batch 3.1.10: durable execution lease duration.  The execution
# owner keeps this default next to claim/finalize behavior; callers may
# override it through CronEngine(execution_lease_seconds=...).
EXECUTION_LEASE_SECONDS = 600.0

# M4 (round-3.1.12): periodic lease-sweep interval for detecting
# in-process executor hangs.
LEASE_SWEEP_INTERVAL_SECONDS = 60.0


class SchedulerExecution:
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
        done, _pending = await asyncio.wait(
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
        """Delegate pure schedule calculation to the dedicated calculator."""
        return ScheduleCalculator.compute(task)

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
            now = utc_now_naive()
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
                    expired_ids = await self._task_repository.query_expired_lease_task_ids(
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
                except Exception:
                    logger.exception(
                        "periodic lease sweep failed; entering "
                        "DEGRADED mode"
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
            due_candidates = DueTaskSelector.select(
                self._tasks.values(),
                now=now,
                pending_persistence_ids=self._pending_persistence,
                executing_ids={
                    task_id
                    for task_id, owner in self._execute_tasks.items()
                    if not owner.done()
                },
            )
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
                except TimeoutError:
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
                except Exception:
                    logger.exception(
                        "cron task %s: could not persist FAILED state "
                        "for unauthenticated-principal task",
                        task.name
                    )
            return

        # ── TOCTOU closure (round-11 review Critical-2/High-1) ──────────────
        # Snapshot the authenticated principal_id into a LOCAL variable
        # immediately after the check above, BEFORE any ``await`` (the
        # durable-claim DB call below yields control).  The mutable
        # ``task.principal_id`` can be changed concurrently (a test
        # corrupting the row, a future ``cron_migrate``, a control op),
        # so the executor MUST receive the snapshot, never a re-read of
        # ``task.principal_id``.  Without this, the check at line 2629
        # passes on ``"alice"``, an await yields, the field becomes ``""``,
        # and line ~2773 re-reads it into the executor — a classic
        # check-then-use race that silently executes as the server UID.
        bound_principal_id = task.principal_id
        # Round-12 review P1-2: also snapshot project_id and policy_digest
        # before the durable-claim await, and bind them into the DB CAS so a
        # drifted DB row cannot be claimed under a stale in-memory identity.
        bound_project_id = task.project_id
        bound_policy_digest = task.policy_digest

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
        started_at_dt = utc_now_naive()
        # M4 batch 3.1.10 (HIGH-3): durable execution claim.
        execution_id = uuid.uuid4().hex
        lease_until_dt = started_at_dt + timedelta(seconds=self._execution_lease_seconds)
        if self.db:
            # M4 batch 3.1.11 (CRITICAL-1): fail-closed on claim.
            claim_committed = False
            try:
                rowcount = await self._task_repository.claim_task(
                    task.id,
                    execution_id=execution_id,
                    started_at=started_at_dt.isoformat(),
                    lease_until=lease_until_dt.isoformat(),
                    expected_version=version_at_start,
                    principal_id=bound_principal_id,
                    policy_digest=bound_policy_digest,
                    project_id=bound_project_id,
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
            except Exception:
                # Claim raised — could be DB error OR commit-then-raise.
                # Read back to verify whether the claim actually
                # committed.  Only proceed if the DB shows EXACTLY our
                # execution_id + RUNNING + expected version.
                logger.exception(
                    "cron task %s: durable claim raised; verifying "
                    "whether the claim committed (commit-then-raise)",
                    task.name,
                )
                try:
                    row = await self._task_repository.get_task(task.id)
                except Exception:
                    logger.exception(
                        "cron task %s: could not read back row after "
                        "claim exception; FAIL-CLOSED — refusing to "
                        "execute without confirmed lease",
                        task.name
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
                #
                # TOCTOU closure (round-11 review): use the snapshot
                # ``bound_principal_id`` captured before the durable-claim
                # await, NOT ``task.principal_id`` (which a concurrent
                # mutation could have cleared to empty).
                result = await self._executor(task.id, task.prompt, bound_principal_id)
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
            if task.schedule.iso_time or task.schedule.repeat and task.run_count >= task.schedule.repeat:
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
            except Exception:
                logger.exception(
                    "cron task %s: could not finalize cancelled "
                    "terminal state; lease RETAINED for restart "
                    "recovery; will retry on stop()",
                    task.name,
                )
            raise
        except Exception as exc:  # noqa: BLE001 - terminal persistence failure is retained
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
        except Exception:
            logger.exception(
                "cron task %s: could not finalize terminal state %s; "
                "lease RETAINED for restart recovery; will retry on stop()",
                task.name, task.status.value,
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
            await self._task_repository.clear_lease(
                task.id, execution_id=execution_id,
            )
        except Exception:
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
        rowcount = await self._task_repository.finalize_task(
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
            row = await self._task_repository.get_task(task.id)
        except Exception:
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
                logger.exception(
                    "cron task %s: could not write journal entry for "
                    "op %s; keeping marker for stop() retry",
                    task.name, operation_id,
                )
                raise
        try:
            rowcount = await self._task_repository.control_finalize(
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
            row2 = await self._task_repository.get_task(task.id)
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
                row2 = await self._task_repository.get_task(task.id)
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
