"""Recovery owner for the cron scheduler.

This module owns durable recovery: pending persistence reconciliation,
journal replay, lease recovery, snapshot-drift quarantine, and loading
tasks from the repository. It deliberately has no lifecycle loop of its
own; CronEngine supplies the shared state and composes this owner.
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass
from datetime import datetime

from khaos.exceptions import ServiceShutdownError
from khaos.scheduler.models import ScheduleConfig, ScheduledTask, TaskStatus

logger = logging.getLogger(__name__)


@dataclass
class PendingPersistence:
    """A terminal state that is set in memory but not yet durable.

    The marker is immutable for one operation. Its operation id prevents
    stale executor writes from clearing a newer control operation, while
    the desired status and version snapshot let recovery continue even after
    remove() removes the task from the in-memory collection.
    """

    operation_id: str
    desired_status: str
    expected_version: int
    is_control_op: bool
    target_version: int = 0


class SchedulerRecovery:
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
            except TimeoutError:
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
            except Exception:
                logger.exception(
                    "cron engine: could not persist terminal state for "
                    "task %s — durability gap, refusing to continue "
                    "teardown",
                    task_id
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
            row = await self._task_repository.get_task(task_id)
        except Exception:
            logger.exception(
                "cron task %s: reconcile could not read DB — "
                "durability gap",
                task_id
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
            rowcount = await self._task_repository.control_finalize(
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
                row2 = await self._task_repository.get_task(task_id)
            except Exception:
                logger.exception(
                    "cron task %s: reconcile CAS raised and read-back "
                    "failed — durability gap",
                    task_id
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
            logger.exception(
                "cron task %s: reconcile CAS raised and read-back "
                "does not match target — durability gap",
                task_id
            )
            return False
        if rowcount == 0:
            # CAS mismatch — check if prior retry committed or a
            # newer op won.
            try:
                row2 = await self._task_repository.get_task(task_id)
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
        except Exception:
            logger.exception(
                "cron task %s: executor reconcile CAS raised — "
                "durability gap",
                task_id
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
            row = await self._task_repository.get_task(task_id)
        except Exception:
            logger.exception(
                "cron task %s: executor reconcile could not read "
                "DB — durability gap; keeping marker",
                task_id
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
        await self._task_repository.insert_journal_entry(
            operation_id=operation_id,
            task_id=task.id,
            operation_type=operation_type,
            desired_status=desired_status,
            expected_version=expected_version,
            target_version=target_version,
            principal_id=task.principal_id,
            policy_digest=self._policy_digest,
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
            await self._task_repository.mark_journal_applied(operation_id)
        except Exception:
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
            entries = await self._task_repository.list_pending_journal_entries()
        except Exception:
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
                row = await self._task_repository.get_task(task_id)
            except Exception:
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
            except Exception:
                logger.exception(
                    "cron engine start: could not roll-forward journal "
                    "entry %s for task %s — leaving entry pending for "
                    "next start()",
                    op_id, task_id,
                )
        if replayed or skipped_stale:
            logger.info(
                "cron engine start: journal replay — %d rolled forward, "
                "%d marked stale",
                replayed, skipped_stale,
            )

    def _check_snapshot_drift(self, task: ScheduledTask) -> str | None:
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

    async def _quarantine_drifted_task(self, task: ScheduledTask, reason: str) -> None:
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
            except Exception:
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
            except Exception:
                logger.exception(
                    "cron task %s: could not persist FAILED state for "
                    "drifted task; will be retried by stop()",
                    task.name,
                )

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
        rows = await self._task_repository.list_tasks()
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
                row = await self._task_repository.get_task(task_id)
            except Exception:
                self._degraded = True
                logger.exception(
                    "cron engine: could not reload task %s from DB "
                    "during sweep; entering DEGRADED mode",
                    task_id
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
        # Read the owner constant at call time so tests and operators can
        # tune the bounded cancellation budget without creating an import
        # cycle between the execution and recovery owners.
        from khaos.scheduler import execution as execution_owner

        cancel_timeout = execution_owner._CANCEL_IN_FLIGHT_TIMEOUT
        async with self._task_lock(task_id):
            has_marker = task_id in self._pending_persistence
            exec_task = self._execute_tasks.get(task_id)
            if exec_task is not None and not exec_task.done():
                # Bump epoch so the executor's terminal write is
                # discarded (the lease sweep's FAILED state wins).
                self._bump_epoch(task_id)
                exec_task.cancel()
                done, _pending = await asyncio.wait(
                    {exec_task}, timeout=cancel_timeout,
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
                recovered = await self._task_repository.recover_one_expired(
                    task_id, now_iso=now_iso,
                )
            except Exception:
                self._degraded = True
                logger.exception(
                    "cron task %s: lease sweep could not write FAILED; "
                    "entering DEGRADED mode",
                    task_id
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
                    row = await self._task_repository.get_task(task_id)
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


def _parse_dt(value) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value))
    except (ValueError, TypeError):
        return None
