"""Round-4 review Batch 4 (§11.2): periodic maintenance service.

Runs GC and cleanup tasks on a fixed interval (default: hourly) to
prevent unbounded resource growth in long-running processes.

Tasks:
  - ``prune_terminal_chat_streams``: delete chat ledger events for
    sessions that have been terminal for longer than the retention
    window (default: 24 hours).
  - ``ApprovalBroker.sweep_expired``: evict consumed and expired
    approval records.

Round-5 Batch 5.2 (C-05): ``recover_inflight_chat_streams`` has been
REMOVED from the periodic loop.  Recovery now runs ONLY once at process
startup (see ``grpc_server._recover_inflight_at_startup``) using a
``boot_id`` to avoid recovering streams owned by the current process.
Calling recovery periodically was the C-05 bug: hourly maintenance
terminated active chats that were waiting on long tool calls because
their lease had expired between heartbeat renewals.

Future tasks (deferred to a later batch):
  - prune idle task managers
  - cleanup stale cgroups/netns/wrappers
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import TYPE_CHECKING

from khaos.db import Database

if TYPE_CHECKING:
    from khaos.agent.approval import ApprovalBroker

logger = logging.getLogger(__name__)

# Default retention: chat ledgers older than 24 hours are pruned.
_DEFAULT_RETENTION_SECONDS = 24 * 3600
# Default interval: run every hour.
_DEFAULT_INTERVAL_SECONDS = 3600
# Default TTL for approval broker records.
_DEFAULT_APPROVAL_TTL_SECONDS = 3600.0
# Batch 6.5 (round-6 §25.3): retention for the DURABLE approval ledger
# (operation_approvals / operation_approval_events rows).  The in-memory
# ``ApprovalBroker.sweep_expired`` clears the dicts; the DB rows need their
# own pruning or they grow without bound.  7 days keeps recently-resolved
# approvals auditable while bounding storage.
_DEFAULT_APPROVAL_LEDGER_RETENTION_SECONDS = 7 * 24 * 3600


class MaintenanceService:
    """Periodic GC and cleanup for long-running processes.

    Round-4 review Batch 4 (§11.2 + §13.1): runs the following tasks
    on a fixed schedule (default: hourly):

      - ``prune_terminal_chat_streams``: delete chat ledger events for
        sessions that have been terminal for longer than the retention
        window (default: 24 hours).  Previously these GC methods existed
        but had no production caller.
      - ``ApprovalBroker.sweep_expired``: evict consumed and expired
        approval records.  Previously the broker kept every record
        forever, causing unbounded memory growth.

    Round-5 Batch 5.2 (C-05): ``recover_inflight_chat_streams`` was
    REMOVED from the periodic loop.  Recovery is now a startup-only
    operation owned by ``grpc_server`` (which passes the current
    ``boot_id`` to avoid recovering the current process's own active
    streams).  See the module docstring for the rationale.

    The service is best-effort: if a GC cycle raises, the error is
    logged and the next cycle proceeds normally.  It never crashes the
    host process.
    """

    def __init__(
        self,
        db: Database,
        *,
        approval_broker: "ApprovalBroker | None" = None,
        interval_seconds: float = _DEFAULT_INTERVAL_SECONDS,
        retention_seconds: float = _DEFAULT_RETENTION_SECONDS,
        approval_ttl_seconds: float = _DEFAULT_APPROVAL_TTL_SECONDS,
        approval_ledger_retention_seconds: float = _DEFAULT_APPROVAL_LEDGER_RETENTION_SECONDS,
    ) -> None:
        self._db = db
        self._approval_broker = approval_broker
        self._interval = max(60.0, interval_seconds)
        self._retention = retention_seconds
        self._approval_ttl = approval_ttl_seconds
        self._approval_ledger_retention = approval_ledger_retention_seconds
        self._task: asyncio.Task[None] | None = None
        self._running = False

    def start(self) -> None:
        """Start the periodic maintenance loop as a background task."""
        if self._task is not None:
            return
        self._running = True
        self._task = asyncio.create_task(self._loop(), name="maintenance")

    async def stop(self) -> None:
        """Stop the maintenance loop and wait for it to finish."""
        self._running = False
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

    async def _loop(self) -> None:
        """Run ``run_once`` on a fixed interval until ``stop()``."""
        # Run an initial cycle immediately on startup.
        await self.run_once()
        while self._running:
            try:
                await asyncio.sleep(self._interval)
            except asyncio.CancelledError:
                return
            if not self._running:
                return
            await self.run_once()

    async def run_once(self) -> dict[str, int]:
        """Run one GC cycle and return a summary of cleanup counts."""
        counts: dict[str, int] = {}
        now = time.time()

        # 1. Prune terminal chat streams older than retention.
        try:
            deleted = await self._db.prune_terminal_chat_streams(
                older_than_seconds=self._retention,
                now=now,
            )
            if deleted > 0:
                counts["chat_streams_pruned"] = deleted
                logger.info("maintenance: pruned %d terminal chat streams", deleted)
        except Exception as exc:  # noqa: BLE001
            logger.error("maintenance: prune_terminal_chat_streams failed: %s", exc)

        # 2. Sweep expired approval broker records (§13.1).
        #
        # C-05 (round-5 Batch 5.2): ``recover_inflight_chat_streams`` was
        # REMOVED from the periodic loop.  Recovery is now a startup-only
        # operation owned by ``grpc_server`` (which passes the current
        # ``boot_id``).  Calling recovery periodically was the C-05 bug:
        # hourly maintenance terminated active chats that were waiting on
        # long tool calls because their lease had expired between
        # heartbeat renewals.
        if self._approval_broker is not None:
            try:
                swept = await self._approval_broker.sweep_expired(
                    ttl_seconds=self._approval_ttl,
                )
                total = sum(swept.values())
                if total > 0:
                    counts["approvals_swept"] = total
                    logger.info("maintenance: swept %d expired approvals", total)
            except Exception as exc:  # noqa: BLE001
                logger.error("maintenance: approval sweep failed: %s", exc)

        # 3. Batch 6.5 (round-6 §25.3): prune the DURABLE approval ledger.
        #    ``sweep_expired`` only clears the in-memory dicts; the DB rows
        #    in ``operation_approvals`` / ``operation_approval_events`` grow
        #    without bound otherwise.  Runs in its own try so a failure
        #    does not skip subsequent cycles.
        try:
            pruned = await self._db.prune_approval_ledger(
                retention_seconds=int(self._approval_ledger_retention),
            )
            total_pruned = sum(pruned.values())
            if total_pruned > 0:
                counts["approval_ledger_pruned"] = total_pruned
                logger.info(
                    "maintenance: pruned %d durable approval rows (%s)",
                    total_pruned, pruned,
                )
        except Exception as exc:  # noqa: BLE001
            logger.error("maintenance: prune_approval_ledger failed: %s", exc)

        return counts

