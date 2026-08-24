"""Recoverable Memory V2 rebuild and consistency verification."""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from time import monotonic
from typing import Any, cast

from khaos.memory.core.broker import MemoryBroker
from khaos.memory.core.contracts import RuntimeMemoryContext

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class ConsistencyReport:
    """Bounded provider consistency result."""

    supported: bool
    consistent: bool
    counts: dict[str, int | bool]


@dataclass(frozen=True, slots=True)
class RebuildReport:
    """Result of a ledger replay followed by index reconstruction."""

    replayed_nodes: int
    indexed_nodes: int
    consistency: ConsistencyReport
    duration_ms: int


@dataclass(frozen=True, slots=True)
class MaintenanceReport:
    """Complete bounded maintenance result for one runtime scope."""

    deduplicated_evidence: int
    lifecycle_tiers: dict[str, int]
    rebuild: RebuildReport | None
    consistency: ConsistencyReport
    duration_ms: int


class MemoryMaintenanceService:
    """Run explicit, bounded maintenance outside the AgentLoop hot path."""

    def __init__(self, broker: MemoryBroker) -> None:
        self.broker = broker

    async def rebuild(
        self,
        runtime: RuntimeMemoryContext,
        *,
        from_ledger: bool = True,
        limit: int = 10_000,
    ) -> RebuildReport:
        """Replay canonical candidate events and rebuild provider indexes."""

        started = monotonic()
        await self.broker.record_audit(
            "MEMORY_REBUILD_STARTED",
            runtime,
            detail={"from_ledger": from_ledger, "limit": limit},
        )
        replayed = 0
        if from_ledger:
            replayed = await self.broker.rebuild_from_ledger(runtime, limit=limit)
        indexed = await self.broker.rebuild()
        consistency = await self.verify(runtime)
        duration_ms = max(0, int((monotonic() - started) * 1000))
        await self.broker.record_audit(
            "MEMORY_REBUILD_FINISHED",
            runtime,
            detail={
                "replayed_nodes": replayed,
                "indexed_nodes": indexed,
                "consistent": consistency.consistent,
                "duration_ms": duration_ms,
            },
        )
        observability = getattr(self.broker, "observability", None)
        record = getattr(observability, "record", None)
        if callable(record):
            try:
                await cast(Callable[..., Awaitable[Any]], record)(
                    "memory.rebuild.duration_ms",
                    duration_ms,
                    runtime,
                    unit="ms",
                    provider_id=self.broker.provider.provider_id,
                    profile_id=(
                        self.broker.profile.profile_id
                        if self.broker.profile is not None
                        else ""
                    ),
                    operation="rebuild",
                    metadata={"consistent": consistency.consistent},
                )
            except Exception:
                logger.debug("memory rebuild metric recording failed", exc_info=True)
        return RebuildReport(
            replayed_nodes=replayed,
            indexed_nodes=indexed,
            consistency=consistency,
            duration_ms=duration_ms,
        )

    async def verify(self, runtime: RuntimeMemoryContext) -> ConsistencyReport:
        """Verify rebuildable indexes without treating them as authority."""

        del runtime
        verifier = getattr(self.broker.provider, "verify_indexes", None)
        if not callable(verifier):
            return ConsistencyReport(False, False, {})
        counts = dict(await cast(Callable[..., Awaitable[Any]], verifier)())
        return ConsistencyReport(
            supported=True,
            consistent=bool(counts.get("consistent", False)),
            counts=counts,
        )

    async def maintain(
        self,
        runtime: RuntimeMemoryContext,
        *,
        rebuild: bool = True,
        limit: int = 10_000,
    ) -> MaintenanceReport:
        """Run deduplication, lifecycle refresh, rebuild, and verification."""

        if limit <= 0 or limit > 10_000:
            raise ValueError("maintenance limit is outside the bounded range")
        started = monotonic()
        await self.broker.record_audit(
            "MEMORY_MAINTENANCE_STARTED",
            runtime,
            detail={"rebuild": rebuild, "limit": limit},
        )
        overrides = (
            dict(self.broker.profile.maintenance_overrides)
            if self.broker.profile is not None
            else {}
        )
        deduplicate = getattr(self.broker.provider, "deduplicate_evidence", None)
        deduplicated = (
            int(
                await cast(Callable[..., Awaitable[Any]], deduplicate)(
                    runtime,
                    limit=min(limit, 10_000),
                )
            )
            if callable(deduplicate)
            and overrides.get("deduplicate_evidence", True)
            else 0
        )
        refresh = getattr(self.broker.provider, "refresh_lifecycle", None)
        tiers = (
            dict(
                await cast(Callable[..., Awaitable[Any]], refresh)(
                    runtime,
                    limit=limit,
                )
            )
            if callable(refresh) and overrides.get("refresh_lifecycle", True)
            else {}
        )
        rebuild_report = (
            await self.rebuild(runtime, limit=limit)
            if rebuild and overrides.get("rebuild", True)
            else None
        )
        consistency = rebuild_report.consistency if rebuild_report is not None else await self.verify(runtime)
        duration_ms = max(0, int((monotonic() - started) * 1000))
        await self.broker.record_audit(
            "MEMORY_MAINTENANCE_FINISHED",
            runtime,
            detail={
                "deduplicated_evidence": deduplicated,
                "lifecycle_tiers": tiers,
                "consistent": consistency.consistent,
                "duration_ms": duration_ms,
            },
        )
        return MaintenanceReport(
            deduplicated_evidence=deduplicated,
            lifecycle_tiers=tiers,
            rebuild=rebuild_report,
            consistency=consistency,
            duration_ms=duration_ms,
        )


__all__ = [
    "ConsistencyReport",
    "MaintenanceReport",
    "MemoryMaintenanceService",
    "RebuildReport",
]
