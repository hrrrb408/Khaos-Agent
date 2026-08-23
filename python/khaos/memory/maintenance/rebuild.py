"""Recoverable Memory V2 rebuild and consistency verification."""

from __future__ import annotations

from dataclasses import dataclass
from time import monotonic

from khaos.memory.core.broker import MemoryBroker
from khaos.memory.core.contracts import RuntimeMemoryContext


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
                await record(
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
            except Exception:  # noqa: BLE001 - metrics are non-authoritative
                pass
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
        counts = dict(await verifier())
        return ConsistencyReport(
            supported=True,
            consistent=bool(counts.get("consistent", False)),
            counts=counts,
        )


__all__ = ["ConsistencyReport", "MemoryMaintenanceService", "RebuildReport"]
