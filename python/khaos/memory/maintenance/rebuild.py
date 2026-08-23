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
        replayed = 0
        if from_ledger:
            replayed = await self.broker.rebuild_from_ledger(runtime, limit=limit)
        indexed = await self.broker.rebuild()
        consistency = await self.verify(runtime)
        return RebuildReport(
            replayed_nodes=replayed,
            indexed_nodes=indexed,
            consistency=consistency,
            duration_ms=max(0, int((monotonic() - started) * 1000)),
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
