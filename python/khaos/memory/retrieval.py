"""Deterministic memory-layer selection and ranking policy."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC

from khaos.memory.models import Memory, MemoryScope


def memory_updated_timestamp(memory: Memory) -> float:
    """Return a comparable UTC timestamp for legacy and current rows."""

    updated_at = memory.updated_at
    if updated_at is None:
        return float("-inf")
    if updated_at.tzinfo is None:
        updated_at = updated_at.replace(tzinfo=UTC)
    return updated_at.timestamp()


@dataclass(frozen=True, slots=True)
class MemoryLayers:
    """The three candidate sets used by prompt injection."""

    global_memories: list[Memory]
    current_mode_memories: list[Memory]
    cross_mode_memories: list[Memory]


class MemoryRetriever:
    """Classify and rank already-loaded memories without persistence I/O."""

    def build_layers(
        self,
        global_memories: list[Memory],
        current_mode_memories: list[Memory],
        all_memories: list[Memory],
        current_scope: MemoryScope,
    ) -> MemoryLayers:
        """Build L0/L1/L2 candidates with stable, explicit ordering."""

        cross_mode = sorted(
            (
                memory
                for memory in all_memories
                if memory.scope not in {MemoryScope.GLOBAL, current_scope}
            ),
            key=lambda memory: (
                memory.confidence.value,
                memory.access_freq,
                memory_updated_timestamp(memory),
                memory.id if memory.id is not None else -1,
            ),
            reverse=True,
        )
        return MemoryLayers(
            global_memories=global_memories,
            current_mode_memories=current_mode_memories,
            cross_mode_memories=cross_mode,
        )


__all__ = ["MemoryLayers", "MemoryRetriever", "memory_updated_timestamp"]
