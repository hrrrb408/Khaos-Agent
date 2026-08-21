"""Principal- and project-scoped memory RPC service.

The service owns no transport state.  The caller supplies an immutable
``RequestContext`` and this module constructs a short-lived ``MemoryStore``
from that context for each operation.  Keeping that binding here makes it
harder for a future RPC handler to accidentally reuse a server-level store
with the wrong principal.
"""

from __future__ import annotations

from dataclasses import asdict

from khaos.db import Database
from khaos.memory import (
    Memory,
    MemoryConfidence,
    MemoryScope,
    MemoryStore,
)
from khaos.runtime import RequestContext


class MemoryService:
    """Expose memory operations with context-derived ownership."""

    def __init__(self, db: Database) -> None:
        self.db = db

    def _store(self, ctx: RequestContext) -> MemoryStore:
        """Build a store bound to the authenticated principal and project."""
        return MemoryStore(
            self.db,
            principal_id=ctx.principal_id,
            project_id=ctx.project_id,
        )

    async def get_memory(
        self, ctx: RequestContext, scope: str, key: str
    ) -> dict[str, object]:
        """Return one memory or raise ``KeyError`` when it is not present."""
        memory = await self._store(ctx).get(MemoryScope(scope), key)
        if memory is None:
            raise KeyError(key)
        return memory_to_dict(memory)

    async def set_memory(
        self,
        ctx: RequestContext,
        scope: str,
        key: str,
        value: str,
        ttl: int = 604800,
        confidence: int = 2,
    ) -> dict[str, object]:
        """Create or replace a memory in the caller's scope."""
        memory = await self._store(ctx).set(
            Memory(
                id=None,
                scope=MemoryScope(scope),
                key=key,
                value=value,
                ttl=ttl,
                confidence=MemoryConfidence(confidence),
            )
        )
        # ``MemoryStore.set`` returns the stored row for the supported
        # conflict modes.  Keep the explicit guard so a future unresolved
        # conflict cannot be reported as a successful write.
        if memory is None:
            return {"ok": False, "error": "memory conflict unresolved"}
        return {"ok": True, "id": memory.id}

    async def delete_memory(
        self, ctx: RequestContext, memory_id: int
    ) -> dict[str, object]:
        """Delete only a row owned by this principal and project."""
        # Keep deletion on the same MemoryStore boundary as every other
        # operation so ownership and audit behavior cannot drift between RPC
        # methods and local runtime callers.
        await self._store(ctx).delete_by_id(memory_id)
        return {"ok": True}

    async def search_memory(
        self, ctx: RequestContext, query: str, top_k: int = 5
    ) -> list[dict[str, object]]:
        """Search only the caller's principal/project memory view."""
        memories = await self._store(ctx).search(query, top_k)
        return [memory_to_dict(memory) for memory in memories]


def memory_to_dict(memory: Memory) -> dict[str, object]:
    """Serialize a memory without leaking enum or datetime internals."""
    data: dict[str, object] = asdict(memory)
    data["scope"] = memory.scope.value
    data["confidence"] = memory.confidence.value
    data["created_at"] = memory.created_at.isoformat() if memory.created_at else ""
    data["updated_at"] = memory.updated_at.isoformat() if memory.updated_at else ""
    return data


__all__ = ["MemoryService", "memory_to_dict"]
