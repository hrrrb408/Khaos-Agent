"""SQLite-backed memory store with FTS5 search."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Optional


class MemoryScope(Enum):
    """Memory visibility scope."""

    GLOBAL = "global"
    OFFICE = "office"
    CODING = "coding"


class MemoryConfidence(Enum):
    """Memory confidence level."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3


@dataclass
class Memory:
    """One durable memory entry."""

    id: Optional[int]
    scope: MemoryScope
    key: str
    value: str
    ttl: int = 604800
    confidence: MemoryConfidence = MemoryConfidence.MEDIUM
    access_freq: int = 0
    created_at: datetime | None = None
    updated_at: datetime | None = None


class MemoryStore:
    """Three-scope memory storage."""

    def __init__(self, db):
        self.db = db

    async def get(self, scope: MemoryScope, key: str) -> Memory | None:
        row = await self.db.get_memory(scope.value, key)
        return self._from_row(row) if row is not None else None

    async def set(self, memory: Memory) -> Memory:
        memory_id = await self.db.upsert_memory(
            memory.scope.value,
            memory.key,
            memory.value,
            memory.ttl,
            memory.confidence.value,
        )
        stored = await self.get(memory.scope, memory.key)
        assert stored is not None
        stored.id = memory_id
        return stored

    async def delete(self, scope: MemoryScope, key: str) -> None:
        await self.db.delete_memory(scope.value, key)

    async def list_by_scope(self, scope: MemoryScope) -> list[Memory]:
        return [self._from_row(row) for row in await self.db.list_memories(scope.value)]

    async def list_all(self) -> list[Memory]:
        return [self._from_row(row) for row in await self.db.list_memories()]

    async def search(self, query: str, top_k: int = 5) -> list[Memory]:
        memories = [self._from_row(row) for row in await self.db.search_memories(query, top_k)]
        for memory in memories:
            if memory.id is not None:
                await self.touch(memory.id)
        return memories

    async def touch(self, memory_id: int) -> None:
        await self.db.touch_memory(memory_id)

    @staticmethod
    def _from_row(row: dict) -> Memory:
        return Memory(
            id=int(row["id"]),
            scope=MemoryScope(str(row["scope"])),
            key=str(row["key"]),
            value=str(row["value"]),
            ttl=int(row["ttl"]),
            confidence=MemoryConfidence(int(row["confidence"])),
            access_freq=int(row["access_freq"]),
            created_at=_parse_datetime(row.get("created_at")),
            updated_at=_parse_datetime(row.get("updated_at")),
        )


def _parse_datetime(value) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(str(value))

