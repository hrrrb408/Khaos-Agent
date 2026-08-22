"""Persistence ports and the SQLite adapter for durable memories."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Protocol

from khaos.db.repositories.memories import MemorySqlRepository
from khaos.memory.ownership import MemoryVisibility

MemoryRow = Mapping[str, Any]


class MemoryRepository(Protocol):
    """Persistence contract consumed by :class:`MemoryStore`.

    The port carries ownership on every operation.  This makes it impossible
    for an in-memory implementation or a future backend to silently fall back
    to an unscoped read/write.
    """

    async def get(
        self,
        scope: str,
        key: str,
        *,
        principal_id: str,
        namespace: str,
        session_id: str,
        project_id: str,
    ) -> MemoryRow | None: ...

    async def upsert(
        self,
        scope: str,
        key: str,
        value: str,
        ttl: int,
        confidence: int,
        *,
        principal_id: str,
        namespace: str,
        session_id: str,
        project_id: str,
    ) -> int: ...

    async def delete(
        self,
        scope: str,
        key: str,
        *,
        principal_id: str,
        namespace: str,
        session_id: str,
        project_id: str,
    ) -> None: ...

    async def delete_by_id(
        self,
        memory_id: int,
        *,
        principal_id: str,
        project_id: str,
        visibility: MemoryVisibility | None = None,
    ) -> None: ...

    async def list(
        self,
        scope: str | None = None,
        *,
        principal_id: str,
        project_id: str,
        visibility: MemoryVisibility | None = None,
    ) -> Sequence[MemoryRow]: ...

    async def search(
        self,
        query: str,
        top_k: int,
        *,
        principal_id: str,
        project_id: str,
        visibility: MemoryVisibility | None = None,
    ) -> Sequence[MemoryRow]: ...

    async def touch(
        self,
        memory_id: int,
        *,
        principal_id: str,
        project_id: str,
        visibility: MemoryVisibility | None = None,
    ) -> None: ...


class SqliteMemoryRepository(MemorySqlRepository):
    """SQLite implementation of the memory repository port.

    SQL lives in :mod:`khaos.db.repositories.memories`; this name is kept in
    the memory package as the composition-root adapter used by callers.
    """


__all__ = ["MemoryRepository", "MemoryRow", "SqliteMemoryRepository"]
