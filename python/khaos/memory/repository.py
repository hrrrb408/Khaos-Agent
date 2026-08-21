"""Persistence ports and the SQLite adapter for durable memories."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Protocol

from khaos.db import Database

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
    ) -> None: ...

    async def list(
        self,
        scope: str | None = None,
        *,
        principal_id: str,
        project_id: str,
    ) -> Sequence[MemoryRow]: ...

    async def search(
        self,
        query: str,
        top_k: int,
        *,
        principal_id: str,
        project_id: str,
    ) -> Sequence[MemoryRow]: ...

    async def touch(
        self,
        memory_id: int,
        *,
        principal_id: str,
        project_id: str,
    ) -> None: ...


class SqliteMemoryRepository:
    """Adapt the database memory methods to the repository port.

    SQL remains in ``Database``.  This adapter is the only persistence object
    the memory domain needs to know about, which gives tests a small seam for a
    fake repository and keeps the aggregate free of storage details.
    """

    def __init__(self, db: Database) -> None:
        self._db = db

    async def get(
        self,
        scope: str,
        key: str,
        *,
        principal_id: str,
        namespace: str,
        session_id: str,
        project_id: str,
    ) -> MemoryRow | None:
        return await self._db.get_memory(
            scope,
            key,
            principal_id=principal_id,
            namespace=namespace,
            session_id=session_id,
            project_id=project_id,
        )

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
    ) -> int:
        return await self._db.upsert_memory(
            scope,
            key,
            value,
            ttl,
            confidence,
            principal_id=principal_id,
            namespace=namespace,
            session_id=session_id,
            project_id=project_id,
        )

    async def delete(
        self,
        scope: str,
        key: str,
        *,
        principal_id: str,
        namespace: str,
        session_id: str,
        project_id: str,
    ) -> None:
        await self._db.delete_memory(
            scope,
            key,
            principal_id=principal_id,
            namespace=namespace,
            session_id=session_id,
            project_id=project_id,
        )

    async def delete_by_id(
        self,
        memory_id: int,
        *,
        principal_id: str,
        project_id: str,
    ) -> None:
        await self._db.delete_memory_by_id(
            memory_id,
            principal_id=principal_id,
            project_id=project_id,
        )

    async def list(
        self,
        scope: str | None = None,
        *,
        principal_id: str,
        project_id: str,
    ) -> Sequence[MemoryRow]:
        return await self._db.list_memories(
            scope,
            principal_id=principal_id,
            project_id=project_id,
        )

    async def search(
        self,
        query: str,
        top_k: int,
        *,
        principal_id: str,
        project_id: str,
    ) -> Sequence[MemoryRow]:
        return await self._db.search_memories(
            query,
            top_k,
            principal_id=principal_id,
            project_id=project_id,
        )

    async def touch(
        self,
        memory_id: int,
        *,
        principal_id: str,
        project_id: str,
    ) -> None:
        await self._db.touch_memory(
            memory_id,
            principal_id=principal_id,
            project_id=project_id,
        )


__all__ = ["MemoryRepository", "MemoryRow", "SqliteMemoryRepository"]
