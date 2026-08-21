"""Domain facade for principal- and project-scoped durable memories.

``MemoryStore`` is intentionally small: ownership, persistence, conflict
resolution, TTL policy, and extraction each live in their own module.  The
facade preserves the public API used by the runtime and older callers while
preventing SQL and text-parsing details from spreading through the system.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from khaos.memory.conflict import ConflictResolver
from khaos.memory.decay import expired_memory_ids
from khaos.memory.extraction import (
    extract_memories_from_messages,
    extract_memories_from_text,
)
from khaos.memory.models import (
    Memory,
    MemoryConfidence,
    MemoryScope,
    memory_from_row,
)
from khaos.memory.ownership import MemoryOwner
from khaos.memory.repository import MemoryRepository, SqliteMemoryRepository
from khaos.time_utils import utc_now_naive

logger = logging.getLogger(__name__)

MAX_SEARCH_TOP_K = 100
MAX_SEARCH_QUERY_LENGTH = 4096


class MemoryStore:
    """Principal/project-bound memory aggregate.

    The ``db`` positional argument is retained as a migration compatibility
    seam.  New production code can inject a ``MemoryRepository`` directly;
    when ``db`` is supplied, it is wrapped once by
    :class:`SqliteMemoryRepository` and never accessed by this class again.
    """

    def __init__(
        self,
        db: Any | None = None,
        *,
        principal_id: str = "legacy",
        project_id: str = "",
        repository: MemoryRepository | None = None,
        audit_logger: Any | None = None,
    ) -> None:
        if db is not None and repository is not None:
            raise ValueError("pass either db or repository, not both")
        if repository is None:
            if db is None:
                raise ValueError("a database or memory repository is required")
            repository = SqliteMemoryRepository(db)
        self._repository = repository
        self._owner = MemoryOwner(
            principal_id=principal_id,
            project_id=project_id,
        )
        self._audit_logger = audit_logger

    @property
    def principal_id(self) -> str:
        """Return the immutable principal binding."""

        return self._owner.principal_id

    @property
    def project_id(self) -> str:
        """Return the immutable project binding."""

        return self._owner.project_id

    def _effective_principal(self, namespace: str) -> str:
        """Compatibility helper for callers that inspect the old boundary."""

        return self._owner.effective_principal(namespace)

    def _identity(self, namespace: str, session_id: str) -> tuple[str, str, str]:
        self._owner.validate(namespace, session_id)
        return (
            self._owner.effective_principal(namespace),
            namespace,
            session_id,
        )

    async def get(
        self,
        scope: MemoryScope,
        key: str,
        *,
        namespace: str = "private",
        session_id: str = "",
    ) -> Memory | None:
        """Read one memory visible to this store's owner."""

        principal_id, namespace, session_id = self._identity(namespace, session_id)
        row = await self._repository.get(
            scope.value,
            key,
            principal_id=principal_id,
            namespace=namespace,
            session_id=session_id,
            project_id=self.project_id,
        )
        return memory_from_row(row) if row is not None else None

    async def set(
        self,
        memory: Memory,
        on_conflict: str = "overwrite",
        *,
        namespace: str = "private",
        session_id: str = "",
    ) -> Memory | None:
        """Insert or update a memory under the bound ownership context.

        ``overwrite`` preserves the historical API.  ``resolve`` delegates to
        the pure conflict policy and returns ``None`` for an unresolved tie.
        """

        if on_conflict not in {"overwrite", "resolve"}:
            raise ValueError("on_conflict must be 'overwrite' or 'resolve'")
        principal_id, namespace, session_id = self._identity(namespace, session_id)
        existing = await self.get(
            memory.scope,
            memory.key,
            namespace=namespace,
            session_id=session_id,
        )
        if (
            existing is not None
            and existing.value != memory.value
            and on_conflict == "resolve"
        ):
            decision = ConflictResolver.decide(memory, existing)
            if decision.winner is None:
                logger.warning(
                    "memory conflict unresolved for (%s, %s): %s",
                    memory.scope.value,
                    memory.key,
                    decision.reason,
                )
                await self._audit_event(
                    "memory.conflict",
                    f"{memory.scope.value}:{memory.key}",
                    "unresolved",
                    {"reason": decision.reason, "namespace": namespace},
                    session_id,
                )
                return None
            memory = decision.winner
        stored = await self._raw_upsert(
            memory,
            principal_id=principal_id,
            namespace=namespace,
            session_id=session_id,
        )
        await self._audit_event(
            "memory.set",
            f"{memory.scope.value}:{memory.key}",
            "success",
            {
                "namespace": namespace,
                "confidence": memory.confidence.value,
                "ttl": memory.ttl,
            },
            session_id,
        )
        return stored

    async def _raw_upsert(
        self,
        memory: Memory,
        *,
        principal_id: str,
        namespace: str,
        session_id: str,
    ) -> Memory:
        memory_id = await self._repository.upsert(
            memory.scope.value,
            memory.key,
            memory.value,
            memory.ttl,
            memory.confidence.value,
            principal_id=principal_id,
            namespace=namespace,
            session_id=session_id,
            project_id=self.project_id,
        )
        stored = await self.get(
            memory.scope,
            memory.key,
            namespace=namespace,
            session_id=session_id,
        )
        if stored is None:
            raise RuntimeError(
                "memory repository committed an upsert but returned no row"
            )
        stored.id = memory_id
        return stored

    @staticmethod
    def resolve_conflict(new: Memory, existing: Memory) -> Memory | None:
        """Compatibility wrapper around the pure conflict policy."""

        return ConflictResolver.decide(new, existing).winner

    async def decay(self, now: datetime | None = None) -> int:
        """Delete expired visible memories and return the number removed."""

        moment = now or utc_now_naive()
        memories = await self.list_all()
        expired_ids = expired_memory_ids(memories, now=moment)
        for memory_id in expired_ids:
            await self._repository.delete_by_id(
                memory_id,
                principal_id=self.principal_id,
                project_id=self.project_id,
            )
        if expired_ids:
            logger.info("memory decay removed %d expired entries", len(expired_ids))
            await self._audit_event(
                "memory.decay",
                self.project_id or "unbound-project",
                "success",
                {"removed": len(expired_ids)},
                None,
            )
        return len(expired_ids)

    async def delete(
        self,
        scope: MemoryScope,
        key: str,
        *,
        namespace: str = "private",
        session_id: str = "",
    ) -> None:
        """Delete one visible memory by its stable identity."""

        principal_id, namespace, session_id = self._identity(namespace, session_id)
        await self._repository.delete(
            scope.value,
            key,
            principal_id=principal_id,
            namespace=namespace,
            session_id=session_id,
            project_id=self.project_id,
        )
        await self._audit_event(
            "memory.delete",
            f"{scope.value}:{key}",
            "success",
            {"namespace": namespace},
            session_id,
        )

    async def delete_by_id(self, memory_id: int) -> None:
        """Delete one row only when it belongs to this owner/project."""

        if memory_id <= 0:
            raise ValueError("memory_id must be positive")
        await self._repository.delete_by_id(
            memory_id,
            principal_id=self.principal_id,
            project_id=self.project_id,
        )
        await self._audit_event(
            "memory.delete",
            str(memory_id),
            "success",
            {"by": "id"},
            None,
        )

    async def list_by_scope(self, scope: MemoryScope) -> list[Memory]:
        """List memories in one scope visible to the bound principal."""

        rows = await self._repository.list(
            scope.value,
            principal_id=self.principal_id,
            project_id=self.project_id,
        )
        return [memory_from_row(row) for row in rows]

    async def list_all(self) -> list[Memory]:
        """List all private and project-shared memories visible to the owner."""

        rows = await self._repository.list(
            principal_id=self.principal_id,
            project_id=self.project_id,
        )
        return [memory_from_row(row) for row in rows]

    async def search(self, query: str, top_k: int = 5) -> list[Memory]:
        """Search visible memories through the repository's FTS boundary."""

        if not isinstance(query, str) or len(query) > MAX_SEARCH_QUERY_LENGTH:
            raise ValueError("memory search query is missing or too long")
        if top_k < 0 or top_k > MAX_SEARCH_TOP_K:
            raise ValueError(f"top_k must be between 0 and {MAX_SEARCH_TOP_K}")
        if top_k == 0 or not query.strip():
            return []
        rows = await self._repository.search(
            query,
            top_k,
            principal_id=self.principal_id,
            project_id=self.project_id,
        )
        memories = [memory_from_row(row) for row in rows]
        for memory in memories:
            if memory.id is not None:
                await self.touch(memory.id)
        await self._audit_event(
            "memory.search",
            query[:128],
            "success",
            {"returned": len(memories), "top_k": top_k},
            None,
        )
        return memories

    async def touch(self, memory_id: int) -> None:
        """Increment access frequency within the owner/project boundary."""

        if memory_id <= 0:
            raise ValueError("memory_id must be positive")
        await self._repository.touch(
            memory_id,
            principal_id=self.principal_id,
            project_id=self.project_id,
        )
        await self._audit_event(
            "memory.touch",
            str(memory_id),
            "success",
            {},
            None,
        )

    async def _audit_event(
        self,
        action: str,
        target: str,
        result: str,
        detail: dict[str, Any],
        session_id: str | None,
    ) -> None:
        """Emit best-effort audit evidence through the injected logger."""

        if self._audit_logger is None:
            return
        try:
            row_id = await self._audit_logger.log(
                action,
                target,
                result,
                detail,
                session_id=session_id,
            )
            if row_id < 0:
                logger.warning("audit logger rejected memory event: %s", action)
        except Exception:
            logger.warning("memory audit event failed: %s", action, exc_info=True)


# Compatibility for direct imports from the former monolithic module.
__all__ = [
    "Memory",
    "MemoryConfidence",
    "MemoryScope",
    "MemoryStore",
    "extract_memories_from_messages",
    "extract_memories_from_text",
]
