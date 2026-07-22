"""SQLite-backed memory store with FTS5 search."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Optional

from khaos.time_utils import utc_now_naive

logger = logging.getLogger(__name__)


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
    """Three-scope memory storage.

    M4 batch 3.1.16A-2 (CRITICAL #5): every store is bound to exactly
    one ``principal_id`` at construction.  All reads and writes are
    scoped to that principal — a different principal's memories are
    invisible.  Project-shared memories (``namespace='shared'``,
    ``principal_id=''``) are visible to every principal.

    Legacy callers that omit ``principal_id`` get ``'legacy'`` — the
    memory is stored but never loaded by authenticated principals.

    M4 batch 3.1.16A-5-1b (CRITICAL): ``project_id`` is also bound at
    construction and stamped on every upsert so memories are
    cryptographically tied to the project that produced them.  The
    RPC dispatcher's drift check (``ctx.project_id !=
    agent._bound_project_id``) is the sole authority — when the store
    is constructed via ``build_runtime`` the ``project_id`` comes from
    ``RuntimeConfig.project_id`` (set by ``AgentService`` from the
    verified RPC payload), NOT from ``compute_project_id(root)``.
    """

    def __init__(
        self, db, *, principal_id: str = "legacy", project_id: str = "",
    ):
        self.db = db
        self._principal_id = principal_id
        # M4 batch 3.1.16A-5-1b: project identity stamp.  Default ``''``
        # ("unbound") matches the schema column default — legacy callers
        # / tests that omit it produce ``project_id=''`` rows which are
        # still visible (the UNIQUE key is unchanged) but distinguishable
        # from rows stamped by a project-bound runtime.
        self._project_id = project_id

    def _effective_principal(self, namespace: str) -> str:
        """A2-4: project-shared memories live under ``principal_id=''`` so
        every principal sees them.  Private and session-scoped memories
        stay bound to this store's principal.  This matches the
        documented contract: ``namespace='shared'`` is the project-wide
        cross-principal channel; everything else is principal-scoped."""
        if namespace == "shared":
            return ""
        return self._principal_id

    async def get(
        self,
        scope: MemoryScope,
        key: str,
        *,
        namespace: str = "private",
        session_id: str = "",
    ) -> Memory | None:
        row = await self.db.get_memory(
            scope.value, key,
            principal_id=self._effective_principal(namespace),
            namespace=namespace,
            session_id=session_id,
        )
        return self._from_row(row) if row is not None else None

    async def set(
        self,
        memory: Memory,
        on_conflict: str = "overwrite",
        *,
        namespace: str = "private",
        session_id: str = "",
    ) -> Memory | None:
        """Insert or update a memory.

        ``on_conflict`` controls what happens when a memory already exists for
        the same (namespace, principal_id, session_id, scope, key) but with a
        *different* value:

        - ``"overwrite"`` (default, backward-compatible): always replace.
        - ``"resolve"``: consult :meth:`resolve_conflict`; if it returns None
          the conflict is unresolved and this method returns None without
          writing (the caller should surface the conflict to the user). A
          resolved winner is written.

        When the value is unchanged the existing row is returned untouched.
        """
        existing = await self.get(
            memory.scope, memory.key, namespace=namespace, session_id=session_id,
        )
        if existing is None or existing.value == memory.value:
            return await self._raw_upsert(
                memory, namespace=namespace, session_id=session_id,
            )

        if on_conflict == "resolve":
            winner = self.resolve_conflict(memory, existing)
            if winner is None:
                logger.warning(
                    "memory conflict unresolved for (%s, %s): existing=%r new=%r",
                    memory.scope.value,
                    memory.key,
                    existing.value,
                    memory.value,
                )
                return None
            return await self._raw_upsert(
                winner, namespace=namespace, session_id=session_id,
            )

        return await self._raw_upsert(
            memory, namespace=namespace, session_id=session_id,
        )

    async def _raw_upsert(
        self,
        memory: Memory,
        *,
        namespace: str = "private",
        session_id: str = "",
    ) -> Memory:
        memory_id = await self.db.upsert_memory(
            memory.scope.value,
            memory.key,
            memory.value,
            memory.ttl,
            memory.confidence.value,
            principal_id=self._effective_principal(namespace),
            namespace=namespace,
            session_id=session_id,
            # M4 batch 3.1.16A-5-1b: stamp the project identity on every
            # upsert.  ``upsert_memory``'s ``ON CONFLICT`` clause does NOT
            # touch ``project_id`` — owner-preserving — so once a memory
            # is bound to a (principal, project) pair it cannot be
            # re-stamped by a later upsert from a different context.
            project_id=self._project_id,
        )
        stored = await self.get(
            memory.scope, memory.key, namespace=namespace, session_id=session_id,
        )
        assert stored is not None
        stored.id = memory_id
        return stored

    @staticmethod
    def resolve_conflict(new: Memory, existing: Memory) -> Memory | None:
        """Pick the winner between two memories for the same key.

        Rules (from FR-014 Phase 3):
        - Higher confidence wins outright.
        - Equal confidence: the incoming ``new`` wins by default — it is the
          latest information being asserted right now (newest-information-first).
          ``new`` only loses when it carries an explicit ``updated_at`` older
          than ``existing``'s, which signals stale data being replayed.
        - Equal confidence *and* equal timestamps cannot be decided -> return
          None to flag the conflict for human resolution.

        ``new`` and ``existing`` are treated as immutable; the winner is
        returned by reference.
        """
        if new.confidence.value > existing.confidence.value:
            return new
        if existing.confidence.value > new.confidence.value:
            return existing
        # Equal confidence -> compare timestamps when both are known. An
        # explicit older `new` is treated as stale and the existing winner
        # stands; otherwise `new` (the current assertion) wins.
        new_ts = new.updated_at
        existing_ts = existing.updated_at
        if new_ts is not None and existing_ts is not None and new_ts < existing_ts:
            return existing
        return new

    async def decay(self, now: datetime | None = None) -> int:
        """Delete memories past their TTL and return the count removed.

        A memory is expired when ``updated_at + ttl_seconds < now``. ``now``
        defaults to the current UTC time. Rows with a NULL ``updated_at`` are
        treated as freshly created and never decayed.

        M4 batch 3.1.16A-2: only this principal's memories are decayed —
        the list_all() call is principal-scoped, so ``delete_memory_by_id``
        can only receive IDs that belong to this principal.
        """
        moment = now or utc_now_naive()
        before = len(await self.list_all())
        # SQLite stores ISO timestamps; compare in Python to avoid timezone
        # parsing pitfalls inside SQL.
        expired_ids: list[int] = []
        for memory in await self.list_all():
            if memory.id is None or memory.updated_at is None:
                continue
            age = (moment - memory.updated_at).total_seconds()
            if age > memory.ttl:
                expired_ids.append(memory.id)
        for memory_id in expired_ids:
            await self.db.delete_memory_by_id(memory_id)
        removed = before - len(await self.list_all()) if expired_ids else 0
        if removed:
            logger.info("memory decay removed %d expired entries", removed)
        return removed

    async def delete(
        self,
        scope: MemoryScope,
        key: str,
        *,
        namespace: str = "private",
        session_id: str = "",
    ) -> None:
        await self.db.delete_memory(
            scope.value, key,
            principal_id=self._effective_principal(namespace),
            namespace=namespace,
            session_id=session_id,
        )

    async def list_by_scope(self, scope: MemoryScope) -> list[Memory]:
        """List all memories for this principal in the given scope.

        Includes the principal's private memories AND project-shared
        memories (``namespace='shared'``).  Legacy rows are excluded.
        """
        return [
            self._from_row(row)
            for row in await self.db.list_memories(
                scope.value, principal_id=self._principal_id,
            )
        ]

    async def list_all(self) -> list[Memory]:
        """List all memories visible to this principal.

        Includes the principal's private memories AND project-shared
        memories.  Legacy rows and other principals' private memories
        are excluded.
        """
        return [
            self._from_row(row)
            for row in await self.db.list_memories(principal_id=self._principal_id)
        ]

    async def search(self, query: str, top_k: int = 5) -> list[Memory]:
        """FTS5 search across this principal's visible memories."""
        memories = [
            self._from_row(row)
            for row in await self.db.search_memories(
                query, top_k, principal_id=self._principal_id,
            )
        ]
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


# --- proactive memory extraction -------------------------------------------

# Each rule is (regex, scope, key_template). The regex's first capture group
# becomes the memory value. Patterns are deliberately simple and language-
# mixed to keep this dependency-free; deeper extraction is a model-time task.
_EXTRACTION_RULES: list[tuple[re.Pattern[str], MemoryScope, str]] = [
    # "我叫X" / "我的名字是X" / "I am X" / "my name is X"
    (
        re.compile(r"(?:我叫|我的名字是|我是)\s*([^\s,，。.!！?？]{1,30})", re.IGNORECASE),
        MemoryScope.GLOBAL,
        "user_name",
    ),
    (
        re.compile(r"my name is ([A-Za-z][\w\- ]{0,30})", re.IGNORECASE),
        MemoryScope.GLOBAL,
        "user_name",
    ),
    # "我喜欢X" / "I like X" / "I prefer X"  -> preference:<X>
    (
        re.compile(r"我(?:喜欢|偏好|倾向于)\s*([^\s,，。.!！?？]{1,40})", re.IGNORECASE),
        MemoryScope.GLOBAL,
        "preference",
    ),
    (
        re.compile(r"i (?:like|prefer) ([a-z0-9 \-]{2,40})", re.IGNORECASE),
        MemoryScope.GLOBAL,
        "preference",
    ),
    # "记住X" / "remember X"  -> note:<X>
    (
        re.compile(r"记住[：:\s]*([^\n]{2,80})"),
        MemoryScope.GLOBAL,
        "note",
    ),
    (
        re.compile(r"remember (?:that )?(.{2,80})", re.IGNORECASE),
        MemoryScope.GLOBAL,
        "note",
    ),
]


def extract_memories_from_text(text: str, scope: MemoryScope = MemoryScope.GLOBAL) -> list[Memory]:
    """Scan free text for declarative memory signals.

    Returns a list of candidate :class:`Memory` objects (not yet persisted).
    Each rule contributes at most one memory per match, keyed by a stable key
    so repeated statements upsert rather than duplicate. Confidence is MEDIUM
    since these are inferred from phrasing, not explicitly confirmed.
    """
    if not text:
        return []
    found: list[Memory] = []
    seen: set[tuple[MemoryScope, str]] = set()
    for pattern, rule_scope, key_base in _EXTRACTION_RULES:
        for match in pattern.finditer(text):
            value = match.group(1).strip()
            if not value:
                continue
            key = key_base if key_base in {"user_name", "note"} else f"{key_base}:{value.lower()}"
            identity = (rule_scope, key)
            if identity in seen:
                continue
            seen.add(identity)
            found.append(
                Memory(
                    id=None,
                    scope=scope if scope != MemoryScope.GLOBAL else rule_scope,
                    key=key,
                    value=value,
                    confidence=MemoryConfidence.MEDIUM,
                )
            )
    return found


def extract_memories_from_messages(
    messages: list,
    scope: MemoryScope = MemoryScope.GLOBAL,
) -> list[Memory]:
    """Scan a list of chat messages for memory-worthy user statements.

    Only ``user``-role messages are scanned (assistants and tools do not assert
    personal facts). Each message object may be a khaos Message or any object
    with ``.role``/``.content`` attributes, or a plain dict.
    """
    extracted: list[Memory] = []
    for message in messages:
        role = _get(message, "role")
        if role != "user":
            continue
        content = _get(message, "content") or ""
        extracted.extend(extract_memories_from_text(str(content), scope))
    return extracted


def _get(obj, attr: str):
    if isinstance(obj, dict):
        return obj.get(attr)
    return getattr(obj, attr, None)
