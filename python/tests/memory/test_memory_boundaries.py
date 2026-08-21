"""Architectural regression tests for the memory subsystem boundaries."""

from __future__ import annotations

import inspect
from datetime import UTC, datetime

import pytest
from khaos.db import Database
from khaos.memory import (
    ConflictResolver,
    Memory,
    MemoryConfidence,
    MemoryScope,
    MemoryStore,
)


class RecordingAuditLogger:
    """Small audit port used to verify the store emits mutation evidence."""

    def __init__(self) -> None:
        self.events: list[tuple[str, str, str]] = []

    async def log(
        self,
        action: str,
        target: str,
        result: str,
        detail: dict[str, object],
        *,
        session_id: str | None = None,
    ) -> int:
        del detail, session_id
        self.events.append((action, target, result))
        return len(self.events)


async def _db(tmp_path):
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    return db


def test_store_is_a_domain_facade_not_a_sqlite_writer():
    source = inspect.getsource(MemoryStore)

    assert "self.db." not in source
    assert "upsert_memory(" not in source
    assert "search_memories(" not in source


def test_equal_explicit_conflict_timestamp_is_unresolved():
    timestamp = datetime(2026, 8, 22, tzinfo=UTC)
    existing = Memory(
        None,
        MemoryScope.GLOBAL,
        "name",
        "Alice",
        confidence=MemoryConfidence.MEDIUM,
        updated_at=timestamp,
    )
    new = Memory(
        None,
        MemoryScope.GLOBAL,
        "name",
        "Bob",
        confidence=MemoryConfidence.MEDIUM,
        updated_at=timestamp,
    )

    decision = ConflictResolver.decide(new, existing)

    assert decision.winner is None
    assert decision.reason == "equal_confidence_and_timestamp"


async def test_touch_is_scoped_to_principal_and_project(tmp_path):
    db = await _db(tmp_path)
    alice = MemoryStore(db, principal_id="alice", project_id="project-a")
    bob = MemoryStore(db, principal_id="bob", project_id="project-a")

    memory = await alice.set(Memory(None, MemoryScope.GLOBAL, "secret", "value"))
    assert memory is not None and memory.id is not None

    await bob.touch(memory.id)
    assert (await alice.get(MemoryScope.GLOBAL, "secret")).access_freq == 0

    await alice.touch(memory.id)
    assert (await alice.get(MemoryScope.GLOBAL, "secret")).access_freq == 1
    await db.close()


async def test_store_emits_audit_events_for_mutations(tmp_path):
    db = await _db(tmp_path)
    audit = RecordingAuditLogger()
    store = MemoryStore(db, audit_logger=audit)

    memory = await store.set(Memory(None, MemoryScope.GLOBAL, "key", "value"))
    assert memory is not None and memory.id is not None
    await store.touch(memory.id)
    await store.delete(MemoryScope.GLOBAL, "key")

    assert [event[0] for event in audit.events] == [
        "memory.set",
        "memory.touch",
        "memory.delete",
    ]
    await db.close()


async def test_unknown_namespace_fails_closed(tmp_path):
    db = await _db(tmp_path)
    store = MemoryStore(db)

    with pytest.raises(ValueError, match="unsupported memory namespace"):
        await store.get(MemoryScope.GLOBAL, "key", namespace="unexpected")
    with pytest.raises(ValueError, match="requires a session_id"):
        await store.get(MemoryScope.GLOBAL, "key", namespace="session")
    await db.close()
