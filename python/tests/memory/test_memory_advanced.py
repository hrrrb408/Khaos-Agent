"""Phase 3 advanced memory: TTL decay, conflict resolution, proactive extraction."""

from __future__ import annotations

from datetime import datetime, timedelta

from khaos.db import Database
from khaos.memory import (
    Memory,
    MemoryBudget,
    MemoryConfidence,
    MemoryManager,
    MemoryScope,
    MemoryStore,
)
from khaos.memory.store import extract_memories_from_messages, extract_memories_from_text
from khaos.modes import Mode
from khaos.time_utils import utc_now_naive


async def _store(tmp_path):
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    return db, MemoryStore(db)


async def _manager(tmp_path, **kwargs):
    db, store = await _store(tmp_path)
    manager = MemoryManager(store, budget=MemoryBudget(), **kwargs)
    return db, store, manager


# --- TTL decay ------------------------------------------------------------


async def test_decay_removes_expired_memories(tmp_path):
    db, store = await _store(tmp_path)
    # Write a memory with a 1-second TTL.
    await store.set(Memory(None, MemoryScope.GLOBAL, "short", "v", ttl=1))

    # Travel 2 seconds into the future.
    future = utc_now_naive() + timedelta(seconds=2)
    removed = await store.decay(now=future)

    assert removed == 1
    assert await store.get(MemoryScope.GLOBAL, "short") is None
    await db.close()


async def test_decay_keeps_fresh_memories(tmp_path):
    db, store = await _store(tmp_path)
    await store.set(Memory(None, MemoryScope.GLOBAL, "long", "v", ttl=86400))

    removed = await store.decay(now=utc_now_naive())

    assert removed == 0
    assert (await store.get(MemoryScope.GLOBAL, "long")) is not None
    await db.close()


# --- conflict resolution --------------------------------------------------


async def test_resolve_conflict_higher_confidence_wins(tmp_path):
    db, store = await _store(tmp_path)
    await store.set(
        Memory(None, MemoryScope.GLOBAL, "name", "Alice", confidence=MemoryConfidence.LOW)
    )
    # New higher-confidence statement with a *different* value.
    await store.set(
        Memory(
            None,
            MemoryScope.GLOBAL,
            "name",
            "Bob",
            confidence=MemoryConfidence.HIGH,
        ),
        on_conflict="resolve",
    )

    assert (await store.get(MemoryScope.GLOBAL, "name")).value == "Bob"
    await db.close()


async def test_resolve_conflict_lower_confidence_keeps_existing(tmp_path):
    db, store = await _store(tmp_path)
    await store.set(
        Memory(None, MemoryScope.GLOBAL, "name", "Bob", confidence=MemoryConfidence.HIGH)
    )
    # Incoming LOW confidence should not overwrite a HIGH existing value.
    await store.set(
        Memory(
            None,
            MemoryScope.GLOBAL,
            "name",
            "Alice",
            confidence=MemoryConfidence.LOW,
        ),
        on_conflict="resolve",
    )

    assert (await store.get(MemoryScope.GLOBAL, "name")).value == "Bob"
    await db.close()


async def test_resolve_conflict_equal_confidence_newer_wins(tmp_path):
    db, store = await _store(tmp_path)
    await store.set(
        Memory(
            None,
            MemoryScope.GLOBAL,
            "name",
            "Alice",
            confidence=MemoryConfidence.MEDIUM,
        )
    )
    # New same-confidence statement wins the tie (newest-information-first):
    # an incoming assertion with no explicit older timestamp supersedes.
    await store.set(
        Memory(
            None,
            MemoryScope.GLOBAL,
            "name",
            "Bob",
            confidence=MemoryConfidence.MEDIUM,
        ),
        on_conflict="resolve",
    )

    assert (await store.get(MemoryScope.GLOBAL, "name")).value == "Bob"
    await db.close()


async def test_resolve_conflict_equal_confidence_explicit_older_loses(tmp_path):
    db, store = await _store(tmp_path)
    # Existing carries a recent timestamp.
    await store.set(
        Memory(
            None,
            MemoryScope.GLOBAL,
            "name",
            "Bob",
            confidence=MemoryConfidence.MEDIUM,
            updated_at=datetime(2026, 7, 7),
        )
    )
    # Incoming same-confidence but explicitly stale -> existing stands.
    await store.set(
        Memory(
            None,
            MemoryScope.GLOBAL,
            "name",
            "Alice",
            confidence=MemoryConfidence.MEDIUM,
            updated_at=datetime(2026, 1, 1),
        ),
        on_conflict="resolve",
    )

    assert (await store.get(MemoryScope.GLOBAL, "name")).value == "Bob"
    await db.close()


async def test_overwrite_mode_always_replaces(tmp_path):
    """Default overwrite mode preserves Phase 1 semantics."""
    db, store = await _store(tmp_path)
    await store.set(
        Memory(None, MemoryScope.GLOBAL, "k", "old", confidence=MemoryConfidence.HIGH)
    )
    await store.set(
        Memory(None, MemoryScope.GLOBAL, "k", "new", confidence=MemoryConfidence.LOW)
    )

    assert (await store.get(MemoryScope.GLOBAL, "k")).value == "new"
    await db.close()


# --- proactive extraction -------------------------------------------------


def test_extract_user_name_from_chinese():
    memories = extract_memories_from_text("你好，我叫瑞邦，请多关照")

    assert any(m.key == "user_name" and m.value == "瑞邦" for m in memories)


def test_extract_user_name_from_english():
    memories = extract_memories_from_text("Hi, my name is Alice")

    assert any(m.key == "user_name" and m.value == "Alice" for m in memories)


def test_extract_preference_and_note():
    memories = extract_memories_from_text("我喜欢简洁，记住：用 type hints")

    keys = {m.key for m in memories}
    assert any(k.startswith("preference") for k in keys)
    assert any(k == "note" for k in keys)


def test_extract_ignores_non_user_messages():
    from khaos.agent.core import Message

    messages = [
        Message(role="assistant", content="我叫助手"),
        Message(role="user", content="我叫瑞邦"),
    ]
    memories = extract_memories_from_messages(messages)

    assert [m.value for m in memories] == ["瑞邦"]


def test_extract_empty_text_returns_empty():
    assert extract_memories_from_text("") == []
    assert extract_memories_from_text("   只是普通对话，没有要记的内容") == []


async def test_update_from_conversation_persists_extracted(tmp_path):
    db, store, manager = await _manager(tmp_path)
    from khaos.agent.core import Message

    messages = [Message(role="user", content="我叫瑞邦")]
    persisted = await manager.update_from_conversation(messages, Mode.OFFICE)

    assert len(persisted) == 1
    stored = await store.get(MemoryScope.GLOBAL, "user_name")
    assert stored is not None
    assert stored.value == "瑞邦"
    await db.close()


async def test_update_from_conversation_empty_returns_empty(tmp_path):
    db, store, manager = await _manager(tmp_path)
    from khaos.agent.core import Message

    persisted = await manager.update_from_conversation(
        [Message(role="user", content="今天天气不错")], Mode.OFFICE
    )

    assert persisted == []
    await db.close()


# --- L2 ranking ----------------------------------------------------------


async def test_inject_ranks_l2_by_confidence_then_frequency(tmp_path):
    db, store, manager = await _manager(tmp_path)
    # OFFICE is the default scope; populate the CODING scope (L2 residue).
    await store.set(
        Memory(
            None,
            MemoryScope.CODING,
            "low",
            "v1",
            confidence=MemoryConfidence.LOW,
            access_freq=0,
        )
    )
    await store.set(
        Memory(
            None,
            MemoryScope.CODING,
            "high",
            "v2",
            confidence=MemoryConfidence.HIGH,
            access_freq=5,
        )
    )

    text = await manager.inject("s1")

    # High-confidence entry appears before low-confidence.
    assert text.index("high") < text.index("low")
    await db.close()
