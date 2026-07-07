from khaos.db import Database
from khaos.memory import Memory, MemoryConfidence, MemoryScope, MemoryStore


async def _store(tmp_path):
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    return db, MemoryStore(db)


async def test_memory_set_and_get(tmp_path):
    db, store = await _store(tmp_path)

    await store.set(Memory(None, MemoryScope.GLOBAL, "user", "Ruibang"))
    memory = await store.get(MemoryScope.GLOBAL, "user")

    assert memory is not None
    assert memory.value == "Ruibang"
    await db.close()


async def test_memory_upsert_updates_value(tmp_path):
    db, store = await _store(tmp_path)

    first = await store.set(Memory(None, MemoryScope.GLOBAL, "style", "short"))
    second = await store.set(Memory(None, MemoryScope.GLOBAL, "style", "direct"))

    assert first.id == second.id
    assert (await store.get(MemoryScope.GLOBAL, "style")).value == "direct"
    await db.close()


async def test_memory_scope_isolation(tmp_path):
    db, store = await _store(tmp_path)

    await store.set(Memory(None, MemoryScope.OFFICE, "tone", "calm"))
    await store.set(Memory(None, MemoryScope.CODING, "tone", "precise"))

    assert (await store.get(MemoryScope.OFFICE, "tone")).value == "calm"
    assert (await store.get(MemoryScope.CODING, "tone")).value == "precise"
    await db.close()


async def test_memory_delete(tmp_path):
    db, store = await _store(tmp_path)
    await store.set(Memory(None, MemoryScope.GLOBAL, "x", "y"))

    await store.delete(MemoryScope.GLOBAL, "x")

    assert await store.get(MemoryScope.GLOBAL, "x") is None
    await db.close()


async def test_list_by_scope(tmp_path):
    db, store = await _store(tmp_path)
    await store.set(Memory(None, MemoryScope.OFFICE, "a", "1"))
    await store.set(Memory(None, MemoryScope.CODING, "b", "2"))

    office = await store.list_by_scope(MemoryScope.OFFICE)

    assert [memory.key for memory in office] == ["a"]
    await db.close()


async def test_list_all_orders_by_confidence(tmp_path):
    db, store = await _store(tmp_path)
    await store.set(Memory(None, MemoryScope.GLOBAL, "low", "1", confidence=MemoryConfidence.LOW))
    await store.set(Memory(None, MemoryScope.GLOBAL, "high", "2", confidence=MemoryConfidence.HIGH))

    all_memories = await store.list_all()

    assert all_memories[0].key == "high"
    await db.close()


async def test_fts_search_finds_value(tmp_path):
    db, store = await _store(tmp_path)
    await store.set(Memory(None, MemoryScope.GLOBAL, "market", "alpha beta gamma"))

    results = await store.search("beta")

    assert [memory.key for memory in results] == ["market"]
    await db.close()


async def test_fts_search_respects_top_k(tmp_path):
    db, store = await _store(tmp_path)
    for index in range(3):
        await store.set(Memory(None, MemoryScope.GLOBAL, f"k{index}", "needle"))

    results = await store.search("needle", top_k=2)

    assert len(results) == 2
    await db.close()


async def test_touch_increments_access_freq(tmp_path):
    db, store = await _store(tmp_path)
    memory = await store.set(Memory(None, MemoryScope.GLOBAL, "k", "needle"))

    await store.touch(memory.id)
    touched = await store.get(MemoryScope.GLOBAL, "k")

    assert touched.access_freq == 1
    await db.close()


async def test_search_touches_results(tmp_path):
    db, store = await _store(tmp_path)
    await store.set(Memory(None, MemoryScope.GLOBAL, "k", "needle"))

    result = (await store.search("needle"))[0]
    touched = await store.get(result.scope, result.key)

    assert touched.access_freq == 1
    await db.close()


async def test_missing_memory_returns_none(tmp_path):
    db, store = await _store(tmp_path)

    assert await store.get(MemoryScope.GLOBAL, "missing") is None
    await db.close()


async def test_confidence_round_trip(tmp_path):
    db, store = await _store(tmp_path)

    await store.set(Memory(None, MemoryScope.CODING, "rule", "pytest", confidence=MemoryConfidence.HIGH))

    assert (await store.get(MemoryScope.CODING, "rule")).confidence is MemoryConfidence.HIGH
    await db.close()

