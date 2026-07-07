from khaos.agent.core import SimpleTokenEngine
from khaos.db import Database
from khaos.memory import (
    Memory,
    MemoryBudget,
    MemoryManager,
    MemoryScope,
    MemoryStore,
)
from khaos.modes import Mode


async def _manager(tmp_path, mode=Mode.CODING, budget=None, intent=""):
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    store = MemoryStore(db)
    manager = MemoryManager(
        store,
        budget=budget,
        token_engine=SimpleTokenEngine(),
        mode_getter=lambda: mode,
        intent_getter=lambda: intent,
    )
    return db, store, manager


async def test_inject_includes_global_and_current_mode(tmp_path):
    db, store, manager = await _manager(tmp_path, mode=Mode.CODING)
    await store.set(Memory(None, MemoryScope.GLOBAL, "user", "Ruibang"))
    await store.set(Memory(None, MemoryScope.CODING, "style", "run tests"))

    text = await manager.inject("s1")

    assert "L0 全局记忆" in text
    assert "user: Ruibang" in text
    assert "style: run tests" in text
    await db.close()


async def test_inject_excludes_other_mode_from_l1(tmp_path):
    db, store, manager = await _manager(tmp_path, mode=Mode.OFFICE)
    await store.set(Memory(None, MemoryScope.CODING, "style", "pytest"))

    text = await manager.inject("s1")

    assert "L1 模式记忆" not in text
    assert "L2 相关记忆" in text
    await db.close()


async def test_inject_respects_total_budget(tmp_path):
    db, store, manager = await _manager(tmp_path, budget=MemoryBudget(total_tokens=5, l0_max_tokens=100))
    await store.set(Memory(None, MemoryScope.GLOBAL, "long", "one two three four five six seven"))

    text = await manager.inject("s1")

    assert len(text.split()) <= 5
    await db.close()


async def test_empty_memory_injection_returns_empty(tmp_path):
    db, store, manager = await _manager(tmp_path)

    assert await manager.inject("s1") == ""
    await db.close()


async def test_cross_mode_transfer_formats_intent(tmp_path):
    db, store, manager = await _manager(tmp_path, intent="finish coding task")

    text = await manager.cross_mode_transfer(Mode.OFFICE, Mode.CODING)

    assert "office -> coding" in text
    assert "finish coding task" in text
    await db.close()


async def test_update_from_conversation_phase1_noop(tmp_path):
    db, store, manager = await _manager(tmp_path)

    assert await manager.update_from_conversation([], Mode.CODING) == []
    await db.close()

