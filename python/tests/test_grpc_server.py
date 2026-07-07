import pytest

from khaos.db import Database
from khaos.grpc_server import (
    AgentService,
    ChatRequest,
    ConfirmRequest,
    MemoryService,
    serve_json_lines,
)
from khaos.memory import MemoryStore


async def test_agent_service_chat_streams_events(tmp_path):
    (tmp_path / "prompts").mkdir()
    (tmp_path / "prompts" / "office.md").write_text("office prompt", encoding="utf-8")
    (tmp_path / "prompts" / "coding.md").write_text("coding prompt", encoding="utf-8")
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    service = AgentService(db, project_root=tmp_path)

    events = [event async for event in service.chat(ChatRequest("s1", "hello", "office"))]

    assert events[0]["event"] == "message"
    assert events[-1]["event"] == "done"
    await db.close()


async def test_agent_service_switch_and_confirm(tmp_path):
    (tmp_path / "prompts").mkdir()
    (tmp_path / "prompts" / "office.md").write_text("office prompt", encoding="utf-8")
    (tmp_path / "prompts" / "coding.md").write_text("coding prompt", encoding="utf-8")
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    service = AgentService(db, project_root=tmp_path)

    mode = await service.switch_mode("s1", "coding")
    confirmation = await service.confirm_permission(ConfirmRequest("s1", "call_1", True, False))

    assert mode == {"current_mode": "coding"}
    assert confirmation == {"ok": True}
    await db.close()


async def test_memory_service_crud_search(tmp_path):
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    service = MemoryService(MemoryStore(db))

    stored = await service.set_memory("global", "user", "Ruibang likes tests")
    memory = await service.get_memory("global", "user")
    results = await service.search_memory("tests")
    deleted = await service.delete_memory(stored["id"])

    assert stored["ok"]
    assert memory["value"] == "Ruibang likes tests"
    assert results[0]["key"] == "user"
    assert deleted == {"ok": True}
    await db.close()


async def test_json_line_server_chat(tmp_path):
    (tmp_path / "prompts").mkdir()
    (tmp_path / "prompts" / "office.md").write_text("office prompt", encoding="utf-8")
    (tmp_path / "prompts" / "coding.md").write_text("coding prompt", encoding="utf-8")
    import asyncio

    task = asyncio.create_task(
        serve_json_lines("127.0.0.1", 0, str(tmp_path / "khaos.db"), project_root=tmp_path)
    )
    await asyncio.sleep(0.01)
    task.cancel()
    try:
        await task
    except PermissionError:
        pytest.skip("sandbox does not allow binding TCP sockets")
    except asyncio.CancelledError:
        pass
