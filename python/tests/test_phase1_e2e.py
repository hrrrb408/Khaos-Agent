from khaos.agent import AgentConfig, AgentLoop
from khaos.agent.compressor import ContextCompressor
from khaos.agent.error_handler import ErrorHandler
from khaos.db import Database
from khaos.memory import Memory, MemoryManager, MemoryScope, MemoryStore
from khaos.modes import Mode, ModeManager
from khaos.permissions import PermissionEngine
from khaos.routing.router import create_default_router
from khaos.tools import create_runtime_registry
from khaos.tools.scheduler import ToolScheduler


async def test_full_phase1_flow_with_memory_tool_compression_and_error_handler(tmp_path):
    (tmp_path / "prompts").mkdir()
    (tmp_path / "prompts" / "office.md").write_text("office prompt", encoding="utf-8")
    (tmp_path / "prompts" / "coding.md").write_text("coding prompt", encoding="utf-8")
    target = tmp_path / "note.txt"
    target.write_text("hello\n", encoding="utf-8")
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    await db.create_session("s1", mode="coding")
    mode_manager = ModeManager(db, project_root=tmp_path)
    await mode_manager.switch(Mode.CODING)
    memory_store = MemoryStore(db)
    await memory_store.set(Memory(None, MemoryScope.GLOBAL, "user", "Ruibang"))
    memory_manager = MemoryManager(
        memory_store,
        mode_getter=lambda: mode_manager.current_mode,
        intent_getter=lambda: "finish phase 1",
    )
    router = create_default_router()
    compressor = ContextCompressor(router)
    scheduler = ToolScheduler(create_runtime_registry(), PermissionEngine(db))
    loop = AgentLoop(
        AgentConfig(compression_threshold=20),
        mode_manager,
        router,
        db,
        tool_scheduler=scheduler,
        confirm_callback=lambda request: {"approved": True},
        context_compressor=compressor,
        memory_manager=memory_manager,
        error_handler=ErrorHandler(db=db, router=router, compressor=compressor),
    )

    events = [message async for message in loop.run(f"/tool read_file {target}", "s1")]
    persisted = await db.list_messages("s1")
    logs = await db.list_audit_logs()

    assert any(message.event == "permission_request" for message in events)
    assert any(message.event == "tool_result" for message in events)
    assert events[-1].content == "done"
    assert any(message.role == "tool" for message in persisted)
    assert logs[0]["action"] == "read_file"
    await db.close()

