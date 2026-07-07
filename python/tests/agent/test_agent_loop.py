from khaos.agent import AgentConfig, AgentLoop, Message
from khaos.agent.compressor import CompressionLevel, CompressionResult
from khaos.db import Database
from khaos.modes import Mode, ModeManager
from khaos.permissions import PermissionEngine
from khaos.routing.router import create_default_router
from khaos.tools import create_runtime_registry
from khaos.tools.scheduler import ToolScheduler


async def test_agent_loop_streams_and_persists_messages(tmp_path):
    (tmp_path / "prompts").mkdir()
    (tmp_path / "prompts" / "office.md").write_text("office prompt", encoding="utf-8")
    (tmp_path / "prompts" / "coding.md").write_text("coding prompt", encoding="utf-8")
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    await db.create_session("s1")
    mode_manager = ModeManager(db, project_root=tmp_path)
    router = create_default_router()
    loop = AgentLoop(AgentConfig(), mode_manager, router, db)

    chunks = [message async for message in loop.run("hello", "s1")]
    persisted = await db.list_messages("s1")

    assert "".join(chunk.content for chunk in chunks if chunk.role == "assistant") == "Khaos mock response."
    assert [message.role for message in persisted] == ["user", "assistant"]
    assert persisted[0].content == "hello"
    assert persisted[1].content == "Khaos mock response."
    await db.close()


async def test_agent_loop_uses_coding_route(tmp_path):
    (tmp_path / "prompts").mkdir()
    (tmp_path / "prompts" / "office.md").write_text("office prompt", encoding="utf-8")
    (tmp_path / "prompts" / "coding.md").write_text("coding prompt", encoding="utf-8")
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    await db.create_session("s1", mode="coding")
    mode_manager = ModeManager(db, project_root=tmp_path)
    await mode_manager.switch(Mode.CODING)
    router = create_default_router()
    loop = AgentLoop(AgentConfig(), mode_manager, router, db)

    chunks = [message async for message in loop.run("edit file", "s1")]

    assert chunks[-1].content == "done"
    assert mode_manager.mode_config.preferred_model_function == "coding"
    await db.close()


async def test_agent_loop_executes_real_read_file_tool(tmp_path):
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
    engine = PermissionEngine(db)
    scheduler = ToolScheduler(create_runtime_registry(), engine)
    loop = AgentLoop(
        AgentConfig(),
        mode_manager,
        create_default_router(),
        db,
        tool_scheduler=scheduler,
        confirm_callback=lambda request: {"approved": True},
    )

    events = [message async for message in loop.run(f"/tool read_file {target}", "s1")]
    persisted = await db.list_messages("s1")

    assert "tool_call" in [message.event for message in events]
    assert "permission_request" in [message.event for message in events]
    tool_results = [message for message in events if message.event == "tool_result"]
    assert tool_results[0].metadata["success"] is True
    assert "1: hello" in str(tool_results[0].metadata["output"])
    assert [message.role for message in persisted] == ["user", "assistant", "tool", "assistant"]
    await db.close()


async def test_agent_loop_terminal_read_only_auto_approved(tmp_path):
    (tmp_path / "prompts").mkdir()
    (tmp_path / "prompts" / "office.md").write_text("office prompt", encoding="utf-8")
    (tmp_path / "prompts" / "coding.md").write_text("coding prompt", encoding="utf-8")
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    await db.create_session("s1", mode="coding")
    mode_manager = ModeManager(db, project_root=tmp_path)
    await mode_manager.switch(Mode.CODING)
    scheduler = ToolScheduler(create_runtime_registry(), PermissionEngine(db))
    loop = AgentLoop(
        AgentConfig(),
        mode_manager,
        create_default_router(),
        db,
        tool_scheduler=scheduler,
    )

    events = [message async for message in loop.run("/tool terminal echo hi", "s1")]

    assert "permission_request" not in [message.event for message in events]
    tool_result = next(message for message in events if message.event == "tool_result")
    assert tool_result.metadata["success"] is True
    assert tool_result.metadata["output"]["stdout"] == "hi\n"
    await db.close()


async def test_agent_loop_triggers_compression_before_model_call(tmp_path):
    class RecordingRouter:
        def __init__(self):
            self.seen_messages = []

        async def call(self, function, messages):
            self.seen_messages = messages
            yield Message(role="assistant", content="ok")
            yield Message(role="assistant", content="", stop_reason="end_turn")

    class FakeCompressor:
        def __init__(self):
            self.called = False

        async def compress(self, messages, threshold):
            self.called = True
            return CompressionResult(
                CompressionLevel.CONTEXT_COLLAPSE,
                100,
                2,
                [messages[0], Message(role="assistant", content="[摘要开始] x [摘要结束]"), messages[-1]],
            )

    (tmp_path / "prompts").mkdir()
    (tmp_path / "prompts" / "office.md").write_text("office prompt", encoding="utf-8")
    (tmp_path / "prompts" / "coding.md").write_text("coding prompt", encoding="utf-8")
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    await db.create_session("s1")
    await db.insert_message("s1", Message(role="user", content="old " * 20, token_count=20))
    mode_manager = ModeManager(db, project_root=tmp_path)
    router = RecordingRouter()
    compressor = FakeCompressor()
    loop = AgentLoop(
        AgentConfig(compression_threshold=5),
        mode_manager,
        router,
        db,
        context_compressor=compressor,
    )

    [message async for message in loop.run("new " * 10, "s1")]

    assert compressor.called
    assert any("[摘要开始]" in message.content for message in router.seen_messages)
    await db.close()


async def test_agent_loop_injects_memory_into_system_prompt(tmp_path):
    class RecordingRouter:
        def __init__(self):
            self.seen_messages = []

        async def call(self, function, messages):
            self.seen_messages = messages
            yield Message(role="assistant", content="ok")
            yield Message(role="assistant", content="", stop_reason="end_turn")

    class FakeMemoryManager:
        async def inject(self, session_id):
            return "L0 全局记忆:\n- user: Ruibang"

    (tmp_path / "prompts").mkdir()
    (tmp_path / "prompts" / "office.md").write_text("office prompt", encoding="utf-8")
    (tmp_path / "prompts" / "coding.md").write_text("coding prompt", encoding="utf-8")
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    await db.create_session("s1")
    mode_manager = ModeManager(db, project_root=tmp_path)
    router = RecordingRouter()
    loop = AgentLoop(
        AgentConfig(),
        mode_manager,
        router,
        db,
        memory_manager=FakeMemoryManager(),
    )

    [message async for message in loop.run("hello", "s1")]

    assert "L0 全局记忆" in router.seen_messages[0].content
    await db.close()
