from khaos.agent import AgentConfig, AgentLoop, Message
from khaos.agent.compressor import CompressionLevel, CompressionResult
from khaos.db import Database
from khaos.modes import Mode, ModeManager
from khaos.permissions import PermissionEngine
from khaos.routing.router import create_default_router
from khaos.tools import create_runtime_registry
from khaos.tools.scheduler import ToolResult, ToolScheduler


async def test_task_activity_uses_original_tool_arguments():
    class RecordingTaskManager:
        def __init__(self):
            self.viewed = []
            self.modified = []

        async def track_file_viewed(self, task_id, path):
            self.viewed.append((task_id, path))

        async def track_file_modified(self, task_id, path):
            self.modified.append((task_id, path))

    loop = AgentLoop.__new__(AgentLoop)
    loop.task_manager = RecordingTaskManager()

    await loop._record_task_activity(
        ToolResult("r1", "read_file", True, output="formatted output", arguments={"path": "src/a.py"}),
        "task-1",
    )
    await loop._record_task_activity(
        ToolResult("w1", "write_file", True, output="ok", arguments={"path": "src/b.py"}),
        "task-1",
    )

    assert loop.task_manager.viewed == [("task-1", "src/a.py")]
    assert loop.task_manager.modified == [("task-1", "src/b.py")]


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


async def test_agent_loop_retries_once_after_empty_model_response(tmp_path):
    class EmptyThenOkRouter:
        def __init__(self):
            self.calls = 0

        async def call(self, function, messages):
            self.calls += 1
            if self.calls == 1:
                yield Message(role="assistant", content="", stop_reason="end_turn")
                return
            yield Message(role="assistant", content="ok")
            yield Message(role="assistant", content="", stop_reason="end_turn")

    (tmp_path / "prompts").mkdir()
    (tmp_path / "prompts" / "office.md").write_text("office prompt", encoding="utf-8")
    (tmp_path / "prompts" / "coding.md").write_text("coding prompt", encoding="utf-8")
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    await db.create_session("s1")
    mode_manager = ModeManager(db, project_root=tmp_path)
    router = EmptyThenOkRouter()
    loop = AgentLoop(AgentConfig(), mode_manager, router, db)

    chunks = [message async for message in loop.run("hello", "s1")]
    persisted = await db.list_messages("s1")

    assert router.calls == 2
    assert "".join(chunk.content for chunk in chunks if chunk.role == "assistant") == "ok"
    assert chunks[-1].content == "done"
    assert [message.role for message in persisted] == ["user", "assistant"]
    assert persisted[1].content == "ok"
    await db.close()


async def test_agent_loop_reports_error_after_repeated_empty_model_response(tmp_path):
    class EmptyRouter:
        async def call(self, function, messages):
            yield Message(role="assistant", content="", stop_reason="end_turn")

    (tmp_path / "prompts").mkdir()
    (tmp_path / "prompts" / "office.md").write_text("office prompt", encoding="utf-8")
    (tmp_path / "prompts" / "coding.md").write_text("coding prompt", encoding="utf-8")
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    await db.create_session("s1")
    mode_manager = ModeManager(db, project_root=tmp_path)
    loop = AgentLoop(AgentConfig(), mode_manager, EmptyRouter(), db)

    chunks = [message async for message in loop.run("hello", "s1")]
    persisted = await db.list_messages("s1")

    assert chunks[-1].event == "error"
    assert chunks[-1].metadata["code"] == "EMPTY_MODEL_RESPONSE"
    assert [message.role for message in persisted] == ["user"]
    await db.close()


async def test_agent_loop_read_file_without_workspace_fails_closed(tmp_path):
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
    assert tool_results[0].metadata["success"] is False
    assert "active TaskWorkspace" in str(tool_results[0].metadata["error"])
    assert [message.role for message in persisted] == ["user", "assistant", "tool", "assistant"]
    await db.close()


async def test_agent_loop_terminal_read_only_without_workspace_fails_closed(tmp_path):
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
    assert tool_result.metadata["success"] is False
    assert "no safe execution backend" in tool_result.metadata["error"]
    await db.close()


async def test_agent_loop_passes_tool_schemas_to_router(tmp_path):
    class ToolSchemaRouter:
        def __init__(self):
            self.seen_tools = None

        async def call(self, function, messages, **kwargs):
            del function, messages
            self.seen_tools = kwargs.get("tools")
            yield Message(role="assistant", content="ok")
            yield Message(role="assistant", content="", stop_reason="end_turn")

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
    router = ToolSchemaRouter()
    loop = AgentLoop(
        AgentConfig(),
        mode_manager,
        router,
        db,
        tool_scheduler=scheduler,
    )

    [message async for message in loop.run("please inspect files", "s1")]

    assert router.seen_tools is not None
    read_file = next(
        tool for tool in router.seen_tools if tool["function"]["name"] == "read_file"
    )
    assert read_file["type"] == "function"
    assert read_file["function"]["description"]
    assert read_file["function"]["parameters"]["required"] == ["path"]
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


# ---------------------------------------------------------------------------
# Phase 6: project context loader (KHAOS.md / AGENTS.md) injection
# ---------------------------------------------------------------------------


class _RecordingRouter:
    def __init__(self):
        self.seen_messages = []

    async def call(self, function, messages):
        self.seen_messages = messages
        yield Message(role="assistant", content="ok")
        yield Message(role="assistant", content="", stop_reason="end_turn")


async def test_agent_loop_injects_project_context_into_system_prompt(tmp_path):
    (tmp_path / "prompts").mkdir()
    (tmp_path / "prompts" / "office.md").write_text("office prompt", encoding="utf-8")
    (tmp_path / "prompts" / "coding.md").write_text("coding prompt", encoding="utf-8")
    # Project instructions file at the project root.
    (tmp_path / "KHAOS.md").write_text("# Project Rules\nf-strings only", encoding="utf-8")

    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    await db.create_session("s1")
    mode_manager = ModeManager(db, project_root=tmp_path)
    router = _RecordingRouter()

    from khaos.project_context import ProjectContextLoader

    loader = ProjectContextLoader(tmp_path)
    loop = AgentLoop(
        AgentConfig(),
        mode_manager,
        router,
        db,
        project_context_loader=loader,
    )

    [message async for message in loop.run("hello", "s1")]

    system_prompt = router.seen_messages[0].content
    assert "# Project Instructions" in system_prompt
    assert "# Project Rules" in system_prompt
    assert "f-strings only" in system_prompt
    await db.close()


async def test_agent_loop_without_project_context_loader_does_not_inject(tmp_path):
    (tmp_path / "prompts").mkdir()
    (tmp_path / "prompts" / "office.md").write_text("office prompt", encoding="utf-8")
    (tmp_path / "prompts" / "coding.md").write_text("coding prompt", encoding="utf-8")
    # Even though KHAOS.md exists, without a loader it must NOT be injected.
    (tmp_path / "KHAOS.md").write_text("SHOULD_NOT_APPEAR", encoding="utf-8")

    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    await db.create_session("s1")
    mode_manager = ModeManager(db, project_root=tmp_path)
    router = _RecordingRouter()
    loop = AgentLoop(AgentConfig(), mode_manager, router, db)  # no loader

    [message async for message in loop.run("hello", "s1")]

    system_prompt = router.seen_messages[0].content
    assert "# Project Instructions" not in system_prompt
    assert "SHOULD_NOT_APPEAR" not in system_prompt
    await db.close()


async def test_agent_loop_injection_order_project_before_memory_before_skill(tmp_path):
    """Project context > memory > skill in the system prompt."""

    class FakeMemoryManager:
        async def inject(self, session_id):
            return "MEMORY_BLOCK"

    class FakeSkillManager:
        def match(self, mode, user_input):
            return ["skill-x"]

        def format_for_prompt(self, matched):
            return "SKILL_BLOCK"

    (tmp_path / "prompts").mkdir()
    (tmp_path / "prompts" / "office.md").write_text("BASE_PROMPT", encoding="utf-8")
    (tmp_path / "prompts" / "coding.md").write_text("coding prompt", encoding="utf-8")
    (tmp_path / "KHAOS.md").write_text("PROJECT_BLOCK", encoding="utf-8")

    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    await db.create_session("s1")
    mode_manager = ModeManager(db, project_root=tmp_path)
    router = _RecordingRouter()

    from khaos.project_context import ProjectContextLoader

    loader = ProjectContextLoader(tmp_path)
    loop = AgentLoop(
        AgentConfig(),
        mode_manager,
        router,
        db,
        memory_manager=FakeMemoryManager(),
        skill_manager=FakeSkillManager(),
        project_context_loader=loader,
    )

    [message async for message in loop.run("hello", "s1")]

    system_prompt = router.seen_messages[0].content
    assert "BASE_PROMPT" in system_prompt
    # All three blocks present and in the correct order.
    assert system_prompt.index("PROJECT_BLOCK") < system_prompt.index("MEMORY_BLOCK")
    assert system_prompt.index("MEMORY_BLOCK") < system_prompt.index("SKILL_BLOCK")
    await db.close()
