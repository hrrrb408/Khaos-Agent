"""AgentLoop 完整流程集成测试。

注意：这些测试不连接真实 LLM，用 mock 替代模型调用。
测试的是 AgentLoop 内部的消息流转、工具调度、权限检查、记忆注入等流程。
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import AsyncIterator

from khaos.agent import AgentConfig, AgentLoop, Message
from khaos.agent.compressor import CompressionLevel, CompressionResult
from khaos.db import Database
from khaos.memory import Memory, MemoryConfidence, MemoryManager, MemoryScope, MemoryStore
from khaos.modes import Mode, ModeManager
from khaos.tools.scheduler import PermissionRequest, SchedulerEvent, ToolResult


class MockRouter:
    """Streaming mock matching the current ModelRouter call interface."""

    def __init__(self, responses: list[list[Message]] | None = None):
        self.responses = responses or []
        self.call_count = 0
        self.last_messages: list[Message] = []

    async def call(self, function: str, messages: list[Message]) -> AsyncIterator[Message]:
        del function
        self.call_count += 1
        self.last_messages = messages
        index = (self.call_count - 1) % len(self.responses) if self.responses else -1
        chunks = self.responses[index] if self.responses else [
            Message(role="assistant", content="mock reply"),
            Message(role="assistant", content="", stop_reason="end_turn"),
        ]
        for chunk in chunks:
            yield chunk


class MockToolScheduler:
    """Tool scheduler test double that records tool-result feedback loops."""

    def __init__(self, events: list[SchedulerEvent]):
        self.events = events
        self.called = False
        self.seen_tool_calls: list[dict] = []

    async def stream_batch(
        self,
        tool_calls: list[dict],
        mode: str,
        session_id: str | None = None,
        confirm_callback=None,
    ):
        del mode, session_id, confirm_callback
        self.called = True
        self.seen_tool_calls = tool_calls
        for event in self.events:
            yield event


@dataclass
class RecordingCompressor:
    called: bool = False

    async def compress(self, messages: list[Message], threshold: int) -> CompressionResult:
        del threshold
        self.called = True
        return CompressionResult(
            CompressionLevel.CONTEXT_COLLAPSE,
            original_tokens=100,
            compressed_tokens=2,
            messages=[
                messages[0],
                Message(role="assistant", content="[摘要开始] history [摘要结束]"),
                messages[-1],
            ],
        )


async def create_test_db(path: Path) -> Database:
    """Create a migrated test database."""
    db = Database(path)
    await db.connect()
    await db.run_migrations()
    return db


def write_prompts(root: Path) -> None:
    """Create minimal prompt files required by ModeManager."""
    prompts = root / "prompts"
    prompts.mkdir()
    (prompts / "office.md").write_text("office prompt", encoding="utf-8")
    (prompts / "coding.md").write_text("coding prompt", encoding="utf-8")


async def create_mode_manager(db: Database, root: Path, mode: Mode = Mode.OFFICE) -> ModeManager:
    """Create and initialize a mode manager."""
    manager = ModeManager(db, project_root=root)
    if mode is not Mode.OFFICE:
        await manager.switch(mode)
    return manager


class TestAgentLoopBasicFlow:
    async def test_records_routes_and_returns_assistant_message(self, tmp_path):
        write_prompts(tmp_path)
        db = await create_test_db(tmp_path / "khaos.db")
        await db.create_session("s-basic")
        router = MockRouter()
        loop = AgentLoop(
            AgentConfig(),
            await create_mode_manager(db, tmp_path),
            router,
            db,
        )

        events = [message async for message in loop.run("hello", "s-basic")]
        persisted = await db.list_messages("s-basic")

        assert router.call_count == 1
        assert [message.role for message in persisted] == ["user", "assistant"]
        assert persisted[0].content == "hello"
        assert persisted[1].content == "mock reply"
        assert any(message.role == "assistant" and message.content == "mock reply" for message in events)
        await db.close()


class TestAgentLoopToolCallFlow:
    async def test_tool_call_result_is_sent_back_to_router(self, tmp_path):
        write_prompts(tmp_path)
        db = await create_test_db(tmp_path / "khaos.db")
        await db.create_session("s-tool", mode="coding")
        tool_call = {"id": "call-read", "name": "read_file", "arguments": {"path": "README.md"}}
        router = MockRouter(
            [
                [
                    Message(
                        role="assistant",
                        content="",
                        tool_calls=[tool_call],
                        stop_reason="tool_use",
                    )
                ],
                [
                    Message(role="assistant", content="final answer"),
                    Message(role="assistant", content="", stop_reason="end_turn"),
                ],
            ]
        )
        scheduler = MockToolScheduler(
            [
                SchedulerEvent(
                    event="tool_result",
                    result=ToolResult(
                        tool_call_id="call-read",
                        name="read_file",
                        success=True,
                        output="file contents",
                    ),
                )
            ]
        )
        loop = AgentLoop(
            AgentConfig(),
            await create_mode_manager(db, tmp_path, Mode.CODING),
            router,
            db,
            tool_scheduler=scheduler,
        )

        events = [message async for message in loop.run("read it", "s-tool")]
        persisted = await db.list_messages("s-tool")

        assert scheduler.called
        assert scheduler.seen_tool_calls == [tool_call]
        assert "tool_call" in [message.event for message in events]
        assert any(message.role == "tool" and message.tool_call_id == "call-read" for message in router.last_messages)
        assert persisted[-1].content == "final answer"
        await db.close()


class TestAgentLoopPermissionDenied:
    async def test_permission_request_stops_tool_execution_without_confirmation(self, tmp_path):
        write_prompts(tmp_path)
        db = await create_test_db(tmp_path / "khaos.db")
        await db.create_session("s-denied", mode="coding")
        tool_call = {"id": "call-terminal", "name": "terminal", "arguments": {"command": "touch x"}}
        router = MockRouter(
            [[Message(role="assistant", content="", tool_calls=[tool_call], stop_reason="tool_use")]]
        )
        scheduler = MockToolScheduler(
            [
                SchedulerEvent(
                    event="permission_request",
                    permission_request=PermissionRequest(
                        tool_call_id="call-terminal",
                        name="terminal",
                        arguments={"command": "touch x"},
                        level="execute",
                        target="touch x",
                        reason="No matching rule, default: ask-every",
                    ),
                )
            ]
        )
        loop = AgentLoop(
            AgentConfig(max_turns=1),
            await create_mode_manager(db, tmp_path, Mode.CODING),
            router,
            db,
            tool_scheduler=scheduler,
        )

        events = [message async for message in loop.run("run command", "s-denied")]

        assert scheduler.called
        assert "permission_request" in [message.event for message in events]
        assert "tool_result" not in [message.event for message in events]
        await db.close()


class TestAgentLoopMemoryInjection:
    async def test_memory_manager_injects_memory_into_system_prompt(self, tmp_path):
        write_prompts(tmp_path)
        db = await create_test_db(tmp_path / "khaos.db")
        await db.create_session("s-memory")
        store = MemoryStore(db)
        await store.set(
            Memory(
                id=None,
                scope=MemoryScope.GLOBAL,
                key="preference",
                value="Ruibang prefers concise integration tests",
                confidence=MemoryConfidence.HIGH,
            )
        )
        mode_manager = await create_mode_manager(db, tmp_path)
        memory_manager = MemoryManager(store, mode_getter=lambda: mode_manager.current_mode)
        router = MockRouter()
        loop = AgentLoop(
            AgentConfig(),
            mode_manager,
            router,
            db,
            memory_manager=memory_manager,
        )

        [message async for message in loop.run("use memory", "s-memory")]

        assert "Ruibang prefers concise integration tests" in router.last_messages[0].content
        await db.close()


class TestAgentLoopCompressorTriggered:
    async def test_context_compressor_runs_when_threshold_is_exceeded(self, tmp_path):
        write_prompts(tmp_path)
        db = await create_test_db(tmp_path / "khaos.db")
        await db.create_session("s-compress")
        await db.insert_message("s-compress", Message(role="user", content="old " * 20, token_count=20))
        router = MockRouter()
        compressor = RecordingCompressor()
        loop = AgentLoop(
            AgentConfig(compression_threshold=5),
            await create_mode_manager(db, tmp_path),
            router,
            db,
            context_compressor=compressor,
        )

        [message async for message in loop.run("new " * 10, "s-compress")]

        assert compressor.called
        assert any("[摘要开始]" in message.content for message in router.last_messages)
        await db.close()
