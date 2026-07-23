import asyncio
import os

import pytest
import httpx

from khaos.agent import ErrorCode, ErrorEvent, ErrorHandler, Message
from khaos.agent.error_handler import ModelContextTooLongError, ModelRateLimitError
from khaos.db import Database


def test_error_event_to_message():
    message = ErrorEvent(ErrorCode.MODEL_TIMEOUT, "slow").to_message()

    assert message.event == "error"
    assert message.metadata["code"] == "MODEL_TIMEOUT"


def test_classify_errors():
    handler = ErrorHandler()

    assert handler.classify(asyncio.TimeoutError()) is ErrorCode.MODEL_TIMEOUT
    assert handler.classify(httpx.ConnectError("network down")) is ErrorCode.MODEL_UNAVAILABLE
    assert handler.classify(ModelRateLimitError()) is ErrorCode.MODEL_RATE_LIMITED
    assert handler.classify(ModelContextTooLongError()) is ErrorCode.MODEL_CONTEXT_TOO_LONG
    assert handler.classify(PermissionError()) is ErrorCode.PERMISSION_DENIED


async def test_handle_uses_exception_type_when_message_is_empty(tmp_path):
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    principal_id = f"local-uid:{os.getuid()}"
    await db.create_session("s1", principal_id=principal_id)
    handler = ErrorHandler(db=db, principal_id=principal_id)

    event = await handler.handle(AssertionError(), "s1")

    assert event.message == "AssertionError"
    assert event.to_message().metadata["message"] == "AssertionError"
    await db.close()


async def test_handle_audits_error(tmp_path):
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    principal_id = f"local-uid:{os.getuid()}"
    await db.create_session("s1", principal_id=principal_id)
    handler = ErrorHandler(db=db, principal_id=principal_id)

    event = await handler.handle(asyncio.TimeoutError("slow"), "s1")
    logs = await db.list_audit_logs()

    assert event.code is ErrorCode.MODEL_TIMEOUT
    assert logs[0]["action"] == "error:MODEL_TIMEOUT"
    await db.close()


async def test_retry_rate_limited_eventually_succeeds():
    calls = 0

    async def operation():
        nonlocal calls
        calls += 1
        if calls < 3:
            raise ModelRateLimitError("429")
        return "ok"

    result = await ErrorHandler(max_retries=3).retry_rate_limited(operation)

    assert result == "ok"
    assert calls == 3


async def test_retry_rate_limited_raises_after_budget():
    async def operation():
        raise ModelRateLimitError("429")

    with pytest.raises(ModelRateLimitError):
        await ErrorHandler(max_retries=2).retry_rate_limited(operation)


async def test_fallback_model_call_uses_router():
    class Router:
        async def call_with_fallback(self, function, messages):
            yield Message(role="assistant", content=f"{function}:fallback")

    chunks = await ErrorHandler(router=Router()).fallback_model_call("agent_loop", [])

    assert chunks[0].content == "agent_loop:fallback"


async def test_prompt_too_long_runs_compressor():
    class Compressor:
        async def compress(self, messages, threshold):
            return ("compressed", threshold, messages)

    result = await ErrorHandler(compressor=Compressor()).recover_prompt_too_long([Message("user", "x")], 10)

    assert result[0] == "compressed"
    assert result[1] == 10


async def test_agent_loop_error_handler_integration(tmp_path):
    from khaos.agent import AgentConfig, AgentLoop
    from khaos.modes import ModeManager

    class FailingRouter:
        async def call(self, function, messages):
            raise asyncio.TimeoutError("model slow")
            yield

    (tmp_path / "prompts").mkdir()
    (tmp_path / "prompts" / "office.md").write_text("office prompt", encoding="utf-8")
    (tmp_path / "prompts" / "coding.md").write_text("coding prompt", encoding="utf-8")
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    principal_id = f"local-uid:{os.getuid()}"
    await db.create_session("s1", principal_id=principal_id)
    loop = AgentLoop(
        AgentConfig(),
        ModeManager(db, project_root=tmp_path),
        FailingRouter(),
        db,
        error_handler=ErrorHandler(db=db, principal_id=principal_id),
        principal_id=principal_id,
    )

    events = [message async for message in loop.run("hello", "s1")]

    assert events[-1].event == "error"
    assert events[-1].metadata["code"] == "MODEL_TIMEOUT"
    await db.close()
