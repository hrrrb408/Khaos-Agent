"""JSON-line RPC 服务器集成测试。

启动一个真实的 asyncio Unix socket server，测试控制面调用契约。
"""

from __future__ import annotations

import asyncio
import json
import uuid
from pathlib import Path

import pytest

from khaos.db import Database
from khaos.grpc_server import AgentService, ChatRequest
from khaos.runtime import RequestContext


def _test_ctx() -> RequestContext:
    """M4 batch 3.1.16A-4-1: build a RequestContext for mock service tests.

    Uses :meth:`RequestContext.for_cli` which is Windows-safe.
    """
    return RequestContext.for_cli()


class MockAgentService:
    """Small mock agent service with the same chat surface."""

    async def chat(self, ctx: RequestContext, request: ChatRequest):
        del ctx  # Mock does not scope by principal.
        yield {
            "event": "message",
            "data": {"role": "assistant", "content": f"mock reply: {request.message}", "token_count": 2},
        }
        yield {"event": "done", "data": {"total_tokens": 2, "stop_reason": "end_turn"}}


async def serve_test_json_lines(socket_path: Path, agent: MockAgentService):
    """Start a JSON-line server using the same method contract as serve_json_lines."""

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            line = await reader.readline()
            request = json.loads(line.decode("utf-8"))
            method = request.get("method")
            payload = request.get("payload", {})
            if method == "AgentService.Chat":
                async for event in agent.chat(_test_ctx(), ChatRequest(**payload)):
                    writer.write((json.dumps(event, ensure_ascii=False) + "\n").encode("utf-8"))
                    await writer.drain()
            else:
                writer.write(json.dumps({"error": "unknown method"}).encode("utf-8") + b"\n")
                await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    return await asyncio.start_unix_server(handle, path=str(socket_path))


async def read_json_line(reader: asyncio.StreamReader) -> dict:
    """Read one JSON line from a local stream."""
    return json.loads((await reader.readline()).decode("utf-8"))


class TestJSONLinesChat:
    async def test_chat_streams_sse_style_events(self, tmp_path):
        socket_path = Path("/tmp") / f"khaos-json-{uuid.uuid4().hex}.sock"
        try:
            server = await serve_test_json_lines(socket_path, MockAgentService())
        except PermissionError:
            pytest.skip("sandbox does not allow binding Unix sockets")
        async with server:
            reader, writer = await asyncio.open_unix_connection(str(socket_path))
            writer.write(
                json.dumps(
                    {
                        "method": "AgentService.Chat",
                        "payload": {"session_id": "s-json", "message": "hello", "mode": "office"},
                    }
                ).encode("utf-8")
                + b"\n"
            )
            await writer.drain()

            first = await read_json_line(reader)
            second = await read_json_line(reader)
            writer.close()
            await writer.wait_closed()
        socket_path.unlink(missing_ok=True)

        assert first["event"] == "message"
        assert first["data"]["content"] == "mock reply: hello"
        assert second["event"] == "done"


class TestJSONLinesHealth:
    async def test_unknown_method_returns_error(self, tmp_path):
        socket_path = Path("/tmp") / f"khaos-json-{uuid.uuid4().hex}.sock"
        try:
            server = await serve_test_json_lines(socket_path, MockAgentService())
        except PermissionError:
            pytest.skip("sandbox does not allow binding Unix sockets")
        async with server:
            reader, writer = await asyncio.open_unix_connection(str(socket_path))
            writer.write(json.dumps({"method": "NoSuch.Method", "payload": {}}).encode("utf-8") + b"\n")
            await writer.drain()
            response = await read_json_line(reader)
            writer.close()
            await writer.wait_closed()
        socket_path.unlink(missing_ok=True)

        assert response == {"error": "unknown method"}


async def test_real_agent_service_can_be_mocked_for_json_lines(tmp_path):
    """Keep the real service import path exercised without real model calls."""

    class FixedAgentService(AgentService):
        async def chat(self, ctx: RequestContext, request: ChatRequest):
            del ctx, request
            yield {"event": "message", "data": {"role": "assistant", "content": "fixed", "token_count": 1}}
            yield {"event": "done", "data": {"total_tokens": 1, "stop_reason": "end_turn"}}

    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    service = FixedAgentService(db, project_root=Path(tmp_path))
    events = [event async for event in service.chat(_test_ctx(), ChatRequest("s", "hello", "office"))]

    assert events[0]["data"]["content"] == "fixed"
    await db.close()
