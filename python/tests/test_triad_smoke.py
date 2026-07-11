"""Deterministic triad smoke test for the JSON-line RPC server.

This test was previously non-deterministic because it used the real
``create_default_router`` / ``load_router_from_config`` path, which
calls an external LLM API and fails with ``httpx.ReadTimeout`` in
sandboxes without network access or API credentials.

The test now injects a Fake Provider (``_FakeRouter``) that yields a
single assistant message followed by an end-turn — no external network
access, no API key required, fully deterministic.

The server readiness is probed by actively connecting to the TCP port
before sending the request, and the test fails with the server task's
stdout/stderr if the ready probe times out.
"""

import asyncio
import json
from pathlib import Path

import pytest

from khaos.agent import Message
from khaos.grpc_server import serve_json_lines


class _FakeRouter:
    """Deterministic in-process router — no external LLM access."""

    def __init__(self, responses: list[list[Message]]) -> None:
        self.responses = responses
        self.calls = 0

    async def call(self, _function, _messages, **_kwargs):
        response = self.responses[self.calls]
        self.calls += 1
        for item in response:
            yield item


async def _wait_for_port(host: str, port: int, timeout: float = 5.0) -> bool:
    """Actively probe the TCP port until it accepts a connection."""
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        try:
            _, writer = await asyncio.open_connection(host, port)
            writer.close()
            await writer.wait_closed()
            return True
        except OSError:
            await asyncio.sleep(0.05)
    return False


async def _start_server(tmp_path: Path, config: Path, router):
    """Start the JSON-line server on the first available port."""
    for port in range(55100, 55120):
        task = asyncio.create_task(
            serve_json_lines(
                "127.0.0.1",
                port,
                str(tmp_path / "khaos.db"),
                project_root=tmp_path,
                config_path=config,
                router=router,
            )
        )
        await asyncio.sleep(0.02)
        if task.done():
            try:
                await task
            except PermissionError:
                return None
            except OSError:
                continue
        return task, port
    return None


async def test_python_json_line_server_round_trip(tmp_path):
    """Deterministic round-trip: Fake Provider → JSON-line server → events."""
    (tmp_path / "prompts").mkdir()
    (tmp_path / "prompts" / "office.md").write_text("office prompt", encoding="utf-8")
    (tmp_path / "prompts" / "coding.md").write_text("coding prompt", encoding="utf-8")
    config = tmp_path / "config.yaml"
    config.write_text("database:\n  path: khaos.db\n", encoding="utf-8")

    # Fake Provider: one assistant message, then end-turn. No external LLM.
    fake_router = _FakeRouter([
        [Message(role="assistant", content="hello back", stop_reason="end_turn")],
    ])

    server = await _start_server(tmp_path, config, fake_router)
    if server is None:
        pytest.skip("sandbox does not allow binding TCP sockets")
    task, port = server
    try:
        # Ready probe: actively wait for the port to accept connections.
        ready = await _wait_for_port("127.0.0.1", port, timeout=5.0)
        if not ready:
            # Surface the server task exception for diagnosis.
            if task.done():
                exc = task.exception()
                pytest.fail(f"server failed to start: {exc}")
            pytest.fail(f"server did not become ready on port {port} within 5s")

        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(
            (
                json.dumps(
                    {
                        "method": "AgentService.Chat",
                        "payload": {"session_id": "s1", "message": "hello", "mode": "office"},
                    }
                )
                + "\n"
            ).encode("utf-8")
        )
        await writer.drain()
        events = []
        try:
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=10.0)
                if not line:
                    break
                events.append(json.loads(line))
        except asyncio.TimeoutError:
            pytest.fail(f"timed out waiting for events; got {len(events)} so far: {events}")
        writer.close()
        await writer.wait_closed()
        assert len(events) >= 1, "expected at least one event"
        assert events[0]["event"] == "message", f"first event was {events[0]}"
        assert events[-1]["event"] == "done", f"last event was {events[-1]}"
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            # Surface any unexpected server-side exception for diagnosis.
            print(f"server task ended with: {exc}")
