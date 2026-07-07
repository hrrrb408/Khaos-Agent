import asyncio
import json
from pathlib import Path

import pytest

from khaos.grpc_server import serve_json_lines


async def test_python_json_line_server_round_trip(tmp_path):
    (tmp_path / "prompts").mkdir()
    (tmp_path / "prompts" / "office.md").write_text("office prompt", encoding="utf-8")
    (tmp_path / "prompts" / "coding.md").write_text("coding prompt", encoding="utf-8")
    config = tmp_path / "config.yaml"
    config.write_text("database:\n  path: khaos.db\n", encoding="utf-8")
    server = await _start_server(tmp_path, config)
    if server is None:
        pytest.skip("sandbox does not allow binding TCP sockets")
    task, port = server
    try:
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
        while True:
            line = await reader.readline()
            if not line:
                break
            events.append(json.loads(line))
        writer.close()
        await writer.wait_closed()
        assert events[0]["event"] == "message"
        assert events[-1]["event"] == "done"
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


async def _start_server(tmp_path: Path, config: Path):
    for port in range(55100, 55120):
        task = asyncio.create_task(
            serve_json_lines(
                "127.0.0.1",
                port,
                str(tmp_path / "khaos.db"),
                project_root=tmp_path,
                config_path=config,
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
