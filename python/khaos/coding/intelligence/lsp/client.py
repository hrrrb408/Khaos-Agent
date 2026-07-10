"""Minimal, offline stdio LSP JSON-RPC client."""

from __future__ import annotations

import asyncio
import json
import uuid
from dataclasses import dataclass


@dataclass(frozen=True)
class LspDiagnostic:
    code: str
    message: str
    degraded: bool = True


class LspClient:
    def __init__(self, argv: tuple[str, ...], *, timeout: float = 10.0, restart_limit: int = 1) -> None:
        self.argv = argv
        self.timeout = timeout
        self.restart_limit = restart_limit
        self._process: asyncio.subprocess.Process | None = None
        self._next_id = 0
        self._restarts = 0

    async def start(self, root_uri: str) -> dict:
        if not self.argv:
            return {"ok": False, "diagnostic": LspDiagnostic("empty-command", "LSP command is empty")}
        try:
            self._process = await asyncio.create_subprocess_exec(*self.argv, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            response = await self.request("initialize", {"rootUri": root_uri, "capabilities": {}})
            await self.notify("initialized", {})
            return {"ok": True, "capabilities": response.get("capabilities", {})}
        except (OSError, asyncio.TimeoutError, RuntimeError) as exc:
            await self.close()
            return {"ok": False, "diagnostic": LspDiagnostic("server-unavailable", str(exc))}

    async def request(self, method: str, params: dict) -> dict:
        process = self._process
        if process is None or process.stdin is None or process.stdout is None:
            raise RuntimeError("LSP client is not started")
        self._next_id += 1
        request_id = self._next_id
        await _write_message(process.stdin, {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})
        while True:
            message = await asyncio.wait_for(_read_message(process.stdout), self.timeout)
            if message.get("id") == request_id:
                if "error" in message:
                    raise RuntimeError(str(message["error"]))
                return dict(message.get("result") or {})

    async def notify(self, method: str, params: dict) -> None:
        if self._process is not None and self._process.stdin is not None:
            await _write_message(self._process.stdin, {"jsonrpc": "2.0", "method": method, "params": params})

    async def close(self) -> None:
        process = self._process
        if process is None:
            return
        try:
            if process.returncode is None and process.stdin is not None:
                await self.request("shutdown", {})
                await self.notify("exit", {})
                await asyncio.wait_for(process.wait(), self.timeout)
        except (OSError, asyncio.TimeoutError, RuntimeError):
            if process.returncode is None:
                process.kill()
                await process.wait()
        finally:
            self._process = None


async def _write_message(writer: asyncio.StreamWriter, message: dict) -> None:
    payload = json.dumps(message, separators=(",", ":")).encode("utf-8")
    writer.write(f"Content-Length: {len(payload)}\r\n\r\n".encode("ascii") + payload)
    await writer.drain()


async def _read_message(reader: asyncio.StreamReader) -> dict:
    headers: dict[str, str] = {}
    while True:
        line = await reader.readline()
        if not line:
            raise RuntimeError("LSP server closed stdout")
        if line in {b"\r\n", b"\n"}:
            break
        key, _, value = line.decode("ascii").partition(":")
        headers[key.lower()] = value.strip()
    length = int(headers.get("content-length", "0"))
    payload = await reader.readexactly(length)
    return dict(json.loads(payload.decode("utf-8")))
