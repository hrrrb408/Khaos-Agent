"""Offline stdio LSP JSON-RPC client backed by ExecutionService."""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote, urlparse

from khaos.coding.execution.models import ExecutionRequest, NetworkPolicy, ResourceBudget


_MAX_MESSAGE_BYTES = 8 * 1024 * 1024


@dataclass(frozen=True)
class LspDiagnostic:
    code: str
    message: str
    degraded: bool = True


class LspClient:
    def __init__(
        self,
        argv: tuple[str, ...],
        *,
        execution_service,
        task_id: str,
        workspace_id: str,
        trusted_argv: tuple[str, ...] | None = None,
        timeout: float = 10.0,
        restart_limit: int = 1,
    ) -> None:
        self.argv = tuple(argv)
        self.trusted_argv = None if trusted_argv is None else tuple(trusted_argv)
        self.execution_service = execution_service
        self.task_id = task_id
        self.workspace_id = workspace_id
        self.timeout = timeout
        self.restart_limit = restart_limit
        self._process = None
        self._reader_task: asyncio.Task | None = None
        self._pending: dict[int, asyncio.Future[dict]] = {}
        self._next_id = 0
        self._restarts = 0
        self._closed = False
        self._started = False
        self._stream_error: Exception | None = None

    @property
    def stderr(self) -> str:
        return "" if self._process is None else self._process.stderr_text

    @property
    def stderr_truncated(self) -> bool:
        return False if self._process is None else self._process.stderr_truncated

    async def start(self, root_uri: str) -> dict:
        if self._closed:
            return {"ok": False, "diagnostic": LspDiagnostic("closed", "LSP client is closed")}
        if not self.argv:
            return {"ok": False, "diagnostic": LspDiagnostic("empty-command", "LSP command is empty")}
        if self.trusted_argv != self.argv:
            return {"ok": False, "diagnostic": LspDiagnostic("untrusted-command", "LSP command is not from trusted configuration")}
        try:
            root = self._validate_root_uri(root_uri)
            request = ExecutionRequest(
                argv=self.argv,
                cwd=root,
                environment={},
                allowed_environment_keys=frozenset(),
                network_policy=NetworkPolicy.NONE,
                budget=ResourceBudget(timeout_seconds=self.timeout, output_bytes=65536),
                task_id=self.task_id,
                workspace_id=self.workspace_id,
                access_mode="read-only",
                backend_hint="managed",
            )
            self._process = await self.execution_service.start_managed_process(request)
            self._reader_task = asyncio.create_task(self._reader_loop())
            response = await self.request("initialize", {"rootUri": root_uri, "capabilities": {}})
            await self.notify("initialized", {})
            self._started = True
            return {"ok": True, "capabilities": response.get("capabilities", {})}
        except (OSError, asyncio.TimeoutError, RuntimeError, PermissionError, ValueError) as exc:
            await self.close()
            return {"ok": False, "diagnostic": LspDiagnostic("server-unavailable", str(exc))}

    async def request(self, method: str, params: dict) -> dict:
        if self._closed or self._process is None or self._process.stdin is None:
            raise RuntimeError("LSP client is not started or is closed")
        if self._stream_error is not None:
            raise RuntimeError(f"LSP server stream ended: {self._stream_error}")
        self._next_id += 1
        request_id = self._next_id
        future: asyncio.Future[dict] = asyncio.get_running_loop().create_future()
        self._pending[request_id] = future
        try:
            await _write_message(self._process, {
                "jsonrpc": "2.0", "id": request_id, "method": method, "params": params,
            })
            message = await asyncio.wait_for(future, self.timeout)
            if "error" in message:
                raise RuntimeError(str(message["error"]))
            return dict(message.get("result") or {})
        finally:
            self._pending.pop(request_id, None)

    async def notify(self, method: str, params: dict) -> None:
        if self._closed or self._process is None:
            raise RuntimeError("LSP client is not started or is closed")
        if self._stream_error is not None:
            raise RuntimeError(f"LSP server stream ended: {self._stream_error}")
        await _write_message(self._process, {"jsonrpc": "2.0", "method": method, "params": params})

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        process = self._process
        try:
            if process is not None and process.returncode is None:
                try:
                    await self._request_during_close("shutdown", {})
                    await _write_message(process, {"jsonrpc": "2.0", "method": "exit", "params": {}})
                    await asyncio.wait_for(process.wait(), self.timeout)
                except (OSError, asyncio.TimeoutError, RuntimeError):
                    await process.terminate()
                    try:
                        await asyncio.wait_for(process.wait(), 2.0)
                    except asyncio.TimeoutError:
                        await process.kill()
                        await process.wait()
        finally:
            if self._reader_task is not None:
                self._reader_task.cancel()
                await asyncio.gather(self._reader_task, return_exceptions=True)
            self._fail_pending(RuntimeError("LSP client closed"))
            if process is not None:
                await self.execution_service.terminate(process.execution_id)
            self._process = None
            self._reader_task = None

    async def _request_during_close(self, method: str, params: dict) -> dict:
        process = self._process
        if process is None:
            raise RuntimeError("LSP process is unavailable")
        self._next_id += 1
        request_id = self._next_id
        future: asyncio.Future[dict] = asyncio.get_running_loop().create_future()
        self._pending[request_id] = future
        try:
            await _write_message(process, {
                "jsonrpc": "2.0", "id": request_id, "method": method, "params": params,
            })
            return await asyncio.wait_for(future, self.timeout)
        finally:
            self._pending.pop(request_id, None)

    async def _reader_loop(self) -> None:
        process = self._process
        if process is None or process.stdout is None:
            return
        try:
            while True:
                message = await _read_message(process.stdout)
                request_id = message.get("id")
                if isinstance(request_id, int):
                    future = self._pending.get(request_id)
                    if future is not None and not future.done():
                        future.set_result(message)
        except (RuntimeError, asyncio.IncompleteReadError, json.JSONDecodeError, ValueError) as exc:
            self._stream_error = exc
            self._fail_pending(RuntimeError(f"LSP server stream ended: {exc}"))

    def _fail_pending(self, error: Exception) -> None:
        for future in tuple(self._pending.values()):
            if not future.done():
                future.set_exception(error)

    def _validate_root_uri(self, root_uri: str) -> Path:
        parsed = urlparse(root_uri)
        if parsed.scheme != "file":
            raise ValueError("LSP rootUri must be a file URI")
        root = Path(unquote(parsed.path)).expanduser().resolve()
        workspace = self.execution_service.workspace_manager.get(self.workspace_id)
        if workspace is None or workspace.task_id != self.task_id:
            raise PermissionError("task/workspace binding is invalid")
        if root != workspace.worktree_path.expanduser().resolve():
            raise PermissionError("LSP rootUri must match the active TaskWorkspace")
        return root


async def _write_message(process, message: dict) -> None:
    payload = json.dumps(message, separators=(",", ":")).encode("utf-8")
    await process.write_stdin(
        f"Content-Length: {len(payload)}\r\n\r\n".encode("ascii") + payload
    )


async def _read_message(reader: asyncio.StreamReader) -> dict:
    headers: dict[str, str] = {}
    while True:
        line = await reader.readline()
        if not line:
            raise RuntimeError("LSP server closed stdout")
        if line in {b"\r\n", b"\n"}:
            break
        try:
            key, value = line.decode("ascii").split(":", 1)
        except ValueError as exc:
            raise ValueError("invalid LSP header") from exc
        headers[key.lower().strip()] = value.strip()
    length_value = headers.get("content-length")
    if length_value is None or not length_value.isdigit():
        raise ValueError("invalid LSP Content-Length")
    length = int(length_value)
    if length < 0 or length > _MAX_MESSAGE_BYTES:
        raise ValueError("LSP Content-Length exceeds limit")
    payload = await reader.readexactly(length)
    decoded = json.loads(payload.decode("utf-8"))
    if not isinstance(decoded, dict):
        raise ValueError("LSP payload must be an object")
    return decoded
