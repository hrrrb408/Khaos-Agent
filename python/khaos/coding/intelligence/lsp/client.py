"""Offline stdio LSP JSON-RPC client backed by ExecutionService."""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote, urlparse

from khaos.coding.execution.cleanup_ledger import CleanupLedger
from khaos.coding.execution.models import (
    ExecutionRequest,
    NetworkPolicy,
    ResourceBudget,
)

logger = logging.getLogger(__name__)

_MAX_MESSAGE_BYTES = 8 * 1024 * 1024


@dataclass(frozen=True)
class LspDiagnostic:
    code: str
    message: str
    degraded: bool = True


class LspCloseError(RuntimeError):
    """Typed error when LSP close partially fails (Batch 15.3)."""


class _LspState:
    """Round-15 review §十一/§十二/§十三: LSP lifecycle state machine.

    NEW → STARTING → RUNNING → CLOSING → CLOSED (or QUARANTINED).
    Prevents concurrent ``start()`` double-spawn and false-close on
    ``close()`` partial failure.
    """

    NEW = "new"
    STARTING = "starting"
    RUNNING = "running"
    CLOSING = "closing"
    CLOSED = "closed"
    QUARANTINED = "quarantined"


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
        # Round-15 review §十一/§十二/§十三: typed lifecycle state replaces
        # the two booleans (_closed/_started) whose combinations allowed
        # concurrent start() double-spawn and false-close on partial
        # close() failure.
        self._lifecycle_state = _LspState.NEW
        self._lifecycle_lock = asyncio.Lock()
        self._close_error: BaseException | None = None
        # Batch 15.3: per-step completion ledger so a QUARANTINED close is
        # retryable — only failed steps are retried.
        self._cleanup_ledger = CleanupLedger()
        self._stream_error: Exception | None = None

    @property
    def _closed(self) -> bool:
        """Backward-compat: True only when cleanly CLOSED (not QUARANTINED)."""
        return self._lifecycle_state is _LspState.CLOSED

    @property
    def _started(self) -> bool:
        """Backward-compat: True when RUNNING (past STARTING)."""
        return self._lifecycle_state in {_LspState.RUNNING, _LspState.CLOSING, _LspState.CLOSED, _LspState.QUARANTINED}

    @property
    def stderr(self) -> str:
        return "" if self._process is None else self._process.stderr_text

    @property
    def stderr_truncated(self) -> bool:
        return False if self._process is None else self._process.stderr_truncated

    async def start(self, root_uri: str) -> dict:
        # Round-15 review §十一: concurrent start() must not double-spawn.
        # The lifecycle lock + STARTING state prevent two tasks from both
        # passing the ``_started`` check and spawning two LSP processes.
        async with self._lifecycle_lock:
            if self._lifecycle_state is _LspState.CLOSED:
                return {"ok": False, "diagnostic": LspDiagnostic("closed", "LSP client is closed")}
            if self._lifecycle_state is _LspState.QUARANTINED:
                return {"ok": False, "diagnostic": LspDiagnostic("quarantined", "LSP client is quarantined")}
            if self._lifecycle_state is _LspState.STARTING:
                return {"ok": False, "diagnostic": LspDiagnostic("already-starting", "LSP client is already starting")}
            if self._lifecycle_state in {_LspState.RUNNING, _LspState.CLOSING}:
                return {"ok": False, "diagnostic": LspDiagnostic("already-started", "LSP client already started")}
            if not self.argv:
                return {"ok": False, "diagnostic": LspDiagnostic("empty-command", "LSP command is empty")}
            if self.trusted_argv != self.argv:
                return {"ok": False, "diagnostic": LspDiagnostic("untrusted-command", "LSP command is not from trusted configuration")}
            self._lifecycle_state = _LspState.STARTING
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
            # Round-15 review §十一: only transition to RUNNING after the
            # full start sequence (spawn + initialize + initialized) succeeds.
            self._lifecycle_state = _LspState.RUNNING
            return {"ok": True, "capabilities": response.get("capabilities", {})}
        except (TimeoutError, OSError, RuntimeError, PermissionError, ValueError) as exc:
            await self.close()
            return {"ok": False, "diagnostic": LspDiagnostic("server-unavailable", str(exc))}
        except asyncio.CancelledError:
            # Round-15 review §十三: start cancellation must roll back the
            # partially-spawned process.  close() is idempotent and will
            # terminate the process if it was spawned.
            await self.close()
            raise

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
        """Close the LSP client, terminating the server if needed.

        Round-15 review §十二: previously ``close()`` always set
        ``_closed=True`` in ``finally``, even when ``terminate()`` raised.
        This was a false-close: the client claimed to no longer own the
        process while the process might still be alive.  Now close() uses a
        typed state machine (CLOSING → CLOSED/QUARANTINED) and a per-step
        ``CleanupLedger`` so a partial failure enters QUARANTINED and a
        retry only runs the failed steps.

        Batch 15.3: the graceful LSP ``shutdown`` request is best-effort —
        a ``TimeoutError``/``OSError``/``RuntimeError`` from it simply
        triggers the force-terminate path and is NOT recorded as a cleanup
        error.  Only the force-terminate, reader-cancel, and
        execution-service terminate steps are required cleanup steps whose
        failure enters QUARANTINED.
        """
        if self._lifecycle_state is _LspState.CLOSED:
            return
        if self._lifecycle_state is _LspState.NEW:
            # Never started — nothing to clean up.
            self._lifecycle_state = _LspState.CLOSED
            return
        # Concurrent close callers: serialise via the lifecycle lock so
        # only one runs the cleanup sequence at a time.
        async with self._lifecycle_lock:
            if self._lifecycle_state is _LspState.CLOSED:
                return
            self._lifecycle_state = _LspState.CLOSING
            self._cleanup_ledger.reset_errors()
            cancel_requested = False
            process = self._process

            # Steps 1+2: ensure the LSP process is terminated.  The graceful
            # ``shutdown`` request is best-effort — its failure (timeout,
            # stream error) just triggers force-terminate.  The combined
            # step ``process_terminate`` is marked done ONLY when the
            # postcondition is met: process.returncode is not None.
            # Batch 16.1 (round-16 review §四–§六): previously mark_done
            # was called unconditionally after record_error, which erased
            # the error via CleanupLedger.mark_done's ``_errors.pop()``.
            # This was a textbook false-close: the ledger reported no
            # errors even though the process was still alive.
            if process is not None and not self._cleanup_ledger.is_done("process_terminate"):
                if process.returncode is None:
                    # Try graceful shutdown first.
                    try:
                        await self._request_during_close("shutdown", {})
                        await _write_message(process, {"jsonrpc": "2.0", "method": "exit", "params": {}})
                        await asyncio.wait_for(process.wait(), self.timeout)
                    except asyncio.CancelledError:
                        cancel_requested = True
                    except (TimeoutError, OSError, RuntimeError):
                        # Graceful shutdown failed — fall through to
                        # force-terminate.  This is expected behavior, not
                        # a cleanup error.
                        pass
                    # If still alive, force-terminate.
                    if process.returncode is None:
                        try:
                            await process.terminate()
                            try:
                                await asyncio.wait_for(process.wait(), 2.0)
                            except TimeoutError:
                                await process.kill()
                                await process.wait()
                        except asyncio.CancelledError:
                            cancel_requested = True
                        except Exception as exc:  # noqa: BLE001
                            self._cleanup_ledger.record_error("process_terminate", exc)
                            logger.debug("LSP force-terminate failed: %s", exc)
                # Postcondition: process must be confirmed dead.
                if process.returncode is not None:
                    self._cleanup_ledger.mark_done("process_terminate")
                elif not self._cleanup_ledger.failed_steps or "process_terminate" not in self._cleanup_ledger.failed_steps:
                    # No error was recorded but postcondition is not met
                    # (e.g. CancelledError interrupted before terminate
                    # could run).  Record a postcondition violation.
                    self._cleanup_ledger.record_error(
                        "process_terminate",
                        RuntimeError("process_terminate postcondition not met: returncode is None"),
                    )

            # Step 3: cancel and await reader task.
            # Batch 16.1: mark_done only when reader_task is None or done().
            if not self._cleanup_ledger.is_done("reader_cancel"):
                if self._reader_task is not None:
                    try:
                        self._reader_task.cancel()
                        await asyncio.gather(self._reader_task, return_exceptions=True)
                    except asyncio.CancelledError:
                        cancel_requested = True
                    except Exception as exc:  # noqa: BLE001
                        self._cleanup_ledger.record_error("reader_cancel", exc)
                # Postcondition: reader_task is None or done.
                if self._reader_task is None or self._reader_task.done():
                    self._cleanup_ledger.mark_done("reader_cancel")
                elif not self._cleanup_ledger.failed_steps or "reader_cancel" not in self._cleanup_ledger.failed_steps:
                    self._cleanup_ledger.record_error(
                        "reader_cancel",
                        RuntimeError("reader_cancel postcondition not met: task still active"),
                    )

            # Step 4: fail pending requests.
            if not self._cleanup_ledger.is_done("fail_pending"):
                self._fail_pending(RuntimeError("LSP client closed"))
                self._cleanup_ledger.mark_done("fail_pending")

            # Step 5: terminate via ExecutionService (unregister from supervisor).
            # Batch 16.1: mark_done only after successful terminate.
            if process is not None and not self._cleanup_ledger.is_done("exec_terminate"):
                try:
                    await self.execution_service.terminate(process.execution_id)
                    self._cleanup_ledger.mark_done("exec_terminate")
                except asyncio.CancelledError:
                    cancel_requested = True
                except Exception as exc:  # noqa: BLE001 — terminate during close
                    self._cleanup_ledger.record_error("exec_terminate", exc)
                    logger.debug("LSP execution_service.terminate failed: %s", exc)

            errors = self._cleanup_ledger.errors
            if errors:
                self._close_error = errors[0]
                self._lifecycle_state = _LspState.QUARANTINED
                # Do NOT clear _process/_reader_task — a retry may need them.
                raise LspCloseError(
                    f"LSP close completed with {len(errors)} error(s): "
                    + "; ".join(type(e).__name__ for e in errors)
                ) from errors[0]
            self._lifecycle_state = _LspState.CLOSED
            self._process = None
            self._reader_task = None
            if cancel_requested:
                raise asyncio.CancelledError()

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
        raise ValueError("LSP payload must be an object")  # noqa: TRY004 - parser compatibility
    return decoded
