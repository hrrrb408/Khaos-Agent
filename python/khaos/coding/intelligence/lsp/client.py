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
        # A process returned from ExecutionService is owned immediately,
        # before lifecycle publication.  This closes the acquisition gap
        # where a spawned process existed only in a local variable while a
        # concurrent close could prove ``_process is None`` and transition
        # CLOSED.
        self._pending_process = None
        self._execution_id: str | None = None
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
        # Round-17 review §三: start transaction tracking.  The generation
        # counter invalidates a start transaction when close() begins, so
        # spawn-after-close is rolled back instead of leaking a process.
        # The shared ``_close_task`` ensures concurrent close() callers
        # observe the same result (like ExecutionService).
        self._start_generation = 0
        self._start_task: asyncio.Task | None = None
        self._close_task: asyncio.Task | None = None

    @property
    def _closed(self) -> bool:
        """Backward-compat: True only when cleanly CLOSED (not QUARANTINED)."""
        return self._lifecycle_state is _LspState.CLOSED

    @property
    def _started(self) -> bool:
        """Backward-compat: True when RUNNING (past STARTING)."""
        return self._lifecycle_state in {_LspState.RUNNING, _LspState.CLOSING, _LspState.CLOSED, _LspState.QUARANTINED}

    # Round-17 review §十四: ResourceOwner protocol — unified lifecycle
    # properties so LspClient can be tested by the same Resource Ownership
    # Closure E2E suite as ProcessSupervisor and BrowserEgressProxy.

    @property
    def admission_closed(self) -> bool:
        """Compatibility alias for the generation admission fence."""
        return self._lifecycle_state is not _LspState.NEW

    @property
    def generation_admission_closed(self) -> bool:
        """True when a new LSP process generation must be rejected."""
        return self._lifecycle_state is not _LspState.NEW

    @property
    def child_admission_closed(self) -> bool:
        """True when this LSP generation cannot admit child work."""
        return self._lifecycle_state is not _LspState.RUNNING

    @property
    def terminal_closed(self) -> bool:
        """True ONLY when CLOSED — process, reader, and exec ownership
        are all proven terminal."""
        return self._lifecycle_state is _LspState.CLOSED

    @property
    def is_quarantined(self) -> bool:
        """True when QUARANTINED — cleanup failed, resources may be alive."""
        return self._lifecycle_state is _LspState.QUARANTINED

    def owned_resources(self) -> tuple[str, ...]:
        """Descriptors of currently-held resources: LSP process, reader
        task, and ExecutionService ownership."""
        resources: list[str] = []
        process = self._process or self._pending_process
        if process is not None:
            label = "lsp_process" if process is self._process else "lsp_pending_process"
            resources.append(f"{label}:{process.execution_id}")
        if self._execution_service_owns(process):
            resources.append("execution_service:managed_process")
        if self._reader_task is not None and not self._reader_task.done():
            resources.append("lsp_reader_task")
        if self._pending:
            resources.append("lsp_request_transactions")
        if self._start_task is not None and not self._start_task.done():
            resources.append("lsp_start_transaction")
        return tuple(resources)

    def terminal_postcondition(self) -> bool:
        """True when process is None, reader task is done/None, and no
        start transaction is in flight."""
        return (
            self._process is None
            and self._pending_process is None
            and (self._reader_task is None or self._reader_task.done())
            and (self._start_task is None or self._start_task.done())
            and not self._pending
            and not self._execution_service_owns(None)
        )

    def _execution_service_owns(self, process) -> bool:
        """Return independent evidence that ExecutionService still owns us."""
        execution_id = getattr(process, "execution_id", None) or self._execution_id
        if execution_id is None:
            return False
        owns_execution = getattr(self.execution_service, "owns_execution", None)
        if callable(owns_execution):
            return bool(owns_execution(execution_id))
        active = getattr(self.execution_service, "_active", None)
        return isinstance(active, dict) and execution_id in active

    @property
    def stderr(self) -> str:
        return "" if self._process is None else self._process.stderr_text

    @property
    def stderr_truncated(self) -> bool:
        return False if self._process is None else self._process.stderr_truncated

    async def start(self, root_uri: str) -> dict:
        """Start the LSP server and initialize the JSON-RPC session.

        Round-17 review §三: the start transaction now tracks a generation
        counter.  If ``close()`` begins while ``start()`` is suspended at
        ``await spawn(...)``, the generation mismatch is detected on
        ownership publication and the spawned process is rolled back
        (terminated + unregistered) instead of being published to a
        closed client and leaked.
        """
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
            self._start_generation += 1
            generation = self._start_generation
            self._lifecycle_state = _LspState.STARTING
            self._start_task = asyncio.current_task()
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
            process = await self.execution_service.start_managed_process(request)
            # No await is allowed between receiving the acquired process and
            # recording it as pending ownership.  Publication may still race
            # with close(), but the process can no longer disappear from the
            # owner's graph while rollback is in progress.
            self._pending_process = process
            self._execution_id = process.execution_id
            # Round-17 review §三: ownership publication with generation
            # validation.  After spawn returns, re-check state/generation
            # under the lock before publishing ``self._process``.  If
            # close() won the race (transitioned to CLOSING/CLOSED),
            # rollback the spawned process instead of publishing it to a
            # closed client.  This closes the spawn-after-close window.
            published = False
            async with self._lifecycle_lock:
                if (
                    self._lifecycle_state is not _LspState.STARTING
                    or self._start_generation != generation
                ):
                    # Close won the race — rollback the spawned process.
                    # Release the lock before awaiting termination.
                    pass
                else:
                    self._process = process
                    self._pending_process = None
                    published = True
            if not published:
                await self._rollback_spawned_process(process)
                return {"ok": False, "diagnostic": LspDiagnostic("closed", "LSP client closed during start")}
            self._reader_task = asyncio.create_task(self._reader_loop())
            response = await self.request("initialize", {"rootUri": root_uri, "capabilities": {}})
            await self.notify("initialized", {})
            # Round-17 review §三: final publication — transition to
            # RUNNING only if still STARTING.  If close() raced in
            # during initialize, close() owns the cleanup; just return.
            async with self._lifecycle_lock:
                if self._lifecycle_state is not _LspState.STARTING:
                    self._start_task = None
                    return {"ok": False, "diagnostic": LspDiagnostic("closed", "LSP client closed during initialization")}
                self._lifecycle_state = _LspState.RUNNING
                self._start_task = None
            return {"ok": True, "capabilities": response.get("capabilities", {})}
        except (TimeoutError, OSError, RuntimeError, PermissionError, ValueError) as exc:
            # Only call close() if we're still STARTING.  If close()
            # already began (CLOSING/CLOSED), it owns the cleanup.
            if self._lifecycle_state is _LspState.STARTING:
                await self.close()
            return {"ok": False, "diagnostic": LspDiagnostic("server-unavailable", str(exc))}
        except asyncio.CancelledError:
            # Round-15 review §十三: start cancellation must roll back the
            # partially-spawned process.  close() is idempotent and will
            # terminate the process if it was spawned.
            if self._lifecycle_state is _LspState.STARTING:
                await self.close()
            raise
        finally:
            async with self._lifecycle_lock:
                if self._start_task is asyncio.current_task():
                    self._start_task = None

    async def request(self, method: str, params: dict) -> dict:
        # Round-17: check CLOSING in addition to CLOSED so an in-flight
        # start() initialize unblocks immediately when close() begins.
        if self._lifecycle_state is _LspState.CLOSED:
            raise RuntimeError("LSP client is closed")
        if self._lifecycle_state is _LspState.CLOSING:
            raise RuntimeError("LSP client is closing")
        if self._process is None or self._process.stdin is None:
            raise RuntimeError("LSP client is not started")
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
        if self._lifecycle_state is _LspState.CLOSED:
            raise RuntimeError("LSP client is closed")
        if self._lifecycle_state is _LspState.CLOSING:
            raise RuntimeError("LSP client is closing")
        if self._process is None:
            raise RuntimeError("LSP client is not started")
        if self._stream_error is not None:
            raise RuntimeError(f"LSP server stream ended: {self._stream_error}")
        await _write_message(self._process, {"jsonrpc": "2.0", "method": method, "params": params})

    async def close(self) -> None:
        """Close the LSP client, terminating the server if needed.

        Round-17 review §三: close() now uses a shared ``_close_task`` so
        concurrent callers observe the same result (like ExecutionService).
        The actual cleanup runs in ``_run_close()`` which:

        1. Transitions to CLOSING and fails pending requests (unblocking
           any in-flight ``start()`` initialize).
        2. Waits for an in-flight start transaction to either publish
           ``_process`` or rollback — so close() sees any spawned process.
        3. Runs the per-step cleanup ledger (process_terminate,
           reader_cancel, fail_pending, exec_terminate) with postcondition
           verification.  CancelledError during exec_terminate now enters
           QUARANTINED (not CLOSED) because ownership release is unproven.

        CRITICAL: if close() is called from within start() (i.e., the
        current task IS the start task), ``_run_close()`` is called
        directly instead of creating a separate ``_close_task``.  This
        avoids a deadlock: ``_run_close()`` Phase 2 would try to
        ``await asyncio.shield(start_task)``, but the start task is the
        one calling close() and cannot complete until close() returns.
        Calling ``_run_close()`` directly in the same task makes the
        Phase 2 ``start_task is not current`` check correctly skip the
        wait.
        """
        if self._lifecycle_state is _LspState.CLOSED:
            return
        if self._lifecycle_state is _LspState.NEW:
            self._lifecycle_state = _LspState.CLOSED
            return
        # Deadlock avoidance: if close() is called from within start()
        # (i.e., the current task IS the start task), run _run_close()
        # directly instead of creating a separate _close_task.  Otherwise
        # _run_close() Phase 2 would await shield(start_task), but
        # start_task is the one calling close() and cannot complete until
        # close() returns — a circular dependency / deadlock.  Running
        # _run_close() in the same task makes the Phase 2 ``start_task is
        # not current`` check correctly skip the wait.
        current_task = asyncio.current_task()
        if self._start_task is current_task:
            await self._run_close()
            return
        # Reuse an in-flight close task so concurrent callers observe the
        # same result.  A completed (failed) task is NOT reused —
        # QUARANTINED is retryable and a new task is created to use the
        # ledger to skip completed steps.
        if self._close_task is not None and not self._close_task.done():
            await asyncio.shield(self._close_task)
            return
        self._close_task = asyncio.ensure_future(self._run_close())
        await asyncio.shield(self._close_task)

    async def _run_close(self) -> None:
        """The actual cleanup sequence — may run multiple times via retry."""
        # Phase 1: transition to CLOSING and capture in-flight start task.
        start_task: asyncio.Task | None = None
        async with self._lifecycle_lock:
            if self._lifecycle_state is _LspState.CLOSED:
                return
            if self._lifecycle_state is _LspState.NEW:
                self._lifecycle_state = _LspState.CLOSED
                return
            start_task = self._start_task
            self._lifecycle_state = _LspState.CLOSING
            self._cleanup_ledger.reset_errors()
        # Fail pending requests outside the lock so an in-flight start()
        # initialize unblocks immediately instead of waiting for timeout.
        self._fail_pending(RuntimeError("LSP client is closing"))

        # Phase 2: if a DIFFERENT start transaction is in flight, wait
        # for it to either publish _process or rollback.  The lock is NOT
        # held during this wait so the start task can acquire it to check
        # state / publish / rollback.  This ensures _run_close sees any
        # spawned process before deciding to skip process_terminate.
        #
        # CRITICAL: if start_task is the CURRENT task (i.e., start()
        # called close() from its own exception handler), we MUST NOT
        # await it — that would deadlock (a task cannot wait for itself
        # to complete).  In that case the start task is already on the
        # stack and will return immediately after close() returns.
        current = asyncio.current_task()
        if (
            start_task is not None
            and not start_task.done()
            and start_task is not current
        ):
            try:
                await asyncio.shield(start_task)
            except (Exception, asyncio.CancelledError):
                pass  # start() handles its own rollback

        # Phase 3: cleanup with lock held.
        cancel_requested = False
        async with self._lifecycle_lock:
            if self._lifecycle_state is _LspState.CLOSED:
                return
            self._cleanup_ledger.reset_errors()
            # Include an acquired-but-not-yet-published process in cleanup.
            # The pending slot is the ownership lease for the spawn
            # transaction; it must not be dropped merely because publication
            # lost the start/close race.
            process = self._process or self._pending_process

            async def _run_step(
                step: str,
                action,
                verify,
                resource_generation=None,
            ) -> None:
                nonlocal cancel_requested
                try:
                    await self._cleanup_ledger.run_step(
                        step,
                        action=action,
                        verify=verify,
                        resource_generation=resource_generation,
                    )
                except asyncio.CancelledError:
                    # The ledger retains the failed step; continue collecting
                    # proof for the other resources before retry/quarantine.
                    cancel_requested = True

            async def _terminate_process() -> None:
                if process is None or process.returncode is not None:
                    return
                try:
                    if process is self._process:
                        await self._request_during_close("shutdown", {})
                        await _write_message(
                            process,
                            {"jsonrpc": "2.0", "method": "exit", "params": {}},
                        )
                    await asyncio.wait_for(process.wait(), self.timeout)
                except (TimeoutError, OSError, RuntimeError):
                    pass
                if process.returncode is None:
                    await process.terminate()
                    try:
                        await asyncio.wait_for(process.wait(), 2.0)
                    except TimeoutError:
                        await process.kill()
                        await process.wait()

            await _run_step(
                "process_terminate",
                _terminate_process,
                lambda: process is None or process.returncode is not None,
                getattr(process, "execution_id", None),
            )

            async def _cancel_reader() -> None:
                if self._reader_task is not None:
                    self._reader_task.cancel()
                    await asyncio.gather(self._reader_task, return_exceptions=True)

            await _run_step(
                "reader_cancel",
                _cancel_reader,
                lambda: self._reader_task is None or self._reader_task.done(),
            )

            async def _fail_pending_requests() -> None:
                self._fail_pending(RuntimeError("LSP client closed"))

            await _run_step(
                "fail_pending",
                _fail_pending_requests,
                lambda: not self._pending,
            )

            # Terminate via ExecutionService and independently prove that
            # the parent service no longer owns the execution id.
            execution_id = getattr(process, "execution_id", None) or self._execution_id

            async def _terminate_execution() -> None:
                if execution_id is not None:
                    await self.execution_service.terminate(execution_id)

            await _run_step(
                "exec_terminate",
                _terminate_execution,
                lambda: not self._execution_service_owns(process),
                execution_id,
            )

            errors = self._cleanup_ledger.errors
            if errors:
                self._close_error = errors[0]
                self._lifecycle_state = _LspState.QUARANTINED
                raise LspCloseError(
                    f"LSP close completed with {len(errors)} error(s): "
                    + "; ".join(type(e).__name__ for e in errors)
                ) from errors[0]
            self._lifecycle_state = _LspState.CLOSED
            self._process = None
            self._pending_process = None
            self._execution_id = None
            self._reader_task = None
            if cancel_requested:
                raise asyncio.CancelledError()

    async def _rollback_spawned_process(self, process) -> None:
        """Round-17 review §三: rollback a process whose ownership
        publication failed because close() won the start/close race.

        Terminates the process and unregisters it from ExecutionService so
        no resource is leaked.  Failure is retained as ownership: the
        pending slot is cleared only after both the process and the service
        ownership have terminal proof.  The concurrent close path can then
        quarantine and retry instead of observing a false CLOSED state.
        """
        errors: list[BaseException] = []
        try:
            if process.returncode is None:
                try:
                    await process.terminate()
                    try:
                        await asyncio.wait_for(process.wait(), 2.0)
                    except TimeoutError:
                        await process.kill()
                        await process.wait()
                except BaseException as exc:  # noqa: BLE001 — retain ownership on cancellation
                    errors.append(exc)
                    logger.debug("LSP rollback: process terminate failed: %s", exc)
            if process.returncode is None:
                errors.append(RuntimeError("LSP rollback process remains live"))
            try:
                await self.execution_service.terminate(process.execution_id)
            except BaseException as exc:  # noqa: BLE001 — retain ownership on cancellation
                errors.append(exc)
                logger.debug("LSP rollback: exec terminate failed: %s", exc)
            if self._execution_service_owns(process):
                errors.append(RuntimeError("LSP rollback execution ownership remains active"))
        finally:
            if not errors and process.returncode is not None and not self._execution_service_owns(process):
                if self._pending_process is process:
                    self._pending_process = None
                self._execution_id = None
        if errors:
            raise RuntimeError(
                "LSP rollback did not prove terminal ownership: "
                + "; ".join(type(error).__name__ for error in errors)
            ) from errors[0]

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
        # Once every waiter has been given a terminal exception, the owner
        # no longer retains a request transaction.  Individual request
        # ``finally`` blocks may still call pop(), which is harmless.
        self._pending.clear()

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
