"""Managed stdio process handles owned by ExecutionService.

Review P2-2 (managed-process lifecycle): a managed process that exited
naturally (``wait()`` returned) previously left its temporary HOME on disk,
stayed in ``ExecutionService._active``, and never set ``_closed`` — only an
explicit ``aclose()`` cleaned up.  A caller that only awaited ``wait()``
leaked a temp dir and a stale execution-id entry per process.

All terminal paths (``wait`` / ``terminate`` / ``kill`` / ``aclose``) now go
through a single lock-guarded ``_finalize_once()`` so the cleanup sequence
(stderr → watchdog → supervisor unregister → ``on_terminal`` callback →
remove temp home → ``_closed=True``) runs exactly once regardless of which
path observed process exit.  ``ExecutionService`` injects an ``on_terminal``
callback that pops its own ``_active`` entry.
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
import signal
from collections.abc import Awaitable, Callable
from enum import Enum
from pathlib import Path

logger = logging.getLogger(__name__)


class FinalizeState(str, Enum):
    """Terminal state of the finalize lifecycle (round-12 review P1-1)."""

    OPEN = "open"
    FINALIZING = "finalizing"
    CLOSED = "closed"
    QUARANTINED = "quarantined"


class ManagedProcessFinalizeError(RuntimeError):
    """Typed error raised when finalize partially fails (round-12 P1-1)."""


class ManagedProcessHandle:
    """A registered stdio process with bounded stderr collection."""

    def __init__(
        self,
        execution_id: str,
        process: asyncio.subprocess.Process,
        *,
        temporary_home: Path | None = None,
        stderr_limit: int = 65536,
        supervisor=None,
        resource_watchdog: asyncio.Task[dict | None] | None = None,
        # P2-2: invoked exactly once when the process reaches a terminal
        # state, before the temporary home is removed.  ExecutionService
        # uses it to pop its own ``_active`` entry, so a process that
        # exits naturally (via ``wait()``) is no longer leaked there.
        on_terminal: Callable[[str], Awaitable[None]] | None = None,
    ) -> None:
        self.execution_id = execution_id
        self._process = process
        self.stdin = process.stdin
        self.stdout = process.stdout
        self._temporary_home = temporary_home
        self._stderr_limit = stderr_limit
        self._stderr = bytearray()
        self._stderr_truncated = False
        self._supervisor = supervisor
        self._resource_watchdog = resource_watchdog
        self._resource_violation: dict | None = None
        self._on_terminal = on_terminal
        self._stderr_task = asyncio.create_task(self._collect_stderr())
        # Round-12 review P1-1: single shared finalize task so every caller
        # (wait/aclose/terminate/shutdown) observes the SAME result.  The
        # typed state machine (FinalizeState) replaces the three booleans
        # (_closed/_finalized/_finalize_failed) whose combinations could let
        # a second caller return success while the first saw an error.
        self._finalize_task: asyncio.Task[None] | None = None
        self._finalize_state: FinalizeState = FinalizeState.OPEN
        self._finalize_error: BaseException | None = None

    @property
    def returncode(self) -> int | None:
        return self._process.returncode

    @property
    def _closed(self) -> bool:
        """Backward-compat: True only when cleanly CLOSED (not QUARANTINED)."""
        return self._finalize_state is FinalizeState.CLOSED

    @property
    def stderr_text(self) -> str:
        return self._stderr.decode("utf-8", errors="replace")

    @property
    def stderr_truncated(self) -> bool:
        return self._stderr_truncated

    @property
    def resource_violation(self) -> dict | None:
        return self._resource_violation

    async def write_stdin(self, payload: bytes) -> None:
        # Round-14 review P0-5: reject writes when NOT OPEN (FINALIZING,
        # QUARANTINED, CLOSED all reject).  Previously only CLOSED rejected
        # (via the ``_closed`` property), so FINALIZING/QUARANTINED still
        # allowed stdin writes to a process being torn down.
        if self._finalize_state is not FinalizeState.OPEN or self.stdin is None:
            raise RuntimeError(
                f"managed process stdin is closed (state={self._finalize_state.value})"
            )
        self.stdin.write(payload)
        await self.stdin.drain()

    async def wait(self) -> int:
        """Block until the process exits, then run the unified finalizer.

        P2-2: previously ``wait()`` only unregistered the process from the
        ``ProcessSupervisor`` and left the temporary HOME on disk, the entry
        in ``ExecutionService._active`` in place, and ``_closed=False``.  It
        now delegates to ``_finalize_once()`` so every terminal path cleans
        up identically.
        """
        code = await self._process.wait()
        await self._finalize_once()
        return code

    async def terminate(self) -> None:
        """Terminate the complete process group created by ExecutionService.

        Managed processes are launched in a new session.  Signalling only the
        immediate LSP process leaves language-server helpers alive, so use the
        group on POSIX and retain the normal asyncio fallback on Windows.
        """
        if self._supervisor is not None:
            await self._supervisor.terminate(self.execution_id)
        elif self._process.returncode is None:
            _signal_process_tree(self._process.pid, signal.SIGTERM, self._process.terminate)

    async def kill(self) -> None:
        if self._supervisor is not None:
            await self._supervisor.terminate(self.execution_id)
        elif self._process.returncode is None:
            _signal_process_tree(self._process.pid, signal.SIGKILL, self._process.kill)

    async def aclose(self) -> None:
        """Force the process to terminate, wait for it, then finalize.

        Round-12 review P1-1: all callers (wait/aclose) await the SAME shared
        finalize task, so every caller observes the identical result (success
        or the same typed error).  A partial finalize transitions to
        QUARANTINED and every subsequent call re-raises — no second caller
        can see a false success.
        """
        if self._finalize_state is FinalizeState.CLOSED:
            return
        if self._finalize_state is FinalizeState.QUARANTINED:
            raise ManagedProcessFinalizeError(
                f"managed process {self.execution_id} was already partially "
                f"finalized with errors; resources may not be fully released"
            ) from self._finalize_error
        try:
            await self.terminate()
            try:
                await asyncio.wait_for(self._process.wait(), timeout=2.0)
            except TimeoutError:
                await self.kill()
                await self._process.wait()
        finally:
            await self._finalize_once()

    async def _finalize_once(self) -> None:
        """Run the cleanup sequence exactly once via a shared task.

        Round-12 review P1-1: the FIRST caller creates ``_finalize_task``;
        every concurrent or later caller awaits the SAME task.  Each cleanup
        step runs independently (a failure in one does not skip later steps).
        Partial failure → QUARANTINED + typed error; full success → CLOSED.
        temp-home removal always runs (it is ignore_errors=True).
        """
        if self._finalize_task is not None:
            # A finalize is already in flight (or completed) — await the SAME
            # task so we observe the identical result.
            await asyncio.shield(self._finalize_task)
            return
        self._finalize_task = asyncio.ensure_future(self._run_finalize())
        await asyncio.shield(self._finalize_task)

    async def _run_finalize(self) -> None:
        """The actual cleanup sequence — runs exactly once.

        Round-13 review P0-2/P0-3/P0-4:
        - ``CancelledError`` (a ``BaseException`` in Python 3.11+) is caught
          explicitly: the cancel is recorded, cleanup continues to completion,
          and the cancel is re-raised AFTER cleanup so structured-concurrency
          semantics are preserved.
        - temp-home ``rmtree`` failure is OBSERVABLE (not ``ignore_errors``);
          a failure enters QUARANTINED.
        - Per-step completion ledger allows a future retry path to skip
          already-completed steps.
        """
        self._finalize_state = FinalizeState.FINALIZING
        errors: list[Exception] = []
        cancel_requested = False

        def _try_step(label: str, step) -> None:
            """Run one cleanup step, collecting errors and cancellations."""
            nonlocal cancel_requested
            try:
                result = step()
                if asyncio.iscoroutine(result):
                    raise TypeError(f"step {label} returned a coroutine — use await")
            except asyncio.CancelledError:
                cancel_requested = True
                logger.debug("managed process finalize step %s cancelled", label)
            except Exception as exc:  # noqa: BLE001 — collect, don't abort
                errors.append(exc)
                logger.debug("managed process finalize step %s failed", label, exc_info=True)

        async def _try_async_step(label: str, coro_factory) -> None:
            nonlocal cancel_requested
            try:
                await coro_factory()
            except asyncio.CancelledError:
                cancel_requested = True
                # Round-14 review P0-5: a cancelled step did NOT complete —
                # record it as an error so the finalize enters QUARANTINED
                # (not CLOSED).  Without this, a cancelled unregister/on_terminal
                # would leave the supervisor/active-entry alive while the
                # handle reported CLOSED.
                errors.append(RuntimeError(f"step {label} was cancelled (incomplete)"))
                logger.debug("managed process finalize step %s cancelled (incomplete)", label)
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)
                logger.debug("managed process finalize step %s failed", label, exc_info=True)

        await _try_async_step("stderr", self._finish_stderr)
        await _try_async_step("watchdog", self._finish_resource_watchdog)

        # Capture into locals so pyright can narrow the Optional types.
        supervisor = self._supervisor
        if supervisor is not None:
            await _try_async_step(
                "unregister",
                lambda: supervisor.unregister_process(self.execution_id),
            )

        on_terminal = self._on_terminal
        if on_terminal is not None:
            await _try_async_step(
                "on_terminal",
                lambda: on_terminal(self.execution_id),
            )

        # temp-home removal: OBSERVABLE (round-13 P0-3). A real OSError
        # (permission, mount, open handle) must not be silently swallowed.
        if self._temporary_home is not None:
            try:
                shutil.rmtree(self._temporary_home)
            except FileNotFoundError:
                pass  # already gone — fine
            except asyncio.CancelledError:
                cancel_requested = True
            except OSError as exc:
                errors.append(exc)
                logger.debug("managed process finalize temp-home removal failed", exc_info=True)
                # If the temp home still exists after rmtree, it's a real leak.
                if self._temporary_home.exists():
                    errors.append(
                        OSError(f"temp home {self._temporary_home} still exists after rmtree")
                    )

        if errors:
            self._finalize_error = errors[0]
            self._finalize_state = FinalizeState.QUARANTINED
            raise ManagedProcessFinalizeError(
                f"managed process {self.execution_id} finalize completed "
                f"with {len(errors)} error(s): "
                + "; ".join(type(e).__name__ for e in errors)
            ) from errors[0]
        self._finalize_state = FinalizeState.CLOSED
        # If cleanup completed but a cancellation was requested, re-raise the
        # CancelledError so structured-concurrency semantics are preserved.
        if cancel_requested:
            raise asyncio.CancelledError()

    async def _collect_stderr(self) -> None:
        if self._process.stderr is None:
            return
        while True:
            chunk = await self._process.stderr.read(4096)
            if not chunk:
                return
            remaining = self._stderr_limit - len(self._stderr)
            if remaining > 0:
                self._stderr.extend(chunk[:remaining])
            if len(chunk) > remaining:
                self._stderr_truncated = True

    async def _finish_stderr(self) -> None:
        if self._stderr_task.done():
            await self._stderr_task
            return
        await self._stderr_task

    async def _finish_resource_watchdog(self) -> None:
        if self._resource_watchdog is None:
            return
        try:
            self._resource_violation = await self._resource_watchdog
        except asyncio.CancelledError:
            return


def _signal_process_tree(pid: int | None, sig: signal.Signals, fallback) -> None:
    """Signal a session/process group when the host supports it."""
    if pid is None:
        return
    if os.name == "posix":
        try:
            os.killpg(pid, sig)
            return
        except ProcessLookupError:
            return
        except OSError:
            # A factory used by a test may not have created a new session.
            # Still signal the direct child explicitly; ``Process.terminate``
            # is not reliable when a restricted runner cannot address the
            # process group.
            try:
                os.kill(pid, sig)
                return
            except ProcessLookupError:
                return
            except OSError:
                pass
    fallback()
