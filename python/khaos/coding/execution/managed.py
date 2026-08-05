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
import os
import shutil
import signal
from collections.abc import Awaitable, Callable
from pathlib import Path


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
        self._closed = False
        self._supervisor = supervisor
        self._resource_watchdog = resource_watchdog
        self._resource_violation: dict | None = None
        self._on_terminal = on_terminal
        self._stderr_task = asyncio.create_task(self._collect_stderr())
        # P2-2: serializes finalization so the cleanup sequence runs exactly
        # once even if ``wait()`` and ``aclose()`` race (e.g. the process
        # exits naturally while the caller is tearing it down).
        self._finalize_lock = asyncio.Lock()
        self._finalized = False
        # Round-11 review Medium-High-1: a partial finalize (some cleanup
        # steps raised) sets this so a later ``aclose()`` re-raises instead
        # of returning a false success — mirroring Runtime QUARANTINED.
        self._finalize_failed = False

    @property
    def returncode(self) -> int | None:
        return self._process.returncode

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
        if self._closed or self.stdin is None:
            raise RuntimeError("managed process stdin is closed")
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

        P2-2: this is now a thin wrapper around ``_finalize_once()`` — the
        only difference from ``wait()`` is that ``aclose()`` signals the
        process first (terminate → kill) instead of waiting for a natural
        exit.

        Round-11 review Medium-High-1: if a prior finalize partially failed
        (``_finalize_failed``), re-raise instead of returning a false success.
        """
        if self._closed:
            return
        if self._finalize_failed:
            raise RuntimeError(
                f"managed process {self.execution_id} was already partially "
                f"finalized with errors; resources may not be fully released"
            )
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
        """Run the cleanup sequence exactly once across all terminal paths.

        Round-11 review Medium-High-1: each cleanup step runs independently
        so a failure in one (stderr collector, watchdog, supervisor
        unregister, ``on_terminal`` callback) does NOT skip the later steps
        (temporary HOME removal).  Errors are collected; if any step failed
        the handle is marked ``_finalize_failed`` (not cleanly closed) so a
        later ``aclose()`` re-raises instead of returning a false success —
        mirroring the Runtime close false-success fix (P2-1).
        """
        async with self._finalize_lock:
            if self._finalized:
                return
            self._finalized = True
            errors: list[Exception] = []

            # Each step is isolated — a failure must not prevent later steps.
            for label, step in (
                ("stderr", self._finish_stderr),
                ("watchdog", self._finish_resource_watchdog),
            ):
                try:
                    await step()
                except Exception as exc:  # noqa: BLE001 — collect, don't abort
                    errors.append(exc)
                    logger.debug("managed process finalize step %s failed", label, exc_info=True)

            if self._supervisor is not None:
                try:
                    await self._supervisor.unregister_process(self.execution_id)
                except Exception as exc:  # noqa: BLE001
                    errors.append(exc)
                    logger.debug("managed process finalize supervisor unregister failed", exc_info=True)

            if self._on_terminal is not None:
                try:
                    await self._on_terminal(self.execution_id)
                except Exception as exc:  # noqa: BLE001
                    errors.append(exc)
                    logger.debug("managed process finalize on_terminal failed", exc_info=True)

            # temp-home removal is always attempted (ignore_errors=True so it
            # never raises), regardless of earlier step failures.
            if self._temporary_home is not None:
                shutil.rmtree(self._temporary_home, ignore_errors=True)

            if errors:
                # Partial cleanup — mark failed so aclose() re-raises rather
                # than returning a false success.  ``_closed`` stays False.
                self._finalize_failed = True
                raise RuntimeError(
                    f"managed process {self.execution_id} finalize completed "
                    f"with {len(errors)} error(s): "
                    + "; ".join(type(e).__name__ for e in errors)
                ) from errors[0]
            self._closed = True

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
