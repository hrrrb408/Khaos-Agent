"""Managed stdio process handles owned by ExecutionService."""

from __future__ import annotations

import asyncio
import os
import signal
import shutil
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
        self._stderr_task = asyncio.create_task(self._collect_stderr())

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
        code = await self._process.wait()
        await self._finish_stderr()
        await self._finish_resource_watchdog()
        if self._supervisor is not None:
            await self._supervisor.unregister_process(self.execution_id)
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
        if self._closed:
            return
        self._closed = True
        try:
            await self.terminate()
            try:
                await asyncio.wait_for(self._process.wait(), timeout=2.0)
            except asyncio.TimeoutError:
                await self.kill()
                await self._process.wait()
        finally:
            await self._finish_stderr()
            await self._finish_resource_watchdog()
            if self._supervisor is not None:
                await self._supervisor.unregister_process(self.execution_id)
            if self._temporary_home is not None:
                shutil.rmtree(self._temporary_home, ignore_errors=True)

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
