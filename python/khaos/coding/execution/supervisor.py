"""Unified lifecycle supervision for Agent-owned subprocess trees."""

from __future__ import annotations

import asyncio
import os
import signal
import time
from dataclasses import dataclass, field
from pathlib import Path

from khaos.coding.execution.models import ExecutionRequest, ExecutionResult


@dataclass
class _ActiveProcess:
    process: asyncio.subprocess.Process
    termination_requested: bool = False
    termination_lock: asyncio.Lock = field(default_factory=asyncio.Lock)


class ProcessSupervisor:
    """Own process groups, bounded output, cancellation, and teardown."""

    def __init__(self, *, termination_grace_seconds: float = 2.0) -> None:
        if termination_grace_seconds <= 0:
            raise ValueError("termination grace period must be positive")
        self.termination_grace_seconds = termination_grace_seconds
        self._active: dict[str, _ActiveProcess] = {}
        self._registry_lock = asyncio.Lock()

    @property
    def active_execution_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._active))

    async def run(
        self,
        request: ExecutionRequest,
        *,
        cwd: Path | None = None,
        env: dict[str, str] | None = None,
    ) -> ExecutionResult:
        """Run one foreground process with bounded, fairly split output."""
        execution_id = request.correlation_id
        if not execution_id:
            raise ValueError("supervised execution requires a correlation id")
        started = time.monotonic()
        process = await asyncio.create_subprocess_exec(
            *request.argv,
            cwd=str(cwd or request.cwd),
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
        active = _ActiveProcess(process)
        await self._register(execution_id, active)
        total_limit = request.permission_profile.resources.output_bytes
        stdout_limit = (total_limit + 1) // 2
        stderr_limit = total_limit // 2
        stdout_task = asyncio.create_task(
            _drain_bounded(process.stdout, stdout_limit)
        )
        stderr_task = asyncio.create_task(
            _drain_bounded(process.stderr, stderr_limit)
        )
        status = "failed"
        diagnostics: dict[str, object] = {}
        try:
            try:
                await asyncio.wait_for(
                    process.wait(),
                    timeout=request.permission_profile.resources.timeout_seconds,
                )
                status = (
                    "cancelled"
                    if active.termination_requested
                    else "passed" if process.returncode == 0 else "failed"
                )
            except asyncio.TimeoutError:
                active.termination_requested = True
                await self._terminate_active(active)
                status = "timed-out"
                diagnostics.update(
                    {
                        "timeout_seconds": (
                            request.permission_profile.resources.timeout_seconds
                        ),
                        "process_group_terminated": True,
                    }
                )
            except asyncio.CancelledError:
                active.termination_requested = True
                await asyncio.shield(self._terminate_active(active))
                await asyncio.shield(
                    asyncio.gather(stdout_task, stderr_task)
                )
                raise
            stdout, stdout_total = await stdout_task
            stderr, stderr_total = await stderr_task
        finally:
            await self._unregister(execution_id, active)

        diagnostics.update(
            {
                "output_truncated": (
                    stdout_total > len(stdout) or stderr_total > len(stderr)
                ),
                "stdout_truncated": stdout_total > len(stdout),
                "stderr_truncated": stderr_total > len(stderr),
                "stdout_bytes_dropped": max(0, stdout_total - len(stdout)),
                "stderr_bytes_dropped": max(0, stderr_total - len(stderr)),
                "process_group_terminated": bool(
                    diagnostics.get("process_group_terminated")
                    or active.termination_requested
                ),
            }
        )
        return ExecutionResult(
            execution_id=execution_id,
            status=status,
            return_code=process.returncode,
            stdout=stdout.decode("utf-8", errors="replace"),
            stderr=stderr.decode("utf-8", errors="replace"),
            duration_ms=int((time.monotonic() - started) * 1000),
            diagnostics=diagnostics,
        )

    async def register_process(
        self, execution_id: str, process: asyncio.subprocess.Process
    ) -> None:
        """Register a managed stdio process owned by another I/O adapter."""
        await self._register(execution_id, _ActiveProcess(process))

    async def unregister_process(self, execution_id: str) -> None:
        async with self._registry_lock:
            self._active.pop(execution_id, None)

    async def terminate(self, execution_id: str) -> bool:
        """Terminate one complete process group, returning whether it existed."""
        async with self._registry_lock:
            active = self._active.get(execution_id)
        if active is None:
            return False
        active.termination_requested = True
        await self._terminate_active(active)
        return True

    async def shutdown(self) -> None:
        for execution_id in self.active_execution_ids:
            await self.terminate(execution_id)

    async def _register(
        self, execution_id: str, active: _ActiveProcess
    ) -> None:
        async with self._registry_lock:
            if execution_id in self._active:
                await self._terminate_active(active)
                raise RuntimeError(f"execution id is already active: {execution_id}")
            self._active[execution_id] = active

    async def _unregister(
        self, execution_id: str, active: _ActiveProcess
    ) -> None:
        async with self._registry_lock:
            if self._active.get(execution_id) is active:
                self._active.pop(execution_id, None)

    async def _terminate_active(self, active: _ActiveProcess) -> None:
        async with active.termination_lock:
            process = active.process
            if process.returncode is not None:
                return
            _signal_process_group(process, signal.SIGTERM)
            try:
                await asyncio.wait_for(
                    process.wait(), timeout=self.termination_grace_seconds
                )
                return
            except asyncio.TimeoutError:
                _signal_process_group(process, signal.SIGKILL)
                await process.wait()


async def _drain_bounded(
    stream: asyncio.StreamReader | None, limit: int
) -> tuple[bytes, int]:
    if stream is None:
        return b"", 0
    retained = bytearray()
    total = 0
    while True:
        chunk = await stream.read(8192)
        if not chunk:
            break
        total += len(chunk)
        remaining = limit - len(retained)
        if remaining > 0:
            retained.extend(chunk[:remaining])
    return bytes(retained), total


def _signal_process_group(
    process: asyncio.subprocess.Process, sig: signal.Signals
) -> None:
    if process.returncode is not None:
        return
    if os.name == "posix" and process.pid is not None:
        try:
            os.killpg(process.pid, sig)
            return
        except ProcessLookupError:
            return
        except OSError:
            pass
    if sig is signal.SIGKILL:
        process.kill()
    else:
        process.terminate()
