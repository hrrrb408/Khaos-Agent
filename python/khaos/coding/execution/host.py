"""Host execution backend with process-group and path safeguards."""

from __future__ import annotations

import asyncio
import os
import signal
import time
import uuid
from pathlib import Path

from khaos.coding.execution.models import ExecutionRequest, ExecutionResult, NetworkPolicy


class ExecutionDenied(PermissionError):
    """Raised when an execution request violates the workspace boundary."""


class HostExecutionBackend:
    name = "host"

    async def probe(self) -> dict[str, object]:
        return {"available": True, "network_enforcement": "best-effort", "network_policy": NetworkPolicy.NONE.value}

    async def execute(self, request: ExecutionRequest) -> ExecutionResult:
        if not request.argv or any(not isinstance(arg, str) for arg in request.argv):
            raise ValueError("argv must contain at least one string")
        cwd = request.cwd.expanduser().resolve()
        if not cwd.is_dir():
            raise ExecutionDenied(f"cwd is not a directory: {cwd}")
        roots = tuple(path.expanduser().resolve() for path in request.writable_roots)
        if roots and not _under(cwd, roots):
            raise ExecutionDenied("cwd is outside writable roots")
        if request.network_policy is not NetworkPolicy.NONE:
            raise ExecutionDenied("host backend only permits network_policy=none")
        env = {
            key: value
            for key, value in os.environ.items()
            if key in request.allowed_environment_keys
        }
        env.update({key: value for key, value in request.environment.items() if key in request.allowed_environment_keys})
        execution_id = uuid.uuid4().hex[:12]
        started = time.monotonic()
        process = await asyncio.create_subprocess_exec(
            *request.argv,
            cwd=str(cwd),
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), request.budget.timeout_seconds)
            status = "passed" if process.returncode == 0 else "failed"
            diagnostics: dict[str, object] = {}
        except asyncio.TimeoutError:
            _terminate_group(process.pid)
            await process.wait()
            stdout, stderr = b"", b""
            status = "timed-out"
            diagnostics = {"timeout_seconds": request.budget.timeout_seconds, "process_group_terminated": True}
        limit = request.budget.output_bytes
        return ExecutionResult(
            execution_id,
            status,
            process.returncode if status != "timed-out" else None,
            stdout[:limit].decode("utf-8", errors="replace"),
            stderr[:limit].decode("utf-8", errors="replace"),
            int((time.monotonic() - started) * 1000),
            diagnostics,
        )

    async def terminate(self, execution_id: str) -> None:
        # Foreground execute owns and terminates its process group. This hook is
        # intentionally a no-op until a persistent execution registry is added.
        return None


def _under(path: Path, roots: tuple[Path, ...]) -> bool:
    return any(path == root or root in path.parents for root in roots)


def _terminate_group(pid: int | None) -> None:
    if pid is None:
        return
    try:
        os.killpg(pid, signal.SIGTERM)
    except ProcessLookupError:
        return
