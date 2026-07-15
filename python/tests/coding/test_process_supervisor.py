import asyncio
import os
import sys
from pathlib import Path

import pytest

from khaos.coding.execution import (
    ExecutionRequest,
    ExecutionService,
    HostExecutionBackend,
    ResourceBudget,
)
from khaos.coding.execution.supervisor import ProcessSupervisor


@pytest.mark.asyncio
async def test_supervisor_bounds_stdout_and_stderr_fairly(tmp_path: Path):
    supervisor = ProcessSupervisor()
    command = (
        "import os; "
        "os.write(1, b'o' * 20000); "
        "os.write(2, b'e' * 20000)"
    )
    request = ExecutionRequest(
        (sys.executable, "-c", command),
        tmp_path,
        budget=ResourceBudget(output_bytes=1000),
        correlation_id="bounded-output",
    )

    result = await supervisor.run(request)

    assert result.status == "passed"
    assert len(result.stdout.encode()) <= 500
    assert len(result.stderr.encode()) <= 500
    assert result.diagnostics["stdout_truncated"] is True
    assert result.diagnostics["stderr_truncated"] is True
    assert result.diagnostics["stdout_bytes_dropped"] >= 19500
    assert result.diagnostics["stderr_bytes_dropped"] >= 19500
    assert supervisor.active_execution_ids == ()


@pytest.mark.asyncio
async def test_supervisor_terminate_kills_complete_process_group(tmp_path: Path):
    supervisor = ProcessSupervisor(termination_grace_seconds=0.1)
    pid_file = tmp_path / "child.pid"
    command = "\n".join(
        [
            "import subprocess, time",
            "from pathlib import Path",
            "child = subprocess.Popen(['sleep', '30'])",
            f"Path({str(pid_file)!r}).write_text(str(child.pid))",
            "print(child.pid, flush=True)",
            "time.sleep(30)",
        ]
    )
    request = ExecutionRequest(
        (sys.executable, "-c", command),
        tmp_path,
        budget=ResourceBudget(timeout_seconds=35),
        correlation_id="tree-termination",
    )
    running = asyncio.create_task(supervisor.run(request))
    await _wait_until_active(supervisor, "tree-termination")
    for _ in range(100):
        if pid_file.exists():
            break
        await asyncio.sleep(0.01)
    else:
        pytest.fail("child process did not start")

    assert await supervisor.terminate("tree-termination") is True
    result = await asyncio.wait_for(running, timeout=5)

    assert result.status == "cancelled"
    child_pid = int(pid_file.read_text())
    await _wait_until_process_gone(child_pid)
    assert supervisor.active_execution_ids == ()


@pytest.mark.asyncio
async def test_cancelling_run_cleans_process_group_and_registry(tmp_path: Path):
    supervisor = ProcessSupervisor(termination_grace_seconds=0.1)
    request = ExecutionRequest(
        (sys.executable, "-c", "import time; time.sleep(30)"),
        tmp_path,
        budget=ResourceBudget(timeout_seconds=35),
        correlation_id="task-cancel",
    )
    running = asyncio.create_task(supervisor.run(request))
    await _wait_until_active(supervisor, "task-cancel")

    running.cancel()
    with pytest.raises(asyncio.CancelledError):
        await running

    assert supervisor.active_execution_ids == ()
    assert await supervisor.terminate("task-cancel") is False


@pytest.mark.asyncio
async def test_timeout_is_terminal_and_registry_is_cleaned(tmp_path: Path):
    supervisor = ProcessSupervisor(termination_grace_seconds=0.1)
    request = ExecutionRequest(
        (sys.executable, "-c", "import time; time.sleep(30)"),
        tmp_path,
        budget=ResourceBudget(timeout_seconds=0.05),
        correlation_id="timeout",
    )

    result = await supervisor.run(request)

    assert result.status == "timed-out"
    assert result.diagnostics["process_group_terminated"] is True
    assert supervisor.active_execution_ids == ()


@pytest.mark.asyncio
async def test_execution_service_terminate_reaches_foreground_process(
    tmp_path: Path,
):
    service = ExecutionService(HostExecutionBackend())
    request = ExecutionRequest(
        (sys.executable, "-c", "import time; time.sleep(30)"),
        tmp_path,
        budget=ResourceBudget(timeout_seconds=35),
        correlation_id="service-terminate",
    )
    running = asyncio.create_task(service.execute(request))
    await _wait_until_active(service.process_supervisor, "service-terminate")

    await service.terminate("service-terminate")
    result = await asyncio.wait_for(running, timeout=5)

    assert result.status == "cancelled"
    assert service.process_supervisor.active_execution_ids == ()


@pytest.mark.asyncio
async def test_legacy_host_subclass_without_super_init_is_still_supervised(
    tmp_path: Path,
):
    class LegacyHostBackend(HostExecutionBackend):
        def __init__(self) -> None:
            self.calls = 0

        async def execute(self, request: ExecutionRequest):
            self.calls += 1
            return await super().execute(request)

    backend = LegacyHostBackend()
    result = await backend.execute(
        ExecutionRequest(
            (sys.executable, "-c", "print('ok')"),
            tmp_path,
            correlation_id="legacy-subclass",
        )
    )

    assert result.status == "passed"
    assert result.stdout == "ok\n"
    assert backend.calls == 1
    assert backend.supervisor.active_execution_ids == ()


async def _wait_until_active(
    supervisor: ProcessSupervisor, execution_id: str
) -> None:
    for _ in range(100):
        if execution_id in supervisor.active_execution_ids:
            return
        await asyncio.sleep(0.01)
    pytest.fail(f"execution did not become active: {execution_id}")


async def _wait_until_process_gone(pid: int) -> None:
    for _ in range(100):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        await asyncio.sleep(0.01)
    pytest.fail(f"child process survived supervisor termination: {pid}")
