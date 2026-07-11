from pathlib import Path
import sys

import pytest

from khaos.coding.execution.host import ExecutionDenied, HostExecutionBackend
from khaos.coding.execution.models import ExecutionRequest, NetworkPolicy, ResourceBudget


@pytest.mark.asyncio
async def test_host_backend_confines_cwd_and_filters_environment(tmp_path: Path):
    backend = HostExecutionBackend()
    result = await backend.execute(
        ExecutionRequest(
            (sys.executable, "-c", "import os; print(os.getenv('SECRET')); print(os.getenv('PATH') is not None)"),
            tmp_path,
            (tmp_path,),
            {"SECRET": "do-not-leak", "PATH": "/usr/bin"},
            frozenset({"PATH"}),
        )
    )
    assert result.status == "passed"
    assert "do-not-leak" not in result.stdout
    assert "True" in result.stdout


@pytest.mark.asyncio
async def test_host_backend_timeout_and_process_group_cleanup(tmp_path: Path):
    result = await HostExecutionBackend().execute(
        ExecutionRequest((sys.executable, "-c", "import time; time.sleep(5)"), tmp_path, (tmp_path,), budget=ResourceBudget(timeout_seconds=0.05))
    )
    assert result.status == "timed-out"
    assert result.diagnostics["process_group_terminated"] is True


@pytest.mark.asyncio
async def test_host_backend_rejects_outside_cwd_and_network(tmp_path: Path):
    backend = HostExecutionBackend()
    with pytest.raises(ExecutionDenied):
        await backend.execute(ExecutionRequest(("pwd",), tmp_path.parent, (tmp_path,)))
    with pytest.raises(ExecutionDenied):
        await backend.execute(ExecutionRequest(("pwd",), tmp_path, (tmp_path,), network_policy=NetworkPolicy.LOOPBACK_ONLY))
