import sys
from pathlib import Path

import pytest

from khaos.coding.execution import ExecutionRequest, ExecutionService, HostExecutionBackend


@pytest.mark.asyncio
async def test_execution_service_is_single_delegation_point(tmp_path: Path):
    service = ExecutionService(HostExecutionBackend())
    result = await service.execute(ExecutionRequest((sys.executable, "-c", "print('ok')"), tmp_path, (tmp_path,)))
    assert result.status == "passed"
