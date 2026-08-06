import asyncio
import sys
from pathlib import Path

import pytest

from khaos.coding.execution import ExecutionRequest, ExecutionService, HostExecutionBackend


@pytest.mark.asyncio
async def test_execution_service_is_single_delegation_point(tmp_path: Path):
    service = ExecutionService(HostExecutionBackend())
    result = await service.execute(ExecutionRequest((sys.executable, "-c", "print('ok')"), tmp_path, (tmp_path,)))
    assert result.status == "passed"


# ───── Round-13 P0-1: ExecutionService shutdown false-close tests ─────────


@pytest.mark.asyncio
async def test_shutdown_partial_terminate_failure_does_not_skip_rest():
    """Round-13 P0-1: if one terminate() raises, the supervisor and docker
    backend MUST still be shut down, and the service MUST enter QUARANTINED
    (not CLOSED), so a retry re-raises instead of returning a false success."""
    from khaos.coding.execution.service import (
        ExecutionServiceShutdownError, _ShutdownState,
    )
    from unittest.mock import AsyncMock, MagicMock

    supervisor = MagicMock()
    supervisor.shutdown = AsyncMock()
    docker_backend = MagicMock()
    docker_backend.shutdown = AsyncMock()
    service = ExecutionService(
        HostExecutionBackend(), process_supervisor=supervisor, docker_backend=docker_backend,
    )
    # Inject two fake active executions; the first terminate raises.
    service._active = {
        "exec-A": ("task", "ws", MagicMock()),
        "exec-B": ("task", "ws", MagicMock()),
    }
    call_count = {"n": 0}
    original_terminate = service.terminate

    async def flaky_terminate(eid):
        call_count["n"] += 1
        if eid == "exec-A":
            raise RuntimeError("terminate A boom")
        return await original_terminate(eid)

    service.terminate = flaky_terminate

    with pytest.raises(ExecutionServiceShutdownError):
        await service.shutdown()

    # Both executions were attempted (not just the first).
    assert call_count["n"] == 2
    # Supervisor and Docker were STILL shut down despite exec-A failing.
    supervisor.shutdown.assert_awaited_once()
    docker_backend.shutdown.assert_awaited_once()
    # State is QUARANTINED, not CLOSED.
    assert service._shutdown_state is _ShutdownState.QUARANTINED
    # A second shutdown re-raises the same typed error (no false success).
    with pytest.raises(ExecutionServiceShutdownError):
        await service.shutdown()


@pytest.mark.asyncio
async def test_shutdown_concurrent_callers_observe_same_result():
    """Round-13 P0-1: two concurrent shutdown() callers must both observe
    the SAME result — if shutdown fails, both receive the error."""
    from khaos.coding.execution.service import ExecutionServiceShutdownError
    from unittest.mock import AsyncMock, MagicMock

    supervisor = MagicMock()
    supervisor.shutdown = AsyncMock(side_effect=RuntimeError("supervisor boom"))
    service = ExecutionService(HostExecutionBackend(), process_supervisor=supervisor)

    results: list[str] = []

    async def _shutdown():
        try:
            await service.shutdown()
            results.append("ok")
        except ExecutionServiceShutdownError:
            results.append("error")

    await asyncio.gather(_shutdown(), _shutdown())
    assert results == ["error", "error"], f"callers saw different results: {results}"


@pytest.mark.asyncio
async def test_shutdown_clean_close_transitions_to_closed():
    """Round-13 P0-1: a clean shutdown reaches CLOSED state."""
    from khaos.coding.execution.service import _ShutdownState
    from unittest.mock import AsyncMock, MagicMock

    supervisor = MagicMock()
    supervisor.shutdown = AsyncMock()
    service = ExecutionService(HostExecutionBackend(), process_supervisor=supervisor)

    assert service._shutdown_state is _ShutdownState.OPEN
    await service.shutdown()
    assert service._shutdown_state is _ShutdownState.CLOSED
    assert service._closed is True  # backward-compat property
