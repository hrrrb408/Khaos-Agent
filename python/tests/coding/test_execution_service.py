import asyncio
import os
import sys
from pathlib import Path

import pytest

from khaos.coding.execution import ExecutionRequest, ExecutionService, HostExecutionBackend


@pytest.mark.asyncio
async def test_execution_service_is_single_delegation_point(tmp_path: Path):
    service = ExecutionService(HostExecutionBackend())
    if os.name != "posix":
        with pytest.raises(PermissionError, match="unsupported on this platform|POSIX"):
            await service.execute(
                ExecutionRequest((sys.executable, "-c", "print('ok')"), tmp_path, (tmp_path,))
            )
        return
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


@pytest.mark.asyncio
async def test_shutdown_cancelled_terminate_never_reports_closed():
    """A cancelled terminate is retained as a retryable ownership failure."""
    from unittest.mock import AsyncMock, MagicMock

    from khaos.coding.execution.service import (
        ExecutionServiceShutdownError,
        _ShutdownState,
    )

    supervisor = MagicMock()
    supervisor.shutdown = AsyncMock()
    service = ExecutionService(
        HostExecutionBackend(), process_supervisor=supervisor,
    )
    service._active = {"cancelled": ("task", "workspace", MagicMock())}
    service.terminate = AsyncMock(side_effect=asyncio.CancelledError())  # type: ignore[assignment]

    with pytest.raises(ExecutionServiceShutdownError):
        await service.shutdown()

    assert service._shutdown_state is _ShutdownState.QUARANTINED
    assert not service.terminal_closed
    assert service._active
    supervisor.shutdown.assert_awaited_once()


@pytest.mark.asyncio
async def test_shutdown_closes_pending_managed_handle_before_closed():
    """The acquire-to-publish handle registry is part of shutdown ownership."""
    from unittest.mock import AsyncMock, MagicMock

    from khaos.coding.execution import ManagedProcessHandle
    from khaos.coding.execution.service import _ShutdownState

    supervisor = MagicMock()
    supervisor.shutdown = AsyncMock()
    service = ExecutionService(
        HostExecutionBackend(), process_supervisor=supervisor,
    )
    handle = MagicMock(spec=ManagedProcessHandle)
    handle.aclose = AsyncMock()
    handle.terminal_closed = True
    handle.terminal_postcondition.return_value = True
    handle.owned_resources.return_value = ()
    service._pending_managed_handles["pending"] = handle

    await service.shutdown()

    handle.aclose.assert_awaited_once()
    assert service._pending_managed_handles == {}
    assert service._shutdown_state is _ShutdownState.CLOSED
    assert service.terminal_postcondition()


# ───── Round-15 P0-A: deterministic admission race regression tests ──────
#
# These tests use barrier events (NOT sleeps) to deterministically
# reproduce the races described in the round-15 review §三/§四/§六.
# Each test proves that the admission transaction prevents a late-spawned
# process from surviving shutdown.


@pytest.mark.asyncio
async def test_execute_after_shutdown_is_rejected():
    """Round-15 P0-A: execute() must reject after shutdown() completes."""
    from unittest.mock import AsyncMock, MagicMock

    supervisor = MagicMock()
    supervisor.shutdown = AsyncMock()
    service = ExecutionService(HostExecutionBackend(), process_supervisor=supervisor)
    await service.shutdown()

    request = ExecutionRequest(
        (sys.executable, "-c", "print('late')"),
        Path("/tmp"),
    )
    with pytest.raises(RuntimeError, match="not accepting new executions"):
        await service.execute(request)


@pytest.mark.asyncio
async def test_start_managed_process_after_shutdown_is_rejected():
    """Round-15 P0-A: start_managed_process() must reject after shutdown()."""
    from unittest.mock import AsyncMock, MagicMock

    supervisor = MagicMock()
    supervisor.shutdown = AsyncMock()
    service = ExecutionService(HostExecutionBackend(), process_supervisor=supervisor)
    await service.shutdown()

    request = ExecutionRequest(
        (sys.executable, "-c", "print('late')"),
        Path("/tmp"),
        task_id="task",
        workspace_id="ws",
    )
    with pytest.raises(RuntimeError, match="not accepting new executions"):
        await service.start_managed_process(request)


@pytest.mark.asyncio
async def test_shutdown_cancels_in_flight_execute_admission():
    """Round-15 P0-A: shutdown() must cancel an execute() that is paused
    between admission and backend spawn, preventing a late process.

    Uses a barrier event so the test is deterministic (no sleeps).  The
    mock backend signals it has been reached, then waits for a release
    event.  shutdown() is called while execute() is paused at the backend.
    The admission task is cancelled and shutdown completes without
    hanging on a late spawn.
    """
    from unittest.mock import AsyncMock, MagicMock

    supervisor = MagicMock()
    supervisor.shutdown = AsyncMock()
    reached_backend = asyncio.Event()
    release_backend = asyncio.Event()

    async def _hanging_execute(request):
        reached_backend.set()
        await release_backend.wait()
        return MagicMock()

    backend = MagicMock()
    backend.execute = _hanging_execute
    service = ExecutionService(backend, process_supervisor=supervisor)

    request = ExecutionRequest(
        (sys.executable, "-c", "print('race')"),
        Path("/tmp"),
    )
    execute_task = asyncio.create_task(service.execute(request))
    # Deterministic wait: the backend is reached before shutdown is called.
    await asyncio.wait_for(reached_backend.wait(), timeout=5)

    # shutdown() must cancel the in-flight execute task and complete.
    await asyncio.wait_for(service.shutdown(), timeout=5)

    # The execute task must have been cancelled (not left hanging).
    with pytest.raises((asyncio.CancelledError, RuntimeError)):
        await execute_task

    # After shutdown, no initializing tasks remain.
    assert service._initializing == {}


@pytest.mark.asyncio
async def test_supervisor_rejects_register_after_shutdown():
    """Round-15 P0-B: ProcessSupervisor must reject new registrations
    after shutdown() has begun, even if a caller bypasses
    ExecutionService."""
    from unittest.mock import MagicMock

    from khaos.coding.execution.supervisor import (
        ProcessSupervisor,
        SupervisorClosedError,
    )

    supervisor = ProcessSupervisor()
    await supervisor.shutdown()
    assert supervisor.is_closed

    # register_process must reject.
    fake_process = MagicMock()
    with pytest.raises(SupervisorClosedError):
        await supervisor.register_process("late-id", fake_process)


@pytest.mark.asyncio
async def test_supervisor_concurrent_register_during_shutdown_is_rejected():
    """Round-15 P0-B: a registration that races with shutdown is rejected
    at the fence instead of silently being added after the snapshot."""
    from unittest.mock import MagicMock

    from khaos.coding.execution.supervisor import (
        ProcessSupervisor,
        SupervisorClosedError,
    )

    supervisor = ProcessSupervisor()
    # Start shutdown in a task so it runs concurrently with register.
    shutdown_task = asyncio.create_task(supervisor.shutdown())
    # Yield control so shutdown begins.
    await asyncio.sleep(0)
    # Now attempt to register — must be rejected (CLOSING or CLOSED).
    fake_process = MagicMock()
    with pytest.raises(SupervisorClosedError):
        await supervisor.register_process("race-id", fake_process)
    await shutdown_task


# ───── Batch 15.3: Retryable Cleanup Ledger regression tests ──────────
#
# These tests prove that QUARANTINED is retryable: a second shutdown()
# call after a partial failure uses the CleanupLedger to skip completed
# steps and only retry the failed ones.


@pytest.mark.asyncio
async def test_shutdown_retry_skips_completed_steps():
    """Batch 15.3: after a partial shutdown failure, a retry only attempts
    the failed steps — completed terminates, supervisor, and docker are
    skipped via the CleanupLedger."""
    from unittest.mock import MagicMock

    from khaos.coding.execution.service import (
        ExecutionServiceShutdownError, _ShutdownState,
    )

    supervisor = MagicMock()
    supervisor_shutdown_count = {"n": 0}

    async def _supervisor_shutdown():
        supervisor_shutdown_count["n"] += 1

    supervisor.shutdown = _supervisor_shutdown
    docker_backend = MagicMock()
    docker_shutdown_count = {"n": 0}

    async def _docker_shutdown():
        docker_shutdown_count["n"] += 1

    docker_backend.shutdown = _docker_shutdown
    service = ExecutionService(
        HostExecutionBackend(),
        process_supervisor=supervisor,
        docker_backend=docker_backend,
    )

    # Inject one execution that fails to terminate.
    service._active = {"exec-fail": ("task", "ws", MagicMock())}
    terminate_count = {"n": 0}

    async def _failing_terminate(eid):
        terminate_count["n"] += 1
        raise RuntimeError("terminate boom")

    service.terminate = _failing_terminate

    # First shutdown: exec-fail fails, supervisor+docker succeed.
    with pytest.raises(ExecutionServiceShutdownError):
        await service.shutdown()
    assert terminate_count["n"] == 1
    assert supervisor_shutdown_count["n"] == 1
    assert docker_shutdown_count["n"] == 1
    assert service._shutdown_state is _ShutdownState.QUARANTINED

    # Second shutdown (retry): exec-fail is retried, supervisor+docker
    # are SKIPPED (already done in the ledger).
    with pytest.raises(ExecutionServiceShutdownError):
        await service.shutdown()
    assert terminate_count["n"] == 2  # retried
    assert supervisor_shutdown_count["n"] == 1  # NOT retried
    assert docker_shutdown_count["n"] == 1  # NOT retried


@pytest.mark.asyncio
async def test_shutdown_retry_succeeds_when_failed_step_recovers():
    """Batch 15.3: if the previously-failed step succeeds on retry, the
    service transitions from QUARANTINED to CLOSED."""
    from unittest.mock import AsyncMock, MagicMock

    from khaos.coding.execution.service import _ShutdownState

    supervisor = MagicMock()
    supervisor.shutdown = AsyncMock()
    service = ExecutionService(
        HostExecutionBackend(), process_supervisor=supervisor,
    )

    service._active = {"exec-recover": ("task", "ws", MagicMock())}
    call_count = {"n": 0}

    async def _recovering_terminate(eid):
        call_count["n"] += 1
        if call_count["n"] == 1:
            raise RuntimeError("transient failure")
        # Second call succeeds — pop from _active.
        service._active.pop(eid, None)

    service.terminate = _recovering_terminate

    # First shutdown: fails.
    from khaos.coding.execution.service import ExecutionServiceShutdownError
    with pytest.raises(ExecutionServiceShutdownError):
        await service.shutdown()
    assert service._shutdown_state is _ShutdownState.QUARANTINED

    # Second shutdown (retry): succeeds, transitions to CLOSED.
    await service.shutdown()
    assert service._shutdown_state is _ShutdownState.CLOSED
    assert service._closed is True


# ───── Batch 15.7: adversarial lifecycle race variants (review §二十四) ──
#
# The round-15 review §二十四 called out two missing regression variants:
#   - managed spawn paused halfway + shutdown
#   - late publish after CLOSED
# Both use barrier events (NOT sleeps) per review §二十五 so they are
# deterministic under CI load.


@pytest.mark.asyncio
@pytest.mark.posix_host
async def test_shutdown_cancels_in_flight_managed_spawn(tmp_path: Path):
    """Batch 15.7: shutdown() must cancel a ``start_managed_process()``
    that is paused inside ``managed_process_factory`` (between admission
    and process spawn), preventing a late process.

    Uses a barrier event so the test is deterministic.  The factory
    signals it has been reached, then waits for a release event.
    ``shutdown()`` is called while the spawn is paused.  The admission
    task is cancelled and shutdown completes without hanging on a late
    spawn — mirroring ``test_shutdown_cancels_in_flight_execute_admission``
    for the managed-process path.
    """
    import subprocess
    from unittest.mock import AsyncMock, MagicMock

    from khaos.coding.execution import ManagedProcessHandle, ResourceBudget
    from khaos.coding.execution.service import _ShutdownState
    from khaos.coding.workspace.manager import WorkspaceManager

    # Minimal git repo + worktree so start_managed_process's workspace
    # checks pass.
    repo = tmp_path / "repo"
    repo.mkdir()
    for cmd in (
        ["git", "init", "-q"],
        ["git", "config", "user.email", "t@t.com"],
        ["git", "config", "user.name", "T"],
    ):
        subprocess.run(cmd, cwd=repo, check=True)
    (repo / "file.txt").write_text("base\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "base"], cwd=repo, check=True)
    manager = WorkspaceManager(tmp_path / "worktrees")
    workspace = await manager.create(repo, "race-task")

    supervisor = MagicMock()
    supervisor.shutdown = AsyncMock()
    reached_factory = asyncio.Event()
    release_factory = asyncio.Event()

    async def _hanging_factory(resolved_context, temporary_home):
        reached_factory.set()
        await release_factory.wait()
        # Return a mock handle — but this line is never reached because
        # shutdown cancels the task first.
        return MagicMock(spec=ManagedProcessHandle)

    service = ExecutionService(
        HostExecutionBackend(),
        manager,
        process_supervisor=supervisor,
        managed_process_factory=_hanging_factory,
    )

    request = ExecutionRequest(
        (sys.executable, "-c", "print('race')"),
        workspace.worktree_path,
        task_id=workspace.task_id,
        workspace_id=workspace.id,
        budget=ResourceBudget(timeout_seconds=10),
    )
    spawn_task = asyncio.create_task(service.start_managed_process(request))
    # Deterministic wait: the factory is reached before shutdown is called.
    await asyncio.wait_for(reached_factory.wait(), timeout=5)

    # shutdown() must cancel the in-flight spawn task and complete.
    await asyncio.wait_for(service.shutdown(), timeout=5)

    # The spawn task must have been cancelled (not left hanging).
    with pytest.raises((asyncio.CancelledError, RuntimeError)):
        await spawn_task

    # After shutdown, no initializing tasks remain and none were published.
    assert service._initializing == {}
    assert service._active == {}
    assert service._shutdown_state is _ShutdownState.CLOSED


@pytest.mark.asyncio
@pytest.mark.posix_host
async def test_late_publish_after_closing_kills_handle(tmp_path: Path):
    """Batch 15.7: if ``_shutdown_state`` transitions away from OPEN
    between the final re-check and the ``_active`` publish (the
    "late publish" window in ``_start_managed_after_admission``), the
    fully-formed handle must be terminated via ``aclose()`` and MUST NOT
    be published to ``_active``.

    This is the "late publish after CLOSED" variant from review §二十四.
    The factory simulates shutdown racing in by flipping the state to
    CLOSING just before returning the handle — deterministic, no sleeps.
    """
    import subprocess
    from unittest.mock import AsyncMock, MagicMock

    from khaos.coding.execution import ManagedProcessHandle, ResourceBudget
    from khaos.coding.execution.service import _ShutdownState
    from khaos.coding.workspace.manager import WorkspaceManager

    repo = tmp_path / "repo"
    repo.mkdir()
    for cmd in (
        ["git", "init", "-q"],
        ["git", "config", "user.email", "t@t.com"],
        ["git", "config", "user.name", "T"],
    ):
        subprocess.run(cmd, cwd=repo, check=True)
    (repo / "file.txt").write_text("base\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "base"], cwd=repo, check=True)
    manager = WorkspaceManager(tmp_path / "worktrees")
    workspace = await manager.create(repo, "late-publish-task")

    supervisor = MagicMock()
    supervisor.shutdown = AsyncMock()

    # The handle whose aclose() must be called when the late-publish
    # guard fires.  We track the call via AsyncMock.
    mock_handle = MagicMock(spec=ManagedProcessHandle)
    mock_handle.aclose = AsyncMock()

    async def _factory_that_simulates_shutdown_race(resolved_context, temporary_home):
        # Simulate shutdown() racing in between the final OPEN re-check
        # (which already passed) and the _active publish.  Flip the
        # state to CLOSING so the guard at the publish site fires.
        service._shutdown_state = _ShutdownState.CLOSING
        return mock_handle

    service = ExecutionService(
        HostExecutionBackend(),
        manager,
        process_supervisor=supervisor,
        managed_process_factory=_factory_that_simulates_shutdown_race,
    )

    request = ExecutionRequest(
        (sys.executable, "-c", "print('late')"),
        workspace.worktree_path,
        task_id=workspace.task_id,
        workspace_id=workspace.id,
        budget=ResourceBudget(timeout_seconds=10),
    )
    # The late-publish guard must raise RuntimeError, NOT publish the handle.
    with pytest.raises(RuntimeError, match="not accepting new executions"):
        await service.start_managed_process(request)

    # The handle was terminated via aclose() — no orphaned process.
    mock_handle.aclose.assert_awaited_once()
    # The handle was NOT published to _active (no late survival).
    assert service._active == {}
    # _initializing was cleaned up by the finally block in
    # start_managed_process.
    assert service._initializing == {}
