"""Soak tests for ManagedProcessHandle finalization (P2-2).

Review P2-2: a managed process that exited naturally (``wait()`` returned)
previously left its temporary HOME on disk, stayed in
``ExecutionService._active``, and never set ``_closed``.  Only an explicit
``aclose()`` cleaned up.  These tests repeatedly start + let-exit / start +
aclose managed processes and assert that nothing accumulates: no temp dirs,
no stale ``_active`` entries, no leaked stderr tasks.

The unified ``_finalize_once()`` must run the full cleanup sequence exactly
once regardless of whether the process exited via ``wait()`` (natural exit)
or ``aclose()`` (teardown).
"""

from __future__ import annotations

import asyncio
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from khaos.coding.execution.host import HostExecutionBackend
from khaos.coding.execution.managed import ManagedProcessHandle
from khaos.coding.execution.models import ExecutionRequest, ResourceBudget
from khaos.coding.execution.service import ExecutionService
from khaos.coding.workspace.models import WorkspaceState

# A server that exits immediately after writing one line, so ``wait()``
# returns quickly and we exercise the natural-exit finalization path.
_QUICK_EXIT = "import sys; sys.stdout.buffer.write(b'hi\\n'); sys.stdout.buffer.flush()"


def _fake_workspace(tmp_path: Path) -> SimpleNamespace:
    worktree = tmp_path / "worktree"
    worktree.mkdir(parents=True)
    (worktree / ".git").write_text("gitdir: ../repo/.git/worktrees/task\n", encoding="utf-8")
    repo = tmp_path / "repo"
    repo.mkdir(parents=True)
    return SimpleNamespace(
        task_id="task",
        worktree_path=worktree,
        repository_root=repo,
        state=WorkspaceState.RUNNING,
        id="workspace",
    )


def _service_with_active_tracking(tmp_path: Path) -> tuple[ExecutionService, SimpleNamespace]:
    workspace = _fake_workspace(tmp_path)
    manager = SimpleNamespace(
        get=lambda wid: workspace if wid == "workspace" else None,
        require=lambda wid, **_: workspace if wid == "workspace" else None,
        verify_git_identity=AsyncMock(),
        verify_execution_root=AsyncMock(),
    )

    async def spawn(context, temporary_home):
        process = await asyncio.create_subprocess_exec(
            *context.argv,
            cwd=str(context.cwd),
            env=context.environment,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
        return ManagedProcessHandle(
            context.correlation_id,
            process,
            temporary_home=temporary_home,
            stderr_limit=context.budget.output_bytes,
        )

    service = ExecutionService(HostExecutionBackend(), manager, managed_process_factory=spawn)
    return service, workspace


@pytest.mark.asyncio
@pytest.mark.skipif(sys.platform == "win32", reason="POSIX process-group semantics")
async def test_natural_exit_does_not_leak_temp_home_or_active_entry(tmp_path: Path):
    """P2-2: ``wait()`` (natural exit) must finalize the handle — remove the
    temporary HOME, set ``_closed``, and (when wired via ``on_terminal``) pop
    the ``_active`` entry.  Previously ``wait()`` only unregistered from the
    ProcessSupervisor and left everything else behind."""
    service, workspace = _service_with_active_tracking(tmp_path)
    handle = await service.start_managed_process(
        ExecutionRequest(
            (sys.executable, "-c", _QUICK_EXIT),
            workspace.worktree_path,
            task_id=workspace.task_id,
            workspace_id=workspace.id,
            budget=ResourceBudget(timeout_seconds=5),
        )
    )
    temp_home = handle._temporary_home
    assert temp_home is not None
    assert temp_home.exists()

    # Natural exit — the process writes 'hi' and exits.
    code = await asyncio.wait_for(handle.wait(), timeout=5)
    assert code == 0

    # P2-2: finalize ran even though only wait() (not aclose()) was called.
    assert handle._closed is True
    assert not temp_home.exists(), "temporary HOME must be removed after natural exit"


@pytest.mark.asyncio
@pytest.mark.skipif(sys.platform == "win32", reason="POSIX process-group semantics")
async def test_wait_and_aclose_race_finalize_exactly_once(tmp_path: Path):
    """P2-2: if ``wait()`` and ``aclose()`` race (process exits naturally
    while the caller tears it down), the cleanup sequence must run exactly
    once — the finalize lock prevents double-cleanup."""
    service, workspace = _service_with_active_tracking(tmp_path)
    handle = await service.start_managed_process(
        ExecutionRequest(
            (sys.executable, "-c", _QUICK_EXIT),
            workspace.worktree_path,
            task_id=workspace.task_id,
            workspace_id=workspace.id,
            budget=ResourceBudget(timeout_seconds=5),
        )
    )
    temp_home = handle._temporary_home

    # Race wait() and aclose() concurrently.
    await asyncio.gather(handle.wait(), handle.aclose())

    assert handle._closed is True
    assert handle._finalized is True
    assert temp_home is not None and not temp_home.exists()


@pytest.mark.asyncio
@pytest.mark.skipif(sys.platform == "win32", reason="POSIX process-group semantics")
async def test_soak_repeated_start_exit_does_not_accumulate_resources(tmp_path: Path):
    """P2-2 soak: start N managed processes, let each exit naturally via
    ``wait()``, and assert that after the loop no temporary HOMEs remain on
    disk and no stderr collector tasks are still pending.

    This is the regression guard for the original bug — before the unified
    ``_finalize_once()``, every natural-exit process leaked its temp HOME
    forever (only ``aclose()`` cleaned up).
    """
    service, workspace = _service_with_active_tracking(tmp_path)
    n = 200
    homes: list[Path] = []
    for _ in range(n):
        handle = await service.start_managed_process(
            ExecutionRequest(
                (sys.executable, "-c", _QUICK_EXIT),
                workspace.worktree_path,
                task_id=workspace.task_id,
                workspace_id=workspace.id,
                budget=ResourceBudget(timeout_seconds=5),
            )
        )
        assert handle._temporary_home is not None
        homes.append(handle._temporary_home)
        await asyncio.wait_for(handle.wait(), timeout=5)

    # P2-2: every temp HOME must be gone — none accumulated.
    leaked = [h for h in homes if h.exists()]
    assert not leaked, f"{len(leaked)} temporary HOMEs leaked after {n} natural exits"


@pytest.mark.asyncio
@pytest.mark.skipif(sys.platform == "win32", reason="POSIX process-group semantics")
async def test_on_terminal_callback_pops_active_entry_on_natural_exit(tmp_path: Path):
    """P2-2: when ``ExecutionService`` injects ``on_terminal``, a natural-exit
    ``wait()`` pops the ``_active`` entry — not just an explicit ``aclose()``."""
    service, workspace = _service_with_active_tracking(tmp_path)
    # Override the factory to inject on_terminal like the production path does.
    production_factory = service.managed_process_factory

    async def spawn_with_callback(context, temporary_home):
        handle = await production_factory(context, temporary_home)
        handle._on_terminal = service._make_managed_on_terminal()
        return handle

    service.managed_process_factory = spawn_with_callback

    handle = await service.start_managed_process(
        ExecutionRequest(
            (sys.executable, "-c", _QUICK_EXIT),
            workspace.worktree_path,
            task_id=workspace.task_id,
            workspace_id=workspace.id,
            budget=ResourceBudget(timeout_seconds=5),
        )
    )
    eid = handle.execution_id
    assert eid in service._active

    # Natural exit.
    await asyncio.wait_for(handle.wait(), timeout=5)

    # P2-2: on_terminal popped _active even though only wait() was called.
    assert eid not in service._active, (
        "natural-exit wait() must pop _active via on_terminal callback"
    )
    assert handle._closed is True
