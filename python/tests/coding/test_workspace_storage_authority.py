import asyncio
import os
import sys
from pathlib import Path

import pytest

from khaos.coding.execution import ExecutionRequest, ExecutionService, ResourceBudget
from khaos.coding.execution.supervisor import ProcessSupervisor
from khaos.coding.workspace.manager import WorkspaceError, WorkspaceManager
from khaos.coding.workspace.models import (
    TaskWorkspace,
    WorkspaceState,
    WorkspaceTransition,
)
from khaos.coding.workspace.storage import (
    WorkspaceStorageLimits,
    WorkspaceStorageSnapshot,
    WorkspaceStorageViolation,
    capture_workspace_snapshot,
)
from khaos.tools.file_tools import copy_file, write_file


pytestmark = pytest.mark.skipif(
    sys.platform == "win32",
    reason="TaskWorkspace dirfd storage authority is POSIX-only",
)


def _registered_manager(
    root: Path,
    *,
    byte_limit: int = 512 * 1024 * 1024,
    entry_limit: int = 100_000,
) -> tuple[WorkspaceManager, TaskWorkspace]:
    limits = WorkspaceStorageLimits(byte_limit, entry_limit)
    manager = WorkspaceManager(
        root=root.parent / "managed-worktrees", storage_limits=limits
    )
    workspace = TaskWorkspace(
        id="workspace",
        task_id="task",
        repository_root=root.parent,
        worktree_path=root,
        base_ref="HEAD",
        base_sha="base",
        branch_name="task/storage",
        state=WorkspaceState.READY,
        writable_roots=(root,),
        storage_baseline=capture_workspace_snapshot(root),
        storage_limits=limits,
    )
    manager._workspaces[workspace.id] = workspace
    manager._task_ids.add(workspace.task_id)
    return manager, workspace


def _context(manager: WorkspaceManager) -> dict[str, object]:
    return {
        "workspace_manager": manager,
        "task_id": "task",
        "workspace_id": "workspace",
    }


@pytest.mark.asyncio
async def test_write_file_without_terminal_rolls_back_byte_overage(tmp_path):
    manager, workspace = _registered_manager(tmp_path, byte_limit=1)

    with pytest.raises(WorkspaceStorageViolation) as caught:
        await write_file("payload.bin", "x" * 8192, **_context(manager))

    assert caught.value.rollback_succeeded is True
    assert caught.value.quarantine_required is False
    assert not (tmp_path / "payload.bin").exists()
    assert workspace.state is WorkspaceState.READY


@pytest.mark.asyncio
async def test_repeated_copy_rolls_back_entry_overage(tmp_path):
    (tmp_path / "source.txt").write_text("source", encoding="utf-8")
    manager, workspace = _registered_manager(tmp_path, entry_limit=1)

    assert (await copy_file("source.txt", "one.txt", **_context(manager)))["ok"]
    with pytest.raises(WorkspaceStorageViolation) as caught:
        await copy_file("source.txt", "two.txt", **_context(manager))

    assert caught.value.rollback_succeeded is True
    assert (tmp_path / "one.txt").exists()
    assert not (tmp_path / "two.txt").exists()
    assert workspace.state is WorkspaceState.READY


@pytest.mark.asyncio
async def test_process_writes_and_exits_before_watchdog_tick(tmp_path):
    baseline = capture_workspace_snapshot(tmp_path)
    supervisor = ProcessSupervisor()
    command = (
        "from pathlib import Path; "
        "[(Path('.') / f'fast-{i}').write_bytes(b'x') for i in range(8)]"
    )

    result = await supervisor.run(
        ExecutionRequest(
            (sys.executable, "-c", command),
            tmp_path,
            budget=ResourceBudget(workspace_entries=2),
            access_mode="workspace-write",
            writable_roots=(tmp_path,),
        ),
        workspace_root=tmp_path,
        workspace_baseline=baseline,
    )

    assert result.status == "resource-exhausted"
    assert result.diagnostics["resource_violation"]["kind"] == "workspace-entries"


def test_chmod_zero_directory_makes_snapshot_incomplete(tmp_path):
    hidden = tmp_path / "hidden"
    hidden.mkdir()
    (hidden / "payload").write_bytes(b"x" * 8192)
    hidden.chmod(0)
    try:
        snapshot = capture_workspace_snapshot(tmp_path)
    finally:
        hidden.chmod(0o700)

    assert snapshot.complete is False


def test_rename_identity_churn_is_fail_closed(tmp_path, monkeypatch):
    import khaos.coding.workspace.storage as storage

    root_identity = (1, 1)
    scans = iter(
        WorkspaceStorageSnapshot(
            {(1, index): 4096},
            1,
            True,
            {"payload": (1, index)},
            root_identity,
        )
        for index in (2, 3, 4)
    )
    monkeypatch.setattr(storage, "_capture_once", lambda _root: next(scans))

    snapshot = storage.capture_workspace_snapshot(tmp_path)

    assert snapshot.complete is False


@pytest.mark.asyncio
async def test_file_tool_and_process_write_share_authority(tmp_path):
    manager, workspace = _registered_manager(tmp_path, byte_limit=1)
    supervisor = ProcessSupervisor(storage_authority=manager.storage_authority)
    command = (
        "from pathlib import Path; import time; "
        "Path('terminal.bin').write_bytes(b'x' * 8192); time.sleep(0.2)"
    )
    process = asyncio.create_task(
        supervisor.run(
            ExecutionRequest(
                (sys.executable, "-c", command),
                tmp_path,
                budget=ResourceBudget(workspace_bytes=1),
                access_mode="workspace-write",
                writable_roots=(tmp_path,),
            ),
            workspace_root=tmp_path,
            workspace_baseline=workspace.storage_baseline,
        )
    )
    await asyncio.sleep(0.05)

    with pytest.raises(WorkspaceStorageViolation):
        await write_file("tool.txt", "tool", **_context(manager))
    result = await process

    assert result.status == "resource-exhausted"
    assert workspace.state is WorkspaceState.FAILED


@pytest.mark.asyncio
async def test_cleanup_failure_leaves_workspace_quarantined(tmp_path, monkeypatch):
    manager, workspace = _registered_manager(tmp_path)

    async def fail_git(*_args, **_kwargs):
        raise WorkspaceError("simulated cleanup failure")

    monkeypatch.setattr(manager, "_git", fail_git)

    transition = await manager.quarantine(workspace.id)

    assert transition is WorkspaceTransition.FAILED
    assert workspace.state is WorkspaceState.FAILED


@pytest.mark.asyncio
async def test_cancelled_execution_still_accounts_workspace(tmp_path):
    manager, workspace = _registered_manager(tmp_path, byte_limit=1)

    class CancelledBackend:
        async def execute(self, request):
            (request.cwd / "cancelled.bin").write_bytes(b"x" * 8192)
            raise asyncio.CancelledError

    service = ExecutionService(
        backend=CancelledBackend(), workspace_manager=manager
    )
    request = ExecutionRequest(
        (sys.executable, "-c", "pass"),
        tmp_path,
        task_id=workspace.task_id,
        workspace_id=workspace.id,
        access_mode="workspace-write",
        writable_roots=(tmp_path,),
    )

    with pytest.raises(asyncio.CancelledError):
        await service.execute(request)

    assert workspace.state is WorkspaceState.FAILED
