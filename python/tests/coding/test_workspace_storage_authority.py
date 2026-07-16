import asyncio
import threading
import os
import sys
import time
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
    WorkspaceMutation,
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
async def test_overwrite_overage_stream_restores_from_recovery_file(tmp_path):
    target = tmp_path / "target.txt"
    target.write_text("before", encoding="utf-8")
    manager, workspace = _registered_manager(tmp_path, byte_limit=1)

    with pytest.raises(WorkspaceStorageViolation) as caught:
        await write_file("target.txt", "x" * 8192, **_context(manager))

    assert caught.value.rollback_succeeded is True
    assert target.read_text(encoding="utf-8") == "before"
    recovery = manager.file_recovery_root(workspace.id)
    assert list(recovery.iterdir()) == []


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

    async def verify_git_identity(_workspace_id):
        return None

    manager.verify_git_identity = verify_git_identity

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


@pytest.mark.asyncio
async def test_cancel_waits_for_mutation_transaction_before_releasing_fence(tmp_path):
    manager, _workspace = _registered_manager(tmp_path)
    started = threading.Event()
    release = threading.Event()

    def delayed_operation():
        started.set()
        assert release.wait(2)
        target = tmp_path / "delayed.txt"
        target.write_text("committed", encoding="utf-8")
        return WorkspaceMutation("first", lambda: target.unlink(missing_ok=True))

    first = asyncio.create_task(manager.mutate_with_storage_authority(
        "workspace", "task", delayed_operation
    ))
    assert await asyncio.to_thread(started.wait, 1)
    first.cancel()
    second = asyncio.create_task(manager.mutate_with_storage_authority(
        "workspace", "task", lambda: WorkspaceMutation("second", lambda: None)
    ))
    await asyncio.sleep(0.02)
    assert not first.done()
    assert not second.done()

    release.set()
    with pytest.raises(asyncio.CancelledError):
        await first
    assert await second == "second"
    assert (tmp_path / "delayed.txt").read_text(encoding="utf-8") == "committed"


@pytest.mark.asyncio
async def test_timeout_does_not_return_before_delayed_mutation_is_settled(tmp_path):
    manager, _workspace = _registered_manager(tmp_path)
    release = threading.Event()

    def delayed_operation():
        assert release.wait(2)
        target = tmp_path / "timeout.txt"
        target.write_text("settled", encoding="utf-8")
        return WorkspaceMutation("done", lambda: target.unlink(missing_ok=True))

    asyncio.get_running_loop().call_later(0.1, release.set)
    started_at = time.monotonic()
    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(
            manager.mutate_with_storage_authority(
                "workspace", "task", delayed_operation
            ),
            timeout=0.01,
        )

    assert time.monotonic() - started_at >= 0.08
    assert (tmp_path / "timeout.txt").read_text(encoding="utf-8") == "settled"
