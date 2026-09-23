import asyncio
import sys
import threading
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
    WorkspaceMutation,
    WorkspaceStorageAuthority,
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
    root_identity = root.stat()
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
        root_device=root_identity.st_dev,
        root_inode=root_identity.st_ino,
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


def test_finalize_failure_rolls_back_published_effect_and_quarantines(tmp_path):
    target = tmp_path / "published.txt"
    baseline = capture_workspace_snapshot(tmp_path)
    rolled_back = False

    def operation():
        nonlocal rolled_back
        target.write_text("published", encoding="utf-8")

        def rollback():
            nonlocal rolled_back
            rolled_back = True
            target.unlink(missing_ok=True)

        def finalize():
            raise OSError("injected finalize failure")

        return WorkspaceMutation("result", rollback, finalize)

    authority = WorkspaceStorageAuthority()
    with pytest.raises(WorkspaceStorageViolation) as caught:
        authority.mutate(
            "workspace",
            tmp_path,
            baseline,
            WorkspaceStorageLimits(),
            operation,
        )

    assert rolled_back is True
    assert not target.exists()
    assert caught.value.rollback_succeeded is True
    assert caught.value.quarantine_required is True
    assert caught.value.diagnostic["kind"] == "workspace-finalize"


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
    # Round-12: the violation kind may be ``workspace-entries`` (the expected
    # over-limit) OR ``workspace-observation`` (the snapshot caught a partial
    # write mid-scan on a slow runner, which is fail-closed).  Both prove the
    # storage authority detected the over-budget write — the exact kind is
    # environment-sensitive.
    violation = result.diagnostics["resource_violation"]
    assert violation["kind"] in ("workspace-entries", "workspace-observation"), (
        f"expected a workspace violation, got: {violation}"
    )


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
    from khaos.coding.workspace import storage

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


def test_transient_incomplete_scan_retries_to_stable_view(tmp_path, monkeypatch):
    from khaos.coding.workspace import storage

    root_identity = (1, 1)
    stable = WorkspaceStorageSnapshot(
        {(1, 2): 4096},
        1,
        True,
        {"payload": (1, 2)},
        root_identity,
    )
    transient = WorkspaceStorageSnapshot(
        {(1, 2): 4096},
        1,
        False,
        {"payload": (1, 2)},
        root_identity,
    )
    scans = iter((transient, stable, stable))
    monkeypatch.setattr(storage, "_capture_once", lambda _root: next(scans))

    snapshot = storage.capture_workspace_snapshot(tmp_path)

    assert snapshot.complete is True
    assert snapshot.allocated_by_inode == stable.allocated_by_inode


@pytest.mark.asyncio
async def test_file_tool_and_process_write_share_authority(tmp_path):
    """File-tool writes and process (terminal) writes share the same
    WorkspaceStorageAuthority.  An over-budget process write must block a
    subsequent file-tool write (and vice-versa).

    Round-11 review: the previous version asserted ``workspace.state is
    WorkspaceState.FAILED`` but called ``ProcessSupervisor.run()`` directly,
    which does NOT quarantine the workspace (quarantine is an
    ``ExecutionService`` responsibility).  The assertion was wrong on every
    platform and timed out on CI.  The test now asserts what the shared
    authority actually guarantees: the process is reported
    ``resource-exhausted`` AND the file-tool write is rejected with
    ``WorkspaceStorageViolation`` — proving the two paths share one
    authority.
    """
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

    # While the over-budget process is running, a file-tool write MUST be
    # rejected — the two paths share the same storage authority.
    with pytest.raises(WorkspaceStorageViolation):
        await write_file("tool.txt", "tool", **_context(manager))
    result = await process

    # The process MUST be reported resource-exhausted.
    assert result.status == "resource-exhausted"


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
