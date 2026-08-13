import os
import subprocess
import sys
from pathlib import Path

import pytest

from khaos.coding.execution import (
    ExecutionRequest,
    ExecutionResult,
    ExecutionService,
    HostExecutionBackend,
)
from khaos.coding.execution.binding import open_execution_directory_binding
from khaos.coding.execution.models import ResourceBudget
from khaos.coding.execution.native_launcher import build_process_launch
from khaos.coding.execution.supervisor import ProcessSupervisor
from khaos.coding.workspace.manager import WorkspaceManager


@pytest.mark.asyncio
@pytest.mark.posix_host
async def test_execution_service_rejects_cross_task_workspace(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "x@y"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "x"], cwd=repo, check=True)
    (repo / "a").write_text("a")
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "base"], cwd=repo, check=True)
    manager = WorkspaceManager(tmp_path / "wt")
    workspace = await manager.create(repo, "task-a")
    service = ExecutionService(HostExecutionBackend(), manager)
    request = ExecutionRequest((sys.executable, "-c", "print('ok')"), workspace.worktree_path, access_mode="workspace-write", task_id="task-b", workspace_id=workspace.id)
    with pytest.raises(PermissionError):
        await service.execute(request)


@pytest.mark.asyncio
@pytest.mark.posix_host
async def test_execution_service_rejects_cross_principal_workspace(tmp_path: Path):
    repo = tmp_path / "repo-owner"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "x@y"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "x"], cwd=repo, check=True)
    (repo / "a").write_text("a")
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "base"], cwd=repo, check=True)
    manager = WorkspaceManager(tmp_path / "wt-owner")
    workspace = await manager.create(
        repo, "task-owner", principal_id="alice", project_id="project-a"
    )
    service = ExecutionService(HostExecutionBackend(), manager)
    service.bind_runtime_authority(
        principal_id="mallory", project_id="project-a", runtime_id="runtime-m"
    )
    request = ExecutionRequest(
        (sys.executable, "-c", "print('should-not-run')"),
        workspace.worktree_path,
        access_mode="workspace-write",
        task_id=workspace.task_id,
        workspace_id=workspace.id,
    )

    with pytest.raises(PermissionError, match="owner"):
        await service.execute(request)


def test_execution_service_cannot_be_rebound_to_another_runtime():
    service = ExecutionService(HostExecutionBackend())
    service.bind_runtime_authority(
        principal_id="alice", project_id="project-a", runtime_id="runtime-a"
    )

    with pytest.raises(PermissionError, match="cannot be shared"):
        service.bind_runtime_authority(
            principal_id="alice", project_id="project-a", runtime_id="runtime-b"
        )


def test_native_launcher_is_required_outside_explicit_development(
    tmp_path: Path, monkeypatch
):
    """Host rlimits never silently fall back to a Python pre-exec hook."""
    monkeypatch.delenv("KHAOS_DEV_MODE", raising=False)
    monkeypatch.setattr(
        "khaos.coding.execution.native_launcher._find_launcher", lambda: None
    )
    if os.name != "posix":
        with pytest.raises(PermissionError, match="unsupported on this platform"):
            build_process_launch(
                ("true",),
                cwd=tmp_path,
                directory_binding=None,
                budget=ResourceBudget(),
                enforce_resource_limits=True,
            )
        return
    with pytest.raises(PermissionError, match="native execution launcher"):
        build_process_launch(
            ("true",),
            cwd=tmp_path,
            directory_binding=None,
            budget=ResourceBudget(),
            enforce_resource_limits=True,
        )

    monkeypatch.setenv("KHAOS_DEV_MODE", "1")
    launch = build_process_launch(
        ("true",),
        cwd=tmp_path,
        directory_binding=None,
        budget=ResourceBudget(),
        enforce_resource_limits=True,
    )
    assert launch.argv[2] == "khaos.coding.execution.native_launcher_runtime"
    assert launch.start_new_session is False


@pytest.mark.asyncio
@pytest.mark.posix_host
async def test_supervisor_uses_pinned_directory_fd_for_child_cwd(tmp_path: Path):
    root = tmp_path / "worktree"
    cwd = root / "src"
    cwd.mkdir(parents=True)
    root_info = root.stat()
    cwd_info = cwd.stat()
    request = ExecutionRequest(
        (
            sys.executable,
            "-c",
            "import os; print(os.getcwd())",
        ),
        cwd,
        access_mode="workspace-write",
        workspace_root_identity=(int(root_info.st_dev), int(root_info.st_ino)),
        workspace_cwd_identity=(int(cwd_info.st_dev), int(cwd_info.st_ino)),
    )

    result = await ProcessSupervisor().run(
        request,
        cwd=cwd,
        execution_root=root,
        enforce_resource_limits=False,
    )

    assert result.status == "passed"
    assert result.stdout.strip() == str(cwd)


@pytest.mark.posix_host
def test_directory_binding_rejects_symlinked_cwd_component(tmp_path: Path):
    root = tmp_path / "worktree"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (root / "linked").symlink_to(outside, target_is_directory=True)

    with pytest.raises(PermissionError):
        open_execution_directory_binding(root, root / "linked")


@pytest.mark.asyncio
@pytest.mark.posix_host
async def test_execution_git_pointer_drift_is_quarantined_before_return(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "x@y"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "x"], cwd=repo, check=True)
    (repo / "a").write_text("a")
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "base"], cwd=repo, check=True)
    manager = WorkspaceManager(tmp_path / "wt")
    workspace = await manager.create(repo, "task-drift")

    class TamperBackend:
        async def execute(self, request):
            (request.cwd / ".git").write_text(
                f"gitdir: {repo / '.git'}\n", encoding="utf-8"
            )
            return ExecutionResult("exec", "passed", 0, "", "", 1, {})

    service = ExecutionService(TamperBackend(), manager)
    request = ExecutionRequest(
        (sys.executable, "-c", "pass"),
        workspace.worktree_path,
        access_mode="workspace-write",
        task_id=workspace.task_id,
        workspace_id=workspace.id,
    )

    with pytest.raises(PermissionError, match="Git identity"):
        await service.execute(request)

    assert not workspace.worktree_path.exists()
