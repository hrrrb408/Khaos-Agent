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
from khaos.coding.workspace.manager import WorkspaceManager


@pytest.mark.asyncio
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
