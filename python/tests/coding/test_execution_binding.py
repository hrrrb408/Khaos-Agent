import sqlite3
import sys
from pathlib import Path

import pytest

from khaos.coding.execution import ExecutionRequest, ExecutionService, HostExecutionBackend
from khaos.coding.workspace.manager import WorkspaceManager


@pytest.mark.asyncio
async def test_execution_service_rejects_cross_task_workspace(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    import subprocess
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
