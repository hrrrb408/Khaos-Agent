import subprocess
from pathlib import Path

import pytest

from khaos.coding.workspace.manager import WorkspaceError, WorkspaceManager
from khaos.coding.workspace.models import WorkspaceState, WorkspaceTransition


def _repo(path: Path) -> Path:
    path.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=path, check=True)
    (path / "README.md").write_text("base\n")
    subprocess.run(["git", "add", "."], cwd=path, check=True)
    subprocess.run(["git", "commit", "-qm", "base"], cwd=path, check=True)
    return path


@pytest.mark.asyncio
async def test_worktree_lifecycle_and_changeset_binding(tmp_path: Path):
    repository = _repo(tmp_path / "repo")
    manager = WorkspaceManager(tmp_path / "worktrees")
    workspace = await manager.create(repository, "task-1")
    assert workspace.state is WorkspaceState.READY
    (workspace.worktree_path / "README.md").write_text("changed\n")
    changeset = await manager.build_changeset(workspace.id)
    assert "README.md" in changeset.changed_files
    assert changeset.approval_key("apply").startswith(f"{workspace.id}:{changeset.id}:")
    assert await manager.transition(workspace.id, WorkspaceState.RUNNING) is WorkspaceTransition.UPDATED
    assert await manager.transition(workspace.id, WorkspaceState.CLEANED) is WorkspaceTransition.INVALID
    assert await manager.transition(workspace.id, WorkspaceState.FAILED) is WorkspaceTransition.UPDATED
    assert await manager.cleanup(workspace.id, force=True) is WorkspaceTransition.UPDATED


@pytest.mark.asyncio
async def test_dirty_main_worktree_is_rejected(tmp_path: Path):
    repository = _repo(tmp_path / "repo")
    (repository / "README.md").write_text("dirty\n")
    with pytest.raises(WorkspaceError, match="未提交修改"):
        await WorkspaceManager(tmp_path / "worktrees").create(repository, "task-1")
