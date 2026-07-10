from pathlib import Path

import pytest

from khaos.tools.sandbox_tools import validate_task_workspace


def test_docker_mount_rejects_repository_and_non_worktree(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    with pytest.raises(PermissionError):
        validate_task_workspace(repo, repo)
    outside = tmp_path / "outside"
    outside.mkdir()
    with pytest.raises(PermissionError):
        validate_task_workspace(outside, repo)
