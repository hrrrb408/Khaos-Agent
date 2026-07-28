from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from khaos.permissions.resource import resolve_authorization_resource


class _Manager:
    def __init__(self, workspace) -> None:
        self.workspace = workspace

    def get(self, workspace_id: str):
        if workspace_id == self.workspace.id:
            return self.workspace
        return None


def _workspace(root: Path, *, workspace_id: str = "workspace-a"):
    return SimpleNamespace(
        id=workspace_id,
        task_id="task-a",
        worktree_path=root,
        generation=7,
    )


def test_path_resource_is_anchored_to_active_workspace(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    resource = resolve_authorization_resource(
        "write_file",
        {"path": "src/app.py", "content": "x"},
        principal_id="principal-a",
        project_id="project-a",
        task_id="task-a",
        workspace_id="workspace-a",
        workspace_manager=_Manager(workspace),
    )

    target = json.loads(resource.canonical_target)
    assert target["paths"] == str(tmp_path / "src" / "app.py")
    assert resource.workspace_generation == 7
    assert resource.root_device == tmp_path.stat().st_dev
    assert resource.root_inode == tmp_path.stat().st_ino


def test_workspace_escape_and_cross_workspace_replay_are_rejected(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    manager = _Manager(workspace)
    with pytest.raises(PermissionError, match="escapes"):
        resolve_authorization_resource(
            "read_file",
            {"path": "../secret"},
            principal_id="principal-a",
            project_id="project-a",
            task_id="task-a",
            workspace_id="workspace-a",
            workspace_manager=manager,
        )
    with pytest.raises(PermissionError, match="does not match"):
        resolve_authorization_resource(
            "read_file",
            {"path": "README.md"},
            principal_id="principal-a",
            project_id="project-a",
            task_id="task-b",
            workspace_id="workspace-a",
            workspace_manager=manager,
        )


def test_shell_resource_covers_every_command_segment(tmp_path: Path) -> None:
    resource = resolve_authorization_resource(
        "terminal_shell",
        {"shell": "/bin/bash", "script": "printf ok | tee out; rm -f x", "cwd": "."},
        principal_id="principal-a",
        project_id="project-a",
        task_id="task-a",
        workspace_id="workspace-a",
        workspace_manager=_Manager(_workspace(tmp_path)),
    )

    target = json.loads(resource.canonical_target)
    assert target["segments"] == [["printf", "ok"], ["tee", "out"], ["rm", "-f", "x"]]
