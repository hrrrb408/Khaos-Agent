from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from khaos.permissions.resource import (
    resolve_authorization_resource,
    resolve_copy_or_move,
    resolve_process_control,
    resolve_single_workspace_path,
    resolve_terminal_shell,
)
from khaos.coding.workspace.models import TaskWorkspace


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
        principal_id="principal-a",
        project_id="project-a",
        creator_runtime_id="runtime-a",
    )


def test_path_resource_is_anchored_to_active_workspace(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    resource = resolve_authorization_resource(
        "write_file",
        {"path": "src/app.py", "content": "x"},
        principal_id="principal-a",
        project_id="project-a",
        runtime_id="runtime-a",
        task_id="task-a",
        workspace_id="workspace-a",
        workspace_manager=_Manager(workspace),
        resource_resolver=resolve_single_workspace_path,
    )

    target = json.loads(resource.canonical_target)
    assert target["path"] == str(tmp_path / "src" / "app.py")
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
            runtime_id="runtime-a",
            task_id="task-a",
            workspace_id="workspace-a",
            workspace_manager=manager,
            resource_resolver=resolve_single_workspace_path,
        )
    with pytest.raises(PermissionError, match="protected"):
        resolve_authorization_resource(
            "write_file",
            {"path": ".codex/instructions.md", "content": "unsafe"},
            principal_id="principal-a",
            project_id="project-a",
            runtime_id="runtime-a",
            task_id="task-a",
            workspace_id="workspace-a",
            workspace_manager=manager,
            resource_resolver=resolve_single_workspace_path,
        )


def test_workspace_owner_replay_is_rejected(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    manager = _Manager(workspace)
    with pytest.raises(PermissionError, match="owner"):
        resolve_authorization_resource(
            "read_file",
            {"path": "README.md"},
            principal_id="principal-b",
            project_id="project-a",
            runtime_id="runtime-a",
            task_id="task-a",
            workspace_id="workspace-a",
            workspace_manager=manager,
            resource_resolver=resolve_single_workspace_path,
        )

    with pytest.raises(PermissionError, match="runtime owner"):
        resolve_authorization_resource(
            "read_file",
            {"path": "README.md"},
            principal_id="principal-a",
            project_id="project-a",
            runtime_id="runtime-b",
            task_id="task-a",
            workspace_id="workspace-a",
            workspace_manager=manager,
            resource_resolver=resolve_single_workspace_path,
        )
    with pytest.raises(PermissionError, match="does not match"):
        resolve_authorization_resource(
            "read_file",
            {"path": "README.md"},
            principal_id="principal-a",
            project_id="project-a",
            runtime_id="runtime-a",
            task_id="task-b",
            workspace_id="workspace-a",
            workspace_manager=manager,
            resource_resolver=resolve_single_workspace_path,
        )


def test_workspace_authority_identity_is_immutable(tmp_path: Path) -> None:
    workspace = TaskWorkspace(
        id="workspace-a",
        task_id="task-a",
        repository_root=tmp_path,
        worktree_path=tmp_path,
        base_ref="main",
        base_sha="a" * 40,
        branch_name="khaos/task/task-a",
        principal_id="principal-a",
        project_id="project-a",
        creator_runtime_id="runtime-a",
        root_device=tmp_path.stat().st_dev,
        root_inode=tmp_path.stat().st_ino,
    )
    for field, value in (
        ("principal_id", "principal-b"),
        ("project_id", "project-b"),
        ("creator_runtime_id", "runtime-b"),
        ("root_inode", 0),
    ):
        with pytest.raises(AttributeError, match="immutable"):
            setattr(workspace, field, value)


def test_shell_resource_covers_every_command_segment(tmp_path: Path) -> None:
    resource = resolve_authorization_resource(
        "terminal_shell",
        {"shell": "/bin/bash", "script": "printf ok | tee out; rm -f x", "cwd": "."},
        principal_id="principal-a",
        project_id="project-a",
        runtime_id="runtime-a",
        task_id="task-a",
        workspace_id="workspace-a",
        workspace_manager=_Manager(_workspace(tmp_path)),
        resource_resolver=resolve_terminal_shell,
    )

    target = json.loads(resource.canonical_target)
    assert target["tokens"] == ["printf", "ok", "|", "tee", "out", ";", "rm", "-f", "x"]
    assert target["script_digest"]


def test_copy_move_resource_uses_actual_schema_fields(tmp_path: Path) -> None:
    resource = resolve_authorization_resource(
        "copy_file",
        {"src": "input.txt", "dst": "output.txt"},
        principal_id="principal-a",
        project_id="project-a",
        runtime_id="runtime-a",
        task_id="task-a",
        workspace_id="workspace-a",
        workspace_manager=_Manager(_workspace(tmp_path)),
        resource_resolver=resolve_copy_or_move,
    )

    assert json.loads(resource.canonical_target) == {
        "destination": str(tmp_path / "output.txt"),
        "source": str(tmp_path / "input.txt"),
        "tool": "copy_file",
    }


@pytest.mark.parametrize("action", ["poll", "wait", "kill", "log"])
def test_process_control_has_non_shell_resource(tmp_path: Path, action: str) -> None:
    resource = resolve_authorization_resource(
        "process",
        {"action": action, "id": "process-123"},
        principal_id="principal-a",
        project_id="project-a",
        runtime_id="runtime-a",
        task_id="task-a",
        workspace_id="workspace-a",
        workspace_manager=_Manager(_workspace(tmp_path)),
        resource_resolver=resolve_process_control,
    )

    assert json.loads(resource.canonical_target) == {
        "action": action,
        "process_id": "process-123",
        "tool": "process",
    }
