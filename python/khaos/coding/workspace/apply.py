"""ChangeSet output and apply policies."""

from __future__ import annotations

from enum import Enum
from pathlib import Path

from khaos.coding.workspace.manager import WorkspaceError, WorkspaceManager
from khaos.coding.workspace.models import ChangeSet


class OutputMode(str, Enum):
    PATCH_ONLY = "patch-only"
    COMMIT_IN_WORKTREE = "commit-in-worktree"
    APPLY_TO_CURRENT_BRANCH = "apply-to-current-branch"


async def output_changeset(manager: WorkspaceManager, workspace_id: str, changeset: ChangeSet, mode: OutputMode, *, message: str = "Khaos coding task") -> str:
    if mode is OutputMode.PATCH_ONLY:
        return changeset.patch
    if mode is OutputMode.COMMIT_IN_WORKTREE:
        return await manager.commit_in_worktree(workspace_id, changeset, message)
    workspace = manager._workspaces.get(workspace_id)
    if workspace is None:
        raise WorkspaceError("workspace not found")
    clean = await manager._git(workspace.repository_root, "status", "--porcelain")
    head = await manager._git(workspace.repository_root, "rev-parse", "HEAD")
    if clean or head != changeset.base_sha:
        raise WorkspaceError("主工作树不干净或 base SHA 已漂移")
    patch_file = workspace.worktree_path.parent / f"{changeset.id}.apply.patch"
    patch_file.write_text(changeset.patch, encoding="utf-8")
    await manager._git(workspace.repository_root, "apply", "--index", str(patch_file))
    return "applied"
