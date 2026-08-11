"""ChangeSet output and apply policies."""

from __future__ import annotations

from enum import Enum

from khaos.coding.workspace.manager import WorkspaceError, WorkspaceManager
from khaos.coding.workspace.models import ChangeSet


class OutputMode(str, Enum):
    PATCH_ONLY = "patch-only"
    COMMIT_IN_WORKTREE = "commit-in-worktree"
    APPLY_TO_CURRENT_BRANCH = "apply-to-current-branch"


async def output_changeset(manager: WorkspaceManager, workspace_id: str, changeset: ChangeSet, mode: OutputMode, *, message: str = "Khaos coding task") -> str:
    if mode is OutputMode.PATCH_ONLY:
        if changeset.artifact is None:
            return changeset.patch
        return await manager.read_changeset_patch(workspace_id, changeset)
    if mode is OutputMode.COMMIT_IN_WORKTREE:
        return await manager.commit_in_worktree(workspace_id, changeset, message)
    workspace = manager._workspaces.get(workspace_id)
    if workspace is None:
        raise WorkspaceError("workspace not found")
    authority = workspace.authority_envelope
    git_kwargs = {"authority": authority} if authority is not None else {}
    clean = await manager._git(
        workspace.repository_root, "status", "--porcelain", **git_kwargs
    )
    head = await manager._git(
        workspace.repository_root, "rev-parse", "HEAD", **git_kwargs
    )
    if clean or head != changeset.base_sha:
        raise WorkspaceError("主工作树不干净或 base SHA 已漂移")
    patch_file = workspace.worktree_path.parent / f"{changeset.id}.apply.patch"
    await manager.export_changeset_artifact(workspace_id, changeset, patch_file)
    try:
        await manager._git(
            workspace.repository_root,
            "apply",
            "--index",
            str(patch_file),
            **git_kwargs,
        )
    finally:
        patch_file.unlink(missing_ok=True)
    return "applied"
