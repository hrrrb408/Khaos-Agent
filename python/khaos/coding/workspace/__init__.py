"""Task-scoped Git Worktree and ChangeSet services."""

from khaos.coding.workspace.artifacts import (
    MAX_CHANGESET_BYTES,
    copy_verified_artifact,
    read_verified_artifact,
    verified_artifact_path,
    write_exclusive_artifact,
)
from khaos.coding.workspace.errors import WorkspaceError
from khaos.coding.workspace.manager import WorkspaceManager
from khaos.coding.workspace.models import ChangeSet, WorkspaceState, WorkspaceTransition

__all__ = [
    "MAX_CHANGESET_BYTES",
    "ChangeSet",
    "WorkspaceError",
    "WorkspaceManager",
    "WorkspaceState",
    "WorkspaceTransition",
    "copy_verified_artifact",
    "read_verified_artifact",
    "verified_artifact_path",
    "write_exclusive_artifact",
]
