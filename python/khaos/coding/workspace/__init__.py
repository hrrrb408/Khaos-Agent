"""Task-scoped Git Worktree and ChangeSet services."""

from khaos.coding.workspace.artifacts import (
    MAX_CHANGESET_BYTES,
    copy_verified_artifact,
    read_verified_artifact,
    verified_artifact_path,
    write_exclusive_artifact,
)
from khaos.coding.workspace.errors import WorkspaceError
from khaos.coding.workspace.git_process import (
    TrustedGitError,
    TrustedGitProcessOwner,
    TrustedGitProcessState,
)
from khaos.coding.workspace.manager import WorkspaceManager
from khaos.coding.workspace.models import ChangeSet, WorkspaceState, WorkspaceTransition
from khaos.coding.workspace.trusted_git_locator import (
    PlatformTrustedGitLocator,
    StaticTrustedGitLocator,
    TrustedGitLocator,
)
from khaos.coding.workspace.trusted_git_policy import (
    TrustedGitExecutableIdentity,
    TrustedGitExecutablePolicy,
    TrustedGitExecutablePolicyError,
)
from khaos.coding.workspace.trusted_git_preflight import (
    TrustedGitAvailability,
    TrustedGitDiagnosticReport,
    TrustedGitPreflightResult,
    diagnose_trusted_git,
)
from khaos.coding.workspace.trusted_git import TrustedGitRunner

__all__ = [
    "MAX_CHANGESET_BYTES",
    "ChangeSet",
    "TrustedGitError",
    "TrustedGitAvailability",
    "TrustedGitDiagnosticReport",
    "TrustedGitExecutableIdentity",
    "TrustedGitExecutablePolicy",
    "TrustedGitExecutablePolicyError",
    "TrustedGitLocator",
    "TrustedGitProcessOwner",
    "TrustedGitProcessState",
    "TrustedGitPreflightResult",
    "TrustedGitRunner",
    "PlatformTrustedGitLocator",
    "StaticTrustedGitLocator",
    "WorkspaceError",
    "WorkspaceManager",
    "WorkspaceState",
    "WorkspaceTransition",
    "copy_verified_artifact",
    "read_verified_artifact",
    "verified_artifact_path",
    "write_exclusive_artifact",
    "diagnose_trusted_git",
]
