"""Workspace domain models for Coding Tasks."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path

from khaos.coding.workspace.git_identity import GitWorktreeIdentity
from khaos.coding.workspace.storage import (
    WorkspaceStorageLimits,
    WorkspaceStorageSnapshot,
)
from khaos.security.authority import AuthorityEnvelope

MAX_CHANGESET_INLINE_BYTES = 1024 * 1024


class WorkspaceState(str, Enum):
    CREATING = "creating"
    READY = "ready"
    INDEXING = "indexing"
    RUNNING = "running"
    VERIFYING = "verifying"
    REVIEWING = "reviewing"
    AWAITING_APPROVAL = "awaiting-approval"
    APPLYING = "applying"
    APPLIED = "applied"
    FAILED = "failed"
    CANCELLED = "cancelled"
    CLEANING = "cleaning"
    CLEANED = "cleaned"


class WorkspaceTransition(str, Enum):
    UPDATED = "updated"
    NOT_FOUND = "not_found"
    INVALID = "invalid_transition"
    FAILED = "failed"  # Batch 2.6 §4: lease invalidation failure (retryable)


@dataclass
class TaskWorkspace:
    id: str
    task_id: str
    repository_root: Path
    worktree_path: Path
    base_ref: str
    base_sha: str
    branch_name: str
    state: WorkspaceState = WorkspaceState.CREATING
    writable_roots: tuple[Path, ...] = ()
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    recovery_root: Path | None = None
    storage_baseline: WorkspaceStorageSnapshot | None = None
    storage_limits: WorkspaceStorageLimits = field(
        default_factory=WorkspaceStorageLimits
    )
    git_identity: GitWorktreeIdentity | None = None
    generation: int = 1
    # Authority identity is appended to preserve the pre-M5 positional
    # construction contract used by migration and test fixtures.
    principal_id: str = "legacy"
    project_id: str = ""
    creator_runtime_id: str = ""
    authority_generation: int = 1
    root_device: int | None = None
    root_inode: int | None = None
    authority_envelope: AuthorityEnvelope | None = None
    change_artifacts: set[Path] = field(default_factory=set, repr=False)
    change_artifact_bytes: int = field(default=0, repr=False)
    change_artifact_reservations: int = field(default=0, repr=False)
    _authority_sealed: bool = field(default=False, init=False, repr=False)

    _IMMUTABLE_AUTHORITY_FIELDS = frozenset(
        {
            "id",
            "task_id",
            "principal_id",
            "project_id",
            "creator_runtime_id",
            "authority_generation",
            "root_device",
            "root_inode",
            "authority_envelope",
        }
    )

    def __post_init__(self) -> None:
        if self.authority_generation <= 0:
            raise ValueError("workspace authority generation must be positive")
        object.__setattr__(self, "_authority_sealed", True)

    def __setattr__(self, name: str, value: object) -> None:
        if (
            name in self._IMMUTABLE_AUTHORITY_FIELDS
            and getattr(self, "_authority_sealed", False)
        ):
            raise AttributeError(f"TaskWorkspace authority field is immutable: {name}")
        object.__setattr__(self, name, value)


@dataclass(frozen=True)
class ChangeSetArtifact:
    """Authority-owned streamed diff with bounded disclosure metadata."""

    path: Path
    byte_length: int
    sha256: str
    preview: str

    def __post_init__(self) -> None:
        if self.byte_length < 0 or len(self.sha256) != 64:
            raise ValueError("invalid ChangeSet artifact metadata")


@dataclass(frozen=True)
class ChangeSet:
    id: str
    workspace_id: str
    base_sha: str
    head_sha: str | None
    patch: str
    diff_stat: str
    changed_files: tuple[str, ...]
    risk_level: str
    content_hash: str
    created_at: datetime
    artifact: ChangeSetArtifact | None = None

    @classmethod
    def create(
        cls,
        *,
        id: str,
        workspace_id: str,
        base_sha: str,
        head_sha: str | None,
        patch: str,
        diff_stat: str,
        changed_files: tuple[str, ...],
        risk_level: str = "low",
        artifact: ChangeSetArtifact | None = None,
    ) -> ChangeSet:
        patch_bytes = patch.encode("utf-8")
        if len(patch_bytes) > MAX_CHANGESET_INLINE_BYTES:
            raise ValueError("inline ChangeSet patch exceeds the configured bound")
        digest = artifact.sha256 if artifact is not None else hashlib.sha256(patch_bytes).hexdigest()
        return cls(
            id,
            workspace_id,
            base_sha,
            head_sha,
            patch,
            diff_stat,
            changed_files,
            risk_level,
            digest,
            datetime.now(UTC),
            artifact,
        )

    def approval_key(self, operation: str) -> str:
        """Return an approval binding that cannot be reused for another diff."""
        return f"{self.workspace_id}:{self.id}:{self.content_hash}:{operation}"
