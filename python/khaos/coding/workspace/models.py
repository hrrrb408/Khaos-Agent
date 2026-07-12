"""Workspace domain models for Coding Tasks."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path


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
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


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

    @classmethod
    def create(cls, *, id: str, workspace_id: str, base_sha: str, head_sha: str | None, patch: str, diff_stat: str, changed_files: tuple[str, ...], risk_level: str = "low") -> "ChangeSet":
        digest = hashlib.sha256(patch.encode("utf-8")).hexdigest()
        return cls(id, workspace_id, base_sha, head_sha, patch, diff_stat, changed_files, risk_level, digest, datetime.now(timezone.utc))

    def approval_key(self, operation: str) -> str:
        """Return an approval binding that cannot be reused for another diff."""
        return f"{self.workspace_id}:{self.id}:{self.content_hash}:{operation}"
