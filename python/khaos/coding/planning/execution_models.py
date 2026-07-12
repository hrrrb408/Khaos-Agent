"""Immutable Batch 3 planned-execution and edit-bundle contracts."""
from __future__ import annotations

import hashlib
import json
import unicodedata
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any


class ExecutionRunStatus(str, Enum):
    CREATED = "created"
    VALIDATING = "validating"
    MUTATING = "mutating"
    MUTATED = "mutated"
    ROLLING_BACK = "rolling-back"
    ROLLED_BACK = "rolled-back"
    FAILED = "failed"
    POISONED = "poisoned"
    CANCELLED = "cancelled"


class PlannedEditOperation(str, Enum):
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    RENAME = "rename"


@dataclass(frozen=True)
class PlanExecutionRun:
    execution_run_id: str
    plan_id: str
    plan_content_hash: str
    approval_request_id: str
    authorization_id: str
    execution_context_id: str
    lease_id: str
    task_id: str
    workspace_id: str
    repository_id: str
    base_sha: str
    repository_generation: int
    binding_digest: str
    edit_bundle_digest: str
    status: ExecutionRunStatus
    started_at: float
    updated_at: float
    completed_at: float | None = None
    failure_code: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class PlannedFileEdit:
    edit_id: str
    plan_step_id: str
    operation: PlannedEditOperation
    path: str
    destination_path: str | None = None
    expected_exists: bool = True
    expected_content_hash: str | None = None
    new_content: str | None = field(default=None, repr=False)
    new_content_hash: str | None = None
    expected_mode: int | None = None
    new_mode: int | None = None
    encoding: str = "utf-8"
    metadata: dict[str, Any] = field(default_factory=dict)

    def canonical(self) -> dict[str, Any]:
        content_hash = (
            hashlib.sha256(self.new_content.encode("utf-8")).hexdigest()
            if self.new_content is not None else None
        )
        return {
            "edit_id": self.edit_id,
            "plan_step_id": self.plan_step_id,
            "operation": self.operation.value,
            "path": unicodedata.normalize("NFC", self.path),
            "destination_path": (
                unicodedata.normalize("NFC", self.destination_path)
                if self.destination_path else None
            ),
            "expected_exists": self.expected_exists,
            "expected_content_hash": self.expected_content_hash,
            "new_content_hash": content_hash,
            "expected_mode": self.expected_mode,
            "new_mode": self.new_mode,
            "encoding": self.encoding,
            "metadata": self.metadata,
        }

    def normalized(self) -> "PlannedFileEdit":
        canonical = self.canonical()
        return replace(
            self,
            path=canonical["path"],
            destination_path=canonical["destination_path"],
            new_content_hash=canonical["new_content_hash"],
        )


@dataclass(frozen=True)
class PlannedEditBundle:
    bundle_id: str
    plan_id: str
    plan_content_hash: str
    task_id: str
    workspace_id: str
    repository_id: str
    binding_digest: str
    ordered_edits: tuple[PlannedFileEdit, ...]
    content_digest: str = ""
    created_at: float = 0.0
    producer: str = "server"
    metadata: dict[str, Any] = field(default_factory=dict)

    def normalized(self) -> "PlannedEditBundle":
        edits = tuple(edit.normalized() for edit in self.ordered_edits)
        payload = {
            "bundle_id": self.bundle_id,
            "plan_id": self.plan_id,
            "plan_content_hash": self.plan_content_hash,
            "task_id": self.task_id,
            "workspace_id": self.workspace_id,
            "repository_id": self.repository_id,
            "binding_digest": self.binding_digest,
            "ordered_edits": [edit.canonical() for edit in edits],
            "producer": self.producer,
            "metadata": self.metadata,
        }
        digest = hashlib.sha256(json.dumps(
            payload, ensure_ascii=False, sort_keys=True,
            separators=(",", ":"), default=str,
        ).encode("utf-8")).hexdigest()
        return replace(self, ordered_edits=edits, content_digest=digest)


@dataclass(frozen=True)
class WorkspaceMutationResult:
    execution_run_id: str
    status: ExecutionRunStatus
    bundle_digest: str
    changed_paths: tuple[str, ...]
    failure_code: str = ""
    idempotent: bool = False
