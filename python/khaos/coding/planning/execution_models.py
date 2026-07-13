"""Immutable Batch 3 planned-execution and edit-bundle contracts."""
from __future__ import annotations

import hashlib
import json
import unicodedata
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any
from khaos.coding.planning.safe_identifiers import (
    SafeRecoveryArtifactName, SafeRecoveryRunId, SafeWorkspaceRelativePath,
)


class ExecutionRunStatus(str, Enum):
    CREATED = "created"
    VALIDATING = "validating"
    MUTATING = "mutating"
    SEALING = "sealing"
    MUTATED = "mutated"
    ROLLING_BACK = "rolling-back"
    ROLLBACK_SEALING = "rollback-sealing"
    ROLLED_BACK = "rolled-back"
    FAILED = "failed"
    POISONED = "poisoned"
    CANCELLED = "cancelled"


class PlannedEditOperation(str, Enum):
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    RENAME = "rename"


class DurableEditPhase(str, Enum):
    """Persisted edit phases accepted by the mutation journal CAS."""

    JOURNALED = "journaled"
    MUTATION_STARTED = "mutation-started"
    FILESYSTEM_APPLIED = "filesystem-applied"
    DIRECTORY_SYNCED = "directory-synced"
    APPLIED = "applied"
    ROLLBACK_STARTED = "rollback-started"
    ROLLBACK_FILESYSTEM_APPLIED = "rollback-filesystem-applied"
    ROLLBACK_DIRECTORY_SYNCED = "rollback-directory-synced"
    ROLLED_BACK = "rolled-back"


class RollbackResumeDisposition(str, Enum):
    STARTED = "started"
    RESUMED = "resumed"
    SEALING = "sealing"
    TERMINAL = "terminal"


@dataclass(frozen=True)
class RollbackResumeState:
    disposition: RollbackResumeDisposition
    run_status: ExecutionRunStatus
    failure_code: str


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


@dataclass(frozen=True)
class AttestedPathState:
    """Canonical final state for one declared relative path."""

    path: str
    exists: bool
    content_hash: str = ""
    mode: int | None = None
    file_type: str = ""
    identity_digest: str = ""
    parent_identity_digest: str = ""

    def canonical(self) -> dict[str, Any]:
        value = {
            "path": unicodedata.normalize("NFC", self.path),
            "exists": self.exists,
            "content_hash": self.content_hash,
            "mode": self.mode,
        }
        # Preserve canonical compatibility for terminal attestations written
        # before Batch 3.0.6; new ownership fields are present only when bound.
        if self.file_type:
            value["file_type"] = self.file_type
        if self.identity_digest:
            value["identity_digest"] = self.identity_digest
        if self.parent_identity_digest:
            value["parent_identity_digest"] = self.parent_identity_digest
        return value


@dataclass(frozen=True)
class FinalMutationAttestation:
    """Immutable proof of declared and repository state before sealing."""

    execution_run_id: str
    bundle_digest: str
    ordered_states: tuple[AttestedPathState, ...]
    path_state_digest: str
    head: str
    generation: int
    index_digest: str
    worktree_admin_digest: str
    workspace_state_digest: str
    execution_context_id: str
    lease_id: str
    binding_digest: str
    attested_at: float
    attestation_digest: str = ""

    def canonical(self) -> dict[str, Any]:
        return {
            "execution_run_id": self.execution_run_id,
            "bundle_digest": self.bundle_digest,
            "ordered_states": [state.canonical() for state in self.ordered_states],
            "path_state_digest": self.path_state_digest,
            "head": self.head,
            "generation": self.generation,
            "index_digest": self.index_digest,
            "worktree_admin_digest": self.worktree_admin_digest,
            "workspace_state_digest": self.workspace_state_digest,
            "execution_context_id": self.execution_context_id,
            "lease_id": self.lease_id,
            "binding_digest": self.binding_digest,
            "attested_at": self.attested_at,
        }

    def normalized(self) -> "FinalMutationAttestation":
        ordered = tuple(sorted(self.ordered_states, key=lambda state: state.path))
        path_payload = [state.canonical() for state in ordered]
        path_digest = hashlib.sha256(json.dumps(
            path_payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")).hexdigest()
        candidate = replace(
            self, ordered_states=ordered, path_state_digest=path_digest,
            attestation_digest="",
        )
        digest = hashlib.sha256(json.dumps(
            candidate.canonical(), ensure_ascii=False, sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")).hexdigest()
        return replace(candidate, attestation_digest=digest)


@dataclass(frozen=True)
class RollbackFinalAttestation(FinalMutationAttestation):
    rollback_reason: str = ""
    journal_digest: str = ""

    def canonical(self) -> dict[str, Any]:
        value = super().canonical()
        value.update({
            "rollback_reason": self.rollback_reason,
            "journal_digest": self.journal_digest,
        })
        return value

    def normalized(self) -> "RollbackFinalAttestation":
        ordered = tuple(sorted(self.ordered_states, key=lambda state: state.path))
        path_digest = hashlib.sha256(json.dumps(
            [state.canonical() for state in ordered], ensure_ascii=False,
            sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")).hexdigest()
        candidate = replace(
            self, ordered_states=ordered, path_state_digest=path_digest,
            attestation_digest="",
        )
        digest = hashlib.sha256(json.dumps(
            candidate.canonical(), ensure_ascii=False, sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")).hexdigest()
        return replace(candidate, attestation_digest=digest)


@dataclass(frozen=True)
class MutationSealTombstone:
    execution_run_id: str
    seal_kind: str
    bundle_digest: str
    attestation_digest: str
    journal_digest: str
    recovery_container_identity: str
    sealed_at: float
    tombstone_digest: str = ""

    def normalized(self) -> "MutationSealTombstone":
        payload = {
            "execution_run_id": self.execution_run_id,
            "seal_kind": self.seal_kind,
            "bundle_digest": self.bundle_digest,
            "attestation_digest": self.attestation_digest,
            "journal_digest": self.journal_digest,
            "recovery_container_identity": self.recovery_container_identity,
            "sealed_at": self.sealed_at,
        }
        digest = hashlib.sha256(json.dumps(
            payload, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")).hexdigest()
        return replace(self, tombstone_digest=digest)


@dataclass(frozen=True)
class InitialPathState:
    path: str
    exists: bool
    content_hash: str = ""
    mode: int | None = None
    file_type: str = "missing"
    identity_digest: str = ""


@dataclass(frozen=True)
class InitialApprovedEdit:
    """Canonical server-approved edit contract bound into the initial proof."""

    edit_id: str
    operation: PlannedEditOperation
    path: str
    destination_path: str | None
    after_hash: str
    after_mode: int | None

    def canonical(self) -> dict[str, Any]:
        return {
            "edit_id": self.edit_id,
            "operation": self.operation.value,
            "path": self.path,
            "destination_path": self.destination_path,
            "after_hash": self.after_hash,
            "after_mode": self.after_mode,
        }


@dataclass(frozen=True)
class InitialWorkspaceAttestation:
    execution_run_id: str
    plan_id: str
    bundle_digest: str
    context_id: str
    lease_id: str
    binding_digest: str
    task_id: str
    workspace_id: str
    repository_id: str
    head: str
    generation: int
    index_digest: str
    worktree_admin_identity: str
    workspace_state_digest: str
    declared_states: tuple[InitialPathState, ...]
    workspace_states: tuple[InitialPathState, ...]
    attested_at: float
    attestation_digest: str = ""
    approved_edits: tuple[InitialApprovedEdit, ...] = ()

    def normalized(self) -> "InitialWorkspaceAttestation":
        states = tuple(sorted(self.declared_states, key=lambda item: item.path))
        workspace_states = tuple(sorted(self.workspace_states, key=lambda item: item.path))
        approved_edits = tuple(sorted(
            self.approved_edits,
            key=lambda item: (item.path, item.destination_path or "", item.edit_id),
        ))
        payload = {
            **self.__dict__,
            "declared_states": [item.__dict__ for item in states],
            "workspace_states": [item.__dict__ for item in workspace_states],
            "approved_edits": [item.canonical() for item in approved_edits],
            "attestation_digest": "",
        }
        digest = hashlib.sha256(json.dumps(
            payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")).hexdigest()
        return replace(
            self, declared_states=states, workspace_states=workspace_states,
            approved_edits=approved_edits, attestation_digest=digest,
        )


@dataclass(frozen=True)
class ValidatedRecoveryEvent:
    ordinal: int
    edit_id: str
    operation: PlannedEditOperation
    path: SafeWorkspaceRelativePath
    destination: SafeWorkspaceRelativePath | None
    before_hash: str
    after_hash: str
    before_mode: int | None
    after_mode: int | None
    artifact: SafeRecoveryArtifactName | None
    durable_phase: str
    phase_version: int
    applied_identity_digest: str = ""
    applied_parent_identity_digest: str = ""
    applied_destination_identity_digest: str = ""
    rollback_identity_digest: str = ""
    identity_version: int = 0
    execution_run_id: str = ""
    rollback_parent_identity_digest: str = ""
    rollback_destination_parent_identity_digest: str = ""
    rollback_sync_mask: int = 0
    rollback_directory_sync_digest: str = ""
    rollback_synced_at: float | None = None

    def __getitem__(self, key: str) -> Any:
        aliases = {
            "path": self.path.value, "destination_path": self.destination.value if self.destination else None,
            "recovery_artifact": self.artifact.value if self.artifact else None,
            "operation": self.operation.value, "status": self.durable_phase,
        }
        return aliases[key] if key in aliases else getattr(self, key)


@dataclass(frozen=True)
class ValidatedRecoveryJournal:
    run_id: SafeRecoveryRunId
    events: tuple[ValidatedRecoveryEvent, ...]
    canonical_digest: str
