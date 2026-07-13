"""Immutable contracts for trusted, sandboxed plan verification execution."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any


def _digest(payload: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")).hexdigest()


class VerificationRunStatus(str, Enum):
    CREATED = "created"
    VALIDATING = "validating"
    PREPARING_SANDBOX = "preparing-sandbox"
    RUNNING = "running"
    PASSED = "passed"
    FAILED = "failed"
    ERRORED = "errored"
    TIMED_OUT = "timed-out"
    CANCELLED = "cancelled"
    STALE = "stale"
    POISONED = "poisoned"


class VerificationStepStatus(str, Enum):
    CREATED = "created"
    RUNNING = "running"
    PASSED = "passed"
    FAILED = "failed"
    ERRORED = "errored"
    TIMED_OUT = "timed-out"
    CANCELLED = "cancelled"
    ABORTED = "aborted"


class DisposableWorkspaceState(str, Enum):
    """Batch 3.1.2 §8: lifecycle states for disposable verification workspaces."""
    PREPARED = "prepared"
    SEALED = "sealed"
    MOUNTED = "mounted"
    CLEANUP_PENDING = "cleanup-pending"
    CLEANED = "cleaned"
    CLEANUP_FAILED = "cleanup-failed"
    QUARANTINED = "quarantined"


@dataclass(frozen=True)
class TrustedVerificationCommand:
    command_id: str
    requirement_id: str
    kind: str
    language: str
    executable_id: str
    argv: tuple[str, ...]
    cwd: str
    config_path: str
    config_hash: str
    toolchain_id: str
    toolchain_version: str
    sandbox_profile_id: str
    timeout_ms: int
    output_limit_bytes: int
    expected_exit_codes: tuple[int, ...]
    executes_project_code: bool
    command_digest: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    # Batch 3.1.3 §5: toolchain attestation binding fields.
    # These enter the command canonical digest, verification plan digest,
    # Approval verification binding, Verification Step, and crash recovery
    # validation.  Empty by default for backward compatibility; production
    # paths require them to be non-empty.
    toolchain_attestation_digest: str = ""
    binary_digest: str = ""
    version_output_digest: str = ""
    image_attestation_digest: str = ""

    def canonical(self) -> dict[str, Any]:
        return {
            "command_id": self.command_id,
            "requirement_id": self.requirement_id,
            "kind": self.kind,
            "language": self.language,
            "executable_id": self.executable_id,
            "argv": list(self.argv),
            "cwd": self.cwd,
            "config_path": self.config_path,
            "config_hash": self.config_hash,
            "toolchain_id": self.toolchain_id,
            "toolchain_version": self.toolchain_version,
            "sandbox_profile_id": self.sandbox_profile_id,
            "timeout_ms": self.timeout_ms,
            "output_limit_bytes": self.output_limit_bytes,
            "expected_exit_codes": list(self.expected_exit_codes),
            "executes_project_code": self.executes_project_code,
            "metadata": self.metadata,
            # Batch 3.1.3 §5: attestation binding fields in canonical digest.
            "toolchain_attestation_digest": self.toolchain_attestation_digest,
            "binary_digest": self.binary_digest,
            "version_output_digest": self.version_output_digest,
            "image_attestation_digest": self.image_attestation_digest,
        }

    def normalized(self) -> "TrustedVerificationCommand":
        candidate = replace(self, command_digest="")
        return replace(candidate, command_digest=_digest(candidate.canonical()))


@dataclass(frozen=True)
class VerificationExecutionRun:
    verification_run_id: str
    execution_run_id: str
    plan_id: str
    plan_content_hash: str
    approval_request_id: str
    execution_context_id: str
    task_id: str
    workspace_id: str
    repository_id: str
    bundle_digest: str
    final_mutation_attestation_digest: str
    verification_plan_digest: str
    trusted_catalog_fingerprint: str
    sandbox_profile_digest: str
    status: VerificationRunStatus
    started_at: float
    updated_at: float
    completed_at: float | None = None
    failure_code: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class VerificationStepRun:
    step_run_id: str
    verification_run_id: str
    requirement_id: str
    command_id: str
    command_digest: str
    ordinal: int
    status: VerificationStepStatus
    exit_code: int | None = None
    signal: int | None = None
    started_at: float | None = None
    completed_at: float | None = None
    duration_ms: int = 0
    timeout_ms: int = 0
    stdout_digest: str = ""
    stderr_digest: str = ""
    output_artifact_id: str = ""
    output_truncated: bool = False
    sandbox_instance_id: str = ""
    sandbox_image_digest: str = ""
    resource_usage: dict[str, Any] = field(default_factory=dict)
    failure_code: str = ""


@dataclass(frozen=True)
class VerificationPhaseContext:
    """Opaque, server-issued continuation capability for one execution run."""

    verification_context_id: str
    phase_lease_id: str
    execution_run_id: str
    plan_id: str
    task_id: str
    workspace_id: str
    repository_id: str
    bundle_digest: str
    attestation_digest: str
    binding_digest: str
    owner_execution_id: str
    server_epoch: int
    boot_id: str
    expiry: float


@dataclass(frozen=True)
class VerificationResult:
    verification_run_id: str
    status: VerificationRunStatus
    step_runs: tuple[VerificationStepRun, ...]
    idempotent: bool = False
    failure_code: str = ""


def verification_plan_digest(
    commands: tuple[TrustedVerificationCommand, ...],
    *,
    catalog_fingerprint: str,
    sandbox_profile_digest: str,
) -> str:
    return _digest({
        "commands": [command.normalized().command_digest for command in commands],
        "catalog_fingerprint": catalog_fingerprint,
        "sandbox_profile_digest": sandbox_profile_digest,
    })


@dataclass(frozen=True)
class DisposableWorkspaceRecord:
    """Batch 3.1.2 §8: persistence row for a disposable verification workspace."""
    workspace_id: str
    verification_run_id: str
    step_run_id: str
    instance_id: str
    manifest_digest: str
    manifest_json: str = "[]"
    allowed_generated_output: tuple[str, ...] = ()
    state: DisposableWorkspaceState = DisposableWorkspaceState.PREPARED
    boot_id: str = ""
    created_at: float = 0.0
    sealed_at: float | None = None
    mounted_at: float | None = None
    cleanup_started_at: float | None = None
    cleaned_at: float | None = None
    failure_code: str = ""
