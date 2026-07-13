"""Batch 3.1.1 §1 / Batch 3.1.2 §1: Durable sandbox instance lifecycle records.

A ``VerificationSandboxInstance`` is an immutable persistence record that
tracks a Docker container from PREPARED through TERMINATED.  The record
is written to SQLite *before* the container is created, so a crash at
any point leaves a durable trail that the next Runtime boot can
reconcile.
"""
from __future__ import annotations

import enum
import time
from dataclasses import dataclass, field
from typing import Any


class SandboxInstanceState(str, enum.Enum):
    """Lifecycle states for a durable sandbox instance."""

    PREPARED = "prepared"
    STARTING = "starting"
    RUNNING = "running"
    TERMINATING = "terminating"
    TERMINATED = "terminated"
    CLEANUP_FAILED = "cleanup-failed"
    ORPHANED = "orphaned"
    ORPHANED_CLEANED = "orphaned-cleaned"


@dataclass(frozen=True)
class VerificationSandboxInstance:
    """Immutable record of one Docker container created for verification."""

    sandbox_instance_id: str
    verification_run_id: str
    step_run_id: str
    backend_id: str
    backend_instance_name: str
    runtime_epoch: int
    boot_id: str
    image_reference: str
    expected_image_digest: str
    actual_image_digest: str = ""
    actual_container_image_id: str = ""
    workspace_manifest_digest: str = ""
    container_id: str = ""
    state: SandboxInstanceState = SandboxInstanceState.PREPARED
    created_at: float = field(default_factory=time.time)
    started_at: float | None = None
    terminated_at: float | None = None
    cleanup_status: str = ""
    failure_code: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
