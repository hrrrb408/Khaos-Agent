"""Batch 3.1.1 §1 / Batch 3.1.2 §1: Durable sandbox instance lifecycle records.

A ``VerificationSandboxInstance`` is an immutable persistence record that
tracks a Docker container from PREPARED through TERMINATED.  The record
is written to SQLite *before* the container is created, so a crash at
any point leaves a durable trail that the next Runtime boot can
reconcile.

Batch 3.1.5 §3: the same table now stores both verification instances
and toolchain-attestation instances, distinguished by ``instance_kind``.
Toolchain-attestation instances carry ``toolchain_id``, ``probe_ordinal``,
and ``image_attestation_digest`` so each probe container is attributable
across boots.
"""
from __future__ import annotations

import enum
import time
from dataclasses import dataclass, field
from typing import Any


class SandboxInstanceState(str, enum.Enum):
    """Lifecycle states for a durable sandbox instance.

    Batch 3.1.3 §2: the full state machine is::

        PREPARED → CREATED_ATTESTED → STARTING → RUNNING
                → TERMINATING → REMOVED → TERMINATED

    Exception path::

        any → CLEANUP_PENDING → CLEANUP_FAILED
    """

    PREPARED = "prepared"
    CREATED_ATTESTED = "created-attested"
    STARTING = "starting"
    RUNNING = "running"
    TERMINATING = "terminating"
    REMOVED = "removed"
    TERMINATED = "terminated"
    CLEANUP_PENDING = "cleanup-pending"
    CLEANUP_FAILED = "cleanup-failed"
    ORPHANED = "orphaned"
    ORPHANED_CLEANED = "orphaned-cleaned"


class SandboxInstanceKind(str, enum.Enum):
    """Batch 3.1.5 §3: distinguishes verification containers from
    toolchain-attestation containers in the unified sandbox instance table."""

    VERIFICATION = "verification"
    TOOLCHAIN_ATTESTATION = "toolchain-attestation"


@dataclass(frozen=True)
class VerificationSandboxInstance:
    """Immutable record of one Docker container created for verification
    or toolchain attestation."""

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
    attestation_digest: str = ""
    state: SandboxInstanceState = SandboxInstanceState.PREPARED
    created_at: float = field(default_factory=time.time)
    started_at: float | None = None
    terminated_at: float | None = None
    cleanup_status: str = ""
    failure_code: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    # Batch 3.1.5 §3: toolchain-attestation instance identity.
    # For verification instances these are empty/zero.
    instance_kind: str = "verification"
    toolchain_id: str = ""
    probe_ordinal: int = 0
    image_attestation_digest: str = ""
