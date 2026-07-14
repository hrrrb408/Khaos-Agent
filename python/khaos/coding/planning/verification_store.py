"""SQLite CAS persistence for trusted verification and phase leases."""
from __future__ import annotations

import json
import sqlite3
import time
import uuid
from typing import Any

from khaos.coding.planning.verification_execution_models import (
    DisposableWorkspaceRecord, DisposableWorkspaceState,
    VerificationExecutionRun, VerificationRunStatus, VerificationStepRun,
    VerificationStepStatus,
)
from khaos.coding.planning.verification_sandbox_instance import (
    SandboxInstanceState, VerificationSandboxInstance,
)


_SCHEMA = """
CREATE TABLE IF NOT EXISTS plan_verification_runs (
 verification_run_id TEXT PRIMARY KEY,
 execution_run_id TEXT NOT NULL UNIQUE,
 plan_id TEXT NOT NULL, plan_content_hash TEXT NOT NULL,
 approval_request_id TEXT NOT NULL, execution_context_id TEXT NOT NULL,
 task_id TEXT NOT NULL, workspace_id TEXT NOT NULL, repository_id TEXT NOT NULL,
 bundle_digest TEXT NOT NULL, final_mutation_attestation_digest TEXT NOT NULL,
 verification_plan_digest TEXT NOT NULL, trusted_catalog_fingerprint TEXT NOT NULL,
 sandbox_profile_digest TEXT NOT NULL, status TEXT NOT NULL,
 started_at REAL NOT NULL, updated_at REAL NOT NULL, completed_at REAL,
 failure_code TEXT NOT NULL DEFAULT '', metadata_json TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS plan_verification_steps (
 step_run_id TEXT PRIMARY KEY, verification_run_id TEXT NOT NULL,
 requirement_id TEXT NOT NULL, command_id TEXT NOT NULL, command_digest TEXT NOT NULL,
 ordinal INTEGER NOT NULL, status TEXT NOT NULL, exit_code INTEGER, signal INTEGER,
 started_at REAL, completed_at REAL, duration_ms INTEGER NOT NULL DEFAULT 0,
 timeout_ms INTEGER NOT NULL, stdout_digest TEXT NOT NULL DEFAULT '',
 stderr_digest TEXT NOT NULL DEFAULT '', output_artifact_id TEXT NOT NULL DEFAULT '',
 output_truncated INTEGER NOT NULL DEFAULT 0, sandbox_instance_id TEXT NOT NULL DEFAULT '',
 sandbox_image_digest TEXT NOT NULL DEFAULT '', resource_usage_json TEXT NOT NULL DEFAULT '{}',
 failure_code TEXT NOT NULL DEFAULT '', UNIQUE(verification_run_id, ordinal)
);
CREATE TABLE IF NOT EXISTS plan_verification_audit_events (
 audit_id TEXT PRIMARY KEY, verification_run_id TEXT NOT NULL,
 event_type TEXT NOT NULL, result TEXT NOT NULL, error_code TEXT NOT NULL DEFAULT '',
 correlation_id TEXT NOT NULL, created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS plan_verification_artifacts (
 artifact_id TEXT PRIMARY KEY, verification_run_id TEXT NOT NULL,
 relative_name TEXT NOT NULL, content_digest TEXT NOT NULL, byte_length INTEGER NOT NULL,
 expires_at REAL NOT NULL, quarantined INTEGER NOT NULL DEFAULT 0, created_at REAL NOT NULL,
 status TEXT NOT NULL DEFAULT 'sealed'
);
CREATE TABLE IF NOT EXISTS plan_execution_phase_leases (
 phase_lease_id TEXT PRIMARY KEY, execution_run_id TEXT NOT NULL,
 phase TEXT NOT NULL, owner_execution_id TEXT NOT NULL, task_id TEXT NOT NULL,
 workspace_id TEXT NOT NULL, repository_id TEXT NOT NULL, plan_id TEXT NOT NULL,
 bundle_digest TEXT NOT NULL, attestation_digest TEXT NOT NULL,
 binding_digest TEXT NOT NULL, server_epoch INTEGER NOT NULL, boot_id TEXT NOT NULL,
 expiry REAL NOT NULL, status TEXT NOT NULL, created_at REAL NOT NULL, released_at REAL
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_active_verification_phase_lease
ON plan_execution_phase_leases(execution_run_id) WHERE status='active';
CREATE TABLE IF NOT EXISTS verification_sandbox_instances (
 sandbox_instance_id TEXT PRIMARY KEY,
 verification_run_id TEXT NOT NULL,
 step_run_id TEXT NOT NULL,
 backend_id TEXT NOT NULL,
 backend_instance_name TEXT NOT NULL,
 runtime_epoch INTEGER NOT NULL,
 boot_id TEXT NOT NULL,
 image_reference TEXT NOT NULL,
 expected_image_digest TEXT NOT NULL,
 actual_image_digest TEXT NOT NULL DEFAULT '',
 actual_container_image_id TEXT NOT NULL DEFAULT '',
 workspace_manifest_digest TEXT NOT NULL DEFAULT '',
 container_id TEXT NOT NULL DEFAULT '',
 attestation_digest TEXT NOT NULL DEFAULT '',
 state TEXT NOT NULL DEFAULT 'prepared',
 created_at REAL NOT NULL,
 started_at REAL,
 terminated_at REAL,
 cleanup_status TEXT NOT NULL DEFAULT '',
 failure_code TEXT NOT NULL DEFAULT '',
 metadata_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS ix_vsi_boot_state
ON verification_sandbox_instances(boot_id, state);
CREATE INDEX IF NOT EXISTS ix_vsi_run
ON verification_sandbox_instances(verification_run_id);
CREATE TABLE IF NOT EXISTS toolchain_attestations (
 toolchain_id TEXT PRIMARY KEY,
 executable_path TEXT NOT NULL,
 binary_digest TEXT NOT NULL,
 version_output_digest TEXT NOT NULL,
 parsed_version TEXT NOT NULL,
 actual_image_attestation TEXT NOT NULL,
 attested_at REAL NOT NULL,
 attestation_digest TEXT NOT NULL,
 boot_id TEXT NOT NULL,
 server_epoch INTEGER NOT NULL,
 image_attestation_digest TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS ix_ta_boot
ON toolchain_attestations(boot_id);
CREATE TABLE IF NOT EXISTS disposable_verification_workspaces (
 workspace_id TEXT PRIMARY KEY,
 verification_run_id TEXT NOT NULL,
 step_run_id TEXT NOT NULL DEFAULT '',
 instance_id TEXT NOT NULL,
 manifest_digest TEXT NOT NULL,
 manifest_json TEXT NOT NULL DEFAULT '[]',
 allowed_generated_output TEXT NOT NULL DEFAULT '[]',
 state TEXT NOT NULL DEFAULT 'prepared',
 boot_id TEXT NOT NULL DEFAULT '',
 created_at REAL NOT NULL,
 sealed_at REAL,
 mounted_at REAL,
 cleanup_started_at REAL,
 cleaned_at REAL,
 failure_code TEXT NOT NULL DEFAULT '',
 metadata_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS ix_dvw_boot_state
ON disposable_verification_workspaces(boot_id, state);
CREATE INDEX IF NOT EXISTS ix_dvw_run
ON disposable_verification_workspaces(verification_run_id);
"""


class VerificationExecutionStore:
    def __init__(self, approval_store: Any) -> None:
        self._approval_store = approval_store
        self._conn: sqlite3.Connection = approval_store._conn
        self._conn.executescript(_SCHEMA)
        self._conn.commit()
        # Batch 3.1.3 §5: add image_attestation_digest column to existing
        # databases (CREATE TABLE IF NOT EXISTS won't add columns).
        self._migrate_image_attestation_digest()

    def _migrate_image_attestation_digest(self) -> None:
        """Add image_attestation_digest column if absent (Batch 3.1.3 §5)."""
        cols = {
            row["name"]
            for row in self._conn.execute("PRAGMA table_info(toolchain_attestations)")
        }
        if "image_attestation_digest" not in cols:
            self._conn.execute(
                "ALTER TABLE toolchain_attestations "
                "ADD COLUMN image_attestation_digest TEXT NOT NULL DEFAULT ''"
            )
            self._conn.commit()

    def create_run(self, run: VerificationExecutionRun) -> tuple[VerificationExecutionRun, bool]:
        existing = self.get_run_by_execution(run.execution_run_id)
        if existing is not None:
            if existing.verification_plan_digest != run.verification_plan_digest:
                raise RuntimeError("verification plan digest changed for execution run")
            return existing, True
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            row = self._conn.execute(
                "SELECT status FROM plan_execution_runs WHERE execution_run_id=?",
                (run.execution_run_id,),
            ).fetchone()
            if row is None or row["status"] != "mutated":
                raise RuntimeError("execution run must be MUTATED")
            self._conn.execute(
                "INSERT INTO plan_verification_runs VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (run.verification_run_id, run.execution_run_id, run.plan_id,
                 run.plan_content_hash, run.approval_request_id, run.execution_context_id,
                 run.task_id, run.workspace_id, run.repository_id, run.bundle_digest,
                 run.final_mutation_attestation_digest, run.verification_plan_digest,
                 run.trusted_catalog_fingerprint, run.sandbox_profile_digest,
                 run.status.value, run.started_at, run.updated_at, run.completed_at,
                 run.failure_code, json.dumps(run.metadata, sort_keys=True, separators=(",", ":"))),
            )
            self._audit(run.verification_run_id, "run-created", "created", "", run.execution_run_id)
            self._conn.commit()
            return run, False
        except sqlite3.IntegrityError:
            self._conn.rollback()
            existing = self.get_run_by_execution(run.execution_run_id)
            if existing is None or existing.verification_plan_digest != run.verification_plan_digest:
                raise
            return existing, True
        except Exception:
            self._conn.rollback()
            raise

    def transition_run(
        self, verification_run_id: str, *, expected: tuple[VerificationRunStatus, ...],
        target: VerificationRunStatus, failure_code: str = "",
    ) -> None:
        allowed = {
            VerificationRunStatus.CREATED: {VerificationRunStatus.VALIDATING, VerificationRunStatus.CANCELLED},
            VerificationRunStatus.VALIDATING: {VerificationRunStatus.PREPARING_SANDBOX, VerificationRunStatus.STALE, VerificationRunStatus.ERRORED, VerificationRunStatus.CANCELLED},
            VerificationRunStatus.PREPARING_SANDBOX: {VerificationRunStatus.RUNNING, VerificationRunStatus.ERRORED, VerificationRunStatus.CANCELLED},
            VerificationRunStatus.RUNNING: {VerificationRunStatus.FINALIZING, VerificationRunStatus.PASSED, VerificationRunStatus.FAILED, VerificationRunStatus.ERRORED, VerificationRunStatus.TIMED_OUT, VerificationRunStatus.CANCELLED, VerificationRunStatus.POISONED},
            VerificationRunStatus.FINALIZING: {VerificationRunStatus.PASSED, VerificationRunStatus.ERRORED, VerificationRunStatus.POISONED},
        }
        if not expected or any(target not in allowed.get(item, set()) for item in expected):
            raise RuntimeError("invalid verification run transition")
        terminal = target in {
            VerificationRunStatus.PASSED, VerificationRunStatus.FAILED,
            VerificationRunStatus.ERRORED, VerificationRunStatus.TIMED_OUT,
            VerificationRunStatus.CANCELLED, VerificationRunStatus.STALE,
            VerificationRunStatus.POISONED,
        }
        execution_target = {
            VerificationRunStatus.PASSED: "verified",
            VerificationRunStatus.FAILED: "verification-failed",
            VerificationRunStatus.ERRORED: "verification-error",
            VerificationRunStatus.TIMED_OUT: "verification-error",
            VerificationRunStatus.CANCELLED: "cancelled",
            VerificationRunStatus.POISONED: "poisoned",
        }.get(target)
        placeholders = ",".join("?" for _ in expected)
        now = time.time()
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            cur = self._conn.execute(
                f"UPDATE plan_verification_runs SET status=?,updated_at=?,completed_at=?,failure_code=? "
                f"WHERE verification_run_id=? AND status IN ({placeholders})",
                (target.value, now, now if terminal else None, failure_code,
                 verification_run_id, *(item.value for item in expected)),
            )
            if cur.rowcount != 1:
                raise RuntimeError("verification run CAS failed")
            if target == VerificationRunStatus.RUNNING:
                row = self._conn.execute(
                    "SELECT execution_run_id FROM plan_verification_runs WHERE verification_run_id=?",
                    (verification_run_id,),
                ).fetchone()
                cur = self._conn.execute(
                    "UPDATE plan_execution_runs SET status='verifying',updated_at=? "
                    "WHERE execution_run_id=? AND status='mutated'", (now, row[0]),
                )
                if cur.rowcount != 1:
                    raise RuntimeError("execution run VERIFYING CAS failed")
            elif execution_target:
                row = self._conn.execute(
                    "SELECT execution_run_id FROM plan_verification_runs WHERE verification_run_id=?",
                    (verification_run_id,),
                ).fetchone()
                cur = self._conn.execute(
                    "UPDATE plan_execution_runs SET status=?,updated_at=?,completed_at=?,failure_code=? "
                    "WHERE execution_run_id=? AND status='verifying'",
                    (execution_target, now, now, failure_code, row[0]),
                )
                if cur.rowcount != 1:
                    raise RuntimeError("execution/verification terminal CAS failed")
            self._audit(verification_run_id, "run-transition", target.value, failure_code, verification_run_id)
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    def create_steps(self, steps: tuple[VerificationStepRun, ...]) -> None:
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            for step in steps:
                self._conn.execute(
                    "INSERT INTO plan_verification_steps VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (step.step_run_id, step.verification_run_id, step.requirement_id,
                     step.command_id, step.command_digest, step.ordinal, step.status.value,
                     step.exit_code, step.signal, step.started_at, step.completed_at,
                     step.duration_ms, step.timeout_ms, step.stdout_digest,
                     step.stderr_digest, step.output_artifact_id, int(step.output_truncated),
                     step.sandbox_instance_id, step.sandbox_image_digest,
                     json.dumps(step.resource_usage, sort_keys=True), step.failure_code),
                )
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    def finish_step(self, step: VerificationStepRun) -> None:
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            cur = self._conn.execute(
                "UPDATE plan_verification_steps SET status=?,exit_code=?,signal=?,started_at=?,"
                "completed_at=?,duration_ms=?,stdout_digest=?,stderr_digest=?,output_artifact_id=?,"
                "output_truncated=?,sandbox_instance_id=?,sandbox_image_digest=?,resource_usage_json=?,"
                "failure_code=? WHERE step_run_id=? AND status IN ('created','running')",
                (step.status.value, step.exit_code, step.signal, step.started_at,
                 step.completed_at, step.duration_ms, step.stdout_digest, step.stderr_digest,
                 step.output_artifact_id, int(step.output_truncated), step.sandbox_instance_id,
                 step.sandbox_image_digest, json.dumps(step.resource_usage, sort_keys=True),
                 step.failure_code, step.step_run_id),
            )
            if cur.rowcount != 1:
                raise RuntimeError("verification step CAS failed")
            self._audit(step.verification_run_id, "step-finished", step.status.value,
                        step.failure_code, step.step_run_id)
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    def mark_step_running(self, step_run_id: str) -> None:
        now = time.time()
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            cur = self._conn.execute(
                "UPDATE plan_verification_steps SET status='running',started_at=? "
                "WHERE step_run_id=? AND status='created'", (now, step_run_id),
            )
            if cur.rowcount != 1:
                raise RuntimeError("verification step start CAS failed")
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    def recover_interrupted(self) -> int:
        """Never infer PREPARING/RUNNING/FINALIZING work as passed after restart."""
        now = time.time()
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            rows = self._conn.execute(
                "SELECT verification_run_id,execution_run_id FROM plan_verification_runs "
                "WHERE status IN ('preparing-sandbox','running','finalizing')"
            ).fetchall()
            for row in rows:
                self._conn.execute(
                    "UPDATE plan_verification_steps SET status='aborted',completed_at=?,"
                    "failure_code='runtime-restart' WHERE verification_run_id=? AND status='running'",
                    (now, row[0]),
                )
                self._conn.execute(
                    "UPDATE plan_verification_runs SET status='errored',updated_at=?,completed_at=?,"
                    "failure_code='runtime-restart' WHERE verification_run_id=?",
                    (now, now, row[0]),
                )
                self._conn.execute(
                    "UPDATE plan_execution_runs SET status='verification-error',updated_at=?,"
                    "completed_at=?,failure_code='runtime-restart' WHERE execution_run_id=? "
                    "AND status='verifying'", (now, now, row[1]),
                )
                self._audit(row[0], "crash-recovered", "errored", "runtime-restart", row[0])
            self._conn.commit()
            return len(rows)
        except Exception:
            self._conn.rollback()
            raise

    def save_artifact_record(
        self, *, artifact_id: str, verification_run_id: str,
        relative_name: str, content_digest: str, byte_length: int,
        expires_at: float,
    ) -> None:
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            self._conn.execute(
                "INSERT INTO plan_verification_artifacts VALUES (?,?,?,?,?,?,?,?)",
                (artifact_id, verification_run_id, relative_name, content_digest,
                 byte_length, expires_at, 0, time.time()),
            )
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    def get_run_by_execution(self, execution_run_id: str) -> VerificationExecutionRun | None:
        row = self._conn.execute(
            "SELECT * FROM plan_verification_runs WHERE execution_run_id=?", (execution_run_id,),
        ).fetchone()
        return self._row_to_run(row) if row else None

    def get_run(self, verification_run_id: str) -> VerificationExecutionRun | None:
        """Batch 3.1.2 §2: look up a verification run by verification_run_id."""
        row = self._conn.execute(
            "SELECT * FROM plan_verification_runs WHERE verification_run_id=?",
            (verification_run_id,),
        ).fetchone()
        return self._row_to_run(row) if row else None

    def list_steps(self, verification_run_id: str) -> tuple[VerificationStepRun, ...]:
        rows = self._conn.execute(
            "SELECT * FROM plan_verification_steps WHERE verification_run_id=? ORDER BY ordinal",
            (verification_run_id,),
        ).fetchall()
        return tuple(self._row_to_step(row) for row in rows)

    def acquire_phase_lease(self, **fields: Any) -> str:
        lease_id = f"vlease_{uuid.uuid4().hex}"
        now = time.time()
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            row = self._conn.execute(
                "SELECT status FROM plan_execution_runs WHERE execution_run_id=?",
                (fields["execution_run_id"],),
            ).fetchone()
            if row is None or row[0] not in (
                "mutated", "verified", "verification-failed", "verification-error",
            ):
                raise RuntimeError("verification lease requires MUTATED execution run")
            self._conn.execute(
                "INSERT INTO plan_execution_phase_leases VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (lease_id, fields["execution_run_id"], "verification",
                 fields["owner_execution_id"], fields["task_id"], fields["workspace_id"],
                 fields["repository_id"], fields["plan_id"], fields["bundle_digest"],
                 fields["attestation_digest"], fields["binding_digest"],
                 fields["server_epoch"], fields["boot_id"], fields["expiry"],
                 "active", now, None),
            )
            self._conn.commit()
            return lease_id
        except Exception:
            self._conn.rollback()
            raise

    def require_phase_lease(self, lease_id: str, *, now: float | None = None) -> sqlite3.Row:
        row = self._conn.execute(
            "SELECT * FROM plan_execution_phase_leases WHERE phase_lease_id=?", (lease_id,),
        ).fetchone()
        if row is None or row["status"] != "active" or float(row["expiry"]) <= (now or time.time()):
            raise PermissionError("verification phase lease is inactive")
        return row

    def release_phase_lease(self, lease_id: str) -> None:
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            cur = self._conn.execute(
                "UPDATE plan_execution_phase_leases SET status='released',released_at=? "
                "WHERE phase_lease_id=? AND status='active'", (time.time(), lease_id),
            )
            if cur.rowcount != 1:
                raise RuntimeError("verification phase lease release failed")
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    def invalidate_phase_leases(self, *, boot_id: str) -> int:
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            cur = self._conn.execute(
                "UPDATE plan_execution_phase_leases SET status='revoked',released_at=? "
                "WHERE boot_id=? AND status='active'", (time.time(), boot_id),
            )
            self._conn.commit()
            return int(cur.rowcount or 0)
        except Exception:
            self._conn.rollback()
            raise

    def _audit(self, run_id: str, event: str, result: str, error: str, correlation: str) -> None:
        self._conn.execute(
            "INSERT INTO plan_verification_audit_events VALUES (?,?,?,?,?,?,?)",
            (f"pva_{uuid.uuid4().hex}", run_id, event, result, error, correlation, time.time()),
        )

    @staticmethod
    def _row_to_run(row: sqlite3.Row) -> VerificationExecutionRun:
        return VerificationExecutionRun(
            verification_run_id=row["verification_run_id"], execution_run_id=row["execution_run_id"],
            plan_id=row["plan_id"], plan_content_hash=row["plan_content_hash"],
            approval_request_id=row["approval_request_id"], execution_context_id=row["execution_context_id"],
            task_id=row["task_id"], workspace_id=row["workspace_id"], repository_id=row["repository_id"],
            bundle_digest=row["bundle_digest"],
            final_mutation_attestation_digest=row["final_mutation_attestation_digest"],
            verification_plan_digest=row["verification_plan_digest"],
            trusted_catalog_fingerprint=row["trusted_catalog_fingerprint"],
            sandbox_profile_digest=row["sandbox_profile_digest"],
            status=VerificationRunStatus(row["status"]), started_at=float(row["started_at"]),
            updated_at=float(row["updated_at"]), completed_at=row["completed_at"],
            failure_code=row["failure_code"], metadata=json.loads(row["metadata_json"]),
        )

    @staticmethod
    def _row_to_step(row: sqlite3.Row) -> VerificationStepRun:
        return VerificationStepRun(
            step_run_id=row["step_run_id"], verification_run_id=row["verification_run_id"],
            requirement_id=row["requirement_id"], command_id=row["command_id"],
            command_digest=row["command_digest"], ordinal=int(row["ordinal"]),
            status=VerificationStepStatus(row["status"]), exit_code=row["exit_code"],
            signal=row["signal"], started_at=row["started_at"], completed_at=row["completed_at"],
            duration_ms=int(row["duration_ms"]), timeout_ms=int(row["timeout_ms"]),
            stdout_digest=row["stdout_digest"], stderr_digest=row["stderr_digest"],
            output_artifact_id=row["output_artifact_id"],
            output_truncated=bool(row["output_truncated"]),
            sandbox_instance_id=row["sandbox_instance_id"],
            sandbox_image_digest=row["sandbox_image_digest"],
            resource_usage=json.loads(row["resource_usage_json"]), failure_code=row["failure_code"],
        )

    # ------------------------------------------------------------------
    # Batch 3.1.1 §1: VerificationSandboxInstance lifecycle
    # ------------------------------------------------------------------

    def create_sandbox_instance(self, instance: VerificationSandboxInstance) -> None:
        """Persist a PREPARED/STARTING instance BEFORE creating the container."""
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            self._conn.execute(
                "INSERT INTO verification_sandbox_instances VALUES "
                "(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (instance.sandbox_instance_id, instance.verification_run_id,
                 instance.step_run_id, instance.backend_id,
                 instance.backend_instance_name, instance.runtime_epoch,
                 instance.boot_id, instance.image_reference,
                 instance.expected_image_digest, instance.actual_image_digest,
                 instance.actual_container_image_id,
                 instance.workspace_manifest_digest, instance.container_id,
                 instance.attestation_digest,
                 instance.state.value, instance.created_at, instance.started_at,
                 instance.terminated_at, instance.cleanup_status,
                 instance.failure_code,
                 json.dumps(instance.metadata, sort_keys=True, separators=(",", ":"))),
            )
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    def persist_created_instance(
        self, sandbox_instance_id: str, *,
        container_id: str, attestation_digest: str,
        actual_image_digest: str, actual_container_image_id: str,
    ) -> None:
        """Batch 3.1.3 §1: atomically persist container identity + CREATED_ATTESTED.

        This is the critical durability point — container_id and attestation
        are persisted in a single BEGIN IMMEDIATE BEFORE docker start is
        called, so a crash after create but before start leaves a durable
        trail.
        """
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            cur = self._conn.execute(
                "UPDATE verification_sandbox_instances SET container_id=?, "
                "attestation_digest=?, actual_image_digest=?, "
                "actual_container_image_id=?, state='created-attested' "
                "WHERE sandbox_instance_id=? AND state='prepared'",
                (container_id, attestation_digest, actual_image_digest,
                 actual_container_image_id, sandbox_instance_id),
            )
            if cur.rowcount != 1:
                raise RuntimeError("persist_created_instance CAS failed")
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    def update_sandbox_instance(
        self, sandbox_instance_id: str, *,
        state: SandboxInstanceState | None = None,
        container_id: str | None = None,
        actual_image_digest: str | None = None,
        actual_container_image_id: str | None = None,
        attestation_digest: str | None = None,
        started_at: float | None = None,
        terminated_at: float | None = None,
        cleanup_status: str | None = None,
        failure_code: str | None = None,
    ) -> None:
        """Update mutable fields of a sandbox instance (state + metadata)."""
        sets: list[str] = []
        params: list[Any] = []
        if state is not None:
            sets.append("state=?")
            params.append(state.value)
        if container_id is not None:
            sets.append("container_id=?")
            params.append(container_id)
        if actual_image_digest is not None:
            sets.append("actual_image_digest=?")
            params.append(actual_image_digest)
        if actual_container_image_id is not None:
            sets.append("actual_container_image_id=?")
            params.append(actual_container_image_id)
        if attestation_digest is not None:
            sets.append("attestation_digest=?")
            params.append(attestation_digest)
        if started_at is not None:
            sets.append("started_at=?")
            params.append(started_at)
        if terminated_at is not None:
            sets.append("terminated_at=?")
            params.append(terminated_at)
        if cleanup_status is not None:
            sets.append("cleanup_status=?")
            params.append(cleanup_status)
        if failure_code is not None:
            sets.append("failure_code=?")
            params.append(failure_code)
        if not sets:
            return
        params.append(sandbox_instance_id)
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            cur = self._conn.execute(
                f"UPDATE verification_sandbox_instances SET {','.join(sets)} "
                f"WHERE sandbox_instance_id=?",
                params,
            )
            if cur.rowcount != 1:
                raise RuntimeError("sandbox instance update failed (not found)")
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    def get_sandbox_instance(self, sandbox_instance_id: str) -> VerificationSandboxInstance | None:
        row = self._conn.execute(
            "SELECT * FROM verification_sandbox_instances WHERE sandbox_instance_id=?",
            (sandbox_instance_id,),
        ).fetchone()
        return self._row_to_instance(row) if row else None

    def list_active_sandbox_instances(self) -> tuple[VerificationSandboxInstance, ...]:
        """Return all non-terminal instances (need crash reconciliation)."""
        rows = self._conn.execute(
            "SELECT * FROM verification_sandbox_instances "
            "WHERE state IN ('prepared','created-attested','starting','running',"
            "'terminating','cleanup-pending') "
            "ORDER BY created_at",
        ).fetchall()
        return tuple(self._row_to_instance(row) for row in rows)

    def list_sandbox_instances_for_boot(self, boot_id: str) -> tuple[VerificationSandboxInstance, ...]:
        rows = self._conn.execute(
            "SELECT * FROM verification_sandbox_instances WHERE boot_id=? ORDER BY created_at",
            (boot_id,),
        ).fetchall()
        return tuple(self._row_to_instance(row) for row in rows)

    def list_sandbox_instances_for_run(self, verification_run_id: str) -> tuple[VerificationSandboxInstance, ...]:
        rows = self._conn.execute(
            "SELECT * FROM verification_sandbox_instances WHERE verification_run_id=? ORDER BY created_at",
            (verification_run_id,),
        ).fetchall()
        return tuple(self._row_to_instance(row) for row in rows)

    def mark_sandbox_instance_orphaned(self, sandbox_instance_id: str, *, failure_code: str = "") -> None:
        self.update_sandbox_instance(
            sandbox_instance_id,
            state=SandboxInstanceState.ORPHANED,
            failure_code=failure_code,
        )

    def mark_sandbox_instance_cleanup_failed(self, sandbox_instance_id: str, *, failure_code: str = "") -> None:
        self.update_sandbox_instance(
            sandbox_instance_id,
            state=SandboxInstanceState.CLEANUP_FAILED,
            cleanup_status="failed",
            failure_code=failure_code,
        )

    def reconcile_sandbox_instances(self) -> int:
        """Batch 3.1.1 §2: mark all active sandbox instances as ORPHANED.

        Called during ``configure_trusted_verification`` after
        ``recover_interrupted`` has transitioned runs to ERRORED.  Any
        sandbox instance still in PREPARED/STARTING/RUNNING/TERMINATING
        state is marked ORPHANED — the corresponding Docker container
        (if any) is terminated separately via ``backend.reconcile_instances``.
        """
        active = self.list_active_sandbox_instances()
        for instance in active:
            self.mark_sandbox_instance_orphaned(
                instance.sandbox_instance_id,
                failure_code="runtime-restart-orphaned",
            )
        return len(active)

    @staticmethod
    def _row_to_instance(row: sqlite3.Row) -> VerificationSandboxInstance:
        return VerificationSandboxInstance(
            sandbox_instance_id=row["sandbox_instance_id"],
            verification_run_id=row["verification_run_id"],
            step_run_id=row["step_run_id"],
            backend_id=row["backend_id"],
            backend_instance_name=row["backend_instance_name"],
            runtime_epoch=int(row["runtime_epoch"]),
            boot_id=row["boot_id"],
            image_reference=row["image_reference"],
            expected_image_digest=row["expected_image_digest"],
            actual_image_digest=row["actual_image_digest"],
            actual_container_image_id=row["actual_container_image_id"],
            workspace_manifest_digest=row["workspace_manifest_digest"],
            container_id=row["container_id"],
            attestation_digest=row["attestation_digest"] if "attestation_digest" in row.keys() else "",
            state=SandboxInstanceState(row["state"]),
            created_at=float(row["created_at"]),
            started_at=row["started_at"],
            terminated_at=row["terminated_at"],
            cleanup_status=row["cleanup_status"],
            failure_code=row["failure_code"],
            metadata=json.loads(row["metadata_json"]),
        )

    # ------------------------------------------------------------------
    # Batch 3.1.1 §3: Atomic step+run+execution terminal transitions
    # ------------------------------------------------------------------

    def _finish_step_and_run_impl(
        self, step: VerificationStepRun, *,
        run_target: VerificationRunStatus, execution_target: str,
        run_failure_code: str = "",
    ) -> None:
        """Single BEGIN IMMEDIATE: Step → terminal + Run → terminal + Execution → terminal + Audit."""
        now = time.time()
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            # 1. Step → terminal
            cur = self._conn.execute(
                "UPDATE plan_verification_steps SET status=?,exit_code=?,signal=?,started_at=?,"
                "completed_at=?,duration_ms=?,stdout_digest=?,stderr_digest=?,output_artifact_id=?,"
                "output_truncated=?,sandbox_instance_id=?,sandbox_image_digest=?,resource_usage_json=?,"
                "failure_code=? WHERE step_run_id=? AND status IN ('created','running')",
                (step.status.value, step.exit_code, step.signal, step.started_at,
                 step.completed_at, step.duration_ms, step.stdout_digest, step.stderr_digest,
                 step.output_artifact_id, int(step.output_truncated), step.sandbox_instance_id,
                 step.sandbox_image_digest, json.dumps(step.resource_usage, sort_keys=True),
                 step.failure_code, step.step_run_id),
            )
            if cur.rowcount != 1:
                raise RuntimeError("verification step CAS failed in finish_step_and_run")
            # 2. Run → terminal
            run_row = self._conn.execute(
                "SELECT execution_run_id FROM plan_verification_runs WHERE verification_run_id=?",
                (step.verification_run_id,),
            ).fetchone()
            if run_row is None:
                raise RuntimeError("verification run not found in finish_step_and_run")
            cur = self._conn.execute(
                "UPDATE plan_verification_runs SET status=?,updated_at=?,completed_at=?,failure_code=? "
                "WHERE verification_run_id=? AND status='running'",
                (run_target.value, now, now, run_failure_code,
                 step.verification_run_id),
            )
            if cur.rowcount != 1:
                raise RuntimeError("verification run CAS failed in finish_step_and_run")
            # 3. Execution → terminal
            cur = self._conn.execute(
                "UPDATE plan_execution_runs SET status=?,updated_at=?,completed_at=?,failure_code=? "
                "WHERE execution_run_id=? AND status='verifying'",
                (execution_target, now, now, run_failure_code, run_row[0]),
            )
            if cur.rowcount != 1:
                raise RuntimeError("execution run CAS failed in finish_step_and_run")
            # 4. Audit
            self._audit(step.verification_run_id, "step-and-run-finished",
                        step.status.value, step.failure_code, step.step_run_id)
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    def finish_step_and_run(self, step: VerificationStepRun) -> None:
        """Step PASSED + Run PASSED + Execution verified — single transaction."""
        self._finish_step_and_run_impl(
            step, run_target=VerificationRunStatus.PASSED,
            execution_target="verified",
        )

    def finalize_success(
        self, *, step: VerificationStepRun | None, verification_run_id: str,
        execution_run_id: str, workspace_id: str = "",
    ) -> None:
        """Batch 3.1.4 §6: atomic finalization in ONE BEGIN IMMEDIATE.

        Commits the following in a single transaction:
        1. Final Step → PASSED (the deferred last step, if any)
        2. Verification Run → PASSED (expected FINALIZING)
        3. Execution Run → VERIFIED (expected VERIFYING)
        4. Terminal Audit

        This replaces the forbidden ``finish_step() → cleanup →
        transition_run(PASSED)`` split.  The caller must:
        - Transition Run to FINALIZING before calling this.
        - Complete cleanup (disposable workspace destroy, sandbox instance
          removal, artifact sealing) BEFORE calling this.
        - Only call this when all required steps passed and cleanup succeeded.
        - Pass ``step=None`` when the last step was already committed
          (e.g. optional failure on the last step).
        """
        now = time.time()
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            # 1. Final Step → PASSED (if deferred)
            if step is not None:
                cur = self._conn.execute(
                    "UPDATE plan_verification_steps SET status=?,exit_code=?,signal=?,started_at=?,"
                    "completed_at=?,duration_ms=?,stdout_digest=?,stderr_digest=?,output_artifact_id=?,"
                    "output_truncated=?,sandbox_instance_id=?,sandbox_image_digest=?,resource_usage_json=?,"
                    "failure_code=? WHERE step_run_id=? AND status IN ('created','running')",
                    (step.status.value, step.exit_code, step.signal, step.started_at,
                     step.completed_at, step.duration_ms, step.stdout_digest, step.stderr_digest,
                     step.output_artifact_id, int(step.output_truncated), step.sandbox_instance_id,
                     step.sandbox_image_digest, json.dumps(step.resource_usage, sort_keys=True),
                     step.failure_code, step.step_run_id),
                )
                if cur.rowcount != 1:
                    raise RuntimeError("final step CAS failed in finalize_success")
            # 2. Verification Run → PASSED (expected FINALIZING)
            cur = self._conn.execute(
                "UPDATE plan_verification_runs SET status=?,updated_at=?,completed_at=?,failure_code=? "
                "WHERE verification_run_id=? AND status='finalizing'",
                (VerificationRunStatus.PASSED.value, now, now, "",
                 verification_run_id),
            )
            if cur.rowcount != 1:
                raise RuntimeError("verification run CAS failed in finalize_success")
            # 3. Execution Run → VERIFIED (expected VERIFYING)
            cur = self._conn.execute(
                "UPDATE plan_execution_runs SET status=?,updated_at=?,completed_at=?,failure_code=? "
                "WHERE execution_run_id=? AND status='verifying'",
                ("verified", now, now, "", execution_run_id),
            )
            if cur.rowcount != 1:
                raise RuntimeError("execution run CAS failed in finalize_success")
            # 4. Terminal Audit
            self._audit(verification_run_id, "finalized-success",
                        "passed", "", step.step_run_id if step else "")
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    def fail_step_and_run(self, step: VerificationStepRun, *, run_failure_code: str = "required-step-failed") -> None:
        """Step FAILED + Run FAILED + Execution verification-failed — single transaction."""
        self._finish_step_and_run_impl(
            step, run_target=VerificationRunStatus.FAILED,
            execution_target="verification-failed",
            run_failure_code=run_failure_code,
        )

    def timeout_step_and_run(self, step: VerificationStepRun) -> None:
        """Step TIMED_OUT + Run TIMED_OUT + Execution verification-error — single transaction."""
        self._finish_step_and_run_impl(
            step, run_target=VerificationRunStatus.TIMED_OUT,
            execution_target="verification-error",
            run_failure_code="timeout",
        )

    def abort_step_and_run(
        self, step_run_id: str, *, verification_run_id: str,
        failure_code: str = "aborted",
    ) -> None:
        """Step ABORTED + Run ERRORED + Execution verification-error — single transaction.

        Used when a backend exception, artifact failure, or cleanup failure
        prevents normal step completion.  The step must NOT remain RUNNING.
        """
        now = time.time()
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            cur = self._conn.execute(
                "UPDATE plan_verification_steps SET status='aborted',completed_at=?,"
                "failure_code=? WHERE step_run_id=? AND status IN ('created','running')",
                (now, failure_code, step_run_id),
            )
            if cur.rowcount != 1:
                raise RuntimeError("verification step abort CAS failed")
            run_row = self._conn.execute(
                "SELECT execution_run_id FROM plan_verification_runs WHERE verification_run_id=?",
                (verification_run_id,),
            ).fetchone()
            if run_row is None:
                raise RuntimeError("verification run not found in abort_step_and_run")
            cur = self._conn.execute(
                "UPDATE plan_verification_runs SET status='errored',updated_at=?,completed_at=?,"
                "failure_code=? WHERE verification_run_id=? AND status='running'",
                (now, now, failure_code, verification_run_id),
            )
            if cur.rowcount != 1:
                raise RuntimeError("verification run abort CAS failed")
            cur = self._conn.execute(
                "UPDATE plan_execution_runs SET status='verification-error',updated_at=?,"
                "completed_at=?,failure_code=? WHERE execution_run_id=? AND status='verifying'",
                (now, now, failure_code, run_row[0]),
            )
            if cur.rowcount != 1:
                raise RuntimeError("execution run abort CAS failed")
            self._audit(verification_run_id, "step-and-run-aborted",
                        "aborted", failure_code, step_run_id)
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    def assert_no_running_steps_in_terminal_run(self) -> int:
        """Batch 3.1.1 §3 invariant: terminal Run → RUNNING step count = 0.

        Returns the number of violations (0 = healthy).
        """
        rows = self._conn.execute(
            "SELECT r.verification_run_id, COUNT(s.step_run_id) as running_count "
            "FROM plan_verification_runs r "
            "JOIN plan_verification_steps s ON s.verification_run_id = r.verification_run_id "
            "WHERE r.status IN ('passed','failed','errored','timed-out','cancelled','stale','poisoned') "
            "AND s.status IN ('created','running') "
            "GROUP BY r.verification_run_id",
        ).fetchall()
        return len(rows)

    # ------------------------------------------------------------------
    # Batch 3.1.2 §9: Additional atomic terminal transitions
    # ------------------------------------------------------------------

    def cancel_step_and_run(
        self, step_run_id: str, *, verification_run_id: str,
        failure_code: str = "cancelled",
        step: VerificationStepRun | None = None,
    ) -> None:
        """Batch 3.1.2 §9: Step CANCELLED + Run CANCELLED + Execution cancelled — single transaction.

        If ``step`` is provided, all step execution details (exit_code,
        signal, duration, digests) are persisted atomically with the
        terminal transition.  Otherwise only status + failure_code are set.
        """
        if step is not None:
            self._finish_step_and_run_impl(
                step, run_target=VerificationRunStatus.CANCELLED,
                execution_target="cancelled",
                run_failure_code=failure_code,
            )
            return
        now = time.time()
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            cur = self._conn.execute(
                "UPDATE plan_verification_steps SET status='cancelled',completed_at=?,"
                "failure_code=? WHERE step_run_id=? AND status IN ('created','running')",
                (now, failure_code, step_run_id),
            )
            if cur.rowcount != 1:
                raise RuntimeError("verification step cancel CAS failed")
            run_row = self._conn.execute(
                "SELECT execution_run_id FROM plan_verification_runs WHERE verification_run_id=?",
                (verification_run_id,),
            ).fetchone()
            if run_row is None:
                raise RuntimeError("verification run not found in cancel_step_and_run")
            cur = self._conn.execute(
                "UPDATE plan_verification_runs SET status='cancelled',updated_at=?,completed_at=?,"
                "failure_code=? WHERE verification_run_id=? AND status='running'",
                (now, now, failure_code, verification_run_id),
            )
            if cur.rowcount != 1:
                raise RuntimeError("verification run cancel CAS failed")
            cur = self._conn.execute(
                "UPDATE plan_execution_runs SET status='cancelled',updated_at=?,"
                "completed_at=?,failure_code=? WHERE execution_run_id=? AND status='verifying'",
                (now, now, failure_code, run_row[0]),
            )
            if cur.rowcount != 1:
                raise RuntimeError("execution run cancel CAS failed")
            self._audit(verification_run_id, "step-and-run-cancelled",
                        "cancelled", failure_code, step_run_id)
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    def poison_step_and_run(
        self, step_run_id: str, *, verification_run_id: str,
        failure_code: str = "poisoned",
    ) -> None:
        """Batch 3.1.2 §9: Step ERRORED + Run POISONED + Execution poisoned — single transaction."""
        now = time.time()
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            cur = self._conn.execute(
                "UPDATE plan_verification_steps SET status='errored',completed_at=?,"
                "failure_code=? WHERE step_run_id=? AND status IN ('created','running')",
                (now, failure_code, step_run_id),
            )
            if cur.rowcount != 1:
                raise RuntimeError("verification step poison CAS failed")
            run_row = self._conn.execute(
                "SELECT execution_run_id FROM plan_verification_runs WHERE verification_run_id=?",
                (verification_run_id,),
            ).fetchone()
            if run_row is None:
                raise RuntimeError("verification run not found in poison_step_and_run")
            cur = self._conn.execute(
                "UPDATE plan_verification_runs SET status='poisoned',updated_at=?,completed_at=?,"
                "failure_code=? WHERE verification_run_id=? AND status='running'",
                (now, now, failure_code, verification_run_id),
            )
            if cur.rowcount != 1:
                raise RuntimeError("verification run poison CAS failed")
            cur = self._conn.execute(
                "UPDATE plan_execution_runs SET status='poisoned',updated_at=?,"
                "completed_at=?,failure_code=? WHERE execution_run_id=? AND status='verifying'",
                (now, now, failure_code, run_row[0]),
            )
            if cur.rowcount != 1:
                raise RuntimeError("execution run poison CAS failed")
            self._audit(verification_run_id, "step-and-run-poisoned",
                        "poisoned", failure_code, step_run_id)
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    def cleanup_fail_step_and_run(
        self, step_run_id: str, *, verification_run_id: str,
        failure_code: str = "cleanup-failed",
    ) -> None:
        """Batch 3.1.2 §9: Step ERRORED + Run ERRORED + Execution verification-error — single transaction.

        Used when disposable workspace cleanup fails.  The run must NOT
        be marked PASSED even if all steps passed.
        """
        now = time.time()
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            cur = self._conn.execute(
                "UPDATE plan_verification_steps SET status='errored',completed_at=?,"
                "failure_code=? WHERE step_run_id=? AND status IN ('created','running','passed')",
                (now, failure_code, step_run_id),
            )
            if cur.rowcount != 1:
                raise RuntimeError("verification step cleanup-fail CAS failed")
            run_row = self._conn.execute(
                "SELECT execution_run_id FROM plan_verification_runs WHERE verification_run_id=?",
                (verification_run_id,),
            ).fetchone()
            if run_row is None:
                raise RuntimeError("verification run not found in cleanup_fail_step_and_run")
            cur = self._conn.execute(
                "UPDATE plan_verification_runs SET status='errored',updated_at=?,completed_at=?,"
                "failure_code=? WHERE verification_run_id=? AND status IN ('running','passed')",
                (now, now, failure_code, verification_run_id),
            )
            if cur.rowcount != 1:
                raise RuntimeError("verification run cleanup-fail CAS failed")
            cur = self._conn.execute(
                "UPDATE plan_execution_runs SET status='verification-error',updated_at=?,"
                "completed_at=?,failure_code=? WHERE execution_run_id=? AND status='verifying'",
                (now, now, failure_code, run_row[0]),
            )
            if cur.rowcount != 1:
                raise RuntimeError("execution run cleanup-fail CAS failed")
            self._audit(verification_run_id, "step-and-run-cleanup-failed",
                        "errored", failure_code, step_run_id)
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    # ------------------------------------------------------------------
    # Batch 3.1.2 §3: Atomic crash terminalization with sandbox instance
    # ------------------------------------------------------------------

    def reconcile_sandbox_instance_atomic(
        self, *, sandbox_instance_id: str, step_run_id: str,
        verification_run_id: str, execution_run_id: str,
        instance_state: SandboxInstanceState, failure_code: str,
    ) -> None:
        """Batch 3.1.2 §3: single BEGIN IMMEDIATE for crash terminalization.

        After residual instance cleanup succeeds:
        - Instance → TERMINATED/ORPHANED_CLEANED
        - Step → ABORTED
        - Verification Run → ERRORED
        - Execution Run → VERIFICATION_ERROR
        - Audit
        - COMMIT
        """
        now = time.time()
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            cur = self._conn.execute(
                "UPDATE verification_sandbox_instances SET state=?,terminated_at=?,"
                "failure_code=? WHERE sandbox_instance_id=?",
                (instance_state.value, now, failure_code, sandbox_instance_id),
            )
            if cur.rowcount != 1:
                raise RuntimeError("sandbox instance reconcile CAS failed")
            cur = self._conn.execute(
                "UPDATE plan_verification_steps SET status='aborted',completed_at=?,"
                "failure_code=? WHERE step_run_id=? AND status IN ('created','running')",
                (now, failure_code, step_run_id),
            )
            if cur.rowcount != 1:
                raise RuntimeError("verification step reconcile CAS failed")
            cur = self._conn.execute(
                "UPDATE plan_verification_runs SET status='errored',updated_at=?,completed_at=?,"
                "failure_code=? WHERE verification_run_id=? AND status IN ('running','preparing-sandbox')",
                (now, now, failure_code, verification_run_id),
            )
            if cur.rowcount != 1:
                raise RuntimeError("verification run reconcile CAS failed")
            cur = self._conn.execute(
                "UPDATE plan_execution_runs SET status='verification-error',updated_at=?,"
                "completed_at=?,failure_code=? WHERE execution_run_id=? AND status='verifying'",
                (now, now, failure_code, execution_run_id),
            )
            if cur.rowcount != 1:
                raise RuntimeError("execution run reconcile CAS failed")
            self._audit(verification_run_id, "crash-reconciled",
                        instance_state.value, failure_code, sandbox_instance_id)
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    # ------------------------------------------------------------------
    # Batch 3.1.1 §3: Artifact RESERVED→SEALED protocol
    # ------------------------------------------------------------------

    def reserve_artifact(
        self, *, artifact_id: str, verification_run_id: str,
        relative_name: str, expires_at: float,
    ) -> None:
        """Batch 3.1.1 §3: insert a RESERVED artifact row BEFORE writing the file."""
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            self._conn.execute(
                "INSERT INTO plan_verification_artifacts "
                "(artifact_id, verification_run_id, relative_name, content_digest, "
                " byte_length, expires_at, quarantined, created_at, status) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (artifact_id, verification_run_id, relative_name,
                 "", 0, expires_at, 0, time.time(), "reserved"),
            )
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    def seal_artifact(
        self, *, artifact_id: str, content_digest: str, byte_length: int,
    ) -> None:
        """Batch 3.1.1 §3: atomically transition RESERVED → SEALED after fsync."""
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            cur = self._conn.execute(
                "UPDATE plan_verification_artifacts SET content_digest=?, byte_length=?, "
                "status='sealed' WHERE artifact_id=? AND status='reserved'",
                (content_digest, byte_length, artifact_id),
            )
            if cur.rowcount != 1:
                raise RuntimeError("artifact seal CAS failed (not reserved or not found)")
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    def quarantine_artifact(self, artifact_id: str, *, reason: str = "") -> None:
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            cur = self._conn.execute(
                "UPDATE plan_verification_artifacts SET quarantined=1, status='quarantined' "
                "WHERE artifact_id=?",
                (artifact_id,),
            )
            if cur.rowcount != 1:
                raise RuntimeError("artifact quarantine failed")
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    def list_unsealed_artifacts(self) -> tuple[sqlite3.Row, ...]:
        """Return artifacts in RESERVED state (crash recovery)."""
        return tuple(self._conn.execute(
            "SELECT * FROM plan_verification_artifacts WHERE status='reserved'"
        ).fetchall())

    def list_artifacts_without_files(self, artifact_root: Any) -> tuple[sqlite3.Row, ...]:
        """Return SEALED artifacts whose file is missing (crash recovery)."""
        rows = self._conn.execute(
            "SELECT * FROM plan_verification_artifacts WHERE status='sealed'"
        ).fetchall()
        missing: list[sqlite3.Row] = []
        for row in rows:
            from pathlib import Path
            path = Path(artifact_root) / row["relative_name"]
            if not path.exists():
                missing.append(row)
        return tuple(missing)

    def list_all_artifacts(self) -> tuple[sqlite3.Row, ...]:
        """Batch 3.1.3 §7: return all non-quarantined artifacts for reconciliation.

        Returns both RESERVED and SEALED rows so the runner can detect
        orphan files, incomplete writes, and sealed artifacts whose final
        file was deleted or corrupted after a crash.
        """
        return tuple(self._conn.execute(
            "SELECT * FROM plan_verification_artifacts "
            "WHERE status IN ('reserved','sealed') ORDER BY created_at"
        ).fetchall())

    # ------------------------------------------------------------------
    # Batch 3.1.2 §5: Toolchain attestation persistence
    # ------------------------------------------------------------------

    def persist_toolchain_attestation(
        self, attestation: Any, *, boot_id: str, server_epoch: int,
    ) -> None:
        """Persist a :class:`ToolchainAttestation` row (UPSERT by toolchain_id).

        The attestation is bound to the current boot context so a new boot
        can detect stale attestations and re-attest.  The
        ``attestation_digest`` is the canonical binding used at execution
        time to re-verify the toolchain before launch.
        """
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            self._conn.execute(
                "INSERT INTO toolchain_attestations "
                "(toolchain_id, executable_path, binary_digest, "
                " version_output_digest, parsed_version, "
                " actual_image_attestation, attested_at, attestation_digest, "
                " boot_id, server_epoch, image_attestation_digest) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(toolchain_id) DO UPDATE SET "
                " executable_path=excluded.executable_path, "
                " binary_digest=excluded.binary_digest, "
                " version_output_digest=excluded.version_output_digest, "
                " parsed_version=excluded.parsed_version, "
                " actual_image_attestation=excluded.actual_image_attestation, "
                " attested_at=excluded.attested_at, "
                " attestation_digest=excluded.attestation_digest, "
                " boot_id=excluded.boot_id, "
                " server_epoch=excluded.server_epoch, "
                " image_attestation_digest=excluded.image_attestation_digest",
                (attestation.toolchain_id, attestation.executable_path,
                 attestation.binary_digest, attestation.version_output_digest,
                 attestation.parsed_version, attestation.actual_image_attestation,
                 attestation.attested_at, attestation.attestation_digest,
                 boot_id, server_epoch,
                 getattr(attestation, "image_attestation_digest", "")),
            )
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    def get_toolchain_attestation(self, toolchain_id: str) -> Any | None:
        """Return the persisted :class:`ToolchainAttestation` or None.

        Imports :class:`ToolchainAttestation` lazily to avoid a circular
        import (``verification_sandbox`` imports from this module's
        sibling ``verification_sandbox_instance``).
        """
        row = self._conn.execute(
            "SELECT * FROM toolchain_attestations WHERE toolchain_id=?",
            (toolchain_id,),
        ).fetchone()
        if row is None:
            return None
        from khaos.coding.planning.verification_sandbox import ToolchainAttestation
        return ToolchainAttestation(
            toolchain_id=row["toolchain_id"],
            executable_path=row["executable_path"],
            binary_digest=row["binary_digest"],
            version_output_digest=row["version_output_digest"],
            parsed_version=row["parsed_version"],
            actual_image_attestation=row["actual_image_attestation"],
            attested_at=row["attested_at"],
            attestation_digest=row["attestation_digest"],
            image_attestation_digest=row["image_attestation_digest"],
        )

    def list_toolchain_attestations(self) -> tuple[Any, ...]:
        """Return all persisted toolchain attestations (any boot)."""
        rows = self._conn.execute(
            "SELECT * FROM toolchain_attestations ORDER BY toolchain_id"
        ).fetchall()
        from khaos.coding.planning.verification_sandbox import ToolchainAttestation
        return tuple(ToolchainAttestation(
            toolchain_id=row["toolchain_id"],
            executable_path=row["executable_path"],
            binary_digest=row["binary_digest"],
            version_output_digest=row["version_output_digest"],
            parsed_version=row["parsed_version"],
            actual_image_attestation=row["actual_image_attestation"],
            attested_at=row["attested_at"],
            attestation_digest=row["attestation_digest"],
            image_attestation_digest=row["image_attestation_digest"],
        ) for row in rows)

    def clear_toolchain_attestations_for_boot(self, *, boot_id: str) -> int:
        """Remove toolchain attestations from a previous boot.

        Called during ``configure_trusted_verification`` after new
        attestations have been persisted, so stale attestations from a
        crashed boot don't linger.  Returns the number of rows removed.
        """
        cur = self._conn.execute(
            "DELETE FROM toolchain_attestations WHERE boot_id != ?",
            (boot_id,),
        )
        self._conn.commit()
        return cur.rowcount

    # ------------------------------------------------------------------
    # Batch 3.1.2 §8: Disposable verification workspace persistence
    # ------------------------------------------------------------------

    def create_disposable_workspace(
        self, record: DisposableWorkspaceRecord,
    ) -> None:
        """Persist a new disposable workspace row in PREPARED state."""
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            self._conn.execute(
                "INSERT INTO disposable_verification_workspaces VALUES ("
                "?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (record.workspace_id, record.verification_run_id,
                 record.step_run_id, record.instance_id,
                 record.manifest_digest, record.manifest_json,
                 json.dumps(list(record.allowed_generated_output)),
                 record.state.value, record.boot_id, record.created_at,
                 record.sealed_at, record.mounted_at, record.cleanup_started_at,
                 record.cleaned_at, record.failure_code, "{}"),
            )
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    def transition_disposable_workspace(
        self, workspace_id: str, *,
        expected: tuple[DisposableWorkspaceState, ...],
        target: DisposableWorkspaceState,
        failure_code: str = "",
    ) -> None:
        """CAS transition for disposable workspace state."""
        now = time.time()
        expected_str = tuple(e.value for e in expected)
        placeholders = ",".join("?" * len(expected_str))
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            if target == DisposableWorkspaceState.SEALED:
                col, val = "sealed_at", now
            elif target == DisposableWorkspaceState.MOUNTED:
                col, val = "mounted_at", now
            elif target == DisposableWorkspaceState.CLEANUP_PENDING:
                col, val = "cleanup_started_at", now
            elif target == DisposableWorkspaceState.CLEANED:
                col, val = "cleaned_at", now
            else:
                col, val = None, None
            if col is not None:
                cur = self._conn.execute(
                    f"UPDATE disposable_verification_workspaces SET state=?,{col}=?,"
                    f"failure_code=? WHERE workspace_id=? AND state IN ({placeholders})",
                    (target.value, val, failure_code, workspace_id, *expected_str),
                )
            else:
                cur = self._conn.execute(
                    f"UPDATE disposable_verification_workspaces SET state=?,"
                    f"failure_code=? WHERE workspace_id=? AND state IN ({placeholders})",
                    (target.value, failure_code, workspace_id, *expected_str),
                )
            if cur.rowcount != 1:
                raise RuntimeError("disposable workspace CAS failed")
            self._audit(
                workspace_id, "disposable-workspace-transition",
                target.value, failure_code, workspace_id,
            )
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    def seal_disposable_workspace(
        self, workspace_id: str, *,
        manifest_digest: str, manifest_json: str,
    ) -> None:
        """Batch 3.1.3 §6: seal the PREPARED row with the manifest.

        Atomically updates the manifest fields and transitions
        PREPARED → SEALED in a single BEGIN IMMEDIATE transaction.
        This is called after the filesystem copy completes successfully.
        """
        now = time.time()
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            cur = self._conn.execute(
                "UPDATE disposable_verification_workspaces "
                "SET manifest_digest=?, manifest_json=?, state='sealed', "
                "sealed_at=? WHERE workspace_id=? AND state='prepared'",
                (manifest_digest, manifest_json, now, workspace_id),
            )
            if cur.rowcount != 1:
                raise RuntimeError("seal_disposable_workspace CAS failed")
            self._audit(
                workspace_id, "disposable-workspace-sealed",
                "sealed", "", workspace_id,
            )
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    def get_disposable_workspace(
        self, workspace_id: str,
    ) -> DisposableWorkspaceRecord | None:
        row = self._conn.execute(
            "SELECT * FROM disposable_verification_workspaces WHERE workspace_id=?",
            (workspace_id,),
        ).fetchone()
        return self._row_to_disposable_workspace(row) if row else None

    def get_disposable_workspace_by_instance(
        self, instance_id: str,
    ) -> DisposableWorkspaceRecord | None:
        row = self._conn.execute(
            "SELECT * FROM disposable_verification_workspaces WHERE instance_id=?",
            (instance_id,),
        ).fetchone()
        return self._row_to_disposable_workspace(row) if row else None

    def list_active_disposable_workspaces(
        self,
    ) -> tuple[DisposableWorkspaceRecord, ...]:
        """Return all workspaces not in a terminal state (cleaned/cleanup-failed/quarantined)."""
        rows = self._conn.execute(
            "SELECT * FROM disposable_verification_workspaces "
            "WHERE state NOT IN ('cleaned','cleanup-failed','quarantined') "
            "ORDER BY created_at",
        ).fetchall()
        return tuple(self._row_to_disposable_workspace(row) for row in rows)

    def list_disposable_workspaces_for_boot(
        self, boot_id: str,
    ) -> tuple[DisposableWorkspaceRecord, ...]:
        rows = self._conn.execute(
            "SELECT * FROM disposable_verification_workspaces WHERE boot_id=? "
            "ORDER BY created_at", (boot_id,),
        ).fetchall()
        return tuple(self._row_to_disposable_workspace(row) for row in rows)

    def list_disposable_workspaces_for_run(
        self, verification_run_id: str,
    ) -> tuple[DisposableWorkspaceRecord, ...]:
        rows = self._conn.execute(
            "SELECT * FROM disposable_verification_workspaces WHERE verification_run_id=? "
            "ORDER BY created_at", (verification_run_id,),
        ).fetchall()
        return tuple(self._row_to_disposable_workspace(row) for row in rows)

    def mark_disposable_workspace_cleanup_failed(
        self, workspace_id: str, *, failure_code: str = "cleanup-failed",
    ) -> None:
        """Mark a workspace as cleanup-failed (fail-closed, not cleaned)."""
        now = time.time()
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            self._conn.execute(
                "UPDATE disposable_verification_workspaces SET state='cleanup-failed',"
                "failure_code=?,cleaned_at=? WHERE workspace_id=?",
                (failure_code, now, workspace_id),
            )
            self._audit(
                workspace_id, "disposable-workspace-cleanup-failed",
                "cleanup-failed", failure_code, workspace_id,
            )
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    def mark_disposable_workspace_cleaned(
        self, workspace_id: str,
    ) -> None:
        """Mark a workspace as cleaned (cleanup succeeded)."""
        now = time.time()
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            self._conn.execute(
                "UPDATE disposable_verification_workspaces SET state='cleaned',"
                "cleaned_at=? WHERE workspace_id=?",
                (now, workspace_id),
            )
            self._audit(
                workspace_id, "disposable-workspace-cleaned",
                "cleaned", "", workspace_id,
            )
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    @staticmethod
    def _row_to_disposable_workspace(row: sqlite3.Row) -> DisposableWorkspaceRecord:
        return DisposableWorkspaceRecord(
            workspace_id=row["workspace_id"],
            verification_run_id=row["verification_run_id"],
            step_run_id=row["step_run_id"],
            instance_id=row["instance_id"],
            manifest_digest=row["manifest_digest"],
            manifest_json=row["manifest_json"],
            allowed_generated_output=tuple(json.loads(row["allowed_generated_output"])),
            state=DisposableWorkspaceState(row["state"]),
            boot_id=row["boot_id"],
            created_at=row["created_at"],
            sealed_at=row["sealed_at"],
            mounted_at=row["mounted_at"],
            cleanup_started_at=row["cleanup_started_at"],
            cleaned_at=row["cleaned_at"],
            failure_code=row["failure_code"],
        )
