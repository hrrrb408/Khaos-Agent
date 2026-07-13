"""SQLite CAS persistence for trusted verification and phase leases."""
from __future__ import annotations

import json
import sqlite3
import time
import uuid
from typing import Any

from khaos.coding.planning.verification_execution_models import (
    VerificationExecutionRun, VerificationRunStatus, VerificationStepRun,
    VerificationStepStatus,
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
 expires_at REAL NOT NULL, quarantined INTEGER NOT NULL DEFAULT 0, created_at REAL NOT NULL
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
"""


class VerificationExecutionStore:
    def __init__(self, approval_store: Any) -> None:
        self._approval_store = approval_store
        self._conn: sqlite3.Connection = approval_store._conn
        self._conn.executescript(_SCHEMA)
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
            VerificationRunStatus.RUNNING: {VerificationRunStatus.PASSED, VerificationRunStatus.FAILED, VerificationRunStatus.ERRORED, VerificationRunStatus.TIMED_OUT, VerificationRunStatus.CANCELLED, VerificationRunStatus.POISONED},
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
        """Never infer PREPARING/RUNNING work as passed after restart."""
        now = time.time()
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            rows = self._conn.execute(
                "SELECT verification_run_id,execution_run_id FROM plan_verification_runs "
                "WHERE status IN ('preparing-sandbox','running')"
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
