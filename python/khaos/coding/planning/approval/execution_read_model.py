"""Read-only queries for durable planned-execution state.

The approval store owns atomic writes and recovery transitions.  This module
owns the SQL shape and integrity-preserving row conversion for execution runs,
edit journals, and terminal attestations.  It deliberately receives an
already-open connection and never commits, rolls back, or changes persisted
state.
"""
from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from typing import Any


class PlanExecutionReadModel:
    """Read-only SQL facade for planned execution records and proofs."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn
        self._verification_success_verifier: Callable[[str], Any] | None = None
        self._authoritative_verification_reads_required = False

    def install_verification_success_verifier(
        self, verifier: Callable[[str], Any]
    ) -> None:
        """Bind the runtime-owned proof verifier used by VERIFIED reads."""
        if self._verification_success_verifier is not None:
            if self._verification_success_verifier == verifier:
                return
            raise PermissionError("verification success verifier already installed")
        self._verification_success_verifier = verifier

    def require_authoritative_verification_reads(self) -> None:
        """Require proof authority whenever a VERIFIED run is read."""
        self._authoritative_verification_reads_required = True

    def reset_verification_success_verifier(self) -> None:
        """Clear the boot-scoped verifier during runtime shutdown."""
        self._verification_success_verifier = None

    def get_execution_run_by_context(self, execution_context_id: str) -> Any | None:
        row = self._conn.execute(
            "SELECT * FROM plan_execution_runs WHERE execution_context_id=?",
            (execution_context_id,),
        ).fetchone()
        return self.row_to_execution_run(row) if row is not None else None

    def get_execution_run(
        self,
        execution_run_id: str,
        *,
        verification_success_verifier: Callable[[str], Any] | None = None,
        authoritative_verification_reads_required: bool = False,
    ) -> Any | None:
        row = self._conn.execute(
            "SELECT * FROM plan_execution_runs WHERE execution_run_id=?",
            (execution_run_id,),
        ).fetchone()
        if row is not None and row["status"] == "verified":
            verifier = verification_success_verifier or self._verification_success_verifier
            requires_authority = (
                authoritative_verification_reads_required
                or self._authoritative_verification_reads_required
            )
            if verifier is None:
                if requires_authority:
                    raise PermissionError(
                        "VERIFIED execution cannot be trusted without authority"
                    )
            else:
                verifier(execution_run_id)
        return self.row_to_execution_run(row) if row is not None else None

    def list_incomplete_execution_runs(self) -> tuple[Any, ...]:
        rows = self._conn.execute(
            "SELECT * FROM plan_execution_runs WHERE status IN "
            "('validating','mutating','sealing','rolling-back','rollback-sealing','poisoned') "
            "ORDER BY started_at,execution_run_id"
        ).fetchall()
        return tuple(self.row_to_execution_run(row) for row in rows)

    def list_execution_edit_events(self, execution_run_id: str) -> tuple[sqlite3.Row, ...]:
        return tuple(
            self._conn.execute(
                "SELECT * FROM plan_execution_edit_events WHERE execution_run_id=? "
                "ORDER BY ordinal,event_id",
                (execution_run_id,),
            ).fetchall()
        )

    def execution_journal_progress(self, execution_run_id: str) -> tuple[int, int]:
        row = self._conn.execute(
            "SELECT journaled_edit_count,(SELECT COUNT(*) FROM "
            "plan_execution_edit_events e WHERE e.execution_run_id=r.execution_run_id) "
            "AS actual_count FROM plan_execution_runs r WHERE execution_run_id=?",
            (execution_run_id,),
        ).fetchone()
        if row is None:
            raise RuntimeError("execution run not found")
        return int(row["journaled_edit_count"]), int(row["actual_count"])

    def get_initial_workspace_attestation(self, run_id: str) -> Any | None:
        row = self._conn.execute(
            "SELECT canonical_json,attestation_digest FROM plan_execution_initial_attestations "
            "WHERE execution_run_id=?",
            (run_id,),
        ).fetchone()
        if row is None:
            return None
        from khaos.coding.planning.execution_models import (
            InitialApprovedEdit,
            InitialPathState,
            InitialWorkspaceAttestation,
            PlannedEditOperation,
        )

        try:
            payload = json.loads(row["canonical_json"])
            value = InitialWorkspaceAttestation(
                **{
                    key: val
                    for key, val in payload.items()
                    if key not in {"declared_states", "workspace_states", "approved_edits"}
                },
                declared_states=tuple(
                    InitialPathState(**item) for item in payload["declared_states"]
                ),
                workspace_states=tuple(
                    InitialPathState(**item) for item in payload["workspace_states"]
                ),
                approved_edits=tuple(
                    InitialApprovedEdit(
                        **{**item, "operation": PlannedEditOperation(item["operation"])}
                    )
                    for item in payload.get("approved_edits", ())
                ),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise RuntimeError("initial attestation corrupt") from exc
        normalized = value.normalized()
        if normalized.attestation_digest != row["attestation_digest"]:
            raise RuntimeError("initial attestation digest mismatch")
        return normalized

    def get_final_mutation_attestation(self, execution_run_id: str) -> Any | None:
        row = self._conn.execute(
            "SELECT * FROM plan_execution_final_attestations WHERE execution_run_id=?",
            (execution_run_id,),
        ).fetchone()
        if row is None:
            return None
        from khaos.coding.planning.execution_models import (
            AttestedPathState,
            FinalMutationAttestation,
        )

        try:
            payload = json.loads(row["canonical_json"])
            value = FinalMutationAttestation(
                execution_run_id=payload["execution_run_id"],
                bundle_digest=payload["bundle_digest"],
                ordered_states=tuple(
                    AttestedPathState(**item) for item in payload["ordered_states"]
                ),
                path_state_digest=payload["path_state_digest"],
                head=payload["head"],
                generation=int(payload["generation"]),
                index_digest=payload["index_digest"],
                worktree_admin_digest=payload["worktree_admin_digest"],
                workspace_state_digest=payload["workspace_state_digest"],
                execution_context_id=payload["execution_context_id"],
                lease_id=payload["lease_id"],
                binding_digest=payload["binding_digest"],
                attested_at=float(payload["attested_at"]),
                attestation_digest=row["attestation_digest"],
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise RuntimeError("final mutation attestation is corrupt") from exc
        normalized = value.normalized()
        if (
            normalized.attestation_digest != row["attestation_digest"]
            or normalized.bundle_digest != row["bundle_digest"]
            or normalized.canonical() != value.canonical()
        ):
            raise RuntimeError("final mutation attestation digest mismatch")
        return normalized

    def get_verification_step(self, step_run_id: str) -> Any | None:
        """Return one persisted verification step through the read model.

        M7.4 uses this narrow read-only surface to bind an evidence descriptor
        to the exact requirement, command digest, terminal status, exit code,
        output digests, and truncation flag recorded by M4.  It never returns
        raw stdout/stderr or exposes the underlying connection.
        """
        row = self._conn.execute(
            "SELECT * FROM plan_verification_steps WHERE step_run_id=?",
            (step_run_id,),
        ).fetchone()
        if row is None:
            return None
        from khaos.coding.planning.verification_execution_models import (
            VerificationStepRun,
            VerificationStepStatus,
        )

        try:
            resource_usage = json.loads(row["resource_usage_json"])
            if type(resource_usage) is not dict:
                raise ValueError("verification step resource usage is not an object")
            return VerificationStepRun(
                step_run_id=row["step_run_id"],
                verification_run_id=row["verification_run_id"],
                requirement_id=row["requirement_id"],
                command_id=row["command_id"],
                command_digest=row["command_digest"],
                ordinal=int(row["ordinal"]),
                status=VerificationStepStatus(row["status"]),
                exit_code=row["exit_code"],
                signal=row["signal"],
                started_at=row["started_at"],
                completed_at=row["completed_at"],
                duration_ms=int(row["duration_ms"]),
                timeout_ms=int(row["timeout_ms"]),
                stdout_digest=row["stdout_digest"],
                stderr_digest=row["stderr_digest"],
                output_artifact_id=row["output_artifact_id"],
                output_truncated=bool(row["output_truncated"]),
                sandbox_instance_id=row["sandbox_instance_id"],
                sandbox_image_digest=row["sandbox_image_digest"],
                resource_usage=resource_usage,
                failure_code=row["failure_code"],
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise RuntimeError("verification step is corrupt") from exc

    def get_rollback_final_attestation(self, execution_run_id: str) -> Any | None:
        row = self._conn.execute(
            "SELECT * FROM plan_execution_rollback_attestations WHERE execution_run_id=?",
            (execution_run_id,),
        ).fetchone()
        if row is None:
            return None
        from khaos.coding.planning.execution_models import (
            AttestedPathState,
            RollbackFinalAttestation,
        )

        try:
            payload = json.loads(row["canonical_json"])
            value = RollbackFinalAttestation(
                execution_run_id=payload["execution_run_id"],
                bundle_digest=payload["bundle_digest"],
                ordered_states=tuple(
                    AttestedPathState(**item) for item in payload["ordered_states"]
                ),
                path_state_digest=payload["path_state_digest"],
                head=payload["head"],
                generation=int(payload["generation"]),
                index_digest=payload["index_digest"],
                worktree_admin_digest=payload["worktree_admin_digest"],
                workspace_state_digest=payload["workspace_state_digest"],
                execution_context_id=payload["execution_context_id"],
                lease_id=payload["lease_id"],
                binding_digest=payload["binding_digest"],
                attested_at=float(payload["attested_at"]),
                rollback_reason=payload["rollback_reason"],
                journal_digest=payload["journal_digest"],
                attestation_digest=row["attestation_digest"],
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise RuntimeError("rollback attestation is corrupt") from exc
        normalized = value.normalized()
        if normalized.attestation_digest != row["attestation_digest"]:
            raise RuntimeError("rollback attestation digest mismatch")
        return normalized

    @staticmethod
    def row_to_execution_run(row: sqlite3.Row) -> Any:
        """Convert a persisted execution row without mutating the database."""
        from khaos.coding.planning.execution_models import (
            ExecutionRunStatus,
            PlanExecutionRun,
        )

        return PlanExecutionRun(
            execution_run_id=row["execution_run_id"],
            plan_id=row["plan_id"],
            plan_content_hash=row["plan_content_hash"],
            approval_request_id=row["approval_request_id"],
            authorization_id=row["authorization_id"],
            execution_context_id=row["execution_context_id"],
            lease_id=row["lease_id"],
            task_id=row["task_id"],
            workspace_id=row["workspace_id"],
            repository_id=row["repository_id"],
            base_sha=row["base_sha"],
            repository_generation=int(row["repository_generation"]),
            binding_digest=row["binding_digest"],
            edit_bundle_digest=row["edit_bundle_digest"],
            status=ExecutionRunStatus(row["status"]),
            started_at=float(row["started_at"]),
            updated_at=float(row["updated_at"]),
            completed_at=row["completed_at"],
            failure_code=row["failure_code"],
            metadata=json.loads(row["metadata_json"]),
        )
