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
            if verification_success_verifier is None:
                if authoritative_verification_reads_required:
                    raise PermissionError(
                        "VERIFIED execution cannot be trusted without authority"
                    )
            else:
                verification_success_verifier(execution_run_id)
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
