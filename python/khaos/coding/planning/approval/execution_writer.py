"""Transactional writer for planned execution runs and terminal proofs.

``PlanApprovalStore`` remains the approval/lease ledger facade during the
migration period, but it must not be the second owner of execution-run writes.
This writer owns the transaction boundary for run lifecycle transitions,
attestation persistence, terminal seals, and crash recovery.  It receives an
already-open connection and the execution read model; it never manages the
connection lifecycle or approval state.
"""
from __future__ import annotations

import json
import sqlite3
import time
import uuid
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from khaos.coding.planning.approval.execution_read_model import PlanExecutionReadModel

if TYPE_CHECKING:
    from khaos.coding.planning.execution_models import RollbackResumeState


class PlanExecutionWriter:
    """Own atomic planned-execution run and proof writes."""

    def __init__(
        self,
        conn: sqlite3.Connection,
        read_model: PlanExecutionReadModel,
        audit_writer: Callable[..., None] | None = None,
    ) -> None:
        self._conn = conn
        self._read_model = read_model
        self._audit_writer = audit_writer or self._insert_execution_audit

    def create_execution_run(self, run: Any) -> Any:
        """Create one run per authorization/context, or return idempotently."""
        existing = self._read_model.get_execution_run_by_context(
            run.execution_context_id
        )
        if existing is not None:
            return existing
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            self._conn.execute(
                "INSERT INTO plan_execution_runs "
                "(execution_run_id,plan_id,plan_content_hash,approval_request_id,"
                "authorization_id,execution_context_id,lease_id,task_id,workspace_id,"
                "repository_id,base_sha,repository_generation,binding_digest,"
                "edit_bundle_digest,status,started_at,updated_at,completed_at,"
                "failure_code,metadata_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    run.execution_run_id,
                    run.plan_id,
                    run.plan_content_hash,
                    run.approval_request_id,
                    run.authorization_id,
                    run.execution_context_id,
                    run.lease_id,
                    run.task_id,
                    run.workspace_id,
                    run.repository_id,
                    run.base_sha,
                    int(run.repository_generation),
                    run.binding_digest,
                    run.edit_bundle_digest,
                    run.status.value,
                    run.started_at,
                    run.updated_at,
                    run.completed_at,
                    run.failure_code,
                    json.dumps(
                        {"edit_count": int(run.metadata.get("edit_count", 0))},
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                ),
            )
            self._audit_writer(
                run.execution_run_id,
                "run-created",
                result="created",
                correlation_id=run.execution_context_id,
            )
            self._conn.commit()
            return run
        except sqlite3.IntegrityError:
            self._conn.rollback()
            existing = self._read_model.get_execution_run_by_context(
                run.execution_context_id
            )
            if existing is None:
                raise
            return existing
        except Exception:
            self._conn.rollback()
            raise

    def transition_execution_run(
        self,
        execution_run_id: str,
        *,
        expected: tuple[str, ...],
        target: str,
        failure_code: str = "",
        completed: bool = False,
    ) -> None:
        """Advance a run through its explicit state machine using CAS."""
        allowed = {
            "created": frozenset({"validating", "cancelled"}),
            "validating": frozenset(
                {"mutating", "rolling-back", "failed", "poisoned", "cancelled"}
            ),
            "mutating": frozenset(
                {"sealing", "rolling-back", "poisoned", "cancelled", "failed"}
            ),
            "sealing": frozenset({"mutated", "poisoned"}),
            "rolling-back": frozenset({"rollback-sealing", "poisoned"}),
            "rollback-sealing": frozenset({"rolled-back", "poisoned", "cancelled"}),
            "poisoned": frozenset({"rolling-back"}),
        }
        if not expected or any(
            target not in allowed.get(source, frozenset()) for source in expected
        ):
            raise RuntimeError("invalid execution run state transition")
        now = time.time()
        placeholders = ",".join("?" for _ in expected)
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            cur = self._conn.execute(
                f"UPDATE plan_execution_runs SET status=?,updated_at=?,"
                "completed_at=?,failure_code=? WHERE execution_run_id=? "
                f"AND status IN ({placeholders})",
                (
                    target,
                    now,
                    now if completed else None,
                    failure_code,
                    execution_run_id,
                    *expected,
                ),
            )
            if int(cur.rowcount or 0) != 1:
                raise RuntimeError("invalid execution run transition")
            self._audit_writer(
                execution_run_id,
                "run-transition",
                result=target,
                error_code=failure_code,
                correlation_id=execution_run_id,
            )
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    def begin_or_resume_rollback(
        self,
        execution_run_id: str,
        *,
        failure_code: str,
        now: float | None = None,
    ) -> RollbackResumeState:
        """Atomically begin or resume rollback without changing its reason."""
        from khaos.coding.planning.execution_models import (
            ExecutionRunStatus,
            RollbackResumeDisposition,
            RollbackResumeState,
        )

        timestamp = time.time() if now is None else float(now)
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            row = self._conn.execute(
                "SELECT status,failure_code FROM plan_execution_runs "
                "WHERE execution_run_id=?",
                (execution_run_id,),
            ).fetchone()
            if row is None:
                raise RuntimeError("execution run not found")
            status = ExecutionRunStatus(row["status"])
            stored_reason = str(row["failure_code"] or "")
            effective_reason = stored_reason or failure_code
            if status in {
                ExecutionRunStatus.VALIDATING,
                ExecutionRunStatus.MUTATING,
                ExecutionRunStatus.POISONED,
            }:
                cur = self._conn.execute(
                    "UPDATE plan_execution_runs SET status='rolling-back',"
                    "failure_code=?,updated_at=? WHERE execution_run_id=? AND status=?",
                    (effective_reason, timestamp, execution_run_id, status.value),
                )
                if int(cur.rowcount or 0) != 1:
                    raise RuntimeError("rollback run CAS conflict")
                self._audit_writer(
                    execution_run_id,
                    "rollback-started",
                    result="rolling-back",
                    error_code=effective_reason,
                    correlation_id=execution_run_id,
                )
                disposition = RollbackResumeDisposition.STARTED
                status = ExecutionRunStatus.ROLLING_BACK
            elif status == ExecutionRunStatus.ROLLING_BACK:
                if not stored_reason:
                    cur = self._conn.execute(
                        "UPDATE plan_execution_runs SET failure_code=?,updated_at=? "
                        "WHERE execution_run_id=? AND status='rolling-back' "
                        "AND failure_code=''",
                        (effective_reason, timestamp, execution_run_id),
                    )
                    if int(cur.rowcount or 0) != 1:
                        raise RuntimeError("rollback reason CAS conflict")
                disposition = RollbackResumeDisposition.RESUMED
            elif status == ExecutionRunStatus.ROLLBACK_SEALING:
                disposition = RollbackResumeDisposition.SEALING
            elif status in {
                ExecutionRunStatus.ROLLED_BACK,
                ExecutionRunStatus.CANCELLED,
            }:
                disposition = RollbackResumeDisposition.TERMINAL
            else:
                raise RuntimeError("execution run cannot enter rollback")
            self._conn.commit()
            return RollbackResumeState(disposition, status, effective_reason)
        except Exception:
            self._conn.rollback()
            raise

    def mark_execution_recovery_sealed(
        self, execution_run_id: str, *, seal_digest: str
    ) -> None:
        self._mark_sealed(
            execution_run_id,
            expected_status="sealing",
            seal_column="recovery_seal_digest",
            seal_time_column="recovery_sealed_at",
            seal_digest=seal_digest,
            audit_event="recovery-sealed",
        )

    def mark_execution_rollback_sealed(
        self, execution_run_id: str, *, seal_digest: str
    ) -> None:
        self._mark_sealed(
            execution_run_id,
            expected_status="rollback-sealing",
            seal_column="rollback_seal_digest",
            seal_time_column="rollback_sealed_at",
            seal_digest=seal_digest,
            audit_event="rollback-recovery-sealed",
        )

    def _mark_sealed(
        self,
        execution_run_id: str,
        *,
        expected_status: str,
        seal_column: str,
        seal_time_column: str,
        seal_digest: str,
        audit_event: str,
    ) -> None:
        now = time.time()
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            cur = self._conn.execute(
                f"UPDATE plan_execution_runs SET {seal_time_column}=?,"
                f"{seal_column}=?,updated_at=? WHERE execution_run_id=? "
                f"AND status=?",
                (now, seal_digest, now, execution_run_id, expected_status),
            )
            if int(cur.rowcount or 0) != 1:
                raise RuntimeError(f"execution run is not {expected_status}")
            self._audit_writer(
                execution_run_id,
                audit_event,
                result="sealed",
                correlation_id=execution_run_id,
            )
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    def save_final_mutation_attestation(self, attestation: Any) -> None:
        normalized = attestation.normalized()
        payload = json.dumps(
            normalized.canonical(),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            self._conn.execute(
                "INSERT INTO plan_execution_final_attestations "
                "(execution_run_id,bundle_digest,canonical_json,attestation_digest,attested_at) "
                "VALUES (?,?,?,?,?)",
                (
                    normalized.execution_run_id,
                    normalized.bundle_digest,
                    payload,
                    normalized.attestation_digest,
                    normalized.attested_at,
                ),
            )
            self._audit_writer(
                normalized.execution_run_id,
                "final-mutation-attested",
                result="attested",
                correlation_id=normalized.attestation_digest,
            )
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    def save_initial_workspace_attestation(self, attestation: Any) -> None:
        value = attestation.normalized()
        payload = json.dumps(
            {
                **value.__dict__,
                "declared_states": [item.__dict__ for item in value.declared_states],
                "workspace_states": [item.__dict__ for item in value.workspace_states],
                "approved_edits": [item.canonical() for item in value.approved_edits],
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            self._conn.execute(
                "INSERT INTO plan_execution_initial_attestations VALUES (?,?,?,?)",
                (value.execution_run_id, payload, value.attestation_digest, value.attested_at),
            )
            cur = self._conn.execute(
                "UPDATE plan_execution_runs SET initial_attestation_digest=? "
                "WHERE execution_run_id=? AND status='validating'",
                (value.attestation_digest, value.execution_run_id),
            )
            if int(cur.rowcount or 0) != 1:
                raise RuntimeError("run cannot accept initial attestation")
            self._audit_writer(
                value.execution_run_id,
                "initial-workspace-attested",
                result="attested",
                correlation_id=value.attestation_digest,
            )
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    def save_rollback_final_attestation(self, attestation: Any) -> None:
        normalized = attestation.normalized()
        payload = json.dumps(
            normalized.canonical(),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            self._conn.execute(
                "INSERT INTO plan_execution_rollback_attestations "
                "(execution_run_id,bundle_digest,canonical_json,attestation_digest,attested_at) "
                "VALUES (?,?,?,?,?)",
                (
                    normalized.execution_run_id,
                    normalized.bundle_digest,
                    payload,
                    normalized.attestation_digest,
                    normalized.attested_at,
                ),
            )
            self._audit_writer(
                normalized.execution_run_id,
                "rollback-final-attested",
                result="attested",
                correlation_id=normalized.attestation_digest,
            )
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    def commit_terminal_seal(
        self,
        execution_run_id: str,
        *,
        expected_status: str,
        terminal_status: str,
        seal_digest: str,
        tombstone_digest: str,
        rollback: bool,
        failure_code: str = "",
    ) -> None:
        now = time.time()
        seal_time = "rollback_sealed_at" if rollback else "recovery_sealed_at"
        seal_column = "rollback_seal_digest" if rollback else "recovery_seal_digest"
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            cur = self._conn.execute(
                f"UPDATE plan_execution_runs SET status=?,updated_at=?,completed_at=?,"
                f"failure_code=?,{seal_time}=?,{seal_column}=?,terminal_tombstone_digest=? "
                "WHERE execution_run_id=? AND status=?",
                (
                    terminal_status,
                    now,
                    now,
                    failure_code,
                    now,
                    seal_digest,
                    tombstone_digest,
                    execution_run_id,
                    expected_status,
                ),
            )
            if int(cur.rowcount or 0) != 1:
                raise RuntimeError("invalid terminal seal transition")
            self._audit_writer(
                execution_run_id,
                "terminal-seal-committed",
                result=terminal_status,
                error_code=failure_code,
                correlation_id=tombstone_digest,
            )
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    def commit_recovered_terminal_state(
        self,
        *,
        workspace_id: str,
        poison_owner: str,
        **kwargs: Any,
    ) -> None:
        execution_run_id = kwargs["execution_run_id"]
        now = time.time()
        rollback = bool(kwargs["rollback"])
        seal_time = "rollback_sealed_at" if rollback else "recovery_sealed_at"
        seal_column = "rollback_seal_digest" if rollback else "recovery_seal_digest"
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            proof = (
                self._read_model.get_rollback_final_attestation(execution_run_id)
                if rollback
                else self._read_model.get_final_mutation_attestation(execution_run_id)
            )
            if proof is None or proof.attestation_digest != kwargs["attestation_digest"]:
                raise RuntimeError("recovered terminal attestation mismatch")
            cur = self._conn.execute(
                f"UPDATE plan_execution_runs SET status=?,updated_at=?,completed_at=?,"
                f"failure_code=?,{seal_time}=?,{seal_column}=?,terminal_tombstone_digest=? "
                "WHERE execution_run_id=? AND status=?",
                (
                    kwargs["terminal_status"],
                    now,
                    now,
                    kwargs.get("failure_code", ""),
                    now,
                    kwargs["seal_digest"],
                    kwargs["tombstone_digest"],
                    execution_run_id,
                    kwargs["expected_status"],
                ),
            )
            if int(cur.rowcount or 0) != 1:
                raise RuntimeError("invalid recovered terminal transition")
            self._conn.execute(
                "DELETE FROM workspace_mutation_poison_scopes "
                "WHERE workspace_id=? AND poison_owner=?",
                (workspace_id, poison_owner),
            )
            self._audit_writer(
                execution_run_id,
                "recovered-terminal-committed",
                result=kwargs["terminal_status"],
                correlation_id=kwargs["tombstone_digest"],
            )
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    def commit_recovered_no_mutation(
        self,
        *,
        execution_run_id: str,
        workspace_id: str,
        poison_owner: str,
        expected_status: str,
        terminal_status: str,
        baseline_digest: str,
        failure_code: str = "no-mutation-crash",
    ) -> None:
        """Atomically terminalize a proven zero-journal startup crash."""
        now = time.time()
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            proof = self._read_model.get_initial_workspace_attestation(execution_run_id)
            run_digest = self._conn.execute(
                "SELECT initial_attestation_digest FROM plan_execution_runs "
                "WHERE execution_run_id=?",
                (execution_run_id,),
            ).fetchone()
            if (
                proof is None
                or proof.attestation_digest != baseline_digest
                or run_digest is None
                or run_digest["initial_attestation_digest"] != baseline_digest
            ):
                raise RuntimeError("zero-journal baseline mismatch")
            count = self._conn.execute(
                "SELECT COUNT(e.event_id) AS event_count,r.journaled_edit_count "
                "FROM plan_execution_runs r LEFT JOIN plan_execution_edit_events e "
                "ON e.execution_run_id=r.execution_run_id "
                "WHERE r.execution_run_id=? GROUP BY r.execution_run_id",
                (execution_run_id,),
            ).fetchone()
            if count is None or int(count["event_count"]) != 0 or int(
                count["journaled_edit_count"]
            ) != 0:
                raise RuntimeError("zero-journal recovery found edit events")
            cur = self._conn.execute(
                "UPDATE plan_execution_runs SET status=?,updated_at=?,completed_at=?,"
                "failure_code=? WHERE execution_run_id=? AND status=?",
                (
                    terminal_status,
                    now,
                    now,
                    failure_code,
                    execution_run_id,
                    expected_status,
                ),
            )
            if int(cur.rowcount or 0) != 1:
                raise RuntimeError("invalid zero-journal terminal transition")
            self._audit_writer(
                execution_run_id,
                "recovered-no-mutation-committed",
                result=terminal_status,
                error_code=failure_code,
                correlation_id=baseline_digest,
            )
            self._conn.execute(
                "DELETE FROM workspace_mutation_poison_scopes "
                "WHERE workspace_id=? AND poison_owner=?",
                (workspace_id, poison_owner),
            )
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    def _insert_execution_audit(
        self,
        execution_run_id: str,
        event_type: str,
        *,
        operation: str = "",
        path: str = "",
        before_hash: str = "",
        after_hash: str = "",
        result: str,
        error_code: str = "",
        correlation_id: str,
    ) -> None:
        self._conn.execute(
            "INSERT INTO plan_execution_audit_events "
            "(audit_id,execution_run_id,event_type,operation,path,before_hash,"
            "after_hash,result,error_code,correlation_id,created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                uuid.uuid4().hex,
                execution_run_id,
                event_type,
                operation,
                path,
                before_hash,
                after_hash,
                result,
                error_code,
                correlation_id,
                time.time(),
            ),
        )
