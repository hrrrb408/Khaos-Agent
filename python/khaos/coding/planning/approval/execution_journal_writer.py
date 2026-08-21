"""Transactional writer for durable planned-execution edit journals.

The edit journal is a separate state machine from the approval ledger and from
the execution-run terminal proof writer.  ``PlanExecutionJournalWriter`` owns
the journal row, phase CAS, rollback identity evidence, and directory-sync
proof transactions.  It receives an already-open connection and never owns
its lifecycle or any approval authority.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import time
import uuid
from collections.abc import Callable


class PlanExecutionJournalWriter:
    """Own atomic edit-journal and rollback-evidence writes."""

    def __init__(
        self,
        conn: sqlite3.Connection,
        audit_writer: Callable[..., None] | None = None,
    ) -> None:
        self._conn = conn
        self._audit_writer = audit_writer or self._insert_execution_audit

    def insert_edit_event(
        self,
        *,
        event_id: str,
        execution_run_id: str,
        edit_id: str,
        ordinal: int,
        operation: str,
        path: str,
        destination_path: str | None,
        before_hash: str | None,
        before_mode: int | None,
        recovery_artifact: str | None,
        planned_after_hash: str = "",
        planned_after_mode: int | None = None,
    ) -> None:
        now = time.time()
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            self._conn.execute(
                "INSERT INTO plan_execution_edit_events "
                "(event_id,execution_run_id,edit_id,ordinal,operation,path,"
                "destination_path,before_hash,after_hash,before_mode,after_mode,status,recovery_artifact,"
                "created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,'journaled',?,?,?)",
                (
                    event_id,
                    execution_run_id,
                    edit_id,
                    ordinal,
                    operation,
                    path,
                    destination_path,
                    before_hash,
                    planned_after_hash,
                    before_mode,
                    planned_after_mode,
                    recovery_artifact,
                    now,
                    now,
                ),
            )
            cur = self._conn.execute(
                "UPDATE plan_execution_runs SET journaled_edit_count="
                "journaled_edit_count+1 WHERE execution_run_id=? AND status='mutating'",
                (execution_run_id,),
            )
            if int(cur.rowcount or 0) != 1:
                raise RuntimeError("run cannot accept journal event")
            self._audit_writer(
                execution_run_id,
                "edit-journaled",
                operation=operation,
                path=path,
                before_hash=before_hash or "",
                result="journaled",
                correlation_id=edit_id,
            )
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    def transition_edit_event(
        self,
        execution_run_id: str,
        edit_id: str,
        *,
        expected_phase: str,
        target_phase: str,
        after_hash: str | None = None,
        after_mode: int | None = None,
        error_code: str = "",
        applied_identity_digest: str | None = None,
        applied_parent_identity_digest: str | None = None,
        applied_destination_identity_digest: str | None = None,
    ) -> None:
        """Advance one edit phase using a transactionally checked CAS."""
        from khaos.coding.planning.execution_models import DurableEditPhase

        transitions = {
            DurableEditPhase.JOURNALED.value: frozenset(
                {
                    DurableEditPhase.MUTATION_STARTED.value,
                    DurableEditPhase.ROLLED_BACK.value,
                }
            ),
            DurableEditPhase.MUTATION_STARTED.value: frozenset(
                {
                    DurableEditPhase.FILESYSTEM_APPLIED.value,
                    DurableEditPhase.ROLLED_BACK.value,
                }
            ),
            DurableEditPhase.FILESYSTEM_APPLIED.value: frozenset(
                {
                    DurableEditPhase.DIRECTORY_SYNCED.value,
                    DurableEditPhase.ROLLBACK_STARTED.value,
                }
            ),
            DurableEditPhase.DIRECTORY_SYNCED.value: frozenset(
                {
                    DurableEditPhase.APPLIED.value,
                    DurableEditPhase.ROLLBACK_STARTED.value,
                }
            ),
            DurableEditPhase.APPLIED.value: frozenset(
                {DurableEditPhase.ROLLBACK_STARTED.value}
            ),
            DurableEditPhase.ROLLBACK_STARTED.value: frozenset(),
            DurableEditPhase.ROLLBACK_FILESYSTEM_APPLIED.value: frozenset(),
            DurableEditPhase.ROLLBACK_DIRECTORY_SYNCED.value: frozenset(
                {DurableEditPhase.ROLLED_BACK.value}
            ),
        }
        if target_phase != expected_phase and target_phase not in transitions.get(
            expected_phase, frozenset()
        ):
            raise RuntimeError("invalid execution edit phase transition")
        now = time.time()
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            row = self._conn.execute(
                "SELECT e.operation,e.path,e.before_hash,e.after_hash,e.after_mode,"
                "e.status,e.phase_version,e.error_code,"
                "e.applied_identity_digest,e.applied_parent_identity_digest,"
                "e.applied_destination_identity_digest,e.rollback_identity_digest,"
                "e.rollback_parent_identity_digest,"
                "e.rollback_destination_parent_identity_digest,"
                "e.rollback_sync_mask,e.rollback_directory_sync_digest,"
                "e.rollback_synced_at,e.identity_version,r.status AS run_status "
                "FROM plan_execution_edit_events e JOIN plan_execution_runs r "
                "ON r.execution_run_id=e.execution_run_id "
                "WHERE e.execution_run_id=? AND e.edit_id=?",
                (execution_run_id, edit_id),
            ).fetchone()
            if row is None:
                raise RuntimeError("execution edit event not found")
            if row["status"] != expected_phase:
                raise RuntimeError("execution edit phase CAS conflict")
            stored_after_hash = row["after_hash"] if after_hash is None else after_hash
            stored_after_mode = row["after_mode"] if after_mode is None else after_mode
            stored_identity = (
                row["applied_identity_digest"]
                if applied_identity_digest is None
                else applied_identity_digest
            )
            stored_parent_identity = (
                row["applied_parent_identity_digest"]
                if applied_parent_identity_digest is None
                else applied_parent_identity_digest
            )
            stored_destination_identity = (
                row["applied_destination_identity_digest"]
                if applied_destination_identity_digest is None
                else applied_destination_identity_digest
            )
            if target_phase == expected_phase:
                if (
                    stored_after_hash != row["after_hash"]
                    or stored_after_mode != row["after_mode"]
                    or error_code != str(row["error_code"] or "")
                    or stored_identity != row["applied_identity_digest"]
                    or stored_parent_identity != row["applied_parent_identity_digest"]
                    or stored_destination_identity
                    != row["applied_destination_identity_digest"]
                ):
                    raise RuntimeError("idempotent edit phase retry changed state")
                self._conn.commit()
                return
            if row["status"] in {
                DurableEditPhase.APPLIED.value,
                DurableEditPhase.ROLLBACK_STARTED.value,
                DurableEditPhase.ROLLBACK_FILESYSTEM_APPLIED.value,
                DurableEditPhase.ROLLBACK_DIRECTORY_SYNCED.value,
                DurableEditPhase.ROLLED_BACK.value,
            } and (
                stored_after_hash != row["after_hash"]
                or stored_after_mode != row["after_mode"]
            ):
                raise RuntimeError("sealed edit after state cannot change")
            if target_phase in {
                DurableEditPhase.MUTATION_STARTED.value,
                DurableEditPhase.FILESYSTEM_APPLIED.value,
                DurableEditPhase.DIRECTORY_SYNCED.value,
                DurableEditPhase.APPLIED.value,
            } and row["run_status"] != "mutating":
                raise RuntimeError("forward edit phase requires mutating run")
            if target_phase in {
                DurableEditPhase.ROLLBACK_STARTED.value,
                DurableEditPhase.ROLLBACK_FILESYSTEM_APPLIED.value,
                DurableEditPhase.ROLLBACK_DIRECTORY_SYNCED.value,
                DurableEditPhase.ROLLED_BACK.value,
            } and row["run_status"] not in {"rolling-back", "rollback-sealing"}:
                raise RuntimeError("rollback phase requires rollback run")
            if target_phase == DurableEditPhase.FILESYSTEM_APPLIED.value:
                if not stored_parent_identity:
                    raise RuntimeError("filesystem identity evidence missing")
                if row["operation"] != "delete" and not stored_identity:
                    raise RuntimeError("applied object identity evidence missing")
                if row["operation"] == "rename" and not stored_destination_identity:
                    raise RuntimeError("rename destination identity evidence missing")
            if (
                target_phase == DurableEditPhase.ROLLED_BACK.value
                and expected_phase == DurableEditPhase.ROLLBACK_DIRECTORY_SYNCED.value
                and (
                    int(row["identity_version"]) != 3
                    or not row["rollback_identity_digest"]
                    or not row["rollback_parent_identity_digest"]
                    or int(row["rollback_sync_mask"]) not in {1, 3}
                    or not row["rollback_directory_sync_digest"]
                    or row["rollback_synced_at"] is None
                )
            ):
                raise RuntimeError("rollback directory sync evidence missing")
            next_version = int(row["phase_version"]) + (target_phase != expected_phase)
            next_identity_version = int(row["identity_version"])
            if target_phase == DurableEditPhase.FILESYSTEM_APPLIED.value:
                if next_identity_version not in {0, 1}:
                    raise RuntimeError("applied identity version conflict")
                next_identity_version = 1
            cur = self._conn.execute(
                "UPDATE plan_execution_edit_events SET status=?,after_hash=?,"
                "after_mode=?,error_code=?,updated_at=?,phase_version=?,"
                "applied_identity_digest=?,applied_parent_identity_digest=?,"
                "applied_destination_identity_digest=?,identity_version=? "
                "WHERE execution_run_id=? AND edit_id=? AND status=? AND phase_version=?",
                (
                    target_phase,
                    stored_after_hash,
                    stored_after_mode,
                    error_code,
                    now,
                    next_version,
                    stored_identity,
                    stored_parent_identity,
                    stored_destination_identity,
                    next_identity_version,
                    execution_run_id,
                    edit_id,
                    expected_phase,
                    int(row["phase_version"]),
                ),
            )
            if int(cur.rowcount or 0) != 1:
                raise RuntimeError("execution edit phase CAS conflict")
            self._audit_writer(
                execution_run_id,
                "edit-transition",
                operation=row["operation"],
                path=row["path"],
                before_hash=row["before_hash"] or "",
                after_hash=stored_after_hash or "",
                result=target_phase,
                error_code=error_code,
                correlation_id=edit_id,
            )
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    def record_rollback_filesystem_applied(
        self,
        execution_run_id: str,
        edit_id: str,
        *,
        rollback_identity_digest: str,
        rollback_parent_identity_digest: str,
        rollback_destination_parent_identity_digest: str,
        rollback_sync_mask: int,
        error_code: str,
        expected_phase: str = "rollback-started",
    ) -> None:
        """Persist rollback syscall ownership before any directory fsync."""
        if not rollback_identity_digest or not rollback_parent_identity_digest:
            raise RuntimeError("rollback identity evidence missing")
        if rollback_sync_mask not in {1, 3}:
            raise RuntimeError("rollback sync mask invalid")
        now = time.time()
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            row = self._conn.execute(
                "SELECT e.operation,e.path,e.status,e.error_code,"
                "e.phase_version,e.rollback_identity_digest,"
                "e.rollback_parent_identity_digest,"
                "e.rollback_destination_parent_identity_digest,"
                "e.rollback_sync_mask,e.rollback_directory_sync_digest,"
                "e.identity_version,r.status AS run_status "
                "FROM plan_execution_edit_events e JOIN plan_execution_runs r "
                "ON r.execution_run_id=e.execution_run_id "
                "WHERE e.execution_run_id=? AND e.edit_id=?",
                (execution_run_id, edit_id),
            ).fetchone()
            if row is None:
                raise RuntimeError("execution edit event not found")
            if row["run_status"] not in {"rolling-back", "rollback-sealing"}:
                raise RuntimeError("rollback identity requires rollback run")
            if row["operation"] != "rename" and (
                rollback_sync_mask != 1
                or rollback_destination_parent_identity_digest
            ):
                raise RuntimeError("non-rename rollback sync scope invalid")
            if row["operation"] == "rename":
                if not rollback_destination_parent_identity_digest:
                    raise RuntimeError("rename rollback parent identity missing")
                if rollback_sync_mask not in {1, 3}:
                    raise RuntimeError("rename rollback sync mask invalid")
            existing = str(row["rollback_identity_digest"] or "")
            existing_error = str(row["error_code"] or "")
            if row["status"] == "rollback-filesystem-applied":
                if (
                    existing != rollback_identity_digest
                    or str(row["rollback_parent_identity_digest"] or "")
                    != rollback_parent_identity_digest
                    or str(row["rollback_destination_parent_identity_digest"] or "")
                    != rollback_destination_parent_identity_digest
                    or int(row["rollback_sync_mask"]) != rollback_sync_mask
                    or existing_error != error_code
                    or int(row["identity_version"]) != 2
                    or row["rollback_directory_sync_digest"]
                ):
                    raise RuntimeError("rollback filesystem identity CAS conflict")
                self._conn.commit()
                return
            if row["status"] != expected_phase:
                raise RuntimeError("rollback filesystem phase CAS conflict")
            if int(row["identity_version"]) not in {1, 2}:
                raise RuntimeError("applied identity evidence missing")
            if existing and existing != rollback_identity_digest:
                raise RuntimeError("rollback identity CAS conflict")
            if existing_error and existing_error != error_code:
                raise RuntimeError("rollback reason CAS conflict")
            cur = self._conn.execute(
                "UPDATE plan_execution_edit_events SET status='rollback-filesystem-applied',"
                "rollback_identity_digest=?,rollback_parent_identity_digest=?,"
                "rollback_destination_parent_identity_digest=?,rollback_sync_mask=?,"
                "identity_version=2,error_code=?,updated_at=?,phase_version=phase_version+1 "
                "WHERE execution_run_id=? AND edit_id=? AND status=? "
                "AND phase_version=? AND identity_version IN (1,2)",
                (
                    rollback_identity_digest,
                    rollback_parent_identity_digest,
                    rollback_destination_parent_identity_digest,
                    rollback_sync_mask,
                    error_code,
                    now,
                    execution_run_id,
                    edit_id,
                    expected_phase,
                    int(row["phase_version"]),
                ),
            )
            if int(cur.rowcount or 0) != 1:
                raise RuntimeError("rollback filesystem phase CAS conflict")
            self._audit_writer(
                execution_run_id,
                "rollback-filesystem-applied",
                operation=row["operation"],
                path=row["path"],
                result="rollback-filesystem-applied",
                error_code=error_code,
                correlation_id=edit_id,
            )
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    @staticmethod
    def _rollback_directory_sync_digest(
        *,
        execution_run_id: str,
        edit_id: str,
        parent_identity_digest: str,
        destination_parent_identity_digest: str,
        sync_mask: int,
    ) -> str:
        payload = {
            "execution_run_id": execution_run_id,
            "edit_id": edit_id,
            "parent_identity_digest": parent_identity_digest,
            "destination_parent_identity_digest": destination_parent_identity_digest,
            "sync_mask": sync_mask,
            "phase": "rollback-directory-synced",
        }
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()

    def record_rollback_directory_synced(
        self, execution_run_id: str, edit_id: str, *, error_code: str
    ) -> str:
        """Commit proof that every persisted rollback parent was fsynced."""
        now = time.time()
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            row = self._conn.execute(
                "SELECT e.operation,e.path,e.status,e.phase_version,e.error_code,"
                "e.rollback_identity_digest,"
                "e.rollback_parent_identity_digest,"
                "e.rollback_destination_parent_identity_digest,"
                "e.rollback_sync_mask,e.rollback_directory_sync_digest,"
                "e.rollback_synced_at,e.identity_version,r.status AS run_status "
                "FROM plan_execution_edit_events e JOIN plan_execution_runs r "
                "ON r.execution_run_id=e.execution_run_id "
                "WHERE e.execution_run_id=? AND e.edit_id=?",
                (execution_run_id, edit_id),
            ).fetchone()
            if row is None:
                raise RuntimeError("execution edit event not found")
            if row["run_status"] not in {"rolling-back", "rollback-sealing"}:
                raise RuntimeError("rollback directory sync requires rollback run")
            if str(row["error_code"] or "") != error_code:
                raise RuntimeError("rollback directory sync reason conflict")
            digest = self._rollback_directory_sync_digest(
                execution_run_id=execution_run_id,
                edit_id=edit_id,
                parent_identity_digest=str(
                    row["rollback_parent_identity_digest"] or ""
                ),
                destination_parent_identity_digest=str(
                    row["rollback_destination_parent_identity_digest"] or ""
                ),
                sync_mask=int(row["rollback_sync_mask"]),
            )
            if row["status"] == "rollback-directory-synced":
                if (
                    str(row["rollback_directory_sync_digest"] or "") != digest
                    or row["rollback_synced_at"] is None
                    or int(row["identity_version"]) != 3
                ):
                    raise RuntimeError("rollback directory sync CAS conflict")
                self._conn.commit()
                return digest
            if (
                row["status"] != "rollback-filesystem-applied"
                or int(row["identity_version"]) != 2
                or not row["rollback_identity_digest"]
                or not row["rollback_parent_identity_digest"]
                or int(row["rollback_sync_mask"]) not in {1, 3}
                or (
                    int(row["rollback_sync_mask"]) == 3
                    and not row["rollback_destination_parent_identity_digest"]
                )
            ):
                raise RuntimeError("rollback filesystem evidence missing")
            cur = self._conn.execute(
                "UPDATE plan_execution_edit_events "
                "SET status='rollback-directory-synced',"
                "rollback_directory_sync_digest=?,rollback_synced_at=?,"
                "identity_version=3,updated_at=?,phase_version=phase_version+1 "
                "WHERE execution_run_id=? AND edit_id=? "
                "AND status='rollback-filesystem-applied' AND phase_version=? "
                "AND identity_version=2 AND rollback_directory_sync_digest=''",
                (digest, now, now, execution_run_id, edit_id, int(row["phase_version"])),
            )
            if int(cur.rowcount or 0) != 1:
                raise RuntimeError("rollback directory sync CAS conflict")
            self._audit_writer(
                execution_run_id,
                "rollback-directory-synced",
                operation=row["operation"],
                path=row["path"],
                result="rollback-directory-synced",
                error_code=error_code,
                correlation_id=edit_id,
            )
            self._conn.commit()
            return digest
        except Exception:
            self._conn.rollback()
            raise

    def update_edit_event(
        self,
        execution_run_id: str,
        edit_id: str,
        *,
        status: str,
        after_hash: str | None = None,
        after_mode: int | None = None,
        error_code: str = "",
        applied_identity_digest: str | None = None,
        applied_parent_identity_digest: str | None = None,
        applied_destination_identity_digest: str | None = None,
    ) -> None:
        """Compatibility facade; arbitrary phase writes are not accepted."""
        row = self._conn.execute(
            "SELECT status FROM plan_execution_edit_events "
            "WHERE execution_run_id=? AND edit_id=?",
            (execution_run_id, edit_id),
        ).fetchone()
        if row is None:
            raise RuntimeError("execution edit event not found")
        self.transition_edit_event(
            execution_run_id,
            edit_id,
            expected_phase=str(row["status"]),
            target_phase=status,
            after_hash=after_hash,
            after_mode=after_mode,
            error_code=error_code,
            applied_identity_digest=applied_identity_digest,
            applied_parent_identity_digest=applied_parent_identity_digest,
            applied_destination_identity_digest=applied_destination_identity_digest,
        )

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
