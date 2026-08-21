"""Read-only queries for persisted plan approval state.

The read model receives an already-open, already-authorized SQLite connection.
It owns SQL shape and row conversion for approval requests, decisions, audit
events, and execution authorizations, but it never opens or closes a
connection, commits a transaction, or changes persisted state.  Transactional
writers remain in :mod:`khaos.coding.planning.approval.store` until each write
boundary has its own owner and regression contract.
"""
from __future__ import annotations

import json
import sqlite3
from typing import Any

from khaos.coding.planning.approval.models import (
    AuthorizationStatus,
    PlanApprovalAuditEvent,
    PlanApprovalDecision,
    PlanApprovalRequest,
    PlanApprovalStatus,
    PlanExecutionAuthorization,
)


class PlanApprovalReadModel:
    """Read-only SQL facade for plan approval records.

    The caller supplies the connection selected by the owning runtime.  This
    class deliberately has no lifecycle or transaction methods: a read cannot
    accidentally become a second database owner.
    """

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def get_request(self, approval_request_id: str) -> PlanApprovalRequest | None:
        row = self._conn.execute(
            "SELECT * FROM plan_approval_requests WHERE approval_request_id = ?",
            (approval_request_id,),
        ).fetchone()
        return self.row_to_request(row) if row is not None else None

    def get_request_by_broker(self, broker_request_id: str) -> PlanApprovalRequest | None:
        row = self._conn.execute(
            "SELECT * FROM plan_approval_requests WHERE broker_request_id = ?",
            (broker_request_id,),
        ).fetchone()
        return self.row_to_request(row) if row is not None else None

    @staticmethod
    def row_to_request(row: sqlite3.Row) -> PlanApprovalRequest:
        """Convert a persisted request row, tolerating pre-migration rows."""
        keys = set(row.keys())
        approved_plan_id = (
            row["approved_verification_plan_id"]
            if "approved_verification_plan_id" in keys
            else ""
        )
        approved_plan_digest = (
            row["approved_verification_plan_digest"]
            if "approved_verification_plan_digest" in keys
            else ""
        )
        return PlanApprovalRequest(
            approval_request_id=row["approval_request_id"],
            plan_id=row["plan_id"],
            plan_content_hash=row["plan_content_hash"],
            repository_id=row["repository_id"],
            task_id=row["task_id"],
            workspace_id=row["workspace_id"],
            base_sha=row["base_sha"],
            repository_generation=int(row["repository_generation"]),
            risk_level=row["risk_level"],
            requested_operations=tuple(json.loads(row["requested_operations"])),
            affected_files=tuple(json.loads(row["affected_files"])),
            affected_symbols=tuple(json.loads(row["affected_symbols"])),
            verification_digest=row["verification_digest"],
            binding_digest=row["binding_digest"],
            requested_at=float(row["requested_at"]),
            expires_at=float(row["expires_at"]),
            status=PlanApprovalStatus(row["status"]),
            broker_request_id=row["broker_request_id"],
            reason=row["reason"] or "",
            metadata=json.loads(row["metadata"] or "{}"),
            approved_verification_plan_id=approved_plan_id or "",
            approved_verification_plan_digest=approved_plan_digest or "",
        )

    def list_decisions(self, approval_request_id: str) -> list[PlanApprovalDecision]:
        rows = self._conn.execute(
            "SELECT * FROM plan_approval_decisions WHERE approval_request_id = ? "
            "ORDER BY decided_at ASC, decision_id ASC",
            (approval_request_id,),
        ).fetchall()
        return [
            PlanApprovalDecision(
                approval_request_id=row["approval_request_id"],
                decision=PlanApprovalStatus(row["decision"]),
                actor_id=row["actor_id"],
                actor_type=row["actor_type"],
                decided_at=float(row["decided_at"]),
                reason=row["reason"] or "",
                authenticated_context=json.loads(row["authenticated_context"] or "{}"),
                metadata=json.loads(row["metadata"] or "{}"),
            )
            for row in rows
        ]

    def list_audit_events(
        self,
        *,
        approval_request_id: str | None = None,
        plan_id: str | None = None,
    ) -> list[PlanApprovalAuditEvent]:
        clauses: list[str] = []
        params: list[Any] = []
        if approval_request_id is not None:
            clauses.append("approval_request_id = ?")
            params.append(approval_request_id)
        if plan_id is not None:
            clauses.append("plan_id = ?")
            params.append(plan_id)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = self._conn.execute(
            f"SELECT * FROM plan_approval_audit_events {where} "
            "ORDER BY timestamp ASC, event_id ASC",
            params,
        ).fetchall()
        return [
            PlanApprovalAuditEvent(
                event_id=row["event_id"],
                event_type=row["event_type"],
                approval_request_id=row["approval_request_id"],
                plan_id=row["plan_id"],
                previous_status=row["previous_status"],
                new_status=row["new_status"],
                actor_id=row["actor_id"],
                actor_type=row["actor_type"],
                authenticated_source=row["authenticated_source"],
                timestamp=float(row["timestamp"]),
                reason_code=row["reason_code"],
                task_id=row["task_id"],
                workspace_id=row["workspace_id"],
                repository_id=row["repository_id"],
                correlation_id=row["correlation_id"],
            )
            for row in rows
        ]

    def get_authorization(
        self, authorization_id: str
    ) -> PlanExecutionAuthorization | None:
        row = self._conn.execute(
            "SELECT * FROM plan_execution_authorizations WHERE authorization_id = ?",
            (authorization_id,),
        ).fetchone()
        return self.row_to_authorization(row) if row is not None else None

    @staticmethod
    def row_to_authorization(row: sqlite3.Row) -> PlanExecutionAuthorization:
        """Convert a persisted authorization row without restoring its nonce."""
        return PlanExecutionAuthorization(
            authorization_id=row["authorization_id"],
            approval_request_id=row["approval_request_id"],
            plan_id=row["plan_id"],
            plan_content_hash=row["plan_content_hash"],
            repository_id=row["repository_id"],
            task_id=row["task_id"],
            workspace_id=row["workspace_id"],
            base_sha=row["base_sha"],
            repository_generation=int(row["repository_generation"]),
            issued_at=float(row["issued_at"]),
            expires_at=float(row["expires_at"]),
            nonce="",
            nonce_hash=row["nonce_hash"],
            status=AuthorizationStatus(row["status"]),
            binding_digest=row["binding_digest"],
        )

    def list_authorizations_for_plan(
        self, plan_id: str
    ) -> list[PlanExecutionAuthorization]:
        rows = self._conn.execute(
            "SELECT * FROM plan_execution_authorizations WHERE plan_id = ? "
            "ORDER BY issued_at ASC",
            (plan_id,),
        ).fetchall()
        return [self.row_to_authorization(row) for row in rows]

    def list_registering_or_pending(self) -> list[PlanApprovalRequest]:
        """Return requests awaiting broker registration or a decision."""
        rows = self._conn.execute(
            "SELECT * FROM plan_approval_requests WHERE status IN (?, ?) "
            "ORDER BY requested_at ASC",
            (PlanApprovalStatus.REGISTERING.value, PlanApprovalStatus.PENDING.value),
        ).fetchall()
        return [self.row_to_request(row) for row in rows]

    def list_requests_for_task(self, task_id: str) -> list[PlanApprovalRequest]:
        rows = self._conn.execute(
            "SELECT * FROM plan_approval_requests WHERE task_id = ? "
            "ORDER BY requested_at ASC",
            (task_id,),
        ).fetchall()
        return [self.row_to_request(row) for row in rows]

    def find_request_by_plan_binding(
        self, plan_id: str, binding_digest: str
    ) -> PlanApprovalRequest | None:
        row = self._conn.execute(
            "SELECT * FROM plan_approval_requests WHERE plan_id = ? AND binding_digest = ? "
            "ORDER BY requested_at DESC LIMIT 1",
            (plan_id, binding_digest),
        ).fetchone()
        return self.row_to_request(row) if row is not None else None
