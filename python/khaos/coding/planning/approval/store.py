"""Persistent store for plan approval state with atomic CAS transitions.

Backed by synchronous ``sqlite3`` (mirroring
``khaos.coding.intelligence.resolution.persistence``) so that every state
transition can be wrapped in a single ``BEGIN IMMEDIATE`` transaction — the
strongest concurrency primitive available without adding a new dependency.

The schema is appended idempotently to the project-wide ``schema.sql`` and is
also created here on first use (``ensure_schema``), so the store works against
both a fresh in-memory database and an existing project database.
"""
from __future__ import annotations

import json
import sqlite3
import time
import uuid
from enum import Enum
from pathlib import Path
from typing import Any

from khaos.coding.planning.approval.models import (
    ALLOWED_APPROVAL_TRANSITIONS,
    AuthorizationStatus,
    PlanApprovalAuditEvent,
    PlanApprovalDecision,
    PlanApprovalRequest,
    PlanApprovalStatus,
    PlanExecutionAuthorization,
    generate_nonce,
    hash_nonce,
)


# ---------------------------------------------------------------------------
# Schema (also mirrored in khaos/db/schema.sql)
# ---------------------------------------------------------------------------

APPROVAL_SCHEMA = """
CREATE TABLE IF NOT EXISTS plan_approval_requests (
    approval_request_id   TEXT PRIMARY KEY,
    plan_id               TEXT NOT NULL,
    plan_content_hash     TEXT NOT NULL,
    repository_id         TEXT NOT NULL,
    task_id               TEXT NOT NULL,
    workspace_id          TEXT NOT NULL,
    base_sha              TEXT NOT NULL,
    repository_generation INTEGER NOT NULL,
    risk_level            TEXT NOT NULL,
    requested_operations  TEXT NOT NULL DEFAULT '[]',
    affected_files        TEXT NOT NULL DEFAULT '[]',
    affected_symbols      TEXT NOT NULL DEFAULT '[]',
    verification_digest   TEXT NOT NULL,
    binding_digest        TEXT NOT NULL,
    requested_at          REAL NOT NULL,
    expires_at            REAL NOT NULL,
    status                TEXT NOT NULL,
    broker_request_id     TEXT NOT NULL,
    reason                TEXT NOT NULL DEFAULT '',
    metadata              TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_plan_approval_requests_plan
    ON plan_approval_requests(plan_id, plan_content_hash);
CREATE INDEX IF NOT EXISTS idx_plan_approval_requests_repo
    ON plan_approval_requests(repository_id, task_id, workspace_id);
CREATE INDEX IF NOT EXISTS idx_plan_approval_requests_broker
    ON plan_approval_requests(broker_request_id);
CREATE INDEX IF NOT EXISTS idx_plan_approval_requests_status
    ON plan_approval_requests(status, expires_at);

CREATE TABLE IF NOT EXISTS plan_approval_decisions (
    decision_id            INTEGER PRIMARY KEY AUTOINCREMENT,
    approval_request_id    TEXT NOT NULL,
    decision               TEXT NOT NULL,
    actor_id               TEXT NOT NULL,
    actor_type             TEXT NOT NULL,
    decided_at             REAL NOT NULL,
    reason                 TEXT NOT NULL DEFAULT '',
    authenticated_context  TEXT NOT NULL DEFAULT '{}',
    metadata               TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_plan_approval_decisions_request
    ON plan_approval_decisions(approval_request_id, decided_at);

CREATE TABLE IF NOT EXISTS plan_execution_authorizations (
    authorization_id     TEXT PRIMARY KEY,
    approval_request_id  TEXT NOT NULL,
    plan_id              TEXT NOT NULL,
    plan_content_hash    TEXT NOT NULL,
    repository_id        TEXT NOT NULL,
    task_id              TEXT NOT NULL,
    workspace_id         TEXT NOT NULL,
    base_sha             TEXT NOT NULL,
    repository_generation INTEGER NOT NULL,
    issued_at            REAL NOT NULL,
    expires_at           REAL NOT NULL,
    nonce_hash           TEXT NOT NULL UNIQUE,
    binding_digest       TEXT NOT NULL,
    status               TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_plan_execution_authorizations_plan
    ON plan_execution_authorizations(plan_id, approval_request_id);
CREATE INDEX IF NOT EXISTS idx_plan_execution_authorizations_scope
    ON plan_execution_authorizations(repository_id, task_id, workspace_id);
CREATE INDEX IF NOT EXISTS idx_plan_execution_authorizations_status
    ON plan_execution_authorizations(status, expires_at);

CREATE TABLE IF NOT EXISTS plan_approval_audit_events (
    event_id              TEXT PRIMARY KEY,
    event_type            TEXT NOT NULL,
    approval_request_id   TEXT NOT NULL,
    plan_id               TEXT NOT NULL,
    previous_status       TEXT NOT NULL,
    new_status            TEXT NOT NULL,
    actor_id              TEXT NOT NULL,
    actor_type            TEXT NOT NULL,
    authenticated_source  TEXT NOT NULL,
    timestamp             REAL NOT NULL,
    reason_code           TEXT NOT NULL,
    task_id               TEXT NOT NULL,
    workspace_id          TEXT NOT NULL,
    repository_id         TEXT NOT NULL,
    correlation_id        TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_plan_approval_audit_events_request
    ON plan_approval_audit_events(approval_request_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_plan_approval_audit_events_plan
    ON plan_approval_audit_events(plan_id, timestamp);
"""


class ApprovalTransitionResult(str, Enum):
    """Outcome of an atomic CAS approval transition."""

    UPDATED = "updated"
    UNCHANGED = "unchanged"  # idempotent same-decision
    INVALID_TRANSITION = "invalid_transition"
    CONFLICT = "conflict"  # opposite decision already applied
    NOT_FOUND = "not_found"
    STALE = "stale"  # binding digest drifted


class PlanApprovalStore:
    """Atomic, durable store for plan approval + authorization state.

    Thread-safe by virtue of SQLite's own ``BEGIN IMMEDIATE`` serialization
    (no Python-level lock is needed). Every mutating method opens a
    transaction, performs a Compare-And-Swap on the persisted status, and
    either commits or rolls back atomically.
    """

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn
        self._conn.row_factory = sqlite3.Row
        self.ensure_schema()

    # ------------------------------------------------------------------
    # Schema bootstrap
    # ------------------------------------------------------------------

    def ensure_schema(self) -> None:
        """Create the approval tables if missing. Idempotent."""
        self._conn.executescript(APPROVAL_SCHEMA)
        self._conn.commit()

    # ------------------------------------------------------------------
    # Request persistence
    # ------------------------------------------------------------------

    def insert_request(self, request: PlanApprovalRequest) -> None:
        """Insert a brand new approval request (must not already exist)."""
        self._conn.execute(
            """
            INSERT INTO plan_approval_requests (
                approval_request_id, plan_id, plan_content_hash, repository_id,
                task_id, workspace_id, base_sha, repository_generation,
                risk_level, requested_operations, affected_files, affected_symbols,
                verification_digest, binding_digest, requested_at, expires_at,
                status, broker_request_id, reason, metadata
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                request.approval_request_id,
                request.plan_id,
                request.plan_content_hash,
                request.repository_id,
                request.task_id,
                request.workspace_id,
                request.base_sha,
                int(request.repository_generation),
                request.risk_level,
                json.dumps(list(request.requested_operations)),
                json.dumps(list(request.affected_files)),
                json.dumps(list(request.affected_symbols)),
                request.verification_digest,
                request.binding_digest,
                float(request.requested_at),
                float(request.expires_at),
                request.status.value,
                request.broker_request_id,
                request.reason,
                json.dumps(request.metadata, default=str, sort_keys=True),
            ),
        )
        self._conn.commit()

    def get_request(self, approval_request_id: str) -> PlanApprovalRequest | None:
        row = self._conn.execute(
            "SELECT * FROM plan_approval_requests WHERE approval_request_id = ?",
            (approval_request_id,),
        ).fetchone()
        if row is None:
            return None
        return self._row_to_request(row)

    def get_request_by_broker(self, broker_request_id: str) -> PlanApprovalRequest | None:
        row = self._conn.execute(
            "SELECT * FROM plan_approval_requests WHERE broker_request_id = ?",
            (broker_request_id,),
        ).fetchone()
        if row is None:
            return None
        return self._row_to_request(row)

    @staticmethod
    def _row_to_request(row: sqlite3.Row) -> PlanApprovalRequest:
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
        )

    # ------------------------------------------------------------------
    # Atomic status CAS
    # ------------------------------------------------------------------

    def compare_and_set_status(
        self,
        approval_request_id: str,
        *,
        expected: set[PlanApprovalStatus],
        target: PlanApprovalStatus,
        current_binding_digest: str | None,
    ) -> ApprovalTransitionResult:
        """Atomically transition a request status under a CAS guard.

        Returns:
            * ``UPDATED`` — transition applied.
            * ``UNCHANGED`` — already in ``target`` (idempotent).
            * ``CONFLICT`` — in a *different* non-target, non-expected state
              (e.g. approve-after-reject).
            * ``STALE`` — ``current_binding_digest`` was supplied and does not
              match the persisted binding (plan drifted).
            * ``INVALID_TRANSITION`` — target not reachable from current status
              per :data:`ALLOWED_APPROVAL_TRANSITIONS`.
            * ``NOT_FOUND`` — request does not exist.

        The decision record and audit event are written in the SAME
        transaction so they can never diverge from the status change.
        """
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            row = self._conn.execute(
                "SELECT status, binding_digest FROM plan_approval_requests "
                "WHERE approval_request_id = ?",
                (approval_request_id,),
            ).fetchone()
            if row is None:
                self._conn.rollback()
                return ApprovalTransitionResult.NOT_FOUND

            current = PlanApprovalStatus(row["status"])

            # Idempotent: already in target.
            if current == target:
                self._conn.rollback()
                return ApprovalTransitionResult.UNCHANGED

            # Binding drift check (only when the caller supplied a digest to
            # compare against — approve callbacks always do).
            if current_binding_digest is not None and row["binding_digest"] != current_binding_digest:
                self._conn.execute(
                    "UPDATE plan_approval_requests SET status = ? WHERE approval_request_id = ?",
                    (PlanApprovalStatus.STALE.value, approval_request_id),
                )
                self._conn.commit()
                return ApprovalTransitionResult.STALE

            allowed = ALLOWED_APPROVAL_TRANSITIONS.get(current, frozenset())
            if target not in allowed:
                # Opposite decision or recovery from a terminal state.
                self._conn.rollback()
                return ApprovalTransitionResult.CONFLICT

            if current not in expected:
                # Caller's expectation wasn't met even if the transition is
                # technically allowed — treat as conflict for safety.
                self._conn.rollback()
                return ApprovalTransitionResult.CONFLICT

            self._conn.execute(
                "UPDATE plan_approval_requests SET status = ? WHERE approval_request_id = ?",
                (target.value, approval_request_id),
            )
            self._conn.commit()
            return ApprovalTransitionResult.UPDATED
        except Exception:
            self._conn.rollback()
            raise

    def mark_expired(self, approval_request_id: str) -> ApprovalTransitionResult:
        """Move a request to ``expired`` if its TTL has elapsed."""
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            row = self._conn.execute(
                "SELECT status, expires_at FROM plan_approval_requests WHERE approval_request_id = ?",
                (approval_request_id,),
            ).fetchone()
            if row is None:
                self._conn.rollback()
                return ApprovalTransitionResult.NOT_FOUND
            current = PlanApprovalStatus(row["status"])
            if current.is_terminal and current != PlanApprovalStatus.EXPIRED:
                self._conn.rollback()
                return ApprovalTransitionResult.UNCHANGED
            if time.time() < float(row["expires_at"]):
                self._conn.rollback()
                return ApprovalTransitionResult.UNCHANGED
            allowed = ALLOWED_APPROVAL_TRANSITIONS.get(current, frozenset())
            if PlanApprovalStatus.EXPIRED not in allowed:
                self._conn.rollback()
                return ApprovalTransitionResult.INVALID_TRANSITION
            self._conn.execute(
                "UPDATE plan_approval_requests SET status = ? WHERE approval_request_id = ?",
                (PlanApprovalStatus.EXPIRED.value, approval_request_id),
            )
            self._conn.commit()
            return ApprovalTransitionResult.UPDATED
        except Exception:
            self._conn.rollback()
            raise

    # ------------------------------------------------------------------
    # Decisions
    # ------------------------------------------------------------------

    def insert_decision(self, decision: PlanApprovalDecision) -> None:
        self._conn.execute(
            """
            INSERT INTO plan_approval_decisions (
                approval_request_id, decision, actor_id, actor_type, decided_at,
                reason, authenticated_context, metadata
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                decision.approval_request_id,
                decision.decision.value,
                decision.actor_id,
                decision.actor_type,
                float(decision.decided_at),
                decision.reason,
                json.dumps(decision.authenticated_context, default=str, sort_keys=True),
                json.dumps(decision.metadata, default=str, sort_keys=True),
            ),
        )
        self._conn.commit()

    def list_decisions(self, approval_request_id: str) -> list[PlanApprovalDecision]:
        rows = self._conn.execute(
            "SELECT * FROM plan_approval_decisions WHERE approval_request_id = ? "
            "ORDER BY decided_at ASC, decision_id ASC",
            (approval_request_id,),
        ).fetchall()
        return [
            PlanApprovalDecision(
                approval_request_id=r["approval_request_id"],
                decision=PlanApprovalStatus(r["decision"]),
                actor_id=r["actor_id"],
                actor_type=r["actor_type"],
                decided_at=float(r["decided_at"]),
                reason=r["reason"] or "",
                authenticated_context=json.loads(r["authenticated_context"] or "{}"),
                metadata=json.loads(r["metadata"] or "{}"),
            )
            for r in rows
        ]

    # ------------------------------------------------------------------
    # Audit events
    # ------------------------------------------------------------------

    def insert_audit_event(self, event: PlanApprovalAuditEvent) -> None:
        self._conn.execute(
            """
            INSERT INTO plan_approval_audit_events (
                event_id, event_type, approval_request_id, plan_id, previous_status,
                new_status, actor_id, actor_type, authenticated_source, timestamp,
                reason_code, task_id, workspace_id, repository_id, correlation_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.event_id,
                event.event_type,
                event.approval_request_id,
                event.plan_id,
                event.previous_status,
                event.new_status,
                event.actor_id,
                event.actor_type,
                event.authenticated_source,
                float(event.timestamp),
                event.reason_code,
                event.task_id,
                event.workspace_id,
                event.repository_id,
                event.correlation_id,
            ),
        )
        self._conn.commit()

    def list_audit_events(
        self, *, approval_request_id: str | None = None, plan_id: str | None = None
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
                event_id=r["event_id"],
                event_type=r["event_type"],
                approval_request_id=r["approval_request_id"],
                plan_id=r["plan_id"],
                previous_status=r["previous_status"],
                new_status=r["new_status"],
                actor_id=r["actor_id"],
                actor_type=r["actor_type"],
                authenticated_source=r["authenticated_source"],
                timestamp=float(r["timestamp"]),
                reason_code=r["reason_code"],
                task_id=r["task_id"],
                workspace_id=r["workspace_id"],
                repository_id=r["repository_id"],
                correlation_id=r["correlation_id"],
            )
            for r in rows
        ]

    # ------------------------------------------------------------------
    # Execution authorizations
    # ------------------------------------------------------------------

    def insert_authorization(self, auth: PlanExecutionAuthorization) -> None:
        """Persist a freshly-minted authorization (nonce hash only)."""
        self._conn.execute(
            """
            INSERT INTO plan_execution_authorizations (
                authorization_id, approval_request_id, plan_id, plan_content_hash,
                repository_id, task_id, workspace_id, base_sha, repository_generation,
                issued_at, expires_at, nonce_hash, binding_digest, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                auth.authorization_id,
                auth.approval_request_id,
                auth.plan_id,
                auth.plan_content_hash,
                auth.repository_id,
                auth.task_id,
                auth.workspace_id,
                auth.base_sha,
                int(auth.repository_generation),
                float(auth.issued_at),
                float(auth.expires_at),
                auth.nonce_hash,
                auth.binding_digest,
                auth.status.value,
            ),
        )
        self._conn.commit()

    def get_authorization(self, authorization_id: str) -> PlanExecutionAuthorization | None:
        row = self._conn.execute(
            "SELECT * FROM plan_execution_authorizations WHERE authorization_id = ?",
            (authorization_id,),
        ).fetchone()
        if row is None:
            return None
        # NOTE: the plaintext nonce is never persisted; callers that need it
        # must hold the in-memory object returned by the gate.
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
            nonce="",  # plaintext deliberately unavailable after restart
            nonce_hash=row["nonce_hash"],
            status=AuthorizationStatus(row["status"]),
            binding_digest=row["binding_digest"],
        )

    def consume_authorization(
        self,
        authorization_id: str,
        *,
        expected_plan_id: str,
        expected_task_id: str,
        expected_workspace_id: str,
        expected_repository_id: str,
        nonce: str,
    ) -> bool:
        """Atomically consume an authorization exactly once.

        Verifies (all within one ``BEGIN IMMEDIATE``):
        1. The authorization exists and is still ``ACTIVE``.
        2. The bound plan/task/workspace/repository match the caller's claim.
        3. The supplied nonce hashes to the stored ``nonce_hash``.
        4. The authorization has not expired.

        On success the status flips to ``CONSUMED`` and the change is
        committed atomically. Any mismatch rolls back and returns ``False``.
        """
        from khaos.coding.planning.approval.models import verify_nonce

        self._conn.execute("BEGIN IMMEDIATE")
        try:
            row = self._conn.execute(
                "SELECT * FROM plan_execution_authorizations WHERE authorization_id = ?",
                (authorization_id,),
            ).fetchone()
            if row is None:
                self._conn.rollback()
                return False
            if row["status"] != AuthorizationStatus.ACTIVE.value:
                self._conn.rollback()
                return False
            if (
                row["plan_id"] != expected_plan_id
                or row["task_id"] != expected_task_id
                or row["workspace_id"] != expected_workspace_id
                or row["repository_id"] != expected_repository_id
            ):
                self._conn.rollback()
                return False
            if not verify_nonce(nonce, row["nonce_hash"]):
                self._conn.rollback()
                return False
            if time.time() >= float(row["expires_at"]):
                self._conn.execute(
                    "UPDATE plan_execution_authorizations SET status = ? WHERE authorization_id = ?",
                    (AuthorizationStatus.EXPIRED.value, authorization_id),
                )
                self._conn.commit()
                return False
            self._conn.execute(
                "UPDATE plan_execution_authorizations SET status = ? WHERE authorization_id = ?",
                (AuthorizationStatus.CONSUMED.value, authorization_id),
            )
            self._conn.commit()
            return True
        except Exception:
            self._conn.rollback()
            raise

    def revoke_authorization(self, authorization_id: str) -> bool:
        """Externally invalidate an authorization (e.g. on Task cancel)."""
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            row = self._conn.execute(
                "SELECT status FROM plan_execution_authorizations WHERE authorization_id = ?",
                (authorization_id,),
            ).fetchone()
            if row is None:
                self._conn.rollback()
                return False
            if row["status"] != AuthorizationStatus.ACTIVE.value:
                self._conn.rollback()
                return False
            self._conn.execute(
                "UPDATE plan_execution_authorizations SET status = ? WHERE authorization_id = ?",
                (AuthorizationStatus.REVOKED.value, authorization_id),
            )
            self._conn.commit()
            return True
        except Exception:
            self._conn.rollback()
            raise

    def revoke_authorizations_for_request(self, approval_request_id: str) -> int:
        """Revoke every still-active authorization tied to a request."""
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            cur = self._conn.execute(
                "UPDATE plan_execution_authorizations SET status = ? "
                "WHERE approval_request_id = ? AND status = ?",
                (AuthorizationStatus.REVOKED.value, approval_request_id, AuthorizationStatus.ACTIVE.value),
            )
            count = int(cur.rowcount or 0)
            self._conn.commit()
            return count
        except Exception:
            self._conn.rollback()
            raise

    def list_authorizations_for_plan(self, plan_id: str) -> list[PlanExecutionAuthorization]:
        rows = self._conn.execute(
            "SELECT * FROM plan_execution_authorizations WHERE plan_id = ? "
            "ORDER BY issued_at ASC",
            (plan_id,),
        ).fetchall()
        return [
            PlanExecutionAuthorization(
                authorization_id=r["authorization_id"],
                approval_request_id=r["approval_request_id"],
                plan_id=r["plan_id"],
                plan_content_hash=r["plan_content_hash"],
                repository_id=r["repository_id"],
                task_id=r["task_id"],
                workspace_id=r["workspace_id"],
                base_sha=r["base_sha"],
                repository_generation=int(r["repository_generation"]),
                issued_at=float(r["issued_at"]),
                expires_at=float(r["expires_at"]),
                nonce="",
                nonce_hash=r["nonce_hash"],
                status=AuthorizationStatus(r["status"]),
                binding_digest=r["binding_digest"],
            )
            for r in rows
        ]


def new_authorization_id() -> str:
    """Generate a fresh opaque authorization identifier."""
    return f"pax_{uuid.uuid4().hex}"


def new_request_id() -> str:
    """Generate a fresh opaque approval request identifier."""
    return f"par_{uuid.uuid4().hex}"


def new_event_id() -> str:
    return f"pae_{uuid.uuid4().hex}"


def open_store(db_path: str | Path) -> PlanApprovalStore:
    """Open a :class:`PlanApprovalStore` against a file path."""
    conn = sqlite3.connect(str(db_path))
    return PlanApprovalStore(conn)
