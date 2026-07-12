"""Persistent store for plan approval state with atomic CAS transitions.

Backed by synchronous ``sqlite3`` (mirroring
``khaos.coding.intelligence.resolution.persistence``) so that every state
transition can be wrapped in a single ``BEGIN IMMEDIATE`` transaction — the
strongest concurrency primitive available without adding a new dependency.

The schema is appended idempotently to the project-wide ``schema.sql`` and is
also created here on first use (``ensure_schema``), so the store works against
both a fresh in-memory database and an existing project database.

Batch 2.1 hardening:

* :meth:`apply_authenticated_decision` — ONE ``BEGIN IMMEDIATE`` transitions
  the request, writes the decision, writes the audit, updates expiry AND
  consumes the broker receipt. Any step failing rolls the whole thing back.
* :meth:`mint_authorization_if_request_active` — atomic mint that refuses to
  create a second ACTIVE authorization for one request.
* :meth:`consume_authorization_with_request` — atomic consume that flips BOTH
  the authorization and its request to CONSUMED in one transaction.
* ``server_epoch`` column + :meth:`revoke_authorizations_outside_epoch` — the
  authoritative restart-invalidation mechanism (replaces "nonce lost in
  memory" as a safety property).
* ``plan_approval_receipts`` outbox — durable receipt token-hash registry so a
  forged dataclass receipt cannot pass validation.
"""
from __future__ import annotations

import json
import secrets
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
    verify_nonce,
    verify_receipt_token,
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
    broker_request_id     TEXT NOT NULL DEFAULT '',
    reason                TEXT NOT NULL DEFAULT '',
    metadata              TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_plan_approval_requests_plan
    ON plan_approval_requests(plan_id, plan_content_hash);
CREATE INDEX IF NOT EXISTS idx_plan_approval_requests_repo
    ON plan_approval_requests(repository_id, task_id, workspace_id);
-- broker_request_id lookup index (uniqueness enforced separately because old
-- Batch 2 rows used the empty string for not-required requests).
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
    authorization_id      TEXT PRIMARY KEY,
    approval_request_id   TEXT NOT NULL,
    plan_id               TEXT NOT NULL,
    plan_content_hash     TEXT NOT NULL,
    repository_id         TEXT NOT NULL,
    task_id               TEXT NOT NULL,
    workspace_id          TEXT NOT NULL,
    base_sha              TEXT NOT NULL,
    repository_generation INTEGER NOT NULL,
    issued_at             REAL NOT NULL,
    expires_at            REAL NOT NULL,
    nonce_hash            TEXT NOT NULL UNIQUE,
    binding_digest        TEXT NOT NULL,
    status                TEXT NOT NULL,
    server_epoch          INTEGER NOT NULL DEFAULT 0
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

-- Batch 2.1: durable broker-decision receipt outbox. Only
-- ApprovalBroker.resolve_plan_approval can create a row here (via the
-- receipt_sink callback); apply_authenticated_decision verifies the token
-- hash AND every authoritative field against this row and marks it consumed
-- inside the same transaction.
CREATE TABLE IF NOT EXISTS plan_approval_receipts (
    receipt_id               TEXT PRIMARY KEY,
    token_hash               TEXT NOT NULL UNIQUE,
    approval_request_id      TEXT NOT NULL,
    broker_request_id        TEXT NOT NULL,
    binding_digest           TEXT NOT NULL,
    decision                 TEXT NOT NULL,
    namespace                TEXT NOT NULL DEFAULT 'plan-execution',
    authenticated_actor_id   TEXT NOT NULL DEFAULT '',
    authenticated_actor_type TEXT NOT NULL DEFAULT '',
    authenticated_source     TEXT NOT NULL DEFAULT '',
    session_request_id       TEXT NOT NULL DEFAULT '',
    server_capability        TEXT NOT NULL DEFAULT '',
    decided_at               REAL NOT NULL DEFAULT 0,
    reason_digest            TEXT NOT NULL DEFAULT '',
    consumed                 INTEGER NOT NULL DEFAULT 0,
    created_at               REAL NOT NULL,
    expires_at               REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_plan_approval_receipts_token
    ON plan_approval_receipts(token_hash);
CREATE INDEX IF NOT EXISTS idx_plan_approval_receipts_request
    ON plan_approval_receipts(approval_request_id);

-- Batch 2.2: persisted monotonic server epoch. The gate reads and rotates
-- this atomically at startup so a restart genuinely invalidates old
-- authorizations (the in-memory default epoch was not a real safety property).
CREATE TABLE IF NOT EXISTS plan_execution_server_state (
    singleton_key  TEXT PRIMARY KEY DEFAULT 'global',
    current_epoch  INTEGER NOT NULL DEFAULT 0,
    boot_id        TEXT NOT NULL DEFAULT '',
    updated_at     REAL NOT NULL DEFAULT 0
);

-- Batch 2.2: persisted authoritative plan snapshots. The gate and decision
-- path resolve plans by plan_id from here, not from a caller-supplied object.
-- A plan_id cannot be silently replaced with different content.
CREATE TABLE IF NOT EXISTS plan_snapshots (
    plan_id              TEXT PRIMARY KEY,
    content_hash         TEXT NOT NULL,
    binding_digest       TEXT NOT NULL,
    repository_id        TEXT NOT NULL,
    task_id              TEXT NOT NULL,
    workspace_id         TEXT NOT NULL,
    schema_version       TEXT NOT NULL DEFAULT 'khaos.planning.v1',
    canonical_plan_json  TEXT NOT NULL,
    created_at           REAL NOT NULL,
    status               TEXT NOT NULL DEFAULT 'active'
);

CREATE INDEX IF NOT EXISTS idx_plan_snapshots_repo
    ON plan_snapshots(repository_id, task_id, workspace_id);

-- Batch 2.2: workspace execution leases (TOCTOU closure for consume).
CREATE TABLE IF NOT EXISTS plan_execution_leases (
    lease_id              TEXT PRIMARY KEY,
    task_id               TEXT NOT NULL,
    workspace_id          TEXT NOT NULL,
    repository_id         TEXT NOT NULL,
    plan_id               TEXT NOT NULL,
    head_sha              TEXT NOT NULL,
    repository_generation INTEGER NOT NULL,
    evidence_digest       TEXT NOT NULL,
    binding_digest        TEXT NOT NULL,
    authorization_id      TEXT NOT NULL,
    expiry                REAL NOT NULL,
    owner_execution_id    TEXT NOT NULL,
    status                TEXT NOT NULL DEFAULT 'active',
    server_epoch          INTEGER NOT NULL DEFAULT 0,
    created_at            REAL NOT NULL
);

-- At most one ACTIVE lease per workspace — enforces workspace exclusivity.
CREATE UNIQUE INDEX IF NOT EXISTS uq_plan_execution_leases_active_workspace
    ON plan_execution_leases(workspace_id) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_plan_execution_leases_task
    ON plan_execution_leases(task_id, status);
"""


# Extra idempotent DDL that needs PRAGMA-based column probing (SQLite cannot
# add a column with IF NOT EXISTS). Run after APPROVAL_SCHEMA.
def _post_schema(conn: sqlite3.Connection) -> None:
    """Add columns / partial indexes introduced in Batch 2.1, idempotently."""
    cols = {r[1] for r in conn.execute("PRAGMA table_info(plan_execution_authorizations)")}
    if "server_epoch" not in cols:
        conn.execute(
            "ALTER TABLE plan_execution_authorizations ADD COLUMN server_epoch INTEGER NOT NULL DEFAULT 0"
        )
    # Partial unique index: at most one ACTIVE authorization per request. We
    # use a filtered unique index so consumed/revoked/expired rows do not
    # block re-mint attempts (which the service refuses anyway, but the DB
    # invariant is defense-in-depth). SQLite supports partial indexes since
    # 3.8.0 (2014); safe to assume.
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_plan_exec_auth_active_per_request "
        "ON plan_execution_authorizations(approval_request_id) WHERE status = 'active'"
    )
    # broker_request_id uniqueness for non-empty values (old not-required
    # rows used '' and many can coexist).
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_plan_approval_requests_broker "
        "ON plan_approval_requests(broker_request_id) WHERE broker_request_id != ''"
    )
    # Batch 2.2: add the full-binding receipt columns to old 2.1 databases.
    receipt_cols = {r[1] for r in conn.execute("PRAGMA table_info(plan_approval_receipts)")}
    for col, decl in (
        ("namespace", "TEXT NOT NULL DEFAULT 'plan-execution'"),
        ("authenticated_actor_id", "TEXT NOT NULL DEFAULT ''"),
        ("authenticated_actor_type", "TEXT NOT NULL DEFAULT ''"),
        ("authenticated_source", "TEXT NOT NULL DEFAULT ''"),
        ("session_request_id", "TEXT NOT NULL DEFAULT ''"),
        ("server_capability", "TEXT NOT NULL DEFAULT ''"),
        ("decided_at", "REAL NOT NULL DEFAULT 0"),
        ("reason_digest", "TEXT NOT NULL DEFAULT ''"),
    ):
        if col not in receipt_cols:
            conn.execute(f"ALTER TABLE plan_approval_receipts ADD COLUMN {col} {decl}")
    # Batch 2.3: add server_epoch to the leases table for old 2.2 databases.
    lease_cols = {r[1] for r in conn.execute("PRAGMA table_info(plan_execution_leases)")}
    if "server_epoch" not in lease_cols:
        conn.execute(
            "ALTER TABLE plan_execution_leases ADD COLUMN server_epoch INTEGER NOT NULL DEFAULT 0"
        )


class ApprovalTransitionResult(str, Enum):
    """Outcome of an atomic CAS approval transition."""

    UPDATED = "updated"
    UNCHANGED = "unchanged"  # idempotent same-decision
    INVALID_TRANSITION = "invalid_transition"
    CONFLICT = "conflict"  # opposite decision already applied
    NOT_FOUND = "not_found"
    STALE = "stale"  # binding digest drifted


class _BrokerReceiptWriter:
    __slots__ = ("__store", "__capability")

    def __init__(self, store: "PlanApprovalStore", capability: object) -> None:
        self.__store = store
        self.__capability = capability

    def write(self, **fields: Any) -> None:
        self.__store._insert_receipt(self.__capability, **fields)


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
        # Batch 2.3 §6: a server-owned capability token that only the broker
        # receives. insert_receipt refuses to run without it, so ordinary
        # store callers cannot create receipt rows.
        self.__receipt_writer_capability = object()

    def _broker_receipt_writer(self) -> _BrokerReceiptWriter:
        """Internal broker wiring hook; never exported from the package."""
        return _BrokerReceiptWriter(self, self.__receipt_writer_capability)

    # ------------------------------------------------------------------
    # Schema bootstrap
    # ------------------------------------------------------------------

    def ensure_schema(self) -> None:
        """Create the approval tables if missing. Idempotent."""
        self._conn.executescript(APPROVAL_SCHEMA)
        _post_schema(self._conn)
        self._conn.commit()

    # ------------------------------------------------------------------
    # Receipt outbox
    # ------------------------------------------------------------------

    def _insert_receipt(
        self,
        capability: object,
        *,
        receipt_id: str,
        token_hash: str,
        approval_request_id: str,
        broker_request_id: str,
        binding_digest: str,
        decision: str,
        namespace: str = "plan-execution",
        authenticated_actor_id: str = "",
        authenticated_actor_type: str = "",
        authenticated_source: str = "",
        session_request_id: str = "",
        server_capability: str = "",
        decided_at: float = 0.0,
        reason_digest: str = "",
        expires_at: float,
        created_at: float | None = None,
        now: float | None = None,
    ) -> None:
        """Persist a broker-decision receipt outbox row with ALL authoritative fields.

        Batch 2.3 §6: requires the store's ``receipt_writer_token`` (passed
        as ``writer_capability``). Direct calls by ordinary store users →
        PermissionError. Uses plain INSERT (not INSERT OR REPLACE) so a
        receipt_id or token_hash conflict raises instead of silently
        overwriting — a persisted decision cannot be rewritten.
        """
        if capability is not self.__receipt_writer_capability:
            raise PermissionError(
                "insert_receipt requires the broker's writer_capability; "
                "direct receipt writes by ordinary callers are forbidden"
            )
        ts = float(created_at if created_at is not None else (now if now is not None else time.time()))
        # Plain INSERT — refuses to overwrite an existing receipt_id or
        # token_hash (both UNIQUE). A replay attempt raises IntegrityError.
        self._conn.execute(
            """
            INSERT INTO plan_approval_receipts (
                receipt_id, token_hash, approval_request_id, broker_request_id,
                binding_digest, decision, namespace, authenticated_actor_id,
                authenticated_actor_type, authenticated_source, session_request_id,
                server_capability, decided_at, reason_digest, consumed, created_at, expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
            """,
            (
                receipt_id, token_hash, approval_request_id, broker_request_id,
                binding_digest, decision, namespace, authenticated_actor_id,
                authenticated_actor_type, authenticated_source, session_request_id,
                server_capability, float(decided_at), reason_digest, ts, float(expires_at),
            ),
        )
        self._conn.commit()

    def get_receipt_by_token(self, token: str) -> sqlite3.Row | None:
        """Look up a receipt row by verifying a plaintext token.

        Constant-time: hashes the token and compares against stored hashes.
        """
        from khaos.coding.planning.approval.models import hash_receipt_token

        th = hash_receipt_token(token)
        return self._conn.execute(
            "SELECT * FROM plan_approval_receipts WHERE token_hash = ?",
            (th,),
        ).fetchone()

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
    # Atomic status CAS (internal helper — does NOT write decision/audit)
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

        NOTE (Batch 2.1): this method ONLY transitions the request status. It
        does NOT write a decision record or audit event — those belong to
        :meth:`apply_authenticated_decision`, which does everything in one
        transaction. This method is retained for non-decision transitions
        (revoke, invalidate, stale-on-drift).
        """
        if self._conn.in_transaction:
            self._conn.commit()
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

            if current == target:
                self._conn.rollback()
                return ApprovalTransitionResult.UNCHANGED

            if current_binding_digest is not None and row["binding_digest"] != current_binding_digest:
                self._conn.execute(
                    "UPDATE plan_approval_requests SET status = ? WHERE approval_request_id = ?",
                    (PlanApprovalStatus.STALE.value, approval_request_id),
                )
                self._conn.commit()
                return ApprovalTransitionResult.STALE

            allowed = ALLOWED_APPROVAL_TRANSITIONS.get(current, frozenset())
            if target not in allowed:
                self._conn.rollback()
                return ApprovalTransitionResult.CONFLICT

            if current not in expected:
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

    # ------------------------------------------------------------------
    # Atomic authenticated decision (§2) — the heart of the closure
    # ------------------------------------------------------------------

    def apply_authenticated_decision(
        self,
        *,
        approval_request_id: str,
        receipt,
        decision_record: PlanApprovalDecision,
        audit_event: PlanApprovalAuditEvent,
        new_expiry: float | None,
        now: float,
    ) -> ApprovalTransitionResult:
        """Apply a broker decision, the decision row, the audit row, the
        expiry update AND the receipt consumption in ONE ``BEGIN IMMEDIATE``.

        Failure of any step rolls back the entire transaction: the request
        status is unchanged, no decision row, no audit row, expiry unchanged,
        receipt not consumed.

        Full-field authenticity (Batch 2.2): the receipt's one-time token is
        hashed and matched against the ``plan_approval_receipts`` outbox row,
        AND EVERY authoritative field on the receipt (namespace, actor_id,
        actor_type, source, session_request_id, server_capability, decided_at,
        reason_digest, binding_digest, decision) is compared against that row.
        Tampering ANY field on a real receipt is detected and refused as
        CONFLICT. A forged dataclass receipt cannot supply a token whose hash
        matches an unconsumed outbox row in the first place.

        The idempotent path (request already in the decision state) STILL
        verifies the token + all fields before returning UNCHANGED — there is
        no early return that skips receipt verification.

        Returns:
            * ``UPDATED`` — decision applied atomically.
            * ``UNCHANGED`` — request already in ``decision`` (idempotent).
            * ``CONFLICT`` — receipt replay, cross-request, field tamper, or
              state conflict.
            * ``STALE`` — binding drift detected.
            * ``NOT_FOUND`` — request or receipt unknown.
        """
        decision = receipt.decision
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            # 1. Verify the receipt token against the outbox.
            receipt_row = self.get_receipt_by_token(receipt.one_time_token)
            if receipt_row is None:
                self._conn.rollback()
                return ApprovalTransitionResult.NOT_FOUND
            if int(receipt_row["consumed"]) == 1:
                # Replay attempt — refuse.
                self._conn.rollback()
                return ApprovalTransitionResult.CONFLICT
            if receipt_row["approval_request_id"] != approval_request_id:
                # Cross-request replay.
                self._conn.rollback()
                return ApprovalTransitionResult.CONFLICT
            if receipt_row["decision"] != decision.value:
                # Receipt's bound decision does not match the caller's claim.
                self._conn.rollback()
                return ApprovalTransitionResult.CONFLICT
            if now >= float(receipt_row["expires_at"]):
                self._conn.rollback()
                return ApprovalTransitionResult.CONFLICT

            # 1b. Verify EVERY authoritative field (Batch 2.2 §1). Tampering
            # any of these on a real receipt is a CONFLICT. We compare against
            # the durable outbox row, not the in-memory receipt object.
            field_checks = (
                ("namespace", receipt.namespace),
                ("authenticated_actor_id", receipt.authenticated_actor_id),
                ("authenticated_actor_type", receipt.authenticated_actor_type),
                ("authenticated_source", receipt.authenticated_source),
                ("session_request_id", receipt.session_request_id),
                ("server_capability", receipt.server_capability),
                ("reason_digest", receipt.reason_digest),
            )
            for col, expected in field_checks:
                if str(receipt_row[col]) != str(expected):
                    self._conn.rollback()
                    return ApprovalTransitionResult.CONFLICT
            # decided_at is a float; compare with small tolerance for JSON round-trip.
            if abs(float(receipt_row["decided_at"]) - float(receipt.decided_at)) > 1e-6:
                self._conn.rollback()
                return ApprovalTransitionResult.CONFLICT
            if str(receipt_row["binding_digest"]) != str(receipt.binding_digest):
                self._conn.rollback()
                return ApprovalTransitionResult.CONFLICT

            # 2. Verify the request status + binding.
            row = self._conn.execute(
                "SELECT status, binding_digest FROM plan_approval_requests "
                "WHERE approval_request_id = ?",
                (approval_request_id,),
            ).fetchone()
            if row is None:
                self._conn.rollback()
                return ApprovalTransitionResult.NOT_FOUND
            current = PlanApprovalStatus(row["status"])
            if current == decision:
                # Idempotent — STILL consume the receipt (after the full field
                # verification above passed) so it can't be reused.
                self._conn.execute(
                    "UPDATE plan_approval_receipts SET consumed = 1 WHERE receipt_id = ?",
                    (receipt_row["receipt_id"],),
                )
                self._conn.commit()
                return ApprovalTransitionResult.UNCHANGED
            if row["binding_digest"] != receipt_row["binding_digest"]:
                # Binding drift between request and receipt.
                self._conn.execute(
                    "UPDATE plan_approval_requests SET status = ? WHERE approval_request_id = ?",
                    (PlanApprovalStatus.STALE.value, approval_request_id),
                )
                self._conn.commit()
                return ApprovalTransitionResult.STALE
            allowed = ALLOWED_APPROVAL_TRANSITIONS.get(current, frozenset())
            if decision not in allowed:
                self._conn.rollback()
                return ApprovalTransitionResult.CONFLICT

            # 3. Transition request status.
            self._conn.execute(
                "UPDATE plan_approval_requests SET status = ? WHERE approval_request_id = ?",
                (decision.value, approval_request_id),
            )
            # 4. Update expiry (approved requests get the approved TTL).
            if new_expiry is not None:
                self._conn.execute(
                    "UPDATE plan_approval_requests SET expires_at = ? WHERE approval_request_id = ?",
                    (float(new_expiry), approval_request_id),
                )
            # 5. Insert decision record.
            self._conn.execute(
                """
                INSERT INTO plan_approval_decisions (
                    approval_request_id, decision, actor_id, actor_type, decided_at,
                    reason, authenticated_context, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    decision_record.approval_request_id,
                    decision_record.decision.value,
                    decision_record.actor_id,
                    decision_record.actor_type,
                    float(decision_record.decided_at),
                    decision_record.reason,
                    json.dumps(decision_record.authenticated_context, default=str, sort_keys=True),
                    json.dumps(decision_record.metadata, default=str, sort_keys=True),
                ),
            )
            # 6. Insert audit event.
            self._conn.execute(
                """
                INSERT INTO plan_approval_audit_events (
                    event_id, event_type, approval_request_id, plan_id, previous_status,
                    new_status, actor_id, actor_type, authenticated_source, timestamp,
                    reason_code, task_id, workspace_id, repository_id, correlation_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    audit_event.event_id,
                    audit_event.event_type,
                    audit_event.approval_request_id,
                    audit_event.plan_id,
                    audit_event.previous_status,
                    audit_event.new_status,
                    audit_event.actor_id,
                    audit_event.actor_type,
                    audit_event.authenticated_source,
                    float(audit_event.timestamp),
                    audit_event.reason_code,
                    audit_event.task_id,
                    audit_event.workspace_id,
                    audit_event.repository_id,
                    audit_event.correlation_id,
                ),
            )
            # 7. Consume the receipt.
            self._conn.execute(
                "UPDATE plan_approval_receipts SET consumed = 1 WHERE receipt_id = ?",
                (receipt_row["receipt_id"],),
            )
            self._conn.commit()
            return ApprovalTransitionResult.UPDATED
        except Exception:
            self._conn.rollback()
            raise

    # ------------------------------------------------------------------
    # Non-decision transitions (used by revoke / invalidate / registration)
    # ------------------------------------------------------------------

    def transition_request_status(
        self,
        approval_request_id: str,
        *,
        expected: set[PlanApprovalStatus],
        target: PlanApprovalStatus,
        audit_event: PlanApprovalAuditEvent | None = None,
    ) -> ApprovalTransitionResult:
        """Transition a request status (optionally with an audit row) in one tx."""
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            row = self._conn.execute(
                "SELECT status FROM plan_approval_requests WHERE approval_request_id = ?",
                (approval_request_id,),
            ).fetchone()
            if row is None:
                self._conn.rollback()
                return ApprovalTransitionResult.NOT_FOUND
            current = PlanApprovalStatus(row["status"])
            if current == target:
                self._conn.rollback()
                return ApprovalTransitionResult.UNCHANGED
            allowed = ALLOWED_APPROVAL_TRANSITIONS.get(current, frozenset())
            if target not in allowed or current not in expected:
                self._conn.rollback()
                return ApprovalTransitionResult.CONFLICT
            self._conn.execute(
                "UPDATE plan_approval_requests SET status = ? WHERE approval_request_id = ?",
                (target.value, approval_request_id),
            )
            if audit_event is not None:
                self._conn.execute(
                    """
                    INSERT INTO plan_approval_audit_events (
                        event_id, event_type, approval_request_id, plan_id, previous_status,
                        new_status, actor_id, actor_type, authenticated_source, timestamp,
                        reason_code, task_id, workspace_id, repository_id, correlation_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        audit_event.event_id, audit_event.event_type,
                        audit_event.approval_request_id, audit_event.plan_id,
                        audit_event.previous_status, audit_event.new_status,
                        audit_event.actor_id, audit_event.actor_type,
                        audit_event.authenticated_source, float(audit_event.timestamp),
                        audit_event.reason_code, audit_event.task_id,
                        audit_event.workspace_id, audit_event.repository_id,
                        audit_event.correlation_id,
                    ),
                )
            self._conn.commit()
            return ApprovalTransitionResult.UPDATED
        except Exception:
            self._conn.rollback()
            raise

    def set_request_broker(
        self, approval_request_id: str, broker_request_id: str, *, pending: bool = True
    ) -> bool:
        """Atomically attach a broker_request_id and flip registering→pending."""
        target = PlanApprovalStatus.PENDING if pending else PlanApprovalStatus.REGISTERING
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            row = self._conn.execute(
                "SELECT status FROM plan_approval_requests WHERE approval_request_id = ?",
                (approval_request_id,),
            ).fetchone()
            if row is None:
                self._conn.rollback()
                return False
            current = PlanApprovalStatus(row["status"])
            if pending and current != PlanApprovalStatus.REGISTERING:
                self._conn.rollback()
                return False
            self._conn.execute(
                "UPDATE plan_approval_requests SET broker_request_id = ?, status = ? "
                "WHERE approval_request_id = ?",
                (broker_request_id, target.value, approval_request_id),
            )
            self._conn.commit()
            return True
        except Exception:
            self._conn.rollback()
            raise

    def mark_expired(self, approval_request_id: str, *, now: float | None = None) -> ApprovalTransitionResult:
        """Move a request to ``expired`` if its TTL has elapsed."""
        now = time.time() if now is None else now
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
            if now < float(row["expires_at"]):
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
    # Decisions / Audit (read paths + standalone write for non-decision audit)
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
                event.event_id, event.event_type, event.approval_request_id,
                event.plan_id, event.previous_status, event.new_status,
                event.actor_id, event.actor_type, event.authenticated_source,
                float(event.timestamp), event.reason_code, event.task_id,
                event.workspace_id, event.repository_id, event.correlation_id,
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
                event_id=r["event_id"], event_type=r["event_type"],
                approval_request_id=r["approval_request_id"], plan_id=r["plan_id"],
                previous_status=r["previous_status"], new_status=r["new_status"],
                actor_id=r["actor_id"], actor_type=r["actor_type"],
                authenticated_source=r["authenticated_source"],
                timestamp=float(r["timestamp"]), reason_code=r["reason_code"],
                task_id=r["task_id"], workspace_id=r["workspace_id"],
                repository_id=r["repository_id"], correlation_id=r["correlation_id"],
            )
            for r in rows
        ]

    # ------------------------------------------------------------------
    # Execution authorizations
    # ------------------------------------------------------------------

    def insert_authorization(self, *args, **kwargs) -> None:
        """DISABLED (Batch 2.2 §2). Direct authorization insertion bypasses
        the gate's live validation + single-execution invariants.

        This public stub ALWAYS raises — it is retained only so accidental
        callers fail loudly instead of silently mutating the DB. The real
        mint path is :meth:`mint_authorization_if_request_active`, which is
        gate-internal and enforces all safety checks atomically.
        """
        raise PermissionError(
            "direct PlanApprovalStore.insert_authorization is disabled; "
            "use PlanExecutionGate.authorize_execution"
        )

    def consume_authorization(self, *args, **kwargs) -> bool:
        """DISABLED (Batch 2.2 §2). Direct authorization consumption bypasses
        the gate's live validation + request-consumption invariants.

        This public stub ALWAYS raises — retained so accidental callers fail
        loudly. The real consume path is
        :meth:`consume_authorization_with_request` (gate-internal) or the
        lease-based :meth:`PlanExecutionGate.acquire_lease`.
        """
        raise PermissionError(
            "direct PlanApprovalStore.consume_authorization is disabled; "
            "use PlanExecutionGate.acquire_lease / require_authorization"
        )

    def get_authorization(self, authorization_id: str) -> PlanExecutionAuthorization | None:
        row = self._conn.execute(
            "SELECT * FROM plan_execution_authorizations WHERE authorization_id = ?",
            (authorization_id,),
        ).fetchone()
        if row is None:
            return None
        return self._row_to_authorization(row)

    @staticmethod
    def _row_to_authorization(row: sqlite3.Row) -> PlanExecutionAuthorization:
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

    def mint_authorization_if_request_active(
        self,
        auth: PlanExecutionAuthorization,
        *,
        server_epoch: int,
        expected_binding_digest: str,
        audit_event: PlanApprovalAuditEvent | None = None,
        now: float,
    ) -> tuple[bool, PlanExecutionAuthorization | None]:
        """Atomically mint an authorization only if the request is still
        APPROVED/NOT_REQUIRED and no prior ACTIVE/CONSUMED authorization exists.

        Returns ``(True, auth)`` on a fresh mint, ``(True, existing)`` if an
        ACTIVE authorization already exists for this request (idempotent —
        returns the existing server handle, nonce blank because we no longer
        have it in scope), or ``(False, None)`` if the request state forbids
        a new authorization (already consumed / not approved / expired / etc).

        The partial unique index ``uq_plan_exec_auth_active_per_request``
        provides defense-in-depth at the DB level.
        """
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            req = self._conn.execute(
                "SELECT status, expires_at, binding_digest FROM plan_approval_requests "
                "WHERE approval_request_id = ?",
                (auth.approval_request_id,),
            ).fetchone()
            if req is None:
                self._conn.rollback()
                return False, None
            status = PlanApprovalStatus(req["status"])
            if status not in (PlanApprovalStatus.APPROVED, PlanApprovalStatus.NOT_REQUIRED):
                self._conn.rollback()
                return False, None
            if now >= float(req["expires_at"]):
                self._conn.rollback()
                return False, None
            if req["binding_digest"] != expected_binding_digest:
                self._conn.rollback()
                return False, None

            # Is there an existing ACTIVE or CONSUMED authorization? A CONSUMED
            # one means this approval has already executed once → refuse.
            existing = self._conn.execute(
                "SELECT * FROM plan_execution_authorizations "
                "WHERE approval_request_id = ? AND status IN (?, ?) "
                "ORDER BY issued_at DESC LIMIT 1",
                (auth.approval_request_id, AuthorizationStatus.ACTIVE.value, AuthorizationStatus.CONSUMED.value),
            ).fetchone()
            if existing is not None:
                if existing["status"] == AuthorizationStatus.CONSUMED.value:
                    self._conn.rollback()
                    return False, None
                # ACTIVE — return the same handle (idempotent re-mint).
                self._conn.rollback()
                return True, self._row_to_authorization(existing)

            self._conn.execute(
                """
                INSERT INTO plan_execution_authorizations (
                    authorization_id, approval_request_id, plan_id, plan_content_hash,
                    repository_id, task_id, workspace_id, base_sha, repository_generation,
                    issued_at, expires_at, nonce_hash, binding_digest, status, server_epoch
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    auth.authorization_id, auth.approval_request_id, auth.plan_id,
                    auth.plan_content_hash, auth.repository_id, auth.task_id,
                    auth.workspace_id, auth.base_sha, int(auth.repository_generation),
                    float(auth.issued_at), float(auth.expires_at), auth.nonce_hash,
                    auth.binding_digest, auth.status.value, int(server_epoch),
                ),
            )
            if audit_event is not None:
                self._conn.execute(
                    """
                    INSERT INTO plan_approval_audit_events (
                        event_id, event_type, approval_request_id, plan_id, previous_status,
                        new_status, actor_id, actor_type, authenticated_source, timestamp,
                        reason_code, task_id, workspace_id, repository_id, correlation_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        audit_event.event_id, audit_event.event_type,
                        audit_event.approval_request_id, audit_event.plan_id,
                        audit_event.previous_status, audit_event.new_status,
                        audit_event.actor_id, audit_event.actor_type,
                        audit_event.authenticated_source, float(audit_event.timestamp),
                        audit_event.reason_code, audit_event.task_id,
                        audit_event.workspace_id, audit_event.repository_id,
                        audit_event.correlation_id,
                    ),
                )
            self._conn.commit()
            return True, auth
        except Exception:
            self._conn.rollback()
            raise

    def consume_authorization_with_request(
        self,
        authorization_id: str,
        *,
        nonce: str,
        expected_plan_id: str,
        expected_task_id: str,
        expected_workspace_id: str,
        expected_repository_id: str,
        expected_binding_digest: str,
        current_server_epoch: int,
        audit_event: PlanApprovalAuditEvent | None = None,
        now: float,
    ) -> bool:
        """Atomically consume an authorization AND flip its request to CONSUMED.

        Verifies (all within one ``BEGIN IMMEDIATE``):
        1. Authorization exists, is ACTIVE, and belongs to the caller's scope.
        2. The nonce hashes to the stored ``nonce_hash``.
        3. The authorization has not expired and its ``server_epoch`` matches
           the current epoch (restart-invalidation).
        4. The bound binding digest equals ``expected_binding_digest`` (drift
           check at consume time — §6).
        5. The request is still APPROVED/NOT_REQUIRED.

        On success: authorization → CONSUMED, request → CONSUMED, audit
        written, all committed atomically. Any mismatch rolls back.
        """
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
            if int(row["server_epoch"]) != int(current_server_epoch):
                # Restart-invalidation: authorization minted under a prior epoch.
                self._conn.execute(
                    "UPDATE plan_execution_authorizations SET status = ? WHERE authorization_id = ?",
                    (AuthorizationStatus.REVOKED.value, authorization_id),
                )
                self._conn.commit()
                return False
            if not verify_nonce(nonce, row["nonce_hash"]):
                self._conn.rollback()
                return False
            if now >= float(row["expires_at"]):
                self._conn.execute(
                    "UPDATE plan_execution_authorizations SET status = ? WHERE authorization_id = ?",
                    (AuthorizationStatus.EXPIRED.value, authorization_id),
                )
                self._conn.commit()
                return False
            if row["binding_digest"] != expected_binding_digest:
                self._conn.rollback()
                return False

            # Request must still be in an executable state.
            req = self._conn.execute(
                "SELECT status FROM plan_approval_requests WHERE approval_request_id = ?",
                (row["approval_request_id"],),
            ).fetchone()
            if req is None:
                self._conn.rollback()
                return False
            req_status = PlanApprovalStatus(req["status"])
            if req_status not in (PlanApprovalStatus.APPROVED, PlanApprovalStatus.NOT_REQUIRED):
                self._conn.rollback()
                return False

            # Flip both atomically.
            self._conn.execute(
                "UPDATE plan_execution_authorizations SET status = ? WHERE authorization_id = ?",
                (AuthorizationStatus.CONSUMED.value, authorization_id),
            )
            self._conn.execute(
                "UPDATE plan_approval_requests SET status = ? WHERE approval_request_id = ?",
                (PlanApprovalStatus.CONSUMED.value, row["approval_request_id"]),
            )
            if audit_event is not None:
                self._conn.execute(
                    """
                    INSERT INTO plan_approval_audit_events (
                        event_id, event_type, approval_request_id, plan_id, previous_status,
                        new_status, actor_id, actor_type, authenticated_source, timestamp,
                        reason_code, task_id, workspace_id, repository_id, correlation_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        audit_event.event_id, audit_event.event_type,
                        audit_event.approval_request_id, audit_event.plan_id,
                        audit_event.previous_status, audit_event.new_status,
                        audit_event.actor_id, audit_event.actor_type,
                        audit_event.authenticated_source, float(audit_event.timestamp),
                        audit_event.reason_code, audit_event.task_id,
                        audit_event.workspace_id, audit_event.repository_id,
                        audit_event.correlation_id,
                    ),
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

    def revoke_authorizations_outside_epoch(self, current_epoch: int) -> int:
        """Bulk-revoke every ACTIVE authorization minted under a prior epoch.

        Called at process startup once the gate has rotated its epoch. This is
        the authoritative restart-invalidation mechanism (§8) — it does NOT
        rely on the in-memory nonce being lost.
        """
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            cur = self._conn.execute(
                "UPDATE plan_execution_authorizations SET status = ? "
                "WHERE status = ? AND server_epoch != ?",
                (AuthorizationStatus.REVOKED.value, AuthorizationStatus.ACTIVE.value, int(current_epoch)),
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
        return [self._row_to_authorization(r) for r in rows]

    def list_registering_or_pending(self) -> list[PlanApprovalRequest]:
        """Return every request still awaiting broker registration / decision.

        Used by :meth:`PlanApprovalService.reconcile` at startup.
        """
        rows = self._conn.execute(
            "SELECT * FROM plan_approval_requests WHERE status IN (?, ?) "
            "ORDER BY requested_at ASC",
            (PlanApprovalStatus.REGISTERING.value, PlanApprovalStatus.PENDING.value),
        ).fetchall()
        return [self._row_to_request(r) for r in rows]

    def list_requests_for_task(self, task_id: str) -> list[PlanApprovalRequest]:
        rows = self._conn.execute(
            "SELECT * FROM plan_approval_requests WHERE task_id = ? "
            "ORDER BY requested_at ASC",
            (task_id,),
        ).fetchall()
        return [self._row_to_request(r) for r in rows]

    def refresh_expiry(self, approval_request_id: str, new_expiry: float) -> None:
        conn = self._conn
        conn.execute(
            "UPDATE plan_approval_requests SET expires_at = ? WHERE approval_request_id = ?",
            (float(new_expiry), approval_request_id),
        )
        conn.commit()

    def find_request_by_plan_binding(
        self, plan_id: str, binding_digest: str
    ) -> PlanApprovalRequest | None:
        row = self._conn.execute(
            "SELECT * FROM plan_approval_requests WHERE plan_id = ? AND binding_digest = ? "
            "ORDER BY requested_at DESC LIMIT 1",
            (plan_id, binding_digest),
        ).fetchone()
        return self._row_to_request(row) if row is not None else None

    # ------------------------------------------------------------------
    # Persisted server epoch (Batch 2.2 §3)
    # ------------------------------------------------------------------

    def get_current_epoch(self) -> tuple[int, str]:
        """Return ``(current_epoch, boot_id)`` from the persisted singleton.

        Initializes the row to epoch 0 / empty boot_id on first call.
        """
        row = self._conn.execute(
            "SELECT current_epoch, boot_id FROM plan_execution_server_state WHERE singleton_key = 'global'"
        ).fetchone()
        if row is None:
            self._conn.execute(
                "INSERT INTO plan_execution_server_state (singleton_key, current_epoch, boot_id, updated_at) "
                "VALUES ('global', 0, '', ?)",
                (time.time(),),
            )
            self._conn.commit()
            return 0, ""
        return int(row["current_epoch"]), str(row["boot_id"])

    def rotate_epoch(self, *, now: float | None = None) -> tuple[int, str, int]:
        """Atomically increment the persisted epoch and generate a fresh boot_id.

        ONE ``BEGIN IMMEDIATE``: read current epoch, increment, generate
        boot_id, persist, revoke all ACTIVE authorizations outside the new
        epoch → COMMIT. Returns ``(new_epoch, new_boot_id, revoked_count)``.

        Concurrent startup: two calls race on the singleton row; BEGIN
        IMMEDIATE serializes them so the epoch increments twice and only the
        latest boot_id can mint/consume.
        """
        now = time.time() if now is None else now
        new_boot_id = uuid.uuid4().hex
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            row = self._conn.execute(
                "SELECT current_epoch FROM plan_execution_server_state WHERE singleton_key = 'global'"
            ).fetchone()
            if row is None:
                new_epoch = 1
                self._conn.execute(
                    "INSERT INTO plan_execution_server_state (singleton_key, current_epoch, boot_id, updated_at) "
                    "VALUES ('global', ?, ?, ?)",
                    (new_epoch, new_boot_id, now),
                )
            else:
                new_epoch = int(row["current_epoch"]) + 1
                self._conn.execute(
                    "UPDATE plan_execution_server_state SET current_epoch = ?, boot_id = ?, updated_at = ? "
                    "WHERE singleton_key = 'global'",
                    (new_epoch, new_boot_id, now),
                )
            # Revoke all ACTIVE authorizations from prior epochs.
            cur = self._conn.execute(
                "UPDATE plan_execution_authorizations SET status = ? "
                "WHERE status = ? AND server_epoch != ?",
                (AuthorizationStatus.REVOKED.value, AuthorizationStatus.ACTIVE.value, new_epoch),
            )
            revoked = int(cur.rowcount or 0)
            # Batch 2.3: also release all ACTIVE leases from prior epochs so a
            # restart does not leave stale leases permanently blocking a workspace.
            self._conn.execute(
                "UPDATE plan_execution_leases SET status = 'expired' "
                "WHERE status = 'active' AND server_epoch != ?",
                (new_epoch,),
            )
            self._conn.commit()
            return new_epoch, new_boot_id, revoked
        except Exception:
            self._conn.rollback()
            raise

    # ------------------------------------------------------------------
    # Persisted plan snapshots (Batch 2.2 §4)
    # ------------------------------------------------------------------

    def save_plan_snapshot(
        self,
        *,
        plan_id: str,
        content_hash: str,
        binding_digest: str,
        repository_id: str,
        task_id: str,
        workspace_id: str,
        canonical_plan_json: str,
        schema_version: str = "khaos.planning.v1",
        now: float | None = None,
    ) -> bool:
        """Persist an authoritative plan snapshot.

        Returns True on insert, False if a snapshot with the SAME plan_id and
        DIFFERENT content_hash already existed (refused — a plan_id cannot be
        silently replaced with different content; use a new plan_id or
        explicit revision).
        """
        now = time.time() if now is None else now
        existing = self._conn.execute(
            "SELECT content_hash FROM plan_snapshots WHERE plan_id = ?",
            (plan_id,),
        ).fetchone()
        if existing is not None and existing["content_hash"] != content_hash:
            return False
        self._conn.execute(
            """
            INSERT INTO plan_snapshots (
                plan_id, content_hash, binding_digest, repository_id, task_id,
                workspace_id, schema_version, canonical_plan_json, created_at, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active')
            ON CONFLICT(plan_id) DO UPDATE SET status = 'active'
            """,
            (
                plan_id, content_hash, binding_digest, repository_id, task_id,
                workspace_id, schema_version, canonical_plan_json, now,
            ),
        )
        self._conn.commit()
        return True

    def load_plan_snapshot(self, plan_id: str) -> tuple[str, str, str, str] | None:
        """Return canonical JSON, content hash, binding digest and schema for
        a plan_id, or None."""
        row = self._conn.execute(
            "SELECT canonical_plan_json, content_hash, binding_digest, schema_version FROM plan_snapshots "
            "WHERE plan_id = ? AND status = 'active'",
            (plan_id,),
        ).fetchone()
        if row is None:
            return None
        return str(row["canonical_plan_json"]), str(row["content_hash"]), str(row["binding_digest"]), str(row["schema_version"])

    # ------------------------------------------------------------------
    # Atomic request + authorization invalidation (Batch 2.2 §6)
    # ------------------------------------------------------------------

    def invalidate_request_authorizations_leases_and_receipt(
        self,
        request_id: str,
        *,
        target_status: PlanApprovalStatus,
        expected_statuses: set[PlanApprovalStatus],
        audit_event: PlanApprovalAuditEvent | None = None,
        now: float | None = None,
    ) -> ApprovalTransitionResult:
        """Atomically transition a request AND revoke all its ACTIVE
        authorizations AND release all its ACTIVE leases in ONE
        ``BEGIN IMMEDIATE`` (Batch 2.3 §8).

        Replaces the non-atomic compositions in revoke / invalidate_for_task
        / _mark_authorization_stale. Guarantees no request=stale/revoked/
        expired can coexist with an active authorization OR an active lease.
        """
        if self._conn.in_transaction:
            self._conn.commit()
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            row = self._conn.execute(
                "SELECT status, workspace_id FROM plan_approval_requests WHERE approval_request_id = ?",
                (request_id,),
            ).fetchone()
            if row is None:
                self._conn.rollback()
                return ApprovalTransitionResult.NOT_FOUND
            workspace_id = row["workspace_id"]
            current = PlanApprovalStatus(row["status"])
            if current == target_status:
                # Still revoke any stray active authorizations (idempotent).
                self._conn.execute(
                    "UPDATE plan_execution_authorizations SET status = ? "
                    "WHERE approval_request_id = ? AND status = ?",
                    (AuthorizationStatus.REVOKED.value, request_id, AuthorizationStatus.ACTIVE.value),
                )
                # Batch 2.3: also release any active leases on this workspace.
                self._conn.execute(
                    "UPDATE plan_execution_leases SET status = 'expired' "
                    "WHERE workspace_id = ? AND status = 'active'",
                    (workspace_id,),
                )
                self._conn.execute("UPDATE plan_approval_receipts SET consumed=1 WHERE approval_request_id=?", (request_id,))
                if audit_event is not None:
                    self._conn.execute(
                        """
                        INSERT INTO plan_approval_audit_events (
                            event_id, event_type, approval_request_id, plan_id, previous_status,
                            new_status, actor_id, actor_type, authenticated_source, timestamp,
                            reason_code, task_id, workspace_id, repository_id, correlation_id
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            audit_event.event_id, audit_event.event_type,
                            audit_event.approval_request_id, audit_event.plan_id,
                            audit_event.previous_status, audit_event.new_status,
                            audit_event.actor_id, audit_event.actor_type,
                            audit_event.authenticated_source, float(audit_event.timestamp),
                            audit_event.reason_code, audit_event.task_id,
                            audit_event.workspace_id, audit_event.repository_id,
                            audit_event.correlation_id,
                        ),
                    )
                self._conn.commit()
                return ApprovalTransitionResult.UNCHANGED
            if current not in expected_statuses:
                self._conn.rollback()
                return ApprovalTransitionResult.CONFLICT
            allowed = ALLOWED_APPROVAL_TRANSITIONS.get(current, frozenset())
            if target_status not in allowed:
                self._conn.rollback()
                return ApprovalTransitionResult.CONFLICT
            self._conn.execute(
                "UPDATE plan_approval_requests SET status = ? WHERE approval_request_id = ?",
                (target_status.value, request_id),
            )
            self._conn.execute(
                "UPDATE plan_execution_authorizations SET status = ? "
                "WHERE approval_request_id = ? AND status = ?",
                (AuthorizationStatus.REVOKED.value, request_id, AuthorizationStatus.ACTIVE.value),
            )
            # Batch 2.3: release all active leases on this workspace too.
            self._conn.execute(
                "UPDATE plan_execution_leases SET status = 'expired' "
                "WHERE workspace_id = ? AND status = 'active'",
                (workspace_id,),
            )
            self._conn.execute("UPDATE plan_approval_receipts SET consumed=1 WHERE approval_request_id=?", (request_id,))
            if audit_event is not None:
                self._conn.execute(
                    """
                    INSERT INTO plan_approval_audit_events (
                        event_id, event_type, approval_request_id, plan_id, previous_status,
                        new_status, actor_id, actor_type, authenticated_source, timestamp,
                        reason_code, task_id, workspace_id, repository_id, correlation_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        audit_event.event_id, audit_event.event_type,
                        audit_event.approval_request_id, audit_event.plan_id,
                        audit_event.previous_status, audit_event.new_status,
                        audit_event.actor_id, audit_event.actor_type,
                        audit_event.authenticated_source, float(audit_event.timestamp),
                        audit_event.reason_code, audit_event.task_id,
                        audit_event.workspace_id, audit_event.repository_id,
                        audit_event.correlation_id,
                    ),
                )
            self._conn.commit()
            return ApprovalTransitionResult.UPDATED
        except Exception:
            self._conn.rollback()
            raise

    def invalidate_request_and_authorizations(self, *args: Any, **kwargs: Any) -> ApprovalTransitionResult:
        """Backward-compatible name delegating to the unified transaction."""
        return self.invalidate_request_authorizations_leases_and_receipt(*args, **kwargs)

    # ------------------------------------------------------------------
    # Execution leases (Batch 2.2 §7)
    # ------------------------------------------------------------------

    def acquire_lease(
        self,
        *,
        lease_id: str,
        task_id: str,
        workspace_id: str,
        repository_id: str,
        plan_id: str,
        head_sha: str,
        repository_generation: int,
        evidence_digest: str,
        binding_digest: str,
        authorization_id: str,
        owner_execution_id: str,
        expiry: float,
        server_epoch: int = 0,
        now: float | None = None,
    ) -> bool:
        """Atomically acquire an exclusive workspace execution lease.

        The partial unique index ``uq_plan_execution_leases_active_workspace``
        ensures at most one ACTIVE lease per workspace — a concurrent acquire
        on the same workspace fails with IntegrityError.
        """
        now = time.time() if now is None else now
        try:
            self._conn.execute(
                """
                INSERT INTO plan_execution_leases (
                    lease_id, task_id, workspace_id, repository_id, plan_id,
                    head_sha, repository_generation, evidence_digest, binding_digest,
                    authorization_id, expiry, owner_execution_id, status, server_epoch, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)
                """,
                (
                    lease_id, task_id, workspace_id, repository_id, plan_id,
                    head_sha, int(repository_generation), evidence_digest, binding_digest,
                    authorization_id, float(expiry), owner_execution_id, int(server_epoch), now,
                ),
            )
            self._conn.commit()
            return True
        except sqlite3.IntegrityError:
            # Another ACTIVE lease already holds this workspace.
            self._conn.rollback()
            return False

    def release_lease(self, lease_id: str) -> bool:
        """Release (mark released) an execution lease."""
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            cur = self._conn.execute(
                "UPDATE plan_execution_leases SET status = 'released' "
                "WHERE lease_id = ? AND status = 'active'",
                (lease_id,),
            )
            ok = int(cur.rowcount or 0) > 0
            self._conn.commit()
            return ok
        except Exception:
            self._conn.rollback()
            raise

    def get_lease(self, lease_id: str) -> sqlite3.Row | None:
        return self._conn.execute(
            "SELECT * FROM plan_execution_leases WHERE lease_id = ?",
            (lease_id,),
        ).fetchone()

    # ------------------------------------------------------------------
    # Lease-first atomic consume (Batch 2.3 §1) — the single transaction
    # ------------------------------------------------------------------

    def acquire_execution_lease_and_consume(
        self,
        *,
        authorization_id: str,
        nonce: str,
        expected_plan_id: str,
        expected_task_id: str,
        expected_workspace_id: str,
        expected_repository_id: str,
        expected_binding_digest: str,
        current_server_epoch: int,
        lease_id: str,
        owner_execution_id: str,
        head_sha: str,
        repository_generation: int,
        evidence_digest: str,
        audit_event: "PlanApprovalAuditEvent | None",
        now: float,
    ) -> bool:
        """Lease-first atomic consume: ONE ``BEGIN IMMEDIATE`` does ALL of:

        1. Read authorization; verify ACTIVE, scope, nonce, epoch, expiry, binding.
        2. Read approval request; verify APPROVED/NOT_REQUIRED.
        3. Confirm workspace has NO existing ACTIVE lease (else rollback).
        4. Insert ACTIVE lease (stamped with current epoch).
        5. Authorization → CONSUMED.
        6. Request → CONSUMED.
        7. Insert audit event.
        8. COMMIT.

        Any step failing rolls back the ENTIRE transaction: the authorization
        stays ACTIVE, the request stays APPROVED/NOT_REQUIRED, no lease row
        exists, no audit row exists. This closes the TOCTOU between consume
        and lease-acquire that the old two-step path had.
        """
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            # 1. Read + verify the authorization.
            auth_row = self._conn.execute(
                "SELECT * FROM plan_execution_authorizations WHERE authorization_id = ?",
                (authorization_id,),
            ).fetchone()
            if auth_row is None:
                self._conn.rollback()
                return False
            if auth_row["status"] != AuthorizationStatus.ACTIVE.value:
                self._conn.rollback()
                return False
            if (
                auth_row["plan_id"] != expected_plan_id
                or auth_row["task_id"] != expected_task_id
                or auth_row["workspace_id"] != expected_workspace_id
                or auth_row["repository_id"] != expected_repository_id
            ):
                self._conn.rollback()
                return False
            if int(auth_row["server_epoch"]) != int(current_server_epoch):
                self._conn.rollback()
                return False
            if not verify_nonce(nonce, auth_row["nonce_hash"]):
                self._conn.rollback()
                return False
            if now >= float(auth_row["expires_at"]):
                self._conn.rollback()
                return False
            if auth_row["binding_digest"] != expected_binding_digest:
                self._conn.rollback()
                return False

            # 2. Read + verify the approval request.
            req_row = self._conn.execute(
                "SELECT status FROM plan_approval_requests WHERE approval_request_id = ?",
                (auth_row["approval_request_id"],),
            ).fetchone()
            if req_row is None:
                self._conn.rollback()
                return False
            req_status = PlanApprovalStatus(req_row["status"])
            if req_status not in (PlanApprovalStatus.APPROVED, PlanApprovalStatus.NOT_REQUIRED):
                self._conn.rollback()
                return False

            # 3 + 4. Insert the ACTIVE lease. The partial unique index
            # uq_plan_execution_leases_active_workspace makes a conflicting
            # ACTIVE lease raise IntegrityError → rollback (no consume).
            self._conn.execute(
                """
                INSERT INTO plan_execution_leases (
                    lease_id, task_id, workspace_id, repository_id, plan_id,
                    head_sha, repository_generation, evidence_digest, binding_digest,
                    authorization_id, expiry, owner_execution_id, status, server_epoch, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)
                """,
                (
                    lease_id, expected_task_id, expected_workspace_id, expected_repository_id,
                    expected_plan_id, head_sha, int(repository_generation),
                    evidence_digest, expected_binding_digest, authorization_id,
                    float(auth_row["expires_at"]), owner_execution_id,
                    int(current_server_epoch), now,
                ),
            )

            # 5. Authorization → CONSUMED.
            self._conn.execute(
                "UPDATE plan_execution_authorizations SET status = ? WHERE authorization_id = ?",
                (AuthorizationStatus.CONSUMED.value, authorization_id),
            )
            # 6. Request → CONSUMED.
            self._conn.execute(
                "UPDATE plan_approval_requests SET status = ? WHERE approval_request_id = ?",
                (PlanApprovalStatus.CONSUMED.value, auth_row["approval_request_id"]),
            )
            # 7. Audit.
            if audit_event is not None:
                self._conn.execute(
                    """
                    INSERT INTO plan_approval_audit_events (
                        event_id, event_type, approval_request_id, plan_id, previous_status,
                        new_status, actor_id, actor_type, authenticated_source, timestamp,
                        reason_code, task_id, workspace_id, repository_id, correlation_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        audit_event.event_id, audit_event.event_type,
                        audit_event.approval_request_id, audit_event.plan_id,
                        audit_event.previous_status, audit_event.new_status,
                        audit_event.actor_id, audit_event.actor_type,
                        audit_event.authenticated_source, float(audit_event.timestamp),
                        audit_event.reason_code, audit_event.task_id,
                        audit_event.workspace_id, audit_event.repository_id,
                        audit_event.correlation_id,
                    ),
                )
            # 8. COMMIT.
            self._conn.commit()
            return True
        except sqlite3.IntegrityError:
            # A conflicting ACTIVE lease already holds this workspace.
            self._conn.rollback()
            return False
        except Exception:
            self._conn.rollback()
            raise

    def require_active_lease(
        self,
        lease_id: str,
        *,
        owner_execution_id: str,
        expected_task_id: str,
        expected_workspace_id: str,
        expected_repository_id: str,
        expected_plan_id: str,
        current_server_epoch: int,
        now: float,
    ) -> bool:
        """Verify a lease is ACTIVE, owned by the caller, scope-correct,
        unexpired, and bound to the current boot epoch.

        Every Batch 3 execution entry must call this BEFORE touching the
        workspace. Returns True if the lease is valid; False otherwise.
        """
        row = self._conn.execute(
            "SELECT * FROM plan_execution_leases WHERE lease_id = ?",
            (lease_id,),
        ).fetchone()
        if row is None:
            return False
        if row["status"] != "active":
            return False
        if now >= float(row["expiry"]):
            # Auto-expire the stale lease so it doesn't permanently block.
            self._conn.execute(
                "UPDATE plan_execution_leases SET status = 'expired' WHERE lease_id = ?",
                (lease_id,),
            )
            self._conn.commit()
            return False
        if row["owner_execution_id"] != owner_execution_id:
            return False
        if (
            row["task_id"] != expected_task_id
            or row["workspace_id"] != expected_workspace_id
            or row["repository_id"] != expected_repository_id
            or row["plan_id"] != expected_plan_id
        ):
            return False
        if int(row["server_epoch"]) != int(current_server_epoch):
            return False
        auth = self._conn.execute(
            "SELECT status,binding_digest,approval_request_id FROM plan_execution_authorizations WHERE authorization_id=?",
            (row["authorization_id"],),
        ).fetchone()
        if auth is None or auth["status"] != AuthorizationStatus.CONSUMED.value:
            return False
        if auth["binding_digest"] != row["binding_digest"]:
            return False
        request = self._conn.execute(
            "SELECT status,binding_digest FROM plan_approval_requests WHERE approval_request_id=?",
            (auth["approval_request_id"],),
        ).fetchone()
        if request is None or request["status"] != PlanApprovalStatus.CONSUMED.value:
            return False
        if request["binding_digest"] != row["binding_digest"]:
            return False
        return True

    def count_active_leases_for_workspace(self, workspace_id: str) -> int:
        """Return the count of ACTIVE leases on a workspace (invariant check)."""
        row = self._conn.execute(
            "SELECT COUNT(*) AS c FROM plan_execution_leases WHERE workspace_id = ? AND status = 'active'",
            (workspace_id,),
        ).fetchone()
        return int(row["c"]) if row else 0

    def reap_expired_leases(self, *, now: float) -> int:
        """Expire every ACTIVE lease whose TTL has elapsed (§3 item 6/7).

        Returns the count reaped. Called periodically or before any lease
        acquire so an expired lease doesn't permanently block a workspace.
        """
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            cur = self._conn.execute(
                "UPDATE plan_execution_leases SET status = 'expired' "
                "WHERE status = 'active' AND expiry < ?",
                (float(now),),
            )
            count = int(cur.rowcount or 0)
            self._conn.commit()
            return count
        except Exception:
            self._conn.rollback()
            raise


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
