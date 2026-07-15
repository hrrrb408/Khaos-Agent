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

import hashlib
import json
import secrets
import sqlite3
import time
import uuid
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from khaos.coding.planning.execution_models import RollbackResumeState

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
    server_epoch          INTEGER NOT NULL DEFAULT 0,
    boot_id               TEXT NOT NULL DEFAULT ''
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
-- Batch 2.6 §1: broker signature + canonical_payload_digest + signer_key_id
-- columns. apply_authenticated_decision re-verifies the Ed25519 signature so
-- direct DB writes by ordinary code cannot produce a valid receipt row.
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
    expires_at               REAL NOT NULL,
    canonical_payload_digest TEXT NOT NULL DEFAULT '',
    broker_signature         TEXT NOT NULL DEFAULT '',
    signer_key_id            TEXT NOT NULL DEFAULT '',
    signer_epoch             INTEGER NOT NULL DEFAULT 0,
    signer_boot_id           TEXT NOT NULL DEFAULT '',
    issued_at                REAL NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_plan_approval_receipts_token
    ON plan_approval_receipts(token_hash);
CREATE INDEX IF NOT EXISTS idx_plan_approval_receipts_request
    ON plan_approval_receipts(approval_request_id);

-- Batch 2.7: persisted Ed25519 public verification keys. Private signing
-- material remains broker-local and is never written to SQLite. A new boot
-- rotates the key while old public keys remain available for verification.
CREATE TABLE IF NOT EXISTS receipt_verification_keys (
    key_id       TEXT PRIMARY KEY,
    public_key   TEXT NOT NULL,
    key_version  INTEGER NOT NULL,
    boot_epoch   INTEGER NOT NULL,
    boot_id      TEXT NOT NULL DEFAULT '',
    created_at   REAL NOT NULL,
    active       INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS approval_runtime_boots (
    server_epoch INTEGER NOT NULL,
    boot_id TEXT PRIMARY KEY,
    started_at REAL NOT NULL,
    replaced_at REAL
);

CREATE TABLE IF NOT EXISTS workspace_mutation_poison (
    workspace_id TEXT PRIMARY KEY,
    lease_id TEXT NOT NULL,
    reason TEXT NOT NULL,
    poisoned_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS workspace_mutation_poison_scopes (
    workspace_id TEXT NOT NULL,
    poison_owner TEXT NOT NULL,
    reason TEXT NOT NULL,
    poisoned_at REAL NOT NULL,
    PRIMARY KEY(workspace_id, poison_owner)
);

CREATE TABLE IF NOT EXISTS workspace_mutation_audit (
    event_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    lease_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    reason TEXT NOT NULL,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS plan_execution_runs (
    execution_run_id TEXT PRIMARY KEY,
    plan_id TEXT NOT NULL,
    plan_content_hash TEXT NOT NULL,
    approval_request_id TEXT NOT NULL,
    authorization_id TEXT NOT NULL UNIQUE,
    execution_context_id TEXT NOT NULL UNIQUE,
    lease_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    repository_id TEXT NOT NULL,
    base_sha TEXT NOT NULL,
    repository_generation INTEGER NOT NULL,
    binding_digest TEXT NOT NULL,
    edit_bundle_digest TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    completed_at REAL,
    failure_code TEXT NOT NULL DEFAULT '',
    recovery_sealed_at REAL,
    recovery_seal_digest TEXT NOT NULL DEFAULT '',
    rollback_sealed_at REAL,
    rollback_seal_digest TEXT NOT NULL DEFAULT '',
    terminal_tombstone_digest TEXT NOT NULL DEFAULT '',
    initial_attestation_digest TEXT NOT NULL DEFAULT '',
    journaled_edit_count INTEGER NOT NULL DEFAULT 0,
    metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS plan_execution_edit_events (
    event_id TEXT PRIMARY KEY,
    execution_run_id TEXT NOT NULL,
    edit_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL,
    operation TEXT NOT NULL,
    path TEXT NOT NULL,
    destination_path TEXT,
    before_hash TEXT,
    after_hash TEXT,
    before_mode INTEGER,
    after_mode INTEGER,
    status TEXT NOT NULL,
    phase_version INTEGER NOT NULL DEFAULT 0,
    applied_identity_digest TEXT NOT NULL DEFAULT '',
    applied_parent_identity_digest TEXT NOT NULL DEFAULT '',
    applied_destination_identity_digest TEXT NOT NULL DEFAULT '',
    rollback_identity_digest TEXT NOT NULL DEFAULT '',
    rollback_parent_identity_digest TEXT NOT NULL DEFAULT '',
    rollback_destination_parent_identity_digest TEXT NOT NULL DEFAULT '',
    rollback_sync_mask INTEGER NOT NULL DEFAULT 0,
    rollback_directory_sync_digest TEXT NOT NULL DEFAULT '',
    rollback_synced_at REAL,
    identity_version INTEGER NOT NULL DEFAULT 0,
    error_code TEXT NOT NULL DEFAULT '',
    recovery_artifact TEXT,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    UNIQUE(execution_run_id, edit_id)
);
CREATE TABLE IF NOT EXISTS plan_execution_audit_events (
    audit_id TEXT PRIMARY KEY,
    execution_run_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    operation TEXT NOT NULL DEFAULT '',
    path TEXT NOT NULL DEFAULT '',
    before_hash TEXT NOT NULL DEFAULT '',
    after_hash TEXT NOT NULL DEFAULT '',
    result TEXT NOT NULL,
    error_code TEXT NOT NULL DEFAULT '',
    correlation_id TEXT NOT NULL,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS plan_execution_final_attestations (
    execution_run_id TEXT PRIMARY KEY,
    bundle_digest TEXT NOT NULL,
    canonical_json TEXT NOT NULL,
    attestation_digest TEXT NOT NULL,
    attested_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS plan_execution_rollback_attestations (
    execution_run_id TEXT PRIMARY KEY,
    bundle_digest TEXT NOT NULL,
    canonical_json TEXT NOT NULL,
    attestation_digest TEXT NOT NULL,
    attested_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS plan_execution_initial_attestations (
    execution_run_id TEXT PRIMARY KEY,
    canonical_json TEXT NOT NULL,
    attestation_digest TEXT NOT NULL,
    attested_at REAL NOT NULL
);

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
    boot_id               TEXT NOT NULL DEFAULT '',
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
    # Legacy HMAC rows contained private signing secrets. They are never
    # migrated into verifier state; remove them fail-closed.
    conn.execute("DROP TABLE IF EXISTS receipt_signing_keys")
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
    # Batch 2.6 §1: add broker signature columns to old 2.5 databases.
    receipt_cols = {r[1] for r in conn.execute("PRAGMA table_info(plan_approval_receipts)")}
    for col, decl in (
        ("canonical_payload_digest", "TEXT NOT NULL DEFAULT ''"),
        ("broker_signature", "TEXT NOT NULL DEFAULT ''"),
        ("signer_key_id", "TEXT NOT NULL DEFAULT ''"),
        ("signer_epoch", "INTEGER NOT NULL DEFAULT 0"),
        ("signer_boot_id", "TEXT NOT NULL DEFAULT ''"),
        ("issued_at", "REAL NOT NULL DEFAULT 0"),
    ):
        if col not in receipt_cols:
            conn.execute(f"ALTER TABLE plan_approval_receipts ADD COLUMN {col} {decl}")
    verifier_cols = {
        r[1] for r in conn.execute("PRAGMA table_info(receipt_verification_keys)")
    }
    if "boot_id" not in verifier_cols:
        conn.execute(
            "ALTER TABLE receipt_verification_keys ADD COLUMN boot_id TEXT NOT NULL DEFAULT ''"
        )
    # Batch 2.3: add server_epoch to the leases table for old 2.2 databases.
    lease_cols = {r[1] for r in conn.execute("PRAGMA table_info(plan_execution_leases)")}
    if "server_epoch" not in lease_cols:
        conn.execute(
            "ALTER TABLE plan_execution_leases ADD COLUMN server_epoch INTEGER NOT NULL DEFAULT 0"
        )
    # Batch 2.5 §2: bind authorizations and leases to boot_id so a stale
    # runtime cannot mint/consume/validate using a cached epoch alone — the
    # persisted boot_id must also match.
    auth_cols = {r[1] for r in conn.execute("PRAGMA table_info(plan_execution_authorizations)")}
    if "boot_id" not in auth_cols:
        conn.execute(
            "ALTER TABLE plan_execution_authorizations ADD COLUMN boot_id TEXT NOT NULL DEFAULT ''"
        )
    lease_cols = {r[1] for r in conn.execute("PRAGMA table_info(plan_execution_leases)")}
    if "boot_id" not in lease_cols:
        conn.execute(
            "ALTER TABLE plan_execution_leases ADD COLUMN boot_id TEXT NOT NULL DEFAULT ''"
        )
    run_cols = {r[1] for r in conn.execute("PRAGMA table_info(plan_execution_runs)")}
    if run_cols:
        if "recovery_sealed_at" not in run_cols:
            conn.execute("ALTER TABLE plan_execution_runs ADD COLUMN recovery_sealed_at REAL")
        if "recovery_seal_digest" not in run_cols:
            conn.execute(
                "ALTER TABLE plan_execution_runs ADD COLUMN "
                "recovery_seal_digest TEXT NOT NULL DEFAULT ''"
            )
        if "rollback_sealed_at" not in run_cols:
            conn.execute("ALTER TABLE plan_execution_runs ADD COLUMN rollback_sealed_at REAL")
        if "rollback_seal_digest" not in run_cols:
            conn.execute(
                "ALTER TABLE plan_execution_runs ADD COLUMN "
                "rollback_seal_digest TEXT NOT NULL DEFAULT ''"
            )
        if "terminal_tombstone_digest" not in run_cols:
            conn.execute(
                "ALTER TABLE plan_execution_runs ADD COLUMN "
                "terminal_tombstone_digest TEXT NOT NULL DEFAULT ''"
            )
        if "initial_attestation_digest" not in run_cols:
            conn.execute(
                "ALTER TABLE plan_execution_runs ADD COLUMN "
                "initial_attestation_digest TEXT NOT NULL DEFAULT ''"
            )
        if "journaled_edit_count" not in run_cols:
            conn.execute(
                "ALTER TABLE plan_execution_runs ADD COLUMN "
                "journaled_edit_count INTEGER NOT NULL DEFAULT 0"
            )
    event_cols = {
        r[1] for r in conn.execute("PRAGMA table_info(plan_execution_edit_events)")
    }
    if event_cols and "phase_version" not in event_cols:
        conn.execute(
            "ALTER TABLE plan_execution_edit_events ADD COLUMN "
            "phase_version INTEGER NOT NULL DEFAULT 0"
        )
    for column, declaration in (
        ("applied_identity_digest", "TEXT NOT NULL DEFAULT ''"),
        ("applied_parent_identity_digest", "TEXT NOT NULL DEFAULT ''"),
        ("applied_destination_identity_digest", "TEXT NOT NULL DEFAULT ''"),
        ("rollback_identity_digest", "TEXT NOT NULL DEFAULT ''"),
        ("rollback_parent_identity_digest", "TEXT NOT NULL DEFAULT ''"),
        ("rollback_destination_parent_identity_digest", "TEXT NOT NULL DEFAULT ''"),
        ("rollback_sync_mask", "INTEGER NOT NULL DEFAULT 0"),
        ("rollback_directory_sync_digest", "TEXT NOT NULL DEFAULT ''"),
        ("rollback_synced_at", "REAL"),
        ("identity_version", "INTEGER NOT NULL DEFAULT 0"),
    ):
        if event_cols and column not in event_cols:
            conn.execute(
                f"ALTER TABLE plan_execution_edit_events ADD COLUMN "
                f"{column} {declaration}"
            )
    if event_cols:
        # This index must be created only after legacy Batch 3 databases have
        # received the ownership columns above.  Putting it in APPROVAL_SCHEMA
        # makes SQLite evaluate it before _post_schema can migrate the table.
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_plan_execution_edit_events_recovery "
            "ON plan_execution_edit_events("
            "execution_run_id,status,identity_version,ordinal)"
        )
    # Batch 3.1.5 §2: add approved_verification_plan columns to old databases.
    request_cols = {r[1] for r in conn.execute("PRAGMA table_info(plan_approval_requests)")}
    for col, decl in (
        ("approved_verification_plan_id", "TEXT NOT NULL DEFAULT ''"),
        ("approved_verification_plan_digest", "TEXT NOT NULL DEFAULT ''"),
    ):
        if col not in request_cols:
            conn.execute(
                f"ALTER TABLE plan_approval_requests ADD COLUMN {col} {decl}"
            )


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
        # Batch 2.6 §1: a name-mangled writer handle that ONLY the runtime
        # can install (via _install_runtime_receipt_writer). It is NOT a
        # sink closure and NOT exposed as a public attribute. Ordinary
        # callers cannot read or replace it.
        self.__runtime_receipt_writer = None  # type: ignore[assignment]
        self.__runtime_receipt_token = None
        self.__verification_success_verifier = None
        self.__authoritative_verification_reads_required = False
        # Public-only verifier registry. Unknown keys fail closed; prior-boot
        # public keys remain loadable across signing-key rotation.
        self.__receipt_verifiers: dict[str, Any] = {}
        try:
            for verifier in self.load_receipt_verifiers():
                self.__receipt_verifiers[verifier.key_id] = verifier
        except Exception:
            pass

    def _install_runtime_receipt_writer(
        self, writer: Any, *, runtime_token: object, runtime_capability: Any = None
    ) -> None:
        """Install the runtime's receipt writer (name-mangled, token-gated).

        Batch 2.6 §1: replaces the old ``_create_receipt_sink`` /
        ``_bind_receipt_broker`` / ``broker._receipt_writer`` chain. The
        ``runtime_token`` is an opaque object that only
        :class:`ApprovalRuntime` possesses; a forged token is silently
        ignored. The writer is a plain callable that captures the broker's
        internal ``ReceiptSigner`` — it has no readable ``capability`` or
        ``signer`` attribute.
        """
        from khaos.coding.planning.approval.runtime import _consume_runtime_capability

        try:
            _consume_runtime_capability(runtime_capability, "receipt-store")
        except PermissionError as exc:
            raise PermissionError("runtime receipt authority required") from exc
        if runtime_token is None:
            raise PermissionError("runtime receipt token required")
        self.__runtime_receipt_writer = writer  # type: ignore[assignment]
        self.__runtime_receipt_token = runtime_token

    def _reset_runtime_receipt_writer(self) -> None:
        """Clear the runtime receipt writer (used by rollback/shutdown).

        Persisted public verifiers remain loaded so prior-boot receipts stay
        verifiable after signing-key rotation.
        Only the writer (mint path) is cleared.
        """
        self.__runtime_receipt_writer = None  # type: ignore[assignment]
        self.__runtime_receipt_token = None

    def _has_runtime_receipt_writer(self) -> bool:
        """Test-only introspection: does a writer exist?"""
        return self.__runtime_receipt_writer is not None  # type: ignore[attr-defined]

    def _install_verification_success_verifier(self, verifier: Any) -> None:
        """Install Runtime-owned validation for authoritative VERIFIED reads."""
        if self.__verification_success_verifier is not None:
            if self.__verification_success_verifier == verifier:
                return
            raise PermissionError("verification success verifier already installed")
        self.__verification_success_verifier = verifier

    def _require_authoritative_verification_reads(self) -> None:
        self.__authoritative_verification_reads_required = True

    def _reset_verification_success_verifier(self) -> None:
        self.__verification_success_verifier = None

    def _persist_receipt_verifier(self, verifier: Any, *, runtime_token: object) -> None:
        """Persist public verification material only."""
        if runtime_token is not self.__runtime_receipt_token:
            raise PermissionError("runtime authority required")
        import time as _time
        self._conn.execute(
            "INSERT OR REPLACE INTO receipt_verification_keys "
            "(key_id, public_key, key_version, boot_epoch, boot_id, created_at, active) "
            "VALUES (?, ?, ?, ?, ?, ?, 1)",
            (verifier.key_id, verifier.public_key, verifier.key_version,
             verifier.boot_epoch, verifier.boot_id, _time.time()),
        )
        self._conn.commit()
        self.__receipt_verifiers[verifier.key_id] = verifier

    def load_receipt_verifiers(self) -> list:
        """Return public-only verifier objects; legacy HMAC rows are ignored."""
        from khaos.coding.planning.approval.receipt_crypto import ReceiptPublicVerifier
        rows = self._conn.execute(
            "SELECT key_id,public_key,key_version,boot_epoch,boot_id "
            "FROM receipt_verification_keys WHERE active = 1"
        ).fetchall()
        return [ReceiptPublicVerifier(
            str(row["key_id"]), str(row["public_key"]), int(row["key_version"]),
            int(row["boot_epoch"]), str(row["boot_id"]),
        ) for row in rows]

    # ------------------------------------------------------------------
    # Schema bootstrap
    # ------------------------------------------------------------------

    def ensure_schema(self) -> None:
        """Create the approval tables if missing. Idempotent."""
        self._conn.executescript(APPROVAL_SCHEMA)
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            _post_schema(self._conn)
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    # ------------------------------------------------------------------
    # Receipt outbox
    # ------------------------------------------------------------------

    def _insert_signed_receipt(
        self,
        *,
        runtime_token: object = None,
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
        canonical_payload_digest: str = "",
        broker_signature: str = "",
        signer_key_id: str = "",
        signer_epoch: int = 0,
        signer_boot_id: str = "",
        issued_at: float = 0.0,
        created_at: float | None = None,
        now: float | None = None,
    ) -> None:
        """Persist a SIGNED broker-decision receipt outbox row.

        Batch 2.6 §1: this method is called ONLY by the runtime-installed
        receipt writer (the broker's signed writer closure). It is NOT
        callable by ordinary store users — there is no capability token to
        forge. The writer closure is installed by the runtime via
        ``_install_runtime_receipt_writer`` and is name-mangled so it cannot
        be read or replaced from outside the store.

        The ``canonical_payload_digest``, ``broker_signature``, and
        ``signer_key_id`` are persisted alongside the row so
        ``apply_authenticated_decision`` can re-verify the Ed25519 signature
        against the persisted digest. Direct DB writes by ordinary code
        cannot produce a valid signature, so a forged outbox row is rejected
        even if it matches a known token hash.

        Uses plain INSERT (not INSERT OR REPLACE) so a receipt_id or
        token_hash conflict raises — a persisted decision cannot be rewritten.
        """
        if runtime_token is not self.__runtime_receipt_token:
            raise PermissionError("runtime receipt authority required")
        if not broker_signature or not signer_key_id or not canonical_payload_digest:
            raise PermissionError(
                "signed receipt requires broker_signature, signer_key_id, "
                "and canonical_payload_digest; unsigned receipts are refused"
            )
        ts = float(created_at if created_at is not None else (now if now is not None else time.time()))
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            if not self._verify_persisted_boot_context(
                server_epoch=signer_epoch, boot_id=signer_boot_id,
            ):
                raise PermissionError("receipt signer boot is no longer current")
            key = self._conn.execute(
                "SELECT boot_epoch,boot_id FROM receipt_verification_keys WHERE key_id=?",
                (signer_key_id,),
            ).fetchone()
            if key is None or int(key["boot_epoch"]) != int(signer_epoch) or str(key["boot_id"]) != signer_boot_id:
                raise PermissionError("receipt signer key is not bound to current boot")
            self._conn.execute(
            """
            INSERT INTO plan_approval_receipts (
                receipt_id, token_hash, approval_request_id, broker_request_id,
                binding_digest, decision, namespace, authenticated_actor_id,
                authenticated_actor_type, authenticated_source, session_request_id,
                server_capability, decided_at, reason_digest, consumed, created_at,
                expires_at, canonical_payload_digest, broker_signature, signer_key_id,
                signer_epoch, signer_boot_id, issued_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                receipt_id, token_hash, approval_request_id, broker_request_id,
                binding_digest, decision, namespace, authenticated_actor_id,
                authenticated_actor_type, authenticated_source, session_request_id,
                server_capability, float(decided_at), reason_digest, ts, float(expires_at),
                canonical_payload_digest, broker_signature, signer_key_id,
                int(signer_epoch), signer_boot_id, float(issued_at),
            ),
            )
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

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
                status, broker_request_id, reason, metadata,
                approved_verification_plan_id, approved_verification_plan_digest
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                getattr(request, "approved_verification_plan_id", "") or "",
                getattr(request, "approved_verification_plan_digest", "") or "",
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
        # Batch 3.1.5 §2: read approved_verification_plan columns (may be
        # absent in old rows before migration — use .keys() guard).
        keys = set(row.keys())
        avp_id = row["approved_verification_plan_id"] if "approved_verification_plan_id" in keys else ""
        avp_digest = row["approved_verification_plan_digest"] if "approved_verification_plan_digest" in keys else ""
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
            approved_verification_plan_id=avp_id or "",
            approved_verification_plan_digest=avp_digest or "",
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

            # 1c. Batch 2.6 §1: verify the broker signature. Even if an
            # attacker directly inserts a forged outbox row with a known
            # token_hash + matching fields, they cannot produce a valid
            # Ed25519 signature without the broker's private key. Old unsigned
            # receipts (broker_signature="") are rejected fail-closed.
            row_sig = str(receipt_row["broker_signature"]) if "broker_signature" in receipt_row.keys() else ""
            row_signer_key_id = str(receipt_row["signer_key_id"]) if "signer_key_id" in receipt_row.keys() else ""
            row_payload_digest = str(receipt_row["canonical_payload_digest"]) if "canonical_payload_digest" in receipt_row.keys() else ""
            if not row_sig or not row_signer_key_id or not row_payload_digest:
                # Unsigned receipt — fail closed.
                self._conn.rollback()
                return ApprovalTransitionResult.CONFLICT
            # Look up the verifier by signer_key_id.
            verifier = self.__receipt_verifiers.get(row_signer_key_id)  # type: ignore[attr-defined]
            if verifier is None:
                # Unknown signer key — fail closed.
                self._conn.rollback()
                return ApprovalTransitionResult.CONFLICT
            signer_epoch = int(receipt_row["signer_epoch"])
            signer_boot_id = str(receipt_row["signer_boot_id"])
            issued_at = float(receipt_row["issued_at"])
            if (verifier.boot_epoch != signer_epoch
                    or verifier.boot_id != signer_boot_id):
                self._conn.rollback()
                return ApprovalTransitionResult.CONFLICT
            boot = self._conn.execute(
                "SELECT started_at,replaced_at FROM approval_runtime_boots "
                "WHERE server_epoch=? AND boot_id=?",
                (signer_epoch, signer_boot_id),
            ).fetchone()
            if (boot is None or issued_at < float(boot["started_at"])
                    or (boot["replaced_at"] is not None
                        and issued_at >= float(boot["replaced_at"]))
                    or abs(float(receipt_row["created_at"]) - issued_at) > 1e-6):
                self._conn.rollback()
                return ApprovalTransitionResult.CONFLICT
            # Recompute the canonical payload digest from the DURABLE ROW
            # fields (not the in-memory receipt) so a tampered in-memory
            # receipt is detected even if it claims the same signature.
            import hashlib as _hashlib
            canonical_from_row = "|".join([
                str(receipt_row["receipt_id"]),
                str(receipt_row["namespace"]),
                str(receipt_row["broker_request_id"]),
                str(receipt_row["approval_request_id"]),
                str(receipt_row["decision"]),
                str(receipt_row["authenticated_actor_id"]),
                str(receipt_row["authenticated_actor_type"]),
                str(receipt_row["authenticated_source"]),
                str(receipt_row["session_request_id"]),
                str(receipt_row["server_capability"]),
                str(receipt_row["binding_digest"]),
                f"{float(receipt_row['decided_at']):.6f}",
                f"{float(receipt_row['expires_at']):.6f}",
                str(receipt_row["reason_digest"]),
                str(receipt_row["token_hash"]),
                str(signer_epoch),
                signer_boot_id,
                f"{issued_at:.6f}",
            ])
            row_digest_recomputed = _hashlib.sha256(canonical_from_row.encode("utf-8")).hexdigest()
            if row_digest_recomputed != row_payload_digest:
                # Persisted payload digest doesn't match persisted fields — tampered row.
                self._conn.rollback()
                return ApprovalTransitionResult.CONFLICT
            if not verifier.verify_payload_digest(row_payload_digest, row_sig):
                self._conn.rollback()
                return ApprovalTransitionResult.CONFLICT
            # Also verify the in-memory receipt's signature matches (catches
            # a tampered in-memory receipt whose fields differ from the row).
            if (receipt.signer_key_id != verifier.key_id
                    or receipt.signer_epoch != signer_epoch
                    or receipt.signer_boot_id != signer_boot_id
                    or abs(receipt.issued_at - issued_at) > 1e-6
                    or not verifier.verify_payload_digest(
                        receipt.compute_canonical_payload_digest(),
                        receipt.broker_signature,
                    )):
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

    def _verify_persisted_boot_context(
        self, *, server_epoch: int, boot_id: str,
    ) -> bool:
        """Verify the supplied epoch + boot_id match the persisted singleton.

        Batch 2.5 §2: must be called INSIDE a ``BEGIN IMMEDIATE`` transaction.
        Returns True if both match; False otherwise. This prevents a stale
        runtime (whose cached epoch/boot_id no longer matches the persisted
        state) from minting, consuming, or validating.
        """
        row = self._conn.execute(
            "SELECT current_epoch, boot_id FROM plan_execution_server_state "
            "WHERE singleton_key = 'global'"
        ).fetchone()
        if row is None:
            return False
        return int(row["current_epoch"]) == int(server_epoch) and str(row["boot_id"]) == boot_id

    def mint_authorization_if_request_active(
        self,
        auth: PlanExecutionAuthorization,
        *,
        server_epoch: int,
        boot_id: str = "",
        expected_binding_digest: str,
        audit_event: PlanApprovalAuditEvent | None = None,
        now: float,
    ) -> tuple[bool, PlanExecutionAuthorization | None]:
        """Atomically mint an authorization only if the request is still
        APPROVED/NOT_REQUIRED and no prior ACTIVE/CONSUMED authorization exists.

        Batch 2.5 §2: verifies the supplied ``server_epoch`` AND ``boot_id``
        match the persisted ``plan_execution_server_state`` singleton — a
        stale runtime whose cached epoch/boot_id no longer match cannot mint.

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
            # Batch 2.5 §2: verify persisted boot context first.
            if not self._verify_persisted_boot_context(
                server_epoch=server_epoch, boot_id=boot_id,
            ):
                self._conn.rollback()
                return False, None
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
                    issued_at, expires_at, nonce_hash, binding_digest, status, server_epoch, boot_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    auth.authorization_id, auth.approval_request_id, auth.plan_id,
                    auth.plan_content_hash, auth.repository_id, auth.task_id,
                    auth.workspace_id, auth.base_sha, int(auth.repository_generation),
                    float(auth.issued_at), float(auth.expires_at), auth.nonce_hash,
                    auth.binding_digest, auth.status.value, int(server_epoch), boot_id,
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
        current_boot_id: str = "",
        audit_event: PlanApprovalAuditEvent | None = None,
        now: float,
    ) -> bool:
        """Atomically consume an authorization AND flip its request to CONSUMED.

        Verifies (all within one ``BEGIN IMMEDIATE``):
        1. Persisted boot context matches supplied epoch + boot_id (§2).
        2. Authorization exists, is ACTIVE, and belongs to the caller's scope.
        3. The nonce hashes to the stored ``nonce_hash``.
        4. The authorization has not expired and its ``server_epoch`` +
           ``boot_id`` match the current boot (restart-invalidation).
        5. The bound binding digest equals ``expected_binding_digest`` (drift
           check at consume time — §6).
        6. The request is still APPROVED/NOT_REQUIRED.

        On success: authorization → CONSUMED, request → CONSUMED, audit
        written, all committed atomically. Any mismatch rolls back.
        """
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            # Batch 2.5 §2: verify persisted boot context first.
            if not self._verify_persisted_boot_context(
                server_epoch=current_server_epoch, boot_id=current_boot_id,
            ):
                self._conn.rollback()
                return False
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
            if int(row["server_epoch"]) != int(current_server_epoch) or str(row["boot_id"]) != current_boot_id:
                # Restart-invalidation: authorization minted under a prior boot.
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

    def revoke_authorization(
        self, authorization_id: str, *,
        current_server_epoch: int = 0, current_boot_id: str = "",
    ) -> bool:
        """Externally invalidate an authorization (e.g. on Task cancel).

        Batch 2.5 §2: verifies the persisted boot context before revoking.
        A stale runtime cannot revoke authorizations from a newer boot.
        """
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            if not self._verify_persisted_boot_context(
                server_epoch=current_server_epoch, boot_id=current_boot_id,
            ):
                self._conn.rollback()
                return False
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
                "SELECT current_epoch,boot_id FROM plan_execution_server_state WHERE singleton_key = 'global'"
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
                    "UPDATE approval_runtime_boots SET replaced_at=? "
                    "WHERE boot_id=? AND replaced_at IS NULL",
                    (now, str(row["boot_id"])),
                )
                self._conn.execute(
                    "UPDATE plan_execution_server_state SET current_epoch = ?, boot_id = ?, updated_at = ? "
                    "WHERE singleton_key = 'global'",
                    (new_epoch, new_boot_id, now),
                )
            self._conn.execute(
                "INSERT INTO approval_runtime_boots "
                "(server_epoch,boot_id,started_at,replaced_at) VALUES (?,?,?,NULL)",
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

    def release_lease(
        self, lease_id: str, *,
        current_server_epoch: int = 0, current_boot_id: str = "",
    ) -> bool:
        """Release (mark released) an execution lease.

        Batch 2.5 §2: verifies the persisted boot context before releasing.
        A stale runtime cannot release leases from a newer boot.
        """
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            if not self._verify_persisted_boot_context(
                server_epoch=current_server_epoch, boot_id=current_boot_id,
            ):
                self._conn.rollback()
                return False
            cur = self._conn.execute(
                "UPDATE plan_execution_leases SET status = 'released' "
                "WHERE lease_id = ? AND status = 'active'",
                (lease_id,),
            )
            ok = int(cur.rowcount or 0) > 0
            if ok:
                lease = self._conn.execute(
                    "SELECT workspace_id FROM plan_execution_leases WHERE lease_id=?",
                    (lease_id,),
                ).fetchone()
                self._conn.execute(
                    "INSERT INTO workspace_mutation_audit "
                    "(event_id,workspace_id,lease_id,event_type,reason,created_at) "
                    "VALUES (?,?,?,?,?,?)",
                    (uuid.uuid4().hex, str(lease["workspace_id"]), lease_id,
                     "released", "context-exit", time.time()),
                )
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

    def active_lease_scope_for_task(self, task_id: str) -> str | None:
        """Resolve a task's unique ACTIVE workspace from durable leases."""
        rows = self._conn.execute(
            "SELECT DISTINCT workspace_id FROM plan_execution_leases "
            "WHERE task_id=? AND status='active' ORDER BY workspace_id",
            (task_id,),
        ).fetchall()
        if len(rows) > 1:
            raise RuntimeError("task has ACTIVE leases in multiple workspaces")
        return None if not rows else str(rows[0]["workspace_id"])

    def validate_repository_workspace_scope(
        self, repository_id: str, workspace_id: str
    ) -> bool:
        """Reject ambiguity while validating an explicit mutation scope."""
        rows = self._conn.execute(
            "SELECT DISTINCT workspace_id FROM plan_execution_leases "
            "WHERE repository_id=? AND status='active' ORDER BY workspace_id",
            (repository_id,),
        ).fetchall()
        active = {str(row["workspace_id"]) for row in rows}
        return not active or workspace_id in active

    def poison_workspace(self, workspace_id: str, lease_id: str, *, reason: str) -> None:
        """Persist quarantine before a failed release exits the fence."""
        now = time.time()
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            self._conn.execute(
                "INSERT OR REPLACE INTO workspace_mutation_poison "
                "(workspace_id,lease_id,reason,poisoned_at) VALUES (?,?,?,?)",
                (workspace_id, lease_id, reason, now),
            )
            self._conn.execute(
                "INSERT INTO workspace_mutation_audit "
                "(event_id,workspace_id,lease_id,event_type,reason,created_at) "
                "VALUES (?,?,?,?,?,?)",
                (uuid.uuid4().hex, workspace_id, lease_id, "poisoned", reason, now),
            )
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    def list_poisoned_workspaces(self) -> tuple[tuple[str, str], ...]:
        rows = self._conn.execute(
            "SELECT workspace_id,reason FROM workspace_mutation_poison "
            "ORDER BY workspace_id"
        ).fetchall()
        return tuple((str(row["workspace_id"]), str(row["reason"])) for row in rows)

    def add_workspace_poison_scope(
        self, workspace_id: str, *, owner: str, reason: str
    ) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO workspace_mutation_poison_scopes "
            "(workspace_id,poison_owner,reason,poisoned_at) VALUES (?,?,?,?)",
            (workspace_id, owner, reason, time.time()),
        )
        self._conn.commit()

    def clear_workspace_poison_scope(self, workspace_id: str, *, owner: str) -> bool:
        cur = self._conn.execute(
            "DELETE FROM workspace_mutation_poison_scopes "
            "WHERE workspace_id=? AND poison_owner=?",
            (workspace_id, owner),
        )
        self._conn.commit()
        return int(cur.rowcount or 0) == 1

    def list_workspace_poison_scopes(
        self, workspace_id: str | None = None
    ) -> tuple[tuple[str, str, str], ...]:
        if workspace_id is None:
            rows = self._conn.execute(
                "SELECT workspace_id,poison_owner,reason "
                "FROM workspace_mutation_poison_scopes "
                "ORDER BY workspace_id,poison_owner"
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT workspace_id,poison_owner,reason "
                "FROM workspace_mutation_poison_scopes WHERE workspace_id=? "
                "ORDER BY poison_owner", (workspace_id,),
            ).fetchall()
        return tuple(
            (str(row["workspace_id"]), str(row["poison_owner"]), str(row["reason"]))
            for row in rows
        )

    def reconcile_terminal_run_poison_scopes(self) -> tuple[tuple[str, str], ...]:
        rows = self._conn.execute(
            "SELECT p.workspace_id,p.poison_owner FROM workspace_mutation_poison_scopes p "
            "JOIN plan_execution_runs r ON p.poison_owner='run:' || r.execution_run_id "
            "WHERE r.status IN ('mutated','rolled-back','cancelled') "
            "AND r.terminal_tombstone_digest != ''"
        ).fetchall()
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            for row in rows:
                self._conn.execute(
                    "DELETE FROM workspace_mutation_poison_scopes WHERE workspace_id=? AND poison_owner=?",
                    (row["workspace_id"], row["poison_owner"]),
                )
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise
        return tuple((str(row["workspace_id"]), str(row["poison_owner"])) for row in rows)

    def recover_poisoned_workspace(
        self, workspace_id: str, *, force: bool = False, now: float | None = None
    ) -> bool:
        """Expire the quarantined lease, clear poison, and write recovery audit."""
        now = time.time() if now is None else now
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            poison = self._conn.execute(
                "SELECT lease_id,reason FROM workspace_mutation_poison WHERE workspace_id=?",
                (workspace_id,),
            ).fetchone()
            if poison is None:
                self._conn.rollback()
                return False
            lease = self._conn.execute(
                "SELECT status,expiry FROM plan_execution_leases WHERE lease_id=?",
                (poison["lease_id"],),
            ).fetchone()
            if (lease is not None and lease["status"] == "active"
                    and float(lease["expiry"]) > now and not force):
                self._conn.rollback()
                raise RuntimeError("active poisoned lease has not expired")
            self._conn.execute(
                "UPDATE plan_execution_leases SET status='expired' "
                "WHERE lease_id=? AND status='active'",
                (poison["lease_id"],),
            )
            self._conn.execute(
                "DELETE FROM workspace_mutation_poison WHERE workspace_id=?",
                (workspace_id,),
            )
            self._conn.execute(
                "INSERT INTO workspace_mutation_audit "
                "(event_id,workspace_id,lease_id,event_type,reason,created_at) "
                "VALUES (?,?,?,?,?,?)",
                (uuid.uuid4().hex, workspace_id, poison["lease_id"],
                 "recovered", "forced" if force else "expired", now),
            )
            self._conn.commit()
            return True
        except Exception:
            self._conn.rollback()
            raise

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
        current_boot_id: str = "",
        lease_id: str,
        owner_execution_id: str,
        head_sha: str,
        repository_generation: int,
        evidence_digest: str,
        audit_event: "PlanApprovalAuditEvent | None",
        now: float,
    ) -> bool:
        """Lease-first atomic consume: ONE ``BEGIN IMMEDIATE`` does ALL of:

        1. Verify persisted boot context matches supplied epoch + boot_id (§2).
        2. Read authorization; verify ACTIVE, scope, nonce, epoch, boot_id,
           expiry, binding.
        3. Read approval request; verify APPROVED/NOT_REQUIRED.
        4. Confirm workspace has NO existing ACTIVE lease (else rollback).
        5. Insert ACTIVE lease (stamped with current epoch + boot_id).
        6. Authorization → CONSUMED.
        7. Request → CONSUMED.
        8. Insert audit event.
        9. COMMIT.

        Any step failing rolls back the ENTIRE transaction: the authorization
        stays ACTIVE, the request stays APPROVED/NOT_REQUIRED, no lease row
        exists, no audit row exists. This closes the TOCTOU between consume
        and lease-acquire that the old two-step path had.
        """
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            # 1. Batch 2.5 §2: verify persisted boot context first.
            if not self._verify_persisted_boot_context(
                server_epoch=current_server_epoch, boot_id=current_boot_id,
            ):
                self._conn.rollback()
                return False
            # 2. Read + verify the authorization.
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
            if int(auth_row["server_epoch"]) != int(current_server_epoch) or str(auth_row["boot_id"]) != current_boot_id:
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

            # 3. Read + verify the approval request.
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

            # 4 + 5. Insert the ACTIVE lease. The partial unique index
            # uq_plan_execution_leases_active_workspace makes a conflicting
            # ACTIVE lease raise IntegrityError → rollback (no consume).
            self._conn.execute(
                """
                INSERT INTO plan_execution_leases (
                    lease_id, task_id, workspace_id, repository_id, plan_id,
                    head_sha, repository_generation, evidence_digest, binding_digest,
                    authorization_id, expiry, owner_execution_id, status, server_epoch, boot_id, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?)
                """,
                (
                    lease_id, expected_task_id, expected_workspace_id, expected_repository_id,
                    expected_plan_id, head_sha, int(repository_generation),
                    evidence_digest, expected_binding_digest, authorization_id,
                    float(auth_row["expires_at"]), owner_execution_id,
                    int(current_server_epoch), current_boot_id, now,
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
        current_boot_id: str = "",
        now: float,
    ) -> bool:
        """Verify a lease is ACTIVE, owned by the caller, scope-correct,
        unexpired, and bound to the current boot epoch + boot_id.

        Batch 2.5 §2: verifies the persisted boot context matches the
        supplied epoch + boot_id BEFORE checking the lease. A stale runtime
        whose cached epoch/boot_id no longer match the persisted state
        cannot validate contexts.

        Every Batch 3 execution entry must call this BEFORE touching the
        workspace. Returns True if the lease is valid; False otherwise.
        """
        if self._conn.in_transaction:
            self._conn.commit()
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            # Batch 2.5 §2: verify persisted boot context first.
            if not self._verify_persisted_boot_context(
                server_epoch=current_server_epoch, boot_id=current_boot_id,
            ):
                self._conn.rollback()
                return False
            row = self._conn.execute(
                "SELECT * FROM plan_execution_leases WHERE lease_id = ?",
                (lease_id,),
            ).fetchone()
            if row is None:
                self._conn.rollback()
                return False
            if row["status"] != "active":
                self._conn.rollback()
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
                self._conn.rollback()
                return False
            if (
                row["task_id"] != expected_task_id
                or row["workspace_id"] != expected_workspace_id
                or row["repository_id"] != expected_repository_id
                or row["plan_id"] != expected_plan_id
            ):
                self._conn.rollback()
                return False
            if int(row["server_epoch"]) != int(current_server_epoch) or str(row["boot_id"]) != current_boot_id:
                self._conn.rollback()
                return False
            auth = self._conn.execute(
                "SELECT status,binding_digest,approval_request_id,boot_id FROM plan_execution_authorizations WHERE authorization_id=?",
                (row["authorization_id"],),
            ).fetchone()
            if auth is None or auth["status"] != AuthorizationStatus.CONSUMED.value:
                self._conn.rollback()
                return False
            if auth["binding_digest"] != row["binding_digest"]:
                self._conn.rollback()
                return False
            request = self._conn.execute(
                "SELECT status,binding_digest FROM plan_approval_requests WHERE approval_request_id=?",
                (auth["approval_request_id"],),
            ).fetchone()
            if request is None or request["status"] != PlanApprovalStatus.CONSUMED.value:
                self._conn.rollback()
                return False
            if request["binding_digest"] != row["binding_digest"]:
                self._conn.rollback()
                return False
            self._conn.commit()
            return True
        except Exception:
            self._conn.rollback()
            raise

    def invalidate_active_execution_scope(
        self,
        *,
        task_id: str | None = None,
        workspace_id: str | None = None,
        owner_execution_id: str | None = None,
        boot_id: str | None = None,
        reason: str = "execution-cancelled",
        now: float | None = None,
    ) -> int:
        """Atomically invalidate all ACTIVE leases + authorizations matching
        the given scope, WITHOUT rolling back CONSUMED approval requests.

        Batch 2.5 §3: a Task cancel / Workspace cleanup / Runtime shutdown
        must be able to terminate the ACTIVE lease of a CONSUMED approval
        request. The old ``invalidate_request_authorizations_leases_and_receipt``
        tried to transition CONSUMED → REVOKED which is an illegal rollback.
        This method does NOT touch the approval request status at all — it
        only expires the lease and revokes still-ACTIVE authorizations.

        Batch 2.5 §7: when ``boot_id`` is supplied and all scope params are
        None, cancels ALL active leases for that boot (used by
        ``Runtime.shutdown``). When scope params are supplied, they filter
        within the matching set (optionally also filtered by boot_id).

        ONE ``BEGIN IMMEDIATE``:
        1. Find matching ACTIVE leases (by task_id and/or workspace_id and/or
           owner_execution_id, and/or boot_id).
        2. Each matching lease → 'cancelled'.
        3. For each lease's authorization_id: if the authorization is still
           ACTIVE, revoke it. (CONSUMED authorizations stay CONSUMED.)
        4. Write an execution-cancelled audit event per lease.
        5. COMMIT.

        Returns the count of invalidated leases.
        """
        if (task_id is None and workspace_id is None
                and owner_execution_id is None and boot_id is None):
            return 0
        now = time.time() if now is None else now
        if self._conn.in_transaction:
            self._conn.commit()
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            # Build the WHERE clause for matching ACTIVE leases.
            clauses = ["status = 'active'"]
            params: list[Any] = []
            if task_id is not None:
                clauses.append("task_id = ?")
                params.append(task_id)
            if workspace_id is not None:
                clauses.append("workspace_id = ?")
                params.append(workspace_id)
            if owner_execution_id is not None:
                clauses.append("owner_execution_id = ?")
                params.append(owner_execution_id)
            if boot_id is not None:
                clauses.append("boot_id = ?")
                params.append(boot_id)
            where = " AND ".join(clauses)
            leases = self._conn.execute(
                f"SELECT lease_id, task_id, workspace_id, repository_id, plan_id, "
                f"authorization_id, owner_execution_id FROM plan_execution_leases WHERE {where}",
                tuple(params),
            ).fetchall()
            invalidated = 0
            for lease in leases:
                # Expire the lease.
                self._conn.execute(
                    "UPDATE plan_execution_leases SET status = 'cancelled' WHERE lease_id = ?",
                    (lease["lease_id"],),
                )
                # Revoke the authorization if still ACTIVE (not CONSUMED).
                auth_row = self._conn.execute(
                    "SELECT status, approval_request_id, plan_id FROM plan_execution_authorizations "
                    "WHERE authorization_id = ?",
                    (lease["authorization_id"],),
                ).fetchone()
                if auth_row is not None and auth_row["status"] == AuthorizationStatus.ACTIVE.value:
                    self._conn.execute(
                        "UPDATE plan_execution_authorizations SET status = ? WHERE authorization_id = ?",
                        (AuthorizationStatus.REVOKED.value, lease["authorization_id"]),
                    )
                # Write execution-cancelled audit. Use the approval_request_id
                # from the auth row if available, else empty.
                req_id = auth_row["approval_request_id"] if auth_row is not None else ""
                plan_id = auth_row["plan_id"] if auth_row is not None else lease["plan_id"]
                audit_id = f"audit_{uuid.uuid4().hex}"
                self._conn.execute(
                    """
                    INSERT INTO plan_approval_audit_events (
                        event_id, event_type, approval_request_id, plan_id, previous_status,
                        new_status, actor_id, actor_type, authenticated_source, timestamp,
                        reason_code, task_id, workspace_id, repository_id, correlation_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        audit_id, "execution:cancelled", req_id, plan_id,
                        "active", "cancelled",
                        "system", "system", "runtime-shutdown",
                        float(now), reason,
                        lease["task_id"], lease["workspace_id"],
                        lease["repository_id"], lease["lease_id"],
                    ),
                )
                invalidated += 1
            self._conn.commit()
            return invalidated
        except Exception:
            self._conn.rollback()
            raise

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

    # ------------------------------------------------------------------
    # Batch 3 execution journal
    # ------------------------------------------------------------------

    def create_execution_run(self, run: Any) -> Any:
        """Create one run per authorization/context, or return idempotent run."""
        existing = self.get_execution_run_by_context(run.execution_context_id)
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
                (run.execution_run_id, run.plan_id, run.plan_content_hash,
                 run.approval_request_id, run.authorization_id,
                 run.execution_context_id, run.lease_id, run.task_id,
                 run.workspace_id, run.repository_id, run.base_sha,
                 int(run.repository_generation), run.binding_digest,
                 run.edit_bundle_digest, run.status.value, run.started_at,
                 run.updated_at, run.completed_at, run.failure_code,
                 json.dumps(
                     {"edit_count": int(run.metadata.get("edit_count", 0))},
                     sort_keys=True, separators=(",", ":"),
                 )),
            )
            self._insert_execution_audit(
                run.execution_run_id, "run-created", result="created",
                correlation_id=run.execution_context_id,
            )
            self._conn.commit()
            return run
        except sqlite3.IntegrityError:
            self._conn.rollback()
            existing = self.get_execution_run_by_context(run.execution_context_id)
            if existing is None:
                raise
            return existing
        except Exception:
            self._conn.rollback()
            raise

    def transition_execution_run(
        self, execution_run_id: str, *, expected: tuple[str, ...], target: str,
        failure_code: str = "", completed: bool = False,
    ) -> None:
        allowed = {
            "created": frozenset({"validating", "cancelled"}),
            "validating": frozenset({"mutating", "rolling-back", "failed", "poisoned", "cancelled"}),
            "mutating": frozenset({"sealing", "rolling-back", "poisoned", "cancelled", "failed"}),
            "sealing": frozenset({"mutated", "poisoned"}),
            "rolling-back": frozenset({"rollback-sealing", "poisoned"}),
            "rollback-sealing": frozenset({"rolled-back", "poisoned", "cancelled"}),
            "poisoned": frozenset({"rolling-back"}),
        }
        if not expected or any(target not in allowed.get(source, frozenset()) for source in expected):
            raise RuntimeError("invalid execution run state transition")
        now = time.time()
        placeholders = ",".join("?" for _ in expected)
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            cur = self._conn.execute(
                f"UPDATE plan_execution_runs SET status=?,updated_at=?,"
                "completed_at=?,failure_code=? WHERE execution_run_id=? "
                f"AND status IN ({placeholders})",
                (target, now, now if completed else None, failure_code,
                 execution_run_id, *expected),
            )
            if int(cur.rowcount or 0) != 1:
                raise RuntimeError("invalid execution run transition")
            self._insert_execution_audit(
                execution_run_id, "run-transition", result=target,
                error_code=failure_code, correlation_id=execution_run_id,
            )
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    def begin_or_resume_rollback(
        self, execution_run_id: str, *, failure_code: str,
        now: float | None = None,
    ) -> "RollbackResumeState":
        """Atomically begin or resume rollback without overwriting its reason."""
        from khaos.coding.planning.execution_models import (
            ExecutionRunStatus, RollbackResumeDisposition, RollbackResumeState,
        )

        timestamp = time.time() if now is None else float(now)
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            row = self._conn.execute(
                "SELECT status,failure_code FROM plan_execution_runs "
                "WHERE execution_run_id=?", (execution_run_id,),
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
                self._insert_execution_audit(
                    execution_run_id, "rollback-started", result="rolling-back",
                    error_code=effective_reason, correlation_id=execution_run_id,
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

    def insert_edit_event(
        self, *, event_id: str, execution_run_id: str, edit_id: str,
        ordinal: int, operation: str, path: str, destination_path: str | None,
        before_hash: str | None, before_mode: int | None,
        recovery_artifact: str | None, planned_after_hash: str = "",
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
                (event_id, execution_run_id, edit_id, ordinal, operation, path,
                 destination_path, before_hash, planned_after_hash, before_mode,
                 planned_after_mode,
                 recovery_artifact,
                 now, now),
            )
            cur = self._conn.execute(
                "UPDATE plan_execution_runs SET journaled_edit_count="
                "journaled_edit_count+1 WHERE execution_run_id=? AND status='mutating'",
                (execution_run_id,),
            )
            if int(cur.rowcount or 0) != 1:
                raise RuntimeError("run cannot accept journal event")
            self._insert_execution_audit(
                execution_run_id, "edit-journaled", operation=operation, path=path,
                before_hash=before_hash or "", result="journaled",
                correlation_id=edit_id,
            )
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    def transition_edit_event(
        self, execution_run_id: str, edit_id: str, *, expected_phase: str,
        target_phase: str,
        after_hash: str | None = None, after_mode: int | None = None,
        error_code: str = "",
        applied_identity_digest: str | None = None,
        applied_parent_identity_digest: str | None = None,
        applied_destination_identity_digest: str | None = None,
    ) -> None:
        """Advance one edit phase using a transactionally checked CAS."""
        from khaos.coding.planning.execution_models import DurableEditPhase

        transitions = {
            DurableEditPhase.JOURNALED.value: frozenset({
                DurableEditPhase.MUTATION_STARTED.value,
                DurableEditPhase.ROLLED_BACK.value,
            }),
            DurableEditPhase.MUTATION_STARTED.value: frozenset({
                DurableEditPhase.FILESYSTEM_APPLIED.value,
                DurableEditPhase.ROLLED_BACK.value,
            }),
            DurableEditPhase.FILESYSTEM_APPLIED.value: frozenset({
                DurableEditPhase.DIRECTORY_SYNCED.value,
                DurableEditPhase.ROLLBACK_STARTED.value,
            }),
            DurableEditPhase.DIRECTORY_SYNCED.value: frozenset({
                DurableEditPhase.APPLIED.value,
                DurableEditPhase.ROLLBACK_STARTED.value,
            }),
            DurableEditPhase.APPLIED.value: frozenset({
                DurableEditPhase.ROLLBACK_STARTED.value,
            }),
            DurableEditPhase.ROLLBACK_STARTED.value: frozenset(),
            DurableEditPhase.ROLLBACK_FILESYSTEM_APPLIED.value: frozenset(),
            DurableEditPhase.ROLLBACK_DIRECTORY_SYNCED.value: frozenset({
                DurableEditPhase.ROLLED_BACK.value,
            }),
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
                if applied_identity_digest is None else applied_identity_digest
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
                if (stored_after_hash != row["after_hash"]
                        or stored_after_mode != row["after_mode"]
                        or error_code != str(row["error_code"] or "")
                        or stored_identity != row["applied_identity_digest"]
                        or stored_parent_identity
                        != row["applied_parent_identity_digest"]
                        or stored_destination_identity
                        != row["applied_destination_identity_digest"]):
                    raise RuntimeError("idempotent edit phase retry changed state")
                self._conn.commit()
                return
            if row["status"] in {
                DurableEditPhase.APPLIED.value,
                DurableEditPhase.ROLLBACK_STARTED.value,
                DurableEditPhase.ROLLBACK_FILESYSTEM_APPLIED.value,
                DurableEditPhase.ROLLBACK_DIRECTORY_SYNCED.value,
                DurableEditPhase.ROLLED_BACK.value,
            } and (stored_after_hash != row["after_hash"]
                   or stored_after_mode != row["after_mode"]):
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
            if target_phase == DurableEditPhase.ROLLED_BACK.value:
                if expected_phase == DurableEditPhase.ROLLBACK_DIRECTORY_SYNCED.value:
                    if (int(row["identity_version"]) != 3
                            or not row["rollback_identity_digest"]
                            or not row["rollback_parent_identity_digest"]
                            or int(row["rollback_sync_mask"]) not in {1, 3}
                            or not row["rollback_directory_sync_digest"]
                            or row["rollback_synced_at"] is None):
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
                (target_phase, stored_after_hash, stored_after_mode, error_code, now,
                 next_version, stored_identity, stored_parent_identity,
                 stored_destination_identity, next_identity_version,
                 execution_run_id, edit_id, expected_phase,
                 int(row["phase_version"])),
            )
            if int(cur.rowcount or 0) != 1:
                raise RuntimeError("execution edit phase CAS conflict")
            self._insert_execution_audit(
                execution_run_id, "edit-transition", operation=row["operation"],
                path=row["path"], before_hash=row["before_hash"] or "",
                after_hash=stored_after_hash or "", result=target_phase,
                error_code=error_code,
                correlation_id=edit_id,
            )
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    def record_rollback_filesystem_applied(
        self, execution_run_id: str, edit_id: str, *,
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
                (rollback_identity_digest, rollback_parent_identity_digest,
                 rollback_destination_parent_identity_digest, rollback_sync_mask,
                 error_code, now, execution_run_id, edit_id, expected_phase,
                 int(row["phase_version"])),
            )
            if int(cur.rowcount or 0) != 1:
                raise RuntimeError("rollback filesystem phase CAS conflict")
            self._insert_execution_audit(
                execution_run_id, "rollback-filesystem-applied",
                operation=row["operation"], path=row["path"],
                result="rollback-filesystem-applied", error_code=error_code,
                correlation_id=edit_id,
            )
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    @staticmethod
    def _rollback_directory_sync_digest(
        *, execution_run_id: str, edit_id: str,
        parent_identity_digest: str,
        destination_parent_identity_digest: str,
        sync_mask: int,
    ) -> str:
        payload = {
            "execution_run_id": execution_run_id,
            "edit_id": edit_id,
            "parent_identity_digest": parent_identity_digest,
            "destination_parent_identity_digest": (
                destination_parent_identity_digest
            ),
            "sync_mask": sync_mask,
            "phase": "rollback-directory-synced",
        }
        return hashlib.sha256(json.dumps(
            payload, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")).hexdigest()

    def record_rollback_directory_synced(
        self, execution_run_id: str, edit_id: str, *, error_code: str,
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
                execution_run_id=execution_run_id, edit_id=edit_id,
                parent_identity_digest=str(
                    row["rollback_parent_identity_digest"] or ""
                ),
                destination_parent_identity_digest=str(
                    row["rollback_destination_parent_identity_digest"] or ""
                ),
                sync_mask=int(row["rollback_sync_mask"]),
            )
            if row["status"] == "rollback-directory-synced":
                if (str(row["rollback_directory_sync_digest"] or "") != digest
                        or row["rollback_synced_at"] is None
                        or int(row["identity_version"]) != 3):
                    raise RuntimeError("rollback directory sync CAS conflict")
                self._conn.commit()
                return digest
            if (row["status"] != "rollback-filesystem-applied"
                    or int(row["identity_version"]) != 2
                    or not row["rollback_identity_digest"]
                    or not row["rollback_parent_identity_digest"]
                    or int(row["rollback_sync_mask"]) not in {1, 3}
                    or (int(row["rollback_sync_mask"]) == 3
                        and not row["rollback_destination_parent_identity_digest"])):
                raise RuntimeError("rollback filesystem evidence missing")
            cur = self._conn.execute(
                "UPDATE plan_execution_edit_events "
                "SET status='rollback-directory-synced',"
                "rollback_directory_sync_digest=?,rollback_synced_at=?,"
                "identity_version=3,updated_at=?,phase_version=phase_version+1 "
                "WHERE execution_run_id=? AND edit_id=? "
                "AND status='rollback-filesystem-applied' AND phase_version=? "
                "AND identity_version=2 AND rollback_directory_sync_digest=''",
                (digest, now, now, execution_run_id, edit_id,
                 int(row["phase_version"])),
            )
            if int(cur.rowcount or 0) != 1:
                raise RuntimeError("rollback directory sync CAS conflict")
            self._insert_execution_audit(
                execution_run_id, "rollback-directory-synced",
                operation=row["operation"], path=row["path"],
                result="rollback-directory-synced", error_code=error_code,
                correlation_id=edit_id,
            )
            self._conn.commit()
            return digest
        except Exception:
            self._conn.rollback()
            raise

    def update_edit_event(
        self, execution_run_id: str, edit_id: str, *, status: str,
        after_hash: str | None = None, after_mode: int | None = None,
        error_code: str = "",
        applied_identity_digest: str | None = None,
        applied_parent_identity_digest: str | None = None,
        applied_destination_identity_digest: str | None = None,
    ) -> None:
        """Compatibility facade; it no longer accepts arbitrary phase writes."""
        row = self._conn.execute(
            "SELECT status FROM plan_execution_edit_events "
            "WHERE execution_run_id=? AND edit_id=?",
            (execution_run_id, edit_id),
        ).fetchone()
        if row is None:
            raise RuntimeError("execution edit event not found")
        self.transition_edit_event(
            execution_run_id, edit_id, expected_phase=str(row["status"]),
            target_phase=status, after_hash=after_hash, after_mode=after_mode,
            error_code=error_code,
            applied_identity_digest=applied_identity_digest,
            applied_parent_identity_digest=applied_parent_identity_digest,
            applied_destination_identity_digest=applied_destination_identity_digest,
        )

    def mark_execution_recovery_sealed(
        self, execution_run_id: str, *, seal_digest: str
    ) -> None:
        now = time.time()
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            cur = self._conn.execute(
                "UPDATE plan_execution_runs SET recovery_sealed_at=?,"
                "recovery_seal_digest=?,updated_at=? WHERE execution_run_id=? "
                "AND status='sealing'",
                (now, seal_digest, now, execution_run_id),
            )
            if int(cur.rowcount or 0) != 1:
                raise RuntimeError("execution run is not sealing")
            self._insert_execution_audit(
                execution_run_id, "recovery-sealed", result="sealed",
                correlation_id=execution_run_id,
            )
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    def mark_execution_rollback_sealed(
        self, execution_run_id: str, *, seal_digest: str
    ) -> None:
        now = time.time()
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            cur = self._conn.execute(
                "UPDATE plan_execution_runs SET rollback_sealed_at=?,"
                "rollback_seal_digest=?,updated_at=? WHERE execution_run_id=? "
                "AND status='rollback-sealing'",
                (now, seal_digest, now, execution_run_id),
            )
            if int(cur.rowcount or 0) != 1:
                raise RuntimeError("execution run is not rollback-sealing")
            self._insert_execution_audit(
                execution_run_id, "rollback-recovery-sealed", result="sealed",
                correlation_id=execution_run_id,
            )
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    def save_final_mutation_attestation(self, attestation: Any) -> None:
        normalized = attestation.normalized()
        payload = json.dumps(
            normalized.canonical(), ensure_ascii=False, sort_keys=True,
            separators=(",", ":"),
        )
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            self._conn.execute(
                "INSERT INTO plan_execution_final_attestations "
                "(execution_run_id,bundle_digest,canonical_json,attestation_digest,attested_at) "
                "VALUES (?,?,?,?,?)",
                (normalized.execution_run_id, normalized.bundle_digest, payload,
                 normalized.attestation_digest, normalized.attested_at),
            )
            self._insert_execution_audit(
                normalized.execution_run_id, "final-mutation-attested",
                result="attested", correlation_id=normalized.attestation_digest,
            )
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    def save_initial_workspace_attestation(self, attestation: Any) -> None:
        value = attestation.normalized()
        payload = json.dumps({
            **value.__dict__,
            "declared_states": [item.__dict__ for item in value.declared_states],
            "workspace_states": [item.__dict__ for item in value.workspace_states],
            "approved_edits": [item.canonical() for item in value.approved_edits],
        }, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
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
            self._insert_execution_audit(
                value.execution_run_id, "initial-workspace-attested", result="attested",
                correlation_id=value.attestation_digest,
            )
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    def get_initial_workspace_attestation(self, run_id: str) -> Any | None:
        row = self._conn.execute(
            "SELECT canonical_json,attestation_digest FROM plan_execution_initial_attestations "
            "WHERE execution_run_id=?", (run_id,),
        ).fetchone()
        if row is None:
            return None
        from khaos.coding.planning.execution_models import (
            InitialApprovedEdit, InitialPathState, InitialWorkspaceAttestation,
            PlannedEditOperation,
        )
        try:
            payload = json.loads(row["canonical_json"])
            value = InitialWorkspaceAttestation(
                **{key: val for key, val in payload.items() if key not in {
                    "declared_states", "workspace_states", "approved_edits",
                }},
                declared_states=tuple(InitialPathState(**item) for item in payload["declared_states"]),
                workspace_states=tuple(InitialPathState(**item) for item in payload["workspace_states"]),
                approved_edits=tuple(InitialApprovedEdit(
                    **{**item, "operation": PlannedEditOperation(item["operation"])}
                ) for item in payload.get("approved_edits", ())),
            )
        except Exception as exc:
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
            AttestedPathState, FinalMutationAttestation,
        )
        try:
            payload = json.loads(row["canonical_json"])
            value = FinalMutationAttestation(
                execution_run_id=payload["execution_run_id"],
                bundle_digest=payload["bundle_digest"],
                ordered_states=tuple(AttestedPathState(**item) for item in payload["ordered_states"]),
                path_state_digest=payload["path_state_digest"], head=payload["head"],
                generation=int(payload["generation"]), index_digest=payload["index_digest"],
                worktree_admin_digest=payload["worktree_admin_digest"],
                workspace_state_digest=payload["workspace_state_digest"],
                execution_context_id=payload["execution_context_id"],
                lease_id=payload["lease_id"], binding_digest=payload["binding_digest"],
                attested_at=float(payload["attested_at"]),
                attestation_digest=row["attestation_digest"],
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise RuntimeError("final mutation attestation is corrupt") from exc
        normalized = value.normalized()
        if (normalized.attestation_digest != row["attestation_digest"]
                or normalized.bundle_digest != row["bundle_digest"]
                or normalized.canonical() != value.canonical()):
            raise RuntimeError("final mutation attestation digest mismatch")
        return normalized

    def save_rollback_final_attestation(self, attestation: Any) -> None:
        normalized = attestation.normalized()
        payload = json.dumps(
            normalized.canonical(), ensure_ascii=False, sort_keys=True,
            separators=(",", ":"),
        )
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            self._conn.execute(
                "INSERT INTO plan_execution_rollback_attestations "
                "(execution_run_id,bundle_digest,canonical_json,attestation_digest,attested_at) "
                "VALUES (?,?,?,?,?)",
                (normalized.execution_run_id, normalized.bundle_digest, payload,
                 normalized.attestation_digest, normalized.attested_at),
            )
            self._insert_execution_audit(
                normalized.execution_run_id, "rollback-final-attested",
                result="attested", correlation_id=normalized.attestation_digest,
            )
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    def get_rollback_final_attestation(self, execution_run_id: str) -> Any | None:
        row = self._conn.execute(
            "SELECT * FROM plan_execution_rollback_attestations WHERE execution_run_id=?",
            (execution_run_id,),
        ).fetchone()
        if row is None:
            return None
        from khaos.coding.planning.execution_models import (
            AttestedPathState, RollbackFinalAttestation,
        )
        try:
            payload = json.loads(row["canonical_json"])
            value = RollbackFinalAttestation(
                execution_run_id=payload["execution_run_id"],
                bundle_digest=payload["bundle_digest"],
                ordered_states=tuple(AttestedPathState(**item) for item in payload["ordered_states"]),
                path_state_digest=payload["path_state_digest"], head=payload["head"],
                generation=int(payload["generation"]), index_digest=payload["index_digest"],
                worktree_admin_digest=payload["worktree_admin_digest"],
                workspace_state_digest=payload["workspace_state_digest"],
                execution_context_id=payload["execution_context_id"],
                lease_id=payload["lease_id"], binding_digest=payload["binding_digest"],
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

    def commit_terminal_seal(
        self, execution_run_id: str, *, expected_status: str, terminal_status: str,
        seal_digest: str, tombstone_digest: str, rollback: bool,
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
                (terminal_status, now, now, failure_code, now, seal_digest,
                 tombstone_digest, execution_run_id, expected_status),
            )
            if int(cur.rowcount or 0) != 1:
                raise RuntimeError("invalid terminal seal transition")
            self._insert_execution_audit(
                execution_run_id, "terminal-seal-committed", result=terminal_status,
                error_code=failure_code, correlation_id=tombstone_digest,
            )
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    def commit_recovered_terminal_state(self, *, workspace_id: str, poison_owner: str,
                                        **kwargs: Any) -> None:
        execution_run_id = kwargs["execution_run_id"]
        now = time.time()
        rollback = bool(kwargs["rollback"])
        seal_time = "rollback_sealed_at" if rollback else "recovery_sealed_at"
        seal_column = "rollback_seal_digest" if rollback else "recovery_seal_digest"
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            proof = (
                self.get_rollback_final_attestation(execution_run_id)
                if rollback else self.get_final_mutation_attestation(execution_run_id)
            )
            if (proof is None or proof.attestation_digest
                    != kwargs["attestation_digest"]):
                raise RuntimeError("recovered terminal attestation mismatch")
            cur = self._conn.execute(
                f"UPDATE plan_execution_runs SET status=?,updated_at=?,completed_at=?,"
                f"failure_code=?,{seal_time}=?,{seal_column}=?,terminal_tombstone_digest=? "
                "WHERE execution_run_id=? AND status=?",
                (kwargs["terminal_status"], now, now, kwargs.get("failure_code", ""),
                 now, kwargs["seal_digest"], kwargs["tombstone_digest"],
                 execution_run_id, kwargs["expected_status"]),
            )
            if int(cur.rowcount or 0) != 1:
                raise RuntimeError("invalid recovered terminal transition")
            self._conn.execute(
                "DELETE FROM workspace_mutation_poison_scopes WHERE workspace_id=? "
                "AND poison_owner=?", (workspace_id, poison_owner),
            )
            self._insert_execution_audit(
                execution_run_id, "recovered-terminal-committed",
                result=kwargs["terminal_status"], correlation_id=kwargs["tombstone_digest"],
            )
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    def commit_recovered_no_mutation(
        self, *, execution_run_id: str, workspace_id: str,
        poison_owner: str, expected_status: str, terminal_status: str,
        baseline_digest: str, failure_code: str = "no-mutation-crash",
    ) -> None:
        """Atomically terminalize a proven zero-journal startup crash."""
        now = time.time()
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            proof = self.get_initial_workspace_attestation(execution_run_id)
            run_digest = self._conn.execute(
                "SELECT initial_attestation_digest FROM plan_execution_runs "
                "WHERE execution_run_id=?", (execution_run_id,),
            ).fetchone()
            if (proof is None or proof.attestation_digest != baseline_digest
                    or run_digest is None
                    or run_digest["initial_attestation_digest"] != baseline_digest):
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
                (terminal_status, now, now, failure_code, execution_run_id,
                 expected_status),
            )
            if int(cur.rowcount or 0) != 1:
                raise RuntimeError("invalid zero-journal terminal transition")
            self._insert_execution_audit(
                execution_run_id, "recovered-no-mutation-committed",
                result=terminal_status, error_code=failure_code,
                correlation_id=baseline_digest,
            )
            self._conn.execute(
                "DELETE FROM workspace_mutation_poison_scopes WHERE workspace_id=? "
                "AND poison_owner=?", (workspace_id, poison_owner),
            )
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    def _insert_execution_audit(
        self, execution_run_id: str, event_type: str, *, operation: str = "",
        path: str = "", before_hash: str = "", after_hash: str = "",
        result: str, error_code: str = "", correlation_id: str,
    ) -> None:
        self._conn.execute(
            "INSERT INTO plan_execution_audit_events "
            "(audit_id,execution_run_id,event_type,operation,path,before_hash,"
            "after_hash,result,error_code,correlation_id,created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (uuid.uuid4().hex, execution_run_id, event_type, operation, path,
             before_hash, after_hash, result, error_code, correlation_id,
             time.time()),
        )

    def get_execution_run_by_context(self, execution_context_id: str) -> Any | None:
        row = self._conn.execute(
            "SELECT * FROM plan_execution_runs WHERE execution_context_id=?",
            (execution_context_id,),
        ).fetchone()
        return self._row_to_execution_run(row) if row is not None else None

    def get_execution_run(self, execution_run_id: str) -> Any | None:
        row = self._conn.execute(
            "SELECT * FROM plan_execution_runs WHERE execution_run_id=?",
            (execution_run_id,),
        ).fetchone()
        if row is not None and row["status"] == "verified":
            verifier = self.__verification_success_verifier
            if verifier is None:
                if self.__authoritative_verification_reads_required:
                    raise PermissionError(
                        "VERIFIED execution cannot be trusted without authority"
                    )
            else:
                verifier(execution_run_id)
        return self._row_to_execution_run(row) if row is not None else None

    def list_incomplete_execution_runs(self) -> tuple[Any, ...]:
        rows = self._conn.execute(
            "SELECT * FROM plan_execution_runs WHERE status IN "
            "('validating','mutating','sealing','rolling-back','rollback-sealing','poisoned') "
            "ORDER BY started_at,execution_run_id"
        ).fetchall()
        return tuple(self._row_to_execution_run(row) for row in rows)

    def list_execution_edit_events(self, execution_run_id: str) -> tuple[sqlite3.Row, ...]:
        return tuple(self._conn.execute(
            "SELECT * FROM plan_execution_edit_events WHERE execution_run_id=? "
            "ORDER BY ordinal,event_id", (execution_run_id,),
        ).fetchall())

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

    @staticmethod
    def _row_to_execution_run(row: sqlite3.Row) -> Any:
        from khaos.coding.planning.execution_models import (
            ExecutionRunStatus, PlanExecutionRun,
        )
        return PlanExecutionRun(
            execution_run_id=row["execution_run_id"], plan_id=row["plan_id"],
            plan_content_hash=row["plan_content_hash"],
            approval_request_id=row["approval_request_id"],
            authorization_id=row["authorization_id"],
            execution_context_id=row["execution_context_id"],
            lease_id=row["lease_id"], task_id=row["task_id"],
            workspace_id=row["workspace_id"], repository_id=row["repository_id"],
            base_sha=row["base_sha"],
            repository_generation=int(row["repository_generation"]),
            binding_digest=row["binding_digest"],
            edit_bundle_digest=row["edit_bundle_digest"],
            status=ExecutionRunStatus(row["status"]), started_at=float(row["started_at"]),
            updated_at=float(row["updated_at"]), completed_at=row["completed_at"],
            failure_code=row["failure_code"], metadata=json.loads(row["metadata_json"]),
        )


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
