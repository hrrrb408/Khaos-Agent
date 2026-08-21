"""Canonical schema and migration owner for plan approval and execution state.

The store consumes this module but does not define a second schema. SQLite
migrations remain idempotent and fail closed when an expected table shape is
not present.
"""

from __future__ import annotations

import sqlite3

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
def upgrade_schema(conn: sqlite3.Connection) -> None:
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
        # makes SQLite evaluate it before upgrade_schema can migrate the table.
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


__all__ = ["APPROVAL_SCHEMA", "upgrade_schema"]
