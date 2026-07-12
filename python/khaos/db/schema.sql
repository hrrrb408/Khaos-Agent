PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS sessions (
    id          TEXT PRIMARY KEY,
    mode        TEXT NOT NULL DEFAULT 'office',
    status      TEXT NOT NULL DEFAULT 'active',
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT NOT NULL DEFAULT (datetime('now')),
    metadata    TEXT DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS messages (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id   TEXT NOT NULL REFERENCES sessions(id),
    role         TEXT NOT NULL,
    content      TEXT NOT NULL DEFAULT '',
    tool_calls   TEXT DEFAULT '[]',
    tool_call_id TEXT,
    token_count  INTEGER NOT NULL DEFAULT 0,
    created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_messages_session ON messages(session_id, created_at);

CREATE TABLE IF NOT EXISTS memories (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scope       TEXT NOT NULL,
    key         TEXT NOT NULL,
    value       TEXT NOT NULL,
    ttl         INTEGER NOT NULL DEFAULT 604800,
    confidence  INTEGER NOT NULL DEFAULT 2,
    access_freq INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(scope, key)
);

CREATE VIRTUAL TABLE IF NOT EXISTS memory_fts USING fts5(
    key,
    value,
    content=memories,
    content_rowid=id,
    tokenize='unicode61'
);

CREATE TRIGGER IF NOT EXISTS memory_ai AFTER INSERT ON memories BEGIN
    INSERT INTO memory_fts(rowid, key, value) VALUES (new.id, new.key, new.value);
END;

CREATE TRIGGER IF NOT EXISTS memory_ad AFTER DELETE ON memories BEGIN
    INSERT INTO memory_fts(memory_fts, rowid, key, value) VALUES('delete', old.id, old.key, old.value);
END;

CREATE TRIGGER IF NOT EXISTS memory_au AFTER UPDATE ON memories BEGIN
    INSERT INTO memory_fts(memory_fts, rowid, key, value) VALUES('delete', old.id, old.key, old.value);
    INSERT INTO memory_fts(rowid, key, value) VALUES (new.id, new.key, new.value);
END;

CREATE TABLE IF NOT EXISTS permissions (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern          TEXT NOT NULL,
    permission_level TEXT NOT NULL,
    approval         TEXT NOT NULL,
    mode             TEXT NOT NULL DEFAULT 'all',
    granted_at       TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_permissions_level ON permissions(permission_level, mode);

CREATE TABLE IF NOT EXISTS tools (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    name             TEXT NOT NULL UNIQUE,
    schema           TEXT NOT NULL,
    modes            TEXT NOT NULL DEFAULT '["all"]',
    permission_level TEXT NOT NULL,
    parallel         INTEGER NOT NULL DEFAULT 0,
    timeout          INTEGER NOT NULL DEFAULT 60,
    enabled          INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    action      TEXT NOT NULL,
    target      TEXT NOT NULL,
    result      TEXT NOT NULL,
    detail      TEXT DEFAULT '',
    session_id  TEXT REFERENCES sessions(id),
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_audit_log_time ON audit_log(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action);

CREATE TABLE IF NOT EXISTS user_config (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS subagent_tasks (
    id                TEXT PRIMARY KEY,
    parent_session_id TEXT NOT NULL REFERENCES sessions(id),
    goal              TEXT NOT NULL,
    context           TEXT NOT NULL,
    tools             TEXT DEFAULT '[]',
    status            TEXT NOT NULL DEFAULT 'pending',
    result            TEXT,
    error             TEXT,
    created_at        TEXT NOT NULL DEFAULT (datetime('now')),
    finished_at       TEXT
);

-- Phase 6: Session bookmarks for task persistence across sessions
CREATE TABLE IF NOT EXISTS session_bookmarks (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  TEXT NOT NULL,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    mode        TEXT NOT NULL DEFAULT 'office',
    project_root TEXT,
    summary     TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(session_id, name)
);

-- Hermes batch 1: scheduled (cron) tasks
CREATE TABLE IF NOT EXISTS scheduled_tasks (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    prompt          TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending',
    schedule_config TEXT NOT NULL DEFAULT '{}',
    deliver_to      TEXT NOT NULL DEFAULT 'local',
    meta            TEXT NOT NULL DEFAULT '{}',
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    last_run        TEXT,
    next_run        TEXT,
    run_count       INTEGER NOT NULL DEFAULT 0,
    last_result     TEXT,
    error           TEXT
);

CREATE INDEX IF NOT EXISTS idx_scheduled_tasks_status ON scheduled_tasks(status, next_run);

CREATE TABLE IF NOT EXISTS coding_tasks (
    id             TEXT PRIMARY KEY,
    goal           TEXT NOT NULL,
    status         TEXT NOT NULL,
    state_json     TEXT NOT NULL DEFAULT '{}',
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_coding_tasks_status ON coding_tasks(status, updated_at);

-- Hermes batch 2: session history FTS5 search over messages.
-- Separate FTS5 table (rowid mirrors messages.id) populated manually by
-- insert_message_fts(). A standalone table avoids external-content trigger
-- complexity while still giving BM25 ranking + snippet() over message text.
CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts USING fts5(
    session_id,
    role,
    content,
    created_at,
    tokenize='unicode61'
);

-- M4 Batch 2: Plan approval state machine + execution authorization gate.
-- These tables persist the server-authoritative approval lifecycle and the
-- short-lived, single-use execution authorizations. See
-- python/khaos/coding/planning/approval/ for the Python implementation.
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

-- M4 Batch 2.1 + 2.2: Broker authenticity and atomic authorization closure.
-- Durable broker-decision receipt outbox with FULL field binding. Only
-- ApprovalBroker can create a row here; apply_authenticated_decision
-- verifies the token hash AND every authoritative field against this row.
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

-- At most one ACTIVE authorization per approval request (defense-in-depth
-- for the single-execution-per-approval invariant; the service refuses
-- re-mint anyway). Partial unique index so consumed/revoked rows don't block.
CREATE UNIQUE INDEX IF NOT EXISTS uq_plan_exec_auth_active_per_request
    ON plan_execution_authorizations(approval_request_id) WHERE status = 'active';

-- broker_request_id uniqueness for non-empty values (old not-required rows
-- used '' and many can coexist).
CREATE UNIQUE INDEX IF NOT EXISTS uq_plan_approval_requests_broker
    ON plan_approval_requests(broker_request_id) WHERE broker_request_id != '';

-- M4 Batch 2.2: persisted monotonic server epoch. The gate reads and rotates
-- this atomically at startup so a restart genuinely invalidates old
-- authorizations (the in-memory default epoch was not a real safety property).
CREATE TABLE IF NOT EXISTS plan_execution_server_state (
    singleton_key  TEXT PRIMARY KEY DEFAULT 'global',
    current_epoch  INTEGER NOT NULL DEFAULT 0,
    boot_id        TEXT NOT NULL DEFAULT '',
    updated_at     REAL NOT NULL DEFAULT 0
);

-- M4 Batch 2.2: persisted authoritative plan snapshots. The gate and decision
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

-- M4 Batch 2.2: workspace execution leases (TOCTOU closure for consume).
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
    created_at            REAL NOT NULL
);

-- At most one ACTIVE lease per workspace — enforces workspace exclusivity.
CREATE UNIQUE INDEX IF NOT EXISTS uq_plan_execution_leases_active_workspace
    ON plan_execution_leases(workspace_id) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_plan_execution_leases_task
    ON plan_execution_leases(task_id, status);
