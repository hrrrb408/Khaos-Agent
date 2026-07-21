PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS sessions (
    id          TEXT PRIMARY KEY,
    mode        TEXT NOT NULL DEFAULT 'office',
    status      TEXT NOT NULL DEFAULT 'active',
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT NOT NULL DEFAULT (datetime('now')),
    metadata    TEXT DEFAULT '{}',
    -- M4 batch 3.1.16A-4-3 (CRITICAL): durable principal owner.  Every
    -- session belongs to exactly one principal; ``list_sessions`` /
    -- ``search_sessions`` filter by it so one principal cannot see
    -- another's conversation history.  Legacy rows (pre-A-4-3) get
    -- ``'legacy'`` and are hidden from every authenticated principal
    -- (fail-closed).  See ``_ensure_sessions_principal_column``.
    principal_id TEXT NOT NULL DEFAULT 'legacy'
);

CREATE INDEX IF NOT EXISTS idx_sessions_principal
    ON sessions(principal_id, status, updated_at);

CREATE TABLE IF NOT EXISTS messages (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id   TEXT NOT NULL REFERENCES sessions(id),
    role         TEXT NOT NULL,
    content      TEXT NOT NULL DEFAULT '',
    tool_calls   TEXT DEFAULT '[]',
    tool_call_id TEXT,
    token_count  INTEGER NOT NULL DEFAULT 0,
    created_at   TEXT NOT NULL DEFAULT (datetime('now')),
    -- M4 batch 3.1.16A-4-3: principal owner stamped at insert time so
    -- ``list_messages`` / ``get_session_messages`` / ``search_sessions``
    -- can filter without an extra JOIN to ``sessions``.  Must match the
    -- session's principal (enforced by application code, not a DB
    -- constraint, because SQLite CHECK can't reference other tables).
    principal_id TEXT NOT NULL DEFAULT 'legacy'
);

CREATE INDEX IF NOT EXISTS idx_messages_session ON messages(session_id, created_at);
CREATE INDEX IF NOT EXISTS idx_messages_principal
    ON messages(principal_id, session_id, created_at);

CREATE TABLE IF NOT EXISTS agent_turns (
    turn_id       TEXT PRIMARY KEY,
    attempt_id    TEXT NOT NULL,
    session_id    TEXT NOT NULL REFERENCES sessions(id),
    task_id       TEXT,
    status        TEXT NOT NULL CHECK(status IN ('running','completed','interrupted','failed')),
    last_sequence INTEGER NOT NULL DEFAULT 0,
    error_code    TEXT,
    started_at    REAL NOT NULL,
    finished_at   REAL,
    -- M4 batch 3.1.16A-4-3: principal owner stamped at turn start so
    -- turn history queries can be scoped without JOINing sessions.
    -- ``recover_inflight_agent_turns`` is a process-wide sweep and
    -- ignores this column; per-principal visibility is enforced by
    -- ``list_agent_turn_events`` callers.
    principal_id  TEXT NOT NULL DEFAULT 'legacy'
);

CREATE TABLE IF NOT EXISTS agent_turn_events (
    turn_id      TEXT NOT NULL REFERENCES agent_turns(turn_id),
    sequence     INTEGER NOT NULL,
    event_type   TEXT NOT NULL,
    payload_json TEXT NOT NULL DEFAULT '{}',
    created_at   REAL NOT NULL,
    PRIMARY KEY(turn_id, sequence)
);

CREATE INDEX IF NOT EXISTS idx_agent_turns_session
ON agent_turns(session_id, started_at);

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
    -- M4 batch 3.1.16A-2 (CRITICAL #5): principal partitioning.  Memories
    -- are scoped by (namespace, principal_id, session_id, scope, key).
    -- Legacy rows (pre-A-2) get principal_id='legacy' and are never
    -- loaded by authenticated principals.
    --   namespace='private' : principal-private (default)
    --   namespace='session' : session-private (requires session_id)
    --   namespace='shared'  : project-shared (principal_id='')
    principal_id TEXT NOT NULL DEFAULT 'legacy',
    namespace    TEXT NOT NULL DEFAULT 'private',
    session_id   TEXT NOT NULL DEFAULT '',
    UNIQUE(namespace, principal_id, session_id, scope, key)
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
    granted_at       TEXT NOT NULL DEFAULT (datetime('now')),
    -- M4 batch 3.1.16A-2 (CRITICAL #3): principal partitioning.  Rules
    -- are scoped by (principal_id, project_id, policy_digest).  Legacy
    -- rows (pre-A-2) get principal_id='legacy' and are never matched.
    principal_id     TEXT NOT NULL DEFAULT 'legacy',
    project_id       TEXT NOT NULL DEFAULT '',
    policy_digest    TEXT NOT NULL DEFAULT '',
    generation       INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_permissions_level ON permissions(permission_level, mode);
-- M4 batch 3.1.16A-2: principal-scoped lookup index.
CREATE INDEX IF NOT EXISTS idx_permissions_principal
    ON permissions(principal_id, project_id, mode, permission_level);

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
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    -- M4 batch 3.1.16A-2 (HIGH #19): principal attribution.  All audit
    -- entries are stamped with the principal that triggered the action.
    -- Legacy rows (pre-A-2) get principal_id='legacy'.
    principal_id         TEXT NOT NULL DEFAULT 'legacy',
    runtime_id           TEXT,
    task_id              TEXT,
    operation_id         TEXT,
    policy_digest        TEXT,
    authority_generation INTEGER,
    source_transport     TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_log_time ON audit_log(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action);
-- M4 batch 3.1.16A-2: principal-scoped audit lookup.
CREATE INDEX IF NOT EXISTS idx_audit_log_principal
    ON audit_log(principal_id, created_at);

CREATE TABLE IF NOT EXISTS user_config (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- M4 batch 3.1.16A-2 (CRITICAL #4): per-principal mode storage.
-- Replaces the global ``user_config.current_mode`` for mode lookup.
-- ``user_config`` is retained for genuinely global settings (API keys
-- etc.) but mode is now principal-scoped.
--
-- Lookup order in ModeManager:
--   1. (principal_id, session_id) — session-specific override
--   2. (principal_id, '')         — principal default
--   3. system default (office)
CREATE TABLE IF NOT EXISTS principal_modes (
    principal_id TEXT NOT NULL,
    session_id   TEXT NOT NULL DEFAULT '',
    mode         TEXT NOT NULL,
    updated_at   TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (principal_id, session_id)
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
    finished_at       TEXT,
    -- B1: principal that owns this task. Empty for legacy rows; the
    -- spawner / service stamps the authenticated principal here so
    -- collect / status can filter by it.  NOT NULL DEFAULT '' keeps
    -- backward compatibility with rows written before the column existed.
    principal_id      TEXT NOT NULL DEFAULT ''
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
    -- M4 batch 3.1.16A-4-3: principal owner so ``list_bookmarks`` /
    -- ``load_bookmark`` / ``delete_bookmark`` can scope by principal.
    -- Legacy rows get ``'legacy'`` and are invisible to authenticated
    -- principals (fail-closed).
    principal_id TEXT NOT NULL DEFAULT 'legacy',
    UNIQUE(session_id, name)
);

CREATE INDEX IF NOT EXISTS idx_session_bookmarks_principal
    ON session_bookmarks(principal_id, session_id);

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
    error           TEXT,
    lifecycle_version INTEGER NOT NULL DEFAULT 0,
    -- M4 batch 3.1.10: principal-bound ownership.  Every task belongs
    -- to exactly one principal; list / pause / resume / remove filter
    -- on it.  Legacy rows get 'legacy' and are NOT visible to any
    -- authenticated principal (fail-closed).
    principal_id    TEXT NOT NULL DEFAULT 'legacy',
    -- M4 batch 3.1.10: durable execution claim.  Set atomically via
    -- claim_scheduled_task() before the executor runs, so a crash
    -- during execution leaves a durable RUNNING + lease marker that
    -- restart recovery can detect and disclose (at-least-once).
    execution_id    TEXT,
    lease_until     TEXT,
    -- M4 batch 3.1.16B-1 (CRITICAL): security-context snapshot at
    -- creation time.  ``policy_digest`` captures the
    -- ``EffectiveSecurityPolicy.digest`` when the task was created;
    -- ``project_id`` captures ``sha256(realpath(project_root))[:32]``.
    -- B-2 will compare these against the live values at ``start()``
    -- and ``_execute_task`` claim time to detect policy/project drift
    -- — a task created under policy A must NOT silently execute under
    -- policy B if the user tightened security between creation and
    -- firing.  Legacy rows (empty ``policy_digest``) are quarantined
    -- to ``status='failed'`` at migration time (fail-closed).
    policy_digest   TEXT NOT NULL DEFAULT '',
    project_id      TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_scheduled_tasks_status ON scheduled_tasks(status, next_run);
CREATE INDEX IF NOT EXISTS idx_scheduled_tasks_principal ON scheduled_tasks(principal_id, status);
CREATE INDEX IF NOT EXISTS idx_scheduled_tasks_policy ON scheduled_tasks(policy_digest, status);

CREATE TABLE IF NOT EXISTS coding_tasks (
    id             TEXT PRIMARY KEY,
    goal           TEXT NOT NULL,
    status         TEXT NOT NULL,
    state_json     TEXT NOT NULL DEFAULT '{}',
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL,
    -- M4 batch 3.1.16A-3 (CRITICAL): principal-scoped ownership.  Every
    -- coding task is owned by exactly one principal; ``list_coding_tasks``
    -- filters by ``principal_id`` so one principal cannot see, cancel, or
    -- approve another principal's tasks.  Legacy rows (pre-A3) get
    -- ``'legacy'`` and are quarantined to ``status='failed'`` at
    -- migration time — they are never executed or surfaced by an
    -- authenticated principal's TaskManager.
    principal_id   TEXT NOT NULL DEFAULT 'legacy'
);

CREATE INDEX IF NOT EXISTS idx_coding_tasks_status ON coding_tasks(status, updated_at);
CREATE INDEX IF NOT EXISTS idx_coding_tasks_principal ON coding_tasks(principal_id, status);

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
    server_epoch          INTEGER NOT NULL DEFAULT 0,
    created_at            REAL NOT NULL
);

-- At most one ACTIVE lease per workspace — enforces workspace exclusivity.
CREATE UNIQUE INDEX IF NOT EXISTS uq_plan_execution_leases_active_workspace
    ON plan_execution_leases(workspace_id) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_plan_execution_leases_task
    ON plan_execution_leases(task_id, status);

-- M4 Batch 3.1: trusted verification execution.  Output bodies remain in a
-- private artifact root; SQLite stores only identities, digests and status.
CREATE TABLE IF NOT EXISTS plan_verification_runs (
    verification_run_id TEXT PRIMARY KEY,
    execution_run_id TEXT NOT NULL UNIQUE,
    plan_id TEXT NOT NULL,
    plan_content_hash TEXT NOT NULL,
    approval_request_id TEXT NOT NULL,
    execution_context_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    repository_id TEXT NOT NULL,
    bundle_digest TEXT NOT NULL,
    final_mutation_attestation_digest TEXT NOT NULL,
    verification_plan_digest TEXT NOT NULL,
    trusted_catalog_fingerprint TEXT NOT NULL,
    sandbox_profile_digest TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    completed_at REAL,
    failure_code TEXT NOT NULL DEFAULT '',
    metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS plan_verification_steps (
    step_run_id TEXT PRIMARY KEY,
    verification_run_id TEXT NOT NULL,
    requirement_id TEXT NOT NULL,
    command_id TEXT NOT NULL,
    command_digest TEXT NOT NULL,
    ordinal INTEGER NOT NULL,
    status TEXT NOT NULL,
    exit_code INTEGER,
    signal INTEGER,
    started_at REAL,
    completed_at REAL,
    duration_ms INTEGER NOT NULL DEFAULT 0,
    timeout_ms INTEGER NOT NULL,
    stdout_digest TEXT NOT NULL DEFAULT '',
    stderr_digest TEXT NOT NULL DEFAULT '',
    output_artifact_id TEXT NOT NULL DEFAULT '',
    output_truncated INTEGER NOT NULL DEFAULT 0,
    sandbox_instance_id TEXT NOT NULL DEFAULT '',
    sandbox_image_digest TEXT NOT NULL DEFAULT '',
    resource_usage_json TEXT NOT NULL DEFAULT '{}',
    failure_code TEXT NOT NULL DEFAULT '',
    UNIQUE(verification_run_id, ordinal)
);

CREATE TABLE IF NOT EXISTS plan_verification_audit_events (
    audit_id TEXT PRIMARY KEY,
    verification_run_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    result TEXT NOT NULL,
    error_code TEXT NOT NULL DEFAULT '',
    correlation_id TEXT NOT NULL,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS plan_verification_artifacts (
    artifact_id TEXT PRIMARY KEY,
    verification_run_id TEXT NOT NULL,
    relative_name TEXT NOT NULL,
    content_digest TEXT NOT NULL,
    byte_length INTEGER NOT NULL,
    expires_at REAL NOT NULL,
    quarantined INTEGER NOT NULL DEFAULT 0,
    created_at REAL NOT NULL,
    status TEXT NOT NULL DEFAULT 'sealed',
    artifact_dev INTEGER NOT NULL DEFAULT -1,
    artifact_ino INTEGER NOT NULL DEFAULT -1,
    artifact_uid INTEGER NOT NULL DEFAULT -1,
    artifact_gid INTEGER NOT NULL DEFAULT -1,
    artifact_mode INTEGER NOT NULL DEFAULT -1,
    artifact_nlink INTEGER NOT NULL DEFAULT -1
);

CREATE TABLE IF NOT EXISTS plan_execution_phase_leases (
    phase_lease_id TEXT PRIMARY KEY,
    execution_run_id TEXT NOT NULL,
    phase TEXT NOT NULL,
    owner_execution_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    repository_id TEXT NOT NULL,
    plan_id TEXT NOT NULL,
    bundle_digest TEXT NOT NULL,
    attestation_digest TEXT NOT NULL,
    binding_digest TEXT NOT NULL,
    server_epoch INTEGER NOT NULL,
    boot_id TEXT NOT NULL,
    expiry REAL NOT NULL,
    status TEXT NOT NULL,
    created_at REAL NOT NULL,
    released_at REAL
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_active_verification_phase_lease
    ON plan_execution_phase_leases(execution_run_id) WHERE status = 'active';

CREATE TABLE IF NOT EXISTS approved_verification_plan_snapshots (
    approved_verification_plan_id TEXT PRIMARY KEY,
    plan_id TEXT NOT NULL,
    plan_content_hash TEXT NOT NULL,
    requirements_digest TEXT NOT NULL,
    catalog_fingerprint TEXT NOT NULL,
    ordered_command_digests_json TEXT NOT NULL,
    config_hashes_json TEXT NOT NULL,
    sandbox_profile_digest TEXT NOT NULL,
    image_attestation_content_digest TEXT NOT NULL,
    ordered_toolchain_attestation_content_digests_json TEXT NOT NULL,
    binary_digests_json TEXT NOT NULL,
    version_output_digests_json TEXT NOT NULL,
    parsed_versions_json TEXT NOT NULL,
    image_toolchain_policy_fingerprint TEXT NOT NULL,
    snapshot_digest TEXT NOT NULL UNIQUE,
    created_at REAL NOT NULL,
    boot_id TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS verification_cleanup_proofs (
    cleanup_proof_id TEXT PRIMARY KEY,
    verification_run_id TEXT NOT NULL,
    disposable_workspace_id TEXT NOT NULL,
    disposable_workspace_identity TEXT NOT NULL,
    disposable_cleaned_at REAL NOT NULL,
    sandbox_instance_ids_json TEXT NOT NULL,
    sandbox_absence_digests_json TEXT NOT NULL,
    artifact_ids_json TEXT NOT NULL,
    artifact_seal_digests_json TEXT NOT NULL,
    canonical_workspace_final_digest TEXT NOT NULL,
    cleanup_digest TEXT NOT NULL,
    created_at REAL NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_vcp_run
    ON verification_cleanup_proofs(verification_run_id);

CREATE TRIGGER IF NOT EXISTS trg_vcp_immutable_update
BEFORE UPDATE ON verification_cleanup_proofs
BEGIN SELECT RAISE(ABORT, 'verification cleanup proof is immutable'); END;

CREATE TRIGGER IF NOT EXISTS trg_vcp_immutable_delete
BEFORE DELETE ON verification_cleanup_proofs
BEGIN SELECT RAISE(ABORT, 'verification cleanup proof cannot be deleted'); END;

CREATE TABLE IF NOT EXISTS verification_success_evidence (
    verification_run_id TEXT PRIMARY KEY,
    execution_run_id TEXT NOT NULL UNIQUE,
    cleanup_proof_id TEXT NOT NULL UNIQUE,
    cleanup_digest TEXT NOT NULL,
    authority_instance_id TEXT NOT NULL,
    runtime_id TEXT NOT NULL,
    boot_id TEXT NOT NULL,
    payload_digest TEXT NOT NULL UNIQUE,
    created_at REAL NOT NULL
);

CREATE TRIGGER IF NOT EXISTS trg_vse_immutable_update
BEFORE UPDATE ON verification_success_evidence
BEGIN SELECT RAISE(ABORT, 'verification success evidence is immutable'); END;

CREATE TRIGGER IF NOT EXISTS trg_vse_immutable_delete
BEFORE DELETE ON verification_success_evidence
BEGIN SELECT RAISE(ABORT, 'verification success evidence cannot be deleted'); END;

-- Principal-bound one-shot approvals for destructive Git/GitHub/ChangeSet
-- operations. State changes are performed by transaction/CAS in Database;
-- triggers are intentionally not used as a connection-authority boundary.
CREATE TABLE IF NOT EXISTS operation_approvals (
    approval_id TEXT PRIMARY KEY,
    binding_digest TEXT NOT NULL,
    binding_json TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    operation TEXT NOT NULL,
    nonce_hash TEXT NOT NULL,
    expires_at REAL NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('pending','approved','consumed','cancelled')),
    created_at REAL NOT NULL,
    approved_at REAL,
    consumed_at REAL
);

CREATE INDEX IF NOT EXISTS idx_operation_approvals_expiry
    ON operation_approvals(status, expires_at);

CREATE TABLE IF NOT EXISTS operation_approval_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    approval_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    binding_digest TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    detail_json TEXT NOT NULL DEFAULT '{}',
    created_at REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_operation_approval_events_approval
    ON operation_approval_events(approval_id, id);

-- Durable one-shot webhook event consumption. Telegram update IDs use a NULL
-- expiry because the platform has no signed request timestamp; timestamped
-- platforms may prune entries only after their signature freshness window.
CREATE TABLE IF NOT EXISTS webhook_replay_events (
    channel_id TEXT NOT NULL,
    platform TEXT NOT NULL,
    event_id TEXT NOT NULL,
    issued_at REAL NOT NULL,
    expires_at REAL,
    created_at REAL NOT NULL,
    PRIMARY KEY (channel_id, platform, event_id)
);

CREATE INDEX IF NOT EXISTS idx_webhook_replay_expiry
    ON webhook_replay_events(expires_at)
    WHERE expires_at IS NOT NULL;

-- Telegram has no signed request timestamp. Keep a bounded high-water window
-- rather than one permanent row per update for the lifetime of the Runtime.
CREATE TABLE IF NOT EXISTS webhook_replay_watermarks (
    channel_id TEXT NOT NULL,
    platform TEXT NOT NULL,
    high_water INTEGER NOT NULL,
    seen_json TEXT NOT NULL,
    updated_at REAL NOT NULL,
    PRIMARY KEY (channel_id, platform)
);
