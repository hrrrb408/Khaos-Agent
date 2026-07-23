-- F-03 (third-round review): Migration chain v2 — TABLE DEFINITIONS ONLY.
--
-- This file is FROZEN.  Never modify it after release.  Future schema
-- changes must add 0003_xxx.sql, 0004_xxx.sql, etc.  Modifying this
-- file would break the checksum of every database that has already
-- applied v2.
--
-- This file contains ONLY ``CREATE TABLE`` and ``CREATE VIRTUAL TABLE``
-- statements.  Indexes and triggers live in ``0001_post_migration.sql``
-- and are executed AFTER ``_run_legacy_schema_upgrades()`` so that
-- indexes referencing principal_id / project_id / policy_digest (columns
-- added by the legacy upgrade helpers) do not fail on old databases.
--
-- Execution order in ``run_migrations()``:
--   1. 0001_initial_schema.sql   (this file — CREATE TABLE IF NOT EXISTS)
--   2. _run_legacy_schema_upgrades()  (ALTER TABLE ADD COLUMN for old DBs)
--   3. 0001_post_migration.sql   (CREATE INDEX / TRIGGER IF NOT EXISTS)

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_migrations (
    version     INTEGER PRIMARY KEY,
    name        TEXT NOT NULL,
    checksum    TEXT NOT NULL,
    applied_at  TEXT NOT NULL,
    app_version TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    id          TEXT PRIMARY KEY,
    mode        TEXT NOT NULL DEFAULT 'office',
    status      TEXT NOT NULL DEFAULT 'active',
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT NOT NULL DEFAULT (datetime('now')),
    metadata    TEXT DEFAULT '{}',
    principal_id TEXT NOT NULL DEFAULT 'legacy',
    project_id   TEXT NOT NULL DEFAULT '',
    UNIQUE(id, principal_id, project_id)
);

CREATE TABLE IF NOT EXISTS messages (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id   TEXT NOT NULL REFERENCES sessions(id),
    role         TEXT NOT NULL,
    content      TEXT NOT NULL DEFAULT '',
    tool_calls   TEXT DEFAULT '[]',
    tool_call_id TEXT,
    token_count  INTEGER NOT NULL DEFAULT 0,
    created_at   TEXT NOT NULL DEFAULT (datetime('now')),
    principal_id TEXT NOT NULL DEFAULT 'legacy',
    project_id   TEXT NOT NULL DEFAULT '',
    FOREIGN KEY(session_id, principal_id, project_id)
        REFERENCES sessions(id, principal_id, project_id)
);

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
    principal_id  TEXT NOT NULL DEFAULT 'legacy',
    project_id    TEXT NOT NULL DEFAULT '',
    FOREIGN KEY(session_id, principal_id, project_id)
        REFERENCES sessions(id, principal_id, project_id)
);

CREATE TABLE IF NOT EXISTS agent_turn_events (
    turn_id      TEXT NOT NULL REFERENCES agent_turns(turn_id),
    sequence     INTEGER NOT NULL,
    event_type   TEXT NOT NULL,
    payload_json TEXT NOT NULL DEFAULT '{}',
    created_at   REAL NOT NULL,
    PRIMARY KEY(turn_id, sequence)
);

CREATE TABLE IF NOT EXISTS chat_stream_events (
    session_id   TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    project_id   TEXT NOT NULL DEFAULT '',
    sequence     INTEGER NOT NULL,
    event_type   TEXT NOT NULL,
    data_json    TEXT NOT NULL DEFAULT '{}',
    is_terminal  INTEGER NOT NULL DEFAULT 0 CHECK(is_terminal IN (0, 1)),
    created_at   REAL NOT NULL,
    PRIMARY KEY(session_id, sequence),
    FOREIGN KEY(session_id, principal_id, project_id)
        REFERENCES sessions(id, principal_id, project_id)
);

-- Round-5 Batch 5.2: chat stream state machine main table.
CREATE TABLE IF NOT EXISTS chat_streams (
    session_id          TEXT PRIMARY KEY,
    principal_id        TEXT NOT NULL,
    project_id          TEXT NOT NULL DEFAULT '',
    status              TEXT NOT NULL DEFAULT 'running'
        CHECK(status IN ('running','done','error','interrupted')),
    boot_id             TEXT NOT NULL DEFAULT '',
    runtime_id          TEXT NOT NULL DEFAULT '',
    lease_until         REAL,
    last_sequence       INTEGER NOT NULL DEFAULT 0,
    terminal_event_type TEXT,
    started_at          REAL NOT NULL,
    terminal_at         REAL,
    FOREIGN KEY(session_id, principal_id, project_id)
        REFERENCES sessions(id, principal_id, project_id)
);

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
    principal_id TEXT NOT NULL DEFAULT 'legacy',
    namespace    TEXT NOT NULL DEFAULT 'private',
    session_id   TEXT NOT NULL DEFAULT '',
    project_id   TEXT NOT NULL DEFAULT '',
    UNIQUE(project_id, namespace, principal_id, session_id, scope, key)
);

CREATE VIRTUAL TABLE IF NOT EXISTS memory_fts USING fts5(
    key,
    value,
    content=memories,
    content_rowid=id,
    tokenize='unicode61'
);

CREATE TABLE IF NOT EXISTS permissions (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern          TEXT NOT NULL,
    permission_level TEXT NOT NULL,
    approval         TEXT NOT NULL,
    mode             TEXT NOT NULL DEFAULT 'all',
    granted_at       TEXT NOT NULL DEFAULT (datetime('now')),
    principal_id     TEXT NOT NULL DEFAULT 'legacy',
    project_id       TEXT NOT NULL DEFAULT '',
    policy_digest    TEXT NOT NULL DEFAULT '',
    generation       INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS authorization_contexts (
    principal_id  TEXT NOT NULL,
    project_id    TEXT NOT NULL,
    policy_digest TEXT NOT NULL,
    epoch         INTEGER NOT NULL DEFAULT 1 CHECK (epoch >= 1),
    updated_at    TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (principal_id, project_id)
);

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
    principal_id         TEXT NOT NULL DEFAULT 'legacy',
    runtime_id           TEXT,
    task_id              TEXT,
    operation_id         TEXT,
    policy_digest        TEXT,
    authority_generation INTEGER,
    source_transport     TEXT,
    project_id           TEXT NOT NULL DEFAULT '',
    FOREIGN KEY(session_id, principal_id, project_id)
        REFERENCES sessions(id, principal_id, project_id)
);

CREATE TABLE IF NOT EXISTS user_config (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

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
    principal_id      TEXT NOT NULL DEFAULT '',
    project_id        TEXT NOT NULL DEFAULT '',
    FOREIGN KEY(parent_session_id, principal_id, project_id)
        REFERENCES sessions(id, principal_id, project_id)
);

CREATE TABLE IF NOT EXISTS session_bookmarks (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  TEXT NOT NULL,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    mode        TEXT NOT NULL DEFAULT 'office',
    project_root TEXT,
    summary     TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    principal_id TEXT NOT NULL DEFAULT 'legacy',
    project_id   TEXT NOT NULL DEFAULT '',
    UNIQUE(session_id, name),
    FOREIGN KEY(session_id, principal_id, project_id)
        REFERENCES sessions(id, principal_id, project_id)
);

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
    principal_id    TEXT NOT NULL DEFAULT 'legacy',
    execution_id    TEXT,
    lease_until     TEXT,
    policy_digest   TEXT NOT NULL DEFAULT '',
    project_id      TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS scheduler_operation_journal (
    seq              INTEGER PRIMARY KEY AUTOINCREMENT,
    operation_id     TEXT NOT NULL,
    task_id          TEXT NOT NULL,
    operation_type   TEXT NOT NULL,
    desired_status   TEXT NOT NULL,
    expected_version INTEGER NOT NULL,
    target_version   INTEGER NOT NULL,
    principal_id     TEXT NOT NULL DEFAULT '',
    policy_digest    TEXT NOT NULL DEFAULT '',
    created_at       TEXT NOT NULL DEFAULT (datetime('now')),
    applied_at       TEXT,
    project_id       TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS coding_tasks (
    id             TEXT PRIMARY KEY,
    goal           TEXT NOT NULL,
    status         TEXT NOT NULL,
    state_json     TEXT NOT NULL DEFAULT '{}',
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL,
    principal_id   TEXT NOT NULL DEFAULT 'legacy',
    project_id     TEXT NOT NULL DEFAULT ''
);

CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts USING fts5(
    session_id,
    role,
    content,
    created_at,
    tokenize='unicode61'
);

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

CREATE TABLE IF NOT EXISTS plan_execution_server_state (
    singleton_key  TEXT PRIMARY KEY DEFAULT 'global',
    current_epoch  INTEGER NOT NULL DEFAULT 0,
    boot_id        TEXT NOT NULL DEFAULT '',
    updated_at     REAL NOT NULL DEFAULT 0
);

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

CREATE TABLE IF NOT EXISTS webhook_replay_events (
    channel_id TEXT NOT NULL,
    platform TEXT NOT NULL,
    event_id TEXT NOT NULL,
    issued_at REAL NOT NULL,
    expires_at REAL,
    created_at REAL NOT NULL,
    PRIMARY KEY (channel_id, platform, event_id)
);

CREATE TABLE IF NOT EXISTS webhook_replay_watermarks (
    channel_id TEXT NOT NULL,
    platform TEXT NOT NULL,
    high_water INTEGER NOT NULL,
    seen_json TEXT NOT NULL,
    updated_at REAL NOT NULL,
    PRIMARY KEY (channel_id, platform)
);
