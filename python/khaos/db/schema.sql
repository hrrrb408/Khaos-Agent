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
    -- M4 batch 3.1.16A-4-3 (CRITICAL): durable principal owner.  Every
    -- session belongs to exactly one principal; ``list_sessions`` /
    -- ``search_sessions`` filter by it so one principal cannot see
    -- another's conversation history.  Legacy rows (pre-A-4-3) get
    -- ``'legacy'`` and are hidden from every authenticated principal
    -- (fail-closed).  See ``_ensure_sessions_principal_column``.
    principal_id TEXT NOT NULL DEFAULT 'legacy',
    -- M4 batch 3.1.16A-5-1 (CRITICAL): project identity closure.  Every
    -- row is stamped with the project_id (sha256(realpath(root))[:32])
    -- of the runtime that created it.  Legacy rows (pre-A-5-1) get
    -- ``''`` and are treated as "unbound" — A-5-1b will fail-closed
    -- on drift (``ctx.project_id != bound_project_id``).  See
    -- ``_ensure_sessions_project_id_column``.
    project_id   TEXT NOT NULL DEFAULT '',
    UNIQUE(id, principal_id, project_id)
);

CREATE INDEX IF NOT EXISTS idx_sessions_principal
    ON sessions(principal_id, status, updated_at);
-- M4 batch 3.1.16A-5-1: project-scoped index is created by
-- ``_ensure_sessions_project_id_column`` (not here, because legacy
-- DBs don't have the project_id column yet when this script runs).

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
    principal_id TEXT NOT NULL DEFAULT 'legacy',
    -- M4 batch 3.1.16A-5-1: project identity closure (see ``sessions``).
    project_id   TEXT NOT NULL DEFAULT '',
    FOREIGN KEY(session_id, principal_id, project_id)
        REFERENCES sessions(id, principal_id, project_id)
);

CREATE INDEX IF NOT EXISTS idx_messages_session ON messages(session_id, created_at);
CREATE INDEX IF NOT EXISTS idx_messages_principal
    ON messages(principal_id, session_id, created_at);
-- M4 batch 3.1.16A-5-1: project-scoped index created by migration helper.

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
    principal_id  TEXT NOT NULL DEFAULT 'legacy',
    -- M4 batch 3.1.16A-5-1: project identity closure (see ``sessions``).
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

CREATE INDEX IF NOT EXISTS idx_agent_turns_session
ON agent_turns(session_id, started_at);
-- M4 batch 3.1.16A-5-1: project-scoped index created by migration helper.

-- Gateway-facing chat events are a durable broadcast log.  Every subscriber
-- reads independently by sequence; Go never owns or consumes the only copy.
-- Round-6 Batch 6.1: events are keyed by ``stream_id`` (one per chat RPC
-- attempt), NOT ``session_id``.  A session can have many streams (one
-- per turn/attempt); the Terminal invariant is per-stream, not per-session.
CREATE TABLE IF NOT EXISTS chat_stream_events (
    event_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    stream_id    TEXT NOT NULL,
    session_id   TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    project_id   TEXT NOT NULL DEFAULT '',
    sequence     INTEGER NOT NULL,
    event_type   TEXT NOT NULL,
    data_json    TEXT NOT NULL DEFAULT '{}',
    is_terminal  INTEGER NOT NULL DEFAULT 0 CHECK(is_terminal IN (0, 1)),
    created_at   REAL NOT NULL,
    UNIQUE(stream_id, sequence),
    FOREIGN KEY(session_id, principal_id, project_id)
        REFERENCES sessions(id, principal_id, project_id)
);

CREATE INDEX IF NOT EXISTS idx_chat_stream_events_owner
ON chat_stream_events(principal_id, project_id, session_id, event_id);
CREATE INDEX IF NOT EXISTS idx_chat_stream_events_stream
ON chat_stream_events(stream_id, event_id);
CREATE INDEX IF NOT EXISTS idx_chat_stream_events_session
ON chat_stream_events(session_id, principal_id, project_id, event_id);

-- Round-5 Batch 5.2 (C-05/C-06) + Round-6 Batch 6.1: Chat stream state
-- machine main table.  One row PER STREAM (not per session).  A session
-- can have many streams over its lifetime — each chat RPC creates a new
-- stream with its own Terminal lifecycle.  This fixes the Round-5 bug
-- where a session was permanently locked to 'done' after the first turn,
-- breaking multi-turn conversations.
--   stream_id: uuid4().hex, unique per chat RPC attempt.
--   session_id: the conversation container (many streams per session).
--   turn_id / attempt_id: optional future-use identifiers.
--   status: 'running' → exactly one CAS transition to
--           'done'/'error'/'interrupted' (terminal).
--   boot_id: uuid4().hex of the process that started this stream.
--   lease_until: renewed on every non-terminal append; expired lease
--                means the owning process is likely dead.
--   terminal_event_type: which event type terminated the stream
--                        (NULL while running).
-- Legacy streams (pre-round-6) get a row lazily on first append with
-- empty boot_id and NULL lease — recovery treats them as recoverable.
CREATE TABLE IF NOT EXISTS chat_streams (
    stream_id           TEXT PRIMARY KEY,
    session_id          TEXT NOT NULL,
    turn_id             TEXT NOT NULL DEFAULT '',
    attempt_id          TEXT NOT NULL DEFAULT '',
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

CREATE INDEX IF NOT EXISTS idx_chat_streams_session
ON chat_streams(session_id);
CREATE INDEX IF NOT EXISTS idx_chat_streams_boot
ON chat_streams(boot_id, status);
CREATE INDEX IF NOT EXISTS idx_chat_streams_status_lease
ON chat_streams(status, lease_until);

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
    -- M4 batch 3.1.16A-5-1: project identity closure (see ``sessions``).
    project_id   TEXT NOT NULL DEFAULT '',
    -- F-02 (third-round review): project_id is now part of the UNIQUE
    -- key so two projects sharing a state DB cannot collide on the same
    -- (namespace, principal_id, session_id, scope, key) tuple.  Legacy
    -- rows with project_id='' remain visible (they share the empty
    -- project partition); A-5-2 backfill should be run before this
    -- migration on multi-project shared DBs to avoid collapsing
    -- unbound rows onto a single partition.
    UNIQUE(project_id, namespace, principal_id, session_id, scope, key)
);
-- M4 batch 3.1.16A-5-1: project-scoped index created by migration helper.

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
    generation       INTEGER NOT NULL DEFAULT 0,
    -- Phase-1 authority scope: a remembered interactive grant must not
    -- silently apply to unattended transports or another session/task.
    transport_class  TEXT NOT NULL DEFAULT 'interactive',
    grant_lifetime    TEXT NOT NULL DEFAULT 'project_interactive',
    session_id       TEXT NOT NULL DEFAULT '',
    task_id          TEXT NOT NULL DEFAULT '',
    workspace_id     TEXT NOT NULL DEFAULT '',
    expires_at       REAL,
    created_by       TEXT NOT NULL DEFAULT '',
    resource_type    TEXT NOT NULL DEFAULT '',
    resource_spec    TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_permissions_level ON permissions(permission_level, mode);
-- M4 batch 3.1.16A-2: principal-scoped lookup index.
CREATE INDEX IF NOT EXISTS idx_permissions_principal
    ON permissions(principal_id, project_id, policy_digest, generation, mode, permission_level);
CREATE INDEX IF NOT EXISTS idx_permissions_scope
    ON permissions(principal_id, project_id, policy_digest, generation,
                   transport_class, grant_lifetime, session_id, task_id);
CREATE INDEX IF NOT EXISTS idx_permissions_resource
    ON permissions(principal_id, project_id, policy_digest, generation,
                   resource_type, permission_level);

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
    -- M4 batch 3.1.16A-2 (HIGH #19): principal attribution.  All audit
    -- entries are stamped with the principal that triggered the action.
    -- Legacy rows (pre-A-2) get principal_id='legacy'.
    principal_id         TEXT NOT NULL DEFAULT 'legacy',
    runtime_id           TEXT,
    task_id              TEXT,
    operation_id         TEXT,
    policy_digest        TEXT,
    authority_generation INTEGER,
    source_transport     TEXT,
    -- M4 batch 3.1.16A-5-1: project identity closure (see ``sessions``).
    project_id           TEXT NOT NULL DEFAULT '',
    FOREIGN KEY(session_id, principal_id, project_id)
        REFERENCES sessions(id, principal_id, project_id)
);

CREATE INDEX IF NOT EXISTS idx_audit_log_time ON audit_log(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action);
-- M4 batch 3.1.16A-2: principal-scoped audit lookup.
CREATE INDEX IF NOT EXISTS idx_audit_log_principal
    ON audit_log(principal_id, created_at);
-- M4 batch 3.1.16A-5-1: project-scoped index created by migration helper.

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
    project_id   TEXT NOT NULL DEFAULT '',
    session_id   TEXT NOT NULL DEFAULT '',
    mode         TEXT NOT NULL,
    updated_at   TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (project_id, principal_id, session_id)
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
    principal_id      TEXT NOT NULL DEFAULT '',
    project_id        TEXT NOT NULL DEFAULT '',
    FOREIGN KEY(parent_session_id, principal_id, project_id)
        REFERENCES sessions(id, principal_id, project_id)
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
    -- M4 batch 3.1.16A-5-1: project identity closure (see ``sessions``).
    project_id   TEXT NOT NULL DEFAULT '',
    UNIQUE(session_id, name),
    FOREIGN KEY(session_id, principal_id, project_id)
        REFERENCES sessions(id, principal_id, project_id)
);

CREATE INDEX IF NOT EXISTS idx_session_bookmarks_principal
    ON session_bookmarks(principal_id, session_id);
-- M4 batch 3.1.16A-5-1: project-scoped index created by migration helper.

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

-- Versioned migrations run once, so legacy ownership must also be rejected at
-- the write boundary.  Raw/imported rows cannot become executable merely by
-- being inserted after the migration ledger has advanced.
CREATE TRIGGER IF NOT EXISTS trg_scheduled_tasks_quarantine_legacy_insert
AFTER INSERT ON scheduled_tasks
WHEN NEW.principal_id = 'legacy' AND NEW.status != 'failed'
BEGIN
    UPDATE scheduled_tasks
    SET status = 'failed',
        error = 'quarantined: legacy write - task has no authenticated owner; an admin must re-claim it with a real principal before it can run',
        execution_id = NULL,
        lease_until = NULL
    WHERE id = NEW.id;
END;

CREATE TRIGGER IF NOT EXISTS trg_scheduled_tasks_quarantine_legacy_update
AFTER UPDATE OF principal_id, status ON scheduled_tasks
WHEN NEW.principal_id = 'legacy' AND NEW.status != 'failed'
BEGIN
    UPDATE scheduled_tasks
    SET status = 'failed',
        error = 'quarantined: legacy write - task has no authenticated owner; an admin must re-claim it with a real principal before it can run',
        execution_id = NULL,
        lease_until = NULL
    WHERE id = NEW.id;
END;

-- M4 batch 3.1.16B-5 (CRITICAL): durable operation journal for
-- scheduler control ops.  Closes the gap where ``_pending_persistence``
-- was a pure in-memory dict — a process crash (SIGKILL / power loss)
-- left the user's pause/resume/remove intent lost.  On restart
-- ``recover_all_running_tasks`` unconditionally marked every running
-- task FAILED, silently violating the "I paused this" contract.
--
-- This table records each control op's intent BEFORE the CAS UPDATE
-- is attempted.  On restart, ``CronEngine.start()`` replays entries
-- with ``applied_at IS NULL``: pause/remove intents are re-applied
-- (roll-forward) if the DB is still at a non-terminal state; resume
-- intents are re-applied if the DB is still at ``paused``.  Executor
-- finalize writes are NOT journaled here — a crash mid-execution is
-- correctly disclosed as FAILED by ``recover_all_running_tasks``
-- (at-least-once semantics), not silently rolled forward.
--
-- ``operation_type`` is one of: ``pause`` / ``resume`` / ``remove`` /
-- ``quarantine`` (drift quarantine from B-2).  ``create`` is NOT
-- journaled — the INSERT itself is atomic, so a crash either leaves
-- the row created or not created, with no ambiguity to recover from.
--
-- ``applied_at`` is NULL for entries whose CAS has not yet been
-- confirmed successful.  ``start()`` scans these in ``seq`` order
-- and either re-applies them or marks them stale (superseded by a
-- newer op or by recovery).
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
    -- M4 batch 3.1.16A-5-1: project identity closure (see ``sessions``).
    -- Stamped at journal-write time so cross-project forensics can
    -- disambiguate entries when multiple projects share a state DB
    -- (defensive — A-1 isolates DBs by project, but the column
    -- future-proofs against accidental cross-DB contamination).
    project_id       TEXT NOT NULL DEFAULT ''
);

-- Pending-entry lookup (partial index — only NULL rows).
CREATE INDEX IF NOT EXISTS idx_scheduler_journal_pending
    ON scheduler_operation_journal(seq) WHERE applied_at IS NULL;
-- Per-task history (reconcile / forensics).
CREATE INDEX IF NOT EXISTS idx_scheduler_journal_task
    ON scheduler_operation_journal(task_id, seq);
-- M4 batch 3.1.16A-5-1: project-scoped index created by migration helper.

-- Security closure: durable idempotent tool-operation journal.  A running
-- row is never replayed automatically after a restart; it is disclosed as
-- UNKNOWN until an operator reconciles the external effect.
CREATE TABLE IF NOT EXISTS tool_operations (
    operation_id       TEXT PRIMARY KEY,
    tool_name          TEXT NOT NULL,
    arguments_digest   TEXT NOT NULL,
    status             TEXT NOT NULL
        CHECK (status IN ('running', 'completed', 'unknown')),
    effect_id          TEXT NOT NULL,
    effect_status      TEXT NOT NULL,
    reconciliation_hint TEXT NOT NULL DEFAULT '',
    result_json        TEXT NOT NULL DEFAULT '',
    owner_token        TEXT NOT NULL,
    principal_id       TEXT NOT NULL DEFAULT '',
    project_id         TEXT NOT NULL DEFAULT '',
    session_id         TEXT NOT NULL DEFAULT '',
    task_id            TEXT NOT NULL DEFAULT '',
    workspace_id       TEXT NOT NULL DEFAULT '',
    created_at         TEXT NOT NULL,
    updated_at         TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tool_operations_status
    ON tool_operations(status, updated_at);
CREATE INDEX IF NOT EXISTS idx_tool_operations_owner
    ON tool_operations(principal_id, project_id, session_id);

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
    principal_id   TEXT NOT NULL DEFAULT 'legacy',
    -- M4 batch 3.1.16A-5-1: project identity closure (see ``sessions``).
    project_id     TEXT NOT NULL DEFAULT '',
    -- M7.1.3: canonical durable cognitive phase and its independent CAS
    -- version.  Runtime migration source: migrations/0017_*.sql.
    cognitive_state TEXT NOT NULL DEFAULT 'uninitialized'
        CHECK (cognitive_state IN (
            'uninitialized', 'understanding', 'exploring', 'planning',
            'implementing', 'verifying', 'diagnosing', 'recovering',
            'replanning', 'reviewing', 'completion_check'
        )),
    control_state_version INTEGER NOT NULL DEFAULT 0
        CHECK (control_state_version >= 0),
    -- M7.3 closure amendment: exact READY revision that caused the current
    -- IMPLEMENTING cognitive phase.  This is descriptive control state, not
    -- execution/approval/workspace authority; runtime migration source is
    -- migrations/0020_plan_publication_fence.sql.
    published_plan_revision_id TEXT,
    -- M7.5: descriptive identity of the RecoveryDecision that caused the
    -- latest recovery-control transition.  This is not execution, approval,
    -- or lifecycle authority; runtime migration source is v22.
    last_applied_recovery_decision_id TEXT
);

CREATE INDEX IF NOT EXISTS idx_coding_tasks_status ON coding_tasks(status, updated_at);
CREATE INDEX IF NOT EXISTS idx_coding_tasks_principal ON coding_tasks(principal_id, status);
-- M4 batch 3.1.16A-5-1: project-scoped index created by migration helper.

-- M7.6: canonical plan-tool route history and execution projections. Runtime
-- source of truth is migrations/0023_plan_tool_routing.sql.
CREATE TABLE IF NOT EXISTS agent_plan_tool_routes (
    route_id TEXT PRIMARY KEY,
    route_sequence INTEGER NOT NULL CHECK (route_sequence >= 1),
    principal_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    execution_epoch_digest TEXT,
    plan_revision_id TEXT,
    plan_revision_digest TEXT,
    plan_step_id TEXT,
    plan_step_digest TEXT,
    tool_name TEXT NOT NULL,
    tool_security_digest TEXT NOT NULL,
    arguments_digest TEXT NOT NULL,
    authorization_resource_digest TEXT NOT NULL,
    route_disposition TEXT NOT NULL,
    reason_code TEXT NOT NULL,
    route_input_digest TEXT NOT NULL,
    route_digest TEXT NOT NULL,
    task_owner_principal_id TEXT NOT NULL DEFAULT '',
    execution_principal_id TEXT NOT NULL DEFAULT '',
    subagent_assignment_id TEXT,
    subagent_assignment_digest TEXT,
    canonical_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (principal_id, project_id, task_id, route_sequence)
);
CREATE TABLE IF NOT EXISTS agent_plan_step_states (
    principal_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    execution_epoch_digest TEXT NOT NULL,
    plan_revision_id TEXT NOT NULL,
    plan_revision_digest TEXT NOT NULL,
    plan_step_id TEXT NOT NULL,
    plan_step_digest TEXT NOT NULL,
    state TEXT NOT NULL,
    attempt_generation INTEGER NOT NULL,
    covered_targets TEXT NOT NULL,
    covered_targets_digest TEXT NOT NULL,
    active_route_id TEXT,
    active_route_digest TEXT,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (principal_id, project_id, task_id, execution_epoch_digest, plan_step_id)
);
CREATE TABLE IF NOT EXISTS agent_plan_dispatch_fences (
    fence_id TEXT PRIMARY KEY,
    route_id TEXT NOT NULL,
    route_digest TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    execution_epoch_digest TEXT NOT NULL,
    plan_revision_id TEXT NOT NULL,
    plan_step_id TEXT,
    workspace_id TEXT NOT NULL,
    workspace_generation INTEGER NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    finished_at TEXT,
    effect_status TEXT,
    effect_id TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_plan_dispatch_fences_route
    ON agent_plan_dispatch_fences(route_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_plan_dispatch_fences_active_step
    ON agent_plan_dispatch_fences(
        principal_id, project_id, task_id, execution_epoch_digest, plan_step_id
    )
    WHERE status = 'ACTIVE' AND plan_step_id IS NOT NULL;

-- M7.8: immutable plan-bound sub-agent assignments and mutable run state.
CREATE TABLE IF NOT EXISTS agent_subagent_assignments (
    assignment_id TEXT PRIMARY KEY,
    assignment_sequence INTEGER NOT NULL CHECK (assignment_sequence >= 1),
    task_owner_principal_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    parent_task_id TEXT NOT NULL,
    goal_spec_id TEXT NOT NULL,
    goal_spec_digest TEXT NOT NULL,
    parent_task_status TEXT NOT NULL,
    parent_cognitive_state TEXT NOT NULL,
    parent_control_state_version INTEGER NOT NULL CHECK (parent_control_state_version >= 0),
    workspace_id TEXT NOT NULL,
    repository_id TEXT NOT NULL,
    base_revision TEXT,
    workspace_generation INTEGER NOT NULL CHECK (workspace_generation > 0),
    published_plan_revision_id TEXT NOT NULL,
    published_plan_revision_digest TEXT NOT NULL,
    execution_epoch_digest TEXT NOT NULL,
    plan_step_id TEXT NOT NULL,
    plan_step_digest TEXT NOT NULL,
    plan_operation TEXT NOT NULL,
    allowed_tools TEXT NOT NULL,
    child_execution_principal_id TEXT NOT NULL,
    child_session_id TEXT NOT NULL,
    child_runtime_id TEXT NOT NULL,
    depth INTEGER NOT NULL CHECK (depth = 1),
    policy_digest TEXT NOT NULL,
    assignment_json TEXT NOT NULL,
    assignment_digest TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT,
    UNIQUE (task_owner_principal_id, project_id, parent_task_id, execution_epoch_digest, plan_step_id)
);
CREATE TABLE IF NOT EXISTS agent_subagent_runs (
    assignment_id TEXT PRIMARY KEY REFERENCES agent_subagent_assignments(assignment_id),
    state TEXT NOT NULL CHECK (state IN ('PENDING', 'ACTIVE', 'COMPLETED', 'FAILED', 'CANCELLED', 'STALE', 'ORPHANED')),
    state_version INTEGER NOT NULL CHECK (state_version >= 0),
    started_at TEXT,
    finished_at TEXT,
    error TEXT
);

-- M7.1.2: canonical immutable user-goal declaration.  The runtime migration
-- source is migrations/0016_goal_specs.sql; this aggregate schema is retained
-- for tooling and documentation only.
CREATE TABLE IF NOT EXISTS agent_goal_specs (
    goal_spec_id    TEXT PRIMARY KEY,
    task_id         TEXT NOT NULL UNIQUE,
    principal_id    TEXT NOT NULL,
    project_id      TEXT NOT NULL,
    schema_version  INTEGER NOT NULL,
    semantic_digest TEXT NOT NULL,
    canonical_json  TEXT NOT NULL,
    created_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_agent_goal_specs_owner_task
    ON agent_goal_specs(principal_id, project_id, task_id);
CREATE INDEX IF NOT EXISTS idx_agent_goal_specs_owner_digest
    ON agent_goal_specs(principal_id, project_id, semantic_digest);

-- M7.1.4: passive immutable completion-evaluation ledger.  The runtime
-- migration source is migrations/0018_completion_decisions.sql; no legacy
-- TaskStatus is backfilled into this table.
CREATE TABLE IF NOT EXISTS agent_completion_decisions (
    decision_id       TEXT PRIMARY KEY,
    task_id           TEXT NOT NULL,
    principal_id      TEXT NOT NULL,
    project_id        TEXT NOT NULL,
    decision_sequence INTEGER NOT NULL
        CHECK (decision_sequence >= 1),
    schema_version    INTEGER NOT NULL
        CHECK (schema_version >= 1),
    decision_digest   TEXT NOT NULL,
    canonical_json    TEXT NOT NULL,
    created_at        TEXT NOT NULL,
    UNIQUE (task_id, decision_sequence)
);
CREATE INDEX IF NOT EXISTS idx_agent_completion_decisions_owner_task_sequence
    ON agent_completion_decisions(
        principal_id, project_id, task_id, decision_sequence
    );

CREATE TRIGGER IF NOT EXISTS trg_agent_completion_decisions_immutable_update
BEFORE UPDATE ON agent_completion_decisions
BEGIN
    SELECT RAISE(
        ABORT,
        'agent_completion_decisions is append-only: updates are forbidden'
    );
END;

CREATE TRIGGER IF NOT EXISTS trg_agent_completion_decisions_immutable_delete
BEFORE DELETE ON agent_completion_decisions
BEGIN
    SELECT RAISE(
        ABORT,
        'agent_completion_decisions is append-only: deletes are forbidden'
    );
END;

-- M7.3: passive immutable deterministic planning-revision ledger.  The
-- runtime migration source is migrations/0019_plan_revisions.sql; this
-- aggregate schema is retained for tooling and documentation only.
CREATE TABLE IF NOT EXISTS agent_plan_revisions (
    plan_revision_id       TEXT PRIMARY KEY,
    task_id                TEXT NOT NULL,
    principal_id           TEXT NOT NULL,
    project_id             TEXT NOT NULL,
    revision_sequence      INTEGER NOT NULL CHECK (revision_sequence >= 1),
    parent_revision_id     TEXT,
    schema_version         INTEGER NOT NULL CHECK (schema_version >= 1),
    planner_schema_version INTEGER NOT NULL CHECK (planner_schema_version >= 1),
    planner_algorithm_version TEXT NOT NULL,
    goal_spec_id           TEXT NOT NULL,
    goal_spec_digest       TEXT NOT NULL,
    workspace_id           TEXT NOT NULL,
    repository_id          TEXT NOT NULL,
    base_revision           TEXT,
    context_bundle_id      TEXT NOT NULL,
    context_bundle_digest  TEXT NOT NULL,
    context_request_digest TEXT NOT NULL,
    repository_generation  TEXT NOT NULL,
    index_generation       TEXT NOT NULL,
    context_freshness      TEXT NOT NULL CHECK (
        context_freshness IN ('fresh', 'stale', 'mixed_generation', 'unavailable')
    ),
    cognitive_state        TEXT NOT NULL,
    control_state_version  INTEGER NOT NULL CHECK (control_state_version >= 0),
    task_status            TEXT NOT NULL,
    disposition             TEXT NOT NULL CHECK (
        disposition IN ('ready', 'blocked', 'stale', 'invalid')
    ),
    planning_input_digest  TEXT NOT NULL,
    plan_semantic_digest   TEXT NOT NULL,
    canonical_json         TEXT NOT NULL,
    created_at             TEXT NOT NULL,
    UNIQUE (task_id, principal_id, project_id, revision_sequence)
);
CREATE INDEX IF NOT EXISTS idx_agent_plan_revisions_owner_task_sequence
    ON agent_plan_revisions(principal_id, project_id, task_id, revision_sequence);
CREATE INDEX IF NOT EXISTS idx_agent_plan_revisions_owner_parent
    ON agent_plan_revisions(principal_id, project_id, task_id, parent_revision_id);

CREATE TRIGGER IF NOT EXISTS trg_agent_plan_revisions_immutable_update
BEFORE UPDATE ON agent_plan_revisions
BEGIN
    SELECT RAISE(ABORT, 'agent_plan_revisions is append-only: updates are forbidden');
END;
CREATE TRIGGER IF NOT EXISTS trg_agent_plan_revisions_immutable_delete
BEFORE DELETE ON agent_plan_revisions
BEGIN
    SELECT RAISE(ABORT, 'agent_plan_revisions is append-only: deletes are forbidden');
END;

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

-- M7.4: immutable trusted-verification assessment history.  The runtime
-- migration source is migrations/0021_trusted_verification_assessments.sql;
-- this aggregate schema is retained for tooling and documentation only.
CREATE TABLE IF NOT EXISTS agent_verification_assessments (
    assessment_id                       TEXT PRIMARY KEY,
    task_id                              TEXT NOT NULL,
    principal_id                         TEXT NOT NULL,
    project_id                           TEXT NOT NULL,
    assessment_sequence                  INTEGER NOT NULL CHECK (assessment_sequence >= 1),
    schema_version                       INTEGER NOT NULL CHECK (schema_version >= 1),
    goal_spec_id                         TEXT NOT NULL,
    goal_spec_digest                     TEXT NOT NULL,
    cognitive_state                      TEXT NOT NULL,
    control_state_version                INTEGER NOT NULL CHECK (control_state_version >= 0),
    task_status                          TEXT NOT NULL,
    workspace_id                         TEXT NOT NULL,
    repository_id                        TEXT NOT NULL,
    base_revision                        TEXT,
    published_plan_revision_id           TEXT,
    published_plan_revision_digest       TEXT,
    repository_generation                TEXT,
    change_identity                      TEXT,
    policy_digest                        TEXT NOT NULL,
    catalog_fingerprint                  TEXT NOT NULL,
    verification_algorithm_version      TEXT NOT NULL,
    input_digest                         TEXT NOT NULL,
    disposition                          TEXT NOT NULL CHECK (
        disposition IN ('satisfied', 'failed', 'inconclusive', 'unavailable', 'stale')
    ),
    assessment_digest                   TEXT NOT NULL,
    canonical_json                       TEXT NOT NULL,
    created_at                           TEXT NOT NULL,
    CHECK (
        (published_plan_revision_id IS NULL AND published_plan_revision_digest IS NULL)
        OR (published_plan_revision_id IS NOT NULL AND published_plan_revision_digest IS NOT NULL)
    ),
    CHECK (repository_generation IS NOT NULL OR change_identity IS NOT NULL),
    UNIQUE (task_id, principal_id, project_id, assessment_sequence)
);
CREATE INDEX IF NOT EXISTS idx_agent_verification_assessments_owner_task_sequence
    ON agent_verification_assessments(
        principal_id, project_id, task_id, assessment_sequence
    );
CREATE INDEX IF NOT EXISTS idx_agent_verification_assessments_owner_digest
    ON agent_verification_assessments(
        principal_id, project_id, assessment_digest
    );
CREATE TRIGGER IF NOT EXISTS trg_agent_verification_assessments_immutable_update
BEFORE UPDATE ON agent_verification_assessments
BEGIN
    SELECT RAISE(
        ABORT,
        'agent_verification_assessments is append-only: updates are forbidden'
    );
END;
CREATE TRIGGER IF NOT EXISTS trg_agent_verification_assessments_immutable_delete
BEFORE DELETE ON agent_verification_assessments
BEGIN
    SELECT RAISE(
        ABORT,
        'agent_verification_assessments is append-only: deletes are forbidden'
    );
END;

-- M7.5: immutable recovery-decision history.  The runtime migration source
-- is migrations/0022_recovery_control_plane.sql; this aggregate schema is
-- retained for tooling and documentation only.
CREATE TABLE IF NOT EXISTS agent_recovery_decisions (
    recovery_decision_id                 TEXT PRIMARY KEY,
    task_id                              TEXT NOT NULL,
    principal_id                         TEXT NOT NULL,
    project_id                           TEXT NOT NULL,
    recovery_sequence                    INTEGER NOT NULL CHECK (recovery_sequence >= 1),
    schema_version                       INTEGER NOT NULL CHECK (schema_version >= 1),
    goal_spec_id                         TEXT NOT NULL,
    goal_spec_digest                     TEXT NOT NULL,
    source_cognitive_state               TEXT NOT NULL,
    source_control_state_version         INTEGER NOT NULL CHECK (source_control_state_version >= 0),
    source_task_status                   TEXT NOT NULL,
    workspace_id                         TEXT,
    repository_id                        TEXT,
    base_revision                        TEXT,
    published_plan_revision_id           TEXT,
    published_plan_revision_digest       TEXT,
    latest_plan_revision_id              TEXT,
    latest_plan_revision_sequence        INTEGER,
    verification_assessment_id           TEXT,
    verification_assessment_digest       TEXT,
    verification_disposition             TEXT,
    verification_repository_generation   TEXT,
    verification_change_identity         TEXT,
    completion_decision_id               TEXT,
    completion_decision_digest           TEXT,
    completion_decision_sequence         INTEGER,
    completion_outcome                   TEXT,
    completion_continuation_state        TEXT,
    failure_signature_digest             TEXT,
    identical_failure_streak             INTEGER NOT NULL CHECK (identical_failure_streak >= 0),
    recovery_attempt_count               INTEGER NOT NULL CHECK (recovery_attempt_count >= 0),
    replan_count                         INTEGER NOT NULL CHECK (replan_count >= 0),
    total_recovery_count                 INTEGER NOT NULL CHECK (total_recovery_count >= 0),
    planning_status                      TEXT NOT NULL,
    policy_schema_version                INTEGER NOT NULL CHECK (policy_schema_version >= 1),
    policy_max_recovery_attempts_per_plan INTEGER NOT NULL CHECK (policy_max_recovery_attempts_per_plan >= 0),
    policy_identical_failure_threshold   INTEGER NOT NULL CHECK (policy_identical_failure_threshold >= 0),
    policy_max_replans_per_task          INTEGER NOT NULL CHECK (policy_max_replans_per_task >= 0),
    policy_max_recovery_cycles_per_turn  INTEGER NOT NULL CHECK (policy_max_recovery_cycles_per_turn >= 0),
    policy_max_history_records           INTEGER NOT NULL CHECK (policy_max_history_records >= 0),
    policy_digest                        TEXT NOT NULL,
    action                              TEXT NOT NULL CHECK (
        action IN ('no_action', 'recover_current_plan', 'replan', 'block')
    ),
    reason_code                         TEXT NOT NULL,
    subject_ids_json                     TEXT NOT NULL,
    input_digest                         TEXT NOT NULL,
    decision_digest                      TEXT NOT NULL,
    canonical_json                       TEXT NOT NULL,
    created_at                           TEXT NOT NULL,
    CHECK (
        (published_plan_revision_id IS NULL AND published_plan_revision_digest IS NULL)
        OR (published_plan_revision_id IS NOT NULL AND published_plan_revision_digest IS NOT NULL)
    ),
    CHECK (
        (latest_plan_revision_id IS NULL AND latest_plan_revision_sequence IS NULL)
        OR (latest_plan_revision_id IS NOT NULL AND latest_plan_revision_sequence IS NOT NULL)
    ),
    CHECK (
        (verification_assessment_id IS NULL AND verification_assessment_digest IS NULL)
        OR (verification_assessment_id IS NOT NULL AND verification_assessment_digest IS NOT NULL)
    ),
    CHECK (
        (completion_decision_id IS NULL AND completion_decision_digest IS NULL
            AND completion_decision_sequence IS NULL AND completion_outcome IS NULL
            AND completion_continuation_state IS NULL)
        OR (completion_decision_id IS NOT NULL AND completion_decision_digest IS NOT NULL
            AND completion_decision_sequence IS NOT NULL AND completion_outcome IS NOT NULL
            AND completion_continuation_state IS NOT NULL)
    ),
    UNIQUE (task_id, principal_id, project_id, recovery_sequence)
);
CREATE INDEX IF NOT EXISTS idx_agent_recovery_decisions_owner_task_sequence
    ON agent_recovery_decisions(principal_id, project_id, task_id, recovery_sequence);
CREATE INDEX IF NOT EXISTS idx_agent_recovery_decisions_owner_digest
    ON agent_recovery_decisions(principal_id, project_id, decision_digest);
CREATE TRIGGER IF NOT EXISTS trg_agent_recovery_decisions_immutable_update
BEFORE UPDATE ON agent_recovery_decisions
BEGIN
    SELECT RAISE(ABORT, 'agent_recovery_decisions is append-only: updates are forbidden');
END;
CREATE TRIGGER IF NOT EXISTS trg_agent_recovery_decisions_immutable_delete
BEFORE DELETE ON agent_recovery_decisions
BEGIN
    SELECT RAISE(ABORT, 'agent_recovery_decisions is append-only: deletes are forbidden');
END;
