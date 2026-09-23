-- M8.6: durable task supervision, cooperative controls, checkpoints, and
-- generation-bound rewind records.  Event and checkpoint rows are immutable;
-- mutable state is a bounded projection owned by its repository.

CREATE TABLE IF NOT EXISTS task_supervision_events (
    event_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    repository_generation INTEGER,
    plan_revision INTEGER,
    actor TEXT NOT NULL,
    severity TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    event_digest TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    UNIQUE (task_id, principal_id, project_id, sequence)
);

CREATE INDEX IF NOT EXISTS idx_task_supervision_events_owner
    ON task_supervision_events(principal_id, project_id, task_id, sequence);

CREATE TABLE IF NOT EXISTS task_supervision_states (
    task_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    revision INTEGER NOT NULL,
    state_json TEXT NOT NULL,
    state_digest TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (task_id, principal_id, project_id)
);

CREATE TABLE IF NOT EXISTS task_control_state (
    task_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    control_state TEXT NOT NULL,
    revision INTEGER NOT NULL,
    last_command_id TEXT NOT NULL DEFAULT '',
    last_result_json TEXT,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (task_id, principal_id, project_id)
);

CREATE INDEX IF NOT EXISTS idx_task_control_owner
    ON task_control_state(principal_id, project_id, task_id);

CREATE TABLE IF NOT EXISTS task_checkpoints (
    checkpoint_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    repository_generation INTEGER NOT NULL,
    head_commit TEXT NOT NULL,
    tree_digest TEXT NOT NULL,
    task_revision INTEGER NOT NULL,
    plan_revision INTEGER,
    verification_evidence_digest TEXT,
    checkpoint_kind TEXT NOT NULL,
    label TEXT NOT NULL DEFAULT '',
    snapshot_digest TEXT NOT NULL,
    snapshot_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    checkpoint_digest TEXT NOT NULL UNIQUE
);

CREATE INDEX IF NOT EXISTS idx_task_checkpoints_owner
    ON task_checkpoints(principal_id, project_id, task_id, repository_generation);

CREATE TABLE IF NOT EXISTS rewind_records (
    rewind_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    source_generation INTEGER NOT NULL,
    source_head TEXT NOT NULL,
    source_tree TEXT NOT NULL,
    target_checkpoint_id TEXT NOT NULL,
    target_checkpoint_digest TEXT NOT NULL,
    target_generation INTEGER NOT NULL,
    target_head TEXT NOT NULL,
    target_tree TEXT NOT NULL,
    plan_json TEXT NOT NULL,
    plan_digest TEXT NOT NULL UNIQUE,
    transaction_digest TEXT,
    status TEXT NOT NULL,
    result_json TEXT,
    result_digest TEXT,
    resulting_generation INTEGER,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_rewind_records_owner
    ON rewind_records(principal_id, project_id, task_id, created_at);

CREATE TRIGGER IF NOT EXISTS task_supervision_events_no_update
    BEFORE UPDATE ON task_supervision_events
BEGIN
    SELECT RAISE(ABORT, 'task_supervision_events is append-only');
END;

CREATE TRIGGER IF NOT EXISTS task_supervision_events_no_delete
    BEFORE DELETE ON task_supervision_events
BEGIN
    SELECT RAISE(ABORT, 'task_supervision_events is append-only');
END;

CREATE TRIGGER IF NOT EXISTS task_checkpoints_no_update
    BEFORE UPDATE ON task_checkpoints
BEGIN
    SELECT RAISE(ABORT, 'task_checkpoints is immutable');
END;

CREATE TRIGGER IF NOT EXISTS task_checkpoints_no_delete
    BEFORE DELETE ON task_checkpoints
BEGIN
    SELECT RAISE(ABORT, 'task_checkpoints is immutable');
END;
