-- M8.5: durable parallel child/worktree, result, merge, and event records.
-- These tables are projections of authority-owned objects.  JSON payloads are
-- digest-bound by the repository; they are not model-controlled authority.

CREATE TABLE IF NOT EXISTS agent_parallel_assignments (
    assignment_id TEXT PRIMARY KEY,
    parent_task_id TEXT NOT NULL,
    parent_workspace_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    parent_principal_id TEXT NOT NULL,
    child_principal_id TEXT NOT NULL,
    child_runtime_id TEXT NOT NULL,
    role TEXT NOT NULL,
    access_mode TEXT NOT NULL,
    base_generation INTEGER NOT NULL,
    base_commit TEXT NOT NULL,
    assignment_digest TEXT NOT NULL UNIQUE,
    assignment_json TEXT NOT NULL,
    state TEXT NOT NULL,
    revision INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    cleanup_state TEXT NOT NULL DEFAULT 'pending',
    quarantine_reason TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_agent_parallel_assignments_parent
    ON agent_parallel_assignments(project_id, parent_task_id, state, revision);

CREATE TABLE IF NOT EXISTS agent_parallel_child_workspaces (
    assignment_id TEXT PRIMARY KEY,
    child_task_id TEXT NOT NULL,
    child_workspace_id TEXT NOT NULL UNIQUE,
    child_worktree_path TEXT NOT NULL,
    child_branch TEXT NOT NULL,
    base_generation INTEGER NOT NULL,
    base_commit TEXT NOT NULL,
    binding_digest TEXT NOT NULL UNIQUE,
    state TEXT NOT NULL,
    revision INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    cleaned_at TEXT,
    quarantine_reason TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (assignment_id) REFERENCES agent_parallel_assignments(assignment_id)
);

CREATE TABLE IF NOT EXISTS agent_parallel_subagent_results (
    assignment_id TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    result_json TEXT NOT NULL,
    result_digest TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    FOREIGN KEY (assignment_id) REFERENCES agent_parallel_assignments(assignment_id)
);

CREATE TABLE IF NOT EXISTS agent_parallel_merge_records (
    merge_id TEXT PRIMARY KEY,
    parent_task_id TEXT NOT NULL,
    parent_workspace_id TEXT NOT NULL,
    expected_parent_head TEXT NOT NULL,
    expected_parent_generation INTEGER NOT NULL,
    candidate_ids_json TEXT NOT NULL,
    plan_json TEXT NOT NULL,
    plan_digest TEXT NOT NULL,
    state TEXT NOT NULL,
    result_json TEXT,
    result_digest TEXT,
    published_head TEXT,
    published_generation INTEGER,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS agent_parallel_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    assignment_id TEXT,
    merge_id TEXT,
    event_type TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    payload_digest TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (assignment_id) REFERENCES agent_parallel_assignments(assignment_id),
    FOREIGN KEY (merge_id) REFERENCES agent_parallel_merge_records(merge_id)
);

CREATE INDEX IF NOT EXISTS idx_agent_parallel_events_assignment
    ON agent_parallel_events(assignment_id, event_id);

CREATE TRIGGER IF NOT EXISTS agent_parallel_events_no_update
    BEFORE UPDATE ON agent_parallel_events
BEGIN
    SELECT RAISE(ABORT, 'agent_parallel_events is append-only');
END;

CREATE TRIGGER IF NOT EXISTS agent_parallel_events_no_delete
    BEFORE DELETE ON agent_parallel_events
BEGIN
    SELECT RAISE(ABORT, 'agent_parallel_events is append-only');
END;
