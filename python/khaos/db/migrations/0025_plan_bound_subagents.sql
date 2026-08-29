-- M7.8: immutable plan-bound child assignments and CAS run projections.
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
CREATE INDEX IF NOT EXISTS idx_agent_subagent_assignments_owner_task
    ON agent_subagent_assignments(task_owner_principal_id, project_id, parent_task_id);
CREATE TRIGGER IF NOT EXISTS trg_agent_subagent_assignments_no_update
BEFORE UPDATE ON agent_subagent_assignments BEGIN
    SELECT RAISE(ABORT, 'agent_subagent_assignments is append-only');
END;
CREATE TRIGGER IF NOT EXISTS trg_agent_subagent_assignments_no_delete
BEFORE DELETE ON agent_subagent_assignments BEGIN
    SELECT RAISE(ABORT, 'agent_subagent_assignments is append-only');
END;

CREATE TABLE IF NOT EXISTS agent_subagent_runs (
    assignment_id TEXT PRIMARY KEY REFERENCES agent_subagent_assignments(assignment_id),
    state TEXT NOT NULL CHECK (state IN ('PENDING', 'ACTIVE', 'COMPLETED', 'FAILED', 'CANCELLED', 'STALE', 'ORPHANED')),
    state_version INTEGER NOT NULL CHECK (state_version >= 0),
    started_at TEXT,
    finished_at TEXT,
    error TEXT
);
CREATE INDEX IF NOT EXISTS idx_agent_subagent_runs_active
    ON agent_subagent_runs(state, assignment_id);

ALTER TABLE agent_plan_tool_routes ADD COLUMN task_owner_principal_id TEXT NOT NULL DEFAULT '';
ALTER TABLE agent_plan_tool_routes ADD COLUMN execution_principal_id TEXT NOT NULL DEFAULT '';
ALTER TABLE agent_plan_tool_routes ADD COLUMN subagent_assignment_id TEXT;
ALTER TABLE agent_plan_tool_routes ADD COLUMN subagent_assignment_digest TEXT;
