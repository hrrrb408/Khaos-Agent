-- M7.1.2: immutable, owner-bound GoalSpec declarations.
-- The canonical body is stored once here; coding_tasks only carries a
-- projection/reference in state_json.  GoalSpec is not workspace authority.

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

CREATE TRIGGER IF NOT EXISTS trg_agent_goal_specs_immutable_update
BEFORE UPDATE ON agent_goal_specs
BEGIN
    SELECT RAISE(ABORT, 'agent_goal_specs is immutable: updates are forbidden');
END;

CREATE TRIGGER IF NOT EXISTS trg_agent_goal_specs_immutable_delete
BEFORE DELETE ON agent_goal_specs
BEGIN
    SELECT RAISE(ABORT, 'agent_goal_specs is immutable: deletes are forbidden');
END;
