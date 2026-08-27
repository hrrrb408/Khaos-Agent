-- M7.3: immutable deterministic planning revisions.
--
-- This is a passive planning-history ledger.  A READY disposition is not an
-- execution or completion authority, and no legacy task status is backfilled.
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
    ON agent_plan_revisions(
        principal_id, project_id, task_id, revision_sequence
    );

CREATE INDEX IF NOT EXISTS idx_agent_plan_revisions_owner_parent
    ON agent_plan_revisions(
        principal_id, project_id, task_id, parent_revision_id
    );

CREATE TRIGGER IF NOT EXISTS trg_agent_plan_revisions_immutable_update
BEFORE UPDATE ON agent_plan_revisions
BEGIN
    SELECT RAISE(
        ABORT,
        'agent_plan_revisions is append-only: updates are forbidden'
    );
END;

CREATE TRIGGER IF NOT EXISTS trg_agent_plan_revisions_immutable_delete
BEFORE DELETE ON agent_plan_revisions
BEGIN
    SELECT RAISE(
        ABORT,
        'agent_plan_revisions is append-only: deletes are forbidden'
    );
END;
