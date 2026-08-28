-- M7.6: published-plan tool routes, durable step evidence, and dispatch fences.
-- Route history is append-only. Step state and fences are the only mutable
-- projections and are updated by their repositories under the shared writer.
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
    route_disposition TEXT NOT NULL CHECK (route_disposition IN
        ('allow', 'supporting_read', 'blocked', 'stale', 'ambiguous', 'invalid', 'unavailable')),
    reason_code TEXT NOT NULL,
    route_input_digest TEXT NOT NULL,
    route_digest TEXT NOT NULL,
    canonical_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (principal_id, project_id, task_id, route_sequence)
);
CREATE INDEX IF NOT EXISTS idx_agent_plan_tool_routes_scope
    ON agent_plan_tool_routes(principal_id, project_id, task_id, route_sequence);
CREATE TRIGGER IF NOT EXISTS trg_agent_plan_tool_routes_no_update
BEFORE UPDATE ON agent_plan_tool_routes BEGIN
    SELECT RAISE(ABORT, 'agent_plan_tool_routes is append-only');
END;
CREATE TRIGGER IF NOT EXISTS trg_agent_plan_tool_routes_no_delete
BEFORE DELETE ON agent_plan_tool_routes BEGIN
    SELECT RAISE(ABORT, 'agent_plan_tool_routes is append-only');
END;

CREATE TABLE IF NOT EXISTS agent_plan_step_states (
    principal_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    execution_epoch_digest TEXT NOT NULL,
    plan_revision_id TEXT NOT NULL,
    plan_revision_digest TEXT NOT NULL,
    plan_step_id TEXT NOT NULL,
    plan_step_digest TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('PENDING', 'ACTIVE', 'EXECUTED', 'UNCERTAIN')),
    attempt_generation INTEGER NOT NULL CHECK (attempt_generation >= 1),
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
    workspace_generation INTEGER NOT NULL CHECK (workspace_generation > 0),
    status TEXT NOT NULL CHECK (status IN ('ACTIVE', 'TERMINAL', 'UNCERTAIN')),
    created_at TEXT NOT NULL,
    finished_at TEXT,
    effect_status TEXT,
    effect_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_agent_plan_dispatch_fences_active
    ON agent_plan_dispatch_fences(principal_id, project_id, task_id, status);
CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_plan_dispatch_fences_route
    ON agent_plan_dispatch_fences(route_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_plan_dispatch_fences_active_step
    ON agent_plan_dispatch_fences(
        principal_id, project_id, task_id, execution_epoch_digest, plan_step_id
    )
    WHERE status = 'ACTIVE' AND plan_step_id IS NOT NULL;
