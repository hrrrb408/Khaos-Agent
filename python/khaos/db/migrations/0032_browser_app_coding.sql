-- M8.8: durable browser/app identity, action, evidence, and lifecycle
-- projections.  These rows are descriptive recovery metadata only; they are
-- not permission, approval, execution, verification, or completion authority.
-- Live Playwright objects and page contents are never persisted.

CREATE TABLE IF NOT EXISTS browser_resource_state (
    resource_id TEXT PRIMARY KEY,
    resource_kind TEXT NOT NULL,
    task_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    workspace_generation INTEGER NOT NULL CHECK (workspace_generation >= 0),
    principal_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    lifecycle_state TEXT NOT NULL,
    payload_json TEXT NOT NULL CHECK (length(payload_json) <= 65536),
    payload_digest TEXT NOT NULL,
    quarantine_reason TEXT NOT NULL DEFAULT '' CHECK (length(quarantine_reason) <= 2048),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_browser_resource_owner
    ON browser_resource_state(principal_id, project_id, task_id, resource_kind, lifecycle_state);

CREATE TABLE IF NOT EXISTS browser_resource_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    resource_id TEXT NOT NULL,
    resource_kind TEXT NOT NULL,
    task_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    workspace_generation INTEGER NOT NULL CHECK (workspace_generation >= 0),
    principal_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    lifecycle_state TEXT NOT NULL,
    payload_json TEXT NOT NULL CHECK (length(payload_json) <= 65536),
    payload_digest TEXT NOT NULL,
    event_digest TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_browser_resource_events_owner
    ON browser_resource_events(principal_id, project_id, task_id, resource_id, event_id);

CREATE TRIGGER IF NOT EXISTS trg_browser_resource_events_immutable_update
BEFORE UPDATE ON browser_resource_events
BEGIN
    SELECT RAISE(ABORT, 'browser_resource_events is append-only: updates are forbidden');
END;

CREATE TRIGGER IF NOT EXISTS trg_browser_resource_events_immutable_delete
BEFORE DELETE ON browser_resource_events
BEGIN
    SELECT RAISE(ABORT, 'browser_resource_events is append-only: deletes are forbidden');
END;
