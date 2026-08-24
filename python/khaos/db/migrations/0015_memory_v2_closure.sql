-- Memory V2 production closure surfaces.
-- Canonical events remain append-only.  Projection generations and privacy
-- tombstones make rebuild/switch/forget state explicit without mutating the
-- historical event rows.

CREATE TABLE IF NOT EXISTS memory_projection_state (
    provider_id       TEXT PRIMARY KEY,
    active_generation INTEGER NOT NULL DEFAULT 0,
    lifecycle_state   TEXT NOT NULL DEFAULT 'ACTIVE',
    cursor_recorded_at TEXT NOT NULL DEFAULT '',
    cursor_event_id   TEXT NOT NULL DEFAULT '',
    updated_at        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS memory_projection_generations (
    provider_id       TEXT NOT NULL,
    generation        INTEGER NOT NULL,
    project_id        TEXT NOT NULL,
    principal_id      TEXT NOT NULL,
    status            TEXT NOT NULL,
    event_count       INTEGER NOT NULL DEFAULT 0,
    node_count        INTEGER NOT NULL DEFAULT 0,
    error             TEXT NOT NULL DEFAULT '',
    started_at        TEXT NOT NULL,
    finished_at       TEXT,
    PRIMARY KEY (provider_id, generation, project_id, principal_id)
);

CREATE INDEX IF NOT EXISTS idx_memory_projection_generations_status
    ON memory_projection_generations(project_id, principal_id, status, started_at);

CREATE TABLE IF NOT EXISTS memory_privacy_tombstones (
    memory_id    TEXT NOT NULL,
    provider_id  TEXT NOT NULL DEFAULT '',
    namespace    TEXT NOT NULL DEFAULT '',
    event_id     TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    project_id   TEXT NOT NULL,
    session_id   TEXT NOT NULL DEFAULT '',
    created_at   TEXT NOT NULL,
    PRIMARY KEY (memory_id, provider_id, namespace, event_id)
);

CREATE INDEX IF NOT EXISTS idx_memory_privacy_tombstones_event
    ON memory_privacy_tombstones(project_id, principal_id, event_id);

CREATE TABLE IF NOT EXISTS memory_maintenance_state (
    principal_id   TEXT NOT NULL,
    project_id     TEXT NOT NULL,
    operation      TEXT NOT NULL,
    cursor_json    TEXT NOT NULL DEFAULT '{}',
    status         TEXT NOT NULL,
    updated_at     TEXT NOT NULL,
    detail_json    TEXT NOT NULL DEFAULT '{}',
    PRIMARY KEY (principal_id, project_id, operation)
);
