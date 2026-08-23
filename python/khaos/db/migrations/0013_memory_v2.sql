-- Memory V2 canonical event ledger, derived graph and provider state.
-- This migration is append-only in the schema chain.  Rebuildable indexes
-- (memory_nodes_fts and graph adjacency indexes) never become a truth source.

CREATE TABLE IF NOT EXISTS memory_events (
    event_id       TEXT PRIMARY KEY,
    event_type     TEXT NOT NULL,
    principal_id   TEXT NOT NULL,
    project_id     TEXT NOT NULL,
    session_id     TEXT NOT NULL DEFAULT '',
    task_id        TEXT NOT NULL DEFAULT '',
    workspace_id   TEXT NOT NULL DEFAULT '',
    repo_id        TEXT NOT NULL DEFAULT '',
    branch         TEXT NOT NULL DEFAULT '',
    commit_sha     TEXT NOT NULL DEFAULT '',
    source_type    TEXT NOT NULL,
    source_ref     TEXT NOT NULL DEFAULT '',
    occurred_at    TEXT NOT NULL,
    observed_at    TEXT NOT NULL,
    recorded_at    TEXT NOT NULL,
    payload_json   TEXT NOT NULL,
    payload_hash   TEXT NOT NULL,
    trust_hint     TEXT NOT NULL,
    sensitivity    TEXT NOT NULL,
    CHECK (length(event_id) <= 256),
    CHECK (length(payload_json) <= 1048576)
);

CREATE INDEX IF NOT EXISTS idx_memory_events_scope
    ON memory_events(project_id, principal_id, session_id, recorded_at);
CREATE INDEX IF NOT EXISTS idx_memory_events_type
    ON memory_events(project_id, principal_id, event_type, occurred_at);

CREATE TRIGGER IF NOT EXISTS trg_memory_events_append_only_update
BEFORE UPDATE ON memory_events BEGIN
    SELECT RAISE(ABORT, 'memory_events is append-only');
END;

CREATE TRIGGER IF NOT EXISTS trg_memory_events_append_only_delete
BEFORE DELETE ON memory_events BEGIN
    SELECT RAISE(ABORT, 'memory_events is append-only');
END;

CREATE TABLE IF NOT EXISTS memory_nodes (
    memory_id              TEXT PRIMARY KEY,
    memory_type            TEXT NOT NULL,
    status                 TEXT NOT NULL,
    namespace              TEXT NOT NULL,
    scope                  TEXT NOT NULL,
    principal_id           TEXT NOT NULL,
    project_id             TEXT NOT NULL,
    session_id             TEXT NOT NULL DEFAULT '',
    key                    TEXT NOT NULL DEFAULT '',
    content                TEXT NOT NULL,
    content_hash           TEXT NOT NULL,
    authority              TEXT NOT NULL,
    confidence             REAL NOT NULL,
    sensitivity            TEXT NOT NULL,
    usage_policy           TEXT NOT NULL,
    applicability_json      TEXT NOT NULL DEFAULT '{}',
    environment_json        TEXT NOT NULL DEFAULT '{}',
    valid_from              TEXT,
    valid_to                TEXT,
    superseded_by           TEXT,
    created_at              TEXT NOT NULL,
    updated_at              TEXT NOT NULL,
    provider_id             TEXT NOT NULL,
    retrieval_count         INTEGER NOT NULL DEFAULT 0,
    application_count       INTEGER NOT NULL DEFAULT 0,
    verified_success_count  INTEGER NOT NULL DEFAULT 0,
    verified_failure_count  INTEGER NOT NULL DEFAULT 0,
    contradiction_count     INTEGER NOT NULL DEFAULT 0,
    user_confirm_count      INTEGER NOT NULL DEFAULT 0,
    CHECK (confidence >= 0.0 AND confidence <= 1.0),
    CHECK (status IN ('OBSERVED', 'CANDIDATE', 'QUARANTINED', 'ACTIVE',
                     'VERIFIED', 'SUPERSEDED', 'REVOKED', 'REJECTED')),
    CHECK (namespace IN ('private', 'session', 'project', 'shared')),
    CHECK (length(content) <= 65536),
    UNIQUE (project_id, namespace, principal_id, session_id, memory_type,
            scope, key, content_hash)
);

CREATE INDEX IF NOT EXISTS idx_memory_nodes_current
    ON memory_nodes(project_id, principal_id, namespace, session_id, status,
                    scope, updated_at);
CREATE INDEX IF NOT EXISTS idx_memory_nodes_validity
    ON memory_nodes(project_id, principal_id, valid_from, valid_to);
CREATE INDEX IF NOT EXISTS idx_memory_nodes_type
    ON memory_nodes(project_id, principal_id, memory_type, status);

CREATE TABLE IF NOT EXISTS memory_entities (
    entity_id       TEXT PRIMARY KEY,
    entity_type     TEXT NOT NULL,
    canonical_name  TEXT NOT NULL,
    aliases_json    TEXT NOT NULL DEFAULT '[]',
    principal_id    TEXT NOT NULL,
    project_id      TEXT NOT NULL,
    metadata_json   TEXT NOT NULL DEFAULT '{}',
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    UNIQUE (project_id, entity_type, canonical_name)
);

CREATE TABLE IF NOT EXISTS memory_edges (
    edge_id         TEXT PRIMARY KEY,
    from_kind       TEXT NOT NULL,
    from_id         TEXT NOT NULL,
    relation        TEXT NOT NULL,
    to_kind         TEXT NOT NULL,
    to_id           TEXT NOT NULL,
    principal_id    TEXT NOT NULL,
    project_id      TEXT NOT NULL,
    authority       TEXT NOT NULL,
    confidence      REAL NOT NULL,
    valid_from      TEXT,
    valid_to        TEXT,
    source_event_id TEXT,
    created_at      TEXT NOT NULL,
    UNIQUE (project_id, from_kind, from_id, relation, to_kind, to_id)
);

CREATE INDEX IF NOT EXISTS idx_memory_edges_from
    ON memory_edges(project_id, from_kind, from_id, relation);
CREATE INDEX IF NOT EXISTS idx_memory_edges_to
    ON memory_edges(project_id, to_kind, to_id, relation);

CREATE TABLE IF NOT EXISTS memory_evidence (
    evidence_id          TEXT PRIMARY KEY,
    memory_id            TEXT NOT NULL,
    evidence_type        TEXT NOT NULL,
    source_ref            TEXT NOT NULL,
    event_id             TEXT,
    task_id              TEXT,
    turn_id              TEXT,
    tool_call_id         TEXT,
    workspace_id         TEXT,
    commit_sha           TEXT,
    verification_run_id  TEXT,
    observed_at          TEXT NOT NULL,
    valid_from           TEXT,
    valid_to             TEXT,
    principal_id         TEXT NOT NULL,
    project_id           TEXT NOT NULL,
    metadata_json        TEXT NOT NULL DEFAULT '{}',
    UNIQUE (memory_id, evidence_type, source_ref),
    FOREIGN KEY (memory_id) REFERENCES memory_nodes(memory_id)
);

CREATE INDEX IF NOT EXISTS idx_memory_evidence_memory
    ON memory_evidence(project_id, principal_id, memory_id);
CREATE INDEX IF NOT EXISTS idx_memory_evidence_event
    ON memory_evidence(project_id, principal_id, event_id);

CREATE TABLE IF NOT EXISTS memory_provider_state (
    provider_id       TEXT PRIMARY KEY,
    status            TEXT NOT NULL,
    capabilities_json TEXT NOT NULL DEFAULT '{}',
    generation        INTEGER NOT NULL DEFAULT 0,
    last_error        TEXT NOT NULL DEFAULT '',
    updated_at        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS memory_audit (
    audit_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    action         TEXT NOT NULL,
    memory_id      TEXT NOT NULL DEFAULT '',
    provider_id    TEXT NOT NULL DEFAULT '',
    principal_id   TEXT NOT NULL,
    project_id     TEXT NOT NULL,
    session_id     TEXT NOT NULL DEFAULT '',
    detail_json    TEXT NOT NULL DEFAULT '{}',
    created_at     TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_memory_audit_scope
    ON memory_audit(project_id, principal_id, created_at);

CREATE TABLE IF NOT EXISTS memory_nodes_fts (
    memory_id     TEXT NOT NULL,
    key           TEXT NOT NULL,
    content       TEXT NOT NULL,
    memory_type   TEXT NOT NULL,
    applicability TEXT NOT NULL,
    PRIMARY KEY (memory_id)
);

CREATE VIRTUAL TABLE IF NOT EXISTS memory_nodes_fts_search USING fts5(
    memory_id UNINDEXED,
    key,
    content,
    memory_type,
    applicability,
    content='memory_nodes_fts',
    content_rowid='rowid',
    tokenize='unicode61'
);

CREATE TRIGGER IF NOT EXISTS trg_memory_nodes_fts_insert
AFTER INSERT ON memory_nodes BEGIN
    INSERT INTO memory_nodes_fts
        (memory_id, key, content, memory_type, applicability)
    VALUES (new.memory_id, new.key, new.content, new.memory_type,
            new.applicability_json);
    INSERT INTO memory_nodes_fts_search
        (rowid, memory_id, key, content, memory_type, applicability)
    SELECT rowid, memory_id, key, content, memory_type, applicability
    FROM memory_nodes_fts WHERE memory_id = new.memory_id;
END;

CREATE TRIGGER IF NOT EXISTS trg_memory_nodes_fts_delete
AFTER DELETE ON memory_nodes BEGIN
    DELETE FROM memory_nodes_fts_search
    WHERE rowid = (SELECT rowid FROM memory_nodes_fts WHERE memory_id = old.memory_id);
    DELETE FROM memory_nodes_fts WHERE memory_id = old.memory_id;
END;

CREATE TRIGGER IF NOT EXISTS trg_memory_nodes_fts_update
AFTER UPDATE OF key, content, memory_type, applicability_json ON memory_nodes BEGIN
    DELETE FROM memory_nodes_fts_search
    WHERE rowid = (SELECT rowid FROM memory_nodes_fts WHERE memory_id = old.memory_id);
    DELETE FROM memory_nodes_fts WHERE memory_id = old.memory_id;
    INSERT INTO memory_nodes_fts
        (memory_id, key, content, memory_type, applicability)
    VALUES (new.memory_id, new.key, new.content, new.memory_type,
            new.applicability_json);
    INSERT INTO memory_nodes_fts_search
        (rowid, memory_id, key, content, memory_type, applicability)
    SELECT rowid, memory_id, key, content, memory_type, applicability
    FROM memory_nodes_fts WHERE memory_id = new.memory_id;
END;
