-- Memory V2 operational surfaces.
--
-- The v13 ledger remains the canonical source.  These tables are either
-- durable configuration/audit surfaces or rebuildable indexes and therefore
-- never replace memory_events as the authority for a memory claim.

CREATE TABLE IF NOT EXISTS memory_profile_state (
    principal_id   TEXT NOT NULL,
    project_id     TEXT NOT NULL,
    profile_id     TEXT NOT NULL,
    config_json    TEXT NOT NULL DEFAULT '{}',
    updated_at     TEXT NOT NULL,
    PRIMARY KEY (principal_id, project_id)
);

CREATE TABLE IF NOT EXISTS memory_provider_registry (
    provider_id       TEXT PRIMARY KEY,
    manifest_json     TEXT NOT NULL,
    lifecycle_state   TEXT NOT NULL,
    active            INTEGER NOT NULL DEFAULT 0 CHECK (active IN (0, 1)),
    generation        INTEGER NOT NULL DEFAULT 0,
    last_error        TEXT NOT NULL DEFAULT '',
    installed_at      TEXT,
    updated_at        TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_memory_provider_registry_active
    ON memory_provider_registry(active, lifecycle_state, updated_at);

CREATE TABLE IF NOT EXISTS memory_code_nodes (
    node_id        TEXT PRIMARY KEY,
    project_id     TEXT NOT NULL,
    repo_id        TEXT NOT NULL,
    commit_sha     TEXT NOT NULL,
    path           TEXT NOT NULL,
    node_kind      TEXT NOT NULL,
    qualified_name TEXT NOT NULL,
    display_name   TEXT NOT NULL,
    line_start     INTEGER NOT NULL,
    line_end       INTEGER NOT NULL,
    content_hash   TEXT NOT NULL,
    metadata_json  TEXT NOT NULL DEFAULT '{}',
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL,
    UNIQUE (project_id, repo_id, commit_sha, path, node_kind, qualified_name)
);

CREATE INDEX IF NOT EXISTS idx_memory_code_nodes_lookup
    ON memory_code_nodes(project_id, repo_id, commit_sha, path, line_start);
CREATE INDEX IF NOT EXISTS idx_memory_code_nodes_symbol
    ON memory_code_nodes(project_id, qualified_name, display_name);

CREATE TABLE IF NOT EXISTS memory_code_edges (
    edge_id       TEXT PRIMARY KEY,
    project_id    TEXT NOT NULL,
    repo_id       TEXT NOT NULL,
    commit_sha    TEXT NOT NULL,
    from_node_id  TEXT NOT NULL,
    to_node_id    TEXT NOT NULL,
    relation      TEXT NOT NULL,
    confidence    REAL NOT NULL CHECK (confidence >= 0.0 AND confidence <= 1.0),
    source_type   TEXT NOT NULL,
    source_ref    TEXT NOT NULL DEFAULT '',
    created_at    TEXT NOT NULL,
    UNIQUE (project_id, repo_id, commit_sha, from_node_id, relation, to_node_id)
);

CREATE INDEX IF NOT EXISTS idx_memory_code_edges_from
    ON memory_code_edges(project_id, repo_id, commit_sha, from_node_id, relation);
CREATE INDEX IF NOT EXISTS idx_memory_code_edges_to
    ON memory_code_edges(project_id, repo_id, commit_sha, to_node_id, relation);

CREATE TABLE IF NOT EXISTS memory_benchmark_runs (
    run_id          TEXT PRIMARY KEY,
    benchmark_name  TEXT NOT NULL,
    provider_id     TEXT NOT NULL,
    profile_id      TEXT NOT NULL,
    order_variant   TEXT NOT NULL,
    repetition      INTEGER NOT NULL,
    started_at      TEXT NOT NULL,
    finished_at     TEXT,
    status          TEXT NOT NULL,
    metrics_json    TEXT NOT NULL DEFAULT '{}',
    error           TEXT NOT NULL DEFAULT '',
    principal_id    TEXT NOT NULL,
    project_id      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_memory_benchmark_scope
    ON memory_benchmark_runs(project_id, principal_id, benchmark_name, started_at);

CREATE TABLE IF NOT EXISTS memory_metric_samples (
    sample_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    metric_name     TEXT NOT NULL,
    value           REAL NOT NULL,
    unit             TEXT NOT NULL,
    provider_id     TEXT NOT NULL DEFAULT '',
    profile_id      TEXT NOT NULL DEFAULT '',
    operation       TEXT NOT NULL DEFAULT '',
    principal_id    TEXT NOT NULL,
    project_id      TEXT NOT NULL,
    recorded_at     TEXT NOT NULL,
    metadata_json   TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_memory_metric_scope
    ON memory_metric_samples(project_id, principal_id, metric_name, recorded_at);
