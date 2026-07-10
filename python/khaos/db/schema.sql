PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS sessions (
    id          TEXT PRIMARY KEY,
    mode        TEXT NOT NULL DEFAULT 'office',
    status      TEXT NOT NULL DEFAULT 'active',
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT NOT NULL DEFAULT (datetime('now')),
    metadata    TEXT DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS messages (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id   TEXT NOT NULL REFERENCES sessions(id),
    role         TEXT NOT NULL,
    content      TEXT NOT NULL DEFAULT '',
    tool_calls   TEXT DEFAULT '[]',
    tool_call_id TEXT,
    token_count  INTEGER NOT NULL DEFAULT 0,
    created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_messages_session ON messages(session_id, created_at);

CREATE TABLE IF NOT EXISTS memories (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scope       TEXT NOT NULL,
    key         TEXT NOT NULL,
    value       TEXT NOT NULL,
    ttl         INTEGER NOT NULL DEFAULT 604800,
    confidence  INTEGER NOT NULL DEFAULT 2,
    access_freq INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(scope, key)
);

CREATE VIRTUAL TABLE IF NOT EXISTS memory_fts USING fts5(
    key,
    value,
    content=memories,
    content_rowid=id,
    tokenize='unicode61'
);

CREATE TRIGGER IF NOT EXISTS memory_ai AFTER INSERT ON memories BEGIN
    INSERT INTO memory_fts(rowid, key, value) VALUES (new.id, new.key, new.value);
END;

CREATE TRIGGER IF NOT EXISTS memory_ad AFTER DELETE ON memories BEGIN
    INSERT INTO memory_fts(memory_fts, rowid, key, value) VALUES('delete', old.id, old.key, old.value);
END;

CREATE TRIGGER IF NOT EXISTS memory_au AFTER UPDATE ON memories BEGIN
    INSERT INTO memory_fts(memory_fts, rowid, key, value) VALUES('delete', old.id, old.key, old.value);
    INSERT INTO memory_fts(rowid, key, value) VALUES (new.id, new.key, new.value);
END;

CREATE TABLE IF NOT EXISTS permissions (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern          TEXT NOT NULL,
    permission_level TEXT NOT NULL,
    approval         TEXT NOT NULL,
    mode             TEXT NOT NULL DEFAULT 'all',
    granted_at       TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_permissions_level ON permissions(permission_level, mode);

CREATE TABLE IF NOT EXISTS tools (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    name             TEXT NOT NULL UNIQUE,
    schema           TEXT NOT NULL,
    modes            TEXT NOT NULL DEFAULT '["all"]',
    permission_level TEXT NOT NULL,
    parallel         INTEGER NOT NULL DEFAULT 0,
    timeout          INTEGER NOT NULL DEFAULT 60,
    enabled          INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    action      TEXT NOT NULL,
    target      TEXT NOT NULL,
    result      TEXT NOT NULL,
    detail      TEXT DEFAULT '',
    session_id  TEXT REFERENCES sessions(id),
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_audit_log_time ON audit_log(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action);

CREATE TABLE IF NOT EXISTS user_config (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS subagent_tasks (
    id                TEXT PRIMARY KEY,
    parent_session_id TEXT NOT NULL REFERENCES sessions(id),
    goal              TEXT NOT NULL,
    context           TEXT NOT NULL,
    tools             TEXT DEFAULT '[]',
    status            TEXT NOT NULL DEFAULT 'pending',
    result            TEXT,
    error             TEXT,
    created_at        TEXT NOT NULL DEFAULT (datetime('now')),
    finished_at       TEXT
);

-- Phase 6: Session bookmarks for task persistence across sessions
CREATE TABLE IF NOT EXISTS session_bookmarks (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  TEXT NOT NULL,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    mode        TEXT NOT NULL DEFAULT 'office',
    project_root TEXT,
    summary     TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(session_id, name)
);

-- Hermes batch 1: scheduled (cron) tasks
CREATE TABLE IF NOT EXISTS scheduled_tasks (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    prompt          TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending',
    schedule_config TEXT NOT NULL DEFAULT '{}',
    deliver_to      TEXT NOT NULL DEFAULT 'local',
    meta            TEXT NOT NULL DEFAULT '{}',
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    last_run        TEXT,
    next_run        TEXT,
    run_count       INTEGER NOT NULL DEFAULT 0,
    last_result     TEXT,
    error           TEXT
);

CREATE INDEX IF NOT EXISTS idx_scheduled_tasks_status ON scheduled_tasks(status, next_run);

CREATE TABLE IF NOT EXISTS coding_tasks (
    id             TEXT PRIMARY KEY,
    goal           TEXT NOT NULL,
    status         TEXT NOT NULL,
    state_json     TEXT NOT NULL DEFAULT '{}',
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_coding_tasks_status ON coding_tasks(status, updated_at);

-- Hermes batch 2: session history FTS5 search over messages.
-- Separate FTS5 table (rowid mirrors messages.id) populated manually by
-- insert_message_fts(). A standalone table avoids external-content trigger
-- complexity while still giving BM25 ranking + snippet() over message text.
CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts USING fts5(
    session_id,
    role,
    content,
    created_at,
    tokenize='unicode61'
);
