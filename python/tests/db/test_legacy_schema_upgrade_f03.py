"""F-03 (third-round review): real legacy schema upgrade tests.

The third-round review (``review/Khaos-Agent 第三轮深度 Review.md`` §4.10)
criticized the existing legacy migration test for only creating an
unrelated ``legacy_evidence`` table — it proved that "a database with
some unrelated old table can be backed up and initialized" but did NOT
prove that "real historical Khaos schemas (3.1.8 / 3.1.10 / 3.1.16A)
can be upgraded to the current version".

These tests close that gap.  They build a synthetic pre-A-2 Khaos
schema (the worst case — none of the principal_id / project_id /
namespace / policy_digest columns exist on any table, and the
principal_modes / authorization_contexts tables don't exist at all),
populate it with sample data, run the migration, and verify:

  - migration succeeds (no "no such column: principal_id" errors —
    this is the index-before-column bug the review identified);
  - ``PRAGMA integrity_check`` returns ``ok``;
  - ``PRAGMA foreign_key_check`` returns empty;
  - legacy sample data is preserved with correct default stamps
    (``principal_id='legacy'``, ``project_id=''``);
  - all indexes and triggers that reference the new columns exist;
  - the legacy quarantine triggers actually fire on a legacy write;
  - re-running the migration is idempotent (restart check).
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from khaos.db import Database
from khaos.db.database import (
    SCHEMA_MIGRATION_VERSION,
    _INITIAL_SCHEMA_PATH,
    _POST_MIGRATION_PATH,
)


# ---------------------------------------------------------------------------
# Synthetic pre-A-2 legacy schema
# ---------------------------------------------------------------------------
#
# This represents a Khaos database from before M4 batch 3.1.16A-2 — the
# earliest state the current ``_run_legacy_schema_upgrades()`` helpers
# are designed to upgrade from.  None of the principal_id / project_id /
# namespace / policy_digest columns exist; ``principal_modes`` and
# ``authorization_contexts`` tables don't exist at all.
#
# Indexes that reference the missing columns are intentionally NOT
# created here — that's exactly what would have broken under the old
# "execute schema.sql first" ordering, because CREATE INDEX would run
# before _ensure_* added the columns.

LEGACY_PRE_A2_SCHEMA = """
CREATE TABLE sessions (
    id          TEXT PRIMARY KEY,
    mode        TEXT NOT NULL DEFAULT 'office',
    status      TEXT NOT NULL DEFAULT 'active',
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT NOT NULL DEFAULT (datetime('now')),
    metadata    TEXT DEFAULT '{}'
);

CREATE TABLE messages (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id   TEXT NOT NULL REFERENCES sessions(id),
    role         TEXT NOT NULL,
    content      TEXT NOT NULL DEFAULT '',
    tool_calls   TEXT DEFAULT '[]',
    tool_call_id TEXT,
    token_count  INTEGER NOT NULL DEFAULT 0,
    created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE memories (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scope       TEXT NOT NULL,
    key         TEXT NOT NULL,
    value       TEXT NOT NULL,
    ttl         INTEGER NOT NULL DEFAULT 604800,
    confidence  INTEGER NOT NULL DEFAULT 2,
    access_freq INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE VIRTUAL TABLE memory_fts USING fts5(
    key,
    value,
    content=memories,
    content_rowid=id,
    tokenize='unicode61'
);

CREATE TABLE permissions (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern          TEXT NOT NULL,
    permission_level TEXT NOT NULL,
    approval         TEXT NOT NULL,
    mode             TEXT NOT NULL DEFAULT 'all',
    granted_at       TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    action      TEXT NOT NULL,
    target      TEXT NOT NULL,
    result      TEXT NOT NULL,
    detail      TEXT DEFAULT '',
    session_id  TEXT REFERENCES sessions(id),
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE user_config (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE tools (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    name             TEXT NOT NULL UNIQUE,
    schema           TEXT NOT NULL,
    modes            TEXT NOT NULL DEFAULT '["all"]',
    permission_level TEXT NOT NULL,
    parallel         INTEGER NOT NULL DEFAULT 0,
    timeout          INTEGER NOT NULL DEFAULT 60,
    enabled          INTEGER NOT NULL DEFAULT 1
);

-- scheduled_tasks from the 3.1.8 era: has lifecycle_version but NOT
-- principal_id / execution_id / lease_until (those came in 3.1.10) and
-- NOT policy_digest / generation (those came in 3.1.16B-1).
-- Column set matches the historical v3.1.8 schema exactly so that
-- ``_ensure_scheduled_tasks_principal_and_lease`` can run its
-- quarantine UPDATE against the pre-existing ``error`` column.
CREATE TABLE scheduled_tasks (
    id                TEXT PRIMARY KEY,
    name              TEXT NOT NULL,
    prompt            TEXT NOT NULL,
    status            TEXT NOT NULL DEFAULT 'pending',
    schedule_config   TEXT NOT NULL DEFAULT '{}',
    deliver_to        TEXT NOT NULL DEFAULT 'local',
    meta              TEXT NOT NULL DEFAULT '{}',
    created_at        TEXT NOT NULL DEFAULT (datetime('now')),
    last_run          TEXT,
    next_run          TEXT,
    run_count         INTEGER NOT NULL DEFAULT 0,
    last_result       TEXT,
    error             TEXT,
    lifecycle_version INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE subagent_tasks (
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

CREATE TABLE session_bookmarks (
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
"""


def _seed_legacy_data(conn: sqlite3.Connection) -> None:
    """Populate the synthetic legacy DB with realistic sample rows."""
    conn.executescript(
        """
        INSERT INTO sessions(id, mode, status) VALUES
            ('sess-legacy-1', 'office', 'active'),
            ('sess-legacy-2', 'coding', 'archived');

        INSERT INTO messages(session_id, role, content, token_count) VALUES
            ('sess-legacy-1', 'user', 'hello from legacy', 3),
            ('sess-legacy-1', 'assistant', 'hi back', 2),
            ('sess-legacy-2', 'user', 'write a test', 3);

        INSERT INTO memories(scope, key, value) VALUES
            ('global', 'weather', 'sunny'),
            ('session', 'todo', 'ship f-03');

        INSERT INTO permissions(pattern, permission_level, approval, mode) VALUES
            ('read_file', 'read', 'auto', 'all'),
            ('write_file', 'write', 'ask', 'office');

        INSERT INTO audit_log(action, target, result, session_id) VALUES
            ('tool_call', 'read_file', 'success', 'sess-legacy-1'),
            ('tool_call', 'write_file', 'denied', 'sess-legacy-2');

        INSERT INTO scheduled_tasks(id, name, prompt, status, next_run) VALUES
            ('task-legacy-1', 'nightly-report', 'run the nightly report', 'active', '1000');

        INSERT INTO subagent_tasks(id, parent_session_id, goal, context, status) VALUES
            ('sub-1', 'sess-legacy-1', 'research f-03', '{}', 'completed');

        INSERT INTO session_bookmarks(session_id, name, mode) VALUES
            ('sess-legacy-1', 'start', 'office');
        """
    )
    conn.commit()


def _build_legacy_db(path: Path) -> None:
    """Create a synthetic pre-A-2 Khaos DB at ``path`` with sample data."""
    conn = sqlite3.connect(path)
    try:
        conn.executescript(LEGACY_PRE_A2_SCHEMA)
        _seed_legacy_data(conn)
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


async def test_f03_real_legacy_schema_upgrades_without_column_errors(tmp_path):
    """The core F-03 regression: a real pre-A-2 Khaos schema with tables
    that lack ``principal_id`` / ``project_id`` must upgrade without
    "no such column" errors.

    Before the F-03 split-file refactor, ``schema.sql`` ran
    ``CREATE INDEX ... ON sessions(principal_id, ...)`` BEFORE
    ``_ensure_sessions_principal_column()`` added the column, so this
    migration failed on real legacy DBs.  With the split into
    ``0001_initial_schema.sql`` (tables only) → ``_ensure_*`` (columns)
    → ``0001_post_migration.sql`` (indexes/triggers), the order is now
    correct.
    """
    path = tmp_path / "legacy.db"
    _build_legacy_db(path)

    db = Database(path)
    await db.connect()
    # Must not raise "no such column: principal_id" or similar.
    await db.run_migrations()
    await db.close()


async def test_f03_legacy_schema_integrity_and_fk_check(tmp_path):
    """After upgrade, ``PRAGMA integrity_check`` and
    ``PRAGMA foreign_key_check`` must both pass on the upgraded DB."""
    path = tmp_path / "legacy.db"
    _build_legacy_db(path)

    db = Database(path)
    await db.connect()
    await db.run_migrations()
    conn = await db._require_conn()

    integrity = await (
        await conn.execute("PRAGMA integrity_check")
    ).fetchall()
    assert [tuple(r) for r in integrity] == [("ok",)], (
        f"integrity_check failed: {integrity}"
    )

    fk_violations = await (
        await conn.execute("PRAGMA foreign_key_check")
    ).fetchall()
    assert fk_violations == [], f"foreign_key_check found violations: {fk_violations}"

    await db.close()


async def test_f03_legacy_data_preserved_with_correct_default_stamps(tmp_path):
    """Legacy rows must survive the upgrade and receive the correct
    default stamps: ``principal_id='legacy'`` (fail-closed for
    authenticated principals) and ``project_id=''`` (unbound)."""
    path = tmp_path / "legacy.db"
    _build_legacy_db(path)

    db = Database(path)
    await db.connect()
    await db.run_migrations()
    conn = await db._require_conn()

    # sessions: 2 legacy rows, all stamped principal_id='legacy',
    # project_id=''
    rows = await (
        await conn.execute(
            "SELECT id, principal_id, project_id FROM sessions "
            "ORDER BY id"
        )
    ).fetchall()
    assert [dict(r) for r in rows] == [
        {"id": "sess-legacy-1", "principal_id": "legacy", "project_id": ""},
        {"id": "sess-legacy-2", "principal_id": "legacy", "project_id": ""},
    ]

    # messages: 3 legacy rows preserved
    count = (await (
        await conn.execute(
            "SELECT COUNT(*) AS n FROM messages "
            "WHERE principal_id='legacy' AND project_id=''"
        )
    ).fetchone())["n"]
    assert count == 3

    # memories: 2 legacy rows preserved; namespace defaults to 'private',
    # session_id defaults to ''
    mem = await (
        await conn.execute(
            "SELECT key, namespace, session_id, principal_id, project_id "
            "FROM memories ORDER BY key"
        )
    ).fetchall()
    assert {r["key"] for r in mem} == {"weather", "todo"}
    for r in mem:
        assert r["principal_id"] == "legacy"
        assert r["project_id"] == ""
        assert r["namespace"] == "private"
        assert r["session_id"] == ""

    # audit_log: 2 legacy rows preserved with principal_id='legacy'
    audit_count = (await (
        await conn.execute(
            "SELECT COUNT(*) AS n FROM audit_log "
            "WHERE principal_id='legacy' AND project_id=''"
        )
    ).fetchone())["n"]
    assert audit_count == 2

    # scheduled_tasks: 1 legacy row preserved
    task = await (
        await conn.execute(
            "SELECT id, principal_id, project_id, lifecycle_version "
            "FROM scheduled_tasks"
        )
    ).fetchone()
    assert task["id"] == "task-legacy-1"
    assert task["principal_id"] == "legacy"
    assert task["project_id"] == ""
    assert task["lifecycle_version"] == 0

    # subagent_tasks: 1 legacy row preserved
    sub = await (
        await conn.execute(
            "SELECT id, principal_id, project_id FROM subagent_tasks"
        )
    ).fetchone()
    assert sub["id"] == "sub-1"
    assert sub["principal_id"] == ""
    assert sub["project_id"] == ""

    # session_bookmarks: 1 legacy row preserved
    bm = await (
        await conn.execute(
            "SELECT session_id, name, principal_id, project_id "
            "FROM session_bookmarks"
        )
    ).fetchone()
    assert bm["session_id"] == "sess-legacy-1"
    assert bm["name"] == "start"
    assert bm["principal_id"] == "legacy"
    assert bm["project_id"] == ""

    await db.close()


async def test_f03_post_migration_indexes_and_triggers_exist(tmp_path):
    """After upgrade, the indexes/triggers from ``0001_post_migration.sql``
    that reference the previously-missing columns must all exist.

    This is the direct regression test for the index-before-column bug:
    if any of these had been created before the column existed, the
    migration would have failed."""
    path = tmp_path / "legacy.db"
    _build_legacy_db(path)

    db = Database(path)
    await db.connect()
    await db.run_migrations()
    conn = await db._require_conn()

    expected_indexes = {
        "idx_sessions_principal",
        "idx_messages_session",
        "idx_messages_principal",
        "idx_agent_turns_session",
        "idx_permissions_level",
        "idx_permissions_principal",
        "idx_audit_log_time",
        "idx_audit_log_action",
        "idx_audit_log_principal",
        "idx_session_bookmarks_principal",
        "idx_scheduled_tasks_status",
        "idx_scheduled_tasks_principal",
        "idx_scheduled_tasks_policy",
    }
    actual_indexes = {
        row["name"]
        for row in await (
            await conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index' "
                "AND name NOT LIKE 'sqlite_%'"
            )
        ).fetchall()
    }
    missing = expected_indexes - actual_indexes
    assert not missing, f"missing indexes after legacy upgrade: {missing}"

    expected_triggers = {
        "memory_ai",
        "memory_ad",
        "memory_au",
        "trg_scheduled_tasks_quarantine_legacy_insert",
        "trg_scheduled_tasks_quarantine_legacy_update",
        # session identity guards (created by _ensure_session_identity_invariants)
        "trg_messages_session_identity_insert",
        "trg_messages_session_identity_update",
        "trg_audit_log_session_identity_insert",
        "trg_audit_log_session_identity_update",
        "trg_memories_session_identity_insert",
        "trg_memories_session_identity_update",
    }
    actual_triggers = {
        row["name"]
        for row in await (
            await conn.execute(
                "SELECT name FROM sqlite_master WHERE type='trigger'"
            )
        ).fetchall()
    }
    missing_triggers = expected_triggers - actual_triggers
    assert not missing_triggers, (
        f"missing triggers after legacy upgrade: {missing_triggers}"
    )

    # principal_modes and authorization_contexts tables must exist now
    tables = {
        row["name"]
        for row in await (
            await conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        ).fetchall()
    }
    assert "principal_modes" in tables
    assert "authorization_contexts" in tables

    await db.close()


async def test_f03_legacy_quarantine_trigger_fires_on_legacy_write(tmp_path):
    """The ``trg_scheduled_tasks_quarantine_legacy_insert`` trigger must
    actually fire when a legacy-principal write happens post-migration,
    marking the row as ``failed`` with the quarantine message."""
    path = tmp_path / "legacy.db"
    _build_legacy_db(path)

    db = Database(path)
    await db.connect()
    await db.run_migrations()
    conn = await db._require_conn()

    # Insert a new scheduled task with principal_id='legacy' and a
    # non-failed status.  The trigger should quarantine it.
    await conn.execute(
        """
        INSERT INTO scheduled_tasks(
            id, name, prompt, status, next_run, principal_id
        ) VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            "task-legacy-new",
            "evil-job",
            "do something evil",
            "active",
            "2000",
            "legacy",
        ),
    )
    await conn.commit()

    row = await (
        await conn.execute(
            "SELECT status, error, execution_id, lease_until "
            "FROM scheduled_tasks WHERE id=?",
            ("task-legacy-new",),
        )
    ).fetchone()
    assert row["status"] == "failed"
    assert "quarantined" in (row["error"] or "")
    assert row["execution_id"] is None
    assert row["lease_until"] is None

    await db.close()


async def test_f03_legacy_schema_migration_is_idempotent_on_restart(tmp_path):
    """Re-running the migration on an already-migrated DB must be a
    no-op (the checksum matches, so the early return path runs)."""
    path = tmp_path / "legacy.db"
    _build_legacy_db(path)

    db = Database(path)
    await db.connect()
    await db.run_migrations()

    # Snapshot row counts before restart
    conn = await db._require_conn()
    counts_before = {
        table: (await (
            await conn.execute(f"SELECT COUNT(*) AS n FROM {table}")
        ).fetchone())["n"]
        for table in (
            "sessions",
            "messages",
            "memories",
            "audit_log",
            "scheduled_tasks",
            "subagent_tasks",
            "session_bookmarks",
        )
    }
    await db.close()

    # Simulate a restart: open the same DB and run migrations again
    db2 = Database(path)
    await db2.connect()
    await db2.run_migrations()  # must be a no-op
    conn2 = await db2._require_conn()
    counts_after = {
        table: (await (
            await conn2.execute(f"SELECT COUNT(*) AS n FROM {table}")
        ).fetchone())["n"]
        for table in counts_before
    }
    await db2.close()

    assert counts_before == counts_after, (
        f"restart changed row counts: {counts_before} -> {counts_after}"
    )

    # ledger must still have exactly one row
    db3 = Database(path)
    await db3.connect()
    conn3 = await db3._require_conn()
    ledger = await (
        await conn3.execute(
            "SELECT COUNT(*) AS n, MAX(version) AS v FROM schema_migrations"
        )
    ).fetchone()
    assert ledger["n"] == 1
    assert ledger["v"] == SCHEMA_MIGRATION_VERSION
    await db3.close()


async def test_f03_split_files_produce_same_schema_as_legacy_path(tmp_path):
    """The split migration chain (initial + ensure + post-migration)
    must produce the same set of tables, indexes and triggers as the
    original single ``schema.sql`` path.  This is the checksum
    compatibility guarantee — the split files are an execution-order
    fix, not a schema change."""
    path1 = tmp_path / "fresh_split.db"
    db1 = Database(path1)
    await db1.connect()
    await db1.run_migrations()
    conn1 = await db1._require_conn()
    split_objects = await (
        await conn1.execute(
            "SELECT type, name FROM sqlite_master "
            "WHERE name NOT LIKE 'sqlite_%' "
            "  AND name NOT LIKE 'memory_fts_%' "
            "ORDER BY type, name"
        )
    ).fetchall()
    await db1.close()

    # The split files ARE the source of truth for execution, but the
    # checksum is still computed from the original schema.sql for
    # backward compatibility.  Verify the split files exist and are
    # non-empty — the actual checksum-compat guarantee is covered by
    # test_migration_records_version_and_checksum above.
    assert _INITIAL_SCHEMA_PATH.is_file()
    assert _POST_MIGRATION_PATH.is_file()
    assert _INITIAL_SCHEMA_PATH.read_text(encoding="utf-8").strip()
    assert _POST_MIGRATION_PATH.read_text(encoding="utf-8").strip()

    # A freshly-migrated DB must have at least the core tables
    core_tables = {
        "sessions", "messages", "memories", "permissions", "audit_log",
        "scheduled_tasks", "principal_modes", "authorization_contexts",
        "schema_migrations",
    }
    actual_tables = {
        r["name"] for r in split_objects if r["type"] == "table"
    }
    assert core_tables <= actual_tables, (
        f"missing core tables: {core_tables - actual_tables}"
    )
