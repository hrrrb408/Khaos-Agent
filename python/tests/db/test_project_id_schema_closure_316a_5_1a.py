"""M4 Batch 3.1.16A-5-1a — Project Identity Schema Closure.

Acceptance tests for the ``project_id`` column added to 8 tables:

  - sessions
  - messages
  - agent_turns
  - session_bookmarks
  - memories
  - audit_log
  - coding_tasks
  - scheduler_operation_journal

This batch (A-5-1a) is **schema-only** — it adds the column + index
but does NOT modify write paths (that's A-5-1b) or add drift detection
(that's A-5-1b).  The column defaults to ``''`` ("unbound") for legacy
rows so existing data remains visible; A-5-1b will stamp new writes
with the live ``project_id``.

Verifies:
  1.  Fresh DB: all 8 tables have ``project_id`` column after
      ``run_migrations``.
  2.  Fresh DB: all 8 ``idx_*_project`` indexes exist.
  3.  Fresh DB: ``project_id`` column has ``NOT NULL DEFAULT ''``.
  4.  Legacy DB (no ``project_id`` column): ``run_migrations`` adds
      the column; existing rows get ``project_id=''``.
  5.  Idempotent: re-running ``run_migrations`` is a no-op.
  6.  Pre-existing tables with ``project_id`` (``scheduled_tasks``,
      ``permissions``) are NOT touched by A-5-1a helpers.
  7.  ``memories`` UNIQUE constraint is NOT changed (``project_id``
      is a plain column, not part of the UNIQUE key).
  8.  ``scheduler_operation_journal`` (B-5 table) gets the column.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from khaos.db import Database


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


A5_TABLES = [
    "sessions",
    "messages",
    "agent_turns",
    "session_bookmarks",
    "memories",
    "audit_log",
    "coding_tasks",
    "scheduler_operation_journal",
]

A5_INDEXES = [
    ("sessions", "idx_sessions_project"),
    ("messages", "idx_messages_project"),
    ("agent_turns", "idx_agent_turns_project"),
    ("session_bookmarks", "idx_session_bookmarks_project"),
    ("memories", "idx_memories_project"),
    ("audit_log", "idx_audit_log_project"),
    ("coding_tasks", "idx_coding_tasks_project"),
    ("scheduler_operation_journal", "idx_scheduler_journal_project"),
]


async def _make_db(path: Path) -> Database:
    db = Database(path)
    await db.connect()
    await db.run_migrations()
    return db


async def _table_columns(conn, table: str) -> set[str]:
    cursor = await conn.execute(f"PRAGMA table_info({table})")
    return {row[1] for row in await cursor.fetchall()}


async def _index_exists(conn, index_name: str) -> bool:
    cursor = await conn.execute(
        "SELECT name FROM sqlite_master WHERE type='index' AND name=?",
        (index_name,),
    )
    row = await cursor.fetchone()
    return row is not None


async def _column_default(conn, table: str, column: str) -> str | None:
    """Return the SQL default value of a column, or None."""
    cursor = await conn.execute(f"PRAGMA table_info({table})")
    for row in await cursor.fetchall():
        if row[1] == column:
            return row[4]  # dflt_value
    return None


async def _column_notnull(conn, table: str, column: str) -> bool:
    """Return True if the column has NOT NULL constraint."""
    cursor = await conn.execute(f"PRAGMA table_info({table})")
    for row in await cursor.fetchall():
        if row[1] == column:
            # notnull is 1 if NOT NULL, 0 otherwise
            return bool(row[3])
    return False


# ---------------------------------------------------------------------------
# 1-3. Fresh DB: columns, indexes, defaults
# ---------------------------------------------------------------------------


async def test_acceptance_1_fresh_db_all_tables_have_project_id(tmp_path):
    """A5-1: all 8 tables have ``project_id`` column after fresh
    ``run_migrations``."""
    db = await _make_db(tmp_path / "khaos.db")
    try:
        conn = await db._require_conn()
        for table in A5_TABLES:
            cols = await _table_columns(conn, table)
            assert "project_id" in cols, (
                f"table {table} is missing project_id column "
                f"(has: {sorted(cols)})"
            )
    finally:
        await db.close()


async def test_acceptance_2_fresh_db_all_indexes_exist(tmp_path):
    """A5-2: all 8 ``idx_*_project`` indexes exist after fresh
    ``run_migrations``."""
    db = await _make_db(tmp_path / "khaos.db")
    try:
        conn = await db._require_conn()
        for table, index_name in A5_INDEXES:
            exists = await _index_exists(conn, index_name)
            assert exists, (
                f"index {index_name} on table {table} does not exist"
            )
    finally:
        await db.close()


async def test_acceptance_3_project_id_column_default_and_notnull(tmp_path):
    """A5-3: ``project_id`` column has ``NOT NULL DEFAULT ''`` on all
    8 tables."""
    db = await _make_db(tmp_path / "khaos.db")
    try:
        conn = await db._require_conn()
        for table in A5_TABLES:
            is_notnull = await _column_notnull(conn, table, "project_id")
            assert is_notnull, (
                f"table {table}.project_id is NOT NOT NULL"
            )
            default = await _column_default(conn, table, "project_id")
            assert default == "''", (
                f"table {table}.project_id default is {default!r}, "
                f"expected \"''\""
            )
    finally:
        await db.close()


# ---------------------------------------------------------------------------
# 4. Legacy DB migration
# ---------------------------------------------------------------------------


async def test_acceptance_4_legacy_db_migration_adds_column(tmp_path):
    """A5-4: a legacy DB (created without ``project_id`` columns) gets
    the column added by ``run_migrations``, and existing rows get
    ``project_id=''``.
    """
    db_path = tmp_path / "legacy.db"
    # Create a legacy DB by manually running an OLD schema (without
    # project_id columns).  We use the sessions table as representative.
    raw = sqlite3.connect(str(db_path))
    raw.executescript("""
        CREATE TABLE sessions (
            id          TEXT PRIMARY KEY,
            mode        TEXT NOT NULL DEFAULT 'office',
            status      TEXT NOT NULL DEFAULT 'active',
            created_at  TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at  TEXT NOT NULL DEFAULT (datetime('now')),
            metadata    TEXT DEFAULT '{}',
            principal_id TEXT NOT NULL DEFAULT 'legacy'
        );
        INSERT INTO sessions (id, mode, principal_id)
        VALUES ('legacy-session-1', 'office', 'alice');
    """)
    raw.commit()
    raw.close()

    # Now run migrations — should add project_id column.
    db = Database(db_path)
    await db.connect()
    await db.run_migrations()
    try:
        conn = await db._require_conn()
        cols = await _table_columns(conn, "sessions")
        assert "project_id" in cols, "project_id column was not added to legacy sessions table"

        # Existing rows should have project_id='' (the default).
        cursor = await conn.execute(
            "SELECT project_id FROM sessions WHERE id = ?",
            ("legacy-session-1",),
        )
        row = await cursor.fetchone()
        assert row is not None, "legacy row disappeared"
        assert row[0] == "", (
            f"legacy row project_id should be '' (unbound), got {row[0]!r}"
        )
    finally:
        await db.close()


# ---------------------------------------------------------------------------
# 5. Idempotent migration
# ---------------------------------------------------------------------------


async def test_acceptance_5_migration_is_idempotent(tmp_path):
    """A5-5: re-running ``run_migrations`` on an already-migrated DB
    is a no-op (no error, no duplicate columns / indexes)."""
    db_path = tmp_path / "khaos.db"
    db = await _make_db(db_path)
    try:
        # First migration already done in _make_db.  Run again.
        await db.run_migrations()
        # Verify no duplicate columns (PRAGMA table_info should show
        # exactly one project_id per table).
        conn = await db._require_conn()
        for table in A5_TABLES:
            cols = await _table_columns(conn, table)
            # Sets dedupe — if migration added the column twice, the set
            # would still have one entry but the count query below
            # catches it.
            cursor = await conn.execute(
                f"PRAGMA table_info({table})"
            )
            rows = await cursor.fetchall()
            project_id_count = sum(1 for r in rows if r[1] == "project_id")
            assert project_id_count == 1, (
                f"table {table} has {project_id_count} project_id columns "
                f"(expected 1) — migration is not idempotent"
            )
    finally:
        await db.close()


# ---------------------------------------------------------------------------
# 6. Pre-existing project_id tables untouched
# ---------------------------------------------------------------------------


async def test_acceptance_6_preexisting_project_id_tables_untouched(tmp_path):
    """A5-6: ``scheduled_tasks`` and ``permissions`` already had
    ``project_id`` (B-1 and A-2).  A-5-1a helpers must NOT alter them.

    We verify by checking that the column default matches the original
    schema (``''``) and the column is NOT NULL.
    """
    db = await _make_db(tmp_path / "khaos.db")
    try:
        conn = await db._require_conn()
        for table in ("scheduled_tasks", "permissions"):
            is_notnull = await _column_notnull(conn, table, "project_id")
            assert is_notnull, (
                f"table {table}.project_id should be NOT NULL (pre-existing)"
            )
            default = await _column_default(conn, table, "project_id")
            assert default == "''", (
                f"table {table}.project_id default changed to {default!r}"
            )
    finally:
        await db.close()


# ---------------------------------------------------------------------------
# 7. memories UNIQUE constraint includes project_id (F-02)
# ---------------------------------------------------------------------------


async def test_acceptance_7_memories_unique_constraint_includes_project(tmp_path):
    """A5-7 (F-02): ``memories`` UNIQUE constraint now INCLUDES ``project_id``.

    Two rows with the same (namespace, principal, session, scope, key) but
    DIFFERENT ``project_id`` must both succeed — each project gets its own
    row.  Two rows with the SAME ``project_id`` (and same identity tuple)
    must still fail with UNIQUE constraint violation.

    Pre-F-02 this test asserted the opposite (project_id was NOT in the
    UNIQUE key); F-02 (third-round review) reversed that so a shared
    state DB cannot let project B silently overwrite project A's memory.
    """
    db = await _make_db(tmp_path / "khaos.db")
    try:
        conn = await db._require_conn()
        # First insert for proj-a.
        await conn.execute(
            "INSERT INTO memories (scope, key, value, principal_id, "
            "namespace, session_id, project_id) "
            "VALUES ('global', 'k1', 'v1', 'alice', 'private', '', 'proj-a')"
        )
        await conn.commit()
        # Second insert with same (namespace, principal, session, scope,
        # key) but DIFFERENT project_id MUST succeed (two distinct rows).
        await conn.execute(
            "INSERT INTO memories (scope, key, value, principal_id, "
            "namespace, session_id, project_id) "
            "VALUES ('global', 'k1', 'v2', 'alice', 'private', '', 'proj-b')"
        )
        await conn.commit()
        # Third insert with the SAME project_id (and same identity tuple)
        # MUST fail (UNIQUE violation).
        with pytest.raises(sqlite3.IntegrityError, match="UNIQUE"):
            await conn.execute(
                "INSERT INTO memories (scope, key, value, principal_id, "
                "namespace, session_id, project_id) "
                "VALUES ('global', 'k1', 'v3', 'alice', 'private', '', 'proj-a')"
            )
            await conn.commit()
        # Verify both project-scoped rows are present.
        cursor = await conn.execute(
            "SELECT project_id, value FROM memories "
            "WHERE key = 'k1' ORDER BY project_id"
        )
        rows = await cursor.fetchall()
        assert len(rows) == 2
        assert rows[0][0] == "proj-a"
        assert rows[0][1] == "v1"
        assert rows[1][0] == "proj-b"
        assert rows[1][1] == "v2"
    finally:
        await db.close()


# ---------------------------------------------------------------------------
# 8. scheduler_operation_journal gets project_id
# ---------------------------------------------------------------------------


async def test_acceptance_8_scheduler_journal_has_project_id(tmp_path):
    """A5-8: ``scheduler_operation_journal`` (B-5 table) gets the
    ``project_id`` column.  This closes the B-5 oversight where the
    journal had ``principal_id`` and ``policy_digest`` but not
    ``project_id``.
    """
    db = await _make_db(tmp_path / "khaos.db")
    try:
        conn = await db._require_conn()
        cols = await _table_columns(conn, "scheduler_operation_journal")
        assert "project_id" in cols, (
            "scheduler_operation_journal is missing project_id column"
        )
        # Insert a row with project_id and verify it round-trips.
        await conn.execute(
            "INSERT INTO scheduler_operation_journal "
            "(operation_id, task_id, operation_type, desired_status, "
            " expected_version, target_version, principal_id, "
            " policy_digest, project_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("op-1", "task-1", "pause", "paused", 0, 1,
             "alice", "sha256:p", "proj-test"),
        )
        await conn.commit()
        cursor = await conn.execute(
            "SELECT project_id FROM scheduler_operation_journal "
            "WHERE operation_id = ?",
            ("op-1",),
        )
        row = await cursor.fetchone()
        assert row is not None
        assert row[0] == "proj-test", (
            f"project_id did not round-trip, got {row[0]!r}"
        )
    finally:
        await db.close()
