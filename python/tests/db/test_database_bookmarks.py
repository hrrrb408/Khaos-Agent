"""Tests for Phase 6 session bookmarks + summary / changed-files persistence."""

from __future__ import annotations

import sqlite3

from khaos.db import Database


async def _fresh_db(tmp_path) -> Database:
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    return db


# ---------------------------------------------------------------------------
# Bookmarks CRUD
# ---------------------------------------------------------------------------


async def test_save_and_load_bookmark(tmp_path):
    db = await _fresh_db(tmp_path)
    await db.create_session("s1")

    await db.save_bookmark(
        "s1",
        "fix-login",
        description="Fix the login bug",
        mode="coding",
        project_root="/tmp/proj",
        summary="Renamed the auth helper.",
    )

    loaded = await db.load_bookmark("s1", "fix-login")
    assert loaded is not None
    assert loaded["session_id"] == "s1"
    assert loaded["name"] == "fix-login"
    assert loaded["description"] == "Fix the login bug"
    assert loaded["mode"] == "coding"
    assert loaded["project_root"] == "/tmp/proj"
    assert loaded["summary"] == "Renamed the auth helper."
    await db.close()


async def test_save_bookmark_upserts_existing(tmp_path):
    db = await _fresh_db(tmp_path)
    await db.create_session("s1")

    await db.save_bookmark("s1", "bm", summary="v1")
    await db.save_bookmark("s1", "bm", summary="v2", mode="coding")

    loaded = await db.load_bookmark("s1", "bm")
    assert loaded is not None
    assert loaded["summary"] == "v2"
    assert loaded["mode"] == "coding"

    # No duplicate rows.
    bookmarks = await db.list_bookmarks("s1")
    assert len([b for b in bookmarks if b["name"] == "bm"]) == 1
    await db.close()


async def test_load_bookmark_returns_none_when_missing(tmp_path):
    db = await _fresh_db(tmp_path)
    await db.create_session("s1")
    assert await db.load_bookmark("s1", "nope") is None
    await db.close()


async def test_list_bookmarks_filters_by_session(tmp_path):
    db = await _fresh_db(tmp_path)
    await db.create_session("s1")
    await db.create_session("s2")

    await db.save_bookmark("s1", "a")
    await db.save_bookmark("s1", "b")
    await db.save_bookmark("s2", "c")

    s1 = await db.list_bookmarks("s1")
    assert {b["name"] for b in s1} == {"a", "b"}

    all_bm = await db.list_bookmarks()
    assert {b["name"] for b in all_bm} == {"a", "b", "c"}
    await db.close()


async def test_delete_bookmark_removes_only_target(tmp_path):
    db = await _fresh_db(tmp_path)
    await db.create_session("s1")
    await db.save_bookmark("s1", "a")
    await db.save_bookmark("s1", "b")

    await db.delete_bookmark("s1", "a")

    assert await db.load_bookmark("s1", "a") is None
    assert await db.load_bookmark("s1", "b") is not None
    await db.close()


async def test_delete_missing_bookmark_is_silent(tmp_path):
    db = await _fresh_db(tmp_path)
    await db.create_session("s1")
    # Should not raise.
    await db.delete_bookmark("s1", "never-existed")
    await db.close()


# ---------------------------------------------------------------------------
# Session summary
# ---------------------------------------------------------------------------


async def test_save_and_get_session_summary(tmp_path):
    db = await _fresh_db(tmp_path)
    await db.create_session("s1")

    assert await db.get_session_summary("s1") is None

    await db.save_session_summary("s1", "Implemented bookmark persistence.")
    assert await db.get_session_summary("s1") == "Implemented bookmark persistence."
    await db.close()


async def test_save_session_summary_is_idempotent_migration(tmp_path):
    """Calling save_session_summary twice must not error on duplicate ALTER."""
    db = await _fresh_db(tmp_path)
    await db.create_session("s1")

    await db.save_session_summary("s1", "first")
    await db.save_session_summary("s1", "second")  # column already exists

    assert await db.get_session_summary("s1") == "second"
    await db.close()


async def test_get_session_summary_missing_session(tmp_path):
    db = await _fresh_db(tmp_path)
    assert await db.get_session_summary("nope") is None
    await db.close()


# ---------------------------------------------------------------------------
# Changed files
# ---------------------------------------------------------------------------


async def test_save_and_get_session_changes(tmp_path):
    db = await _fresh_db(tmp_path)
    await db.create_session("s1")

    assert await db.get_session_changes("s1") == []

    await db.save_session_changes("s1", ["a.py", "b.py"])
    assert await db.get_session_changes("s1") == ["a.py", "b.py"]
    await db.close()


async def test_changes_and_summary_coexist_in_metadata(tmp_path):
    """summary + changed_files share the metadata JSON without clobbering."""
    db = await _fresh_db(tmp_path)
    await db.create_session("s1")

    await db.save_session_summary("s1", "the summary")
    await db.save_session_changes("s1", ["x.py", "y.py"])

    assert await db.get_session_summary("s1") == "the summary"
    assert await db.get_session_changes("s1") == ["x.py", "y.py"]
    await db.close()


async def test_get_session_changes_returns_empty_list_on_garbage_metadata(tmp_path):
    """Corrupt metadata must degrade to an empty list, not raise."""
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    await db.create_session("s1")
    conn = await db._require_conn()
    await conn.execute(
        "UPDATE sessions SET metadata = ? WHERE id = ?",
        ("{not valid json", "s1"),
    )
    await conn.commit()

    assert await db.get_session_changes("s1") == []
    await db.close()


# ---------------------------------------------------------------------------
# ALTER TABLE idempotency on a pre-existing (un-migrated) sessions table
# ---------------------------------------------------------------------------


async def test_summary_alter_table_idempotent_on_old_schema(tmp_path):
    """Simulate a sessions table created without the summary column and ensure
    save_session_summary adds it exactly once across repeated calls."""
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    # Build sessions by hand WITHOUT the summary column.
    conn = await db._require_conn()
    await conn.execute(
        """
        CREATE TABLE sessions (
            id          TEXT PRIMARY KEY,
            mode        TEXT NOT NULL DEFAULT 'office',
            status      TEXT NOT NULL DEFAULT 'active',
            created_at  TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at  TEXT NOT NULL DEFAULT (datetime('now')),
            metadata    TEXT DEFAULT '{}'
        )
        """
    )
    await conn.execute("INSERT INTO sessions (id) VALUES (?)", ("s1",))
    await conn.commit()

    await db.save_session_summary("s1", "added on old schema")
    # Idempotent: column now exists, second call must not raise.
    await db.save_session_summary("s1", "updated")

    # Column was added exactly once.
    cursor = await conn.execute("PRAGMA table_info(sessions)")
    summary_cols = [row for row in await cursor.fetchall() if row["name"] == "summary"]
    assert len(summary_cols) == 1

    assert await db.get_session_summary("s1") == "updated"
    await db.close()


async def test_session_bookmarks_table_exists_after_migration(tmp_path):
    db = await _fresh_db(tmp_path)
    conn = await db._require_conn()
    cursor = await conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='session_bookmarks'"
    )
    row = await cursor.fetchone()
    assert row is not None
    await db.close()
