"""M4 Batch 3.1.16A-5-2 — Trusted State Migration CLI.

Acceptance tests for the ``khaos migrate project-identity`` CLI that
backfills ``project_id`` on legacy rows left by A-5-1a/A-5-1b.

Scope
-----
The 8 A-5-1a tables (sessions, messages, agent_turns, memories,
audit_log, session_bookmarks, coding_tasks, scheduler_operation_journal)
received ``project_id TEXT NOT NULL DEFAULT ''`` in A-5-1a.  A-5-1b
stamps the live value on new writes, but legacy rows keep ``''``.
A-5-2 reclaims them.

Verifies
--------
  1.  ``count_legacy_rows`` returns 0 on a fresh DB (no legacy rows).
  2.  ``count_legacy_rows`` returns N after N legacy inserts.
  3.  ``backfill_table`` updates N rows in a table.
  4.  ``backfill_table`` is idempotent (second run returns 0).
  5.  ``backfill_table`` raises on unknown table name (SQL injection
      guard).
  6.  ``backfill_table`` raises on empty project_id (fail-closed).
  7.  ``run_backfill`` returns a ``BackfillResult`` with per-table
      reports for all 8 A-5-1a tables.
  8.  ``run_backfill`` with ``dry_run=True`` makes no writes.
  9.  ``run_backfill`` stamps the same ``project_id`` on every table.
  10. ``run_backfill`` with ``tables=[...]`` only backfills listed
      tables.
  11. ``run_backfill`` resolves symlinks in ``project_root`` before
      hashing (so symlink-equivalent paths produce the same id).
  12. ``A_5_1A_TABLES`` order has ``audit_log`` LAST (so the
      migration's own audit entry is not re-stamped by the backfill).
  13. CLI handler ``cmd_migrate`` end-to-end with ``--dry-run`` makes
      no writes and prints the preview.
  14. CLI handler ``cmd_migrate`` end-to-end with ``--yes`` writes
      and prints the per-table updated counts.
  15. CLI handler ``cmd_migrate`` with no subcommand prints usage
      and returns exit code 2.
"""
from __future__ import annotations

import asyncio
import io
import os
import sys
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest

from khaos.cli.main import cmd_migrate, build_command_parser
from khaos.db import Database
from khaos.db.migrations_cli import (
    A_5_1A_TABLES,
    BackfillReport,
    BackfillResult,
    MigrationError,
    backfill_table,
    count_legacy_rows,
    run_backfill,
)
from khaos.db.state_root import project_id as compute_project_id


# ─────────────────────────────── helpers ────────────────────────────────


PROJECT_ROOT_A = Path("/tmp/project-a")  # not real; resolve() handles it


async def _make_db(path: Path) -> Database:
    """Open a fresh Database with migrations applied."""
    db = Database(path)
    await db.connect()
    await db.run_migrations()
    return db


async def _insert_legacy_row(
    db: Database, table: str, *,
    session_id: str = "s1",
    task_id: str = "t1",
    operation_id: str = "op1",
) -> None:
    """Insert a row with project_id='' into ``table``.

    Each table has a different schema, so we use a per-table INSERT
    with the minimum required columns.  All omit ``project_id`` so
    the column default (``''``) applies.
    """
    conn = await db._require_conn()
    if table == "sessions":
        await conn.execute(
            "INSERT INTO sessions (id, mode, principal_id) VALUES (?, 'office', 'u1')",
            (session_id,),
        )
    elif table == "messages":
        await conn.execute(
            "INSERT INTO messages (session_id, role, content, principal_id) "
            "VALUES (?, 'user', 'hello', 'u1')",
            (session_id,),
        )
    elif table == "agent_turns":
        await conn.execute(
            "INSERT INTO agent_turns (turn_id, attempt_id, session_id, status, "
            "started_at, principal_id) "
            "VALUES (?, 'a1', ?, 'running', 0.0, 'u1')",
            (f"turn-{uuid.uuid4().hex[:8]}", session_id),
        )
    elif table == "memories":
        await conn.execute(
            "INSERT INTO memories (scope, key, value, principal_id, namespace) "
            "VALUES ('global', ?, 'v1', 'u1', 'private')",
            (f"k-{uuid.uuid4().hex[:8]}",),
        )
    elif table == "audit_log":
        await conn.execute(
            "INSERT INTO audit_log (action, target, result, principal_id) "
            "VALUES ('write_file', '/tmp/x', 'success', 'u1')",
        )
    elif table == "session_bookmarks":
        await conn.execute(
            "INSERT INTO session_bookmarks (session_id, name, principal_id) "
            "VALUES (?, ?, 'u1')",
            (session_id, f"bm-{uuid.uuid4().hex[:8]}"),
        )
    elif table == "coding_tasks":
        await conn.execute(
            "INSERT INTO coding_tasks (id, goal, status, principal_id) "
            "VALUES (?, 'goal', 'in_progress', 'u1')",
            (task_id,),
        )
    elif table == "scheduler_operation_journal":
        await conn.execute(
            "INSERT INTO scheduler_operation_journal "
            "(operation_id, task_id, operation_type, desired_status, "
            " expected_version, target_version, principal_id) "
            "VALUES (?, ?, 'pause', 'paused', 0, 1, 'u1')",
            (operation_id, task_id),
        )
    else:
        raise ValueError(f"unknown table {table!r}")
    await conn.commit()


async def _count_project_id_empty(db: Database, table: str) -> int:
    """Count rows in ``table`` with project_id=''."""
    conn = await db._require_conn()
    cursor = await conn.execute(
        f"SELECT COUNT(*) FROM {table} WHERE project_id = ''",
    )
    row = await cursor.fetchone()
    await cursor.close()
    return int(row[0]) if row else 0


# ─────────────────────────── count_legacy_rows ──────────────────────────


async def test_acceptance_1_count_legacy_rows_zero_on_fresh_db(tmp_path):
    """A5-2 #1: ``count_legacy_rows`` returns 0 on a fresh DB."""
    db = await _make_db(tmp_path / "khaos.db")
    try:
        for table in A_5_1A_TABLES:
            assert await count_legacy_rows(db, table) == 0, (
                f"{table}: expected 0 legacy rows on fresh DB"
            )
    finally:
        await db.close()


async def test_acceptance_2_count_legacy_rows_after_inserts(tmp_path):
    """A5-2 #2: ``count_legacy_rows`` returns N after N legacy inserts."""
    db = await _make_db(tmp_path / "khaos.db")
    try:
        # Insert 3 legacy rows in sessions.
        await _insert_legacy_row(db, "sessions", session_id="s1")
        await _insert_legacy_row(db, "sessions", session_id="s2")
        await _insert_legacy_row(db, "sessions", session_id="s3")
        assert await count_legacy_rows(db, "sessions") == 3
    finally:
        await db.close()


# ───────────────────────────── backfill_table ───────────────────────────


async def test_acceptance_3_backfill_table_updates_rows(tmp_path):
    """A5-2 #3: ``backfill_table`` updates N rows in a table."""
    db = await _make_db(tmp_path / "khaos.db")
    try:
        await _insert_legacy_row(db, "sessions", session_id="s1")
        await _insert_legacy_row(db, "sessions", session_id="s2")
        pid = compute_project_id(tmp_path)
        updated = await backfill_table(db, "sessions", pid)
        assert updated == 2
        assert await _count_project_id_empty(db, "sessions") == 0
    finally:
        await db.close()


async def test_acceptance_4_backfill_table_is_idempotent(tmp_path):
    """A5-2 #4: ``backfill_table`` is idempotent (second run returns 0)."""
    db = await _make_db(tmp_path / "khaos.db")
    try:
        await _insert_legacy_row(db, "sessions", session_id="s1")
        pid = compute_project_id(tmp_path)
        first = await backfill_table(db, "sessions", pid)
        second = await backfill_table(db, "sessions", pid)
        assert first == 1
        assert second == 0, "second backfill must be a no-op"
    finally:
        await db.close()


async def test_acceptance_5_backfill_table_rejects_unknown_table(tmp_path):
    """A5-2 #5: ``backfill_table`` raises on unknown table name.

    Guards against SQL injection via f-string table name interpolation.
    """
    db = await _make_db(tmp_path / "khaos.db")
    try:
        with pytest.raises(MigrationError, match="unknown table"):
            await backfill_table(db, "permissions; DROP TABLE users--", "pid")
    finally:
        await db.close()


async def test_acceptance_6_backfill_table_rejects_empty_project_id(tmp_path):
    """A5-2 #6: ``backfill_table`` raises on empty project_id (fail-closed)."""
    db = await _make_db(tmp_path / "khaos.db")
    try:
        with pytest.raises(MigrationError, match="project_id must be non-empty"):
            await backfill_table(db, "sessions", "")
    finally:
        await db.close()


# ────────────────────────────── run_backfill ────────────────────────────


async def test_acceptance_7_run_backfill_returns_per_table_reports(tmp_path):
    """A5-2 #7: ``run_backfill`` returns reports for all 8 A-5-1a tables."""
    db = await _make_db(tmp_path / "khaos.db")
    try:
        result = await run_backfill(db, tmp_path)
        assert isinstance(result, BackfillResult)
        reported_tables = {r.table for r in result.reports}
        assert reported_tables == set(A_5_1A_TABLES), (
            f"missing tables: {set(A_5_1A_TABLES) - reported_tables}"
        )
    finally:
        await db.close()


async def test_acceptance_8_run_backfill_dry_run_makes_no_writes(tmp_path):
    """A5-2 #8: ``run_backfill`` with ``dry_run=True`` makes no writes."""
    db = await _make_db(tmp_path / "khaos.db")
    try:
        await _insert_legacy_row(db, "sessions", session_id="s1")
        await _insert_legacy_row(db, "audit_log")
        result = await run_backfill(db, tmp_path, dry_run=True)
        # Dry-run reported the legacy rows.
        sessions_report = next(r for r in result.reports if r.table == "sessions")
        audit_report = next(r for r in result.reports if r.table == "audit_log")
        assert sessions_report.rows_updated == 1
        assert audit_report.rows_updated == 1
        assert sessions_report.dry_run is True
        # But no writes occurred.
        assert await _count_project_id_empty(db, "sessions") == 1
        assert await _count_project_id_empty(db, "audit_log") == 1
    finally:
        await db.close()


async def test_acceptance_9_run_backfill_stamps_same_project_id_everywhere(tmp_path):
    """A5-2 #9: ``run_backfill`` stamps the same project_id on every table."""
    db = await _make_db(tmp_path / "khaos.db")
    try:
        await _insert_legacy_row(db, "sessions", session_id="s1")
        await _insert_legacy_row(db, "audit_log")
        await _insert_legacy_row(db, "memories")
        result = await run_backfill(db, tmp_path)
        assert result.project_id == compute_project_id(tmp_path)
        # Every legacy row was stamped with the same project_id.
        conn = await db._require_conn()
        for table in ("sessions", "audit_log", "memories"):
            cursor = await conn.execute(
                f"SELECT project_id FROM {table} WHERE project_id != '' LIMIT 1"
            )
            row = await cursor.fetchone()
            await cursor.close()
            assert row is not None, f"{table}: no stamped rows"
            assert row[0] == result.project_id, (
                f"{table}: expected project_id={result.project_id!r}, "
                f"got {row[0]!r}"
            )
    finally:
        await db.close()


async def test_acceptance_10_run_backfill_with_table_subset(tmp_path):
    """A5-2 #10: ``run_backfill`` with ``tables=[...]`` only backfills listed tables."""
    db = await _make_db(tmp_path / "khaos.db")
    try:
        await _insert_legacy_row(db, "sessions", session_id="s1")
        await _insert_legacy_row(db, "audit_log")
        result = await run_backfill(db, tmp_path, tables=["sessions"])
        # Only sessions was backfilled.
        assert [r.table for r in result.reports] == ["sessions"]
        assert result.reports[0].rows_updated == 1
        # audit_log still has the legacy row.
        assert await _count_project_id_empty(db, "audit_log") == 1
        # sessions was backfilled.
        assert await _count_project_id_empty(db, "sessions") == 0
    finally:
        await db.close()


async def test_acceptance_11_run_backfill_resolves_symlinks(tmp_path):
    """A5-2 #11: ``run_backfill`` resolves symlinks before hashing.

    Two paths that resolve to the same realpath produce the same
    project_id, so symlink-equivalent project roots are interchangeable.
    """
    db = await _make_db(tmp_path / "khaos.db")
    try:
        # Create a symlink to tmp_path.
        link = tmp_path / "link"
        try:
            link.symlink_to(tmp_path)
        except OSError:
            pytest.skip("symlink creation not supported")
        result_real = await run_backfill(db, tmp_path)
        result_link = await run_backfill(db, link)
        assert result_real.project_id == result_link.project_id
    finally:
        await db.close()


def test_acceptance_12_audit_log_is_last_in_table_order():
    """A5-2 #12: ``A_5_1A_TABLES`` order has ``audit_log`` LAST.

    The migration's own audit entry (if any) is written before the
    backfill completes; backfilling audit_log LAST ensures that entry
    is also re-stamped to the new project_id, so the audit trail is
    self-consistent.
    """
    assert A_5_1A_TABLES[-1] == "audit_log"
    assert A_5_1A_TABLES.count("audit_log") == 1
    assert len(A_5_1A_TABLES) == 8


# ────────────────────────────── CLI handler ─────────────────────────────


def _parse_migrate_args(argv: list[str]):
    """Parse ``khaos migrate ...`` args and return the namespace."""
    parser = build_command_parser()
    return parser.parse_args(argv)


async def test_acceptance_13_cli_dry_run_makes_no_writes(tmp_path, monkeypatch, capsys):
    """A5-2 #13: ``cmd_migrate --dry-run`` makes no writes.

    NOTE: this test is ``async def`` because pytest-asyncio's AUTO mode
    treats it as a coroutine test.  ``cmd_migrate`` itself is sync and
    calls ``asyncio.run()`` internally — that fails when called from
    inside a running loop.  We work around this by offloading the
    sync ``cmd_migrate`` call to a worker thread with its own event
    loop.
    """
    monkeypatch.setenv("KHAOS_ALLOW_PROJECT_DB", "1")
    db_path = tmp_path / "khaos.db"

    # Seed a legacy row.
    db = await _make_db(db_path)
    await _insert_legacy_row(db, "sessions", session_id="s1")
    await db.close()

    args = _parse_migrate_args([
        "migrate", "project-identity",
        "--project-root", str(tmp_path),
        "--db", str(db_path),
        "--dry-run",
    ])

    import concurrent.futures
    loop = asyncio.get_event_loop()
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        exit_code = await loop.run_in_executor(pool, cmd_migrate, args)
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "dry-run" in captured.out.lower() or "dry run" in captured.out.lower()
    assert "1" in captured.out  # 1 legacy row previewed.

    # Verify no writes occurred.
    db = Database(db_path)
    await db.connect()
    try:
        assert await _count_project_id_empty(db, "sessions") == 1
    finally:
        await db.close()


async def test_acceptance_14_cli_yes_writes_and_prints_counts(tmp_path, monkeypatch, capsys):
    """A5-2 #14: ``cmd_migrate --yes`` writes and prints per-table counts.

    See ``test_acceptance_13`` for the thread-pool rationale.
    """
    monkeypatch.setenv("KHAOS_ALLOW_PROJECT_DB", "1")
    db_path = tmp_path / "khaos.db"

    # Seed legacy rows.
    db = await _make_db(db_path)
    await _insert_legacy_row(db, "sessions", session_id="s1")
    await _insert_legacy_row(db, "sessions", session_id="s2")
    await _insert_legacy_row(db, "audit_log")
    await db.close()

    args = _parse_migrate_args([
        "migrate", "project-identity",
        "--project-root", str(tmp_path),
        "--db", str(db_path),
        "--yes",
    ])

    import concurrent.futures
    loop = asyncio.get_event_loop()
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        exit_code = await loop.run_in_executor(pool, cmd_migrate, args)
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "Backfill complete" in captured.out
    assert "3" in captured.out  # 3 total rows updated.

    # Verify writes occurred.
    db = Database(db_path)
    await db.connect()
    try:
        assert await _count_project_id_empty(db, "sessions") == 0
        assert await _count_project_id_empty(db, "audit_log") == 0
    finally:
        await db.close()


def test_acceptance_15_cli_no_subcommand_prints_usage_and_returns_2(
    tmp_path, monkeypatch, capsys,
):
    """A5-2 #15: ``cmd_migrate`` with no subcommand returns exit code 2."""
    args = _parse_migrate_args(["migrate"])
    exit_code = cmd_migrate(args)
    captured = capsys.readouterr()
    assert exit_code == 2
    assert "usage" in captured.err.lower()
