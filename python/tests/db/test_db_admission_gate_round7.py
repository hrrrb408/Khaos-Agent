"""Batch 7.6 (round-7): DB Admission Gate + Supply Chain.

Closes review §二十 (Reader admission fence), §二十一 (:memory: shared
connection), §二十五 (io_uring seccomp — structural check on the launcher
source since the binary is Linux-only).
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

import pytest

from khaos.db import Database
from khaos.db.database import DatabaseClosingError


# ===========================================================================
# §二十 — Reader admission fence
# ===========================================================================


async def test_s20_read_during_close_is_rejected(tmp_path):
    """§二十: once ``close()`` has set the admission fence, a NEW
    ``_read_lease()`` entry must raise ``DatabaseClosingError`` instead
    of entering and then being torn down mid-fetch."""
    db = Database(tmp_path / "fence.db")
    await db.connect()
    await db.run_migrations()
    # Simulate the fence being set (as close() does before draining).
    db._closing = True
    with pytest.raises(DatabaseClosingError):
        async with db._read_lease():
            pass
    # Reset so the db can be closed cleanly.
    db._closing = False
    await db.close()


async def test_s20_read_succeeds_when_not_closing(tmp_path):
    """§二十 sanity: when ``_closing`` is False, reads are admitted
    normally (the fence does not break the happy path)."""
    db = Database(tmp_path / "happy.db")
    await db.connect()
    await db.run_migrations()
    assert db._closing is False
    async with db._read_lease():
        pass  # admitted
    await db.close()


async def test_s20_close_resets_fence_for_reopen(tmp_path):
    """§二十: after ``close()`` completes, ``_closing`` is reset so a
    subsequent ``connect()`` admits reads again (re-open path)."""
    db = Database(tmp_path / "reopen.db")
    await db.connect()
    await db.run_migrations()
    await db.close()
    assert db._closing is False, "close() did not reset the fence"
    # Re-open and read.
    await db.connect()
    async with db._read_lease():
        pass
    await db.close()


# ===========================================================================
# §二十一 — :memory: shared connection
# ===========================================================================


async def test_s21_memory_db_writer_and_reader_share_database():
    """§二十一: a ``:memory:`` database must NOT create two independent
    in-memory DBs.  The writer's migration creates tables; the reader
    must see them.  Pre-fix the reader saw an empty database."""
    db = Database(":memory:")
    await db.connect()
    await db.run_migrations()
    # The reader connection must see the writer's tables (not an empty DB).
    reader = await db._require_reader_conn()
    cursor = await reader.execute(
        "SELECT COUNT(*) FROM sqlite_master "
        "WHERE type='table' AND name='sessions'"
    )
    row = await cursor.fetchone()
    count = row[0] if isinstance(row, (tuple, list)) else row["COUNT(*)"]
    assert count == 1, (
        ":memory: reader did not see the writer's 'sessions' table — "
        "two independent in-memory DBs (§二十一 bug)"
    )
    await db.close()


async def test_s21_memory_db_read_returns_written_data():
    """§二十一: data written via the writer must be readable via the
    reader (proves the shared cache, not just shared schema)."""
    db = Database(":memory:")
    await db.connect()
    await db.run_migrations()
    # Insert a session via the writer.
    writer = await db._require_writer_conn()
    await writer.execute(
        "INSERT INTO sessions (id, mode, status, principal_id, project_id, "
        "created_at, updated_at) "
        "VALUES ('s-mem', 'office', 'active', 'p1', '', 'now', 'now')"
    )
    await writer.commit()
    # Read it back via a read lease (reader path).
    async with db._read_lease():
        result = await db.list_sessions(principal_id="p1")
    assert any(s["id"] == "s-mem" for s in result), (
        ":memory: reader could not read writer-inserted data (§二十一 bug)"
    )
    await db.close()


# ===========================================================================
# §二十五 — io_uring in the launcher seccomp deny list (structural check)
# ===========================================================================


def test_s25_launcher_denies_io_uring_syscalls():
    """§二十五: the Rust launcher's seccomp deny list must include the
    three io_uring syscalls.  We check the source (the binary is
    Linux-only and can't run in the unit-test suite) so the check works
    cross-platform."""
    launcher_src = (
        Path(__file__).resolve().parents[3]
        / "rust" / "khaos-core" / "src" / "bin" / "khaos-sandbox-launcher.rs"
    )
    assert launcher_src.is_file(), "launcher source not found"
    content = launcher_src.read_text(encoding="utf-8")
    for syscall in (
        "SYS_io_uring_setup",
        "SYS_io_uring_enter",
        "SYS_io_uring_register",
    ):
        assert syscall in content, (
            f"§二十五: launcher seccomp does not deny {syscall}"
        )
