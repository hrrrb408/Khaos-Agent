"""Tests for ``khaos.tools.history_tools``.

M4 batch 3.1.16A-4-4-2: the module-global ``_session_search`` holder
and the ``set_session_search`` setter have been removed.  Every handler
now receives ``principal_id`` and ``db`` as keyword arguments (injected
by the broker in production via the ``history.read`` capability).  These
tests pass them directly to mimic the broker injection.

Runs the DB-backed scenarios inside ``asyncio.run`` so each test's
aiosqlite worker thread owns a fresh loop (avoids the pytest-asyncio
teardown deadlock).
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import khaos.tools.history_tools as history_tools
from khaos.db import Database
from khaos.tools.history_tools import (
    history_browse,
    history_read,
    history_search,
)


# ---------------------------------------------------------------------------
# DB-backed fixtures
# ---------------------------------------------------------------------------


async def _seeded_db(tmp_path: Path) -> Database:
    """Build a fresh DB with two principals' worth of session data so
    cross-principal scoping can be asserted."""
    db = Database(tmp_path / "h.db")
    await db.connect()
    await db.run_migrations()
    # Alice owns s1 with messages about pytest.
    await db.create_session("s1", principal_id="api:alice")
    from khaos.agent.core import Message

    mid = await db.insert_message(
        "s1", Message(role="user", content="how to use pytest", token_count=4),
        principal_id="api:alice",
    )
    await db.insert_message_fts("s1", "user", "how to use pytest", 4, rowid=mid)
    mid = await db.insert_message(
        "s1", Message(role="assistant", content="run the pytest command", token_count=4),
        principal_id="api:alice",
    )
    await db.insert_message_fts("s1", "assistant", "run the pytest command", 4, rowid=mid)
    # Bob owns s2 with messages about kubernetes.
    await db.create_session("s2", principal_id="api:bob")
    mid = await db.insert_message(
        "s2", Message(role="user", content="how to debug kubernetes pods", token_count=5),
        principal_id="api:bob",
    )
    await db.insert_message_fts("s2", "user", "how to debug kubernetes pods", 5, rowid=mid)
    return db


# ---------------------------------------------------------------------------
# Happy path — kwargs injected (mirrors broker injection in production)
# ---------------------------------------------------------------------------


def test_search_returns_results_for_caller_principal(tmp_path: Path) -> None:
    async def run():
        db = await _seeded_db(tmp_path)
        try:
            result = await history_search(
                "pytest", principal_id="api:alice", db=db,
            )
            assert result["query"] == "pytest"
            assert len(result["results"]) >= 1
            assert all("pytest" in r["snippet"].lower() for r in result["results"])
        finally:
            await db.close()

    asyncio.run(run())


def test_browse_returns_sessions_for_caller_principal(tmp_path: Path) -> None:
    async def run():
        db = await _seeded_db(tmp_path)
        try:
            result = await history_browse(principal_id="api:alice", db=db)
            # Alice owns only s1.
            assert len(result["sessions"]) == 1
            assert result["sessions"][0]["session_id"] == "s1"
            assert result["sessions"][0]["message_count"] >= 2
        finally:
            await db.close()

    asyncio.run(run())


def test_read_returns_messages_for_caller_principal(tmp_path: Path) -> None:
    async def run():
        db = await _seeded_db(tmp_path)
        try:
            result = await history_read(
                "s1", principal_id="api:alice", db=db,
            )
            assert result["session_id"] == "s1"
            assert len(result["messages"]) == 2
            assert [m["role"] for m in result["messages"]] == ["user", "assistant"]
        finally:
            await db.close()

    asyncio.run(run())


# ---------------------------------------------------------------------------
# Cross-principal isolation (the original CRITICAL bug regression)
# ---------------------------------------------------------------------------


def test_search_does_not_leak_other_principals_history(tmp_path: Path) -> None:
    """Alice's search must not return Bob's sessions — the old module-
    global holder would have served the same ``SessionSearch`` instance
    to every principal."""
    async def run():
        db = await _seeded_db(tmp_path)
        try:
            # Alice searches for "kubernetes" (only Bob has matches).
            result = await history_search(
                "kubernetes", principal_id="api:alice", db=db,
            )
            assert result["query"] == "kubernetes"
            assert result["results"] == [], (
                "Alice must not see Bob's kubernetes results"
            )
            # Bob searches for "pytest" (only Alice has matches).
            result = await history_search(
                "pytest", principal_id="api:bob", db=db,
            )
            assert result["results"] == [], (
                "Bob must not see Alice's pytest results"
            )
        finally:
            await db.close()

    asyncio.run(run())


def test_read_returns_empty_for_foreign_session(tmp_path: Path) -> None:
    """Alice cannot read Bob's session — ``get_session_messages`` filters
    by ``principal_id``."""
    async def run():
        db = await _seeded_db(tmp_path)
        try:
            result = await history_read(
                "s2", principal_id="api:alice", db=db,
            )
            assert result["session_id"] == "s2"
            assert result["messages"] == [], (
                "Alice must not read Bob's session s2"
            )
        finally:
            await db.close()

    asyncio.run(run())


# ---------------------------------------------------------------------------
# Fail-closed — missing principal_id / db
# ---------------------------------------------------------------------------


def test_search_rejects_empty_principal_id() -> None:
    async def run():
        return await history_search("anything", principal_id="", db=None)

    result = asyncio.run(run())
    assert result["status"] == "unavailable"
    assert "principal_id is required" in result["error"]
    assert result["results"] == []


def test_browse_rejects_empty_principal_id() -> None:
    async def run():
        return await history_browse(principal_id="", db=None)

    result = asyncio.run(run())
    assert result["status"] == "unavailable"
    assert "principal_id is required" in result["error"]


def test_read_rejects_empty_principal_id() -> None:
    async def run():
        return await history_read("s1", principal_id="", db=None)

    result = asyncio.run(run())
    assert result["status"] == "unavailable"
    assert "principal_id is required" in result["error"]


def test_search_reports_unavailable_when_db_missing(tmp_path: Path) -> None:
    """A missing ``db`` returns ``unavailable`` (mirrors the original
    "not configured" behavior) so a misconfigured tool context fails
    gracefully rather than crashing."""
    async def run():
        return await history_search("pytest", principal_id="api:alice", db=None)

    result = asyncio.run(run())
    assert result["status"] == "unavailable"
    assert "session search not configured" in result["error"]


def test_browse_reports_unavailable_when_db_missing() -> None:
    async def run():
        return await history_browse(principal_id="api:alice", db=None)

    result = asyncio.run(run())
    assert result["status"] == "unavailable"
    assert "session search not configured" in result["error"]


def test_read_reports_unavailable_when_db_missing() -> None:
    async def run():
        return await history_read("s1", principal_id="api:alice", db=None)

    result = asyncio.run(run())
    assert result["status"] == "unavailable"
    assert "session search not configured" in result["error"]


# ---------------------------------------------------------------------------
# Module-global holder removal
# ---------------------------------------------------------------------------


def test_set_session_search_removed():
    """The setter function has been deleted — callers can no longer
    install a module-global SessionSearch (the source of the cross-
    principal leak)."""
    assert not hasattr(history_tools, "set_session_search")


def test_session_search_holder_removed():
    assert not hasattr(history_tools, "_session_search")
