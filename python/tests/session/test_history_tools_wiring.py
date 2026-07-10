"""Tests for history_tools → SessionSearch wiring.

Runs the DB-backed scenarios inside ``asyncio.run`` so each test's aiosqlite
worker thread owns a fresh loop (avoids the pytest-asyncio teardown deadlock).
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import khaos.tools.history_tools as history_tools
from khaos.db import Database
from khaos.session import SessionSearch
from khaos.tools.history_tools import (
    history_browse,
    history_read,
    history_search,
    set_session_search,
)


async def _seeded_search(tmp_path: Path) -> tuple[SessionSearch, Database]:
    db = Database(tmp_path / "h.db")
    await db.connect()
    await db.run_migrations()
    await db.create_session("s1")
    from khaos.agent.core import Message

    mid = await db.insert_message("s1", Message(role="user", content="how to use pytest", token_count=4))
    await db.insert_message_fts("s1", "user", "how to use pytest", 4, rowid=mid)
    mid = await db.insert_message("s1", Message(role="assistant", content="run the pytest command", token_count=4))
    await db.insert_message_fts("s1", "assistant", "run the pytest command", 4, rowid=mid)
    return SessionSearch(db), db


def test_search_with_injected_returns_real_results(tmp_path: Path) -> None:
    async def run():
        search, db = await _seeded_search(tmp_path)
        set_session_search(search)
        try:
            result = await history_search("pytest")
            assert result["query"] == "pytest"
            assert len(result["results"]) >= 1
            assert all("pytest" in r["snippet"].lower() for r in result["results"])
        finally:
            set_session_search(None)
            await db.close()

    asyncio.run(run())


def test_browse_with_injected_returns_sessions(tmp_path: Path) -> None:
    async def run():
        search, db = await _seeded_search(tmp_path)
        set_session_search(search)
        try:
            result = await history_browse()
            assert len(result["sessions"]) >= 1
            assert result["sessions"][0]["session_id"] == "s1"
            assert result["sessions"][0]["message_count"] >= 2
        finally:
            set_session_search(None)
            await db.close()

    asyncio.run(run())


def test_read_with_injected_returns_messages(tmp_path: Path) -> None:
    async def run():
        search, db = await _seeded_search(tmp_path)
        set_session_search(search)
        try:
            result = await history_read("s1")
            assert result["session_id"] == "s1"
            assert len(result["messages"]) == 2
            assert [m["role"] for m in result["messages"]] == ["user", "assistant"]
        finally:
            set_session_search(None)
            await db.close()

    asyncio.run(run())


def test_search_without_injected_reports_unavailable() -> None:
    set_session_search(None)

    async def run():
        result = await history_search("anything")
        return result

    result = asyncio.run(run())
    assert result["status"] == "unavailable"
    assert result["results"] == []


def test_browse_without_injected_reports_unavailable() -> None:
    set_session_search(None)

    async def run():
        return await history_browse()

    result = asyncio.run(run())
    assert result["status"] == "unavailable"
    assert result["sessions"] == []
