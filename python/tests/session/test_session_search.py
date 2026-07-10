"""Tests for session history search (FTS5 + browse + scroll window).

Runs the full pipeline inside ``asyncio.run`` per test. This keeps each test's
aiosqlite worker thread on its own event loop, avoiding the teardown
deadlock that occurs when many async DB tests share pytest-asyncio's loop
alongside other DB-heavy test files in the suite.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from khaos.db import Database
from khaos.session import SessionSearch


async def _seeded_db(tmp_path: Path) -> Database:
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    await db.create_session("s1")
    await db.create_session("s2")
    # s1: two messages about python testing
    await db.insert_message("s1", _msg("user", "how do I test python async code"))
    await db.insert_message("s1", _msg("assistant", "use pytest with asyncio"))
    # s2: one message about docker
    await db.insert_message("s2", _msg("user", "how to build a docker image"))
    await db.insert_message("s2", _msg("assistant", "use docker build command"))
    return db


def _msg(role: str, content: str):
    from khaos.agent.core import Message

    return Message(role=role, content=content, token_count=len(content.split()))


async def _index_all(db: Database) -> None:
    """Index existing messages into FTS (mirrors what core.py will do)."""
    for sid in ("s1", "s2"):
        rows = await db.get_session_messages(sid, 1000, 0)
        for row in rows:
            await db.insert_message_fts(
                sid, row["role"], row["content"], row.get("token_count", 0), rowid=row["id"]
            )


def test_search_single_term(tmp_path: Path) -> None:
    async def run():
        db = await _seeded_db(tmp_path)
        await _index_all(db)
        results = await SessionSearch(db).search("python")
        assert len(results) >= 1
        assert all("python" in r.snippet.lower() or "python" in r.session_id for r in results)
        await db.close()

    asyncio.run(run())


def test_search_and_operator(tmp_path: Path) -> None:
    async def run():
        db = await _seeded_db(tmp_path)
        await _index_all(db)
        # FTS5 implicit AND: "python async" must match both terms.
        results = await SessionSearch(db).search("python async")
        assert len(results) >= 1
        await db.close()

    asyncio.run(run())


def test_search_quoted_phrase(tmp_path: Path) -> None:
    async def run():
        db = await _seeded_db(tmp_path)
        await _index_all(db)
        results = await SessionSearch(db).search('"docker build"')
        assert len(results) >= 1
        assert any("docker" in r.snippet.lower() for r in results)
        await db.close()

    asyncio.run(run())


def test_browse_returns_summaries(tmp_path: Path) -> None:
    async def run():
        db = await _seeded_db(tmp_path)
        summaries = await SessionSearch(db).browse()
        assert len(summaries) == 2
        ids = {s.session_id for s in summaries}
        assert ids == {"s1", "s2"}
        # Each summary has a message count.
        assert all(s.message_count >= 2 for s in summaries)
        await db.close()

    asyncio.run(run())


def test_scroll_around_message(tmp_path: Path) -> None:
    async def run():
        db = await _seeded_db(tmp_path)
        messages = await db.get_session_messages("s1", 1000, 0)
        anchor = messages[1]["id"]  # second message
        window = await SessionSearch(db).scroll("s1", anchor, window=5)
        assert len(window.messages) >= 1
        assert window.anchor_id == anchor
        await db.close()

    asyncio.run(run())


def test_scroll_has_before_after(tmp_path: Path) -> None:
    async def run():
        db = await _seeded_db(tmp_path)
        messages = await db.get_session_messages("s1", 1000, 0)
        # Anchor on the first message → has_after True, has_before False.
        first = messages[0]["id"]
        window = await SessionSearch(db).scroll("s1", first, window=5)
        assert window.has_after is True
        assert window.has_before is False
        # Anchor on the last message → has_before True, has_after False.
        last = messages[-1]["id"]
        window2 = await SessionSearch(db).scroll("s1", last, window=5)
        assert window2.has_before is True
        assert window2.has_after is False
        await db.close()

    asyncio.run(run())


def test_read_session(tmp_path: Path) -> None:
    async def run():
        db = await _seeded_db(tmp_path)
        msgs = await SessionSearch(db).read_session("s1")
        assert len(msgs) == 2
        assert [m["role"] for m in msgs] == ["user", "assistant"]
        await db.close()

    asyncio.run(run())


def test_empty_results(tmp_path: Path) -> None:
    async def run():
        db = await _seeded_db(tmp_path)
        await _index_all(db)
        results = await SessionSearch(db).search("nonexistentterm12345")
        assert results == []
        await db.close()

    asyncio.run(run())
