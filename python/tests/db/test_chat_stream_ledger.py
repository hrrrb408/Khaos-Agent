from __future__ import annotations

import sqlite3

import pytest

from khaos.db import Database


async def _db(tmp_path) -> Database:
    db = Database(tmp_path / "chat-ledger.db")
    await db.connect()
    await db.run_migrations()
    await db.create_session(
        "s1", principal_id="alice", project_id="project-a",
    )
    return db


async def test_chat_events_are_durable_ordered_and_replayable(tmp_path):
    db = await _db(tmp_path)
    try:
        first = await db.append_chat_stream_event(
            session_id="s1", principal_id="alice", project_id="project-a",
            event_type="message", data={"content": "one"}, now=1.0,
        )
        second = await db.append_chat_stream_event(
            session_id="s1", principal_id="alice", project_id="project-a",
            event_type="done", data={"total_tokens": 1}, now=2.0,
        )
        assert (first, second) == (1, 2)
        replay = await db.list_chat_stream_events(
            session_id="s1", principal_id="alice", project_id="project-a",
            after_sequence=1,
        )
        assert [event["sequence"] for event in replay] == [2]
        assert replay[0]["terminal"] is True
    finally:
        await db.close()


async def test_chat_event_owner_tuple_is_database_enforced(tmp_path):
    db = await _db(tmp_path)
    try:
        with pytest.raises(sqlite3.IntegrityError):
            await db.append_chat_stream_event(
                session_id="s1", principal_id="bob",
                project_id="project-a", event_type="message",
                data={"content": "forged"}, now=1.0,
            )
        assert await db.list_chat_stream_events(
            session_id="s1", principal_id="alice", project_id="project-a",
        ) == []
    finally:
        await db.close()


async def test_inflight_chat_is_closed_durably_on_restart(tmp_path):
    db = await _db(tmp_path)
    try:
        await db.append_chat_stream_event(
            session_id="s1", principal_id="alice", project_id="project-a",
            event_type="started", data={"session_id": "s1"}, now=1.0,
        )
        assert await db.recover_inflight_chat_streams(now=2.0) == 1
        assert await db.recover_inflight_chat_streams(now=3.0) == 0
        events = await db.list_chat_stream_events(
            session_id="s1", principal_id="alice", project_id="project-a",
        )
        assert [event["event"] for event in events] == ["started", "error"]
        assert events[-1]["data"]["code"] == "PROCESS_RESTART"
    finally:
        await db.close()
