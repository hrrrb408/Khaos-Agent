"""Contract tests for the session/message SQL repository boundary."""

from __future__ import annotations

from khaos.agent.core import Message
from khaos.db import Database
from khaos.db.repositories import SessionRepository


async def _database(tmp_path) -> Database:
    db = Database(tmp_path / "sessions.db")
    await db.connect()
    await db.run_migrations()
    return db


async def test_database_facade_uses_one_session_repository(tmp_path) -> None:
    db = await _database(tmp_path)
    assert isinstance(db._session_repository, SessionRepository)

    await db.create_session("s1", principal_id="alice", project_id="project-a")
    message_id = await db.insert_message(
        "s1",
        Message(role="user", content="repository boundary", token_count=2),
        principal_id="alice",
        project_id="project-a",
    )

    rows = await db.get_session_messages(
        "s1", principal_id="alice", project_id="project-a"
    )
    assert [row["id"] for row in rows] == [message_id]
    assert await db.count_session_messages(
        "s1", principal_id="alice", project_id="project-a"
    ) == 1
    await db.close()


async def test_session_repository_owner_filters_are_independent(tmp_path) -> None:
    db = await _database(tmp_path)
    await db.create_session("s1", principal_id="alice", project_id="project-a")
    await db.insert_message(
        "s1",
        Message(role="user", content="owner scoped", token_count=2),
        principal_id="alice",
        project_id="project-a",
    )

    assert await db.get_session("s1", principal_id="alice", project_id="project-a")
    assert await db.get_session("s1", principal_id="alice", project_id="project-b") is None
    assert await db.get_session_messages(
        "s1", principal_id="alice", project_id="project-b"
    ) == []
    assert await db.count_session_messages(
        "s1", principal_id="alice", project_id="project-b"
    ) == 0
    await db.close()


async def test_session_repository_window_and_counts_preserve_order(tmp_path) -> None:
    db = await _database(tmp_path)
    await db.create_session("s1", principal_id="alice", project_id="project-a")
    for content in ("one", "two", "three"):
        await db.insert_message(
            "s1",
            Message(role="user", content=content, token_count=1),
            principal_id="alice",
            project_id="project-a",
        )

    rows = await db.get_session_messages("s1", principal_id="alice", project_id="project-a")
    anchor = rows[1]["id"]
    window = await db.get_message_window(
        "s1", anchor, window=1, principal_id="alice", project_id="project-a"
    )
    assert [row["content"] for row in window] == ["one", "two", "three"]
    assert await db.count_messages_before_after(
        "s1", anchor, principal_id="alice", project_id="project-a"
    ) == (1, 1)
    await db.close()
