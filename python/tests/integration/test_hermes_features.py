"""Integration tests for the Hermes-feature wiring.

Runs each scenario inside ``asyncio.run`` so its aiosqlite worker thread owns a
fresh event loop — this avoids the teardown deadlock that occurs when async
DB tests share pytest-asyncio's loop with other DB-heavy files in the suite.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from khaos.db import Database
from khaos.scheduler import CronEngine, ScheduleConfig
from khaos.session import SessionSearch


async def _db(tmp_path: Path) -> Database:
    db = Database(tmp_path / "hermes.db")
    await db.connect()
    await db.run_migrations()
    return db


def test_cron_create_and_list(tmp_path: Path) -> None:
    """Create a task via CronEngine and confirm it shows in list_tasks."""

    async def run():
        engine = CronEngine(db=None)
        task = await engine.create(
            "standup",
            "summarize today",
            ScheduleConfig(interval_seconds=3600),
            principal_id="hermes-test",
        )
        listed = await engine.list_tasks(principal_id="hermes-test")
        assert task in listed
        assert listed[0].name == "standup"

    asyncio.run(run())


def test_history_search_integration(tmp_path: Path) -> None:
    """Insert + index messages, then FTS-search across sessions."""

    async def run():
        from khaos.agent.core import Message

        db = await _db(tmp_path)
        await db.create_session("sa")
        await db.create_session("sb")
        # sa talks about pytest, sb about docker.
        for role, content in [
            ("user", "how to run pytest"),
            ("assistant", "use the pytest command"),
        ]:
            mid = await db.insert_message("sa", Message(role=role, content=content, token_count=3))
            await db.insert_message_fts("sa", role, content, 3, rowid=mid)
        for role, content in [("user", "build docker image"), ("assistant", "docker build")]:
            mid = await db.insert_message("sb", Message(role=role, content=content, token_count=3))
            await db.insert_message_fts("sb", role, content, 3, rowid=mid)

        results = await SessionSearch(db).search("pytest")
        assert len(results) >= 1
        assert all(r.session_id == "sa" for r in results)
        # docker query lands in sb only.
        docker = await SessionSearch(db).search("docker")
        assert all(r.session_id == "sb" for r in docker)
        await db.close()

    asyncio.run(run())


def test_cron_db_persistence(tmp_path: Path) -> None:
    """A task created with a DB is persisted and reloadable."""

    async def run():
        db = await _db(tmp_path)
        engine = CronEngine(db=db)
        await engine.create(
            "daily",
            "p",
            ScheduleConfig(cron="0 9"),
            deliver_to="local",
            principal_id="hermes-test",
        )
        rows = await db.list_scheduled_tasks(principal_id="hermes-test")
        assert len(rows) == 1
        assert rows[0]["name"] == "daily"
        await db.close()

    asyncio.run(run())
