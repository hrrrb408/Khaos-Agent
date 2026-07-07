from khaos.agent.core import Message
from khaos.db import Database


async def test_schema_creates_all_p0_tables(tmp_path):
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()

    conn = await db._require_conn()
    cursor = await conn.execute(
        "SELECT name FROM sqlite_master WHERE type IN ('table', 'view')"
    )
    names = {row["name"] for row in await cursor.fetchall()}

    assert {
        "sessions",
        "messages",
        "memories",
        "memory_fts",
        "permissions",
        "tools",
        "audit_log",
        "user_config",
        "subagent_tasks",
    }.issubset(names)
    await db.close()


async def test_messages_round_trip(tmp_path):
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    await db.create_session("s1", mode="coding")

    await db.insert_message("s1", Message(role="user", content="hello", token_count=1))
    messages = await db.list_messages("s1")

    assert messages == [Message(role="user", content="hello", token_count=1)]
    await db.close()

