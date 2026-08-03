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


async def test_tool_operation_prune_keeps_effectful_tombstones(tmp_path):
    db = Database(tmp_path / "tool-operations.db")
    await db.connect()
    await db.run_migrations()

    for operation_id in ("no-effect", "applied", "unknown"):
        claimed = await db.claim_tool_operation(
            operation_id=operation_id,
            tool_name="effect",
            arguments_digest=operation_id,
            effect_id=f"effect-{operation_id}",
            owner_token=f"owner-{operation_id}",
            principal_id="principal",
            project_id="project",
            session_id="session",
            task_id="task",
            workspace_id="workspace",
        )
        assert claimed["state"] == "claimed"
        terminal_status = "unknown" if operation_id == "unknown" else "completed"
        effect_status = {
            "no-effect": "not_applied",
            "applied": "applied",
            "unknown": "unknown",
        }[operation_id]
        assert await db.complete_tool_operation(
            operation_id=operation_id,
            owner_token=f"owner-{operation_id}",
            status=terminal_status,
            effect_status=effect_status,
            result_json="{}",
        ) == 1

    async with db.transaction() as conn:
        await conn.execute(
            "UPDATE tool_operations SET updated_at = ?",
            ("2000-01-01T00:00:00",),
        )

    assert await db.prune_tool_operations(
        older_than_seconds=60, now=1_900_000_000, limit=10
    ) == 1
    conn = await db._require_conn()
    cursor = await conn.execute(
        "SELECT operation_id FROM tool_operations ORDER BY operation_id"
    )
    remaining = [str(row["operation_id"]) for row in await cursor.fetchall()]
    assert remaining == ["applied", "unknown"]
    await db.close()
