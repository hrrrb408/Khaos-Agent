import asyncio

import pytest

from khaos.agent.events import TurnCoordinator
from khaos.db import Database


async def _database(path):
    db = Database(path)
    await db.connect()
    await db.run_migrations()
    await db.create_session("session", mode="coding")
    return db


async def test_turn_events_are_ordered_paired_and_single_terminal(tmp_path):
    db = await _database(tmp_path / "khaos.db")
    turn = await TurnCoordinator.start(
        db, session_id="session", task_id="task", principal_id="principal"
    )
    with pytest.raises(PermissionError, match="unmatched tool call"):
        await turn.emit("tool.result", {"tool_call_id": "call"})
    await turn.emit("tool.call", {"tool_call_id": "call", "name": "read_file"})
    await turn.emit("approval.wait", {"tool_call_id": "call"})
    await turn.emit("tool.result", {"tool_call_id": "call", "success": True})
    terminal = await turn.terminal("completed", reason="end_turn")
    assert terminal.payload["unmatched_tool_calls"] == []
    with pytest.raises(PermissionError, match="terminal"):
        await turn.terminal("failed", reason="late")
    with pytest.raises(PermissionError, match="late event"):
        await turn.emit("tool.call", {"tool_call_id": "late"})

    events = await db.list_agent_turn_events(turn.turn_id)
    assert [event["sequence"] for event in events] == list(range(1, 6))
    assert [event["event_type"] for event in events] == [
        "turn.started", "tool.call", "approval.wait", "tool.result",
        "turn.completed",
    ]
    await db.close()


async def test_process_restart_interrupts_inflight_turn(tmp_path):
    path = tmp_path / "khaos.db"
    first_db = await _database(path)
    abandoned = await TurnCoordinator.start(
        first_db, session_id="session", task_id=None, principal_id="principal"
    )
    await abandoned.emit("model.retry", {"attempt": 1})
    await first_db.close()

    restarted_db = await _database(path)
    current = await TurnCoordinator.start(
        restarted_db, session_id="session", task_id=None, principal_id="principal"
    )
    old_events = await restarted_db.list_agent_turn_events(abandoned.turn_id)
    assert old_events[-1]["event_type"] == "turn.interrupted"
    await current.terminal("completed", reason="test")
    await restarted_db.close()


async def test_database_rejects_sequence_race(tmp_path):
    db = await _database(tmp_path / "khaos.db")
    turn = await TurnCoordinator.start(
        db, session_id="session", task_id=None, principal_id="principal"
    )

    async def append(label):
        return await db.append_agent_turn_event(
            turn_id=turn.turn_id,
            expected_sequence=1,
            event_type="model.retry",
            payload={"label": label},
            now=1.0,
        )

    results = await asyncio.gather(append("a"), append("b"), return_exceptions=True)
    assert sum(isinstance(result, int) for result in results) == 1
    assert sum(isinstance(result, PermissionError) for result in results) == 1
    await db.close()
