from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

from khaos.subagents.service import SubAgentService


async def test_handle_spawn_success():
    spawner = MagicMock()
    # M3 (round-5): service returns the real task status, so the mock
    # must carry a ``status`` attribute.  A successful spawn returns
    # ``running`` (the spawner flips ``initializing`` → ``running``
    # once the runner is published).
    spawner.spawn = AsyncMock(
        return_value=SimpleNamespace(id="task_1", status="running")
    )
    service = SubAgentService(spawner, runner=None)

    result = await service.handle_spawn(
        {
            "principal_id": "user1",
            "goal": "inspect",
            "context": "ctx",
            "tools": ["read_file"],
            "timeout": 300,
        }
    )

    assert result == {"ok": True, "task_id": "task_1", "status": "running"}
    task = spawner.spawn.call_args.args[0]
    assert task.goal == "inspect"
    assert task.context == "ctx"
    assert task.tools == ["read_file"]
    # M2: parent_session_id is namespaced per principal.
    assert task.parent_session_id == "subagent:user1"


async def test_handle_spawn_returns_failed_when_aborted():
    """M3 (round-5): when shutdown begins during spawn's DB work, the
    spawner aborts and returns a task with ``status="failed"`` /
    ``error="cancelled"``.  The service MUST surface this to the caller
    as ``ok=false, status=failed`` instead of the previous hardcoded
    ``ok=true, status=running`` — a caller believing a cancelled task is
    running would wait forever for a result that will never come.
    """
    spawner = MagicMock()
    spawner.spawn = AsyncMock(
        return_value=SimpleNamespace(
            id="task_1", status="failed", error="cancelled",
        )
    )
    service = SubAgentService(spawner, runner=None)

    result = await service.handle_spawn(
        {"principal_id": "user1", "goal": "inspect"}
    )

    assert result == {
        "ok": False,
        "task_id": "task_1",
        "status": "failed",
        "error": "cancelled",
    }


async def test_handle_spawn_error():
    spawner = MagicMock()
    spawner.spawn = AsyncMock(side_effect=RuntimeError("boom"))
    service = SubAgentService(spawner, runner=None)

    result = await service.handle_spawn({"principal_id": "user1", "goal": "inspect"})

    assert result == {"ok": False, "error": "boom"}


async def test_handle_spawn_rejects_empty_principal():
    """M2: empty ``principal_id`` is rejected before calling the spawner."""
    spawner = MagicMock()
    spawner.spawn = AsyncMock(return_value=SimpleNamespace(id="task_1"))
    service = SubAgentService(spawner, runner=None)

    result = await service.handle_spawn({"goal": "inspect"})

    assert result == {"ok": False, "error": "principal_id is required"}
    spawner.spawn.assert_not_awaited()


async def test_handle_collect_success():
    spawner = MagicMock()
    spawner.wait_all = AsyncMock(
        return_value=[
            SimpleNamespace(
                id="task_1",
                goal="one",
                status="completed",
                result="done",
                error=None,
            ),
            SimpleNamespace(
                id="task_2",
                goal="two",
                status="failed",
                result=None,
                error="boom",
            ),
        ]
    )
    service = SubAgentService(spawner, runner=None)

    result = await service.handle_collect({"principal_id": "user1"})

    assert result["ok"] is True
    assert result["total"] == 2
    assert result["completed"] == 1
    assert result["failed"] == 1
    assert result["results"][0]["task_id"] == "task_1"
    assert result["results"][1]["error"] == "boom"


async def test_handle_collect_rejects_empty_principal():
    """M2: empty ``principal_id`` is rejected before calling the spawner."""
    spawner = MagicMock()
    spawner.wait_all = AsyncMock(return_value=[])
    service = SubAgentService(spawner, runner=None)

    result = await service.handle_collect({})

    assert result == {"ok": False, "error": "principal_id is required"}
    spawner.wait_all.assert_not_awaited()


async def test_handle_status():
    spawner = MagicMock()
    spawner.stats.return_value = {"active": 1, "total": 2}
    service = SubAgentService(spawner, runner=None)

    result = await service.handle_status({"principal_id": "user1"})

    assert result == {"ok": True, "stats": {"active": 1, "total": 2}}


async def test_handle_status_rejects_empty_principal():
    """M2: empty ``principal_id`` is rejected before calling the spawner."""
    spawner = MagicMock()
    spawner.stats.return_value = {"active": 1, "total": 2}
    service = SubAgentService(spawner, runner=None)

    result = await service.handle_status({})

    assert result == {"ok": False, "error": "principal_id is required"}
    spawner.stats.assert_not_called()
