from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

from khaos.subagents.service import SubAgentService


async def test_handle_spawn_success():
    spawner = MagicMock()
    spawner.spawn = AsyncMock(return_value=SimpleNamespace(id="task_1"))
    service = SubAgentService(spawner, runner=None)

    result = await service.handle_spawn(
        {"goal": "inspect", "context": "ctx", "tools": ["read_file"], "timeout": 300}
    )

    assert result == {"ok": True, "task_id": "task_1", "status": "running"}
    task = spawner.spawn.call_args.args[0]
    assert task.goal == "inspect"
    assert task.context == "ctx"
    assert task.tools == ["read_file"]
    assert task.parent_session_id == "gateway"


async def test_handle_spawn_error():
    spawner = MagicMock()
    spawner.spawn = AsyncMock(side_effect=RuntimeError("boom"))
    service = SubAgentService(spawner, runner=None)

    result = await service.handle_spawn({"goal": "inspect"})

    assert result == {"ok": False, "error": "boom"}


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

    result = await service.handle_collect({})

    assert result["ok"] is True
    assert result["total"] == 2
    assert result["completed"] == 1
    assert result["failed"] == 1
    assert result["results"][0]["task_id"] == "task_1"
    assert result["results"][1]["error"] == "boom"


async def test_handle_status():
    spawner = MagicMock()
    spawner.stats.return_value = {"active": 1, "total": 2}
    service = SubAgentService(spawner, runner=None)

    result = await service.handle_status({})

    assert result == {"ok": True, "stats": {"active": 1, "total": 2}}
