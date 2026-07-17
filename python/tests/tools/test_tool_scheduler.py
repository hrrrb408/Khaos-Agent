import asyncio

from khaos.agent.approval import ApprovalBroker
from khaos.db import Database
from khaos.permissions import ApprovalMode, PermissionEngine
from khaos.tools.registry import ToolDefinition, ToolRegistry
from khaos.tools.scheduler import ToolBudget, ToolScheduler
from khaos.security.middleware import SecurityMiddleware
from khaos.security.sandbox import Sandbox, SandboxMode


async def _ok(value: str = "ok") -> str:
    return value


async def _fail() -> str:
    raise RuntimeError("boom")


async def _office_read(path: str, workspace_root=None) -> dict:
    return {"path": path, "workspace_root": workspace_root}


def _registry() -> ToolRegistry:
    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            name="read",
            description="read",
            parameters={"type": "object", "properties": {"value": {"type": "string"}}},
            modes=["all"],
            permission_level="read",
            parallel=True,
            handler=_ok,
        )
    )
    registry.register(
        ToolDefinition(
            name="write",
            description="write",
            parameters={"type": "object", "properties": {"value": {"type": "string"}}},
            modes=["coding"],
            permission_level="write",
            parallel=False,
            handler=_ok,
        )
    )
    registry.register(
        ToolDefinition(
            name="fail",
            description="fail",
            parameters={"type": "object", "properties": {}},
            modes=["coding"],
            permission_level="read",
            parallel=True,
            handler=_fail,
        )
    )
    return registry


def _approval_context() -> dict:
    return {
        "approval_broker": ApprovalBroker(),
        "principal_id": "test-principal",
        "task_id": "test-task",
        "workspace_id": "test-workspace",
        "turn_id": "test-turn",
    }


async def test_scheduler_executes_parallel_and_serial(tmp_path):
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    scheduler = ToolScheduler(
        _registry(),
        PermissionEngine(db, default_mode=ApprovalMode.AUTO_APPROVE),
    )

    results = await scheduler.execute_batch(
        [
            {"id": "1", "name": "read", "arguments": {"value": "a"}},
            {"id": "2", "name": "write", "arguments": {"value": "b"}},
        ],
        mode="coding",
        session_id=None,
    )

    assert [result.success for result in results] == [True, True]
    assert [result.output for result in results] == ["a", "b"]
    assert [result.arguments for result in results] == [
        {"value": "a"},
        {"value": "b"},
    ]
    await db.close()


async def test_office_scheduler_injects_non_model_workspace_root(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path / "outside.txt"
    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            name="read_file",
            description="read",
            parameters={
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
            modes=["office"],
            permission_level="read",
            parallel=True,
            handler=_office_read,
        )
    )
    db = Database(tmp_path / "office.db")
    await db.connect()
    await db.run_migrations()
    scheduler = ToolScheduler(
        registry,
        PermissionEngine(db, default_mode=ApprovalMode.AUTO_APPROVE),
        security_middleware=SecurityMiddleware(
            sandbox=Sandbox(SandboxMode.WORKSPACE_WRITE, workspace)
        ),
    )

    inside = await scheduler.execute_batch(
        [{"id": "1", "name": "read_file", "arguments": {"path": "inside.txt"}}],
        mode="office",
    )
    escaped = await scheduler.execute_batch(
        [{"id": "2", "name": "read_file", "arguments": {"path": str(outside)}}],
        mode="office",
    )

    assert inside[0].success is True
    assert inside[0].output == {
        "path": "inside.txt",
        "workspace_root": workspace,
    }
    assert escaped[0].success is False
    assert "outside workspace" in escaped[0].error
    await db.close()


async def test_scheduler_emits_permission_request_and_denies_without_confirm(tmp_path):
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    await db.create_session("test-session", mode="coding")
    scheduler = ToolScheduler(_registry(), PermissionEngine(db))

    events = [
        event
        async for event in scheduler.stream_batch(
            [{"id": "1", "name": "write", "arguments": {"value": "b"}}],
            mode="coding",
            session_id="test-session",
            tool_context=_approval_context(),
        )
    ]

    assert [event.event for event in events] == ["permission_request", "tool_result"]
    assert events[-1].result is not None
    assert not events[-1].result.success
    await db.close()


async def test_scheduler_confirm_with_remember_creates_rule(tmp_path):
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    await db.create_session("test-session", mode="coding")
    engine = PermissionEngine(db)
    scheduler = ToolScheduler(_registry(), engine)

    results = await scheduler.execute_batch(
        [{"id": "1", "name": "write", "arguments": {"value": "b"}}],
        mode="coding",
        session_id="test-session",
        confirm_callback=lambda request: {"approved": True, "remember": True},
        tool_context=_approval_context(),
    )
    rules = await db.list_permission_rules()

    assert results[0].success
    assert rules[0]["approval"] == "auto-approve"
    await db.close()


async def test_scheduler_consumes_bound_approval_before_dispatch(tmp_path):
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    await db.create_session("test-session", mode="coding")
    broker = ApprovalBroker()
    context = _approval_context()
    context["approval_broker"] = broker
    captured = {}

    def approve(request):
        captured.update(request)
        return {"approved": True, "remember": False}

    scheduler = ToolScheduler(_registry(), PermissionEngine(db))
    results = await scheduler.execute_batch(
        [{"id": "call-1", "name": "write", "arguments": {"value": "b"}}],
        mode="coding",
        session_id="test-session",
        confirm_callback=approve,
        tool_context=context,
    )

    assert results[0].success
    assert captured["principal_id"] == "test-principal"
    assert captured["session_id"] == "test-session"
    assert captured["task_id"] == "test-task"
    assert captured["workspace_id"] == "test-workspace"
    assert len(captured["binding_digest"]) == 64
    assert len(captured["arguments_digest"]) == 64
    assert len(captured["profile_digest"]) == 64
    assert not await broker.resolve(
        "call-1",
        True,
        principal_id="test-principal",
        session_id="test-session",
        binding_digest=captured["binding_digest"],
    )
    await db.close()


async def test_scheduler_denies_when_bound_approval_cannot_be_resolved(tmp_path):
    class RejectingBroker(ApprovalBroker):
        async def consume_for_dispatch(self, *args, **kwargs):
            return {"approved": False, "remember": False}

    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    await db.create_session("test-session", mode="coding")
    context = _approval_context()
    context["approval_broker"] = RejectingBroker()
    scheduler = ToolScheduler(_registry(), PermissionEngine(db))

    results = await scheduler.execute_batch(
        [{"id": "call-1", "name": "write", "arguments": {"value": "b"}}],
        mode="coding",
        session_id="test-session",
        confirm_callback=lambda request: {"approved": True},
        tool_context=context,
    )

    assert not results[0].success
    assert results[0].error == "User denied permission"
    await db.close()


async def test_scheduler_budget_exhaustion_stops_serial_calls(tmp_path):
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    budget = ToolBudget(max_calls=1)
    scheduler = ToolScheduler(
        _registry(),
        PermissionEngine(db, default_mode=ApprovalMode.AUTO_APPROVE),
        budget=budget,
    )

    results = await scheduler.execute_batch(
        [
            {"id": "1", "name": "write", "arguments": {"value": "a"}},
            {"id": "2", "name": "write", "arguments": {"value": "b"}},
        ],
        mode="coding",
    )

    assert results[0].success
    assert results[1].error == "Tool budget exhausted"
    await db.close()


async def test_scheduler_partial_failure_does_not_stop_others(tmp_path):
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    scheduler = ToolScheduler(
        _registry(),
        PermissionEngine(db, default_mode=ApprovalMode.AUTO_APPROVE),
    )

    results = await scheduler.execute_batch(
        [
            {"id": "1", "name": "fail", "arguments": {}},
            {"id": "2", "name": "write", "arguments": {"value": "b"}},
        ],
        mode="coding",
    )

    assert not results[0].success
    assert results[1].success
    await db.close()


async def test_scheduler_timeout_returns_failure(tmp_path):
    async def slow() -> str:
        await asyncio.sleep(0.05)
        return "slow"

    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            name="slow",
            description="slow",
            parameters={"type": "object", "properties": {}},
            modes=["all"],
            permission_level="read",
            parallel=True,
            timeout=0.01,
            handler=slow,
        )
    )
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    scheduler = ToolScheduler(registry, PermissionEngine(db, ApprovalMode.AUTO_APPROVE))

    results = await scheduler.execute_batch(
        [{"id": "1", "name": "slow", "arguments": {}}],
        mode="coding",
    )

    assert not results[0].success
    await db.close()
