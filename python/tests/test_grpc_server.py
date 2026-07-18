import asyncio
import subprocess
import os
import hashlib
import hmac
import json
import time
import uuid
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from khaos.db import Database
from khaos.agent.approval import ApprovalBinding, ApprovalBroker
from khaos.grpc_server import (
    AgentService,
    ChatRequest,
    ConfirmRequest,
    GatewayRPCAuthenticator,
    _load_rpc_capability,
    _parse_json_line,
    load_router_from_config,
    MemoryService,
    serve_json_lines,
    TaskService,
)
from khaos.memory import MemoryStore
from khaos.channels import ChannelType, PlatformMessage, Sender


async def test_agent_service_chat_streams_events(tmp_path):
    (tmp_path / "prompts").mkdir()
    (tmp_path / "prompts" / "office.md").write_text("office prompt", encoding="utf-8")
    (tmp_path / "prompts" / "coding.md").write_text("coding prompt", encoding="utf-8")
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    service = AgentService(db, project_root=tmp_path)

    events = [event async for event in service.chat(ChatRequest("s1", "hello", "office"))]

    assert events[0]["event"] == "message"
    assert events[-1]["event"] == "done"
    await db.close()


async def test_agent_service_switch_and_confirm(tmp_path):
    (tmp_path / "prompts").mkdir()
    (tmp_path / "prompts" / "office.md").write_text("office prompt", encoding="utf-8")
    (tmp_path / "prompts" / "coding.md").write_text("coding prompt", encoding="utf-8")
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    service = AgentService(db, project_root=tmp_path)

    mode = await service.switch_mode("s1", "coding")
    confirmation = await service.confirm_permission(ConfirmRequest("s1", "call_1", True, False))

    assert mode == {"current_mode": "coding"}
    assert confirmation["ok"] is False
    assert "principal/binding" in confirmation["error"]
    await db.close()


async def test_agent_service_starts_and_stops_cron_engine(tmp_path):
    (tmp_path / "prompts").mkdir()
    (tmp_path / "prompts" / "office.md").write_text("office", encoding="utf-8")
    (tmp_path / "prompts" / "coding.md").write_text("coding", encoding="utf-8")
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    service = AgentService(db, project_root=tmp_path)

    await service.start()
    assert service.cron_engine._running is True
    await service.shutdown()
    assert service.cron_engine._running is False
    await db.close()


async def test_agent_service_owns_shared_audit_logger_across_turns(tmp_path):
    """H3: a turn borrows the logger; only server shutdown closes it."""
    (tmp_path / "prompts").mkdir()
    (tmp_path / "prompts" / "office.md").write_text("office", encoding="utf-8")
    (tmp_path / "prompts" / "coding.md").write_text("coding", encoding="utf-8")
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    service = AgentService(db, project_root=tmp_path)
    shared = MagicMock()
    service._audit_logger = shared

    runtime = await service._build_runtime("s1", "office")
    assert runtime.audit_logger is shared
    assert runtime.owns_audit_logger is False
    await runtime.aclose()
    shared.close.assert_not_called()

    await service.shutdown()
    shared.close.assert_called_once()
    await db.close()


async def test_agent_service_chat_quarantines_failed_runtime_close(
    tmp_path, monkeypatch
):
    """H4: production chat teardown registers an orphan before raising."""
    from khaos.exceptions import RuntimeCloseError
    from khaos.runtime.factory import (
        RuntimeResult,
        _orphan_runtimes,
        cleanup_orphan_runtimes,
    )

    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    service = AgentService(db, project_root=tmp_path)
    office = MagicMock()
    office.shutdown = AsyncMock(side_effect=RuntimeError("stuck"))
    loop = MagicMock()

    async def empty_run(*args, **kwargs):
        if False:
            yield None

    loop.run = empty_run
    runtime = RuntimeResult(
        loop=loop,
        mode_manager=MagicMock(),
        task_manager=None,
        skill_generator=None,
        tool_scheduler=MagicMock(),
        memory_manager=MagicMock(aclose=AsyncMock()),
        skill_manager=MagicMock(),
        new_verify_fix_loop=None,
        office_authority=office,
        principal_id="principal",
        session_id="session",
        runtime_id="runtime",
    )

    async def fake_build(*args, **kwargs):
        return runtime

    monkeypatch.setattr(service, "_build_runtime", fake_build)
    try:
        with pytest.raises(RuntimeCloseError):
            [event async for event in service.chat(ChatRequest("s1", "hi", "office"))]
        assert any(item is runtime for item in _orphan_runtimes)
        assert runtime.quarantined is True
    finally:
        office.shutdown = AsyncMock()
        await cleanup_orphan_runtimes()
        await service.shutdown()
        await db.close()


async def test_webhook_session_and_principal_are_channel_bound(tmp_path, monkeypatch):
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    service = AgentService(db, project_root=tmp_path)
    requests = []

    async def fake_chat(request):
        requests.append(request)
        if False:
            yield {}

    monkeypatch.setattr(service, "chat", fake_chat)
    message = PlatformMessage(
        id="event-1",
        channel=ChannelType.TELEGRAM,
        text="hello",
        sender=Sender(id="sender", platform_id="platform-sender"),
        target="target",
    )

    await service._on_webhook_message("channel-a", message)
    await service._on_webhook_message("channel-b", message)

    assert requests[0].session_id != requests[1].session_id
    assert requests[0].session_id.startswith("webhook:channel-a:telegram:")
    assert requests[0].principal_id == (
        "webhook:channel-a:telegram:platform-sender"
    )
    assert requests[1].principal_id == (
        "webhook:channel-b:telegram:platform-sender"
    )
    await db.close()


async def test_task_service_only_approves_or_rejects_blocked_tasks():
    from khaos.coding.task_manager import TaskManager

    manager = TaskManager()
    service = TaskService(manager)
    task = await manager.create("approval")
    not_blocked = await service.approve(task.id)
    await manager.update_status(task.id, "blocked")
    approved = await service.approve(task.id)
    await manager.update_status(task.id, "blocked")
    rejected = await service.reject(task.id)
    assert not not_blocked["ok"]
    assert not approved["ok"]
    assert not rejected["ok"]


async def test_task_approval_is_consumed_before_running_is_observable():
    from khaos.coding.task_manager import TaskManager, TaskStatus

    broker = ApprovalBroker()
    manager = TaskManager()
    task = await manager.create("atomic approval")
    binding = ApprovalBinding(
        principal_id="principal", session_id="session", task_id=task.id,
        turn_id="turn", tool_call_id="tool-call", tool_name="shell",
        arguments_digest="args", workspace_id="workspace",
        profile_digest="profile", expires_at=time.time() + 60,
    )
    binding_digest = await broker.register_tool_approval(binding)
    await manager.update_status(
        task.id, TaskStatus.BLOCKED,
        pending_approval={
            "tool_call_id": binding.tool_call_id,
            "principal_id": binding.principal_id,
            "session_id": binding.session_id,
            "binding_digest": binding_digest,
        },
    )
    service = TaskService(manager, broker)

    approved = await service.approve(
        task.id, principal_id="principal", session_id="session",
        binding_digest=binding_digest,
    )

    assert approved["ok"] is True
    approved_task = await manager.get(task.id)
    assert approved_task.status is TaskStatus.RUNNING
    evidence = approved_task.metadata["approval_consumption"]
    assert evidence["tool_call_id"] == "tool-call"
    assert evidence["binding_digest"] == binding_digest
    assert evidence["principal_id"] == "principal"
    assert evidence["session_id"] == "session"
    assert evidence["decision"] == "approved"
    assert evidence["consumed_at"] <= time.time()
    record = broker._tool_approvals[binding.tool_call_id]
    assert record.used and record.dispatched
    replay = await service.approve(
        task.id, principal_id="principal", session_id="session",
        binding_digest=binding_digest,
    )
    assert replay["ok"] is False


async def test_stale_task_approval_never_publishes_running_state():
    from khaos.coding.task_manager import TaskManager, TaskStatus

    broker = ApprovalBroker()
    manager = TaskManager()
    task = await manager.create("stale approval")
    await manager.update_status(
        task.id, TaskStatus.BLOCKED,
        pending_approval={
            "tool_call_id": "missing", "principal_id": "principal",
            "session_id": "session", "binding_digest": "digest",
        },
    )
    response = await TaskService(manager, broker).approve(
        task.id, principal_id="principal", session_id="session",
        binding_digest="digest",
    )

    assert response["ok"] is False
    assert (await manager.get(task.id)).status is TaskStatus.BLOCKED


async def test_agent_service_permission_waits_for_confirm(tmp_path):
    project = tmp_path / "project"
    (project / "prompts").mkdir(parents=True)
    (project / "prompts" / "office.md").write_text("office prompt", encoding="utf-8")
    (project / "prompts" / "coding.md").write_text("coding prompt", encoding="utf-8")
    subprocess.run(["git", "init", "-q"], cwd=project, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=project, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=project, check=True)
    subprocess.run(["git", "add", "."], cwd=project, check=True)
    subprocess.run(["git", "commit", "-qm", "base"], cwd=project, check=True)
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    service = AgentService(db, project_root=project)
    target = "agent.txt"

    stream = service.chat(ChatRequest("s1", f"/tool write_file {target} hello", "coding"))
    first = await stream.__anext__()
    second = await stream.__anext__()
    assert first["event"] == "tool_call"
    assert second["event"] == "permission_request"

    confirmation = await service.confirm_permission(
        ConfirmRequest(
            "s1",
            second["data"]["id"],
            True,
            False,
            principal_id=f"local-uid:{os.getuid()}",
            binding_digest=second["data"]["binding_digest"],
        )
    )
    assert confirmation == {"ok": True}
    events = [event async for event in stream]

    assert any(event["event"] == "tool_result" and event["data"]["success"] for event in events)
    task = next(iter(service.task_manager._tasks.values()))
    target_path = task.metadata["worktree_path"]
    from pathlib import Path
    assert (Path(target_path) / target).read_text(encoding="utf-8") == "hello"
    assert not (project / target).exists()
    await db.close()


async def test_agent_service_shutdown_waits_for_active_chat_runtime(
    tmp_path, monkeypatch
):
    """H3: shared authorities cannot close ahead of an active Chat runtime."""
    from unittest.mock import AsyncMock, MagicMock
    from khaos.runtime.factory import RuntimeResult

    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    service = AgentService(db, project_root=tmp_path)
    service.cron_engine.stop = AsyncMock()
    started = asyncio.Event()
    never = asyncio.Event()

    class BlockingLoop:
        async def run(self, message, session_id):
            del message, session_id
            started.set()
            await never.wait()
            if False:
                yield None

    memory = MagicMock(aclose=AsyncMock())
    runtime = RuntimeResult(
        loop=BlockingLoop(), mode_manager=MagicMock(), task_manager=None,
        skill_generator=None, tool_scheduler=MagicMock(),
        memory_manager=memory, skill_manager=MagicMock(),
        new_verify_fix_loop=None, owns_office_authority=False,
    )
    monkeypatch.setattr(
        service, "_build_runtime", AsyncMock(return_value=runtime)
    )

    async def consume():
        async for _ in service.chat(ChatRequest("active", "wait", "office")):
            pass

    chat_task = asyncio.create_task(consume())
    await asyncio.wait_for(started.wait(), timeout=5.0)
    await service.shutdown()

    assert chat_task.done()
    assert runtime._closed is True
    memory.aclose.assert_awaited()
    assert not service._active_runtimes
    await db.close()


async def test_agent_service_shutdown_keeps_audit_open_when_office_fails(
    tmp_path,
):
    """H5: an unterminated shared mutation authority blocks later teardown."""
    from unittest.mock import AsyncMock, MagicMock
    from khaos.exceptions import ServiceShutdownError

    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    service = AgentService(db, project_root=tmp_path)
    service.cron_engine.stop = AsyncMock()
    service._office_authority = MagicMock()
    service._office_authority.shutdown = AsyncMock(
        side_effect=RuntimeError("worker still active")
    )
    service._audit_logger = MagicMock()

    with pytest.raises(ServiceShutdownError):
        await service.shutdown()
    assert service.shutdown_failed is True
    assert service._office_authority.shutdown.await_count == 3
    service._audit_logger.close.assert_not_called()
    await db.close()


@pytest.mark.skipif(os.name == "nt", reason="Unix server lifecycle requires UDS")
async def test_json_line_server_shutdown_closes_active_chat_before_database(
    tmp_path, monkeypatch
):
    """H3: cancelling the real Server waits for Chat Runtime finalization."""
    from unittest.mock import AsyncMock, MagicMock
    from khaos.runtime.factory import RuntimeResult

    started = asyncio.Event()
    never = asyncio.Event()
    database_closed = asyncio.Event()
    runtimes = []
    original_close = Database.close

    async def tracked_close(database):
        await original_close(database)
        database_closed.set()

    monkeypatch.setattr(Database, "close", tracked_close)

    class BlockingLoop:
        async def run(self, message, session_id):
            del message, session_id
            started.set()
            await never.wait()
            if False:
                yield None

    async def fake_build(self, *args, **kwargs):
        del self, args, kwargs
        runtime = RuntimeResult(
            loop=BlockingLoop(), mode_manager=MagicMock(), task_manager=None,
            skill_generator=None, tool_scheduler=MagicMock(),
            memory_manager=MagicMock(aclose=AsyncMock()),
            skill_manager=MagicMock(), new_verify_fix_loop=None,
            owns_office_authority=False,
        )
        runtimes.append(runtime)
        return runtime

    monkeypatch.setattr(AgentService, "_build_runtime", fake_build)
    socket_parent = Path("/tmp") / f"kshutdown-{uuid.uuid4().hex[:10]}"
    socket_parent.mkdir(mode=0o700)
    socket_path = socket_parent / "agent.sock"
    server_task = asyncio.create_task(
        serve_json_lines(
            str(socket_path), str(tmp_path / "server.db"),
            project_root=tmp_path, gateway_capability="c" * 48,
        )
    )
    for _ in range(200):
        if socket_path.exists() or server_task.done():
            break
        await asyncio.sleep(0.01)
    if server_task.done():
        try:
            await server_task
        except (PermissionError, OSError) as exc:
            socket_parent.rmdir()
            pytest.skip(f"sandbox does not allow lifecycle UDS: {exc}")
    try:
        reader, writer = await asyncio.open_unix_connection(str(socket_path))
    except (PermissionError, OSError) as exc:
        server_task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await server_task
        pytest.skip(f"sandbox does not allow lifecycle UDS: {exc}")
    request = _signed_rpc_request(
        "AgentService.Chat",
        {"session_id": "active", "message": "wait", "mode": "office"},
    )
    writer.write((json.dumps(request) + "\n").encode("utf-8"))
    await writer.drain()
    await asyncio.wait_for(started.wait(), timeout=5.0)
    server_task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(server_task, timeout=10.0)
    writer.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
    except (asyncio.TimeoutError, ConnectionError, OSError):
        pass
    assert runtimes and all(runtime._closed for runtime in runtimes)
    assert database_closed.is_set()
    assert not socket_path.exists()
    socket_parent.rmdir()


@pytest.mark.skipif(os.name == "nt", reason="Unix server lifecycle requires UDS")
async def test_json_line_server_shutdown_cancels_detached_subagent_before_db(
    tmp_path, monkeypatch
):
    """H1: cancelling the real server tears down detached SubAgent tasks.

    ``SubAgentService.Spawn`` returns ``running`` while the Spawner runs the
    task on a detached background ``asyncio.Task``.  Previously the server's
    shutdown sequence cancelled connection handlers and chat tasks but
    never the detached subagent tasks — so Office / Browser / Audit / DB
    could be dismantled under a live run.  This test pins the contract that
    shutdown drains the spawner BEFORE the database closes.
    """
    import khaos.grpc_server as grpc_module
    from khaos.subagents.service import SubAgentService
    from khaos.subagents.spawner import SubAgentConfig, SubAgentSpawner, SubAgentTask

    captured_spawners: list[SubAgentSpawner] = []
    release = asyncio.Event()

    async def blocking_runner(task: SubAgentTask) -> str:
        await release.wait()
        return "should-not-reach"

    async def fake_build_subagent_service(db, project_root, config_path, **kwargs):
        # Bypass the full runner wiring — we only need a real Spawner so we
        # can assert shutdown authority over its detached task.
        spawner = SubAgentSpawner(
            SubAgentConfig(), db, runner=blocking_runner,
        )
        captured_spawners.append(spawner)
        return SubAgentService(spawner, runner=None)

    monkeypatch.setattr(
        grpc_module, "_build_subagent_service", fake_build_subagent_service
    )

    socket_parent = Path("/tmp") / f"ksubagent-{uuid.uuid4().hex[:10]}"
    socket_parent.mkdir(mode=0o700)
    socket_path = socket_parent / "agent.sock"
    server_task = asyncio.create_task(
        serve_json_lines(
            str(socket_path), str(tmp_path / "server.db"),
            project_root=tmp_path, gateway_capability="c" * 48,
            enable_subagents=True,
        )
    )
    for _ in range(200):
        if socket_path.exists() or server_task.done():
            break
        await asyncio.sleep(0.01)
    if server_task.done():
        try:
            await server_task
        except (PermissionError, OSError) as exc:
            socket_parent.rmdir()
            pytest.skip(f"sandbox does not allow lifecycle UDS: {exc}")
    try:
        reader, writer = await asyncio.open_unix_connection(str(socket_path))
    except (PermissionError, OSError) as exc:
        server_task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await server_task
        socket_parent.rmdir()
        pytest.skip(f"sandbox does not allow lifecycle UDS: {exc}")

    try:
        request = _signed_rpc_request(
            "SubAgentService.Spawn",
            {"goal": "block", "context": "", "tools": [], "principal_id": "gateway"},
        )
        writer.write((json.dumps(request) + "\n").encode("utf-8"))
        await writer.drain()
        # Wait for the spawn RPC reply AND the detached task to register.
        line = await asyncio.wait_for(reader.readline(), timeout=5.0)
        reply = json.loads(line.decode("utf-8"))
        assert reply["ok"] is True, reply
        assert captured_spawners, "subagent service was never built"
        spawner = captured_spawners[0]
        for _ in range(200):
            if spawner._active_tasks:
                break
            await asyncio.sleep(0.01)
        assert spawner._active_tasks, "detached task never registered"

        # Cancel the server.  Its finally-block must shut the spawner down
        # (cancelling + awaiting the detached task) before the DB closes.
        server_task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(server_task, timeout=15.0)
    finally:
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
        except (asyncio.TimeoutError, ConnectionError, OSError):
            pass
        release.set()
        try:
            socket_parent.rmdir()
        except OSError:
            pass

    # The detached task must have been drained; the spawner is closed.
    assert spawner._active_tasks == {}
    assert spawner._shutting_down is True
    assert not socket_path.exists()


@pytest.mark.skipif(os.name == "nt", reason="Unix server lifecycle requires UDS")
async def test_agent_shutdown_does_not_block_on_wedged_chat(tmp_path, monkeypatch):
    """M2: a slow chat task cannot wedge server teardown indefinitely.

    A chat task that blocks past the cancellation deadline used to make
    ``AgentService.shutdown`` hang on ``asyncio.gather`` forever.  The
    bounded drain deadline (``CHAT_DRAIN_TIMEOUT``) lets shutdown return
    within a predictable ceiling; the residual runtime close / orphan
    quarantine path is the real terminal gate.

    Note: the chat generator below honours cancellation (the test must be
    deterministic across Python versions).  What it pins is that
    ``shutdown`` itself observes the deadline even when the chat task is
    mid-iteration, not the chat task's cancellation behaviour.
    """
    from khaos.runtime.factory import RuntimeResult
    from khaos.grpc_server import CHAT_DRAIN_TIMEOUT

    started = asyncio.Event()
    release = asyncio.Event()

    class SlowLoop:
        async def run(self, message, session_id):
            del message, session_id
            started.set()
            # Block until the test releases us; cancellation propagates
            # normally through ``Event.wait``.
            await release.wait()
            if False:
                yield None

    async def fake_build(self, *args, **kwargs):
        del self, args, kwargs
        return RuntimeResult(
            loop=SlowLoop(), mode_manager=MagicMock(), task_manager=None,
            skill_generator=None, tool_scheduler=MagicMock(),
            memory_manager=MagicMock(aclose=AsyncMock()),
            skill_manager=MagicMock(), new_verify_fix_loop=None,
            owns_office_authority=False,
        )

    monkeypatch.setattr(AgentService, "_build_runtime", fake_build)

    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    service = AgentService(db, project_root=tmp_path)
    await service.start()

    chat_task = asyncio.create_task(_drain_chat(service))
    # Make sure the chat task is actually inside its runtime before we
    # tear the service down — otherwise the test exercises nothing.
    await asyncio.wait_for(started.wait(), timeout=2.0)

    loop = asyncio.get_running_loop()
    start = loop.time()
    # Temporarily shrink the ceiling so the test doesn't wait the full
    # production 10s.  ``shutdown`` reads CHAT_DRAIN_TIMEOUT at call time
    # from the module attribute, so monkeypatching it inline is enough.
    monkeypatch.setattr(
        "khaos.grpc_server.CHAT_DRAIN_TIMEOUT", 0.5
    )
    try:
        await asyncio.wait_for(service.shutdown(), timeout=5.0)
    except asyncio.TimeoutError:
        pytest.fail("AgentService.shutdown hung past its drain deadline")
    elapsed = loop.time() - start
    # shutdown returned within the (monkeypatched) ceiling + slack for
    # the subsequent runtime close / orphan drain.  Must not hang.
    assert elapsed < 4.0
    release.set()
    # The chat task was cancelled during shutdown; let it finish cleanly.
    try:
        await asyncio.wait_for(chat_task, timeout=2.0)
    except (asyncio.TimeoutError, asyncio.CancelledError):
        pass
    await db.close()


async def _drain_chat(service: AgentService) -> None:
    """Consume the chat event stream so the runtime actually starts."""
    request = ChatRequest(session_id="wedged", message="x", mode="office")
    async for _event in service.chat(request):
        pass


async def test_memory_service_crud_search(tmp_path):
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    service = MemoryService(MemoryStore(db))

    stored = await service.set_memory("global", "user", "Ruibang likes tests")
    memory = await service.get_memory("global", "user")
    results = await service.search_memory("tests")
    deleted = await service.delete_memory(stored["id"])

    assert stored["ok"]
    assert memory["value"] == "Ruibang likes tests"
    assert results[0]["key"] == "user"
    assert deleted == {"ok": True}
    await db.close()


@pytest.mark.skipif(os.name == "nt", reason="Unix peer credentials require a UDS")
async def test_json_line_server_authenticates_real_peer_credentials(tmp_path):
    (tmp_path / "prompts").mkdir()
    (tmp_path / "prompts" / "office.md").write_text("office prompt", encoding="utf-8")
    (tmp_path / "prompts" / "coding.md").write_text("coding prompt", encoding="utf-8")
    import asyncio

    socket_parent = Path("/tmp") / f"krpc-{uuid.uuid4().hex[:12]}"
    socket_parent.mkdir(mode=0o700)
    socket_path = socket_parent / "agent.sock"
    task = asyncio.create_task(
        serve_json_lines(
            str(socket_path), str(tmp_path / "khaos.db"),
            project_root=tmp_path, gateway_capability="c" * 48,
        )
    )
    for _ in range(100):
        if socket_path.exists() or task.done():
            break
        await asyncio.sleep(0.01)
    try:
        if task.done():
            await task
        reader, writer = await asyncio.open_unix_connection(str(socket_path))
        request = _signed_rpc_request("ChannelService.List", {})
        writer.write((json.dumps(request) + "\n").encode("utf-8"))
        await writer.drain()
        response = json.loads((await reader.readline()).decode("utf-8"))
        assert isinstance(response, dict)
        assert isinstance(response.get("channels"), list)
        assert all("id" in channel for channel in response["channels"])
        writer.close()
        await writer.wait_closed()
    except (PermissionError, OSError) as exc:
        pytest.skip(f"sandbox does not allow a peer-credential UDS: {exc}")
    finally:
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, OSError, PermissionError):
            pass
        if socket_parent.exists():
            socket_parent.rmdir()


def _signed_rpc_request(method: str, payload: dict, *, nonce: str = "n" * 32):
    capability = "c" * 48
    issued_at = int(time.time())
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")
    digest = hashlib.sha256(canonical).hexdigest()
    principal = str(payload.get("principal_id") or "gateway")
    signed = f"{method}\n{nonce}\n{issued_at}\n{principal}\n{digest}".encode()
    method_key = hmac.new(
        capability.encode(),
        f"khaos-rpc-method-v1\n{method}".encode(),
        hashlib.sha256,
    ).digest()
    return {
        "method": method, "payload": payload,
        "auth": {
            "nonce": nonce, "issued_at": issued_at,
            "principal_id": principal, "payload_digest": digest,
            "mac": hmac.new(method_key, signed, hashlib.sha256).hexdigest(),
        },
    }


def test_rpc_capability_is_method_payload_principal_and_nonce_bound():
    authenticator = GatewayRPCAuthenticator("c" * 48)
    request = _signed_rpc_request(
        "TaskService.Approve", {"task_id": "task", "principal_id": "user"}
    )
    assert authenticator.authenticate(request) == "user"
    with pytest.raises(PermissionError, match="replayed"):
        authenticator.authenticate(request)

    tampered = _signed_rpc_request(
        "TaskService.Approve", {"task_id": "other", "principal_id": "user"},
        nonce="x" * 32,
    )
    tampered["payload"]["task_id"] = "attacker"
    with pytest.raises(PermissionError, match="payload digest"):
        authenticator.authenticate(tampered)

    wrong_method = _signed_rpc_request(
        "TaskService.Approve", {"task_id": "task", "principal_id": "user"},
        nonce="y" * 32,
    )
    wrong_method["method"] = "MemoryService.SetMemory"
    with pytest.raises(PermissionError, match="method capability"):
        authenticator.authenticate(wrong_method)


def test_rpc_authentication_binds_first_valid_gateway_pid():
    authenticator = GatewayRPCAuthenticator("c" * 48)
    first = _signed_rpc_request("TaskService.List", {}, nonce="p" * 32)
    assert authenticator.authenticate(first, peer_pid=1001) == "gateway"
    second = _signed_rpc_request("TaskService.List", {}, nonce="q" * 32)
    with pytest.raises(PermissionError, match="bound Gateway"):
        authenticator.authenticate(second, peer_pid=1002)


def test_rpc_capability_loads_protected_file_and_rejects_default_env(tmp_path, monkeypatch):
    capability_file = tmp_path / "rpc-capability"
    capability_file.write_text("0123456789abcdef0123456789abcdef\n", encoding="utf-8")
    capability_file.chmod(0o600)
    monkeypatch.setenv("KHAOS_PYTHON_CAPABILITY_FILE", str(capability_file))
    monkeypatch.setenv("KHAOS_PYTHON_CAPABILITY", "e" * 48)
    monkeypatch.delenv("KHAOS_ALLOW_LEGACY_CAPABILITY_ENV", raising=False)
    assert _load_rpc_capability() == "0123456789abcdef0123456789abcdef"

    monkeypatch.delenv("KHAOS_PYTHON_CAPABILITY_FILE")
    with pytest.raises(PermissionError, match="inherited value or protected"):
        _load_rpc_capability()


def test_rpc_capability_rejects_symlink(tmp_path, monkeypatch):
    capability_file = tmp_path / "rpc-capability"
    capability_file.write_text("c" * 48, encoding="utf-8")
    capability_file.chmod(0o600)
    capability_link = tmp_path / "rpc-capability-link"
    capability_link.symlink_to(capability_file)
    monkeypatch.setenv("KHAOS_PYTHON_CAPABILITY_FILE", str(capability_link))

    with pytest.raises(PermissionError, match="must not be a symlink"):
        _load_rpc_capability()


def test_parse_json_line_accepts_object_request():
    request = _parse_json_line(b'{"method":"AgentService.Chat","payload":{}}\n')

    assert request["method"] == "AgentService.Chat"
    assert request["payload"] == {}


def test_parse_json_line_rejects_malformed_payload():
    with pytest.raises(ValueError, match="JSON object line"):
        _parse_json_line(b"\n")


def test_parse_json_line_rejects_non_object_payload():
    with pytest.raises(ValueError, match="JSON object"):
        _parse_json_line(b"[]\n")


async def test_load_router_from_nvidia_config(tmp_path, monkeypatch):
    monkeypatch.setenv("NVIDIA_API_KEY", "secret")
    config = tmp_path / "config.yaml"
    config.write_text(
        """
models:
  providers:
    nvidia:
      type: openai_compatible
      base_url: "https://integrate.api.nvidia.com/v1"
      api_key: "${NVIDIA_API_KEY}"
      models:
        - name: "qwen/qwen3-8b"
          max_context_tokens: 32768
          supports_tools: true
          supports_vision: false
  default_model: "qwen/qwen3-8b"
  router:
    type: single
""",
        encoding="utf-8",
    )

    router = load_router_from_config(config)
    model = await router.resolve_model("agent_loop")
    provider = router.provider_manager.get_provider("nvidia")

    assert model.model == "qwen/qwen3-8b"
    assert provider.api_key == "secret"


async def test_load_router_from_project_config_merges_user_config(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    project_config = tmp_path / "config.yaml"
    project_config.write_text(
        """
models:
  providers:
    nvidia:
      type: openai_compatible
      base_url: "https://integrate.api.nvidia.com/v1"
      api_key: "${NVIDIA_API_KEY}"
      models:
        - name: "qwen/qwen3-8b"
          max_context_tokens: 32768
          supports_tools: true
          supports_vision: false
  default_model: "qwen/qwen3-8b"
  router:
    type: single
""",
        encoding="utf-8",
    )
    user_config = tmp_path / ".khaos" / "config.yaml"
    user_config.parent.mkdir()
    user_config.write_text(
        """
models:
  providers:
    nvidia:
      api_key: "user-config-key-123"
""",
        encoding="utf-8",
    )

    router = load_router_from_config(project_config, project_root=tmp_path)
    provider = router.provider_manager.get_provider("nvidia")

    assert provider.api_key == "user-config-key-123"


async def test_build_runtime_wires_token_engine_and_skills(tmp_path):
    """_build_runtime must assemble a working token engine and (if present)
    a skill_manager. The token engine is Rust when available, else the pure-
    Python fallback; either way it must count tokens."""
    (tmp_path / "prompts").mkdir()
    (tmp_path / "prompts" / "office.md").write_text("office", encoding="utf-8")
    (tmp_path / "prompts" / "coding.md").write_text("coding", encoding="utf-8")
    # Plant a skill on disk so the manager picks it up.
    skills_dir = tmp_path / "skills"
    skills_dir.mkdir()
    (skills_dir / "SKILL.md").write_text(
        "---\nname: py\ndescription: python.\ntriggers: [python]\n---\nuse type hints\n",
        encoding="utf-8",
    )
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    service = AgentService(db, project_root=tmp_path)

    # B1: ``_build_runtime`` now returns the full ``RuntimeResult``; the
    # caller owns it and must close it.  The loop is the same instance
    # carried by the result.
    runtime = await service._build_runtime("s1", "office")
    loop = runtime.loop

    try:
        # Token engine works for ASCII text either way.
        assert loop.token_engine.count_tokens("hello world") == 2
        # Skill was loaded and matched the planted trigger.
        assert loop.skill_manager is not None
        matched = loop.skill_manager.match("office", "help with python")
        assert any(s.name == "py" for s in matched)
    finally:
        await runtime.aclose()
    await db.close()


async def test_audit_service_query_roundtrip(tmp_path):
    """The JSON-line AuditService.Query returns persisted records."""
    from khaos.audit import AuditLogger
    from khaos.grpc_server import AuditService

    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    logger = AuditLogger(db)
    service = AuditService(logger)

    await logger.log("write_file", "/tmp/x", "success", {"size": 1})
    entries = await service.query(limit=10)

    assert len(entries) == 1
    assert entries[0]["action"] == "write_file"
    assert entries[0]["result"] == "success"
    await db.close()
    GatewayRPCAuthenticator,
