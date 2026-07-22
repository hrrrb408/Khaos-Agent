"""M4 batch 3.1.16A-4-2 acceptance tests.

Verifies that service bodies actually consume ``ctx.principal_id``
(not just accept it as a parameter).  A-4-1 was a wiring change
(every method takes ``ctx``); A-4-2 makes the methods USE ``ctx`` for
principal-scoped DB queries / owner stamping / cross-principal
hiding.

Coverage:

1. ``MemoryService`` — per-request ``MemoryStore`` scoped to
   ``ctx.principal_id``.  Cross-principal reads/writes/deletes are
   blocked.  Project-shared memories (``namespace='shared'``) remain
   visible to every principal.
2. ``AuditService.query`` — scoped to ``ctx.principal_id``.  An API
   principal cannot read another principal's (or ``local-uid``'s)
   audit trail.
3. ``SubAgentService`` — cross-principal ``collect`` / ``status``
   return nothing; payload-forged ``principal_id`` does not win.
4. ``TaskService`` — cross-principal ``list`` / ``get`` / ``cancel`` /
   ``artifacts`` / ``events`` hide the task's existence; ``create``
   fails closed when the manager is bound to a different principal;
   ``approve`` / ``reject`` reject a payload ``principal_id`` that
   disagrees with ``ctx.principal_id``.
"""

from __future__ import annotations

import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from khaos.agent.approval import ApprovalBinding, ApprovalBroker
from khaos.audit import AuditLogger
from khaos.coding.task_manager import TaskManager, TaskStatus
from khaos.db import Database
from khaos.grpc_server import (
    AuditService,
    MemoryService,
    TaskService,
)
from khaos.runtime import RequestContext


def _ctx(principal_id: str) -> RequestContext:
    """Build a RequestContext for A-4-2 acceptance tests."""
    return RequestContext.for_rpc(principal_id)


# ---------------------------------------------------------------------------
# MemoryService — per-request MemoryStore scoped to ctx.principal_id
# ---------------------------------------------------------------------------


async def test_memory_service_private_memory_is_principal_scoped(tmp_path):
    """Principal A's private memory is invisible to Principal B."""
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    service = MemoryService(db)

    # Principal A writes a private memory.
    await service.set_memory(_ctx("api:alice"), "coding", "secret", "alice-secret")

    # Principal A can read it.
    alice_read = await service.get_memory(_ctx("api:alice"), "coding", "secret")
    assert alice_read["value"] == "alice-secret"

    # Principal B cannot read it — KeyError because MemoryStore.get returns None.
    with pytest.raises(KeyError):
        await service.get_memory(_ctx("api:bob"), "coding", "secret")

    await db.close()


async def test_memory_service_delete_is_principal_scoped(tmp_path):
    """Principal B's delete attempt on Principal A's memory is a no-op.

    The DELETE is scoped to ``ctx.principal_id`` — Principal B's delete
    affects 0 rows (Principal A's memory has a different principal_id).
    The service returns ``{"ok": True}`` either way (no existence leak).
    """
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    service = MemoryService(db)

    set_result = await service.set_memory(
        _ctx("api:alice"), "coding", "secret", "alice-secret",
    )
    memory_id = set_result["id"]

    # Principal B attempts to delete Principal A's memory.
    bob_delete = await service.delete_memory(_ctx("api:bob"), memory_id)
    assert bob_delete == {"ok": True}

    # Principal A's memory is still readable.
    alice_read = await service.get_memory(_ctx("api:alice"), "coding", "secret")
    assert alice_read["value"] == "alice-secret"

    # Principal A deletes their own memory.
    alice_delete = await service.delete_memory(_ctx("api:alice"), memory_id)
    assert alice_delete == {"ok": True}

    # Now the memory is gone.
    with pytest.raises(KeyError):
        await service.get_memory(_ctx("api:alice"), "coding", "secret")

    await db.close()


async def test_memory_service_search_is_principal_scoped(tmp_path):
    """Principal A's private memories do not appear in Principal B's search."""
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    service = MemoryService(db)

    await service.set_memory(
        _ctx("api:alice"), "coding", "hobby", "alice likes cryptography",
    )

    alice_results = await service.search_memory(_ctx("api:alice"), "cryptography")
    assert any("alice" in r["value"] for r in alice_results)

    bob_results = await service.search_memory(_ctx("api:bob"), "cryptography")
    assert not any("alice" in r["value"] for r in bob_results)

    await db.close()


# ---------------------------------------------------------------------------
# AuditService.query — scoped to ctx.principal_id
# ---------------------------------------------------------------------------


async def test_audit_service_query_is_principal_scoped(tmp_path):
    """An API principal cannot read another principal's audit trail.

    The server-level ``AuditLogger`` writes events under whatever
    principal it was constructed with (typically ``local-uid``).
    ``AuditService.query`` scopes the query to ``ctx.principal_id`` so
    an API principal sees only their own events.
    """
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()

    # Server-level logger bound to "local-uid:501" (the local user).
    server_logger = AuditLogger(db, principal_id="local-uid:501")
    await server_logger.log(action="tool.call", target="shell", result="success")
    await server_logger.log(action="file.write", target="/tmp/x", result="success")

    # API principal's logger.
    api_logger = AuditLogger(db, principal_id="api:alice")
    await api_logger.log(action="memory.set", target="memories", result="success")

    service = AuditService(server_logger)

    # Local user sees their 2 events.
    local_entries = await service.query(_ctx("local-uid:501"))
    assert len(local_entries) == 2
    assert all(e["principal_id"] == "local-uid:501" for e in local_entries)

    # API principal sees only their 1 event — not the local user's.
    api_entries = await service.query(_ctx("api:alice"))
    assert len(api_entries) == 1
    assert api_entries[0]["action"] == "memory.set"
    assert api_entries[0]["principal_id"] == "api:alice"

    # A different API principal sees nothing.
    bob_entries = await service.query(_ctx("api:bob"))
    assert len(bob_entries) == 0

    await db.close()


# ---------------------------------------------------------------------------
# SubAgentService — cross-principal collect / status return nothing
# ---------------------------------------------------------------------------


async def test_subagent_collect_is_principal_scoped():
    """Principal B's collect returns 0 tasks even if Principal A has active tasks."""
    spawner = MagicMock()
    # When Principal A collects, the spawner returns 1 task.
    # When Principal B collects, the spawner returns 0 tasks (because
    # the spawner filters by principal_id — this is the B1 contract).
    spawner.wait_all = AsyncMock(
        side_effect=lambda *, principal_id, **_: (
            [
                SimpleNamespace(
                    id="task_a", goal="alice-goal", status="completed",
                    result="done", error=None,
                )
            ]
            if principal_id == "api:alice"
            else []
        ),
    )
    from khaos.subagents.service import SubAgentService
    service = SubAgentService(spawner, runner=None)

    alice_result = await service.handle_collect(_ctx("api:alice"), {})
    assert alice_result["ok"] is True
    assert alice_result["total"] == 1
    assert alice_result["results"][0]["task_id"] == "task_a"

    bob_result = await service.handle_collect(_ctx("api:bob"), {})
    assert bob_result["ok"] is True
    assert bob_result["total"] == 0
    assert bob_result["results"] == []

    # Verify the spawner received the correct principal_id filter.
    assert spawner.wait_all.call_args_list[0].kwargs["principal_id"] == "api:alice"
    assert spawner.wait_all.call_args_list[1].kwargs["principal_id"] == "api:bob"


async def test_subagent_status_is_principal_scoped():
    """Principal B's status counts only Principal B's tasks."""
    spawner = MagicMock()
    spawner.stats = MagicMock(
        side_effect=lambda *, principal_id: (
            {"active": 1, "total": 1} if principal_id == "api:alice" else {"active": 0, "total": 0}
        )
    )
    from khaos.subagents.service import SubAgentService
    service = SubAgentService(spawner, runner=None)

    alice_status = await service.handle_status(_ctx("api:alice"), {})
    assert alice_status["stats"]["active"] == 1

    bob_status = await service.handle_status(_ctx("api:bob"), {})
    assert bob_status["stats"]["active"] == 0


async def test_subagent_spawn_stamps_ctx_principal_not_payload():
    """A compromised Gateway that sends ``principal_id: 'admin'`` in the
    payload MUST NOT win — the task is stamped with ``ctx.principal_id``.
    """
    spawner = MagicMock()
    spawner.spawn = AsyncMock(
        return_value=SimpleNamespace(id="task_1", status="running")
    )
    from khaos.subagents.service import SubAgentService
    service = SubAgentService(spawner, runner=None)

    result = await service.handle_spawn(
        _ctx("api:alice"),
        {"principal_id": "admin", "goal": "inspect"},  # forged payload
    )
    assert result["ok"] is True
    task = spawner.spawn.call_args.args[0]
    assert task.principal_id == "api:alice"  # ctx won, not payload
    assert task.parent_session_id == "subagent:api:alice"


# ---------------------------------------------------------------------------
# TaskService — cross-principal hiding + create fail-closed + approve forgery
# ---------------------------------------------------------------------------


async def _make_db_with_alice_task(tmp_path) -> tuple[Database, str]:
    """Async helper: build a real DB with one task owned by ``api:alice``.

    C-1-5a: TaskService now takes ``db`` (not a TaskManager) and
    constructs per-principal managers on demand.  Tests must use a
    real DB so the per-principal manager can ``load()`` the task.
    """
    db = Database(tmp_path / "task-service-test.db")
    await db.connect()
    await db.run_migrations()
    manager = TaskManager(db=db, principal_id="api:alice")
    await manager.load()
    task = await manager.create("alice-task")
    await db.close()
    return db, task.id


async def test_task_service_list_is_principal_scoped(tmp_path):
    """Principal B's list returns 0 tasks even if Principal A has tasks."""
    db, _ = await _make_db_with_alice_task(tmp_path)
    await db.connect()
    service = TaskService(db)

    alice_tasks = await service.list(_ctx("api:alice"))
    assert len(alice_tasks) == 1
    assert alice_tasks[0]["goal"] == "alice-task"

    bob_tasks = await service.list(_ctx("api:bob"))
    assert bob_tasks == []

    bob_active = await service.list(_ctx("api:bob"), active_only=True)
    assert bob_active == []
    await db.close()


async def test_task_service_get_hides_cross_principal_task(tmp_path):
    """Principal B's get on Principal A's task returns ``not found``.

    Existence is hidden — Principal B cannot enumerate another
    principal's task ids by probing.
    """
    db, task_id = await _make_db_with_alice_task(tmp_path)
    await db.connect()
    service = TaskService(db)

    alice_get = await service.get(_ctx("api:alice"), task_id)
    assert alice_get["goal"] == "alice-task"

    bob_get = await service.get(_ctx("api:bob"), task_id)
    assert bob_get["error"] == "task not found"
    assert bob_get["task_id"] == task_id
    await db.close()


async def test_task_service_cancel_hides_cross_principal_task(tmp_path):
    """Principal B cannot cancel Principal A's task — returns ``not found``."""
    db, task_id = await _make_db_with_alice_task(tmp_path)
    await db.connect()
    service = TaskService(db)

    bob_cancel = await service.cancel(_ctx("api:bob"), task_id)
    assert bob_cancel["ok"] is False
    assert bob_cancel["error"] == "task not found"

    # Principal A can still cancel their own task.
    alice_cancel = await service.cancel(_ctx("api:alice"), task_id)
    assert alice_cancel["ok"] is True
    await db.close()


async def test_task_service_artifacts_hides_cross_principal_task(tmp_path):
    """Principal B's artifacts on Principal A's task returns ``[]``."""
    db, task_id = await _make_db_with_alice_task(tmp_path)
    await db.connect()
    # Modify the task to have some artifacts (via a per-principal manager).
    manager = TaskManager(db=db, principal_id="api:alice")
    await manager.load()
    await manager.track_file_modified(task_id, "/tmp/alice-file.txt")
    service = TaskService(db)

    alice_artifacts = await service.artifacts(_ctx("api:alice"), task_id)
    assert any(a["path"] == "/tmp/alice-file.txt" for a in alice_artifacts)

    bob_artifacts = await service.artifacts(_ctx("api:bob"), task_id)
    assert bob_artifacts == []
    await db.close()


async def test_task_service_events_hides_cross_principal_task(tmp_path):
    """Principal B's events subscription on Principal A's task yields nothing."""
    db, task_id = await _make_db_with_alice_task(tmp_path)
    await db.connect()
    service = TaskService(db)

    # Principal A's subscription would yield events when the task
    # transitions.  Principal B's subscription yields nothing.
    bob_events = []
    async for event in service.events(_ctx("api:bob"), task_id):
        bob_events.append(event)
    assert bob_events == []
    await db.close()


async def test_task_service_create_succeeds_per_principal(tmp_path):
    """``create`` succeeds for any authenticated principal (C-1-5a).

    C-1-5a: previously ``create`` was rejected for API principals
    because the server-level ``TaskManager(local-uid)`` singleton
    rejected mismatched principals (fail-closed, deferred to
    A-4-3/A-4-4).  Now TaskService constructs per-principal
    TaskManagers on demand, so any authenticated principal can
    create tasks.  The task is stamped with ``ctx.principal_id``
    and visible only to that principal's ``list``.
    """
    db = Database(tmp_path / "task-create-test.db")
    await db.connect()
    await db.run_migrations()
    service = TaskService(db)

    # Local user can create.
    local_create = await service.create(_ctx("local-uid:501"), "local-task")
    assert local_create["goal"] == "local-task"

    # API principal can ALSO create (previously rejected).
    api_create = await service.create(_ctx("api:alice"), "api-task")
    assert api_create["goal"] == "api-task"

    # Alice's task is visible only to alice, not to bob.
    alice_tasks = await service.list(_ctx("api:alice"))
    assert len(alice_tasks) == 1
    assert alice_tasks[0]["goal"] == "api-task"

    bob_tasks = await service.list(_ctx("api:bob"))
    assert bob_tasks == []
    await db.close()


async def test_task_service_approve_rejects_forged_payload_principal(tmp_path):
    """``approve`` rejects when the payload's ``principal_id`` disagrees
    with ``ctx.principal_id``.

    A compromised Gateway could forge the payload's ``principal_id`` to
    match the task's pending approval principal.  The transport
    ``ctx.principal_id`` is the authority — any mismatch is rejected.
    """
    db = Database(tmp_path / "approve-test.db")
    await db.connect()
    await db.run_migrations()
    broker = ApprovalBroker()
    manager = TaskManager(db=db, principal_id="api:alice")
    await manager.load()
    task = await manager.create("approval-task")
    binding = ApprovalBinding(
        principal_id="api:alice", session_id="session-1", task_id=task.id,
        turn_id="turn-1", tool_call_id="tool-call-1", tool_name="shell",
        arguments_digest="args", workspace_id="workspace-1",
        profile_digest="profile", expires_at=time.time() + 60,
    )
    binding_digest = await broker.register_tool_approval(binding)
    await manager.update_status(
        task.id, TaskStatus.BLOCKED,
        pending_approval={
            "tool_call_id": binding.tool_call_id,
            "principal_id": "api:alice",
            "session_id": "session-1",
            "binding_digest": binding_digest,
        },
    )
    service = TaskService(db, broker)

    # Forged payload: ctx is "api:bob" but payload claims "api:alice".
    forged = await service.approve(
        _ctx("api:bob"), task.id,
        principal_id="api:alice",  # forged to match pending_approval
        session_id="session-1",
        binding_digest=binding_digest,
    )
    assert forged["ok"] is False
    assert "does not match transport principal" in forged["error"]

    # Legitimate approve: ctx and payload both "api:alice".
    legit = await service.approve(
        _ctx("api:alice"), task.id,
        principal_id="api:alice",
        session_id="session-1",
        binding_digest=binding_digest,
    )
    assert legit["ok"] is True
    await db.close()


async def test_task_service_reject_rejects_forged_payload_principal(tmp_path):
    """``reject`` symmetrically rejects a forged payload principal."""
    db = Database(tmp_path / "reject-test.db")
    await db.connect()
    await db.run_migrations()
    broker = ApprovalBroker()
    manager = TaskManager(db=db, principal_id="api:alice")
    await manager.load()
    task = await manager.create("approval-task")
    binding = ApprovalBinding(
        principal_id="api:alice", session_id="session-1", task_id=task.id,
        turn_id="turn-1", tool_call_id="tool-call-2", tool_name="shell",
        arguments_digest="args", workspace_id="workspace-1",
        profile_digest="profile", expires_at=time.time() + 60,
    )
    binding_digest = await broker.register_tool_approval(binding)
    await manager.update_status(
        task.id, TaskStatus.BLOCKED,
        pending_approval={
            "tool_call_id": binding.tool_call_id,
            "principal_id": "api:alice",
            "session_id": "session-1",
            "binding_digest": binding_digest,
        },
    )
    service = TaskService(db, broker)

    forged = await service.reject(
        _ctx("api:bob"), task.id,
        principal_id="api:alice",
        session_id="session-1",
        binding_digest=binding_digest,
    )
    assert forged["ok"] is False
    assert "does not match transport principal" in forged["error"]
    await db.close()


# ---------------------------------------------------------------------------
# TaskManager.list_all / list_active — principal_id filter parameter
# ---------------------------------------------------------------------------


async def test_task_manager_list_all_filters_by_principal():
    """``list_all(principal_id=...)`` returns only matching tasks.

    The cache is already principal-scoped at load time, but the explicit
    filter is defense in depth — guarantees that a future code path
    mixing principals in one cache cannot leak across the boundary.
    """
    manager = TaskManager(principal_id="api:alice")
    await manager.create("alice-task-1")
    await manager.create("alice-task-2")

    all_tasks = await manager.list_all()
    assert len(all_tasks) == 2

    alice_filtered = await manager.list_all(principal_id="api:alice")
    assert len(alice_filtered) == 2

    bob_filtered = await manager.list_all(principal_id="api:bob")
    assert bob_filtered == []

    legacy_filtered = await manager.list_all(principal_id="legacy")
    assert legacy_filtered == []


async def test_task_manager_list_active_filters_by_principal():
    """``list_active(principal_id=...)`` returns only matching active tasks."""
    manager = TaskManager(principal_id="api:alice")
    task1 = await manager.create("alice-task-1")
    task2 = await manager.create("alice-task-2")
    # Cancel task2 so it's no longer active.
    await manager.cancel(task2.id)

    all_active = await manager.list_active()
    assert len(all_active) == 1
    assert all_active[0]["id"] == task1.id

    alice_active = await manager.list_active(principal_id="api:alice")
    assert len(alice_active) == 1

    bob_active = await manager.list_active(principal_id="api:bob")
    assert bob_active == []


async def test_task_manager_principal_id_property():
    """``TaskManager.principal_id`` exposes the bound principal read-only."""
    manager = TaskManager(principal_id="api:alice")
    assert manager.principal_id == "api:alice"

    # Default is "legacy" (fail-closed).
    default_manager = TaskManager()
    assert default_manager.principal_id == "legacy"

    # Read-only: no setter.
    with pytest.raises(AttributeError):
        manager.principal_id = "api:bob"  # type: ignore[misc]
