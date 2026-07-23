"""Round-4 review Batch 4: ID, Migration & Lifecycle closures.

Tests for:
  - D-01/D-02: Coding Task 128-bit UUID + Plain INSERT + Owner-bound UPDATE
  - §13.1: ApprovalBroker TTL sweep
  - §13.2: TaskService LRU eviction
  - §13.3: BrowserNetworkSandbox.startup_reaper (non-Linux: no-op)
  - §13.4: cgroup.kill flow (non-Linux: no-op)
  - §11.2: MaintenanceService periodic GC
"""

from __future__ import annotations

import asyncio
import sqlite3
import time
from pathlib import Path

import pytest

from khaos.agent.approval import ApprovalBroker, ApprovalBinding
from khaos.coding.task_manager import CodingTask, TaskManager, TaskStatus
from khaos.db import Database
from khaos.db.database import OwnerMismatchError
from khaos.maintenance import MaintenanceService


async def _make_db(tmp_path) -> Database:
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    return db


_PRINCIPAL = "api:alice"
_PROJ_A = "proj-a"
_PROJ_B = "proj-b"


def _make_binding(
    *, tool_call_id: str, principal_id: str = "alice", session_id: str = "s1",
) -> ApprovalBinding:
    """Build a valid ApprovalBinding with all required fields populated."""
    return ApprovalBinding(
        principal_id=principal_id,
        session_id=session_id,
        task_id="task-1",
        turn_id="turn-1",
        tool_call_id=tool_call_id,
        tool_name="dummy_tool",
        arguments_digest="deadbeef",
        workspace_id="ws-1",
        profile_digest="profile-deadbeef",
        expires_at=time.time() + 3600.0,
    )


# ---------------------------------------------------------------------------
# D-01: Coding Task 128-bit UUID
# ---------------------------------------------------------------------------


def test_d01_coding_task_uses_128_bit_uuid():
    """The default ``id`` must be a full 128-bit UUID hex (32 chars)."""
    task = CodingTask(goal="test")
    assert len(task.id) == 32, (
        f"CodingTask.id must be 32 chars (128-bit UUID hex), got {len(task.id)}: {task.id!r}"
    )
    # Must be valid hex.
    int(task.id, 16)


def test_d01_coding_task_id_is_random():
    """Two tasks must get different IDs (collision is virtually impossible)."""
    t1 = CodingTask(goal="a")
    t2 = CodingTask(goal="b")
    assert t1.id != t2.id


# ---------------------------------------------------------------------------
# D-02: Plain INSERT + Owner-bound UPDATE
# ---------------------------------------------------------------------------


async def test_d02_insert_coding_task_plain_insert(tmp_path):
    """``insert_coding_task`` uses Plain INSERT — collision raises IntegrityError."""
    db = await _make_db(tmp_path)
    task_dict = {
        "id": "ct-collision", "goal": "g", "status": "pending",
        "created_at": "2026-01-01T00:00:00", "updated_at": "2026-01-01T00:00:00",
    }
    await db.insert_coding_task(task_dict, principal_id=_PRINCIPAL, project_id=_PROJ_A)
    # Second INSERT with same id → IntegrityError (not silent overwrite).
    with pytest.raises(sqlite3.IntegrityError):
        await db.insert_coding_task(task_dict, principal_id=_PRINCIPAL, project_id=_PROJ_A)
    await db.close()


async def test_d02_update_coding_task_owner_bound(tmp_path):
    """``update_coding_task`` with a foreign project raises OwnerMismatchError."""
    db = await _make_db(tmp_path)
    task_dict = {
        "id": "ct-owner", "goal": "g", "status": "pending",
        "created_at": "2026-01-01T00:00:00", "updated_at": "2026-01-01T00:00:00",
    }
    await db.insert_coding_task(task_dict, principal_id=_PRINCIPAL, project_id=_PROJ_A)
    # UPDATE with foreign project → OwnerMismatchError.
    task_dict["goal"] = "updated"
    with pytest.raises(OwnerMismatchError):
        await db.update_coding_task(task_dict, principal_id=_PRINCIPAL, project_id=_PROJ_B)
    # Original row untouched.
    rows = await db.list_coding_tasks(principal_id=_PRINCIPAL, project_id=_PROJ_A)
    assert len(rows) == 1
    assert rows[0]["goal"] == "g"
    await db.close()


async def test_d02_update_coding_task_same_owner(tmp_path):
    """``update_coding_task`` with the same owner succeeds."""
    db = await _make_db(tmp_path)
    task_dict = {
        "id": "ct-same", "goal": "g", "status": "pending",
        "created_at": "2026-01-01T00:00:00", "updated_at": "2026-01-01T00:00:00",
    }
    await db.insert_coding_task(task_dict, principal_id=_PRINCIPAL, project_id=_PROJ_A)
    task_dict["goal"] = "updated"
    task_dict["status"] = "completed"
    await db.update_coding_task(task_dict, principal_id=_PRINCIPAL, project_id=_PROJ_A)
    rows = await db.list_coding_tasks(principal_id=_PRINCIPAL, project_id=_PROJ_A)
    assert rows[0]["goal"] == "updated"
    assert rows[0]["status"] == "completed"
    await db.close()


async def test_d02_task_manager_persist_uses_insert_then_update(tmp_path):
    """TaskManager._persist uses INSERT on first write, UPDATE on subsequent."""
    db = await _make_db(tmp_path)
    manager = TaskManager(db=db, principal_id=_PRINCIPAL, project_id=_PROJ_A)
    task = await manager.create("test goal")
    assert task._persisted is True
    # Subsequent update uses UPDATE (not INSERT).
    await manager.update_status(task.id, TaskStatus.COMPLETED)
    rows = await db.list_coding_tasks(principal_id=_PRINCIPAL, project_id=_PROJ_A)
    assert len(rows) == 1
    assert rows[0]["status"] == "completed"
    await db.close()


async def test_d02_task_manager_foreign_project_rebind_raises(tmp_path):
    """A manager bound to proj-B cannot re-persist a task created under proj-A."""
    db = await _make_db(tmp_path)
    manager_a = TaskManager(db=db, principal_id=_PRINCIPAL, project_id=_PROJ_A)
    task = await manager_a.create("cross-project takeover")
    manager_b = TaskManager(db=db, principal_id=_PRINCIPAL, project_id=_PROJ_B)
    with pytest.raises(OwnerMismatchError):
        await manager_b._persist(task)
    await db.close()


# ---------------------------------------------------------------------------
# §13.1: ApprovalBroker TTL sweep
# ---------------------------------------------------------------------------


async def test_approval_sweep_evicts_consumed():
    """``sweep_expired`` evicts records that have been consumed (``used=True``)."""
    broker = ApprovalBroker()
    binding = _make_binding(tool_call_id="tc-1")
    await broker.register_tool_approval(binding)
    # Mark as used by consuming the decision.
    await broker.consume_for_dispatch(
        "tc-1", approved=True, principal_id="alice", session_id="s1",
        binding_digest=binding.digest(),
    )
    assert "tc-1" in broker._tool_approvals
    # Sweep → should evict the consumed record.
    counts = await broker.sweep_expired(ttl_seconds=3600)
    assert counts["tool"] >= 1
    assert "tc-1" not in broker._tool_approvals


async def test_approval_sweep_evicts_expired():
    """``sweep_expired`` evicts records older than TTL."""
    broker = ApprovalBroker()
    binding = _make_binding(tool_call_id="tc-old")
    await broker.register_tool_approval(binding)
    # Manually backdate the record.
    record = broker._tool_approvals["tc-old"]
    record.created_at = time.time() - 7200  # 2 hours ago
    # Sweep with 1-hour TTL → should evict.
    counts = await broker.sweep_expired(ttl_seconds=3600)
    assert counts["tool"] >= 1
    assert "tc-old" not in broker._tool_approvals


async def test_approval_sweep_keeps_active():
    """``sweep_expired`` keeps records that are not consumed or expired."""
    broker = ApprovalBroker()
    binding = _make_binding(tool_call_id="tc-active")
    await broker.register_tool_approval(binding)
    counts = await broker.sweep_expired(ttl_seconds=3600)
    assert counts["tool"] == 0
    assert "tc-active" in broker._tool_approvals


# ---------------------------------------------------------------------------
# §13.2: TaskService LRU
# ---------------------------------------------------------------------------


async def test_task_service_lru_eviction(tmp_path):
    """TaskService evicts the oldest manager when the cache is full."""
    from khaos.grpc_server import TaskService
    from khaos.runtime import RequestContext

    db = await _make_db(tmp_path)
    service = TaskService(db)
    service._MAX_MANAGERS = 3  # small limit for testing
    # Fill the cache with 3 managers.
    for i in range(3):
        ctx = RequestContext(
            principal_id=f"user-{i}", project_id="proj-x",
        )
        await service._manager(ctx)
    assert len(service._managers) == 3
    # Access user-0 to make it recently used.
    ctx0 = RequestContext(
        principal_id="user-0", project_id="proj-x",
    )
    await service._manager(ctx0)
    # Add a 4th → should evict user-1 (least recently used).
    ctx3 = RequestContext(
        principal_id="user-3", project_id="proj-x",
    )
    await service._manager(ctx3)
    assert len(service._managers) == 3
    keys = set(service._managers.keys())
    assert ("user-0", "proj-x") in keys  # user-0 was recently used
    assert ("user-1", "proj-x") not in keys  # user-1 was evicted
    assert ("user-3", "proj-x") in keys  # user-3 is the new entry
    await db.close()


async def test_task_service_keyed_by_principal_and_project(tmp_path):
    """TaskService keys by (principal_id, project_id), not just principal_id."""
    from khaos.grpc_server import TaskService
    from khaos.runtime import RequestContext

    db = await _make_db(tmp_path)
    service = TaskService(db)
    ctx_a = RequestContext(
        principal_id="alice", project_id="proj-a",
    )
    ctx_b = RequestContext(
        principal_id="alice", project_id="proj-b",
    )
    mgr_a = await service._manager(ctx_a)
    mgr_b = await service._manager(ctx_b)
    assert mgr_a is not mgr_b
    assert mgr_a._project_id == "proj-a"
    assert mgr_b._project_id == "proj-b"
    await db.close()


# ---------------------------------------------------------------------------
# §13.3: BrowserNetworkSandbox.startup_reaper (non-Linux: no-op)
# ---------------------------------------------------------------------------


def test_startup_reaper_non_linux_noop():
    """On non-Linux, ``startup_reaper`` returns zero counts without error."""
    import sys
    if sys.platform.startswith("linux"):
        pytest.skip("non-Linux only test")
    from khaos.security.browser_sandbox import BrowserNetworkSandbox
    counts = BrowserNetworkSandbox.startup_reaper()
    assert counts == {"netns": 0, "veth": 0, "cgroup": 0, "nft": 0}


# ---------------------------------------------------------------------------
# §13.4: cgroup.kill (non-Linux: no-op)
# ---------------------------------------------------------------------------


def test_cgroup_kill_non_existent_is_noop():
    """``_remove_linux_cgroup`` on a non-existent path is a no-op."""
    from khaos.coding.execution.platform import _remove_linux_cgroup
    # Non-existent path → no error.
    _remove_linux_cgroup(Path("/tmp/khaos-test-cgroup-nonexistent-12345"))


# ---------------------------------------------------------------------------
# §11.2: MaintenanceService
# ---------------------------------------------------------------------------


async def test_maintenance_service_run_once(tmp_path):
    """``MaintenanceService.run_once`` executes without error and returns counts."""
    db = await _make_db(tmp_path)
    service = MaintenanceService(db, interval_seconds=999, retention_seconds=0)
    counts = await service.run_once()
    assert isinstance(counts, dict)
    await db.close()


async def test_maintenance_service_start_stop(tmp_path):
    """``start`` + ``stop`` lifecycle works without error."""
    db = await _make_db(tmp_path)
    service = MaintenanceService(db, interval_seconds=999)
    service.start()
    assert service._task is not None
    await asyncio.sleep(0.1)  # let the initial cycle run
    await service.stop()
    assert service._task is None
    await db.close()


async def test_maintenance_service_with_approval_broker(tmp_path):
    """MaintenanceService sweeps the approval broker on each cycle."""
    db = await _make_db(tmp_path)
    broker = ApprovalBroker()
    binding = _make_binding(tool_call_id="tc-maint")
    await broker.register_tool_approval(binding)
    # Mark as used so sweep evicts it.
    await broker.consume_for_dispatch(
        "tc-maint", approved=True, principal_id="alice", session_id="s1",
        binding_digest=binding.digest(),
    )
    service = MaintenanceService(db, approval_broker=broker, interval_seconds=999)
    counts = await service.run_once()
    assert counts.get("approvals_swept", 0) >= 1
    assert "tc-maint" not in broker._tool_approvals
    await db.close()
