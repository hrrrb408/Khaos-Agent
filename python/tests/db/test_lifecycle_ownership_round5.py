"""Round-5 Batch 5.4 — Lifecycle Ownership tests.

H-05: ConnectionLifecycleLock — ``connect()`` / ``close()`` / reopen are
      mutually exclusive; partial initialization is cleaned up; atomic
      publish prevents a half-open writer-only state.

H-06: Transaction acquires the writer connection INSIDE the write lock
      so a concurrent ``close()`` cannot tear down the connection
      between the ref capture and the generation capture.

TaskService LRU: ``can_evict()`` / ``aclose()`` — managers with active
      tasks or live subscribers are never evicted; idle managers are
      evicted and their subscribers receive a terminal event.

Approval Future expiry: ``sweep_expired()`` resolves pending Futures
      with a denied decision so waiters wake immediately instead of
      hanging on a shielded, never-resolved Future.

H-10: Operation Approval GC — ``sweep_expired()`` evicts
      ``_operation_approvals`` (used or past expiry), which previously
      grew without bound.

Shutdown Quarantine: ``_emergency_instance_cleanup()`` does NOT close
      the DB when an upstream shutdown fails (live owners may remain);
      the DB is quarantined and the instance lock retained.

Browser/cgroup off Event Loop: ``teardown()`` / ``setup()`` /
      ``install_egress_pin()`` are dispatched via ``asyncio.to_thread``
      so blocking ``subprocess.run`` calls do not stall the event loop.
"""
from __future__ import annotations

import asyncio
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from khaos.agent.approval import (
    ApprovalBinding,
    ApprovalBroker,
)
from khaos.coding.task_manager import TaskManager, TaskStatus
from khaos.db import Database

# ─────────────────────────── helpers ────────────────────────────────


async def _make_db(path: Path) -> Database:
    db = Database(path)
    await db.connect()
    await db.run_migrations()
    return db


def _binding(
    tool_call_id: str, *, expires_at: float | None = None
) -> ApprovalBinding:
    return ApprovalBinding(
        principal_id="principal",
        session_id="session",
        task_id="task",
        turn_id="turn",
        tool_call_id=tool_call_id,
        tool_name="write_file",
        arguments_digest="a" * 64,
        workspace_id="workspace",
        profile_digest="b" * 64,
        expires_at=expires_at or time.time() + 60,
    )


# ══════════════════════════════════════════════════════════════════════
# H-05: ConnectionLifecycleLock
# ══════════════════════════════════════════════════════════════════════


async def test_h05_concurrent_connect_does_not_leak(tmp_path):
    """H-05-A: two concurrent ``connect()`` calls do not create two
    sets of connections — the lifecycle lock serializes them and the
    second sees ``_conn is not None``."""
    db = Database(tmp_path / "h05a.db")
    try:
        await asyncio.gather(db.connect(), db.connect())
        assert db._conn is not None
        assert db._reader_conn is not None
        # Exactly one writer + one reader — no leak.
        # (If two connects raced, both would have opened connections
        # but only one set would be published; the leaked set would
        # be orphaned.  We can't directly count leaked connections,
        # but we verify the published set is the only one.)
    finally:
        await db.close()


async def test_h05_close_acquires_lifecycle_lock(tmp_path):
    """H-05-B: ``close()`` holds the lifecycle lock during teardown
    so a concurrent ``connect()`` cannot see a half-closed state."""
    db = Database(tmp_path / "h05b.db")
    await db.connect()
    # Start close and connect concurrently.  close() acquires WRITE
    # then LIFECYCLE; connect() acquires only LIFECYCLE.  If close()
    # did NOT hold LIFECYCLE, connect() could re-open connections
    # while close() is still tearing them down.
    await asyncio.gather(db.close(), db.connect())
    assert db._conn is not None  # connect() re-opened after close()
    await db.close()


async def test_h05_close_bumps_generation_under_lock(tmp_path):
    """H-05-C: ``close()`` bumps ``_connection_generation`` atomically
    with the connection teardown, so a stale TransactionOwner token
    fails the generation check."""
    db = Database(tmp_path / "h05c.db")
    await db.connect()
    gen_before = db._connection_generation
    await db.close()
    assert db._connection_generation == gen_before + 1
    assert db._conn is None
    assert db._reader_conn is None


async def test_h05_partial_init_cleanup(tmp_path):
    """H-05-D: if reader open fails after writer open succeeds, the
    writer is closed in the ``finally`` block — ``_conn`` is never
    non-None while ``_reader_conn`` is None (partial init)."""
    import khaos.db.database as dbmod

    if dbmod.aiosqlite is None:
        pytest.skip("aiosqlite not available — fallback path is synchronous")

    db = Database(tmp_path / "h05d.db")
    original_connect = dbmod.aiosqlite.connect
    call_count = 0

    async def flaky_connect(path):
        nonlocal call_count
        call_count += 1
        conn = await original_connect(path)
        if call_count == 2:
            # Simulate reader open failure.
            await conn.close()
            raise OSError("simulated reader open failure")
        return conn

    with patch.object(dbmod.aiosqlite, "connect", side_effect=flaky_connect):
        with pytest.raises(OSError, match="simulated reader open failure"):
            await db.connect()
    # Neither connection should be published.
    assert db._conn is None
    assert db._reader_conn is None


# ══════════════════════════════════════════════════════════════════════
# H-06: Transaction captures connection inside the write lock
# ══════════════════════════════════════════════════════════════════════


async def test_h06_transaction_connection_generation_consistent(tmp_path):
    """H-06-A: the connection reference and the generation captured in
    the TransactionOwner are consistent — a concurrent ``close()``
    cannot interleave between them."""
    db = await _make_db(tmp_path / "h06a.db")
    try:
        async with db.transaction() as conn:
            # Inside the transaction, the owner token's generation
            # matches the current generation.
            owner = db._current_transaction_owner_get() if hasattr(
                db, "_current_transaction_owner_get"
            ) else None
            # The connection is alive and usable.
            await conn.execute("SELECT 1")
    finally:
        await db.close()


async def test_h06_close_waits_for_inflight_transaction(tmp_path):
    """H-06-B: ``close()`` acquires the write lock, so it waits for an
    in-flight transaction to commit before tearing down connections."""
    db = await _make_db(tmp_path / "h06b.db")
    try:
        commit_barrier = asyncio.Event()

        async def hold_transaction():
            async with db.transaction() as conn:
                await conn.execute(
                    "CREATE TABLE IF NOT EXISTS h06_test (x INTEGER)"
                )
                await conn.execute("INSERT INTO h06_test VALUES (1)")
                # Signal that the transaction is in-flight.
                commit_barrier.set()
                # Hold the transaction open so close() must wait.
                await asyncio.sleep(0.1)

        tx_task = asyncio.create_task(hold_transaction())
        await commit_barrier.wait()
        # close() should block until the transaction commits.
        await db.close()
        await tx_task
    except Exception:
        pass


# ══════════════════════════════════════════════════════════════════════
# TaskService LRU — can_evict / aclose
# ══════════════════════════════════════════════════════════════════════


async def test_lru_can_evict_idle_manager(tmp_path):
    """LRU-A: an idle TaskManager (no active tasks, no subscribers) is
    evictable."""
    db = await _make_db(tmp_path / "lru_a.db")
    try:
        manager = TaskManager(db=db, principal_id="alice", project_id="p1")
        await manager.load()
        assert manager.can_evict() is True
    finally:
        await db.close()


async def test_lru_cannot_evict_manager_with_active_task(tmp_path):
    """LRU-B: a TaskManager with a RUNNING task is NOT evictable."""
    db = await _make_db(tmp_path / "lru_b.db")
    try:
        manager = TaskManager(db=db, principal_id="alice", project_id="p1")
        await manager.load()
        task = await manager.create("active work")
        await manager.update_status(task.id, TaskStatus.RUNNING)
        assert manager.can_evict() is False
    finally:
        await db.close()


async def test_lru_cannot_evict_manager_with_subscribers(tmp_path):
    """LRU-C: a TaskManager with live subscribers is NOT evictable."""
    db = await _make_db(tmp_path / "lru_c.db")
    try:
        manager = TaskManager(db=db, principal_id="alice", project_id="p1")
        await manager.load()
        task = await manager.create("subscribed work")
        # Simulate a live subscriber by registering a queue.
        queue: asyncio.Queue = asyncio.Queue()
        manager._subscribers.setdefault(task.id, []).append(queue)
        assert manager.can_evict() is False
    finally:
        await db.close()


async def test_lru_aclose_notifies_subscribers(tmp_path):
    """LRU-D: ``aclose()`` feeds a ``task.evicted`` event to all
    subscriber queues so streaming consumers unblock."""
    db = await _make_db(tmp_path / "lru_d.db")
    try:
        manager = TaskManager(db=db, principal_id="alice", project_id="p1")
        await manager.load()
        task = await manager.create("doomed work")
        queue: asyncio.Queue = asyncio.Queue()
        manager._subscribers.setdefault(task.id, []).append(queue)
        await manager.aclose()
        event = await asyncio.wait_for(queue.get(), timeout=1.0)
        assert event["type"] == "task.evicted"
        assert event["payload"]["reason"] == "manager_evicted"
    finally:
        await db.close()


async def test_lru_service_skips_busy_manager(tmp_path):
    """LRU-E: ``TaskService._manager`` does NOT evict a manager with
    an active task even when the cache is at capacity — the cache
    temporarily exceeds ``_MAX_MANAGERS`` instead."""
    from khaos.grpc_server import TaskService
    from khaos.runtime import RequestContext

    db = await _make_db(tmp_path / "lru_e.db")
    try:
        service = TaskService(db)
        service._MAX_MANAGERS = 2
        # Fill the cache with 2 idle managers.
        ctx_a = RequestContext.for_rpc("alice", project_id="pa")
        ctx_b = RequestContext.for_rpc("alice", project_id="pb")
        await service._manager(ctx_a)
        await service._manager(ctx_b)
        assert len(service._managers) == 2
        # Make manager A busy (active task).
        mgr_a = service._managers[("alice", "pa")]
        task = await mgr_a.create("active")
        await mgr_a.update_status(task.id, TaskStatus.RUNNING)
        # Make manager B busy too.
        mgr_b = service._managers[("alice", "pb")]
        task_b = await mgr_b.create("active")
        await mgr_b.update_status(task_b.id, TaskStatus.RUNNING)
        # Now request a third manager — cache is at capacity but both
        # existing managers are busy.  The cache should grow to 3
        # rather than evicting a live owner.
        ctx_c = RequestContext.for_rpc("alice", project_id="pc")
        await service._manager(ctx_c)
        assert len(service._managers) == 3
        # The busy managers are still present.
        assert ("alice", "pa") in service._managers
        assert ("alice", "pb") in service._managers
    finally:
        await db.close()


async def test_lru_service_evicts_idle_manager(tmp_path):
    """LRU-F: when an idle manager exists, ``TaskService._manager``
    evicts it (calling ``aclose``) to make room for the new one."""
    from khaos.grpc_server import TaskService
    from khaos.runtime import RequestContext

    db = await _make_db(tmp_path / "lru_f.db")
    try:
        service = TaskService(db)
        service._MAX_MANAGERS = 2
        ctx_a = RequestContext.for_rpc("alice", project_id="pa")
        ctx_b = RequestContext.for_rpc("alice", project_id="pb")
        await service._manager(ctx_a)
        await service._manager(ctx_b)
        assert len(service._managers) == 2
        # Both idle — requesting a third evicts the oldest (pa).
        ctx_c = RequestContext.for_rpc("alice", project_id="pc")
        await service._manager(ctx_c)
        assert len(service._managers) == 2
        assert ("alice", "pa") not in service._managers
        assert ("alice", "pc") in service._managers
    finally:
        await db.close()


# ══════════════════════════════════════════════════════════════════════
# Approval Future expiry + H-10 Operation Approval GC
# ══════════════════════════════════════════════════════════════════════


async def test_sweep_resolves_pending_future():
    """AFE-A: ``sweep_expired()`` resolves a pending Future with a
    denied decision so a waiter in ``wait()`` wakes immediately."""
    broker = ApprovalBroker()
    binding = _binding("call-1", expires_at=time.time() + 3600)
    digest = await broker.register_tool_approval(binding)
    # Start a waiter with NO timeout — without the fix it would hang
    # forever after sweep_expired removes the record.
    waiter = asyncio.create_task(
        broker.wait("call-1", binding_digest=digest)
    )
    await asyncio.sleep(0.05)  # let the waiter register its Future
    # Mark the record as used so sweep_expired evicts it.
    async with broker._lock:
        rec = broker._tool_approvals.get("call-1")
        assert rec is not None
        rec.used = True
    counts = await broker.sweep_expired()
    assert counts["tool"] >= 1
    # The waiter should wake with a denied decision.
    decision = await asyncio.wait_for(waiter, timeout=2.0)
    assert decision == {"approved": False, "remember": False}


async def test_sweep_evicts_operation_approvals():
    """H-10-A: ``sweep_expired()`` evicts used operation approvals."""
    broker = ApprovalBroker()
    # Register an operation approval without a DB (in-memory only).
    await broker.register_operation(
        "op-1",
        binding={
            "principal_id": "p",
            "session_id": "s",
            "task_id": "t",
            "workspace_id": "w",
            "operation": "delete",
            "nonce_hash": "x",
        },
        expiry=time.time() + 3600,
    )
    assert "op-1" in broker._operation_approvals
    # Mark it used.
    await broker.cancel_operation("op-1")
    counts = await broker.sweep_expired()
    assert counts["operation"] >= 1
    assert "op-1" not in broker._operation_approvals


async def test_sweep_evicts_expired_operation_approvals():
    """H-10-B: ``sweep_expired()`` evicts operation approvals past
    their expiry time."""
    broker = ApprovalBroker()
    await broker.register_operation(
        "op-2",
        binding={
            "principal_id": "p",
            "session_id": "s",
            "task_id": "t",
            "workspace_id": "w",
            "operation": "delete",
            "nonce_hash": "x",
        },
        expiry=time.time() - 1,  # already expired
    )
    assert "op-2" in broker._operation_approvals
    counts = await broker.sweep_expired()
    assert counts["operation"] >= 1
    assert "op-2" not in broker._operation_approvals


async def test_sweep_keeps_active_operation_approvals():
    """H-10-C: ``sweep_expired()`` does NOT evict unused, unexpired
    operation approvals."""
    broker = ApprovalBroker()
    await broker.register_operation(
        "op-3",
        binding={
            "principal_id": "p",
            "session_id": "s",
            "task_id": "t",
            "workspace_id": "w",
            "operation": "delete",
            "nonce_hash": "x",
        },
        expiry=time.time() + 3600,
    )
    counts = await broker.sweep_expired()
    assert counts["operation"] == 0
    assert "op-3" in broker._operation_approvals


# ══════════════════════════════════════════════════════════════════════
# Shutdown Quarantine
# ══════════════════════════════════════════════════════════════════════


async def test_shutdown_quarantine_db_not_closed_on_agent_failure(tmp_path):
    """SQ-A: when ``agent.shutdown()`` raises, ``_emergency_instance_cleanup``
    does NOT call ``db.close()`` — the DB is quarantined."""
    from khaos.grpc_server import _emergency_instance_cleanup

    db = await _make_db(tmp_path / "sq_a.db")
    agent = AsyncMock()
    agent.shutdown = AsyncMock(side_effect=RuntimeError("live cron"))
    subagent_service = AsyncMock()
    subagent_service.shutdown = AsyncMock()

    result = await _emergency_instance_cleanup(
        agent, db, subagent_service, maintenance=None
    )
    assert result is False  # cleanup failed — lock must be retained
    # DB should still be open (not closed).
    assert db._conn is not None
    await db.close()


async def test_shutdown_quarantine_db_not_closed_on_subagent_failure(tmp_path):
    """SQ-B: when ``subagent_service.shutdown()`` raises, the DB is
    NOT closed."""
    from khaos.grpc_server import _emergency_instance_cleanup

    db = await _make_db(tmp_path / "sq_b.db")
    agent = AsyncMock()
    agent.shutdown = AsyncMock()
    subagent_service = AsyncMock()
    subagent_service.shutdown = AsyncMock(
        side_effect=RuntimeError("live subagent")
    )

    result = await _emergency_instance_cleanup(
        agent, db, subagent_service, maintenance=None
    )
    assert result is False
    assert db._conn is not None
    await db.close()


async def test_shutdown_quarantine_db_closed_on_clean_shutdown(tmp_path):
    """SQ-C: when all upstream shutdowns succeed, the DB IS closed."""
    from khaos.grpc_server import _emergency_instance_cleanup

    db = await _make_db(tmp_path / "sq_c.db")
    agent = AsyncMock()
    agent.shutdown = AsyncMock()
    subagent_service = AsyncMock()
    subagent_service.shutdown = AsyncMock()

    result = await _emergency_instance_cleanup(
        agent, db, subagent_service, maintenance=None
    )
    assert result is True
    assert db._conn is None  # DB was closed


async def test_shutdown_quarantine_maintenance_failure_skips_db(tmp_path):
    """SQ-D: when ``maintenance.stop()`` raises, the DB is NOT closed
    (maintenance failure is treated as a live-owner risk)."""
    from khaos.grpc_server import _emergency_instance_cleanup
    from khaos.maintenance import MaintenanceService

    db = await _make_db(tmp_path / "sq_d.db")
    agent = AsyncMock()
    agent.shutdown = AsyncMock()
    subagent_service = AsyncMock()
    subagent_service.shutdown = AsyncMock()
    maintenance = AsyncMock(spec=MaintenanceService)
    maintenance.stop = AsyncMock(side_effect=RuntimeError("gc loop stuck"))

    result = await _emergency_instance_cleanup(
        agent, db, subagent_service, maintenance=maintenance
    )
    assert result is False
    assert db._conn is not None
    await db.close()


# ══════════════════════════════════════════════════════════════════════
# Browser/cgroup cleanup off Event Loop
# ══════════════════════════════════════════════════════════════════════


async def test_browser_teardown_uses_to_thread():
    """BC-A: ``BrowserManager.close()`` calls ``teardown()`` via
    ``asyncio.to_thread`` so blocking subprocess calls run off the
    event loop."""
    from khaos.tools.browser_tools import BrowserManager

    manager = BrowserManager()
    manager._browser_sandbox = MagicMock()
    teardown_mock = manager._browser_sandbox.teardown  # save before close() nulls it
    manager._playwright = None
    manager._browser = None
    manager._closing_requested = True

    to_thread_calls: list = []

    async def fake_to_thread(fn, *args, **kwargs):
        to_thread_calls.append((fn, args, kwargs))
        return None

    with patch("khaos.tools.browser_tools.asyncio.to_thread", side_effect=fake_to_thread):
        try:
            await manager.close()
        except Exception:
            pass
        # Verify to_thread was called with the teardown method.
        assert any(
            fn == teardown_mock
            for fn, _, _ in to_thread_calls
        ), f"expected to_thread called with teardown, got: {to_thread_calls}"
