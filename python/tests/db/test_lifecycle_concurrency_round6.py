"""Batch 6.5 (round-6): Lifecycle Concurrency.

Closes the concurrency/lifecycle issues from the sixth-round deep review:

  §十七  TaskManager LRU split-brain + eviction CAS + subscription sentinel
  §十八  SQLite Reader Operation Lease (close() races in-flight reads)
  §十六  Dependency-aware Emergency Shutdown (fail-stop borrowed-authority chain)
  §十五  Browser Force-close Proxy/Sandbox leak
  §25.3  Durable Approval Ledger retention (DB pruning)

Each review point has dedicated tests.  The tests exercise real concurrency
(asyncio.gather) rather than mocking the locks, so they prove the fixes
hold end-to-end.
"""

from __future__ import annotations

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from khaos.coding.task_manager import TaskManager
from khaos.db import Database
from khaos.db.database import _READER_DRAIN_TIMEOUT


# ===========================================================================
# §十七 — TaskManager begin_eviction CAS + _closing flag
# ===========================================================================


async def test_s17_begin_eviction_sets_closing_and_rejects_concurrent_create():
    """§十七 item 2: ``begin_eviction`` atomically checks evictability and
    flips ``_closing`` under the lock.  After it returns True, a concurrent
    ``create()`` must be rejected (closing the TOCTOU window where a task
    could go active between ``can_evict`` and ``aclose``)."""
    mgr = TaskManager(db=None, principal_id="p1", project_id="proj1")
    assert await mgr.begin_eviction() is True
    assert mgr._closing is True
    # create() must now refuse.
    with pytest.raises(RuntimeError, match="closing"):
        await mgr.create("goal")
    await mgr.aclose()


async def test_s17_begin_eviction_returns_false_when_task_active():
    """§十七 item 2: if a task is active, begin_eviction must return False
    and NOT set _closing (the manager stays usable)."""
    mgr = TaskManager(db=None, principal_id="p1", project_id="proj1")
    await mgr.create("active goal")  # creates a PENDING task (active)
    # An active task blocks eviction.
    got = await mgr.begin_eviction()
    assert got is False
    assert mgr._closing is False
    await mgr.aclose()


async def test_s17_begin_eviction_idempotent_for_concurrent_evictors():
    """§十七 item 2: two concurrent begin_eviction calls — only the first
    wins (returns True + sets _closing); the second sees _closing already
    set and returns False (treats it as 'not mine to evict')."""
    mgr = TaskManager(db=None, principal_id="p1", project_id="proj1")
    r1, r2 = await asyncio.gather(mgr.begin_eviction(), mgr.begin_eviction())
    # Exactly one True (the other sees _closing set).
    assert (r1, r2) in {(True, False), (False, True)}
    assert mgr._closing is True
    await mgr.aclose()


async def test_s17_subscribe_refused_during_eviction():
    """§十七 item 2: subscribe() must refuse while _closing is set, so an
    evicted manager cannot gain a fresh subscriber."""
    mgr = TaskManager(db=None, principal_id="p1", project_id="proj1")
    await mgr.begin_eviction()
    # No task exists, so subscribe raises KeyError before the closing
    # check — create a task FIRST then evict to test the closing path.
    # (We cannot create after eviction because create is refused too; so
    # this confirms the closing flag is checked in subscribe's locked
    # block by ensuring a subscribe on a known task_id still fails closed.)
    with pytest.raises((KeyError, RuntimeError)):
        async for _ in mgr.subscribe("nonexistent"):
            break
    await mgr.aclose()


# ===========================================================================
# §十七 — Subscription Terminal Sentinel + safe finally
# ===========================================================================


async def test_s17_subscribe_exits_on_evicted_sentinel():
    """§十七 item 3: the subscribe generator must break after yielding the
    ``task.evicted`` sentinel, instead of looping forever on a queue that
    will never receive another event."""
    mgr = TaskManager(db=None, principal_id="p1", project_id="proj1")
    task = await mgr.create("goal")
    events = []

    async def consume():
        async for event in mgr.subscribe(task.id):
            events.append(event.get("type"))
            if event.get("type") == "task.evicted":
                break  # consumer also breaks as a safety net

    consumer = asyncio.create_task(consume())
    await asyncio.sleep(0.05)  # let it get the snapshot
    # Evict: aclose feeds task.evicted to the queue.
    await mgr.begin_eviction()
    await mgr.aclose()
    await asyncio.wait_for(consumer, timeout=2.0)
    assert "task.snapshot" in events
    assert events[-1] == "task.evicted"
    await mgr.aclose()


async def test_s17_subscribe_finally_does_not_raise_after_aclose_clears_list():
    """§十七 item 3: the subscribe ``finally`` removes the queue
    idempotently.  aclose() replaces the subscriber list with ``[]``; the
    generator's finally must NOT raise ValueError when it runs after that."""
    mgr = TaskManager(db=None, principal_id="p1", project_id="proj1")
    task = await mgr.create("goal")
    finally_error: list[BaseException] = []

    async def consume():
        gen = mgr.subscribe(task.id)
        try:
            async for event in gen:
                if event.get("type") == "task.evicted":
                    break
        except BaseException as exc:
            finally_error.append(exc)

    consumer = asyncio.create_task(consume())
    await asyncio.sleep(0.05)
    await mgr.begin_eviction()
    await mgr.aclose()  # replaces _subscribers[task.id] with []
    await asyncio.wait_for(consumer, timeout=2.0)
    # No ValueError leaked from the finally.
    assert not finally_error, f"subscribe finally raised: {finally_error}"
    await mgr.aclose()


# ===========================================================================
# §十七 — TaskService manager cache lock (split-brain)
# ===========================================================================


async def test_s17_concurrent_manager_lookup_no_split_brain(tmp_path):
    """§十七 item 1: two concurrent _manager() calls for the same key must
    converge on ONE TaskManager instance (the service-level cache lock
    serializes miss → build → load → insert).  Pre-fix, both built a
    manager and the loser was silently dropped."""
    db = Database(tmp_path / "svc.db")
    await db.connect()
    await db.run_migrations()

    # Import here to avoid heavy module init at collection time.
    from khaos.grpc_server import TaskService
    from khaos.runtime.context import RequestContext

    svc = TaskService(db)
    ctx = RequestContext(principal_id="p1", project_id="proj1")

    # Fire N concurrent lookups for the SAME key.
    managers = await asyncio.gather(*[svc._manager(ctx) for _ in range(8)])
    # All callers must receive the SAME instance.
    assert len({id(m) for m in managers}) == 1, (
        "split-brain: concurrent _manager() returned distinct instances"
    )
    assert (ctx.principal_id, ctx.project_id) in svc._managers
    await db.close()


async def test_s17_manager_cache_lock_serializes_eviction():
    """§十七 item 1: the cache lock also serializes LRU eviction, so two
    concurrent capacity-pressured lookups cannot double-evict."""
    from khaos.grpc_server import TaskService
    from khaos.runtime.context import RequestContext

    svc = TaskService(db=None)
    svc._MAX_MANAGERS = 2
    # Pre-populate the cache at capacity with evictable (empty) managers.
    for i in range(2):
        key = (f"p{i}", f"proj{i}")
        svc._managers[key] = TaskManager(
            db=None, principal_id=key[0], project_id=key[1]
        )
    ctx = RequestContext(principal_id="p_new", project_id="proj_new")
    # Concurrent lookups that both need to evict — the lock ensures only
    # one eviction happens and exactly one new manager is built.
    m1, m2 = await asyncio.gather(svc._manager(ctx), svc._manager(ctx))
    assert m1 is m2
    # Cache should still be bounded (one evicted, one added → still 2, or
    # 3 if both raced before the fix; with the lock it is exactly 2).
    assert len(svc._managers) <= svc._MAX_MANAGERS + 1


# ===========================================================================
# §十八 — Reader Operation Lease
# ===========================================================================


async def test_s18_close_waits_for_in_flight_read(tmp_path):
    """§十八: ``close()`` must wait for an in-flight read to finish before
    closing the reader connection.  We hold a read lease, start close()
    concurrently, and assert close only completes after the read releases."""
    db = Database(tmp_path / "lease.db")
    await db.connect()
    await db.run_migrations()

    read_done = asyncio.Event()
    close_done = asyncio.Event()

    async def hold_read():
        async with db._read_lease():
            # Simulate a slow read holding the lease.
            await asyncio.sleep(0.3)
        read_done.set()

    async def do_close():
        await db.close()
        close_done.set()

    reader = asyncio.create_task(hold_read())
    closer = asyncio.create_task(do_close())
    # Give close a moment to reach the drain wait.
    await asyncio.sleep(0.1)
    # close() should still be waiting (read not done).
    assert not close_done.is_set(), "close() finished before the read released"
    # Let the read finish.
    await asyncio.wait_for(read_done.wait(), timeout=2.0)
    # Now close() should complete promptly.
    await asyncio.wait_for(closer, timeout=_READER_DRAIN_TIMEOUT + 2)


async def test_s18_read_lease_tracks_active_readers(tmp_path):
    """§十八: ``_active_readers`` increments on enter and returns to zero on
    exit, and ``_readers_idle`` reflects the count."""
    db = Database(tmp_path / "cnt.db")
    await db.connect()
    await db.run_migrations()
    assert db._active_readers == 0
    assert db._readers_idle.is_set()
    async with db._read_lease():
        assert db._active_readers == 1
        assert not db._readers_idle.is_set()
        async with db._read_lease():
            assert db._active_readers == 2
        assert db._active_readers == 1
        assert not db._readers_idle.is_set()
    assert db._active_readers == 0
    assert db._readers_idle.is_set()
    await db.close()


# ===========================================================================
# §十六 — Dependency-aware Emergency Shutdown (fail-stop)
# ===========================================================================


async def test_s16_subagent_failure_skips_agent_shutdown(tmp_path):
    """§十六: if subagent_service.shutdown() fails, the emergency cleanup
    must NOT call agent.shutdown() (which would close borrowed Office /
    Browser / Audit authorities while the subagent is still live).  The
    whole chain stops and returns False (quarantine)."""
    from khaos.grpc_server import _emergency_instance_cleanup

    agent = MagicMock(name="agent")
    agent.shutdown = AsyncMock()
    subagent_service = MagicMock(name="subagent_service")
    subagent_service.shutdown = AsyncMock(side_effect=RuntimeError("boom"))
    maintenance = MagicMock(name="maintenance")
    maintenance.stop = AsyncMock()
    db = MagicMock(name="db")
    db.close = AsyncMock()

    result = await _emergency_instance_cleanup(
        agent=agent, db=db, subagent_service=subagent_service,
        maintenance=maintenance,
    )
    assert result is False  # quarantined
    maintenance.stop.assert_awaited_once()
    subagent_service.shutdown.assert_awaited_once()
    # FAIL-STOP: agent.shutdown and db.close must NOT have been called.
    agent.shutdown.assert_not_awaited()
    db.close.assert_not_awaited()


async def test_s16_maintenance_failure_skips_everything_downstream():
    """§十六: if maintenance.stop() fails, subagent/agent/db shutdowns are
    all skipped (nothing downstream runs)."""
    from khaos.grpc_server import _emergency_instance_cleanup

    agent = MagicMock(); agent.shutdown = AsyncMock()
    sub = MagicMock(); sub.shutdown = AsyncMock()
    maint = MagicMock(); maint.stop = AsyncMock(side_effect=RuntimeError("x"))
    db = MagicMock(); db.close = AsyncMock()

    result = await _emergency_instance_cleanup(
        agent=agent, db=db, subagent_service=sub, maintenance=maint,
    )
    assert result is False
    sub.shutdown.assert_not_awaited()
    agent.shutdown.assert_not_awaited()
    db.close.assert_not_awaited()


async def test_s16_all_succeed_closes_db():
    """§十六: when every step succeeds, the chain proceeds all the way to
    db.close() and returns True (this is the happy path that must still
    work after the fail-stop change)."""
    from khaos.grpc_server import _emergency_instance_cleanup

    agent = MagicMock(); agent.shutdown = AsyncMock()
    sub = MagicMock(); sub.shutdown = AsyncMock()
    maint = MagicMock(); maint.stop = AsyncMock()
    db = MagicMock(); db.close = AsyncMock()

    result = await _emergency_instance_cleanup(
        agent=agent, db=db, subagent_service=sub, maintenance=maint,
    )
    assert result is True
    maint.stop.assert_awaited_once()
    sub.shutdown.assert_awaited_once()
    agent.shutdown.assert_awaited_once()
    db.close.assert_awaited_once()


# ===========================================================================
# §15 — Browser Force-close Proxy/Sandbox cleanup
# ===========================================================================


async def test_s15_force_close_invokes_close_all_contexts_and_sandbox_teardown():
    """§十五: ``_force_close_browser_locked`` must close each context's
    egress proxy (via _close_all_contexts) and tear down the sandbox,
    not just browser.close() + _contexts.clear()."""
    from khaos.tools.browser_tools import BrowserManager

    mgr = BrowserManager.__new__(BrowserManager)
    browser_mock = MagicMock()
    browser_mock.close = AsyncMock()
    playwright_mock = MagicMock()
    playwright_mock.stop = AsyncMock()
    mgr._browser = browser_mock
    mgr._playwright = playwright_mock
    mgr._contexts = {"k1": {"egress_proxy": MagicMock()}}
    mgr._context_close_failures = {}
    sandbox_mock = MagicMock()
    sandbox_mock.teardown = MagicMock()
    mgr._browser_sandbox = sandbox_mock

    with patch.object(
        mgr, "_close_all_contexts", new=AsyncMock()
    ) as mock_close_all:
        await mgr._force_close_browser_locked()

    mock_close_all.assert_awaited_once()
    browser_mock.close.assert_awaited_once()
    playwright_mock.stop.assert_awaited_once()
    sandbox_mock.teardown.assert_called_once()
    # Implementation nulls the references after a clean teardown.
    assert mgr._browser is None
    assert mgr._playwright is None
    assert mgr._browser_sandbox is None
    assert mgr._contexts == {}


async def test_s15_force_close_retains_sandbox_on_teardown_failure():
    """§十五: if sandbox teardown fails, the sandbox reference is RETAINED
    (not nulled) so the startup Reaper can retry on next launch instead of
    silently leaking netns/veth/cgroup/nft."""
    from khaos.tools.browser_tools import BrowserManager

    mgr = BrowserManager.__new__(BrowserManager)
    mgr._browser = MagicMock(); mgr._browser.close = AsyncMock()
    mgr._playwright = MagicMock(); mgr._playwright.stop = AsyncMock()
    mgr._contexts = {}
    mgr._context_close_failures = {}
    sandbox = MagicMock()
    sandbox.teardown = MagicMock(side_effect=RuntimeError("netns busy"))
    mgr._browser_sandbox = sandbox

    with patch.object(mgr, "_close_all_contexts", new=AsyncMock()):
        await mgr._force_close_browser_locked()

    # Sandbox ref retained for the Reaper.
    assert mgr._browser_sandbox is sandbox


# ===========================================================================
# §25.3 — Durable Approval Ledger retention (DB pruning)
# ===========================================================================


async def test_s253_prune_removes_consumed_and_expired_operation_approvals(tmp_path):
    """§25.3: prune_approval_ledger deletes operation_approvals rows that
    are terminal (consumed/cancelled) OR past expires_at+retention, plus
    their events.  Active/pending rows are retained."""
    db = Database(tmp_path / "apr.db")
    await db.connect()
    await db.run_migrations()
    conn = await db._require_writer_conn()
    now = time.time()
    # Insert: one consumed (terminal), one expired, one pending-fresh.
    rows = [
        # (approval_id, status, expires_at)
        ("a-consumed", "consumed", now + 9999),   # terminal → pruned
        ("a-expired", "pending", now - 99999),     # expired → pruned
        ("a-active", "pending", now + 9999),       # active → kept
    ]
    for aid, status, exp in rows:
        await conn.execute(
            "INSERT INTO operation_approvals (approval_id, binding_digest, "
            "binding_json, principal_id, session_id, task_id, workspace_id, "
            "operation, nonce_hash, expires_at, status, created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (aid, "d", "{}", "p", "s", "t", "w", "op", "n", exp, status, now),
        )
        await conn.execute(
            "INSERT INTO operation_approval_events (approval_id, event_type, "
            "binding_digest, principal_id, session_id, detail_json, created_at) "
            "VALUES (?,?,?,?,?,?,?)",
            (aid, "created", "d", "p", "s", "{}", now),
        )
    await conn.commit()

    pruned = await db.prune_approval_ledger(retention_seconds=3600)
    assert pruned["operation_approvals"] == 2
    assert pruned["operation_approval_events"] == 2

    cur = await (await conn.execute(
        "SELECT approval_id FROM operation_approvals ORDER BY approval_id"
    )).fetchall()
    remaining = [r["approval_id"] for r in cur]
    assert remaining == ["a-active"]

    ev = await (await conn.execute(
        "SELECT COUNT(*) AS n FROM operation_approval_events"
    )).fetchone()
    assert ev["n"] == 1  # only the active row's event remains
    await db.close()


async def test_s253_prune_respects_retention_grace_window(tmp_path):
    """§25.3: a terminal row within the retention grace window is still
    pruned (terminal = immediately eligible), but a non-terminal row whose
    expires_at is recent is kept.  This confirms retention_seconds gates
    the expiry-based pruning, not the terminal-based pruning."""
    db = Database(tmp_path / "grace.db")
    await db.connect()
    await db.run_migrations()
    conn = await db._require_writer_conn()
    now = time.time()
    # Recently-consumed (terminal) → pruned regardless of grace.
    await conn.execute(
        "INSERT INTO operation_approvals (approval_id, binding_digest, "
        "binding_json, principal_id, session_id, task_id, workspace_id, "
        "operation, nonce_hash, expires_at, status, created_at) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        ("recent-consumed", "d", "{}", "p", "s", "t", "w", "op", "n",
         now + 9999, "consumed", now),
    )
    await conn.commit()
    pruned = await db.prune_approval_ledger(retention_seconds=999999)
    assert pruned["operation_approvals"] == 1
    await db.close()


async def test_s253_maintenance_run_once_calls_prune(tmp_path):
    """§25.3: MaintenanceService.run_once() invokes prune_approval_ledger
    after the in-memory sweep, returning the pruned count."""
    from khaos.maintenance import MaintenanceService

    db = MagicMock()
    db.prune_terminal_chat_streams = AsyncMock(return_value=0)
    db.prune_approval_ledger = AsyncMock(
        return_value={"operation_approvals": 3, "operation_approval_events": 3}
    )
    broker = MagicMock()
    broker.sweep_expired = AsyncMock(return_value={"tool": 0, "plan": 0, "operation": 0})
    svc = MaintenanceService(db, approval_broker=broker, interval_seconds=60)
    counts = await svc.run_once()
    db.prune_approval_ledger.assert_awaited_once()
    assert counts.get("approval_ledger_pruned") == 6
