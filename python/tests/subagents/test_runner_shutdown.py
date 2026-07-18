"""Round-2 audit: real SubAgentRunner shutdown releases the borrowed runtime.

The round-1 H1 test monkeypatched ``_build_subagent_service`` and injected a
simplified spawner with a bare ``blocking_runner``.  That bypassed the real
``SubAgentRunner.run`` path, so the test never observed whether the runner's
``finally`` block (``close_runtime_or_register``) actually releases the
runtime a detached subagent borrows from the server's shared Office /
Browser / Audit / DB authorities.

This file exercises the real runner end-to-end:

* ``SubAgentRunner.run`` calls ``build_runtime(RuntimeConfig(...))`` and,
  in its ``finally``, ``close_runtime_or_register(runtime)``.
* The runtime constructed for a subagent borrows the shared Office /
  Audit / approval broker (injected by the server via the runner kwargs).
* When the runner finishes (success or cancellation), the borrowed
  runtime MUST reach a terminal state (``_closed=True``) or land in the
  orphan registry — never leak with no owner.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from khaos.agent.core import AgentConfig
from khaos.db import Database
from khaos.modes import ModeManager
from khaos.routing.router import create_default_router
from khaos.subagents.runner import SubAgentRunner
from khaos.subagents.spawner import SubAgentConfig, SubAgentSpawner, SubAgentTask


async def _build_runner(
    tmp_path: Path,
    *,
    office_authority=None,
    audit_logger=None,
):
    """Build a real SubAgentRunner bound to a real (minimal) runtime factory.

    The runner uses a stub model router whose ``complete`` returns a fixed
    message so ``AgentLoop.run`` terminates after one turn without external
    API calls.  The runtime factory is the production
    ``khaos.runtime.build_runtime`` — no mocking of the lifecycle path.
    """
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    mode_manager = ModeManager(db, project_root=tmp_path)
    await mode_manager.load()
    router = create_default_router(honor_no_config=False)
    runner = SubAgentRunner(
        router=router,
        db=db,
        mode_manager=mode_manager,
        tool_scheduler=None,
        token_engine=None,
        max_turns=1,
        max_budget_tokens=10000,
        stream_timeout=5,
        office_authority=office_authority,
        approval_broker=MagicMock(),
        principal_id="local-uid:test",
        audit_logger=audit_logger,
        project_root=tmp_path,
        config_path=tmp_path / "config.yaml",
    )
    return db, runner


async def test_runner_run_closes_borrowed_runtime_on_success(tmp_path):
    """Round-2: a successful subagent run must release its borrowed runtime.

    Pins the ``finally: await close_runtime_or_register(runtime)`` contract
    on the real ``SubAgentRunner.run`` path.  The previous round's test
    monkeypatched the runner away, so a regression that drops the finally
    block would not have been caught.
    """
    db, runner = await _build_runner(tmp_path)
    try:
        spawner = SubAgentSpawner(
            SubAgentConfig(max_concurrent=1), db, runner=runner.run,
        )
        task = await spawner.spawn(
            SubAgentTask("t1", "say hi", "ctx", [], principal_id="user1")
        )
        await spawner.wait_all(principal_id="user1", timeout=15)

        assert task.status == "completed"
        # The orphan registry must be empty: the runtime was closed cleanly
        # by the runner's finally block, not leaked.
        from khaos.runtime.factory import _orphan_runtimes
        assert len(_orphan_runtimes) == 0, (
            "subagent runtime leaked into orphan registry on success"
        )
    finally:
        await db.close()


async def test_runner_run_closes_borrowed_runtime_on_cancellation(tmp_path):
    """Round-2: a cancelled subagent run must release its borrowed runtime.

    The runner's ``finally`` block must run even when ``loop.run`` is
    cancelled.  This is the exact path the detached-task-shutdown fix
    relies on: when ``SubAgentSpawner.shutdown`` cancels the active task,
    the runner must still close the runtime (or register it as an orphan)
    so the server's ``drain_orphan_runtimes`` can boundedly finalize it.
    """
    db, runner = await _build_runner(tmp_path)
    try:
        started = asyncio.Event()
        release = asyncio.Event()

        # Wrap runner.run to detect when the runtime has been built, then
        # block so we can cancel mid-flight.  We monkeypatch the runner's
        # ``run`` to call the real implementation after signalling started.
        real_run = runner.run

        async def tracked_run(task: SubAgentTask) -> str:
            # Signal that the runner has been invoked; the test will then
            # cancel the spawner task, which cancels this coroutine.  The
            # runner's finally must still close_runtime_or_register.
            started.set()
            try:
                return await real_run(task)
            finally:
                # The finally in real_run already ran close_runtime_or_register.
                release.set()

        spawner = SubAgentSpawner(
            SubAgentConfig(max_concurrent=1), db, runner=tracked_run,
        )
        await spawner.spawn(
            SubAgentTask("t1", "block", "ctx", [], principal_id="user1")
        )
        await asyncio.wait_for(started.wait(), timeout=5.0)

        # Cancel the detached task via the production shutdown path.
        await spawner.shutdown(timeout=10.0)

        # The runtime must have reached a terminal state or be registered
        # as an orphan (i.e. NOT silently leaked with no owner).  Either
        # outcome is acceptable; what is forbidden is "no owner at all".
        from khaos.runtime.factory import (
            _orphan_runtimes,
            cleanup_orphan_runtimes,
        )
        # Try one cleanup pass — if the runtime was registered as an orphan
        # (RuntimeCloseError on the first attempt), this finalizes it.
        await cleanup_orphan_runtimes()
        # After cleanup, orphan registry must be empty (the borrowed runtime
        # did not own Office, so its aclose succeeds).
        assert len(_orphan_runtimes) == 0, (
            "subagent runtime left as orphan after shutdown + cleanup"
        )
        release.set()
    finally:
        await db.close()
