"""M4 Batch 3.1.16B-3 — Audit Closure + Tool Surface + Closure Matrix.

Acceptance tests for the audit logging, tool surface transparency,
and quarantined-task cleanup added in B-3:

  1.  ``CronEngine`` accepts an ``audit_logger`` parameter.
  2.  ``_quarantine_drifted_task`` writes an audit log entry with
      ``action="security:scheduler_drift_quarantine"``.
  3.  Audit log entry captures the task and engine snapshots (so an
      admin can see what drifted).
  4.  Audit write failure does NOT block the quarantine (audit is
      best-effort, quarantine is safety-critical).
  5.  ``cron_list`` exposes ``error`` (so quarantined tasks surface
      their drift reason).
  6.  ``cron_list`` exposes truncated ``policy_digest_prefix`` (8
      chars — enough for debugging, not enough to reconstruct the
      full fingerprint).
  7.  ``engine.remove`` allows removing a quarantined task (FAILED
      with ``error.startswith("quarantined:")``).
  8.  ``engine.remove`` still rejects a natural FAILED task (no
      ``quarantined:`` prefix).
  9.  ``cron_remove`` tool returns ``removed`` for a quarantined task.
  10. End-to-end: drift → quarantine → audit log → cron_list shows
      error → cron_remove clears it.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

from khaos.audit import AuditLogger
from khaos.db import Database
from khaos.scheduler import CronEngine, ScheduleConfig, TaskStatus
from khaos.scheduler.engine import CronEngineState
from khaos.tools import cron_tools


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


async def _make_db(path) -> Database:
    p = Path(path)
    if p.is_dir() or (not p.exists() and not p.name.endswith(".db")):
        p = p / "khaos.db"
    db = Database(p)
    await db.connect()
    await db.run_migrations()
    return db


async def _execute_noop(task_id: str, prompt: str, principal_id: str = "") -> str:
    """No-op executor for testing — returns the prompt unchanged."""
    return prompt


def _make_engine(
    db, *,
    project_id: str = "",
    policy_digest: str = "",
    audit_logger: AuditLogger | None = None,
    tick_interval: float = 999.0,
) -> CronEngine:
    """Construct a CronEngine with a long tick interval."""
    return CronEngine(
        db=db,
        executor=_execute_noop,
        tick_interval=tick_interval,
        project_id=project_id,
        policy_digest=policy_digest,
        audit_logger=audit_logger,
    )


async def _force_cleanup_engine(engine: CronEngine) -> None:
    """Force-stop an engine."""
    engine._running = False
    engine._lifecycle_state = CronEngineState.STOPPED
    if engine._loop_task and not engine._loop_task.done():
        engine._loop_task.cancel()
        try:
            await engine._loop_task
        except asyncio.CancelledError:
            pass
    for task in list(engine._execute_tasks.values()):
        if not task.done():
            task.cancel()
            try:
                await asyncio.wait_for(task, timeout=1.0)
            except (asyncio.CancelledError, asyncio.TimeoutError, Exception):
                pass
    engine._execute_tasks.clear()
    engine._pending_persistence.clear()
    engine._persistence_owners.clear()


async def _make_audit_logger(db, *, principal_id: str = "local-uid:0") -> AuditLogger:
    """Construct an AuditLogger for testing."""
    return AuditLogger(
        db,
        log_path=None,  # in-memory only (no file)
        principal_id=principal_id,
        policy_digest="sha256:test-policy",
    )


# ---------------------------------------------------------------------------
# 1-4. Audit logging
# ---------------------------------------------------------------------------


async def test_acceptance_1_engine_accepts_audit_logger_param(tmp_path):
    """B3-1: ``CronEngine`` accepts an ``audit_logger`` parameter."""
    db = await _make_db(tmp_path)
    audit_logger = await _make_audit_logger(db)
    engine = _make_engine(
        db, project_id="proj-x", policy_digest="sha256:test",
        audit_logger=audit_logger,
    )
    assert engine._audit_logger is audit_logger, (
        "engine must store the audit_logger passed at construction"
    )
    await db.close()


async def test_acceptance_2_quarantine_writes_audit_entry(tmp_path):
    """B3-2: ``_quarantine_drifted_task`` writes an audit log entry
    with ``action="security:scheduler_drift_quarantine"``."""
    db = await _make_db(tmp_path)
    audit_logger = await _make_audit_logger(db)
    # Create a task under policy A.
    task_id = await db.insert_scheduled_task(
        name="drifted task", prompt="hello", status="pending",
        schedule=ScheduleConfig(cron="0 9"), deliver_to="local", meta={},
        principal_id="alice",
        project_id="proj-x", policy_digest="sha256:policy-a",
    )
    # Start an engine under policy B with the audit logger injected.
    engine = _make_engine(
        db, project_id="proj-x", policy_digest="sha256:policy-b",
        audit_logger=audit_logger,
    )
    try:
        await engine.start()
        # Verify the audit log has the drift quarantine entry.
        entries = await audit_logger.query(action="security:scheduler_drift_quarantine")
        assert len(entries) == 1, (
            f"expected 1 drift quarantine audit entry, got {len(entries)}"
        )
        entry = entries[0]
        assert entry.task_id == task_id, (
            "audit entry must reference the quarantined task_id"
        )
        assert "drift" in (entry.target or ""), (
            f"audit entry target must mention drift, got {entry.target!r}"
        )
    finally:
        await _force_cleanup_engine(engine)
        await db.close()


async def test_acceptance_3_audit_entry_captures_snapshots(tmp_path):
    """B3-3: audit log entry captures the task and engine snapshots
    (so an admin can see what drifted).

    H-02 (round-4 review): ``_load_tasks`` now scopes by ``project_id``
    (primary defense) — a cross-project task is excluded at read time
    and never reaches ``start()``'s drift check.  This test uses the
    canonical drift scenario: SAME project, DIFFERENT policy_digest
    (``khaos_policy.yaml`` edited between runs).  The task is loaded
    (same project) and the drift check fires on ``policy_digest``.
    """
    db = await _make_db(tmp_path)
    audit_logger = await _make_audit_logger(db)
    task_id = await db.insert_scheduled_task(
        name="drifted task", prompt="hello", status="pending",
        schedule=ScheduleConfig(cron="0 9"), deliver_to="local", meta={},
        principal_id="alice",
        project_id="proj-engine",  # MATCHING project_id (canonical drift)
        policy_digest="sha256:task-digest",  # DIFFERENT policy_digest
    )
    engine = _make_engine(
        db, project_id="proj-engine", policy_digest="sha256:engine-digest",
        audit_logger=audit_logger,
    )
    try:
        await engine.start()
        entries = await audit_logger.query(action="security:scheduler_drift_quarantine")
        assert len(entries) == 1
        entry = entries[0]
        # The detail dict must capture both snapshots for forensic analysis.
        detail = entry.detail or {}
        assert detail.get("task_policy_digest") == "sha256:task-digest", (
            f"audit detail must capture task_policy_digest, got {detail.get('task_policy_digest')!r}"
        )
        assert detail.get("engine_policy_digest") == "sha256:engine-digest", (
            f"audit detail must capture engine_policy_digest, got {detail.get('engine_policy_digest')!r}"
        )
        assert detail.get("task_project_id") == "proj-engine", (
            f"audit detail must capture task_project_id, got {detail.get('task_project_id')!r}"
        )
        assert detail.get("engine_project_id") == "proj-engine", (
            f"audit detail must capture engine_project_id, got {detail.get('engine_project_id')!r}"
        )
        assert detail.get("task_id") == task_id
        assert detail.get("principal_id") == "alice"
    finally:
        await _force_cleanup_engine(engine)
        await db.close()


async def test_acceptance_4_audit_failure_doesnt_block_quarantine(tmp_path):
    """B3-4: audit write failure does NOT block the quarantine (audit
    is best-effort, quarantine is safety-critical)."""
    db = await _make_db(tmp_path)
    # Create an audit logger whose log_security_event raises.
    class FailingAuditLogger:
        async def log_security_event(self, **kwargs):
            raise RuntimeError("simulated audit log failure")

        async def query(self, **kwargs):
            return []

    failing_logger = FailingAuditLogger()
    task_id = await db.insert_scheduled_task(
        name="drifted task", prompt="hello", status="pending",
        schedule=ScheduleConfig(cron="0 9"), deliver_to="local", meta={},
        principal_id="alice",
        project_id="proj-x", policy_digest="sha256:policy-a",
    )
    engine = _make_engine(
        db, project_id="proj-x", policy_digest="sha256:policy-b",
        audit_logger=failing_logger,
    )
    try:
        # Must NOT raise — audit failure is swallowed.
        await engine.start()
        # The task must still be quarantined despite the audit failure.
        task = engine._tasks.get(task_id)
        assert task is not None
        assert task.status == TaskStatus.FAILED, (
            f"quarantine must proceed despite audit failure, got {task.status}"
        )
        assert task.error is not None
        assert "quarantined:" in task.error
    finally:
        await _force_cleanup_engine(engine)
        await db.close()


# ---------------------------------------------------------------------------
# 5-6. cron_list tool surface
# ---------------------------------------------------------------------------


async def test_acceptance_5_cron_list_exposes_error(tmp_path):
    """B3-5: ``cron_list`` exposes ``error`` (so quarantined tasks
    surface their drift reason)."""
    db = await _make_db(tmp_path)
    # Inject the cron engine into the tool module.
    engine = _make_engine(
        db, project_id="proj-x", policy_digest="sha256:policy-b",
    )
    cron_tools.set_cron_engine(engine)
    try:
        await engine.start()
        # Create a task under policy A (different from engine's policy B).
        # Use insert_scheduled_task to bypass the engine's stamping.
        await db.insert_scheduled_task(
            name="drifted task", prompt="hello", status="pending",
            schedule=ScheduleConfig(cron="0 9"), deliver_to="local", meta={},
            principal_id="alice",
            project_id="proj-x", policy_digest="sha256:policy-a",
        )
        # Force a reload so the task appears in the engine's _tasks.
        await engine._load_tasks()
        # Quarantine it manually (simulating what start() would do).
        for task in list(engine._tasks.values()):
            drift_reason = engine._check_snapshot_drift(task)
            if drift_reason is not None:
                await engine._quarantine_drifted_task(task, drift_reason)
        # Call cron_list — the error field must be present.
        result = await cron_tools.cron_list(principal_id="alice")
        assert "tasks" in result
        assert len(result["tasks"]) == 1
        task_dict = result["tasks"][0]
        assert "error" in task_dict, "cron_list must expose the error field"
        assert task_dict["error"] is not None
        assert "quarantined:" in task_dict["error"], (
            f"error must mention quarantine, got {task_dict['error']!r}"
        )
    finally:
        await _force_cleanup_engine(engine)
        cron_tools.set_cron_engine(None)
        await db.close()


async def test_acceptance_6_cron_list_exposes_truncated_digest(tmp_path):
    """B3-6: ``cron_list`` exposes truncated ``policy_digest_prefix``
    (8 chars — enough for debugging, not enough to reconstruct the
    full fingerprint)."""
    db = await _make_db(tmp_path)
    engine = _make_engine(
        db, project_id="proj-1234567890", policy_digest="sha256:abcdefghijklmnop",
    )
    cron_tools.set_cron_engine(engine)
    try:
        await engine.start()
        task = await engine.create(
            "truncation test", "hello", ScheduleConfig(cron="0 9"),
            principal_id="alice",
        )
        result = await cron_tools.cron_list(principal_id="alice")
        assert len(result["tasks"]) == 1
        task_dict = result["tasks"][0]
        assert task_dict["policy_digest_prefix"] == "sha256:a", (
            f"policy_digest_prefix must be truncated to 8 chars, got "
            f"{task_dict['policy_digest_prefix']!r}"
        )
        assert task_dict["project_id_prefix"] == "proj-123", (
            f"project_id_prefix must be truncated to 8 chars, got "
            f"{task_dict['project_id_prefix']!r}"
        )
        # Verify the full digest is NOT exposed.
        full_digest = task.policy_digest
        assert task_dict["policy_digest_prefix"] != full_digest, (
            "full policy_digest must NOT be exposed in cron_list"
        )
    finally:
        await _force_cleanup_engine(engine)
        cron_tools.set_cron_engine(None)
        await db.close()


# ---------------------------------------------------------------------------
# 7-9. Quarantined task cleanup
# ---------------------------------------------------------------------------


async def test_acceptance_7_remove_allows_quarantined_task(tmp_path):
    """B3-7: ``engine.remove`` allows removing a quarantined task
    (FAILED with ``error.startswith("quarantined:")``)."""
    db = await _make_db(tmp_path)
    task_id = await db.insert_scheduled_task(
        name="drifted task", prompt="hello", status="pending",
        schedule=ScheduleConfig(cron="0 9"), deliver_to="local", meta={},
        principal_id="alice",
        project_id="proj-x", policy_digest="sha256:policy-a",
    )
    engine = _make_engine(
        db, project_id="proj-x", policy_digest="sha256:policy-b",
    )
    try:
        await engine.start()
        # Verify the task was quarantined.
        task = engine._tasks.get(task_id)
        assert task is not None
        assert task.status == TaskStatus.FAILED
        assert task.error is not None
        assert task.error.startswith("quarantined:")
        # Remove it — should succeed (return "ok").
        result = await engine.remove(task_id, principal_id="alice")
        assert result == "ok", (
            f"quarantined task must be removable, got {result!r}"
        )
        # Task must be popped from _tasks.
        assert task_id not in engine._tasks, (
            "quarantined task must be popped from _tasks after removal"
        )
    finally:
        await _force_cleanup_engine(engine)
        await db.close()


async def test_acceptance_8_remove_rejects_natural_failed_task(tmp_path):
    """B3-8: ``engine.remove`` still rejects a natural FAILED task
    (no ``quarantined:`` prefix)."""
    db = await _make_db(tmp_path)
    engine = _make_engine(
        db, project_id="proj-x", policy_digest="sha256:policy-a",
    )
    try:
        await engine.start()
        task = await engine.create(
            "natural fail", "hello", ScheduleConfig(cron="0 9"),
            principal_id="alice",
        )
        # Manually mark the task as FAILED with a non-quarantine error.
        task.status = TaskStatus.FAILED
        task.error = "executor raised RuntimeError: boom"
        # Remove must reject (return "invalid_state").
        result = await engine.remove(task.id, principal_id="alice")
        assert result == "invalid_state", (
            f"natural FAILED task must NOT be removable, got {result!r}"
        )
    finally:
        await _force_cleanup_engine(engine)
        await db.close()


async def test_acceptance_9_cron_remove_tool_clears_quarantined(tmp_path):
    """B3-9: ``cron_remove`` tool returns ``removed`` for a
    quarantined task."""
    db = await _make_db(tmp_path)
    engine = _make_engine(
        db, project_id="proj-x", policy_digest="sha256:policy-b",
    )
    cron_tools.set_cron_engine(engine)
    try:
        await engine.start()
        task_id = await db.insert_scheduled_task(
            name="drifted task", prompt="hello", status="pending",
            schedule=ScheduleConfig(cron="0 9"), deliver_to="local", meta={},
            principal_id="alice",
            project_id="proj-x", policy_digest="sha256:policy-a",
        )
        # Force load + quarantine.
        await engine._load_tasks()
        for task in list(engine._tasks.values()):
            drift_reason = engine._check_snapshot_drift(task)
            if drift_reason is not None:
                await engine._quarantine_drifted_task(task, drift_reason)
        # Call cron_remove — should return "removed".
        result = await cron_tools.cron_remove(task_id, principal_id="alice")
        assert result["status"] == "removed", (
            f"cron_remove must return 'removed' for quarantined task, got {result}"
        )
    finally:
        await _force_cleanup_engine(engine)
        cron_tools.set_cron_engine(None)
        await db.close()


# ---------------------------------------------------------------------------
# 10. End-to-end: drift → quarantine → audit → list → remove
# ---------------------------------------------------------------------------


async def test_acceptance_10_end_to_end_drift_quarantine_audit_list_remove(tmp_path):
    """B3-10: end-to-end — drift → quarantine → audit log → cron_list
    shows error → cron_remove clears it."""
    db = await _make_db(tmp_path)
    audit_logger = await _make_audit_logger(db)
    # Run 1: create a task under policy A.
    engine_a = _make_engine(
        db, project_id="proj-x", policy_digest="sha256:policy-a-v1",
    )
    try:
        await engine_a.start()
        task = await engine_a.create(
            "e2e drift", "hello", ScheduleConfig(cron="0 9"),
            principal_id="alice",
        )
        task_id = task.id
    finally:
        await _force_cleanup_engine(engine_a)

    # Run 2: start a NEW engine under policy B with audit logging.
    engine_b = _make_engine(
        db, project_id="proj-x", policy_digest="sha256:policy-b-v2",
        audit_logger=audit_logger,
    )
    cron_tools.set_cron_engine(engine_b)
    try:
        await engine_b.start()
        # Step 1: verify the task was quarantined.
        task = engine_b._tasks.get(task_id)
        assert task is not None
        assert task.status == TaskStatus.FAILED
        assert task.error is not None
        assert "quarantined:" in task.error

        # Step 2: verify the audit log captured the quarantine.
        entries = await audit_logger.query(action="security:scheduler_drift_quarantine")
        assert len(entries) == 1
        assert entries[0].task_id == task_id

        # Step 3: cron_list shows the error.
        listing = await cron_tools.cron_list(principal_id="alice")
        assert len(listing["tasks"]) == 1
        listed = listing["tasks"][0]
        assert listed["status"] == "failed"
        assert listed["error"] is not None
        assert "quarantined:" in listed["error"]

        # Step 4: cron_remove clears it.
        result = await cron_tools.cron_remove(task_id, principal_id="alice")
        assert result["status"] == "removed"

        # Step 5: cron_list now shows 0 tasks.
        listing = await cron_tools.cron_list(principal_id="alice")
        assert len(listing["tasks"]) == 0, (
            "task must be cleared from cron_list after removal"
        )
    finally:
        await _force_cleanup_engine(engine_b)
        cron_tools.set_cron_engine(None)
        await db.close()
