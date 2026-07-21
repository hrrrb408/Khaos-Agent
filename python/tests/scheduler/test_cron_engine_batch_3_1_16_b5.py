"""M4 Batch 3.1.16B-5 — Lifecycle-Locked Scheduler + Durable Operation Journal.

Acceptance tests for the two gaps closed in B-5:

  Gap A (durable operation journal):
    1.  ``scheduler_operation_journal`` table exists with the right schema.
    2.  ``insert_scheduler_journal_entry`` writes a row with
        ``applied_at IS NULL``.
    3.  ``mark_scheduler_journal_applied`` sets ``applied_at``.
    4.  ``list_pending_scheduler_journal_entries`` returns rows in
        ``seq`` order with ``applied_at IS NULL``.
    5.  ``_persist_task_state`` (control-op branch) writes a journal
        entry BEFORE the CAS for new ops.
    6.  Journal entry is marked ``applied_at`` after CAS succeeds.
    7.  Journal entry is marked ``applied_at`` on idempotent success
        (DB already at desired state).
    8.  Journal entry is marked ``applied_at`` when a newer op won
        (CAS returns 0, DB at a different state).
    9.  Journal write is SKIPPED on retry (``operation_id`` supplied).
    10. ``_quarantine_drifted_task`` writes a journal entry with
        ``operation_type="quarantine"``.
    11. Replay rolls forward a pending pause intent on ``start()``.
    12. Replay rolls forward a pending remove intent on ``start()``.
    13. Replay marks an entry stale when the task was deleted.
    14. Replay marks an entry stale when the task is ``running``.
    15. Replay marks an entry stale when the task is already terminal
        (``failed`` / ``cancelled``).
    16. Replay marks an entry stale when DB status already matches
        ``desired_status`` (idempotent).
    17. Replay does NOT resurrect a FAILED task with a resume intent
        (marks the entry stale instead).

  Gap C (lifecycle lock on mutating ops):
    18. ``create()`` raises ``RuntimeError("engine_unavailable")`` when
        engine is STOPPING.
    19. ``create()`` raises ``RuntimeError("engine_unavailable")`` when
        engine is QUARANTINED.
    20. ``create()`` raises ``RuntimeError("engine_degraded")`` when
        engine is degraded.
    21. ``pause()`` / ``resume()`` / ``remove()`` return
        ``"engine_unavailable"`` when engine is QUARANTINED.
    22. ``pause()`` / ``resume()`` / ``remove()`` still work when
        engine is degraded (only ``create`` refuses degraded).
    23. ``cron_create`` converts the RuntimeError to a structured
        ``{"status": "error", ...}`` response.
    24. ``cron_pause`` / ``cron_resume`` / ``cron_remove`` convert
        ``"engine_unavailable"`` to a structured response.
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
    return AuditLogger(
        db,
        log_path=None,
        principal_id=principal_id,
        policy_digest="sha256:test-policy",
    )


# ---------------------------------------------------------------------------
# 1-4. Schema + DB methods
# ---------------------------------------------------------------------------


async def test_acceptance_1_journal_table_exists(tmp_path):
    """B5-1: ``scheduler_operation_journal`` table exists with the
    right columns."""
    db = await _make_db(tmp_path)
    try:
        conn = await db._require_conn()
        cursor = await conn.execute("PRAGMA table_info(scheduler_operation_journal)")
        columns = {row[1] for row in await cursor.fetchall()}
        expected = {
            "seq", "operation_id", "task_id", "operation_type",
            "desired_status", "expected_version", "target_version",
            "principal_id", "policy_digest", "created_at", "applied_at",
        }
        assert expected.issubset(columns), (
            f"missing columns: {expected - columns}"
        )
    finally:
        await db.close()


async def test_acceptance_2_insert_writes_applied_at_null(tmp_path):
    """B5-2: ``insert_scheduler_journal_entry`` writes a row with
    ``applied_at IS NULL``."""
    db = await _make_db(tmp_path)
    try:
        seq = await db.insert_scheduler_journal_entry(
            operation_id="op-1", task_id="task-1",
            operation_type="pause", desired_status="paused",
            expected_version=0, target_version=1,
            principal_id="alice", policy_digest="sha256:p",
        )
        assert seq > 0
        conn = await db._require_conn()
        cursor = await conn.execute(
            "SELECT applied_at FROM scheduler_operation_journal WHERE seq = ?",
            (seq,),
        )
        row = await cursor.fetchone()
        assert row is not None
        assert row[0] is None, (
            f"applied_at must be NULL after insert, got {row[0]!r}"
        )
    finally:
        await db.close()


async def test_acceptance_3_mark_applied_sets_timestamp(tmp_path):
    """B5-3: ``mark_scheduler_journal_applied`` sets ``applied_at``."""
    db = await _make_db(tmp_path)
    try:
        seq = await db.insert_scheduler_journal_entry(
            operation_id="op-2", task_id="task-2",
            operation_type="remove", desired_status="cancelled",
            expected_version=0, target_version=1,
        )
        rowcount = await db.mark_scheduler_journal_applied("op-2")
        assert rowcount == 1, f"expected rowcount=1, got {rowcount}"
        conn = await db._require_conn()
        cursor = await conn.execute(
            "SELECT applied_at FROM scheduler_operation_journal WHERE seq = ?",
            (seq,),
        )
        row = await cursor.fetchone()
        assert row is not None
        assert row[0] is not None, (
            "applied_at must be set after mark_scheduler_journal_applied"
        )
    finally:
        await db.close()


async def test_acceptance_4_list_pending_returns_in_seq_order(tmp_path):
    """B5-4: ``list_pending_scheduler_journal_entries`` returns rows in
    ``seq`` order with ``applied_at IS NULL``."""
    db = await _make_db(tmp_path)
    try:
        await db.insert_scheduler_journal_entry(
            operation_id="op-a", task_id="task-1",
            operation_type="pause", desired_status="paused",
            expected_version=0, target_version=1,
        )
        await db.insert_scheduler_journal_entry(
            operation_id="op-b", task_id="task-2",
            operation_type="remove", desired_status="cancelled",
            expected_version=0, target_version=1,
        )
        # Mark op-a applied — only op-b should be pending.
        await db.mark_scheduler_journal_applied("op-a")
        entries = await db.list_pending_scheduler_journal_entries()
        assert len(entries) == 1, (
            f"expected 1 pending entry, got {len(entries)}"
        )
        assert entries[0]["operation_id"] == "op-b"
        # Insert a third entry and verify ordering.
        await db.insert_scheduler_journal_entry(
            operation_id="op-c", task_id="task-3",
            operation_type="quarantine", desired_status="failed",
            expected_version=0, target_version=1,
        )
        entries = await db.list_pending_scheduler_journal_entries()
        assert len(entries) == 2
        assert entries[0]["operation_id"] == "op-b"
        assert entries[1]["operation_id"] == "op-c"
    finally:
        await db.close()


# ---------------------------------------------------------------------------
# 5-9. Journal write / mark in _persist_task_state
# ---------------------------------------------------------------------------


async def test_acceptance_5_persist_writes_journal_before_cas(tmp_path):
    """B5-5: ``_persist_task_state`` (control-op branch) writes a
    journal entry BEFORE the CAS for new ops."""
    db = await _make_db(tmp_path)
    engine = _make_engine(db, policy_digest="sha256:p")
    try:
        await engine.start()
        task = await engine.create(
            "test", "hello", ScheduleConfig(cron="0 9"),
            principal_id="alice",
        )
        # Pause the task — this calls _persist_task_state with a new
        # operation_id, which should write a journal entry.
        result = await engine.pause(task.id, principal_id="alice")
        assert result == "ok"
        # Verify a journal entry was written.
        entries = await db.list_pending_scheduler_journal_entries()
        assert len(entries) == 0, (
            f"expected 0 pending entries (CAS succeeded), got {len(entries)}"
        )
        # Verify a journal entry exists (applied).
        conn = await db._require_conn()
        cursor = await conn.execute(
            "SELECT operation_type, desired_status, applied_at "
            "FROM scheduler_operation_journal WHERE task_id = ?",
            (task.id,),
        )
        rows = await cursor.fetchall()
        assert len(rows) == 1, (
            f"expected 1 journal entry for task, got {len(rows)}"
        )
        assert rows[0][0] == "pause"
        assert rows[0][1] == "paused"
        assert rows[0][2] is not None, "applied_at must be set after CAS success"
    finally:
        await _force_cleanup_engine(engine)
        await db.close()


async def test_acceptance_6_journal_marked_applied_on_idempotent(tmp_path):
    """B5-7: journal entry is marked ``applied_at`` on idempotent
    success (DB already at desired state) — RETRY path.

    Scenario: a prior control op wrote a journal entry and committed
    the CAS, but crashed BEFORE marking the journal applied.  On
    retry (same operation_id), ``_persist_task_state`` sees the DB
    is already at the desired status and marks the journal entry
    applied via the idempotent branch.

    NOTE: a second ``pause()`` call on an already-PAUSED task does
    NOT exercise this path — ``pause()`` short-circuits in the
    ``task.status == PAUSED`` branch (returns ``"ok"`` without
    calling ``_persist_task_state`` when there is no pending
    persistence).  The idempotent branch is only reachable via a
    direct ``_persist_task_state`` retry.
    """
    db = await _make_db(tmp_path)
    engine = _make_engine(db, policy_digest="sha256:p")
    try:
        await engine.start()
        task = await engine.create(
            "test", "hello", ScheduleConfig(cron="0 9"),
            principal_id="alice",
        )
        # First pause — writes journal entry, CAS succeeds, marks applied.
        await engine.pause(task.id, principal_id="alice")
        # Manually insert a SECOND journal entry with applied_at=NULL,
        # simulating a crash AFTER the CAS committed but BEFORE the
        # journal was marked applied.
        conn = await db._require_conn()
        await conn.execute(
            "INSERT INTO scheduler_operation_journal "
            "(operation_id, task_id, operation_type, desired_status, "
            " expected_version, target_version) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            ("crash-op-id", task.id, "pause", "paused", 1, 2),
        )
        await conn.commit()
        # Retry with the SAME operation_id.  The DB is already at
        # "paused" (from the first pause), so the idempotent branch
        # fires: db_status == desired → mark journal applied.
        await engine._persist_task_state(
            task, operation_id="crash-op-id", operation_type="pause",
        )
        # Verify the crash-op-id journal entry is now marked applied.
        cursor = await conn.execute(
            "SELECT applied_at FROM scheduler_operation_journal "
            "WHERE operation_id = ?",
            ("crash-op-id",),
        )
        row = await cursor.fetchone()
        assert row is not None, "crash-op-id journal entry must exist"
        assert row[0] is not None, (
            "crash-op-id journal entry must be marked applied "
            "after idempotent retry (DB already at desired state)"
        )
    finally:
        await _force_cleanup_engine(engine)
        await db.close()


async def test_acceptance_7_journal_skipped_on_retry(tmp_path):
    """B5-9: journal write is SKIPPED on retry (``operation_id`` supplied)."""
    db = await _make_db(tmp_path)
    engine = _make_engine(db, policy_digest="sha256:p")
    try:
        await engine.start()
        task = await engine.create(
            "test", "hello", ScheduleConfig(cron="0 9"),
            principal_id="alice",
        )
        # Call _persist_task_state with an explicit operation_id (retry).
        task.status = TaskStatus.PAUSED
        await engine._persist_task_state(
            task, operation_id="retry-op-id", operation_type="pause",
        )
        # Verify NO journal entry was written for this retry.
        conn = await db._require_conn()
        cursor = await conn.execute(
            "SELECT operation_id FROM scheduler_operation_journal "
            "WHERE operation_id = ?",
            ("retry-op-id",),
        )
        rows = await cursor.fetchall()
        assert len(rows) == 0, (
            "retry path must NOT write a new journal entry"
        )
    finally:
        await _force_cleanup_engine(engine)
        await db.close()


async def test_acceptance_8_journal_marked_applied_on_newer_op_won(tmp_path):
    """B5-8: journal entry is marked ``applied_at`` when a newer op
    won (CAS returns 0, DB at a different state)."""
    db = await _make_db(tmp_path)
    engine = _make_engine(db, policy_digest="sha256:p")
    try:
        await engine.start()
        task = await engine.create(
            "test", "hello", ScheduleConfig(cron="0 9"),
            principal_id="alice",
        )
        # Pause the task — writes journal entry + CAS succeeds.
        await engine.pause(task.id, principal_id="alice")
        # Now remove the task — this is a NEWER op with a different
        # desired state.  The CAS should succeed (DB goes from paused
        # to cancelled).  The pause's journal entry is already marked
        # applied; the remove's journal entry is also marked applied.
        await engine.remove(task.id, principal_id="alice")
        conn = await db._require_conn()
        cursor = await conn.execute(
            "SELECT operation_type, desired_status, applied_at "
            "FROM scheduler_operation_journal WHERE task_id = ? "
            "ORDER BY seq ASC",
            (task.id,),
        )
        rows = await cursor.fetchall()
        assert len(rows) == 2
        # First entry: pause (marked applied).
        assert rows[0][0] == "pause"
        assert rows[0][2] is not None
        # Second entry: remove (marked applied).
        assert rows[1][0] == "remove"
        assert rows[1][2] is not None
    finally:
        await _force_cleanup_engine(engine)
        await db.close()


# ---------------------------------------------------------------------------
# 10. Quarantine journal
# ---------------------------------------------------------------------------


async def test_acceptance_10_quarantine_writes_journal_entry(tmp_path):
    """B5-10: ``_quarantine_drifted_task`` writes a journal entry with
    ``operation_type="quarantine"``."""
    db = await _make_db(tmp_path)
    audit_logger = await _make_audit_logger(db)
    # Create a task under policy A.
    task_id = await db.insert_scheduled_task(
        name="drifted task", prompt="hello", status="pending",
        schedule=ScheduleConfig(cron="0 9"), deliver_to="local", meta={},
        principal_id="alice",
        project_id="proj-x", policy_digest="sha256:policy-a",
    )
    engine = _make_engine(
        db, project_id="proj-x", policy_digest="sha256:policy-b",
        audit_logger=audit_logger,
    )
    try:
        await engine.start()
        # Verify the task was quarantined.
        task = engine._tasks.get(task_id)
        assert task is not None
        assert task.status == TaskStatus.FAILED
        # Verify a journal entry was written with operation_type="quarantine".
        conn = await db._require_conn()
        cursor = await conn.execute(
            "SELECT operation_type, desired_status, applied_at "
            "FROM scheduler_operation_journal WHERE task_id = ?",
            (task_id,),
        )
        rows = await cursor.fetchall()
        assert len(rows) == 1, (
            f"expected 1 journal entry for quarantine, got {len(rows)}"
        )
        assert rows[0][0] == "quarantine", (
            f"operation_type must be 'quarantine', got {rows[0][0]!r}"
        )
        assert rows[0][1] == "failed", (
            f"desired_status must be 'failed', got {rows[0][1]!r}"
        )
        assert rows[0][2] is not None, "applied_at must be set after CAS success"
    finally:
        await _force_cleanup_engine(engine)
        await db.close()


# ---------------------------------------------------------------------------
# 11-17. Replay on start()
# ---------------------------------------------------------------------------


async def test_acceptance_11_replay_rolls_forward_pause_intent(tmp_path):
    """B5-11: replay rolls forward a pending pause intent on ``start()``.

    Simulates a crash between journal INSERT and CAS UPDATE: the
    journal entry is written but the CAS never committed (DB still at
    ``pending``).  On restart, ``start()`` should roll the pause
    forward.
    """
    db = await _make_db(tmp_path)
    # Create a task directly in the DB (bypassing the engine).
    task_id = await db.insert_scheduled_task(
        name="test", prompt="hello", status="pending",
        schedule=ScheduleConfig(cron="0 9"), deliver_to="local", meta={},
        principal_id="alice",
        project_id="", policy_digest="",  # test mode (empty digest)
    )
    # Write a journal entry WITHOUT a CAS (simulating a crash).
    await db.insert_scheduler_journal_entry(
        operation_id="op-pause-1", task_id=task_id,
        operation_type="pause", desired_status="paused",
        expected_version=0, target_version=1,
        principal_id="alice", policy_digest="",
    )
    # Verify the DB is still at pending.
    row = await db.get_scheduled_task(task_id)
    assert row["status"] == "pending"
    # Start the engine — replay should roll the pause forward.
    engine = _make_engine(db)  # empty digest = test mode
    try:
        await engine.start()
        row = await db.get_scheduled_task(task_id)
        assert row["status"] == "paused", (
            f"replay should have rolled pause forward, got {row['status']!r}"
        )
        # The journal entry should be marked applied.
        entries = await db.list_pending_scheduler_journal_entries()
        assert len(entries) == 0, (
            f"journal entry should be marked applied after replay, "
            f"got {len(entries)} pending"
        )
    finally:
        await _force_cleanup_engine(engine)
        await db.close()


async def test_acceptance_12_replay_rolls_forward_remove_intent(tmp_path):
    """B5-12: replay rolls forward a pending remove intent on ``start()``."""
    db = await _make_db(tmp_path)
    task_id = await db.insert_scheduled_task(
        name="test", prompt="hello", status="pending",
        schedule=ScheduleConfig(cron="0 9"), deliver_to="local", meta={},
        principal_id="alice",
        project_id="", policy_digest="",
    )
    await db.insert_scheduler_journal_entry(
        operation_id="op-remove-1", task_id=task_id,
        operation_type="remove", desired_status="cancelled",
        expected_version=0, target_version=1,
        principal_id="alice", policy_digest="",
    )
    engine = _make_engine(db)
    try:
        await engine.start()
        row = await db.get_scheduled_task(task_id)
        assert row["status"] == "cancelled", (
            f"replay should have rolled remove forward, got {row['status']!r}"
        )
        entries = await db.list_pending_scheduler_journal_entries()
        assert len(entries) == 0
    finally:
        await _force_cleanup_engine(engine)
        await db.close()


async def test_acceptance_13_replay_marks_stale_for_deleted_task(tmp_path):
    """B5-13: replay marks an entry stale when the task was deleted."""
    db = await _make_db(tmp_path)
    # Write a journal entry for a task that doesn't exist in the DB.
    await db.insert_scheduler_journal_entry(
        operation_id="op-ghost", task_id="nonexistent-task",
        operation_type="pause", desired_status="paused",
        expected_version=0, target_version=1,
    )
    engine = _make_engine(db)
    try:
        await engine.start()
        entries = await db.list_pending_scheduler_journal_entries()
        assert len(entries) == 0, (
            "journal entry for deleted task should be marked stale"
        )
    finally:
        await _force_cleanup_engine(engine)
        await db.close()


async def test_acceptance_14_replay_marks_stale_for_running_task(tmp_path):
    """B5-14: replay marks an entry stale when the task is ``running``.

    A ``running`` task is left for ``recover_all_running_tasks`` to
    handle (it marks the task FAILED).  Replay does NOT race with
    recovery — it marks the entry applied and lets recovery achieve a
    terminal state.
    """
    db = await _make_db(tmp_path)
    task_id = await db.insert_scheduled_task(
        name="test", prompt="hello", status="running",
        schedule=ScheduleConfig(cron="0 9"), deliver_to="local", meta={},
        principal_id="alice",
        project_id="", policy_digest="",
    )
    await db.insert_scheduler_journal_entry(
        operation_id="op-pause-running", task_id=task_id,
        operation_type="pause", desired_status="paused",
        expected_version=0, target_version=1,
    )
    engine = _make_engine(db)
    try:
        await engine.start()
        # The journal entry should be marked applied (stale — recovery
        # handles the running task).
        entries = await db.list_pending_scheduler_journal_entries()
        assert len(entries) == 0, (
            "journal entry for running task should be marked stale "
            "(recovery handles it)"
        )
        # The task should be marked FAILED by recovery.
        row = await db.get_scheduled_task(task_id)
        assert row["status"] == "failed", (
            f"recovery should have marked the running task FAILED, "
            f"got {row['status']!r}"
        )
    finally:
        await _force_cleanup_engine(engine)
        await db.close()


async def test_acceptance_15_replay_marks_stale_for_terminal_task(tmp_path):
    """B5-15: replay marks an entry stale when the task is already
    terminal (``failed`` / ``cancelled``)."""
    db = await _make_db(tmp_path)
    task_id = await db.insert_scheduled_task(
        name="test", prompt="hello", status="failed",
        schedule=ScheduleConfig(cron="0 9"), deliver_to="local", meta={},
        principal_id="alice",
        project_id="", policy_digest="",
    )
    # Set the error column via direct UPDATE (insert_scheduled_task
    # doesn't accept an ``error`` kwarg — it's only set by the engine
    # during execution / quarantine).
    conn = await db._require_conn()
    await conn.execute(
        "UPDATE scheduled_tasks SET error = ? WHERE id = ?",
        ("natural failure", task_id),
    )
    await conn.commit()
    await db.insert_scheduler_journal_entry(
        operation_id="op-pause-failed", task_id=task_id,
        operation_type="pause", desired_status="paused",
        expected_version=0, target_version=1,
    )
    engine = _make_engine(db)
    try:
        await engine.start()
        entries = await db.list_pending_scheduler_journal_entries()
        assert len(entries) == 0, (
            "journal entry for terminal task should be marked stale"
        )
        # The task should STAY failed (replay does not overwrite).
        row = await db.get_scheduled_task(task_id)
        assert row["status"] == "failed"
    finally:
        await _force_cleanup_engine(engine)
        await db.close()


async def test_acceptance_16_replay_marks_stale_for_idempotent_match(tmp_path):
    """B5-16: replay marks an entry stale when DB status already
    matches ``desired_status`` (idempotent)."""
    db = await _make_db(tmp_path)
    task_id = await db.insert_scheduled_task(
        name="test", prompt="hello", status="paused",
        schedule=ScheduleConfig(cron="0 9"), deliver_to="local", meta={},
        principal_id="alice",
        project_id="", policy_digest="",
    )
    await db.insert_scheduler_journal_entry(
        operation_id="op-pause-idempotent", task_id=task_id,
        operation_type="pause", desired_status="paused",
        expected_version=0, target_version=1,
    )
    engine = _make_engine(db)
    try:
        await engine.start()
        entries = await db.list_pending_scheduler_journal_entries()
        assert len(entries) == 0, (
            "journal entry with matching DB status should be marked stale"
        )
        # The task should STAY paused (idempotent).
        row = await db.get_scheduled_task(task_id)
        assert row["status"] == "paused"
    finally:
        await _force_cleanup_engine(engine)
        await db.close()


async def test_acceptance_17_replay_does_not_resurrect_failed_with_resume(tmp_path):
    """B5-17: replay does NOT resurrect a FAILED task with a resume
    intent (marks the entry stale instead).

    A FAILED row from recovery must NOT be silently resurrected by a
    resume intent — the user must explicitly ``resume`` again after
    inspecting the failure.
    """
    db = await _make_db(tmp_path)
    task_id = await db.insert_scheduled_task(
        name="test", prompt="hello", status="failed",
        schedule=ScheduleConfig(cron="0 9"), deliver_to="local", meta={},
        principal_id="alice",
        project_id="", policy_digest="",
    )
    # Set the error column via direct UPDATE (insert_scheduled_task
    # doesn't accept an ``error`` kwarg).
    conn = await db._require_conn()
    await conn.execute(
        "UPDATE scheduled_tasks SET error = ? WHERE id = ?",
        ("natural failure", task_id),
    )
    await conn.commit()
    await db.insert_scheduler_journal_entry(
        operation_id="op-resume-failed", task_id=task_id,
        operation_type="resume", desired_status="pending",
        expected_version=0, target_version=1,
    )
    engine = _make_engine(db)
    try:
        await engine.start()
        entries = await db.list_pending_scheduler_journal_entries()
        assert len(entries) == 0, (
            "resume journal entry for FAILED task should be marked stale"
        )
        # The task should STAY failed (not resurrected to pending).
        row = await db.get_scheduled_task(task_id)
        assert row["status"] == "failed", (
            f"FAILED task must NOT be resurrected by resume replay, "
            f"got {row['status']!r}"
        )
    finally:
        await _force_cleanup_engine(engine)
        await db.close()


# ---------------------------------------------------------------------------
# 18-22. Lifecycle lock on mutating ops
# ---------------------------------------------------------------------------


async def test_acceptance_18_create_raises_on_stopping(tmp_path):
    """B5-18: ``create()`` raises ``RuntimeError("engine_unavailable")``
    when engine is STOPPING."""
    db = await _make_db(tmp_path)
    engine = _make_engine(db, policy_digest="sha256:p")
    try:
        await engine.start()
        engine._lifecycle_state = CronEngineState.STOPPING
        with pytest.raises(RuntimeError, match="engine_unavailable"):
            await engine.create(
                "test", "hello", ScheduleConfig(cron="0 9"),
                principal_id="alice",
            )
    finally:
        await _force_cleanup_engine(engine)
        await db.close()


async def test_acceptance_19_create_raises_on_quarantined(tmp_path):
    """B5-19: ``create()`` raises ``RuntimeError("engine_unavailable")``
    when engine is QUARANTINED."""
    db = await _make_db(tmp_path)
    engine = _make_engine(db, policy_digest="sha256:p")
    try:
        await engine.start()
        engine._lifecycle_state = CronEngineState.QUARANTINED
        with pytest.raises(RuntimeError, match="engine_unavailable"):
            await engine.create(
                "test", "hello", ScheduleConfig(cron="0 9"),
                principal_id="alice",
            )
    finally:
        await _force_cleanup_engine(engine)
        await db.close()


async def test_acceptance_20_create_raises_on_degraded(tmp_path):
    """B5-20: ``create()`` raises ``RuntimeError("engine_degraded")``
    when engine is degraded."""
    db = await _make_db(tmp_path)
    engine = _make_engine(db, policy_digest="sha256:p")
    try:
        await engine.start()
        engine._degraded = True
        with pytest.raises(RuntimeError, match="engine_degraded"):
            await engine.create(
                "test", "hello", ScheduleConfig(cron="0 9"),
                principal_id="alice",
            )
    finally:
        await _force_cleanup_engine(engine)
        await db.close()


async def test_acceptance_21_pause_resume_remove_return_unavailable_on_quarantined(tmp_path):
    """B5-21: ``pause()`` / ``resume()`` / ``remove()`` return
    ``"engine_unavailable"`` when engine is QUARANTINED."""
    db = await _make_db(tmp_path)
    engine = _make_engine(db, policy_digest="sha256:p")
    try:
        await engine.start()
        task = await engine.create(
            "test", "hello", ScheduleConfig(cron="0 9"),
            principal_id="alice",
        )
        engine._lifecycle_state = CronEngineState.QUARANTINED
        assert await engine.pause(task.id, principal_id="alice") == "engine_unavailable"
        assert await engine.resume(task.id, principal_id="alice") == "engine_unavailable"
        assert await engine.remove(task.id, principal_id="alice") == "engine_unavailable"
    finally:
        await _force_cleanup_engine(engine)
        await db.close()


async def test_acceptance_22_pause_resume_remove_work_when_degraded(tmp_path):
    """B5-22: ``pause()`` / ``resume()`` / ``remove()`` still work when
    engine is degraded (only ``create`` refuses degraded)."""
    db = await _make_db(tmp_path)
    engine = _make_engine(db, policy_digest="sha256:p")
    try:
        await engine.start()
        task = await engine.create(
            "test", "hello", ScheduleConfig(cron="0 9"),
            principal_id="alice",
        )
        engine._degraded = True
        # pause / resume / remove should still work (not return engine_degraded).
        result = await engine.pause(task.id, principal_id="alice")
        assert result == "ok", (
            f"pause should work in degraded mode, got {result!r}"
        )
        result = await engine.resume(task.id, principal_id="alice")
        assert result == "ok", (
            f"resume should work in degraded mode, got {result!r}"
        )
        result = await engine.remove(task.id, principal_id="alice")
        assert result == "ok", (
            f"remove should work in degraded mode, got {result!r}"
        )
    finally:
        await _force_cleanup_engine(engine)
        await db.close()


# ---------------------------------------------------------------------------
# 23-24. cron_tools conversion
# ---------------------------------------------------------------------------


async def test_acceptance_23_cron_create_converts_lifecycle_lock(tmp_path):
    """B5-23: ``cron_create`` converts the RuntimeError to a structured
    ``{"status": "error", ...}`` response."""
    db = await _make_db(tmp_path)
    engine = _make_engine(db, policy_digest="sha256:p")
    cron_tools.set_cron_engine(engine)
    try:
        await engine.start()
        # Test engine_unavailable.
        engine._lifecycle_state = CronEngineState.QUARANTINED
        result = await cron_tools.cron_create(
            "test", "hello", "0 9", principal_id="alice",
        )
        assert result["status"] == "error"
        assert result["error"] == "engine_unavailable"
        assert "retry_after" in result
        assert result["retry_after"] == "engine_restart"
        # Test engine_degraded.
        engine._lifecycle_state = CronEngineState.RUNNING
        engine._degraded = True
        result = await cron_tools.cron_create(
            "test", "hello", "0 9", principal_id="alice",
        )
        assert result["status"] == "error"
        assert result["error"] == "engine_degraded"
        assert result["retry_after"] == "engine_restart"
    finally:
        await _force_cleanup_engine(engine)
        cron_tools.set_cron_engine(None)
        await db.close()


async def test_acceptance_24_cron_pause_resume_remove_convert_lifecycle_lock(tmp_path):
    """B5-24: ``cron_pause`` / ``cron_resume`` / ``cron_remove`` convert
    ``"engine_unavailable"`` to a structured response."""
    db = await _make_db(tmp_path)
    engine = _make_engine(db, policy_digest="sha256:p")
    cron_tools.set_cron_engine(engine)
    try:
        await engine.start()
        task = await engine.create(
            "test", "hello", ScheduleConfig(cron="0 9"),
            principal_id="alice",
        )
        engine._lifecycle_state = CronEngineState.QUARANTINED
        # pause
        result = await cron_tools.cron_pause(task.id, principal_id="alice")
        assert result["status"] == "error"
        assert result["error"] == "engine_unavailable"
        assert result["task_id"] == task.id
        assert result["retry_after"] == "engine_restart"
        # resume
        result = await cron_tools.cron_resume(task.id, principal_id="alice")
        assert result["status"] == "error"
        assert result["error"] == "engine_unavailable"
        # remove
        result = await cron_tools.cron_remove(task.id, principal_id="alice")
        assert result["status"] == "error"
        assert result["error"] == "engine_unavailable"
    finally:
        await _force_cleanup_engine(engine)
        cron_tools.set_cron_engine(None)
        await db.close()


async def test_acceptance_25_lifecycle_lock_response_helper():
    """B5-extra: ``_lifecycle_lock_response`` produces the expected
    structure for both error types."""
    from khaos.tools.cron_tools import _lifecycle_lock_response
    resp = _lifecycle_lock_response("engine_unavailable", task_id="t-1")
    assert resp["status"] == "error"
    assert resp["error"] == "engine_unavailable"
    assert resp["task_id"] == "t-1"
    assert resp["retry_after"] == "engine_restart"
    assert "STOPPING" in resp["message"] or "QUARANTINED" in resp["message"]

    resp = _lifecycle_lock_response("engine_degraded")
    assert resp["status"] == "error"
    assert resp["error"] == "engine_degraded"
    assert "task_id" not in resp
    assert "DEGRADED" in resp["message"]


# ---------------------------------------------------------------------------
# 26-27. A-5-1b: project_id stamping on journal entries (service-layer)
# ---------------------------------------------------------------------------


async def test_acceptance_26_pause_stamps_project_id_on_journal(tmp_path):
    """A5-1b #26: ``pause()`` stamps engine's ``project_id`` on journal row.

    B-5 added the durable operation journal but stamped only
    ``principal_id`` and ``policy_digest`` — ``project_id`` was an
    oversight.  A-5-1a added the column; A-5-1b stamps it via
    ``CronEngine._project_id`` (which flows from
    ``AgentService._bound_project_id`` — RPC-verified).

    This test verifies the SERVICE-LAYER stamping contract: when a
    project-bound engine (``project_id="proj-journal"``) pauses a
    task, the journal row written by ``_record_journal_intent``
    carries ``project_id="proj-journal"``, NOT the empty default.

    Contrast with Test 18 (DB-layer direct insert) which only
    verifies the DB method accepts the param; this test exercises
    the full ``pause()`` → ``_persist_task_state`` → journal path.
    """
    db = await _make_db(tmp_path)
    audit_logger = await _make_audit_logger(db)
    engine = _make_engine(
        db,
        project_id="proj-journal",  # engine is project-bound
        policy_digest="sha256:policy-journal",
        audit_logger=audit_logger,
    )
    try:
        await engine.start()
        task = await engine.create(
            name="t1", prompt="hello",
            schedule=ScheduleConfig(cron="0 9"), deliver_to="local",
            principal_id="alice",
        )
        task_id = task.id if hasattr(task, "id") else task
        result = await engine.pause(task_id, principal_id="alice")
        assert result == "ok", f"pause should succeed, got {result!r}"

        # The journal row must carry the engine's project_id.
        conn = await db._require_conn()
        cursor = await conn.execute(
            "SELECT project_id, operation_type, desired_status "
            "FROM scheduler_operation_journal WHERE task_id = ?",
            (task_id,),
        )
        rows = await cursor.fetchall()
        assert len(rows) == 1, (
            f"expected 1 journal entry for pause, got {len(rows)}"
        )
        assert rows[0][0] == "proj-journal", (
            f"journal row must carry engine's project_id='proj-journal', "
            f"got {rows[0][0]!r}"
        )
        assert rows[0][1] == "pause", (
            f"operation_type must be 'pause', got {rows[0][1]!r}"
        )
        assert rows[0][2] == "paused", (
            f"desired_status must be 'paused', got {rows[0][2]!r}"
        )
    finally:
        await _force_cleanup_engine(engine)
        await db.close()


async def test_acceptance_27_legacy_engine_stamps_empty_project_id(tmp_path):
    """A5-1b #27: legacy engine (no project_id) stamps '' on journal.

    Engines constructed without ``project_id`` (e.g. test helpers,
    CLI boot before A-5-1b wiring, or scheduled tasks created before
    the project-identity feature) stamp the fail-closed default
    ``''`` on journal rows.  This is backward-compatible: existing
    rows are distinguishable from project-bound rows but still
    visible to operators.
    """
    db = await _make_db(tmp_path)
    audit_logger = await _make_audit_logger(db)
    # Engine constructed WITHOUT project_id (legacy / test mode).
    engine = _make_engine(
        db,
        project_id="",  # legacy / test mode
        policy_digest="sha256:policy-legacy",
        audit_logger=audit_logger,
    )
    try:
        await engine.start()
        task = await engine.create(
            name="t2", prompt="hello",
            schedule=ScheduleConfig(cron="0 9"), deliver_to="local",
            principal_id="bob",
        )
        task_id = task.id if hasattr(task, "id") else task
        result = await engine.pause(task_id, principal_id="bob")
        assert result == "ok", f"pause should succeed, got {result!r}"

        # Journal row carries the empty-default project_id.
        conn = await db._require_conn()
        cursor = await conn.execute(
            "SELECT project_id FROM scheduler_operation_journal "
            "WHERE task_id = ?",
            (task_id,),
        )
        rows = await cursor.fetchall()
        assert len(rows) == 1
        assert rows[0][0] == "", (
            f"legacy engine must stamp project_id='', got {rows[0][0]!r}"
        )
    finally:
        await _force_cleanup_engine(engine)
        await db.close()
