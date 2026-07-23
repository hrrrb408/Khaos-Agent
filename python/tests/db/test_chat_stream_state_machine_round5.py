"""Round-5 Batch 5.2 (C-05/C-06) — Chat stream state machine invariants.

C-05 identified that ``recover_inflight_chat_streams`` was called
periodically by ``MaintenanceService``, which terminated active chats
waiting on long tool calls because their lease had expired between
heartbeat renewals.

C-06 identified that the chat stream had no durable state machine —
there was no DB-level enforcement that a terminal event could only be
appended once, and no way to distinguish streams owned by the current
process from streams left by a crashed previous process.

This file verifies the following state machine invariants:

  - **Terminal shield**: once a stream is terminal, appending raises
    ``ChatStreamTerminalError``.
  - **CAS terminal transition**: exactly one terminal event per stream.
  - **boot_id-aware recovery**: recovery with ``boot_id`` does NOT
    recover the current process's own active streams.
  - **boot_id-aware recovery**: recovery with ``boot_id`` DOES recover
    other-process streams (different ``boot_id``).
  - **boot_id-aware recovery**: recovery with ``boot_id`` recovers
    expired-lease streams even if the ``boot_id`` matches.
  - **Legacy recovery**: recovery without ``boot_id`` recovers all
    non-terminal streams (backward compatibility).
  - **Lease renewal**: non-terminal appends renew ``lease_until``.
  - **Row lifecycle**: ``chat_streams`` row is created lazily on first
    append and transitions ``running`` → terminal on terminal event.
  - **Cascade delete**: ``delete_chat_stream_events_for_session`` also
    removes the ``chat_streams`` row.
  - **Prune cascade**: ``prune_terminal_chat_streams`` also removes
    ``chat_streams`` rows for pruned sessions.
  - **Maintenance no longer recovers**: ``MaintenanceService.run_once``
    does NOT call ``recover_inflight_chat_streams``.
"""
from __future__ import annotations

import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from khaos.db import Database
from khaos.db.database import ChatStreamTerminalError
from khaos.maintenance import MaintenanceService


PROJECT_ID = "b" * 32
PRINCIPAL = "alice"


# ───────────────────────────── helpers ────────────────────────────────


async def _make_db(path: Path) -> Database:
    db = Database(path)
    await db.connect()
    await db.run_migrations()
    return db


async def _make_session(db: Database, session_id: str = "s1") -> None:
    await db.create_session(
        session_id, principal_id=PRINCIPAL, project_id=PROJECT_ID,
    )


async def _get_chat_stream_row(db: Database, session_id: str) -> dict | None:
    conn = db._conn
    cursor = await conn.execute(
        "SELECT session_id, status, boot_id, runtime_id, lease_until, "
        "last_sequence, terminal_event_type, started_at, terminal_at "
        "FROM chat_streams WHERE session_id = ?",
        (session_id,),
    )
    row = await cursor.fetchone()
    await cursor.close()
    if row is None:
        return None
    return {k: row[k] for k in row.keys()}


# ─────────── C-05-A: terminal shield rejects post-terminal append ─────


async def test_c05_a_terminal_shield_rejects_post_terminal_append(tmp_path):
    """C-05-A: after a terminal event, appending raises
    ``ChatStreamTerminalError``."""
    db = await _make_db(tmp_path / "r5.db")
    try:
        await _make_session(db, "s1")
        await db.append_chat_stream_event(
            session_id="s1", principal_id=PRINCIPAL, project_id=PROJECT_ID,
            event_type="started", data={}, now=1.0,
        )
        await db.append_chat_stream_event(
            session_id="s1", principal_id=PRINCIPAL, project_id=PROJECT_ID,
            event_type="done", data={}, now=2.0,
        )
        # Post-terminal append must be rejected.
        with pytest.raises(ChatStreamTerminalError):
            await db.append_chat_stream_event(
                session_id="s1", principal_id=PRINCIPAL, project_id=PROJECT_ID,
                event_type="message", data={"content": "late"}, now=3.0,
            )
    finally:
        await db.close()


# ─────── C-05-B: terminal shield works for all terminal types ─────────


@pytest.mark.parametrize("terminal_type", ["done", "error", "interrupted"])
async def test_c05_b_terminal_shield_for_all_terminal_types(
    tmp_path, terminal_type,
):
    """C-05-B: every terminal event type (``done``, ``error``,
    ``interrupted``) triggers the shield."""
    db = await _make_db(tmp_path / "r5.db")
    try:
        session_id = f"s-{terminal_type}"
        await _make_session(db, session_id)
        await db.append_chat_stream_event(
            session_id=session_id, principal_id=PRINCIPAL,
            project_id=PROJECT_ID,
            event_type="started", data={}, now=1.0,
        )
        await db.append_chat_stream_event(
            session_id=session_id, principal_id=PRINCIPAL,
            project_id=PROJECT_ID,
            event_type=terminal_type, data={}, now=2.0,
        )
        with pytest.raises(ChatStreamTerminalError):
            await db.append_chat_stream_event(
                session_id=session_id, principal_id=PRINCIPAL,
                project_id=PROJECT_ID,
                event_type="message", data={}, now=3.0,
            )
    finally:
        await db.close()


# ─────────── C-05-C: CAS — exactly one terminal per stream ────────────


async def test_c05_c_cas_exactly_one_terminal_per_stream(tmp_path):
    """C-05-C: the CAS ``UPDATE ... WHERE status='running'`` ensures
    exactly one terminal transition.  A second terminal append is
    rejected by the shield."""
    db = await _make_db(tmp_path / "r5.db")
    try:
        await _make_session(db, "s1")
        await db.append_chat_stream_event(
            session_id="s1", principal_id=PRINCIPAL, project_id=PROJECT_ID,
            event_type="started", data={}, now=1.0,
        )
        # First terminal succeeds.
        await db.append_chat_stream_event(
            session_id="s1", principal_id=PRINCIPAL, project_id=PROJECT_ID,
            event_type="done", data={}, now=2.0,
        )
        row = await _get_chat_stream_row(db, "s1")
        assert row is not None
        assert row["status"] == "done"
        assert row["terminal_event_type"] == "done"
        assert row["terminal_at"] == 2.0

        # Second terminal is rejected by the shield.
        with pytest.raises(ChatStreamTerminalError):
            await db.append_chat_stream_event(
                session_id="s1", principal_id=PRINCIPAL,
                project_id=PROJECT_ID,
                event_type="error", data={}, now=3.0,
            )
        # Status unchanged.
        row = await _get_chat_stream_row(db, "s1")
        assert row["status"] == "done"
        assert row["terminal_event_type"] == "done"
    finally:
        await db.close()


# ───── C-05-D: boot_id-aware recovery skips own active streams ────────


async def test_c05_d_boot_id_recovery_skips_own_streams(tmp_path):
    """C-05-D: recovery with ``boot_id`` does NOT recover streams
    owned by the current process (same ``boot_id``, lease still valid)."""
    db = await _make_db(tmp_path / "r5.db")
    try:
        await _make_session(db, "s1")
        boot_id = "boot-current"
        now = time.time()
        await db.append_chat_stream_event(
            session_id="s1", principal_id=PRINCIPAL, project_id=PROJECT_ID,
            event_type="started", data={}, now=now,
            boot_id=boot_id, runtime_id="s1",
            lease_until=now + 300,  # lease still valid
        )
        # Recovery with the same boot_id must NOT recover s1.
        recovered = await db.recover_inflight_chat_streams(
            now=now + 10, boot_id=boot_id,
        )
        assert recovered == 0

        # Stream is still running — no error terminal was appended.
        events = await db.list_chat_stream_events(
            session_id="s1", principal_id=PRINCIPAL, project_id=PROJECT_ID,
        )
        assert [e["event"] for e in events] == ["started"]
        row = await _get_chat_stream_row(db, "s1")
        assert row["status"] == "running"
    finally:
        await db.close()


# ─ C-05-E: boot_id-aware recovery recovers other-process streams ──────


async def test_c05_e_boot_id_recovery_recovers_other_process(tmp_path):
    """C-05-E: recovery with ``boot_id`` DOES recover streams left by a
    DIFFERENT process (different ``boot_id``)."""
    db = await _make_db(tmp_path / "r5.db")
    try:
        await _make_session(db, "s1")
        now = time.time()
        # Stream created by a PREVIOUS process (different boot_id).
        await db.append_chat_stream_event(
            session_id="s1", principal_id=PRINCIPAL, project_id=PROJECT_ID,
            event_type="started", data={}, now=now,
            boot_id="boot-previous", runtime_id="s1",
            lease_until=now + 300,  # lease still "valid" but wrong boot
        )
        # Recovery with the current boot_id must recover s1.
        recovered = await db.recover_inflight_chat_streams(
            now=now + 10, boot_id="boot-current",
        )
        assert recovered == 1

        events = await db.list_chat_stream_events(
            session_id="s1", principal_id=PRINCIPAL, project_id=PROJECT_ID,
        )
        assert [e["event"] for e in events] == ["started", "error"]
        assert events[-1]["terminal"] is True
        assert events[-1]["data"]["code"] == "PROCESS_RESTART"

        row = await _get_chat_stream_row(db, "s1")
        assert row["status"] == "error"
    finally:
        await db.close()


# ─ C-05-F: boot_id-aware recovery recovers expired-lease streams ──────


async def test_c05_f_boot_id_recovery_recovers_expired_lease(tmp_path):
    """C-05-F: recovery with ``boot_id`` recovers streams whose lease has
    expired EVEN IF the ``boot_id`` matches (owning process is likely
    dead or wedged)."""
    db = await _make_db(tmp_path / "r5.db")
    try:
        await _make_session(db, "s1")
        boot_id = "boot-current"
        now = time.time()
        # Stream created by the current process, but lease has expired.
        await db.append_chat_stream_event(
            session_id="s1", principal_id=PRINCIPAL, project_id=PROJECT_ID,
            event_type="started", data={}, now=now - 600,
            boot_id=boot_id, runtime_id="s1",
            lease_until=now - 300,  # expired 5 minutes ago
        )
        # Recovery with the same boot_id MUST recover s1 because the
        # lease has expired (the owning process is likely dead).
        recovered = await db.recover_inflight_chat_streams(
            now=now, boot_id=boot_id,
        )
        assert recovered == 1

        events = await db.list_chat_stream_events(
            session_id="s1", principal_id=PRINCIPAL, project_id=PROJECT_ID,
        )
        assert [e["event"] for e in events] == ["started", "error"]
        assert events[-1]["terminal"] is True

        row = await _get_chat_stream_row(db, "s1")
        assert row["status"] == "error"
    finally:
        await db.close()


# ─────────── C-05-G: legacy recovery (boot_id=None) recovers all ──────


async def test_c05_g_legacy_recovery_recovers_all(tmp_path):
    """C-05-G: recovery without ``boot_id`` (legacy/test mode) recovers
    ALL non-terminal streams, regardless of ``boot_id`` or lease."""
    db = await _make_db(tmp_path / "r5.db")
    try:
        await _make_session(db, "s1")
        await _make_session(db, "s2")
        now = time.time()
        # s1: current boot_id, valid lease.
        await db.append_chat_stream_event(
            session_id="s1", principal_id=PRINCIPAL, project_id=PROJECT_ID,
            event_type="started", data={}, now=now,
            boot_id="boot-current", runtime_id="s1",
            lease_until=now + 300,
        )
        # s2: different boot_id, expired lease.
        await db.append_chat_stream_event(
            session_id="s2", principal_id=PRINCIPAL, project_id=PROJECT_ID,
            event_type="started", data={}, now=now - 600,
            boot_id="boot-previous", runtime_id="s2",
            lease_until=now - 300,
        )
        # Legacy recovery (boot_id=None) recovers BOTH.
        recovered = await db.recover_inflight_chat_streams(now=now + 1)
        assert recovered == 2

        for sid in ("s1", "s2"):
            events = await db.list_chat_stream_events(
                session_id=sid, principal_id=PRINCIPAL, project_id=PROJECT_ID,
            )
            assert [e["event"] for e in events] == ["started", "error"]
            row = await _get_chat_stream_row(db, sid)
            assert row["status"] == "error"
    finally:
        await db.close()


# ─────────── C-05-H: lease renewal on non-terminal append ─────────────


async def test_c05_h_lease_renewed_on_non_terminal_append(tmp_path):
    """C-05-H: each non-terminal append renews ``lease_until`` so a chat
    waiting on a long tool call is not falsely recovered."""
    db = await _make_db(tmp_path / "r5.db")
    try:
        await _make_session(db, "s1")
        boot_id = "boot-current"
        t0 = 1000.0
        # First append: lease = t0 + 300.
        await db.append_chat_stream_event(
            session_id="s1", principal_id=PRINCIPAL, project_id=PROJECT_ID,
            event_type="started", data={}, now=t0,
            boot_id=boot_id, runtime_id="s1",
            lease_until=t0 + 300,
        )
        row = await _get_chat_stream_row(db, "s1")
        assert row["lease_until"] == t0 + 300
        assert row["last_sequence"] == 1

        # Second append at t0 + 200: lease renewed to t0 + 200 + 300.
        t1 = t0 + 200
        await db.append_chat_stream_event(
            session_id="s1", principal_id=PRINCIPAL, project_id=PROJECT_ID,
            event_type="message", data={"content": "working"}, now=t1,
            boot_id=boot_id, runtime_id="s1",
            lease_until=t1 + 300,
        )
        row = await _get_chat_stream_row(db, "s1")
        assert row["lease_until"] == t1 + 300
        assert row["last_sequence"] == 2
        assert row["status"] == "running"
    finally:
        await db.close()


# ─────────── C-05-I: row lifecycle — lazy create + terminal ───────────


async def test_c05_i_row_lifecycle_lazy_create_and_terminal(tmp_path):
    """C-05-I: ``chat_streams`` row is created lazily on the first
    append and transitions ``running`` → terminal on the terminal event."""
    db = await _make_db(tmp_path / "r5.db")
    try:
        await _make_session(db, "s1")
        # No row before any append.
        assert await _get_chat_stream_row(db, "s1") is None

        # First append creates the row with status='running'.
        await db.append_chat_stream_event(
            session_id="s1", principal_id=PRINCIPAL, project_id=PROJECT_ID,
            event_type="started", data={}, now=1.0,
            boot_id="boot-1", runtime_id="s1",
            lease_until=301.0,
        )
        row = await _get_chat_stream_row(db, "s1")
        assert row is not None
        assert row["status"] == "running"
        assert row["boot_id"] == "boot-1"
        assert row["runtime_id"] == "s1"
        assert row["lease_until"] == 301.0
        assert row["last_sequence"] == 1
        assert row["terminal_event_type"] is None
        assert row["terminal_at"] is None

        # Terminal append transitions to terminal.
        await db.append_chat_stream_event(
            session_id="s1", principal_id=PRINCIPAL, project_id=PROJECT_ID,
            event_type="error", data={"reason": "test"}, now=2.0,
            boot_id="boot-1", runtime_id="s1",
        )
        row = await _get_chat_stream_row(db, "s1")
        assert row["status"] == "error"
        assert row["terminal_event_type"] == "error"
        assert row["terminal_at"] == 2.0
        assert row["last_sequence"] == 2
    finally:
        await db.close()


# ─────────── C-05-J: cascade delete removes chat_streams row ──────────


async def test_c05_j_delete_cascades_to_chat_streams(tmp_path):
    """C-05-J: ``delete_chat_stream_events_for_session`` also removes the
    ``chat_streams`` row so it is not orphaned for recovery."""
    db = await _make_db(tmp_path / "r5.db")
    try:
        await _make_session(db, "s1")
        await _make_session(db, "s2")
        await db.append_chat_stream_event(
            session_id="s1", principal_id=PRINCIPAL, project_id=PROJECT_ID,
            event_type="started", data={}, now=1.0,
        )
        await db.append_chat_stream_event(
            session_id="s2", principal_id=PRINCIPAL, project_id=PROJECT_ID,
            event_type="started", data={}, now=2.0,
        )
        assert await _get_chat_stream_row(db, "s1") is not None
        assert await _get_chat_stream_row(db, "s2") is not None

        deleted = await db.delete_chat_stream_events_for_session(
            session_id="s1", principal_id=PRINCIPAL, project_id=PROJECT_ID,
        )
        assert deleted == 1

        # s1 row gone; s2 row still present.
        assert await _get_chat_stream_row(db, "s1") is None
        assert await _get_chat_stream_row(db, "s2") is not None
    finally:
        await db.close()


# ─────────── C-05-K: prune cascades to chat_streams ───────────────────


async def test_c05_k_prune_cascades_to_chat_streams(tmp_path):
    """C-05-K: ``prune_terminal_chat_streams`` also removes ``chat_streams``
    rows for pruned sessions."""
    db = await _make_db(tmp_path / "r5.db")
    try:
        await _make_session(db, "aged")
        await _make_session(db, "fresh")
        now = time.time()

        # aged: terminal 2 hours ago.
        await db.append_chat_stream_event(
            session_id="aged", principal_id=PRINCIPAL, project_id=PROJECT_ID,
            event_type="started", data={}, now=now - 7200,
        )
        await db.append_chat_stream_event(
            session_id="aged", principal_id=PRINCIPAL, project_id=PROJECT_ID,
            event_type="done", data={}, now=now - 7100,
        )
        # fresh: terminal 10 seconds ago.
        await db.append_chat_stream_event(
            session_id="fresh", principal_id=PRINCIPAL, project_id=PROJECT_ID,
            event_type="started", data={}, now=now - 20,
        )
        await db.append_chat_stream_event(
            session_id="fresh", principal_id=PRINCIPAL, project_id=PROJECT_ID,
            event_type="done", data={}, now=now - 10,
        )

        assert await _get_chat_stream_row(db, "aged") is not None
        assert await _get_chat_stream_row(db, "fresh") is not None

        pruned = await db.prune_terminal_chat_streams(
            older_than_seconds=3600, now=now,
        )
        assert pruned == 2  # aged started + aged done

        # aged row gone; fresh row still present.
        assert await _get_chat_stream_row(db, "aged") is None
        row = await _get_chat_stream_row(db, "fresh")
        assert row is not None
        assert row["status"] == "done"
    finally:
        await db.close()


# ─ C-05-L: MaintenanceService.run_once does NOT call recovery ─────────


async def test_c05_l_maintenance_run_once_does_not_recover(tmp_path):
    """C-05-L: ``MaintenanceService.run_once`` does NOT call
    ``recover_inflight_chat_streams``.  Recovery is startup-only."""
    db = await _make_db(tmp_path / "r5.db")
    try:
        await _make_session(db, "s1")
        # Create an inflight stream that WOULD be recovered by the old
        # periodic recovery call.
        await db.append_chat_stream_event(
            session_id="s1", principal_id=PRINCIPAL, project_id=PROJECT_ID,
            event_type="started", data={}, now=time.time() - 600,
            boot_id="boot-old", lease_until=time.time() - 300,
        )

        service = MaintenanceService(
            db, interval_seconds=999, retention_seconds=99999,
        )
        counts = await service.run_once()

        # Recovery must NOT have been called — no inflight_recovered key.
        assert "inflight_recovered" not in counts

        # The stream is still running (not recovered).
        events = await db.list_chat_stream_events(
            session_id="s1", principal_id=PRINCIPAL, project_id=PROJECT_ID,
        )
        assert [e["event"] for e in events] == ["started"]
        row = await _get_chat_stream_row(db, "s1")
        assert row["status"] == "running"
    finally:
        await db.close()


# ─ C-05-M: recovery idempotent — already-terminal streams skipped ─────


async def test_c05_m_recovery_skips_already_terminal_streams(tmp_path):
    """C-05-M: recovery does NOT touch streams that are already terminal."""
    db = await _make_db(tmp_path / "r5.db")
    try:
        await _make_session(db, "s1")
        await db.append_chat_stream_event(
            session_id="s1", principal_id=PRINCIPAL, project_id=PROJECT_ID,
            event_type="started", data={}, now=1.0,
            boot_id="boot-old", lease_until=100.0,
        )
        await db.append_chat_stream_event(
            session_id="s1", principal_id=PRINCIPAL, project_id=PROJECT_ID,
            event_type="done", data={}, now=2.0,
        )

        # Recovery must skip s1 (it's already terminal).
        recovered = await db.recover_inflight_chat_streams(
            now=1000.0, boot_id="boot-new",
        )
        assert recovered == 0

        events = await db.list_chat_stream_events(
            session_id="s1", principal_id=PRINCIPAL, project_id=PROJECT_ID,
        )
        # No extra error event appended.
        assert [e["event"] for e in events] == ["started", "done"]
    finally:
        await db.close()


# ─ C-05-N: recovery with empty boot_id on streams ─────────────────────


async def test_c05_n_recovery_handles_empty_boot_id_streams(tmp_path):
    """C-05-N: streams with empty ``boot_id`` (created without boot_id)
    are recoverable by any process — they predate the boot_id mechanism."""
    db = await _make_db(tmp_path / "r5.db")
    try:
        await _make_session(db, "s1")
        # Stream created WITHOUT boot_id (empty string default).
        await db.append_chat_stream_event(
            session_id="s1", principal_id=PRINCIPAL, project_id=PROJECT_ID,
            event_type="started", data={}, now=1.0,
        )
        # Recovery with any boot_id must recover s1 (empty boot_id is
        # treated as "pre-boot-id" → always recoverable).
        recovered = await db.recover_inflight_chat_streams(
            now=2.0, boot_id="boot-current",
        )
        assert recovered == 1

        events = await db.list_chat_stream_events(
            session_id="s1", principal_id=PRINCIPAL, project_id=PROJECT_ID,
        )
        assert [e["event"] for e in events] == ["started", "error"]
    finally:
        await db.close()
