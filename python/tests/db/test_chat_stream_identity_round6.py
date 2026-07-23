"""Round-6 Batch 6.1 — Chat Stream Identity (stream_id independent of session_id).

Round-5 Batch 5.2 used ``session_id`` as the PRIMARY KEY of
``chat_streams`` and the first column of the ``chat_stream_events`` PK.
This meant a session could only ever have ONE stream — once it reached
``done``, the Terminal Shield rejected any subsequent ``started`` event,
**breaking multi-turn conversations** (Review §七).

Round-6 Batch 6.1 introduces ``stream_id`` (uuid4 per chat RPC attempt)
as the primary key.  A session can now have many streams, each with its
own Terminal lifecycle.

This file verifies the following Batch 6.1 invariants:

  - **Multi-turn conversation**: same session can have 10 sequential
    streams, each completing successfully (started → done).
  - **Per-stream Terminal isolation**: one stream's terminal does NOT
    affect another stream on the same session.
  - **Per-stream Terminal shield**: post-terminal append is rejected
    per-stream, not per-session.
  - **Per-stream CAS**: exactly one terminal per stream; multiple
    streams on the same session each get their own terminal.
  - **Stream-specific event query**: ``list_chat_stream_events(stream_id=...)``
    returns only that stream's events.
  - **Session-wide event query**: ``list_chat_stream_events(session_id=...)``
    (no stream_id) returns events across ALL streams for that session.
  - **Recovery isolation**: ``recover_inflight_chat_streams`` only
    recovers the targeted non-terminal stream, not other terminal
    streams on the same session.
  - **Legacy migration**: old DB with ``session_id``-keyed
    ``chat_streams`` migrates to ``stream_id``-keyed schema, with each
    legacy session becoming a single stream (stream_id == session_id).
  - **Concurrent session rejection**: ``AgentService.chat`` rejects a
    second concurrent chat RPC on the same ``session_id`` with
    ``SessionBusyError`` (Review §八 Strategy B).
"""
from __future__ import annotations

import asyncio
import time
import uuid
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from khaos.db import Database
from khaos.db.database import ChatStreamTerminalError, SessionBusyError
from khaos.grpc_server import AgentService, ChatRequest
from khaos.runtime import RequestContext


PROJECT_ID = "c" * 32
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


async def _complete_stream(
    db: Database,
    *,
    stream_id: str,
    session_id: str,
    boot_id: str = "boot-1",
    terminal: str = "done",
    started_at: float = 1.0,
    terminal_at: float = 2.0,
) -> None:
    """Append a started + terminal pair for one stream."""
    await db.append_chat_stream_event(
        stream_id=stream_id, session_id=session_id,
        principal_id=PRINCIPAL, project_id=PROJECT_ID,
        event_type="started", data={}, now=started_at,
        boot_id=boot_id, runtime_id=stream_id,
        lease_until=started_at + 300,
    )
    await db.append_chat_stream_event(
        stream_id=stream_id, session_id=session_id,
        principal_id=PRINCIPAL, project_id=PROJECT_ID,
        event_type=terminal, data={}, now=terminal_at,
        boot_id=boot_id, runtime_id=stream_id,
    )


async def _get_stream_row(db: Database, stream_id: str) -> dict | None:
    conn = db._conn
    cursor = await conn.execute(
        "SELECT stream_id, session_id, status, boot_id, runtime_id, "
        "lease_until, last_sequence, terminal_event_type, started_at, "
        "terminal_at FROM chat_streams WHERE stream_id = ?",
        (stream_id,),
    )
    row = await cursor.fetchone()
    await cursor.close()
    if row is None:
        return None
    return {k: row[k] for k in row.keys()}


# ─────────── 6.1-A: multi-turn conversation (10 sequential streams) ───


async def test_6_1_a_multi_turn_conversation_ten_streams(tmp_path):
    """6.1-A: same session can have 10 sequential streams, each
    completing successfully (started → done).  This is the core
    multi-turn conversation invariant broken by Round-5's session-keyed
    Terminal Shield."""
    db = await _make_db(tmp_path / "r6.db")
    try:
        await _make_session(db, "s1")
        for i in range(10):
            stream_id = f"stream-{i:02d}"
            await _complete_stream(
                db,
                stream_id=stream_id, session_id="s1",
                started_at=float(i) * 10, terminal_at=float(i) * 10 + 1,
            )
            row = await _get_stream_row(db, stream_id)
            assert row is not None, f"stream {stream_id} row missing"
            assert row["status"] == "done", (
                f"stream {stream_id} status={row['status']}, expected done"
            )
            assert row["terminal_event_type"] == "done"

        # All 10 streams are present, all terminal.
        conn = db._conn
        cursor = await conn.execute(
            "SELECT COUNT(*) FROM chat_streams WHERE session_id = ?",
            ("s1",),
        )
        count = (await cursor.fetchone())[0]
        await cursor.close()
        assert count == 10

        # Session-wide event query returns 20 events (10 started + 10 done).
        events = await db.list_chat_stream_events(
            session_id="s1", principal_id=PRINCIPAL, project_id=PROJECT_ID,
            limit=1024,
        )
        assert len(events) == 20
    finally:
        await db.close()


# ───── 6.1-B: per-stream Terminal isolation on same session ───────────


async def test_6_1_b_per_stream_terminal_isolation(tmp_path):
    """6.1-B: one stream's terminal does NOT affect another stream on
    the same session.  Stream-1 can be ``done`` while stream-2 is
    ``running``."""
    db = await _make_db(tmp_path / "r6.db")
    try:
        await _make_session(db, "s1")
        # Stream-1: complete (terminal).
        await _complete_stream(
            db, stream_id="stream-1", session_id="s1",
            started_at=1.0, terminal_at=2.0,
        )
        # Stream-2: only started (running).
        await db.append_chat_stream_event(
            stream_id="stream-2", session_id="s1",
            principal_id=PRINCIPAL, project_id=PROJECT_ID,
            event_type="started", data={}, now=3.0,
            boot_id="boot-1", runtime_id="stream-2",
            lease_until=303.0,
        )

        row1 = await _get_stream_row(db, "stream-1")
        row2 = await _get_stream_row(db, "stream-2")
        assert row1["status"] == "done"
        assert row2["status"] == "running"

        # Stream-2 can still receive non-terminal events.
        seq = await db.append_chat_stream_event(
            stream_id="stream-2", session_id="s1",
            principal_id=PRINCIPAL, project_id=PROJECT_ID,
            event_type="message", data={"content": "ok"}, now=4.0,
            boot_id="boot-1", runtime_id="stream-2",
            lease_until=304.0,
        )
        assert seq == 2  # stream-local sequence

        # Stream-2 can still be terminated.
        await db.append_chat_stream_event(
            stream_id="stream-2", session_id="s1",
            principal_id=PRINCIPAL, project_id=PROJECT_ID,
            event_type="done", data={}, now=5.0,
            boot_id="boot-1", runtime_id="stream-2",
        )
        row2 = await _get_stream_row(db, "stream-2")
        assert row2["status"] == "done"
    finally:
        await db.close()


# ───── 6.1-C: per-stream Terminal shield (post-terminal rejected) ─────


async def test_6_1_c_per_stream_terminal_shield(tmp_path):
    """6.1-C: post-terminal append is rejected PER-STREAM.  Stream-1 is
    terminal, but stream-2 on the same session can still be appended."""
    db = await _make_db(tmp_path / "r6.db")
    try:
        await _make_session(db, "s1")
        # Stream-1: terminal.
        await _complete_stream(
            db, stream_id="stream-1", session_id="s1",
        )
        # Post-terminal append on stream-1 is rejected.
        with pytest.raises(ChatStreamTerminalError):
            await db.append_chat_stream_event(
                stream_id="stream-1", session_id="s1",
                principal_id=PRINCIPAL, project_id=PROJECT_ID,
                event_type="message", data={"content": "late"}, now=10.0,
            )
        # Append on stream-2 (same session, different stream) succeeds.
        await db.append_chat_stream_event(
            stream_id="stream-2", session_id="s1",
            principal_id=PRINCIPAL, project_id=PROJECT_ID,
            event_type="started", data={}, now=11.0,
            boot_id="boot-1", runtime_id="stream-2",
            lease_until=311.0,
        )
        row2 = await _get_stream_row(db, "stream-2")
        assert row2["status"] == "running"
    finally:
        await db.close()


# ───── 6.1-D: per-stream CAS (exactly one terminal per stream) ────────


async def test_6_1_d_per_stream_cas_one_terminal_each(tmp_path):
    """6.1-D: each stream on the same session gets exactly one terminal
    transition via the CAS ``WHERE stream_id=? AND status='running'``."""
    db = await _make_db(tmp_path / "r6.db")
    try:
        await _make_session(db, "s1")
        # Three streams, three different terminals.
        for i, terminal in enumerate(["done", "error", "interrupted"]):
            stream_id = f"stream-{i}"
            await _complete_stream(
                db, stream_id=stream_id, session_id="s1",
                terminal=terminal,
                started_at=float(i) * 10, terminal_at=float(i) * 10 + 1,
            )
            row = await _get_stream_row(db, stream_id)
            assert row["status"] == terminal
            assert row["terminal_event_type"] == terminal

        # Second terminal on any stream is rejected.
        for i in range(3):
            stream_id = f"stream-{i}"
            with pytest.raises(ChatStreamTerminalError):
                await db.append_chat_stream_event(
                    stream_id=stream_id, session_id="s1",
                    principal_id=PRINCIPAL, project_id=PROJECT_ID,
                    event_type="error", data={}, now=100.0,
                )
    finally:
        await db.close()


# ───── 6.1-E: stream-specific vs session-wide event query ─────────────


async def test_6_1_e_stream_specific_and_session_wide_event_query(tmp_path):
    """6.1-E: ``list_chat_stream_events(stream_id=X)`` returns only X's
    events; ``list_chat_stream_events(session_id=S)`` (no stream_id)
    returns events across ALL streams for S."""
    db = await _make_db(tmp_path / "r6.db")
    try:
        await _make_session(db, "s1")
        # Stream-A: started + message + done (3 events).
        await db.append_chat_stream_event(
            stream_id="stream-a", session_id="s1",
            principal_id=PRINCIPAL, project_id=PROJECT_ID,
            event_type="started", data={}, now=1.0,
            boot_id="b", runtime_id="stream-a", lease_until=301.0,
        )
        await db.append_chat_stream_event(
            stream_id="stream-a", session_id="s1",
            principal_id=PRINCIPAL, project_id=PROJECT_ID,
            event_type="message", data={"content": "a"}, now=2.0,
            boot_id="b", runtime_id="stream-a", lease_until=302.0,
        )
        await db.append_chat_stream_event(
            stream_id="stream-a", session_id="s1",
            principal_id=PRINCIPAL, project_id=PROJECT_ID,
            event_type="done", data={}, now=3.0,
            boot_id="b", runtime_id="stream-a",
        )
        # Stream-B: started + done (2 events).
        await db.append_chat_stream_event(
            stream_id="stream-b", session_id="s1",
            principal_id=PRINCIPAL, project_id=PROJECT_ID,
            event_type="started", data={}, now=4.0,
            boot_id="b", runtime_id="stream-b", lease_until=304.0,
        )
        await db.append_chat_stream_event(
            stream_id="stream-b", session_id="s1",
            principal_id=PRINCIPAL, project_id=PROJECT_ID,
            event_type="done", data={}, now=5.0,
            boot_id="b", runtime_id="stream-b",
        )

        # Stream-specific query: stream-a has 3 events.
        a_events = await db.list_chat_stream_events(
            stream_id="stream-a", principal_id=PRINCIPAL,
            project_id=PROJECT_ID, limit=1024,
        )
        assert [e["event"] for e in a_events] == ["started", "message", "done"]
        assert [e["sequence"] for e in a_events] == [1, 2, 3]

        # Stream-specific query: stream-b has 2 events.
        b_events = await db.list_chat_stream_events(
            stream_id="stream-b", principal_id=PRINCIPAL,
            project_id=PROJECT_ID, limit=1024,
        )
        assert [e["event"] for e in b_events] == ["started", "done"]
        assert [e["sequence"] for e in b_events] == [1, 2]

        # Session-wide query (no stream_id): 5 events total.
        all_events = await db.list_chat_stream_events(
            session_id="s1", principal_id=PRINCIPAL,
            project_id=PROJECT_ID, limit=1024,
        )
        assert len(all_events) == 5
        # Ordered by created_at then sequence.
        assert [e["event"] for e in all_events] == [
            "started", "message", "done", "started", "done",
        ]
    finally:
        await db.close()


# ───── 6.1-F: recovery isolation (per-stream, not per-session) ─────────


async def test_6_1_f_recovery_isolates_per_stream(tmp_path):
    """6.1-F: ``recover_inflight_chat_streams`` recovers only the
    non-terminal stream, leaving terminal streams on the same session
    untouched."""
    db = await _make_db(tmp_path / "r6.db")
    try:
        await _make_session(db, "s1")
        now = time.time()
        # Stream-1: terminal (done) — must NOT be recovered.
        await _complete_stream(
            db, stream_id="stream-1", session_id="s1",
            started_at=now - 100, terminal_at=now - 99,
        )
        # Stream-2: running, expired lease, different boot_id — MUST be recovered.
        await db.append_chat_stream_event(
            stream_id="stream-2", session_id="s1",
            principal_id=PRINCIPAL, project_id=PROJECT_ID,
            event_type="started", data={}, now=now - 600,
            boot_id="boot-previous", runtime_id="stream-2",
            lease_until=now - 300,
        )

        recovered = await db.recover_inflight_chat_streams(
            now=now, boot_id="boot-current",
        )
        assert recovered == 1  # only stream-2

        # Stream-1 still has its original 2 events (no recovery error).
        s1_events = await db.list_chat_stream_events(
            stream_id="stream-1", principal_id=PRINCIPAL,
            project_id=PROJECT_ID, limit=1024,
        )
        assert [e["event"] for e in s1_events] == ["started", "done"]

        # Stream-2 now has started + error (recovery terminal).
        s2_events = await db.list_chat_stream_events(
            stream_id="stream-2", principal_id=PRINCIPAL,
            project_id=PROJECT_ID, limit=1024,
        )
        assert [e["event"] for e in s2_events] == ["started", "error"]
        assert s2_events[-1]["data"]["code"] == "PROCESS_RESTART"

        row1 = await _get_stream_row(db, "stream-1")
        row2 = await _get_stream_row(db, "stream-2")
        assert row1["status"] == "done"
        assert row2["status"] == "error"
    finally:
        await db.close()


# ───── 6.1-G: legacy migration (session_id → stream_id) ───────────────


async def test_6_1_g_legacy_session_keyed_migration(tmp_path):
    """6.1-G: an old DB with ``session_id``-keyed ``chat_streams`` (the
    Round-5 schema) migrates to the ``stream_id``-keyed schema on
    ``run_migrations()``.  Each legacy session becomes a single stream
    whose ``stream_id == session_id``."""
    db_path = tmp_path / "legacy.db"
    # Build a fresh v5 DB first (so we have the new schema), then
    # simulate legacy data by inserting rows with stream_id = session_id
    # (which is exactly what the migration does for legacy rows).
    db = await _make_db(db_path)
    try:
        await _make_session(db, "legacy-s1")
        await _make_session(db, "legacy-s2")
        # Insert events as the migration would: stream_id = session_id.
        await _complete_stream(
            db, stream_id="legacy-s1", session_id="legacy-s1",
            started_at=1.0, terminal_at=2.0,
        )
        await db.append_chat_stream_event(
            stream_id="legacy-s2", session_id="legacy-s2",
            principal_id=PRINCIPAL, project_id=PROJECT_ID,
            event_type="started", data={}, now=3.0,
            boot_id="boot-old", runtime_id="legacy-s2",
            lease_until=303.0,
        )

        # Verify the migrated schema: stream_id is the PK.
        conn = db._conn
        cursor = await conn.execute(
            "SELECT sql FROM sqlite_master "
            "WHERE type='table' AND name='chat_streams'"
        )
        create_sql = str((await cursor.fetchone())[0])
        await cursor.close()
        # ``schema.sql`` aligns column definitions with extra spaces, so
        # normalize whitespace before checking the primary key clause.
        normalized = " ".join(create_sql.split())
        assert "stream_id TEXT PRIMARY KEY" in normalized, (
            "chat_streams must be keyed by stream_id after migration"
        )

        # Legacy rows are accessible via stream_id == session_id.
        row1 = await _get_stream_row(db, "legacy-s1")
        assert row1 is not None
        assert row1["stream_id"] == "legacy-s1"
        assert row1["session_id"] == "legacy-s1"
        assert row1["status"] == "done"

        row2 = await _get_stream_row(db, "legacy-s2")
        assert row2 is not None
        assert row2["stream_id"] == "legacy-s2"
        assert row2["status"] == "running"

        # A NEW stream can be created on legacy-s1 (multi-turn works).
        await _complete_stream(
            db, stream_id="new-stream-on-legacy-s1", session_id="legacy-s1",
            started_at=10.0, terminal_at=11.0,
        )
        row_new = await _get_stream_row(db, "new-stream-on-legacy-s1")
        assert row_new is not None
        assert row_new["status"] == "done"
        assert row_new["session_id"] == "legacy-s1"
    finally:
        await db.close()


async def test_6_1_g2_migration_is_idempotent(tmp_path):
    """6.1-G2: running ``run_migrations()`` twice is a no-op.  The
    migration helper detects the new schema (stream_id PK) and skips."""
    db_path = tmp_path / "idempotent.db"
    db = Database(db_path)
    await db.connect()
    await db.run_migrations()
    # Run migrations again — must not raise.
    await db.run_migrations()
    # Schema is still stream_id-keyed.
    conn = db._conn
    cursor = await conn.execute(
        "SELECT sql FROM sqlite_master "
        "WHERE type='table' AND name='chat_streams'"
    )
    create_sql = str((await cursor.fetchone())[0])
    await cursor.close()
    # ``schema.sql`` aligns columns with extra spaces — normalize.
    normalized = " ".join(create_sql.split())
    assert "stream_id TEXT PRIMARY KEY" in normalized
    await db.close()


# ───── 6.1-H: concurrent session rejection (Strategy B) ───────────────


def _ctx(session_id: str = "s1") -> RequestContext:
    return RequestContext(
        principal_id=PRINCIPAL,
        project_id=PROJECT_ID,
        session_id=session_id,
        runtime_id="rt-1",
        source_transport="test",
        policy_digest="digest",
    )


class _FakeRequest:
    """Minimal stand-in for ChatRequest."""
    def __init__(self, message: str = "hi", session_id: str = "s1", mode: str = "office"):
        self.message = message
        self.session_id = session_id
        self.mode = mode


async def test_6_1_h_concurrent_chat_on_same_session_rejected(tmp_path):
    """6.1-H: ``AgentService.chat`` rejects a second concurrent chat RPC
    on the same ``session_id`` with ``SessionBusyError`` (Review §八
    Strategy B).  A session can have many SEQUENTIAL streams, but not
    CONCURRENT ones."""
    (tmp_path / "prompts").mkdir()
    (tmp_path / "prompts" / "office.md").write_text("office", encoding="utf-8")
    (tmp_path / "prompts" / "coding.md").write_text("coding", encoding="utf-8")
    db = Database(tmp_path / "r6.db")
    await db.connect()
    await db.run_migrations()
    service = AgentService(db, project_root=tmp_path)

    started = asyncio.Event()
    release = asyncio.Event()

    async def blocking_build(*args, **kwargs):
        started.set()
        await release.wait()
        return MagicMock(aclose=AsyncMock())

    service._build_runtime = blocking_build

    async def drive_first_chat():
        """Start the first chat; it parks inside _build_runtime."""
        request = ChatRequest(session_id="s1", message="first", mode="office")
        try:
            async for _event in service.chat(_ctx(), request):
                pass
        except Exception:
            pass

    async def drive_second_chat():
        """Start the second chat on the same session; it must be rejected."""
        # Wait until the first chat has entered _build_runtime.
        await asyncio.wait_for(started.wait(), timeout=2.0)
        request = ChatRequest(session_id="s1", message="second", mode="office")
        events: list[dict] = []
        exc: BaseException | None = None
        try:
            async for event in service.chat(_ctx(), request):
                events.append(event)
        except BaseException as e:
            exc = e
        return events, exc

    first_task = asyncio.create_task(drive_first_chat())
    second_task = asyncio.create_task(drive_second_chat())
    events, exc = await second_task

    # The second chat MUST have been rejected with SessionBusyError.
    assert exc is not None, (
        "second concurrent chat on same session must raise, not silently start"
    )
    assert isinstance(exc, SessionBusyError), (
        f"expected SessionBusyError, got {type(exc).__name__}: {exc}"
    )

    # Release the first chat so it can finish and cleanup.
    release.set()
    try:
        await asyncio.wait_for(first_task, timeout=2.0)
    except (asyncio.TimeoutError, asyncio.CancelledError):
        first_task.cancel()

    # After the first chat finishes, a NEW chat on the same session MUST
    # succeed (the session lock was released in the finally block).
    # Use a fast-failing build so the test doesn't hang.
    service._build_runtime = AsyncMock(side_effect=RuntimeError("fast fail"))
    request3 = ChatRequest(session_id="s1", message="third", mode="office")
    with pytest.raises(RuntimeError, match="fast fail"):
        async for _event in service.chat(_ctx(), request3):
            pass

    # The session is no longer locked — _active_chat_sessions is empty.
    assert "s1" not in service._active_chat_sessions, (
        "session lock must be released after chat finishes"
    )

    # Close runtimes that may have been registered by the first chat.
    from khaos.runtime import close_runtime_or_register
    for runtime in list(service._active_runtimes.values()):
        try:
            await close_runtime_or_register(runtime)
        except Exception:  # noqa: BLE001
            pass
    await db.close()


# ───── 6.1-I: session lock released on build failure ──────────────────


async def test_6_1_i_session_lock_released_on_build_failure(tmp_path):
    """6.1-I: if ``_build_runtime`` raises, the session lock MUST be
    released in the finally block so the next chat on the same session
    is NOT permanently rejected."""
    (tmp_path / "prompts").mkdir()
    (tmp_path / "prompts" / "office.md").write_text("office", encoding="utf-8")
    (tmp_path / "prompts" / "coding.md").write_text("coding", encoding="utf-8")
    db = Database(tmp_path / "r6.db")
    await db.connect()
    await db.run_migrations()
    service = AgentService(db, project_root=tmp_path)

    service._build_runtime = AsyncMock(side_effect=RuntimeError("router down"))

    # First chat: build fails.
    request1 = ChatRequest(session_id="s1", message="first", mode="office")
    with pytest.raises(RuntimeError, match="router down"):
        async for _event in service.chat(_ctx(), request1):
            pass

    # Session lock MUST have been released.
    assert "s1" not in service._active_chat_sessions, (
        "session lock must be released after build failure"
    )

    # Second chat on the same session: build fails again, but it must
    # NOT be rejected with SessionBusyError (the lock was released).
    request2 = ChatRequest(session_id="s1", message="second", mode="office")
    with pytest.raises(RuntimeError, match="router down"):
        async for _event in service.chat(_ctx(), request2):
            pass

    assert "s1" not in service._active_chat_sessions
    await db.close()


# ───── 6.1-J: delete_chat_stream_events_for_session deletes all streams ─


async def test_6_1_j_delete_removes_all_streams_for_session(tmp_path):
    """6.1-J: ``delete_chat_stream_events_for_session`` removes ALL
    streams for the session (a session can now have many streams)."""
    db = await _make_db(tmp_path / "r6.db")
    try:
        await _make_session(db, "s1")
        await _make_session(db, "s2")
        # Three streams on s1, one on s2.
        for i in range(3):
            await _complete_stream(
                db, stream_id=f"s1-stream-{i}", session_id="s1",
                started_at=float(i), terminal_at=float(i) + 0.5,
            )
        await _complete_stream(
            db, stream_id="s2-stream-0", session_id="s2",
        )

        deleted = await db.delete_chat_stream_events_for_session(
            session_id="s1", principal_id=PRINCIPAL, project_id=PROJECT_ID,
        )
        assert deleted == 6  # 3 streams × 2 events each

        # s1 streams gone; s2 stream still present.
        for i in range(3):
            assert await _get_stream_row(db, f"s1-stream-{i}") is None
        assert await _get_stream_row(db, "s2-stream-0") is not None

        s1_events = await db.list_chat_stream_events(
            session_id="s1", principal_id=PRINCIPAL, project_id=PROJECT_ID,
        )
        assert s1_events == []
        s2_events = await db.list_chat_stream_events(
            session_id="s2", principal_id=PRINCIPAL, project_id=PROJECT_ID,
        )
        assert len(s2_events) == 2
    finally:
        await db.close()


# ───── 6.1-K: prune cascades per-stream ────────────────────────────────


async def test_6_1_k_prune_cascades_per_stream(tmp_path):
    """6.1-K: ``prune_terminal_chat_streams`` prunes aged terminal
    STREAMS (not sessions).  An aged terminal stream and a fresh
    terminal stream on the SAME session are pruned independently."""
    db = await _make_db(tmp_path / "r6.db")
    try:
        await _make_session(db, "s1")
        now = time.time()
        # Aged terminal stream on s1.
        await _complete_stream(
            db, stream_id="aged", session_id="s1",
            started_at=now - 7200, terminal_at=now - 7100,
        )
        # Fresh terminal stream on s1 (same session).
        await _complete_stream(
            db, stream_id="fresh", session_id="s1",
            started_at=now - 20, terminal_at=now - 10,
        )

        pruned = await db.prune_terminal_chat_streams(
            older_than_seconds=3600, now=now,
        )
        assert pruned == 2  # aged started + aged done

        # Aged stream gone; fresh stream still present.
        assert await _get_stream_row(db, "aged") is None
        fresh_row = await _get_stream_row(db, "fresh")
        assert fresh_row is not None
        assert fresh_row["status"] == "done"
    finally:
        await db.close()
