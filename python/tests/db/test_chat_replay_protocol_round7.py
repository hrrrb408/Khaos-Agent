"""Batch 7.2 (round-7): Chat Replay Protocol + Owner Binding.

Closes review §十四 (Critical: session-wide replay cursor used stream-local
``sequence``, missing events across streams on reconnect) and §十五 (High:
``append_chat_stream_event`` did not verify the stream's owner, allowing a
caller that knows a foreign ``stream_id`` to mutate its state machine).

§十四 fix: ``chat_stream_events`` now has a session-global ``event_id``
(AUTOINCREMENT).  Replay paginates on ``event_id > ?`` (truly monotonic),
and each event dict carries ``event_id`` + ``stream_id``.

§十五 fix: ``append_chat_stream_event`` reads back the stream row and
verifies ``(session_id, principal_id, project_id)`` match the caller; all
CAS UPDATEs carry the full owner predicate.
"""

from __future__ import annotations

import time

import pytest

from khaos.db import Database
from khaos.db.database import (
    ChatStreamOwnerMismatchError,
    ChatStreamTerminalError,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _seed_session(db, session_id="s1", principal_id="alice", project_id="proj1"):
    """Create a session row so the chat_events FK is satisfied."""
    conn = await db._require_writer_conn()
    await conn.execute(
        "INSERT OR IGNORE INTO sessions "
        "(id, mode, status, principal_id, project_id, created_at, updated_at) "
        "VALUES (?, 'office', 'active', ?, ?, datetime('now'), datetime('now'))",
        (session_id, principal_id, project_id),
    )
    await conn.commit()


async def _append(db, stream_id, n, *, session_id="s1", principal_id="alice",
                  project_id="proj1", event_type="message", base_now=1000.0):
    """Append ``n`` events to ``stream_id``; return the list of event_ids."""
    ids = []
    for i in range(n):
        seq = await db.append_chat_stream_event(
            stream_id=stream_id, session_id=session_id,
            principal_id=principal_id, project_id=project_id,
            event_type=event_type, data={"i": i}, now=base_now + i,
        )
        # Read back the event_id (the append returns stream-local sequence).
        conn = await db._require_conn()
        row = await (await conn.execute(
            "SELECT event_id FROM chat_stream_events "
            "WHERE stream_id=? AND sequence=?",
            (stream_id, seq),
        )).fetchone()
        ids.append(int(row["event_id"]))
    return ids


# ===========================================================================
# §十四 — Session-global event_id cursor (no missed events across streams)
# ===========================================================================


async def test_s14_session_wide_replay_no_missed_events_across_streams(tmp_path):
    """§十四 core fix: session-wide replay with ``after_sequence > 0`` must
    NOT miss events from other streams whose stream-local ``sequence`` is
    <= the cursor.

    Setup: stream-A gets events (event_id 1,2,3; stream-local seq 1,2,3).
    Then stream-B gets events (event_id 4,5; stream-local seq 1,2).
    A cursor of event_id=3 must return stream-B's events (event_id 4,5),
    even though their stream-local sequence is 1,2 (which the old
    ``sequence > 3`` filter would have dropped).
    """
    db = Database(tmp_path / "replay.db")
    await db.connect()
    await db.run_migrations()
    await _seed_session(db)
    a_ids = await _append(db, "stream-A", 3, base_now=1000.0)
    b_ids = await _append(db, "stream-B", 2, base_now=2000.0)
    assert a_ids == [1, 2, 3]
    assert b_ids == [4, 5]
    # Replay session-wide after event_id=3 (last of stream-A).
    events = await db.list_chat_stream_events(
        session_id="s1", principal_id="alice", project_id="proj1",
        after_sequence=3,
    )
    # Must get stream-B's two events (event_id 4,5), NOT an empty list.
    assert [e["event_id"] for e in events] == [4, 5], (
        "session-wide replay after event_id=3 missed stream-B events "
        "(the old stream-local sequence>3 filter would have dropped them)"
    )
    assert all(e["stream_id"] == "stream-B" for e in events)
    await db.close()


async def test_s14_event_id_is_session_global_monotonic(tmp_path):
    """§十四: event_id is monotonic across ALL streams in a session — it
    never resets to 1 for a new stream.  stream-local ``sequence`` does
    reset, but event_id does not."""
    db = Database(tmp_path / "monotonic.db")
    await db.connect()
    await db.run_migrations()
    await _seed_session(db)
    await _append(db, "sa", 2)  # event_id 1,2
    await _append(db, "sb", 2)  # event_id 3,4
    await _append(db, "sc", 2)  # event_id 5,6
    events = await db.list_chat_stream_events(
        session_id="s1", principal_id="alice", project_id="proj1",
    )
    ids = [e["event_id"] for e in events]
    assert ids == [1, 2, 3, 4, 5, 6], f"event_id not session-global: {ids}"
    # stream-local sequences reset per stream.
    sa = [e for e in events if e["stream_id"] == "sa"]
    sb = [e for e in events if e["stream_id"] == "sb"]
    assert [e["sequence"] for e in sa] == [1, 2]
    assert [e["sequence"] for e in sb] == [1, 2]
    await db.close()


async def test_s14_replay_returns_stream_id_and_event_id(tmp_path):
    """§十四: each replayed event dict must carry ``event_id`` (the cursor)
    and ``stream_id`` (so the client can attribute events to streams)."""
    db = Database(tmp_path / "fields.db")
    await db.connect()
    await db.run_migrations()
    await _seed_session(db)
    await _append(db, "sa", 1)
    events = await db.list_chat_stream_events(
        session_id="s1", principal_id="alice", project_id="proj1",
    )
    e = events[0]
    assert "event_id" in e and "stream_id" in e
    assert e["event_id"] == 1
    assert e["stream_id"] == "sa"
    # Legacy fields preserved.
    for k in ("sequence", "event", "data", "terminal", "created_at"):
        assert k in e
    await db.close()


async def test_s14_stream_specific_replay_still_works(tmp_path):
    """§十四: the stream-specific path (``stream_id`` non-empty) still
    replays correctly using event_id cursor."""
    db = Database(tmp_path / "stream.db")
    await db.connect()
    await db.run_migrations()
    await _seed_session(db)
    await _append(db, "sa", 3)  # event_id 1,2,3
    await _append(db, "sb", 2)  # event_id 4,5
    # Stream-specific: only sa's events, after event_id=1.
    events = await db.list_chat_stream_events(
        stream_id="sa", principal_id="alice", project_id="proj1",
        after_sequence=1,
    )
    assert [e["event_id"] for e in events] == [2, 3]
    assert all(e["stream_id"] == "sa" for e in events)
    await db.close()


async def test_s14_reconnect_resumes_with_no_gaps_no_duplicates(tmp_path):
    """§十四 acceptance: simulate 10 streams × 10 events, then replay the
    full session in pages of 5 using the event_id cursor — the union must
    be exactly all 100 events with no gaps and no duplicates."""
    db = Database(tmp_path / "page.db")
    await db.connect()
    await db.run_migrations()
    await _seed_session(db)
    total = 0
    for s in range(10):
        await _append(db, f"s{s}", 10, base_now=1000.0 + s * 100)
        total += 10
    # Page through.
    cursor = 0
    seen = []
    while True:
        page = await db.list_chat_stream_events(
            session_id="s1", principal_id="alice", project_id="proj1",
            after_sequence=cursor, limit=5,
        )
        if not page:
            break
        for e in page:
            seen.append(e["event_id"])
        cursor = page[-1]["event_id"]
    assert seen == list(range(1, total + 1)), (
        f"pagination had gaps/dupes: got {len(seen)} events, expected {total}"
    )
    await db.close()


# ===========================================================================
# §十五 — Stream Owner Binding
# ===========================================================================


async def test_s15_cross_principal_stream_forgery_rejected(tmp_path):
    """§十五: a caller (bob) that knows alice's stream_id cannot append
    events to it — ``append_chat_stream_event`` verifies the stream's
    owner matches the caller and raises ``ChatStreamOwnerMismatchError``."""
    db = Database(tmp_path / "owner.db")
    await db.connect()
    await db.run_migrations()
    await _seed_session(db, session_id="s-alice", principal_id="alice")
    await _seed_session(db, session_id="s-bob", principal_id="bob")
    # alice creates a stream.
    await db.append_chat_stream_event(
        stream_id="alice-stream", session_id="s-alice",
        principal_id="alice", project_id="proj1",
        event_type="message", data={}, now=1000.0,
    )
    # bob tries to append to alice's stream using bob's own session.
    with pytest.raises(ChatStreamOwnerMismatchError):
        await db.append_chat_stream_event(
            stream_id="alice-stream", session_id="s-bob",
            principal_id="bob", project_id="proj1",
            event_type="message", data={"evil": True}, now=1001.0,
        )
    # bob also cannot terminal it.
    with pytest.raises(ChatStreamOwnerMismatchError):
        await db.append_chat_stream_event(
            stream_id="alice-stream", session_id="s-bob",
            principal_id="bob", project_id="proj1",
            event_type="done", data={}, now=1002.0,
        )
    await db.close()


async def test_s15_cross_project_stream_forgery_rejected(tmp_path):
    """§十五: same principal, different project — the stream belongs to
    proj1, a proj2 caller is refused."""
    db = Database(tmp_path / "xproj.db")
    await db.connect()
    await db.run_migrations()
    await _seed_session(db, session_id="s1", principal_id="alice", project_id="proj1")
    await _seed_session(db, session_id="s1", principal_id="alice", project_id="proj2")
    await db.append_chat_stream_event(
        stream_id="p1-stream", session_id="s1",
        principal_id="alice", project_id="proj1",
        event_type="message", data={}, now=1000.0,
    )
    with pytest.raises(ChatStreamOwnerMismatchError):
        await db.append_chat_stream_event(
            stream_id="p1-stream", session_id="s1",
            principal_id="alice", project_id="proj2",
            event_type="message", data={}, now=1001.0,
        )
    await db.close()


async def test_s15_same_owner_append_succeeds(tmp_path):
    """§十五 sanity: the legitimate owner can still append freely — the
    owner check does not break the happy path."""
    db = Database(tmp_path / "ok.db")
    await db.connect()
    await db.run_migrations()
    await _seed_session(db)
    for i in range(5):
        await db.append_chat_stream_event(
            stream_id="my-stream", session_id="s1",
            principal_id="alice", project_id="proj1",
            event_type="message", data={"i": i}, now=1000.0 + i,
        )
    events = await db.list_chat_stream_events(
        stream_id="my-stream", principal_id="alice", project_id="proj1",
    )
    assert len(events) == 5
    await db.close()


# ===========================================================================
# v7 migration: event_id backfill on old DBs
# ===========================================================================


async def test_v7_event_id_backfilled_on_upgrade(tmp_path):
    """``_ensure_chat_event_id_column`` must add ``event_id`` to a table
    that lacks it (the pre-v7 state), preserving all existing data and
    assigning monotonic event_ids.

    We model the pre-v7 state by rebuilding the table without event_id,
    then call the v7 migrator directly (a full ``run_migrations`` would
    also re-run the Batch 6.1 rebuild, which is a separate concern)."""
    db = Database(tmp_path / "upgrade.db")
    await db.connect()
    await db.run_migrations()
    await _seed_session(db)
    await _append(db, "sa", 2)
    await _append(db, "sb", 1)
    # Rebuild the table to the pre-v7 shape (no event_id, composite PK).
    import sqlite3
    raw = sqlite3.connect(str(tmp_path / "upgrade.db"))
    raw.executescript(
        """
        CREATE TABLE _cse_backup AS SELECT stream_id, session_id,
            principal_id, project_id, sequence, event_type, data_json,
            is_terminal, created_at FROM chat_stream_events;
        DROP TABLE chat_stream_events;
        CREATE TABLE chat_stream_events (
            stream_id TEXT NOT NULL, session_id TEXT NOT NULL,
            principal_id TEXT NOT NULL, project_id TEXT NOT NULL DEFAULT '',
            sequence INTEGER NOT NULL, event_type TEXT NOT NULL,
            data_json TEXT NOT NULL DEFAULT '{}',
            is_terminal INTEGER NOT NULL DEFAULT 0 CHECK(is_terminal IN (0,1)),
            created_at REAL NOT NULL,
            PRIMARY KEY(stream_id, sequence)
        );
        INSERT INTO chat_stream_events SELECT * FROM _cse_backup;
        DROP TABLE _cse_backup;
        """
    )
    raw.commit()
    raw.close()
    # Re-open (fresh connection sees the pre-v7 table) and run the v7 step.
    # The migrator uses _require_conn() which routes to the writer only when
    # wrapped in _MigrationConnection (as run_migrations does); mirror that.
    from khaos.db.database import _MigrationConnection
    db2 = Database(tmp_path / "upgrade.db")
    await db2.connect()
    writer = await db2._require_writer_conn()
    original = db2._conn
    db2._conn = _MigrationConnection(writer)
    try:
        await db2._ensure_chat_event_id_column()
    finally:
        db2._conn = original
    await writer.commit()  # the _MigrationConnection suppressed the commit
    conn = await db2._require_conn()
    cols = [c["name"] for c in await (await conn.execute(
        "PRAGMA table_info(chat_stream_events)")).fetchall()]
    assert "event_id" in cols
    rows = await (await conn.execute(
        "SELECT event_id, stream_id, sequence FROM "
        "chat_stream_events ORDER BY event_id"
    )).fetchall()
    assert len(rows) == 3
    assert [r["event_id"] for r in rows] == [1, 2, 3]
    await db2.close()
