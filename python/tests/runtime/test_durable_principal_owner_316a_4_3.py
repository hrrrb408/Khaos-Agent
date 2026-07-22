"""M4 batch 3.1.16A-4-3 acceptance tests.

Verifies that the durable ``principal_id`` owner column is stamped on
``sessions`` / ``messages`` / ``agent_turns`` / ``session_bookmarks``
and that every DB read path filters by it.  A-4-1 wired
``RequestContext`` through every service method; A-4-2 made service
bodies consume ``ctx.principal_id`` for in-memory scoping (MemoryStore,
AuditLogger, SubAgentTask).  A-4-3 closes the persistence layer: rows
are stamped at INSERT time and filtered at SELECT time so a different
principal cannot observe another principal's sessions / messages /
bookmarks / search results even with direct DB access.

Coverage:

1. Schema migration — all 4 tables get the ``principal_id`` column
   with ``'legacy'`` default + an index; migration is idempotent.
2. ``sessions`` — ``create_session`` stamps the principal; the
   ``ON CONFLICT DO UPDATE`` does NOT re-stamp ownership (a later
   cross-principal upsert is owner-preserving); ``list_sessions``
   filters by principal.
3. ``messages`` — ``insert_message`` stamps; ``list_messages`` /
   ``get_session_messages`` / ``get_message_window`` /
   ``count_session_messages`` / ``count_messages_before_after`` all
   filter by principal; ``principal_id=None`` is the admin opt-in that
   returns everything.
4. ``agent_turns`` — ``start_agent_turn`` stamps principal_id as a
   top-level column; ``TurnCoordinator.start`` propagates it.
5. ``session_bookmarks`` — ``save_bookmark`` stamps;
   ``ON CONFLICT`` is owner-preserving; ``load_bookmark`` /
   ``list_bookmarks`` filter; ``delete_bookmark`` is scoped (a foreign
   principal's delete is a no-op).
6. ``search_sessions`` — FTS5 results are scoped via JOIN to the base
   ``messages`` table on rowid.
7. :class:`SessionSearch` — every underlying DB call receives
   ``principal_id`` from the constructor; ``None`` is the admin opt-in.
8. :class:`AgentLoop` — ``_persist_message`` and ``_build_context``
   use ``self.principal_id`` for both write and read paths.
"""

from __future__ import annotations

import time
import sqlite3
from unittest.mock import AsyncMock, MagicMock

import pytest

from khaos.agent.core import AgentConfig, AgentLoop, Message
from khaos.agent.events import TurnCoordinator
from khaos.db import Database


# ---------------------------------------------------------------------------
# Schema migration
# ---------------------------------------------------------------------------


async def _column_names(db: Database, table: str) -> set[str]:
    conn = await db._require_conn()
    cursor = await conn.execute(f"PRAGMA table_info({table})")
    return {str(row["name"]) for row in await cursor.fetchall()}


async def _index_names(db: Database, table: str) -> set[str]:
    conn = await db._require_conn()
    cursor = await conn.execute(f"PRAGMA index_list({table})")
    return {str(row["name"]) for row in await cursor.fetchall()}


async def test_migration_adds_principal_id_to_sessions(tmp_path):
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    cols = await _column_names(db, "sessions")
    assert "principal_id" in cols
    idxs = await _index_names(db, "sessions")
    assert "idx_sessions_principal" in idxs
    await db.close()


async def test_migration_adds_principal_id_to_messages(tmp_path):
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    cols = await _column_names(db, "messages")
    assert "principal_id" in cols
    idxs = await _index_names(db, "messages")
    assert "idx_messages_principal" in idxs
    await db.close()


async def test_migration_adds_principal_id_to_agent_turns(tmp_path):
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    cols = await _column_names(db, "agent_turns")
    assert "principal_id" in cols
    await db.close()


async def test_migration_adds_principal_id_to_session_bookmarks(tmp_path):
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    cols = await _column_names(db, "session_bookmarks")
    assert "principal_id" in cols
    idxs = await _index_names(db, "session_bookmarks")
    assert "idx_session_bookmarks_principal" in idxs
    await db.close()


async def test_migration_is_idempotent(tmp_path):
    """Running run_migrations twice must not error and must keep the column."""
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    await db.run_migrations()  # second pass — idempotent
    assert "principal_id" in await _column_names(db, "sessions")
    assert "principal_id" in await _column_names(db, "messages")
    assert "principal_id" in await _column_names(db, "agent_turns")
    assert "principal_id" in await _column_names(db, "session_bookmarks")
    await db.close()


async def test_legacy_rows_default_to_legacy_principal(tmp_path):
    """A row inserted without principal_id gets the 'legacy' default.

    This is the fail-closed default — only pre-A-4-3 callers that haven't
    been migrated use it.  Authenticated principals pass a real id.
    """
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    # Insert via raw SQL to bypass the principal_id parameter entirely.
    conn = await db._require_conn()
    await conn.execute("INSERT INTO sessions(id, mode) VALUES('s1', 'office')")
    await conn.commit()
    cursor = await conn.execute(
        "SELECT principal_id FROM sessions WHERE id = 's1'"
    )
    row = await cursor.fetchone()
    assert row["principal_id"] == "legacy"
    await db.close()


# ---------------------------------------------------------------------------
# sessions table
# ---------------------------------------------------------------------------


async def test_create_session_stamps_principal_id(tmp_path):
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    await db.create_session("s1", "office", principal_id="api:alice")

    conn = await db._require_conn()
    cursor = await conn.execute(
        "SELECT principal_id FROM sessions WHERE id = 's1'"
    )
    row = await cursor.fetchone()
    assert row["principal_id"] == "api:alice"
    await db.close()


async def test_create_session_on_conflict_preserves_original_owner(tmp_path):
    """Once a session is bound to Principal A, Principal B's later
    ``create_session`` for the same id MUST NOT re-stamp ownership.

    The ``ON CONFLICT DO UPDATE`` only refreshes ``mode`` and
    ``updated_at``; ``principal_id`` is immutable after the first INSERT.
    """
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    await db.create_session("s1", "office", principal_id="api:alice")
    # Principal B attempts to "re-create" the same session.
    await db.create_session("s1", "coding", principal_id="api:bob")

    conn = await db._require_conn()
    cursor = await conn.execute(
        "SELECT principal_id, mode FROM sessions WHERE id = 's1'"
    )
    row = await cursor.fetchone()
    # Owner stays Alice; mode refreshes to Bob's value.
    assert row["principal_id"] == "api:alice"
    assert row["mode"] == "coding"
    await db.close()


async def test_list_sessions_filters_by_principal(tmp_path):
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    await db.create_session("alice-s1", principal_id="api:alice")
    await db.create_session("alice-s2", principal_id="api:alice")
    await db.create_session("bob-s1", principal_id="api:bob")

    alice_sessions = await db.list_sessions(principal_id="api:alice")
    alice_ids = {s["id"] for s in alice_sessions}
    assert alice_ids == {"alice-s1", "alice-s2"}

    bob_sessions = await db.list_sessions(principal_id="api:bob")
    bob_ids = {s["id"] for s in bob_sessions}
    assert bob_ids == {"bob-s1"}

    # Admin opt-in: sees everything.
    all_sessions = await db.list_sessions(principal_id=None)
    all_ids = {s["id"] for s in all_sessions}
    assert all_ids == {"alice-s1", "alice-s2", "bob-s1"}
    await db.close()


# ---------------------------------------------------------------------------
# messages table
# ---------------------------------------------------------------------------


async def test_insert_message_stamps_principal_id(tmp_path):
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    await db.create_session("s1", principal_id="api:alice")
    msg = Message(role="user", content="hello", token_count=1)
    await db.insert_message("s1", msg, principal_id="api:alice")

    conn = await db._require_conn()
    cursor = await conn.execute(
        "SELECT principal_id FROM messages WHERE session_id = 's1'"
    )
    row = await cursor.fetchone()
    assert row["principal_id"] == "api:alice"
    await db.close()


async def test_list_messages_filters_by_principal(tmp_path):
    """Principal B's ``list_messages`` returns nothing for Principal A's
    session even if the session_id is known."""
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    await db.create_session("s1", principal_id="api:alice")
    await db.insert_message(
        "s1", Message(role="user", content="alice-secret", token_count=1),
        principal_id="api:alice",
    )

    alice_msgs = await db.list_messages("s1", principal_id="api:alice")
    assert len(alice_msgs) == 1
    assert alice_msgs[0].content == "alice-secret"

    # Principal B sees nothing even with the right session_id.
    bob_msgs = await db.list_messages("s1", principal_id="api:bob")
    assert bob_msgs == []

    # Admin opt-in sees the row.
    admin_msgs = await db.list_messages("s1", principal_id=None)
    assert len(admin_msgs) == 1
    await db.close()


async def test_get_session_messages_rejects_mismatched_principal(tmp_path):
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    await db.create_session("s1", principal_id="api:alice")
    await db.insert_message(
        "s1", Message(role="user", content="m1", token_count=1),
        principal_id="api:alice",
    )
    with pytest.raises(sqlite3.IntegrityError, match="identity mismatch"):
        await db.insert_message(
            "s1", Message(role="user", content="m2", token_count=1),
            principal_id="api:bob",
        )

    alice_msgs = await db.get_session_messages("s1", principal_id="api:alice")
    assert len(alice_msgs) == 1
    assert alice_msgs[0]["content"] == "m1"

    bob_msgs = await db.get_session_messages("s1", principal_id="api:bob")
    assert bob_msgs == []

    admin_msgs = await db.get_session_messages("s1", principal_id=None)
    assert len(admin_msgs) == 1
    await db.close()


async def test_get_message_window_rejects_mismatched_principal(tmp_path):
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    await db.create_session("s1", principal_id="api:alice")
    # The database rejects a different principal before read filtering is
    # needed; valid same-owner rows remain queryable as a window.
    a1_rowid = await db.insert_message(
        "s1", Message(role="user", content="a1", token_count=1),
        principal_id="api:alice",
    )
    with pytest.raises(sqlite3.IntegrityError, match="identity mismatch"):
        await db.insert_message(
            "s1", Message(role="user", content="b1", token_count=1),
            principal_id="api:bob",
        )
    await db.insert_message(
        "s1", Message(role="user", content="a2", token_count=1),
        principal_id="api:alice",
    )

    alice_window = await db.get_message_window(
        "s1", a1_rowid, 5, principal_id="api:alice",
    )
    alice_contents = [m["content"] for m in alice_window]
    assert "b1" not in alice_contents
    assert set(alice_contents) == {"a1", "a2"}

    bob_window = await db.get_message_window(
        "s1", a1_rowid, 5, principal_id="api:bob",
    )
    assert bob_window == []
    await db.close()


async def test_count_session_messages_filters_by_principal(tmp_path):
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    await db.create_session("s1", principal_id="api:alice")
    for i in range(3):
        await db.insert_message(
            "s1", Message(role="user", content=f"a{i}", token_count=1),
            principal_id="api:alice",
        )
    with pytest.raises(sqlite3.IntegrityError, match="identity mismatch"):
        await db.insert_message(
            "s1", Message(role="user", content="b1", token_count=1),
            principal_id="api:bob",
        )

    assert await db.count_session_messages("s1", principal_id="api:alice") == 3
    assert await db.count_session_messages("s1", principal_id="api:bob") == 0
    assert await db.count_session_messages("s1", principal_id=None) == 3
    await db.close()


async def test_count_messages_before_after_filters_by_principal(tmp_path):
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    await db.create_session("s1", principal_id="api:alice")
    a1 = await db.insert_message(
        "s1", Message(role="user", content="a1", token_count=1),
        principal_id="api:alice",
    )
    with pytest.raises(sqlite3.IntegrityError, match="identity mismatch"):
        await db.insert_message(
            "s1", Message(role="user", content="b1", token_count=1),
            principal_id="api:bob",
        )
    a2 = await db.insert_message(
        "s1", Message(role="user", content="a2", token_count=1),
        principal_id="api:alice",
    )

    # Alice sees the valid row after a1.
    before, after = await db.count_messages_before_after(
        "s1", a1, principal_id="api:alice",
    )
    assert (before, after) == (0, 1)

    before, after = await db.count_messages_before_after(
        "s1", a1, principal_id="api:bob",
    )
    assert (before, after) == (0, 0)

    # Admin sees the same two valid rows.
    before, after = await db.count_messages_before_after(
        "s1", a1, principal_id=None,
    )
    assert (before, after) == (0, 1)
    await db.close()


# ---------------------------------------------------------------------------
# agent_turns table
# ---------------------------------------------------------------------------


async def test_start_agent_turn_stamps_principal_id(tmp_path):
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    await db.create_session("s1", principal_id="api:alice")
    await db.start_agent_turn(
        turn_id="t1",
        attempt_id="a1",
        session_id="s1",
        task_id=None,
        payload={"foo": "bar"},
        now=time.time(),
        principal_id="api:alice",
    )

    conn = await db._require_conn()
    cursor = await conn.execute(
        "SELECT principal_id FROM agent_turns WHERE turn_id = 't1'"
    )
    row = await cursor.fetchone()
    assert row["principal_id"] == "api:alice"
    await db.close()


async def test_turn_coordinator_start_stamps_principal_id(tmp_path):
    """``TurnCoordinator.start`` propagates ``principal_id`` both as a
    top-level column (for fast filtering) and inside the event payload
    (for backward-compat with event-stream consumers)."""
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    await db.create_session("s1", principal_id="api:alice")

    coord = await TurnCoordinator.start(
        db, session_id="s1", task_id=None, principal_id="api:alice",
    )

    conn = await db._require_conn()
    cursor = await conn.execute(
        "SELECT principal_id FROM agent_turns WHERE turn_id = ?",
        (coord.turn_id,),
    )
    row = await cursor.fetchone()
    assert row["principal_id"] == "api:alice"

    # The first event's payload also carries principal_id (back-compat).
    cursor = await conn.execute(
        "SELECT payload_json FROM agent_turn_events "
        "WHERE turn_id = ? AND sequence = 1",
        (coord.turn_id,),
    )
    ev_row = await cursor.fetchone()
    import json
    payload = json.loads(ev_row["payload_json"])
    assert payload["principal_id"] == "api:alice"
    await db.close()


# ---------------------------------------------------------------------------
# session_bookmarks table
# ---------------------------------------------------------------------------


async def test_save_bookmark_stamps_principal_id(tmp_path):
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    await db.create_session("s1", principal_id="api:alice")
    await db.save_bookmark(
        "s1", "mark1", summary="alice's bookmark",
        principal_id="api:alice",
    )

    conn = await db._require_conn()
    cursor = await conn.execute(
        "SELECT principal_id FROM session_bookmarks "
        "WHERE session_id = 's1' AND name = 'mark1'"
    )
    row = await cursor.fetchone()
    assert row["principal_id"] == "api:alice"
    await db.close()


async def test_save_bookmark_on_conflict_preserves_original_owner(tmp_path):
    """Once a bookmark is bound to Principal A, Principal B's later
    ``save_bookmark`` for the same (session, name) MUST NOT re-stamp
    ownership — but the summary / description / mode / project_root /
    summary fields refresh (owner-preserving upsert).
    """
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    await db.create_session("s1", principal_id="api:alice")
    await db.save_bookmark(
        "s1", "mark1", summary="alice-original",
        principal_id="api:alice",
    )
    # Principal B cannot mutate even the non-owner fields through UPSERT.
    with pytest.raises(sqlite3.IntegrityError, match="identity mismatch"):
        await db.save_bookmark(
            "s1", "mark1", summary="bob-attempt", mode="coding",
            principal_id="api:bob",
        )

    bm = await db.load_bookmark("s1", "mark1", principal_id=None)
    # Owner and mutable fields remain Alice's values.
    assert bm["principal_id"] == "api:alice"
    assert bm["summary"] == "alice-original"
    await db.close()


async def test_load_bookmark_filters_by_principal(tmp_path):
    """Principal B's ``load_bookmark`` returns None for Principal A's
    bookmark — existence is hidden, matching the TaskService.get pattern."""
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    await db.create_session("s1", principal_id="api:alice")
    await db.save_bookmark(
        "s1", "mark1", principal_id="api:alice",
    )

    alice_bm = await db.load_bookmark("s1", "mark1", principal_id="api:alice")
    assert alice_bm is not None
    assert alice_bm["principal_id"] == "api:alice"

    bob_bm = await db.load_bookmark("s1", "mark1", principal_id="api:bob")
    assert bob_bm is None

    admin_bm = await db.load_bookmark("s1", "mark1", principal_id=None)
    assert admin_bm is not None
    await db.close()


async def test_list_bookmarks_filters_by_principal(tmp_path):
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    await db.create_session("s1", principal_id="api:alice")
    await db.save_bookmark("s1", "a1", principal_id="api:alice")
    await db.save_bookmark("s1", "a2", principal_id="api:alice")
    with pytest.raises(sqlite3.IntegrityError, match="identity mismatch"):
        await db.save_bookmark("s1", "b1", principal_id="api:bob")

    alice_bms = await db.list_bookmarks("s1", principal_id="api:alice")
    alice_names = {b["name"] for b in alice_bms}
    assert alice_names == {"a1", "a2"}

    bob_bms = await db.list_bookmarks("s1", principal_id="api:bob")
    bob_names = {b["name"] for b in bob_bms}
    assert bob_names == set()

    admin_bms = await db.list_bookmarks("s1", principal_id=None)
    admin_names = {b["name"] for b in admin_bms}
    assert admin_names == {"a1", "a2"}
    await db.close()


async def test_delete_bookmark_is_principal_scoped(tmp_path):
    """Principal B's ``delete_bookmark`` for Principal A's bookmark is
    a no-op — the DELETE is scoped to ``principal_id`` so it affects 0
    rows.  Principal A's own delete succeeds.
    """
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    await db.create_session("s1", principal_id="api:alice")
    await db.save_bookmark("s1", "mark1", principal_id="api:alice")

    # Bob's delete is a no-op.
    await db.delete_bookmark("s1", "mark1", principal_id="api:bob")
    assert await db.load_bookmark("s1", "mark1", principal_id=None) is not None

    # Alice's own delete works.
    await db.delete_bookmark("s1", "mark1", principal_id="api:alice")
    assert await db.load_bookmark("s1", "mark1", principal_id=None) is None

    # Admin delete (principal_id=None) on a remaining bookmark works.
    await db.save_bookmark("s1", "mark2", principal_id="api:alice")
    await db.delete_bookmark("s1", "mark2", principal_id=None)
    assert await db.load_bookmark("s1", "mark2", principal_id=None) is None
    await db.close()


# ---------------------------------------------------------------------------
# search_sessions — FTS5 scoping via JOIN
# ---------------------------------------------------------------------------


async def test_search_sessions_filters_by_principal(tmp_path):
    """FTS5 results are scoped via JOIN to the base ``messages`` table
    on rowid.  Principal B's search for a term in Principal A's message
    returns nothing."""
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    await db.create_session("s1", principal_id="api:alice")
    # Alice writes a message containing a searchable term.
    rowid = await db.insert_message(
        "s1",
        Message(role="user", content="alice loves cryptography", token_count=3),
        principal_id="api:alice",
    )
    await db.insert_message_fts("s1", "user", "alice loves cryptography", 3, rowid=rowid)

    # Alice finds her message.
    alice_results = await db.search_sessions("cryptography", principal_id="api:alice")
    assert len(alice_results) == 1
    assert "cryptography" in alice_results[0]["snippet"]

    # Bob does not find Alice's message.
    bob_results = await db.search_sessions("cryptography", principal_id="api:bob")
    assert bob_results == []

    # Admin opt-in finds it.
    admin_results = await db.search_sessions("cryptography", principal_id=None)
    assert len(admin_results) == 1
    await db.close()


# ---------------------------------------------------------------------------
# SessionSearch — principal_id propagation
# ---------------------------------------------------------------------------


async def test_session_search_passes_principal_id_to_search(tmp_path):
    """``SessionSearch(principal_id=...)`` filters search results."""
    from khaos.session import SessionSearch

    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    await db.create_session("s1", principal_id="api:alice")
    rowid = await db.insert_message(
        "s1",
        Message(role="user", content="secret project blue", token_count=3),
        principal_id="api:alice",
    )
    await db.insert_message_fts("s1", "user", "secret project blue", 3, rowid=rowid)

    alice_search = SessionSearch(db, principal_id="api:alice")
    results = await alice_search.search("secret")
    assert len(results) == 1

    bob_search = SessionSearch(db, principal_id="api:bob")
    results = await bob_search.search("secret")
    assert results == []

    admin_search = SessionSearch(db, principal_id=None)
    results = await admin_search.search("secret")
    assert len(results) == 1
    await db.close()


async def test_session_search_passes_principal_id_to_browse(tmp_path):
    """``SessionSearch.browse`` only lists sessions owned by the principal."""
    from khaos.session import SessionSearch

    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    await db.create_session("alice-s1", principal_id="api:alice")
    await db.create_session("bob-s1", principal_id="api:bob")

    alice_search = SessionSearch(db, principal_id="api:alice")
    summaries = await alice_search.browse()
    ids = {s.session_id for s in summaries}
    assert ids == {"alice-s1"}

    admin_search = SessionSearch(db, principal_id=None)
    summaries = await admin_search.browse()
    ids = {s.session_id for s in summaries}
    assert ids == {"alice-s1", "bob-s1"}
    await db.close()


async def test_session_search_passes_principal_id_to_read_session(tmp_path):
    """``SessionSearch.read_session`` only returns messages owned by the principal."""
    from khaos.session import SessionSearch

    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    await db.create_session("s1", principal_id="api:alice")
    await db.insert_message(
        "s1", Message(role="user", content="alice-secret", token_count=1),
        principal_id="api:alice",
    )
    with pytest.raises(sqlite3.IntegrityError, match="identity mismatch"):
        await db.insert_message(
            "s1", Message(role="user", content="bob-injected", token_count=1),
            principal_id="api:bob",
        )

    alice_search = SessionSearch(db, principal_id="api:alice")
    msgs = await alice_search.read_session("s1")
    assert len(msgs) == 1
    assert msgs[0]["content"] == "alice-secret"

    bob_search = SessionSearch(db, principal_id="api:bob")
    msgs = await bob_search.read_session("s1")
    assert msgs == []
    await db.close()


# ---------------------------------------------------------------------------
# AgentLoop — _persist_message + _build_context use self.principal_id
# ---------------------------------------------------------------------------


def _build_loop(db, *, principal_id: str | None = None) -> AgentLoop:
    """Construct a minimal AgentLoop with a mock router + mode_manager."""
    mode_manager = MagicMock()
    mode_manager.current_mode.value = "office"
    mode_manager.mode_config.preferred_model_function = "chat"
    mode_manager.load_system_prompt = AsyncMock(return_value="system prompt")
    router = MagicMock()
    router.call = AsyncMock(return_value=iter([]))
    return AgentLoop(
        config=AgentConfig(max_turns=1),
        mode_manager=mode_manager,
        router=router,
        db=db,
        principal_id=principal_id,
    )


async def test_agent_loop_persist_message_uses_self_principal_id(tmp_path):
    """``_persist_message`` stamps ``self.principal_id`` on the message row."""
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    await db.create_session("s1", principal_id="api:alice")

    loop = _build_loop(db, principal_id="api:alice")
    msg = Message(role="user", content="hello", token_count=1)
    await loop._persist_message("s1", msg)

    persisted = await db.list_messages("s1", principal_id="api:alice")
    assert len(persisted) == 1
    assert persisted[0].content == "hello"

    # A different principal cannot see the message.
    bob_persisted = await db.list_messages("s1", principal_id="api:bob")
    assert bob_persisted == []
    await db.close()


async def test_agent_loop_build_context_filters_by_self_principal_id(tmp_path):
    """``_build_context`` only returns messages owned by ``self.principal_id``.

    A message injected under a foreign principal must NOT leak into the
    loop's context window — that would let a different principal's writes
    steer the model.
    """
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    await db.create_session("s1", principal_id="api:alice")
    # Alice's message — should appear in alice's context.
    await db.insert_message(
        "s1", Message(role="user", content="alice-context", token_count=1),
        principal_id="api:alice",
    )
    # Bob's message is rejected before it can poison Alice's context.
    with pytest.raises(sqlite3.IntegrityError, match="identity mismatch"):
        await db.insert_message(
            "s1", Message(role="user", content="bob-poison", token_count=1),
            principal_id="api:bob",
        )

    loop = _build_loop(db, principal_id="api:alice")
    messages = await loop._build_context("s1", "next user input")
    contents = [m.content for m in messages]
    assert "alice-context" in contents
    assert "bob-poison" not in contents
    await db.close()
