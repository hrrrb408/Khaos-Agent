"""Round-4 review Batch 3: Project Identity Closure (H-02 ~ H-06).

These tests verify that every production Repository query enforces
``project_id`` as an independent owner dimension, and that
owner-preserving upserts reject foreign callers (H-05/H-06).

Attack scenario: two projects (proj-a, proj-b) share the same SQLite
DB and the same principal.  Without project_id enforcement, a caller
bound to proj-a can read proj-b's sessions, messages, audit logs,
bookmarks, subagent tasks, scheduled tasks, and coding tasks.

Each test inserts rows for both projects, then queries with
``project_id="proj-a"`` and asserts proj-b's rows are absent.
"""

from __future__ import annotations

import pytest

from khaos.db import Database
from khaos.db.database import OwnerMismatchError
from khaos.agent.core import Message
from khaos.scheduler import ScheduleConfig


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------


async def _make_db(tmp_path) -> Database:
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    return db


_PRINCIPAL = "api:alice"
_PROJ_A = "proj-a"
_PROJ_B = "proj-b"


# ---------------------------------------------------------------------------
# H-05: create_session Owner-Match predicate
# ---------------------------------------------------------------------------


async def test_h05_create_session_foreign_principal_raises(tmp_path):
    """A foreign principal colliding on an existing session_id is
    rejected with ``OwnerMismatchError`` (not silently mutated)."""
    db = await _make_db(tmp_path)
    await db.create_session("s1", "office", principal_id=_PRINCIPAL, project_id=_PROJ_A)
    with pytest.raises(OwnerMismatchError):
        await db.create_session("s1", "coding", principal_id="api:bob", project_id=_PROJ_A)
    await db.close()


async def test_h05_create_session_foreign_project_raises(tmp_path):
    """Same principal, different project — also rejected."""
    db = await _make_db(tmp_path)
    await db.create_session("s2", "office", principal_id=_PRINCIPAL, project_id=_PROJ_A)
    with pytest.raises(OwnerMismatchError):
        await db.create_session("s2", "coding", principal_id=_PRINCIPAL, project_id=_PROJ_B)
    await db.close()


async def test_h05_create_session_same_owner_updates_mode(tmp_path):
    """Same (principal, project) — the upsert refreshes mode (predicate matches)."""
    db = await _make_db(tmp_path)
    await db.create_session("s3", "office", principal_id=_PRINCIPAL, project_id=_PROJ_A)
    await db.create_session("s3", "coding", principal_id=_PRINCIPAL, project_id=_PROJ_A)
    conn = await db._require_conn()
    cursor = await conn.execute("SELECT mode FROM sessions WHERE id = 's3'")
    row = await cursor.fetchone()
    assert row["mode"] == "coding"
    await db.close()


# ---------------------------------------------------------------------------
# H-06: save_bookmark Owner-Match predicate
# ---------------------------------------------------------------------------


async def test_h06_save_bookmark_foreign_principal_raises(tmp_path):
    """A foreign principal colliding on (session_id, name) is rejected.

    The session-identity trigger (``trg_session_bookmarks_session_
    identity_insert``) is the PRIMARY defense for child tables: it
    aborts the INSERT before the ON CONFLICT path is reached because
    no session row matches the foreign (principal_id, project_id).
    The H-06 Owner-Match predicate is defense-in-depth for the
    unreachable case where a mismatched bookmark row already exists
    (e.g. legacy data created before the trigger).
    """
    import sqlite3

    db = await _make_db(tmp_path)
    await db.create_session("bk1", principal_id=_PRINCIPAL, project_id=_PROJ_A)
    await db.save_bookmark("bk1", "snap", description="A",
                           principal_id=_PRINCIPAL, project_id=_PROJ_A)
    with pytest.raises(sqlite3.IntegrityError, match="session identity mismatch"):
        await db.save_bookmark("bk1", "snap", description="B",
                               principal_id="api:bob", project_id=_PROJ_A)
    await db.close()


async def test_h06_save_bookmark_foreign_project_raises(tmp_path):
    """Same principal, different project — also rejected by the trigger."""
    import sqlite3

    db = await _make_db(tmp_path)
    await db.create_session("bk2", principal_id=_PRINCIPAL, project_id=_PROJ_A)
    await db.save_bookmark("bk2", "snap", description="A",
                           principal_id=_PRINCIPAL, project_id=_PROJ_A)
    with pytest.raises(sqlite3.IntegrityError, match="session identity mismatch"):
        await db.save_bookmark("bk2", "snap", description="B",
                               principal_id=_PRINCIPAL, project_id=_PROJ_B)
    await db.close()


async def test_h06_save_bookmark_same_owner_updates(tmp_path):
    """Same owner — the upsert refreshes the bookmark content."""
    db = await _make_db(tmp_path)
    await db.create_session("bk3", principal_id=_PRINCIPAL, project_id=_PROJ_A)
    await db.save_bookmark("bk3", "snap", description="old",
                           principal_id=_PRINCIPAL, project_id=_PROJ_A)
    await db.save_bookmark("bk3", "snap", description="new",
                           principal_id=_PRINCIPAL, project_id=_PROJ_A)
    bm = await db.load_bookmark("bk3", "snap", principal_id=_PRINCIPAL,
                                project_id=_PROJ_A)
    assert bm is not None
    assert bm["description"] == "new"
    await db.close()


# ---------------------------------------------------------------------------
# H-02: Session / Message queries filter by project_id
# ---------------------------------------------------------------------------


async def _seed_sessions_messages(db):
    """Insert sessions + messages for two projects under one principal."""
    for proj, sid in [(_PROJ_A, "sa"), (_PROJ_B, "sb")]:
        await db.create_session(sid, "office", principal_id=_PRINCIPAL, project_id=proj)
        rowid = await db.insert_message(
            sid, Message(role="user", content=f"hello-{proj}"),
            principal_id=_PRINCIPAL, project_id=proj,
        )
        await db.insert_message_fts(sid, "user", f"hello-{proj}", 0, rowid=rowid)
        rowid = await db.insert_message(
            sid, Message(role="assistant", content=f"reply-{proj}"),
            principal_id=_PRINCIPAL, project_id=proj,
        )
        await db.insert_message_fts(sid, "assistant", f"reply-{proj}", 0, rowid=rowid)


async def test_h02_list_messages_filters_by_project(tmp_path):
    db = await _make_db(tmp_path)
    await _seed_sessions_messages(db)
    msgs_a = await db.list_messages("sa", principal_id=_PRINCIPAL, project_id=_PROJ_A)
    assert len(msgs_a) == 2
    # proj-b's messages in session sb are not visible via sa anyway, but
    # verify that querying sb with proj-a filter returns NOTHING.
    msgs_b_as_a = await db.list_messages("sb", principal_id=_PRINCIPAL, project_id=_PROJ_A)
    assert len(msgs_b_as_a) == 0
    # Without project_id filter (admin), both sessions' messages are visible.
    msgs_b_admin = await db.list_messages("sb", principal_id=_PRINCIPAL)
    assert len(msgs_b_admin) == 2
    await db.close()


async def test_h02_get_session_filters_by_project(tmp_path):
    db = await _make_db(tmp_path)
    await _seed_sessions_messages(db)
    # proj-a caller asks for proj-b's session — hidden as None.
    assert await db.get_session("sb", principal_id=_PRINCIPAL, project_id=_PROJ_A) is None
    # proj-b caller sees their own session.
    row = await db.get_session("sb", principal_id=_PRINCIPAL, project_id=_PROJ_B)
    assert row is not None and row["id"] == "sb"
    await db.close()


async def test_h02_list_sessions_filters_by_project(tmp_path):
    db = await _make_db(tmp_path)
    await _seed_sessions_messages(db)
    rows_a = await db.list_sessions(principal_id=_PRINCIPAL, project_id=_PROJ_A)
    ids_a = {r["id"] for r in rows_a}
    assert ids_a == {"sa"}
    rows_b = await db.list_sessions(principal_id=_PRINCIPAL, project_id=_PROJ_B)
    ids_b = {r["id"] for r in rows_b}
    assert ids_b == {"sb"}
    await db.close()


async def test_h02_get_session_messages_filters_by_project(tmp_path):
    db = await _make_db(tmp_path)
    await _seed_sessions_messages(db)
    msgs = await db.get_session_messages(
        "sb", principal_id=_PRINCIPAL, project_id=_PROJ_A,
    )
    assert len(msgs) == 0
    msgs = await db.get_session_messages(
        "sb", principal_id=_PRINCIPAL, project_id=_PROJ_B,
    )
    assert len(msgs) == 2
    await db.close()


async def test_h02_count_session_messages_filters_by_project(tmp_path):
    db = await _make_db(tmp_path)
    await _seed_sessions_messages(db)
    assert await db.count_session_messages("sb", principal_id=_PRINCIPAL, project_id=_PROJ_A) == 0
    assert await db.count_session_messages("sb", principal_id=_PRINCIPAL, project_id=_PROJ_B) == 2
    await db.close()


async def test_h02_search_sessions_filters_by_project(tmp_path):
    db = await _make_db(tmp_path)
    await _seed_sessions_messages(db)
    # FTS search for "hello" — each project sees only its own matches.
    results_a = await db.search_sessions("hello", principal_id=_PRINCIPAL, project_id=_PROJ_A)
    assert {r["session_id"] for r in results_a} == {"sa"}
    results_b = await db.search_sessions("hello", principal_id=_PRINCIPAL, project_id=_PROJ_B)
    assert {r["session_id"] for r in results_b} == {"sb"}
    # Admin (no project filter) sees both projects' matches.
    results_all = await db.search_sessions("hello", principal_id=_PRINCIPAL)
    assert {r["session_id"] for r in results_all} == {"sa", "sb"}
    await db.close()


# ---------------------------------------------------------------------------
# H-03: Audit queries filter by project_id
# ---------------------------------------------------------------------------


async def test_h03_query_audit_logs_filters_by_project(tmp_path):
    db = await _make_db(tmp_path)
    for proj in [_PROJ_A, _PROJ_B]:
        await db.insert_audit_log(
            "write_file", f"/tmp/{proj}/x.txt", "success",
            principal_id=_PRINCIPAL, project_id=proj,
        )
    rows_a = await db.query_audit_logs(principal_id=_PRINCIPAL, project_id=_PROJ_A)
    assert len(rows_a) == 1
    assert rows_a[0]["project_id"] == _PROJ_A
    rows_b = await db.query_audit_logs(principal_id=_PRINCIPAL, project_id=_PROJ_B)
    assert len(rows_b) == 1
    assert rows_b[0]["project_id"] == _PROJ_B
    # Admin (no project filter) sees both.
    rows_all = await db.query_audit_logs(principal_id=_PRINCIPAL)
    assert len(rows_all) == 2
    await db.close()


async def test_h03_list_audit_logs_filters_by_project(tmp_path):
    db = await _make_db(tmp_path)
    for proj in [_PROJ_A, _PROJ_B]:
        await db.insert_audit_log(
            "terminal", f"cmd-{proj}", "success",
            principal_id=_PRINCIPAL, project_id=proj,
        )
    rows_a = await db.list_audit_logs(principal_id=_PRINCIPAL, project_id=_PROJ_A)
    assert len(rows_a) == 1
    assert rows_a[0]["project_id"] == _PROJ_A
    rows_b = await db.list_audit_logs(principal_id=_PRINCIPAL, project_id=_PROJ_B)
    assert len(rows_b) == 1
    await db.close()


# ---------------------------------------------------------------------------
# H-04: Subagent / Bookmark / ScheduledTask / CodingTask queries
# ---------------------------------------------------------------------------


async def test_h04_list_subagent_tasks_filters_by_project(tmp_path):
    db = await _make_db(tmp_path)
    for proj, tid in [(_PROJ_A, "sub-a"), (_PROJ_B, "sub-b")]:
        # The session-identity trigger requires a matching parent session.
        sid = f"parent-{proj}"
        await db.create_session(sid, principal_id=_PRINCIPAL, project_id=proj)
        await db.insert_subagent_task(
            tid, sid, f"goal-{proj}", "{}", "[]",
            principal_id=_PRINCIPAL, project_id=proj,
        )
    rows_a = await db.list_subagent_tasks(principal_id=_PRINCIPAL, project_id=_PROJ_A)
    assert {r["id"] for r in rows_a} == {"sub-a"}
    assert rows_a[0]["project_id"] == _PROJ_A
    rows_b = await db.list_subagent_tasks(principal_id=_PRINCIPAL, project_id=_PROJ_B)
    assert {r["id"] for r in rows_b} == {"sub-b"}
    await db.close()


async def test_h04_load_bookmark_filters_by_project(tmp_path):
    db = await _make_db(tmp_path)
    for proj in [_PROJ_A, _PROJ_B]:
        sid = f"sess-{proj}"
        await db.create_session(sid, principal_id=_PRINCIPAL, project_id=proj)
        await db.save_bookmark(sid, "snap", description=f"d-{proj}",
                               principal_id=_PRINCIPAL, project_id=proj)
    # proj-a caller asks for proj-b's bookmark — hidden as None.
    assert await db.load_bookmark("sess-proj-b", "snap",
                                  principal_id=_PRINCIPAL, project_id=_PROJ_A) is None
    # proj-b caller sees their own.
    bm = await db.load_bookmark("sess-proj-b", "snap",
                                principal_id=_PRINCIPAL, project_id=_PROJ_B)
    assert bm is not None and bm["description"] == "d-proj-b"
    await db.close()


async def test_h04_list_bookmarks_filters_by_project(tmp_path):
    db = await _make_db(tmp_path)
    for proj in [_PROJ_A, _PROJ_B]:
        sid = f"sess-{proj}"
        await db.create_session(sid, principal_id=_PRINCIPAL, project_id=proj)
        await db.save_bookmark(sid, "snap", principal_id=_PRINCIPAL, project_id=proj)
    rows_a = await db.list_bookmarks(principal_id=_PRINCIPAL, project_id=_PROJ_A)
    assert {r["session_id"] for r in rows_a} == {"sess-proj-a"}
    rows_b = await db.list_bookmarks(principal_id=_PRINCIPAL, project_id=_PROJ_B)
    assert {r["session_id"] for r in rows_b} == {"sess-proj-b"}
    await db.close()


async def test_h04_delete_bookmark_filters_by_project(tmp_path):
    """A foreign-project DELETE must not delete another project's bookmark."""
    db = await _make_db(tmp_path)
    await db.create_session("del-s", principal_id=_PRINCIPAL, project_id=_PROJ_A)
    await db.save_bookmark("del-s", "snap", principal_id=_PRINCIPAL, project_id=_PROJ_A)
    # proj-b caller tries to delete proj-a's bookmark — no-op (scoped).
    await db.delete_bookmark("del-s", "snap", principal_id=_PRINCIPAL, project_id=_PROJ_B)
    # Bookmark still exists.
    bm = await db.load_bookmark("del-s", "snap", principal_id=_PRINCIPAL, project_id=_PROJ_A)
    assert bm is not None
    # proj-a caller deletes it.
    await db.delete_bookmark("del-s", "snap", principal_id=_PRINCIPAL, project_id=_PROJ_A)
    assert await db.load_bookmark("del-s", "snap", principal_id=_PRINCIPAL, project_id=_PROJ_A) is None
    await db.close()


async def test_h04_list_scheduled_tasks_filters_by_project(tmp_path):
    db = await _make_db(tmp_path)
    for proj, name in [(_PROJ_A, "task-a"), (_PROJ_B, "task-b")]:
        await db.insert_scheduled_task(
            name=name, prompt="hello", status="pending",
            schedule=ScheduleConfig(cron="0 9"), deliver_to="local",
            principal_id=_PRINCIPAL, project_id=proj,
        )
    rows_a = await db.list_scheduled_tasks(principal_id=_PRINCIPAL, project_id=_PROJ_A)
    assert {r["name"] for r in rows_a} == {"task-a"}
    rows_b = await db.list_scheduled_tasks(principal_id=_PRINCIPAL, project_id=_PROJ_B)
    assert {r["name"] for r in rows_b} == {"task-b"}
    await db.close()


async def test_h04_get_scheduled_task_filters_by_project(tmp_path):
    db = await _make_db(tmp_path)
    tid_b = await db.insert_scheduled_task(
        name="task-b", prompt="hello", status="pending",
        schedule=ScheduleConfig(cron="0 9"), deliver_to="local",
        principal_id=_PRINCIPAL, project_id=_PROJ_B,
    )
    # proj-a caller asks for proj-b's task — hidden as None.
    assert await db.get_scheduled_task(tid_b, principal_id=_PRINCIPAL, project_id=_PROJ_A) is None
    # proj-b caller sees it.
    row = await db.get_scheduled_task(tid_b, principal_id=_PRINCIPAL, project_id=_PROJ_B)
    assert row is not None and row["name"] == "task-b"
    await db.close()


async def test_h04_list_coding_tasks_filters_by_project(tmp_path):
    db = await _make_db(tmp_path)
    for proj, cid in [(_PROJ_A, "ct-a"), (_PROJ_B, "ct-b")]:
        await db.insert_coding_task(
            {"id": cid, "goal": f"g-{proj}", "status": "pending",
             "created_at": "2026-01-01T00:00:00", "updated_at": "2026-01-01T00:00:00"},
            principal_id=_PRINCIPAL, project_id=proj,
        )
    rows_a = await db.list_coding_tasks(principal_id=_PRINCIPAL, project_id=_PROJ_A)
    assert {r["id"] for r in rows_a} == {"ct-a"}
    rows_b = await db.list_coding_tasks(principal_id=_PRINCIPAL, project_id=_PROJ_B)
    assert {r["id"] for r in rows_b} == {"ct-b"}
    await db.close()
