"""Round-5 Batch 5.3 (H-08, H-09) — OwnerContext Closure tests.

H-08: SessionSearch stored project_id but never passed it to the DB —
      history search/browse/scroll/read could cross project boundaries
      on shared DBs.  Verified at the tool level (history_search /
      history_browse / history_read), not just the DB Repository level.

H-09: principal_modes had no project_id dimension — Project A's coding
      mode (gating System Prompt / Tool Availability / Routing) could
      be loaded by Project B for the same principal on a shared DB.
      Verified that ModeManager project-scoping isolates modes.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from khaos.agent.core import Message
from khaos.db import Database
from khaos.modes import Mode, ModeManager
from khaos.session import SessionSearch
from khaos.tools.history_tools import (
    history_browse,
    history_read,
    history_search,
)

PRINCIPAL = "alice"
PROJECT_A = "a" * 32
PROJECT_B = "b" * 32


# ───────────────────────────── helpers ────────────────────────────────


async def _make_db(path: Path) -> Database:
    db = Database(path)
    await db.connect()
    await db.run_migrations()
    return db


async def _seed(
    db: Database,
    *,
    session_id: str,
    principal_id: str,
    project_id: str,
    messages: list[tuple[str, str]],
) -> None:
    """Create a session + insert messages with FTS5 sync."""
    await db.create_session(
        session_id, mode="office",
        principal_id=principal_id, project_id=project_id,
    )
    for role, content in messages:
        msg_id = await db.insert_message(
            session_id,
            Message(role=role, content=content),
            principal_id=principal_id,
            project_id=project_id,
        )
        # Index into messages_fts so search_sessions can find it.
        await db.insert_message_fts(
            session_id, role, content, rowid=msg_id,
        )


# ───────── H-08-A: history_search filters by project_id ───────────────


async def test_h08_a_history_search_filters_by_project(tmp_path):
    """H-08-A: ``history_search`` returns only the caller's project's
    messages, even on a shared DB."""
    db = await _make_db(tmp_path / "h08.db")
    try:
        await _seed(
            db, session_id="sa", principal_id=PRINCIPAL, project_id=PROJECT_A,
            messages=[("user", "deploy alpha service")],
        )
        await _seed(
            db, session_id="sb", principal_id=PRINCIPAL, project_id=PROJECT_B,
            messages=[("user", "deploy beta service")],
        )

        # Project A searches — must NOT see Project B's "beta" message.
        result_a = await history_search(
            "deploy", principal_id=PRINCIPAL, project_id=PROJECT_A, db=db,
        )
        sessions_a = {r["session_id"] for r in result_a["results"]}
        assert sessions_a == {"sa"}

        # Project B searches — must NOT see Project A's "alpha" message.
        result_b = await history_search(
            "deploy", principal_id=PRINCIPAL, project_id=PROJECT_B, db=db,
        )
        sessions_b = {r["session_id"] for r in result_b["results"]}
        assert sessions_b == {"sb"}
    finally:
        await db.close()


# ───────── H-08-B: history_browse filters by project_id ───────────────


async def test_h08_b_history_browse_filters_by_project(tmp_path):
    """H-08-B: ``history_browse`` lists only the caller's project's
    sessions."""
    db = await _make_db(tmp_path / "h08.db")
    try:
        await _seed(
            db, session_id="sa", principal_id=PRINCIPAL, project_id=PROJECT_A,
            messages=[("user", "alpha one"), ("assistant", "ok")],
        )
        await _seed(
            db, session_id="sb", principal_id=PRINCIPAL, project_id=PROJECT_B,
            messages=[("user", "beta two")],
        )

        result_a = await history_browse(
            principal_id=PRINCIPAL, project_id=PROJECT_A, db=db,
        )
        ids_a = {s["session_id"] for s in result_a["sessions"]}
        assert ids_a == {"sa"}

        result_b = await history_browse(
            principal_id=PRINCIPAL, project_id=PROJECT_B, db=db,
        )
        ids_b = {s["session_id"] for s in result_b["sessions"]}
        assert ids_b == {"sb"}
    finally:
        await db.close()


# ───────── H-08-C: history_read filters by project_id ─────────────────


async def test_h08_c_history_read_filters_by_project(tmp_path):
    """H-08-C: ``history_read`` returns [] when asked for another
    project's session."""
    db = await _make_db(tmp_path / "h08.db")
    try:
        await _seed(
            db, session_id="sa", principal_id=PRINCIPAL, project_id=PROJECT_A,
            messages=[("user", "secret alpha")],
        )

        # Project B reads Project A's session → empty (filtered out).
        result = await history_read(
            "sa", principal_id=PRINCIPAL, project_id=PROJECT_B, db=db,
        )
        assert result["messages"] == []

        # Project A reads its own session → returns the message.
        result = await history_read(
            "sa", principal_id=PRINCIPAL, project_id=PROJECT_A, db=db,
        )
        assert len(result["messages"]) == 1
        assert result["messages"][0]["content"] == "secret alpha"
    finally:
        await db.close()


# ───────── H-08-D: SessionSearch.scroll filters by project_id ──────────


async def test_h08_d_session_search_scroll_filters_by_project(tmp_path):
    """H-08-D: ``SessionSearch.scroll`` returns an empty window when the
    session belongs to a different project."""
    db = await _make_db(tmp_path / "h08.db")
    try:
        await _seed(
            db, session_id="sa", principal_id=PRINCIPAL, project_id=PROJECT_A,
            messages=[("user", f"msg {i}") for i in range(5)],
        )
        # Need a real message id for the anchor.
        msgs = await db.get_session_messages(
            "sa", 10, 0,
            principal_id=PRINCIPAL, project_id=PROJECT_A,
        )
        anchor = msgs[2]["id"]

        # Project B scrolls → empty.
        search_b = SessionSearch(db, principal_id=PRINCIPAL, project_id=PROJECT_B)
        window_b = await search_b.scroll("sa", anchor)
        assert window_b.messages == []

        # Project A scrolls → returns messages.
        search_a = SessionSearch(db, principal_id=PRINCIPAL, project_id=PROJECT_A)
        window_a = await search_a.scroll("sa", anchor)
        assert len(window_a.messages) > 0
    finally:
        await db.close()


# ───────── H-08-E: SessionSearch directly passes project_id ───────────


async def test_h08_e_session_search_passes_project_id(tmp_path):
    """H-08-E: SessionSearch.search passes project_id to the DB layer.
    A project-A search returns only project-A sessions even when
    project-B has a matching message."""
    db = await _make_db(tmp_path / "h08.db")
    try:
        await _seed(
            db, session_id="sa", principal_id=PRINCIPAL, project_id=PROJECT_A,
            messages=[("user", "shared keyword")],
        )
        await _seed(
            db, session_id="sb", principal_id=PRINCIPAL, project_id=PROJECT_B,
            messages=[("user", "shared keyword")],
        )
        search_a = SessionSearch(db, principal_id=PRINCIPAL, project_id=PROJECT_A)
        results_a = await search_a.search("shared")
        assert {r.session_id for r in results_a} == {"sa"}

        search_b = SessionSearch(db, principal_id=PRINCIPAL, project_id=PROJECT_B)
        results_b = await search_b.search("shared")
        assert {r.session_id for r in results_b} == {"sb"}
    finally:
        await db.close()


# ───────── H-09-A: ModeManager isolates modes by project_id ────────────


async def test_h09_a_mode_isolated_by_project(tmp_path):
    """H-09-A: switching to coding in Project A does NOT affect
    Project B for the same principal."""
    db = await _make_db(tmp_path / "h09.db")
    try:
        mgr_a = ModeManager(
            db, principal_id=PRINCIPAL, project_id=PROJECT_A,
        )
        await mgr_a.load()
        assert mgr_a.current_mode is Mode.OFFICE

        await mgr_a.switch(Mode.CODING)

        # Project A sees coding.
        mgr_a2 = ModeManager(
            db, principal_id=PRINCIPAL, project_id=PROJECT_A,
        )
        await mgr_a2.load()
        assert mgr_a2.current_mode is Mode.CODING

        # Project B still sees office (NOT leaked from Project A).
        mgr_b = ModeManager(
            db, principal_id=PRINCIPAL, project_id=PROJECT_B,
        )
        await mgr_b.load()
        assert mgr_b.current_mode is Mode.OFFICE
    finally:
        await db.close()


# ───────── H-09-B: per-session override is project-scoped ─────────────


async def test_h09_b_session_override_is_project_scoped(tmp_path):
    """H-09-B: a session-specific override in Project A does not leak
    into Project B's session.

    Note: session_id is globally unique (a session belongs to exactly
    one (principal, project) owner), so Project B uses a different
    session_id.  The point is that Project A's session-scoped coding
    override does NOT change Project B's *principal default* mode."""
    db = await _make_db(tmp_path / "h09.db")
    try:
        # Create one session per project.
        await db.create_session(
            "sa", mode="office",
            principal_id=PRINCIPAL, project_id=PROJECT_A,
        )
        await db.create_session(
            "sb", mode="office",
            principal_id=PRINCIPAL, project_id=PROJECT_B,
        )

        # Project A session override → coding.
        mgr_a = ModeManager(
            db, principal_id=PRINCIPAL, session_id="sa", project_id=PROJECT_A,
        )
        await mgr_a.switch(Mode.CODING)

        # Project A session loads coding.
        assert await mgr_a.load() is Mode.CODING

        # Project B session loads office (no leak from Project A's
        # session override, AND no leak from a principal default since
        # the override was session-scoped, not principal-scoped).
        mgr_b = ModeManager(
            db, principal_id=PRINCIPAL, session_id="sb", project_id=PROJECT_B,
        )
        assert await mgr_b.load() is Mode.OFFICE

        # Also verify Project B's principal default is still office
        # (the session-scoped switch in Project A did not touch it).
        mgr_b_default = ModeManager(
            db, principal_id=PRINCIPAL, project_id=PROJECT_B,
        )
        assert await mgr_b_default.load() is Mode.OFFICE
    finally:
        await db.close()


# ───────── H-09-C: project_id='' preserves legacy behaviour ───────────


async def test_h09_c_empty_project_id_preserves_legacy(tmp_path):
    """H-09-C: ``project_id=''`` (legacy/test mode) still works —
    modes written without project_id are readable without project_id."""
    db = await _make_db(tmp_path / "h09.db")
    try:
        mgr = ModeManager(db, principal_id=PRINCIPAL)
        await mgr.switch(Mode.CODING)

        mgr2 = ModeManager(db, principal_id=PRINCIPAL)
        assert await mgr2.load() is Mode.CODING
    finally:
        await db.close()


# ───────── H-09-D: PK enforces project isolation at DB level ───────────


async def test_h09_d_pk_enforces_project_isolation(tmp_path):
    """H-09-D: the ``principal_modes`` PK is
    ``(project_id, principal_id, session_id)`` — writing the same
    principal+session for two different projects creates two distinct
    rows (no conflict), confirming the project dimension is part of
    the key."""
    db = await _make_db(tmp_path / "h09.db")
    try:
        await db.set_principal_mode(
            PRINCIPAL, "coding", session_id="s1", project_id=PROJECT_A,
        )
        await db.set_principal_mode(
            PRINCIPAL, "office", session_id="s1", project_id=PROJECT_B,
        )

        conn = db._conn
        cursor = await conn.execute(
            "SELECT project_id, mode FROM principal_modes "
            "WHERE principal_id = ? AND session_id = ? "
            "ORDER BY project_id",
            (PRINCIPAL, "s1"),
        )
        rows = [dict(r) for r in await cursor.fetchall()]
        assert len(rows) == 2
        assert rows[0]["project_id"] == PROJECT_A
        assert rows[0]["mode"] == "coding"
        assert rows[1]["project_id"] == PROJECT_B
        assert rows[1]["mode"] == "office"
    finally:
        await db.close()


# ───────── H-09-E: migration rebuild is idempotent ────────────────────


async def test_h09_e_migration_rebuild_idempotent(tmp_path):
    """H-09-E: running migrations twice (simulating a v3→v4 upgrade
    followed by a restart) does not corrupt the principal_modes table
    or lose data."""
    db = await _make_db(tmp_path / "h09.db")
    try:
        await db.set_principal_mode(
            PRINCIPAL, "coding", project_id=PROJECT_A,
        )
        # Re-run the migration helper directly (idempotent).
        await db._ensure_principal_modes_project_id_pk()

        # Data survives.
        mode = await db.get_principal_mode(
            PRINCIPAL, project_id=PROJECT_A,
        )
        assert mode == "coding"
    finally:
        await db.close()
