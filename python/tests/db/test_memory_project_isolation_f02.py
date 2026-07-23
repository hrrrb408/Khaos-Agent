"""F-02 (third-round review) — Memory Project Identity isolation.

Acceptance tests verifying that two projects sharing a single state DB
(via explicit ``--db``) cannot read, overwrite, delete, list, or search
each other's memories of the same key.

Pre-F-02 the ``memories`` UNIQUE key was
``(namespace, principal_id, session_id, scope, key)`` — ``project_id``
was stamped on writes but never used as a read filter or conflict key.
On a shared DB, project B's upsert of the same key silently updated
project A's row (leaving ``row.project_id == A`` but ``row.value == B``),
and project B's get/list/search could see project A's memories.

F-02 makes ``project_id`` part of the UNIQUE key AND forwards it to
every DB read/write call.  These tests exercise the isolation contract
end-to-end via :class:`MemoryStore` (the public API the rest of the
codebase uses).

Coverage matrix (all on ONE shared Database):

  1.  Upsert isolation       — B's upsert creates a new row, A's intact
  2.  Get isolation          — A cannot read B's value, vice versa
  3.  Same-project update    — re-upsert from same project updates row
  4.  Delete isolation       — A's delete leaves B's row untouched
  5.  Delete-by-ID isolation — A cannot delete B's row by id
  6.  List-by-scope isol.    — list_by_scope returns only own project
  7.  List-all isolation     — list_all returns only own project
  8.  Search isolation       — FTS search returns only own project
  9.  Decay isolation        — decay only removes own project's rows
 10.  Shared namespace isol. — even namespace='shared' is project-scoped
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from khaos.db import Database
from khaos.memory import Memory, MemoryConfidence, MemoryScope, MemoryStore


PROJECT_ID_A = "a" * 32
PROJECT_ID_B = "b" * 32
PRINCIPAL = "alice"


# ───────────────────────────── helpers ────────────────────────────────


async def _make_db(path: Path) -> Database:
    db = Database(path)
    await db.connect()
    await db.run_migrations()
    return db


def _mem(key: str, value: str, *, ttl: int = 604800) -> Memory:
    return Memory(
        id=None,
        scope=MemoryScope.GLOBAL,
        key=key,
        value=value,
        ttl=ttl,
        confidence=MemoryConfidence.MEDIUM,
    )


def _store(db: Database, project_id: str) -> MemoryStore:
    return MemoryStore(db, principal_id=PRINCIPAL, project_id=project_id)


# ───────────────────────────── tests ──────────────────────────────────


async def test_f02_1_upsert_isolation(tmp_path):
    """F-02 #1: B's upsert of the same key creates a DISTINCT row; A's
    value and ``project_id`` stamp are intact."""
    db = await _make_db(tmp_path / "shared.db")
    try:
        store_a = _store(db, PROJECT_ID_A)
        store_b = _store(db, PROJECT_ID_B)

        await store_a.set(_mem("k", "v-a"), namespace="private")
        await store_b.set(_mem("k", "v-b"), namespace="private")

        # Each project reads its own value.
        got_a = await store_a.get(MemoryScope.GLOBAL, "k", namespace="private")
        got_b = await store_b.get(MemoryScope.GLOBAL, "k", namespace="private")
        assert got_a is not None and got_a.value == "v-a"
        assert got_b is not None and got_b.value == "v-b"

        # Two distinct rows in the DB (project_id is part of UNIQUE).
        conn = await db._require_conn()
        cursor = await conn.execute(
            "SELECT project_id, value FROM memories "
            "WHERE key='k' ORDER BY project_id"
        )
        rows = await cursor.fetchall()
        await cursor.close()
        assert len(rows) == 2
        assert rows[0]["project_id"] == PROJECT_ID_A
        assert rows[0]["value"] == "v-a"
        assert rows[1]["project_id"] == PROJECT_ID_B
        assert rows[1]["value"] == "v-b"
    finally:
        await db.close()


async def test_f02_2_get_isolation(tmp_path):
    """F-02 #2: A cannot read B's value, and vice versa, even with the
    same (namespace, principal, session, scope, key)."""
    db = await _make_db(tmp_path / "shared.db")
    try:
        store_a = _store(db, PROJECT_ID_A)
        store_b = _store(db, PROJECT_ID_B)

        await store_a.set(_mem("secret", "alpha"), namespace="private")
        await store_b.set(_mem("secret", "beta"), namespace="private")

        # A reads its own value, not B's.
        got_a = await store_a.get(MemoryScope.GLOBAL, "secret", namespace="private")
        assert got_a is not None and got_a.value == "alpha"

        # B reads its own value, not A's.
        got_b = await store_b.get(MemoryScope.GLOBAL, "secret", namespace="private")
        assert got_b is not None and got_b.value == "beta"

        # A third project with no data sees nothing.
        store_c = _store(db, "c" * 32)
        got_c = await store_c.get(MemoryScope.GLOBAL, "secret", namespace="private")
        assert got_c is None
    finally:
        await db.close()


async def test_f02_3_same_project_update_does_not_duplicate(tmp_path):
    """F-02 #3: re-upserting from the SAME project updates the existing
    row (ON CONFLICT) rather than creating a duplicate."""
    db = await _make_db(tmp_path / "shared.db")
    try:
        store = _store(db, PROJECT_ID_A)

        await store.set(_mem("k", "v1"), namespace="private")
        await store.set(_mem("k", "v2"), namespace="private")

        got = await store.get(MemoryScope.GLOBAL, "k", namespace="private")
        assert got is not None and got.value == "v2"

        # Exactly one row for (project_a, k).
        conn = await db._require_conn()
        cursor = await conn.execute(
            "SELECT COUNT(*) AS n FROM memories "
            "WHERE key='k' AND project_id=?",
            (PROJECT_ID_A,),
        )
        row = await cursor.fetchone()
        await cursor.close()
        assert row["n"] == 1
    finally:
        await db.close()


async def test_f02_4_delete_isolation(tmp_path):
    """F-02 #4: A's delete of key 'k' does NOT affect B's row for 'k'."""
    db = await _make_db(tmp_path / "shared.db")
    try:
        store_a = _store(db, PROJECT_ID_A)
        store_b = _store(db, PROJECT_ID_B)

        await store_a.set(_mem("k", "v-a"), namespace="private")
        await store_b.set(_mem("k", "v-b"), namespace="private")

        # A deletes its own copy.
        await store_a.delete(MemoryScope.GLOBAL, "k", namespace="private")

        # A can no longer read it.
        got_a = await store_a.get(MemoryScope.GLOBAL, "k", namespace="private")
        assert got_a is None

        # B's copy is untouched.
        got_b = await store_b.get(MemoryScope.GLOBAL, "k", namespace="private")
        assert got_b is not None and got_b.value == "v-b"
    finally:
        await db.close()


async def test_f02_5_delete_by_id_isolation(tmp_path):
    """F-02 #5: ``delete_memory_by_id`` scoped by project_id — A cannot
    delete B's row by id even if it somehow learns the id."""
    db = await _make_db(tmp_path / "shared.db")
    try:
        store_a = _store(db, PROJECT_ID_A)
        store_b = _store(db, PROJECT_ID_B)

        await store_a.set(_mem("k", "v-a"), namespace="private")
        await store_b.set(_mem("k", "v-b"), namespace="private")

        # Learn B's row id (simulating a leak).
        conn = await db._require_conn()
        cursor = await conn.execute(
            "SELECT id FROM memories WHERE project_id=? AND key='k'",
            (PROJECT_ID_B,),
        )
        b_row = await cursor.fetchone()
        await cursor.close()
        assert b_row is not None
        b_id = int(b_row["id"])

        # A attempts to delete B's row by id — must be a no-op (scoped
        # by A's project_id).
        await db.delete_memory_by_id(
            b_id, principal_id=PRINCIPAL, project_id=PROJECT_ID_A,
        )

        # B's row is still there.
        got_b = await store_b.get(MemoryScope.GLOBAL, "k", namespace="private")
        assert got_b is not None and got_b.value == "v-b"
        assert got_b.id == b_id

        # B CAN delete its own row by id.
        await db.delete_memory_by_id(
            b_id, principal_id=PRINCIPAL, project_id=PROJECT_ID_B,
        )
        got_b2 = await store_b.get(MemoryScope.GLOBAL, "k", namespace="private")
        assert got_b2 is None
    finally:
        await db.close()


async def test_f02_6_list_by_scope_isolation(tmp_path):
    """F-02 #6: ``list_by_scope`` returns only this project's memories."""
    db = await _make_db(tmp_path / "shared.db")
    try:
        store_a = _store(db, PROJECT_ID_A)
        store_b = _store(db, PROJECT_ID_B)

        await store_a.set(_mem("a1", "v-a1"), namespace="private")
        await store_a.set(_mem("a2", "v-a2"), namespace="private")
        await store_b.set(_mem("b1", "v-b1"), namespace="private")
        await store_b.set(_mem("b2", "v-b2"), namespace="private")

        a_keys = {m.key for m in await store_a.list_by_scope(MemoryScope.GLOBAL)}
        b_keys = {m.key for m in await store_b.list_by_scope(MemoryScope.GLOBAL)}

        assert a_keys == {"a1", "a2"}
        assert b_keys == {"b1", "b2"}
        assert not (a_keys & b_keys)
    finally:
        await db.close()


async def test_f02_7_list_all_isolation(tmp_path):
    """F-02 #7: ``list_all`` returns only this project's memories across
    all scopes."""
    db = await _make_db(tmp_path / "shared.db")
    try:
        store_a = _store(db, PROJECT_ID_A)
        store_b = _store(db, PROJECT_ID_B)

        await store_a.set(_mem("a-global", "v"), namespace="private")
        await store_b.set(_mem("b-global", "v"), namespace="private")
        # Different scope to verify list_all spans scopes but stays in-project.
        await store_a.set(
            Memory(
                id=None, scope=MemoryScope.OFFICE, key="a-office", value="v",
                confidence=MemoryConfidence.MEDIUM,
            ),
            namespace="private",
        )

        a_keys = {m.key for m in await store_a.list_all()}
        b_keys = {m.key for m in await store_b.list_all()}

        assert a_keys == {"a-global", "a-office"}
        assert b_keys == {"b-global"}
    finally:
        await db.close()


async def test_f02_8_search_isolation(tmp_path):
    """F-02 #8: FTS5 ``search`` returns only this project's memories."""
    db = await _make_db(tmp_path / "shared.db")
    try:
        store_a = _store(db, PROJECT_ID_A)
        store_b = _store(db, PROJECT_ID_B)

        await store_a.set(_mem("k", "alpha bravo charlie"), namespace="private")
        await store_b.set(_mem("k", "alpha bravo delta"), namespace="private")

        # Both projects index the word "alpha"; search must stay scoped.
        a_hits = await store_a.search("alpha", top_k=10)
        b_hits = await store_b.search("alpha", top_k=10)

        assert len(a_hits) == 1
        assert a_hits[0].value == "alpha bravo charlie"
        assert len(b_hits) == 1
        assert b_hits[0].value == "alpha bravo delta"

        # A search unique to B's content returns nothing for A.
        a_delta = await store_a.search("delta", top_k=10)
        assert a_delta == []
        b_delta = await store_b.search("delta", top_k=10)
        assert len(b_delta) == 1
    finally:
        await db.close()


async def test_f02_9_decay_isolation(tmp_path):
    """F-02 #9: ``decay`` only removes THIS project's expired rows; B's
    expired row with the same key is untouched."""
    db = await _make_db(tmp_path / "shared.db")
    try:
        store_a = _store(db, PROJECT_ID_A)
        store_b = _store(db, PROJECT_ID_B)

        # ttl=1 second; both will be "expired" relative to our fake now.
        await store_a.set(_mem("k", "v-a", ttl=1), namespace="private")
        await store_b.set(_mem("k", "v-b", ttl=1), namespace="private")

        # Run decay for project A with a now far in the future.
        future = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(hours=1)
        removed_a = await store_a.decay(now=future)

        assert removed_a == 1
        # A's row is gone.
        got_a = await store_a.get(MemoryScope.GLOBAL, "k", namespace="private")
        assert got_a is None

        # B's row is STILL there — decay was scoped to project A.
        got_b = await store_b.get(MemoryScope.GLOBAL, "k", namespace="private")
        assert got_b is not None and got_b.value == "v-b"

        # Now run decay for B; B's row is removed too.
        removed_b = await store_b.decay(now=future)
        assert removed_b == 1
        got_b2 = await store_b.get(MemoryScope.GLOBAL, "k", namespace="private")
        assert got_b2 is None
    finally:
        await db.close()


async def test_f02_10_shared_namespace_isolation(tmp_path):
    """F-02 #10: even ``namespace='shared'`` (project-wide cross-principal
    channel) is isolated by ``project_id``.

    Pre-F-02 a shared DB with two projects both using ``namespace='shared'``
    and ``principal_id=''`` would collide on the same row.  F-02 gives
    each project its own shared-namespace row.
    """
    db = await _make_db(tmp_path / "shared.db")
    try:
        # Both stores use principal_id='' via the shared-namespace path
        # (see MemoryStore._effective_principal), but bind to different
        # project_ids.
        store_a = MemoryStore(db, principal_id="alice", project_id=PROJECT_ID_A)
        store_b = MemoryStore(db, principal_id="bob", project_id=PROJECT_ID_B)

        await store_a.set(_mem("team-note", "from-A"), namespace="shared")
        await store_b.set(_mem("team-note", "from-B"), namespace="shared")

        got_a = await store_a.get(
            MemoryScope.GLOBAL, "team-note", namespace="shared",
        )
        got_b = await store_b.get(
            MemoryScope.GLOBAL, "team-note", namespace="shared",
        )
        assert got_a is not None and got_a.value == "from-A"
        assert got_b is not None and got_b.value == "from-B"

        # Two distinct rows even though effective principal_id is '' for both.
        conn = await db._require_conn()
        cursor = await conn.execute(
            "SELECT project_id, value FROM memories "
            "WHERE key='team-note' AND namespace='shared' "
            "ORDER BY project_id"
        )
        rows = await cursor.fetchall()
        await cursor.close()
        assert len(rows) == 2
    finally:
        await db.close()
