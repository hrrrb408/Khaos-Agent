"""F-01 regression: ``transaction()`` recovers from a stale uncommitted
transaction left on the shared connection.

The third-round review (§F-01) found that the shared SQLite connection
could be wedged when a bare write (not wrapped in ``transaction()``)
was cancelled mid-flight: the sqlite3 driver had already issued an
implicit ``BEGIN``, but the cancellation propagated before the bare
``commit()`` ran.  The next ``transaction()`` call then failed with::

    sqlite3.OperationalError: cannot start a transaction within a transaction

This was observed on Ubuntu CI (Python 3.11.15) in
``test_runner_run_closes_borrowed_runtime_on_cancellation`` — the
``SubAgentRunner.run`` cancellation path left a stale transaction,
wedging every subsequent ``_persist_terminal`` → ``update_subagent_task``
→ ``transaction()`` call.

The fix: ``transaction()`` detects the "cannot start a transaction"
error, rolls back the stale transaction, and retries ``BEGIN
IMMEDIATE``.  Rolling back is always safe because the stale
transaction was never committed.
"""

from __future__ import annotations

import pytest

from khaos.db import Database


async def _db(tmp_path) -> Database:
    db = Database(tmp_path / "stale.db")
    await db.connect()
    await db.run_migrations()
    return db


async def test_transaction_recovers_from_stale_uncommitted_write(tmp_path):
    """A stale implicit transaction (from a cancelled bare write) is
    rolled back so the next ``transaction()`` can begin."""
    db = await _db(tmp_path)
    try:
        conn = await db._require_writer_conn()
        # Simulate a bare write that issued an implicit BEGIN but was
        # cancelled before commit() — exactly the cancellation scenario.
        await conn.execute(
            "INSERT INTO sessions (id, principal_id, project_id, "
            "mode, created_at) VALUES (?, ?, ?, ?, datetime('now'))",
            ("stale-1", "alice", "project-a", "office"),
        )
        # Do NOT commit — the implicit transaction is now stale.

        # The next transaction() must recover, not wedge.
        async with db.transaction() as tx:
            await tx.execute(
                "INSERT INTO sessions (id, principal_id, project_id, "
                "mode, created_at) VALUES (?, ?, ?, ?, datetime('now'))",
                ("clean-1", "alice", "project-a", "office"),
            )
        # The stale row was rolled back; the clean row was committed.
        cur = await conn.execute(
            "SELECT id FROM sessions WHERE id IN (?, ?) ORDER BY id",
            ("stale-1", "clean-1"),
        )
        rows = await cur.fetchall()
        ids = [r["id"] for r in rows]
        assert "clean-1" in ids, "clean transaction should have committed"
        assert "stale-1" not in ids, (
            "stale uncommitted row should have been rolled back by the "
            "transaction() recovery path"
        )
    finally:
        await db.close()


async def test_nested_transaction_still_reuses_outer(tmp_path):
    """Nested ``transaction()`` calls still reuse the outer transaction
    — the stale-recovery path is only on the outermost call."""
    db = await _db(tmp_path)
    try:
        async with db.transaction() as outer:
            await outer.execute(
                "INSERT INTO sessions (id, principal_id, project_id, "
                "mode, created_at) VALUES (?, ?, ?, ?, datetime('now'))",
                ("outer-1", "alice", "project-a", "office"),
            )
            # Nested call — must NOT issue a second BEGIN.
            async with db.transaction() as inner:
                assert inner is outer
                await inner.execute(
                    "INSERT INTO sessions (id, principal_id, project_id, "
                    "mode, created_at) VALUES (?, ?, ?, ?, datetime('now'))",
                    ("inner-1", "alice", "project-a", "office"),
                )
        # Both rows committed by the outer transaction.
        conn = await db._require_conn()
        cur = await conn.execute(
            "SELECT id FROM sessions WHERE id IN (?, ?) ORDER BY id",
            ("outer-1", "inner-1"),
        )
        rows = await cur.fetchall()
        ids = [r["id"] for r in rows]
        assert ids == ["inner-1", "outer-1"]
    finally:
        await db.close()


async def test_concurrent_transactions_serialize_via_lock(tmp_path):
    """Two concurrent ``transaction()`` calls serialize on the write
    lock — the second waits for the first to commit, then begins."""
    import asyncio

    db = await _db(tmp_path)
    try:
        order: list[str] = []

        async def writer(name: str) -> None:
            async with db.transaction() as tx:
                order.append(f"{name}-begin")
                await tx.execute(
                    "INSERT INTO sessions (id, principal_id, project_id, "
                    "mode, created_at) VALUES (?, ?, ?, ?, datetime('now'))",
                    (f"s-{name}", "alice", "project-a", "office"),
                )
                await asyncio.sleep(0.05)
                order.append(f"{name}-commit")

        await asyncio.gather(writer("a"), writer("b"))
        # Each writer's begin and commit are adjacent (serialized), not
        # interleaved — proving the lock prevents cross-commit contamination.
        a_idx = order.index("a-begin")
        assert order[a_idx + 1] == "a-commit"
        b_idx = order.index("b-begin")
        assert order[b_idx + 1] == "b-commit"
    finally:
        await db.close()
