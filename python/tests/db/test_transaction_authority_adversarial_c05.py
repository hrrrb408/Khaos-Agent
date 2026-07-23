"""C-05: Adversarial transaction authority tests (Round-4 Batch 1).

These tests construct REAL transaction overlap (not the sequential
``set()``/``wait()`` pattern that F-01 used, where the first coroutine
had already committed before the second started).

The review (§四 C-05, §十九 Batch 1) requires 7 scenarios:

  1. parent transaction → ``create_task`` child write (ContextVar leak)
  2. parent transaction → detached child write (stale owner token)
  3. same task DB-A → DB-B (cross-database pollution)
  4. permission transaction midpoint → Chat GC (real lock serialization)
  5. permission transaction midpoint → Audit read (reader isolation)
  6. cancellation after first SQL (rollback + clean connection)
  7. close during active transaction (lifecycle lock)

Each test uses a midpoint barrier inside ``async with db.transaction()``
so the outer transaction is genuinely in-flight when the adversarial
action fires.
"""

from __future__ import annotations

import asyncio
import time

import pytest

from khaos.db.database import Database, TransactionContextLeakError


@pytest.fixture
async def db(tmp_path):
    db = Database(str(tmp_path / "c05.db"))
    await db.connect()
    await db.run_migrations()
    yield db
    await db.close()


async def _seed_session(db: Database, sid: str, principal: str = "alice", project: str = "p1"):
    await db.create_session(sid, principal_id=principal, project_id=project)


# ---------------------------------------------------------------------------
# Scenario 1: parent transaction → create_task child write
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_create_task_child_inheriting_context_cannot_write(db: Database):
    """``asyncio.create_task()`` copies the parent ContextVar.

    The child sees a non-None ``TransactionOwner`` whose ``.task`` is the
    PARENT task, not itself.  Calling ``transaction()`` must raise
    ``TransactionContextLeakError`` rather than silently skipping
    BEGIN/COMMIT (the old behaviour that let the child believe it was
    nested inside the parent's transaction).
    """
    await _seed_session(db, "s1")

    midpoint = asyncio.Event()
    release_parent = asyncio.Event()
    child_error: BaseException | None = None

    async def child_write():
        # Child inherits the parent's non-None owner via context copy.
        try:
            async with db.transaction() as conn:
                await conn.execute(
                    "INSERT INTO audit_log (action, target, result) "
                    "VALUES ('leak', 'child', 'success')"
                )
        except TransactionContextLeakError as exc:
            nonlocal child_error
            child_error = exc

    async def parent_transaction():
        async with db.transaction() as conn:
            await conn.execute(
                "INSERT INTO audit_log (action, target, result) "
                "VALUES ('parent', 'first', 'ok')"
            )
            midpoint.set()
            # Create the child WHILE the parent transaction is open so
            # the child's context copy captures the non-None owner.
            child = asyncio.create_task(child_write())
            await asyncio.wait_for(release_parent.wait(), timeout=5.0)
            await child

    parent_task = asyncio.create_task(parent_transaction())
    await asyncio.wait_for(midpoint.wait(), timeout=5.0)
    release_parent.set()
    await parent_task

    assert child_error is not None, (
        "child create_task must raise TransactionContextLeakError, not "
        "silently reuse the parent's transaction"
    )
    assert "leaked across boundary" in str(child_error)

    # The child's INSERT must NOT have been committed.
    logs = await db.list_audit_logs()
    actions = [log["action"] for log in logs]
    assert "parent" in actions
    assert "leak" not in actions


# ---------------------------------------------------------------------------
# Scenario 2: parent transaction → detached child write (stale token)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_detached_child_with_stale_token_cannot_write(db: Database):
    """A child created during the parent's transaction retains the stale
    owner token even AFTER the parent has committed.

    The generation/task check must still fail, preventing a detached
    background task from silently smuggling writes into a transaction
    that no longer exists.
    """
    await _seed_session(db, "s2")

    child_started = asyncio.Event()
    release_parent = asyncio.Event()
    child_error: BaseException | None = None

    async def detached_child():
        try:
            async with db.transaction() as conn:
                await conn.execute(
                    "INSERT INTO audit_log (action, target, result) "
                    "VALUES ('detached', 'child', 'success')"
                )
        except TransactionContextLeakError as exc:
            nonlocal child_error
            child_error = exc

    async def parent_transaction():
        async with db.transaction() as conn:
            await conn.execute(
                "INSERT INTO audit_log (action, target, result) "
                "VALUES ('parent', 'first', 'ok')"
            )
            # Create the child while transaction is open.
            child = asyncio.create_task(detached_child())
            child_started.set()
            await asyncio.wait_for(release_parent.wait(), timeout=5.0)
            # Parent commits here; child has not run yet.
        return child

    parent_task = asyncio.create_task(parent_transaction())
    await asyncio.wait_for(child_started.wait(), timeout=5.0)
    release_parent.set()
    child = await parent_task

    # Now let the detached child run AFTER the parent has committed.
    await child

    assert child_error is not None, (
        "detached child with stale owner token must raise, not silently "
        "open a phantom transaction"
    )

    logs = await db.list_audit_logs()
    actions = [log["action"] for log in logs]
    assert "detached" not in actions


# ---------------------------------------------------------------------------
# Scenario 3: same task DB-A → DB-B (cross-database pollution)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_cross_database_context_pollution_rejected(tmp_path):
    """Opening ``db_a.transaction()`` and then ``db_b.transaction()`` in
    the SAME task must raise — the module-level ContextVar would
    otherwise make DB-B believe it is nested inside DB-A's transaction
    and skip BEGIN/COMMIT, corrupting DB-B's transaction semantics.
    """
    db_a = Database(str(tmp_path / "a.db"))
    db_b = Database(str(tmp_path / "b.db"))
    await db_a.connect()
    await db_a.run_migrations()
    await db_b.connect()
    await db_b.run_migrations()
    try:
        await _seed_session(db_a, "sa")
        await _seed_session(db_b, "sb")

        with pytest.raises(TransactionContextLeakError, match="leaked across boundary"):
            async with db_a.transaction() as conn_a:
                await conn_a.execute(
                    "INSERT INTO audit_log (action, target, result) "
                    "VALUES ('a', 'first', 'ok')"
                )
                # DB-B sees owner is not None but owner.database_id != id(db_b)
                async with db_b.transaction() as conn_b:
                    await conn_b.execute(
                        "INSERT INTO audit_log (action, target, result) "
                        "VALUES ('b', 'should_fail', 'no')"
                    )

        # DB-A's transaction was rolled back by the exception.
        logs_a = await db_a.list_audit_logs()
        assert all(log["action"] != "a" for log in logs_a)
        logs_b = await db_b.list_audit_logs()
        assert all(log["action"] != "b" for log in logs_b)
    finally:
        await db_a.close()
        await db_b.close()


# ---------------------------------------------------------------------------
# Scenario 4: permission transaction midpoint → Chat GC (real serialization)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_chat_gc_serialized_behind_permission_transaction(db: Database):
    """Construct a REAL transaction overlap using a midpoint barrier.

    The parent opens ``transaction()``, executes the first SQL, then
    awaits a release signal (the transaction is genuinely in-flight and
    holds ``_write_transaction_lock``).  A concurrent Chat GC call
    (``delete_chat_stream_events_for_session``) must block on the same
    lock — it must NOT smuggle a ``commit()`` that prematurely commits
    the parent's half-written permission row.
    """
    principal = "alice"
    project = "p1"
    session = "s4"
    await _seed_session(db, session, principal, project)

    # Seed a chat event so GC has something to delete.
    await db.append_chat_stream_event(
        stream_id=session, session_id=session,
        principal_id=principal,
        project_id=project,
        event_type="message",
        data={"text": "will be deleted"},
        now=time.time(),
    )

    midpoint = asyncio.Event()
    release_parent = asyncio.Event()
    gc_completed = asyncio.Event()

    async def parent_permission_transaction():
        async with db.transaction() as conn:
            # First SQL: insert a permission rule (uncommitted).
            await conn.execute(
                "INSERT INTO permissions "
                "(pattern, permission_level, approval, mode, principal_id, "
                " project_id, policy_digest, generation) "
                "VALUES ('read_x', 'allow', 'auto', 'office', ?, ?, 'dig', 0)",
                (principal, project),
            )
            midpoint.set()
            await asyncio.wait_for(release_parent.wait(), timeout=10.0)
            # Second SQL: bump the authorization epoch.
            await conn.execute(
                "INSERT INTO authorization_contexts "
                "(principal_id, project_id, policy_digest, epoch) "
                "VALUES (?, ?, 'dig', 1) "
                "ON CONFLICT(principal_id, project_id) DO UPDATE SET "
                "  epoch = epoch + 1, policy_digest='dig', "
                "  updated_at = datetime('now')",
                (principal, project),
            )

    async def chat_gc():
        # Wait until the parent transaction is in-flight.
        await asyncio.wait_for(midpoint.wait(), timeout=5.0)
        # This must block on _write_transaction_lock until the parent commits.
        await db.delete_chat_stream_events_for_session(
            session_id=session,
            principal_id=principal,
            project_id=project,
        )
        gc_completed.set()

    parent_task = asyncio.create_task(parent_permission_transaction())
    gc_task = asyncio.create_task(chat_gc())

    # Give GC a chance to run — it must NOT have completed yet because
    # the parent still holds the lock.
    await asyncio.sleep(0.1)
    assert not gc_completed.is_set(), (
        "Chat GC must be serialized behind the in-flight permission "
        "transaction, not smuggle a concurrent commit"
    )

    # Release the parent; both should complete.
    release_parent.set()
    await asyncio.wait_for(parent_task, timeout=10.0)
    await asyncio.wait_for(gc_task, timeout=10.0)

    # Verify: permission rule was committed atomically.
    rules = await db.list_permission_rules(
        principal_id=principal, project_id=project, policy_digest="dig"
    )
    assert any(r["pattern"] == "read_x" for r in rules)

    # Verify: authorization epoch was bumped.
    ctx = await db.get_authorization_context(principal, project)
    assert ctx is not None and ctx["epoch"] >= 1

    # Verify: chat event was deleted by GC.
    events = await db.list_chat_stream_events(
        session_id=session, principal_id=principal, project_id=project
    )
    assert len(events) == 0


# ---------------------------------------------------------------------------
# Scenario 5: permission transaction midpoint → Audit read (reader isolation)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_audit_read_does_not_see_uncommitted_writer_state(db: Database):
    """A read issued while a write transaction is in-flight must go
    through the reader connection (``PRAGMA query_only = ON``) and
    therefore must NOT see the writer's uncommitted INSERT.

    This verifies the C-04 writer/reader connection split.
    """
    principal = "alice"
    project = "p1"
    await _seed_session(db, "s5", principal, project)

    midpoint = asyncio.Event()
    release_parent = asyncio.Event()
    read_result: list[dict] = []
    read_done = asyncio.Event()

    async def parent_uncommitted_insert():
        async with db.transaction() as conn:
            await conn.execute(
                "INSERT INTO audit_log (action, target, result, principal_id) "
                "VALUES ('uncommitted', 'target', 'ok', ?)",
                (principal,),
            )
            midpoint.set()
            await asyncio.wait_for(release_parent.wait(), timeout=10.0)

    async def concurrent_read():
        await asyncio.wait_for(midpoint.wait(), timeout=5.0)
        # This routes to the reader connection — must NOT see the
        # uncommitted INSERT.
        nonlocal read_result
        read_result = await db.list_audit_logs()
        read_done.set()

    parent_task = asyncio.create_task(parent_uncommitted_insert())
    reader_task = asyncio.create_task(concurrent_read())

    await asyncio.wait_for(read_done.wait(), timeout=10.0)

    # The reader must NOT have seen the uncommitted row.
    actions = [log["action"] for log in read_result]
    assert "uncommitted" not in actions, (
        "reader connection must not see the writer's uncommitted state"
    )

    # Release the parent so it commits and we can clean up.
    release_parent.set()
    await parent_task
    await reader_task

    # After commit, the reader sees the row.
    logs_after = await db.list_audit_logs()
    actions_after = [log["action"] for log in logs_after]
    assert "uncommitted" in actions_after


# ---------------------------------------------------------------------------
# Scenario 6: cancellation after first SQL
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_cancellation_after_first_sql_rolls_back(db: Database):
    """Cancelling the task after the first SQL but before COMMIT must
    roll back the transaction and leave the connection clean for the
    next caller.
    """
    await _seed_session(db, "s6")

    first_sql_done = asyncio.Event()

    async def cancellable_transaction():
        async with db.transaction() as conn:
            await conn.execute(
                "INSERT INTO audit_log (action, target, result) "
                "VALUES ('cancel_me', 'target', 'ok')"
            )
            first_sql_done.set()
            # Block here until cancelled.
            await asyncio.sleep(3600)

    task = asyncio.create_task(cancellable_transaction())
    await asyncio.wait_for(first_sql_done.wait(), timeout=5.0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    # The INSERT must have been rolled back.
    logs = await db.list_audit_logs()
    actions = [log["action"] for log in logs]
    assert "cancel_me" not in actions

    # The connection must be clean: a subsequent transaction works.
    async with db.transaction() as conn:
        await conn.execute(
            "INSERT INTO audit_log (action, target, result) "
            "VALUES ('after_cancel', 'target', 'ok')"
        )
    logs = await db.list_audit_logs()
    actions = [log["action"] for log in logs]
    assert "after_cancel" in actions


# ---------------------------------------------------------------------------
# Scenario 7: close during active transaction (lifecycle lock)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_close_waits_for_in_flight_transaction(db: Database):
    """``close()`` acquires ``_write_transaction_lock`` so it cannot
    tear down connections while a transaction is in-flight.

    The close call blocks until the transaction commits/rolls back,
    then proceeds.  After close, a stale owner token fails the
    generation check.
    """
    await _seed_session(db, "s7")

    transaction_midpoint = asyncio.Event()
    release_transaction = asyncio.Event()
    close_finished = asyncio.Event()

    async def in_flight_transaction():
        async with db.transaction() as conn:
            await conn.execute(
                "INSERT INTO audit_log (action, target, result) "
                "VALUES ('in_flight', 'target', 'ok')"
            )
            transaction_midpoint.set()
            await asyncio.wait_for(release_transaction.wait(), timeout=10.0)

    async def close_while_in_flight():
        await asyncio.wait_for(transaction_midpoint.wait(), timeout=5.0)
        # This must block until the transaction releases the lock.
        await db.close()
        close_finished.set()

    tx_task = asyncio.create_task(in_flight_transaction())
    close_task = asyncio.create_task(close_while_in_flight())

    # Give close a chance — it must NOT have finished yet.
    await asyncio.sleep(0.15)
    assert not close_finished.is_set(), (
        "close() must block while a write transaction is in-flight"
    )

    # Release the transaction; close should then proceed.
    release_transaction.set()
    await asyncio.wait_for(tx_task, timeout=10.0)
    await asyncio.wait_for(close_task, timeout=10.0)

    # The transaction committed successfully before close ran.
    # (We cannot read from the closed DB, but the task didn't raise.)


@pytest.mark.asyncio
async def test_close_from_within_transaction_raises(db: Database):
    """Calling ``close()`` from within a ``transaction()`` block in the
    same task must raise ``TransactionContextLeakError`` (programming
    error — would deadlock on ``_write_transaction_lock``).
    """
    await _seed_session(db, "s8")

    with pytest.raises(TransactionContextLeakError, match="active transaction"):
        async with db.transaction() as conn:
            await conn.execute(
                "INSERT INTO audit_log (action, target, result) "
                "VALUES ('noop', 'target', 'ok')"
            )
            await db.close()
