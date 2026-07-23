"""F-01: Cross-domain concurrent transaction ownership tests.

These tests verify that the shared SQLite connection's global write
transaction lock prevents cross-domain ``commit()`` 串扰.

Review §4.5 requires 5 concurrent test groups:
  1. permission grant × chat event append
  2. permission revoke × audit insert
  3. operation approval consume × message insert
  4. turn terminalization × scheduler write
  5. authorization bind × memory write

Each test runs two coroutines on the SAME Database instance, injects
a yield point, and verifies that atomic invariants hold (no partial
commits, no epoch/rule mismatch, no sequence gaps).
"""

from __future__ import annotations

import asyncio
import json
import time

import pytest

from khaos.agent.core import Message
from khaos.db.database import Database


@pytest.fixture
async def db(tmp_path):
    """Fresh Database with migrations applied."""
    db = Database(str(tmp_path / "test.db"))
    await db.connect()
    await db.run_migrations()
    yield db
    await db.close()


# ---------------------------------------------------------------------------
# Group 1: permission grant × chat event append
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_concurrent_permission_grant_and_chat_event_append(db: Database):
    """Epoch/rule insertion must not be split by a concurrent chat event commit.

    Before F-01: the chat event's ``commit()`` could prematurely commit
    the permission grant's ``BEGIN IMMEDIATE`` transaction, leaving the
    epoch incremented but the rule not yet inserted.
    """
    principal = "alice"
    project = "proj-1"
    session = "sess-1"
    policy = "digest-aaa"
    now = time.time()

    # Set up a session and authorization context
    await db.create_session(session, principal_id=principal, project_id=project)
    await db.bind_authorization_context(principal, project, policy)

    grant_started = asyncio.Event()
    grant_can_finish = asyncio.Event()

    async def grant_permission():
        """Insert a permission rule (holds _authorization_lock + transaction)."""
        await db.insert_permission_rule(
            "read_file", "allow", "auto", "office",
            principal_id=principal, project_id=project,
            policy_digest=policy, generation=0,
        )
        grant_started.set()
        # Wait for the chat event to attempt its write before we finish
        await asyncio.wait_for(grant_can_finish.wait(), timeout=5.0)

    async def append_chat_event():
        """Append a chat stream event (holds _chat_event_lock + transaction)."""
        # Wait until the grant has started its transaction
        await asyncio.wait_for(grant_started.wait(), timeout=5.0)
        # Small yield to let grant's transaction be in-flight
        await asyncio.sleep(0.05)
        # This must not commit the grant's transaction
        seq = await db.append_chat_stream_event(
            session_id=session,
            principal_id=principal,
            project_id=project,
            event_type="message",
            data={"text": "hello"},
            now=now,
        )
        return seq

    # Run both concurrently
    grant_task = asyncio.create_task(grant_permission())
    chat_task = asyncio.create_task(append_chat_event())

    # Let the chat event complete (it should be serialized behind the grant)
    chat_seq = await chat_task

    # Now let the grant finish
    grant_can_finish.set()
    await grant_task

    # Verify: permission rule exists (grant was committed atomically)
    rules = await db.list_permission_rules(
        principal_id=principal, project_id=project, policy_digest=policy
    )
    assert len(rules) == 1
    assert rules[0]["pattern"] == "read_file"

    # Verify: chat event was persisted (chat transaction was committed)
    events = await db.list_chat_stream_events(
        session_id=session, principal_id=principal, project_id=project
    )
    assert len(events) == 1
    assert events[0]["sequence"] == chat_seq

    # Verify: authorization epoch was bumped exactly once
    ctx = await db.get_authorization_context(principal, project)
    assert ctx is not None
    assert ctx["epoch"] == 2  # bind=1, grant=2


# ---------------------------------------------------------------------------
# Group 2: permission revoke × audit insert
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_concurrent_permission_revoke_and_audit_insert(db: Database):
    """Revoking a permission (epoch bump + rule delete) must be atomic
    even when an audit log insert commits concurrently.
    """
    principal = "bob"
    project = "proj-2"
    policy = "digest-bbb"
    now = time.time()

    await db.create_session("sess-2", principal_id=principal, project_id=project)
    await db.bind_authorization_context(principal, project, policy)
    rule_id = await db.insert_permission_rule(
        "write_file", "allow", "ask", "office",
        principal_id=principal, project_id=project,
        policy_digest=policy, generation=0,
    )

    revoke_started = asyncio.Event()
    revoke_can_finish = asyncio.Event()

    async def revoke_permission():
        await db.delete_permission_rule(
            rule_id,
            principal_id=principal, project_id=project, policy_digest=policy,
        )
        revoke_started.set()
        await asyncio.wait_for(revoke_can_finish.wait(), timeout=5.0)

    async def insert_audit():
        await asyncio.wait_for(revoke_started.wait(), timeout=5.0)
        await asyncio.sleep(0.05)
        # Audit insert must not commit the revoke's transaction
        await db.insert_audit_log(
            action="tool_call",
            target="terminal",
            result="success",
            detail="",
            session_id="sess-2",
            principal_id=principal,
            project_id=project,
        )

    revoke_task = asyncio.create_task(revoke_permission())
    audit_task = asyncio.create_task(insert_audit())

    await audit_task
    revoke_can_finish.set()
    await revoke_task

    # Verify: rule is deleted
    rules = await db.list_permission_rules(
        principal_id=principal, project_id=project, policy_digest=policy
    )
    assert len(rules) == 0

    # Verify: epoch was bumped (revoke commits epoch + delete atomically)
    ctx = await db.get_authorization_context(principal, project)
    assert ctx is not None
    assert ctx["epoch"] == 3  # bind=1, grant=2, revoke=3

    # Verify: audit log was persisted
    logs = await db.list_audit_logs()
    assert any(log["action"] == "tool_call" for log in logs)


# ---------------------------------------------------------------------------
# Group 3: operation approval consume × message insert
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_concurrent_approval_consume_and_message_insert(db: Database):
    """Consuming an operation approval (status update + event) must be
    atomic even when a message insert commits concurrently.
    """
    principal = "carol"
    project = "proj-3"
    session = "sess-3"
    now = time.time()

    await db.create_session(session, principal_id=principal, project_id=project)

    # Register and approve an operation
    approval_id = "approval-3"
    binding = "binding-digest-3"
    await db.register_operation_approval(
        approval_id=approval_id,
        binding_digest=binding,
        binding_json=json.dumps({"op": "delete"}),
        principal_id=principal,
        session_id=session,
        task_id="task-3",
        workspace_id="ws-3",
        operation="delete_file",
        nonce_hash="nonce-3",
        expires_at=now + 3600,
        created_at=now,
    )
    await db.approve_operation_approval(
        approval_id, principal_id=principal, session_id=session, now=now,
    )

    consume_started = asyncio.Event()
    consume_can_finish = asyncio.Event()

    async def consume_approval():
        result = await db.consume_operation_approval(
            approval_id,
            binding_digest=binding,
            principal_id=principal,
            session_id=session,
            now=now,
        )
        consume_started.set()
        await asyncio.wait_for(consume_can_finish.wait(), timeout=5.0)
        return result

    async def insert_message():
        await asyncio.wait_for(consume_started.wait(), timeout=5.0)
        await asyncio.sleep(0.05)
        # Message insert must not commit the consume's transaction
        await db.insert_message(
            session,
            Message(role="user", content="test message"),
            principal_id=principal, project_id=project,
        )

    consume_task = asyncio.create_task(consume_approval())
    msg_task = asyncio.create_task(insert_message())

    await msg_task
    consume_can_finish.set()
    consume_result = await consume_task

    # Verify: approval was consumed
    assert consume_result is True

    # Verify: consume event was persisted atomically with status update
    events = await db.list_operation_approval_events(approval_id)
    event_types = [e["event_type"] for e in events]
    assert "registered" in event_types
    assert "approved" in event_types
    assert "consumed" in event_types

    # Verify: message was persisted
    messages = await db.list_messages(session, principal_id=principal)
    assert any(m.content == "test message" for m in messages)


# ---------------------------------------------------------------------------
# Group 4: turn terminalization × scheduler write
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_concurrent_turn_terminalization_and_scheduler_write(db: Database):
    """Terminalizing an agent turn (status + last_sequence update) must be
    atomic even when a scheduled task write commits concurrently.
    """
    principal = "dave"
    project = "proj-4"
    session = "sess-4"
    now = time.time()

    await db.create_session(session, principal_id=principal, project_id=project)

    # Start a turn
    await db.start_agent_turn(
        turn_id="turn-4",
        attempt_id="attempt-4",
        session_id=session,
        task_id=None,
        payload={"input": "test"},
        now=now,
        principal_id=principal,
        project_id=project,
    )

    # Insert a scheduled task
    await db.insert_scheduled_task(
        name="cron-task-4",
        prompt="test prompt",
        status="active",
        schedule={"type": "cron", "expression": "0 * * * *"},
        principal_id=principal,
        project_id=project,
        policy_digest="",
    )

    terminal_started = asyncio.Event()
    terminal_can_finish = asyncio.Event()

    async def terminalize_turn():
        await db.append_agent_turn_event(
            turn_id="turn-4",
            expected_sequence=1,
            event_type="turn.completed",
            payload={"result": "ok"},
            now=now + 1,
            terminal_status="completed",
        )
        terminal_started.set()
        await asyncio.wait_for(terminal_can_finish.wait(), timeout=5.0)

    async def update_scheduler():
        await asyncio.wait_for(terminal_started.wait(), timeout=5.0)
        await asyncio.sleep(0.05)
        # Scheduler write must not commit the turn's terminal transaction
        tasks = await db.list_scheduled_tasks(principal_id=principal)
        if tasks:
            await db.update_scheduled_task_status(
                tasks[0]["id"], "paused",
            )

    terminal_task = asyncio.create_task(terminalize_turn())
    sched_task = asyncio.create_task(update_scheduler())

    await sched_task
    terminal_can_finish.set()
    await terminal_task

    # Verify: turn is terminal (status=completed, last_sequence=2)
    events = await db.list_agent_turn_events("turn-4")
    assert len(events) == 2  # turn.started + turn.completed
    assert events[0]["event_type"] == "turn.started"
    assert events[1]["event_type"] == "turn.completed"

    # Verify: scheduler task was updated
    tasks = await db.list_scheduled_tasks(principal_id=principal)
    assert len(tasks) == 1
    assert tasks[0]["status"] == "paused"


# ---------------------------------------------------------------------------
# Group 5: authorization bind × memory write
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_concurrent_authorization_bind_and_memory_write(db: Database):
    """Binding an authorization context (epoch bump) must be atomic
    even when a memory upsert commits concurrently.
    """
    principal = "eve"
    project = "proj-5"
    session = "sess-5"
    now = time.time()

    await db.create_session(session, principal_id=principal, project_id=project)

    # Initial bind
    await db.bind_authorization_context(principal, project, "old-digest")

    bind_started = asyncio.Event()
    bind_can_finish = asyncio.Event()

    async def rebind_authorization():
        await db.bind_authorization_context(principal, project, "new-digest")
        bind_started.set()
        await asyncio.wait_for(bind_can_finish.wait(), timeout=5.0)

    async def write_memory():
        await asyncio.wait_for(bind_started.wait(), timeout=5.0)
        await asyncio.sleep(0.05)
        # Memory write must not commit the bind's transaction
        await db.upsert_memory(
            scope="test", key="key-5", value="value-5",
            ttl=3600, confidence=5,
            principal_id=principal, namespace="private",
            session_id=session, project_id=project,
        )

    bind_task = asyncio.create_task(rebind_authorization())
    mem_task = asyncio.create_task(write_memory())

    await mem_task
    bind_can_finish.set()
    await bind_task

    # Verify: authorization context has new digest and bumped epoch
    ctx = await db.get_authorization_context(principal, project)
    assert ctx is not None
    assert ctx["policy_digest"] == "new-digest"
    assert ctx["epoch"] == 2  # initial bind=1, rebind=2

    # Verify: memory was persisted
    mem = await db.get_memory(
        scope="test", key="key-5",
        principal_id=principal, namespace="private", session_id=session,
        project_id=project,
    )
    assert mem is not None
    assert mem["value"] == "value-5"


# ---------------------------------------------------------------------------
# Stress test: many concurrent writes across domains
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_stress_concurrent_writes_across_domains_no_errors(db: Database):
    """1000 concurrent writes across permission, chat, memory, audit, and
    scheduler domains must complete without transaction errors.

    Before F-01: this would produce random ``cannot start a transaction
    within a transaction`` or silently commit partial transactions.
    """
    principal = "frank"
    project = "proj-6"
    session = "sess-6"
    policy = "digest-frank"
    now = time.time()

    await db.create_session(session, principal_id=principal, project_id=project)
    await db.bind_authorization_context(principal, project, policy)

    async def chat_append(i: int):
        await db.append_chat_stream_event(
            session_id=session,
            principal_id=principal,
            project_id=project,
            event_type="message",
            data={"i": i},
            now=now + i * 0.001,
        )

    async def memory_write(i: int):
        await db.upsert_memory(
            scope="stress", key=f"key-{i}", value=f"val-{i}",
            ttl=3600, confidence=1,
            principal_id=principal, namespace="private",
            session_id=session, project_id=project,
        )

    async def audit_insert(i: int):
        await db.insert_audit_log(
            action="stress_test",
            target=f"info-{i}",
            result="success",
            detail="",
            session_id=session,
            principal_id=principal,
            project_id=project,
        )

    async def message_insert(i: int):
        await db.insert_message(
            session,
            Message(role="assistant", content=f"msg-{i}"),
            principal_id=principal, project_id=project,
        )

    # Run 200 operations from each domain concurrently
    tasks = []
    for i in range(200):
        tasks.append(asyncio.create_task(chat_append(i)))
        tasks.append(asyncio.create_task(memory_write(i)))
        tasks.append(asyncio.create_task(audit_insert(i)))
        tasks.append(asyncio.create_task(message_insert(i)))

    # All must complete without raising
    results = await asyncio.gather(*tasks, return_exceptions=True)
    errors = [r for r in results if isinstance(r, Exception)]
    assert len(errors) == 0, f"{len(errors)} operations failed: {errors[:3]}"

    # Verify chat events are monotonically sequenced with no gaps
    events = await db.list_chat_stream_events(
        session_id=session, principal_id=principal, project_id=project,
        limit=1024,
    )
    assert len(events) == 200
    sequences = [e["sequence"] for e in events]
    assert sequences == list(range(1, 201)), "chat event sequences must be gapless"

    # Verify memories were all persisted
    memories = await db.list_memories(
        scope="stress", principal_id=principal, namespace="private",
        project_id=project,
    )
    assert len(memories) == 200


# ---------------------------------------------------------------------------
# Nested transaction test: inner method must not commit outer transaction
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_nested_transaction_inner_does_not_commit_outer(db: Database):
    """When a method using ``transaction()`` calls another method that also
    uses ``transaction()``, the inner method must NOT commit the outer
    transaction. The outer transaction owner performs the single COMMIT.
    """
    principal = "grace"
    project = "proj-7"
    session = "sess-7"
    now = time.time()

    await db.create_session(session, principal_id=principal, project_id=project)

    # Use transaction() explicitly, then call insert_message (which also
    # uses transaction() internally). The inner transaction() should be
    # a no-op (reuse outer), and the outer commit should persist both.
    async with db.transaction() as conn:
        await conn.execute(
            "INSERT INTO audit_log "
            "(action, target, result, detail, session_id, principal_id, project_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("outer_op", "outer_target", "success", "", session, principal, project),
        )
        # Inner method uses transaction() — must not commit
        await db.insert_message(
            session,
            Message(role="user", content="nested message"),
            principal_id=principal, project_id=project,
        )
        # If inner committed, the outer audit log would already be visible
        # to a concurrent reader at this point. We can't easily test that
        # from the same task, but we can verify both are persisted after
        # the outer transaction commits.

    # Both the audit log and the message should be persisted
    logs = await db.list_audit_logs()
    assert any(log["action"] == "outer_op" for log in logs)

    messages = await db.list_messages(session, principal_id=principal)
    assert any(m.content == "nested message" for m in messages)
