"""M4 batch 3.1.16A-2 / A-3 acceptance tests — principal partitioning.

End-to-end isolation scenarios across the five persistent-state subsystems
that were refactored to bind ``principal_id`` at construction:

* PermissionEngine  (A2-3)
* MemoryStore       (A2-4)
* ModeManager       (A2-5)
* AuditLogger       (A2-6)
* TaskManager       (A3-4)

The contract: every runtime component is bound to exactly one principal at
construction, and all DB reads/writes are scoped to that principal.  One
principal cannot see, modify, or revoke another principal's state.  Legacy
rows (``principal_id='legacy'``) are invisible to authenticated principals
so pre-A2/A3 data cannot leak into a post-A2/A3 multi-principal deployment.

Each test mirrors a concrete cross-principal attack vector:
1. Permission rule isolation — bob can't see or match alice's rules.
2. Cross-principal revoke is fail-closed — bob's revoke of alice's rule
   raises ``PermissionDeniedError`` rather than silently succeeding.
3. Memory namespace isolation — alice's ``private`` memory is invisible
   to bob; the ``shared`` namespace remains visible to both.
4. Mode isolation — alice switching to coding doesn't affect bob's mode.
5. Audit query isolation — bob's ``query()`` doesn't surface alice's
   audit events (fail-closed default).
6. Legacy quarantine — rules persisted before A2 (``principal_id='legacy'``)
   never match an authenticated principal's engine.
7. Coding task isolation (A3) — alice's tasks are invisible to bob and
   bob cannot cancel alice's tasks.
8. Coding task legacy quarantine (A3) — pre-A3 coding tasks are
   quarantined to ``status='failed'`` and invisible to authenticated
   principals.
"""

from __future__ import annotations

import pytest

from khaos.audit import AuditLogger
from khaos.coding.task_manager import TaskManager, TaskStatus, TransitionResult
from khaos.db import Database
from khaos.exceptions import PermissionDeniedError
from khaos.memory import Memory, MemoryConfidence, MemoryScope, MemoryStore
from khaos.modes import Mode, ModeManager
from khaos.permissions import ApprovalMode, PermissionEngine, PermissionRule


async def _db(tmp_path):
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    return db


PROJECT_ID = "test-project"
POLICY_DIGEST = "test-policy-digest"


# ---------------------------------------------------------------------------
# 1. Permission rule isolation
# ---------------------------------------------------------------------------


async def test_permission_rules_are_principal_scoped(tmp_path):
    """A2-3: alice grants a rule, bob's engine never sees it and never
    matches it even after a fresh ``load_rules``."""
    db = await _db(tmp_path)
    alice = PermissionEngine(
        db, principal_id="alice", project_id=PROJECT_ID,
        policy_digest=POLICY_DIGEST,
    )
    bob = PermissionEngine(
        db, principal_id="bob", project_id=PROJECT_ID,
        policy_digest=POLICY_DIGEST,
    )

    await alice.grant_rule(PermissionRule(
        id=None, pattern="/safe/*",
        permission_level="safe", approval=ApprovalMode.AUTO_APPROVE, mode="all",
    ))
    await alice.load_rules()
    await bob.load_rules()

    # Alice sees 1 rule; bob sees 0.
    assert len(alice._rules) == 1
    assert len(bob._rules) == 0

    # Alice's check matches her rule and auto-approves; bob's check falls
    # through to the default (ASK_EVERY) because he has no matching rule.
    alice_decision = await alice.check(
        "read_file", {"path": "/safe/file"}, "safe", "office",
    )
    bob_decision = await bob.check(
        "read_file", {"path": "/safe/file"}, "safe", "office",
    )
    assert alice_decision.approved is ApprovalMode.AUTO_APPROVE
    assert bob_decision.approved is ApprovalMode.ASK_EVERY
    await db.close()


# ---------------------------------------------------------------------------
# 2. Cross-principal revoke is fail-closed
# ---------------------------------------------------------------------------


async def test_cross_principal_revoke_is_fail_closed(tmp_path):
    """A2-3: bob cannot revoke alice's rule.  ``revoke_rule`` raises
    ``PermissionDeniedError`` (NOT a silent success) so the audit trail
    reflects the refused attempt and the caller can surface it."""
    db = await _db(tmp_path)
    alice = PermissionEngine(
        db, principal_id="alice", project_id=PROJECT_ID,
        policy_digest=POLICY_DIGEST,
    )
    bob = PermissionEngine(
        db, principal_id="bob", project_id=PROJECT_ID,
        policy_digest=POLICY_DIGEST,
    )

    granted = await alice.grant_rule(PermissionRule(
        id=None, pattern="read_file:/safe/*",
        permission_level="safe", approval=ApprovalMode.AUTO_APPROVE, mode="all",
    ))
    rule_id = granted.id
    assert rule_id is not None

    # Bob attempts to revoke alice's rule — must raise, not silently no-op.
    with pytest.raises(PermissionDeniedError):
        await bob.revoke_rule(rule_id)

    # Alice can still see and match her rule — it was NOT deleted.
    await alice.load_rules()
    assert len(alice._rules) == 1
    await db.close()


# ---------------------------------------------------------------------------
# 3. Memory namespace isolation
# ---------------------------------------------------------------------------


async def test_memory_private_namespace_is_principal_scoped(tmp_path):
    """A2-4: alice's ``private`` memory is invisible to bob.  The
    ``shared`` namespace (``principal_id=''``) remains visible to both
    so project-wide memories still work."""
    db = await _db(tmp_path)
    alice_store = MemoryStore(db, principal_id="alice")
    bob_store = MemoryStore(db, principal_id="bob")

    await alice_store.set(
        Memory(id=None, scope=MemoryScope.GLOBAL, key="alice-secret",
               value="alice-only", confidence=MemoryConfidence.HIGH),
        namespace="private",
    )
    await alice_store.set(
        Memory(id=None, scope=MemoryScope.GLOBAL, key="project-fact",
               value="shared-value", confidence=MemoryConfidence.MEDIUM),
        namespace="shared",
    )

    # Bob cannot read alice's private memory.
    bob_sees_private = await bob_store.get(
        MemoryScope.GLOBAL, "alice-secret", namespace="private",
    )
    assert bob_sees_private is None

    # Bob CAN read the shared namespace.
    bob_sees_shared = await bob_store.get(
        MemoryScope.GLOBAL, "project-fact", namespace="shared",
    )
    assert bob_sees_shared is not None
    assert bob_sees_shared.value == "shared-value"

    # Alice can read both.
    assert (await alice_store.get(
        MemoryScope.GLOBAL, "alice-secret", namespace="private",
    )).value == "alice-only"
    await db.close()


# ---------------------------------------------------------------------------
# 4. Mode isolation
# ---------------------------------------------------------------------------


async def test_mode_switch_does_not_leak_across_principals(tmp_path):
    """A2-5: alice switching to coding does not change bob's mode, even
    after a fresh ``load()``."""
    db = await _db(tmp_path)
    alice = ModeManager(db, project_root=tmp_path, principal_id="alice")
    bob = ModeManager(db, project_root=tmp_path, principal_id="bob")

    await alice.load()
    await bob.load()
    assert alice.current_mode is Mode.OFFICE
    assert bob.current_mode is Mode.OFFICE

    await alice.switch(Mode.CODING)

    # Reload bob — he must still be in OFFICE.
    await bob.load()
    assert alice.current_mode is Mode.CODING
    assert bob.current_mode is Mode.OFFICE

    # A freshly-constructed bob manager also sees OFFICE.
    bob_reloaded = ModeManager(db, project_root=tmp_path, principal_id="bob")
    await bob_reloaded.load()
    assert bob_reloaded.current_mode is Mode.OFFICE
    await db.close()


# ---------------------------------------------------------------------------
# 5. Audit query isolation
# ---------------------------------------------------------------------------


async def test_audit_query_filters_by_bound_principal(tmp_path):
    """A2-6: bob's ``query()`` does not surface alice's audit events.
    The default filter is fail-closed — bob must explicitly opt in
    (``principal_id=None``) to see cross-principal events."""
    db = await _db(tmp_path)
    alice = AuditLogger(db, principal_id="alice")
    bob = AuditLogger(db, principal_id="bob")

    await alice.log("write_file", "/alice/file", "success")
    await bob.log("write_file", "/bob/file", "success")

    # Bob's default query only sees his row.
    bob_view = await bob.query()
    assert [e.target for e in bob_view] == ["/bob/file"]

    # Alice's default query only sees her row.
    alice_view = await alice.query()
    assert [e.target for e in alice_view] == ["/alice/file"]

    # Explicit opt-in returns both — but it's an admin operation, not
    # the default.
    all_view = await alice.query(principal_id=None)
    assert sorted(e.target for e in all_view) == ["/alice/file", "/bob/file"]
    await db.close()


# ---------------------------------------------------------------------------
# 6. Legacy quarantine
# ---------------------------------------------------------------------------


async def test_legacy_permission_rules_are_invisible_to_authenticated_principals(
    tmp_path,
):
    """A2-3 + A2-8: rules persisted before A2 (``principal_id='legacy'``)
    never match an authenticated principal's engine.  An attacker who
    compromised the pre-A2 DB cannot pre-place a 'legacy' auto-approve
    rule that an authenticated principal's engine would match."""
    db = await _db(tmp_path)

    # Simulate a pre-A2 row by inserting directly with principal_id='legacy'.
    legacy_rule_id = await db.insert_permission_rule(
        "/attacker/*",
        "safe",
        "auto-approve",
        "all",
        principal_id="legacy",
    )
    assert legacy_rule_id > 0

    # Alice's authenticated engine loads rules scoped to her principal.
    alice = PermissionEngine(
        db, principal_id="alice", project_id=PROJECT_ID,
        policy_digest=POLICY_DIGEST,
    )
    await alice.load_rules()
    assert len(alice._rules) == 0  # legacy rule invisible

    # Alice's check on the attacker path falls through to the default —
    # NOT auto-approve, even though a legacy auto-approve rule exists.
    decision = await alice.check(
        "read_file", {"path": "/attacker/secret"}, "safe", "office",
    )
    assert decision.approved is not ApprovalMode.AUTO_APPROVE
    assert decision.approved is ApprovalMode.ASK_EVERY

    # Bob's view is the same — legacy is invisible to every authenticated
    # principal.
    bob = PermissionEngine(
        db, principal_id="bob", project_id=PROJECT_ID,
        policy_digest=POLICY_DIGEST,
    )
    await bob.load_rules()
    assert len(bob._rules) == 0
    await db.close()


async def test_legacy_audit_rows_are_invisible_to_authenticated_query(tmp_path):
    """A2-6 + A2-8: audit rows stamped ``principal_id='legacy'`` (e.g.
    from an old Khaos build) are invisible to an authenticated
    principal's default ``query()``."""
    db = await _db(tmp_path)

    # Insert a legacy audit row directly (simulating pre-A2 data).
    await db.insert_audit_log(
        "write_file", "/legacy/path", "success",
        detail="{}", session_id=None,
        principal_id="legacy",
    )

    # Alice's authenticated query sees nothing — legacy is quarantined.
    alice = AuditLogger(db, principal_id="alice")
    rows = await alice.query()
    assert rows == []

    # Explicit opt-in surfaces the legacy row (admin operation).
    all_rows = await alice.query(principal_id=None)
    assert len(all_rows) == 1
    assert all_rows[0].principal_id == "legacy"
    await db.close()


# ---------------------------------------------------------------------------
# 7. Coding task isolation (A3)
# ---------------------------------------------------------------------------


async def test_coding_tasks_are_principal_scoped(tmp_path):
    """A3-4: alice creates a task; bob's TaskManager cannot see, list,
    or cancel it.  The task is owned by alice for its entire lifecycle."""
    db = await _db(tmp_path)
    alice = TaskManager(db=db, principal_id="alice")
    bob = TaskManager(db=db, principal_id="bob")

    alice_task = await alice.create("alice's secret refactor")
    await alice.update_status(alice_task.id, TaskStatus.RUNNING)

    # Bob's list_all / list_active do not surface alice's task.
    bob_all = await bob.list_all()
    bob_active = await bob.list_active()
    assert all(item["id"] != alice_task.id for item in bob_all)
    assert all(item["id"] != alice_task.id for item in bob_active)

    # Bob's get returns None — the task is not in his cache.
    assert await bob.get(alice_task.id) is None

    # Bob's cancel returns NOT_FOUND — fail-closed, not a silent success.
    cancel_result = await bob.cancel(alice_task.id)
    assert cancel_result == TransitionResult.NOT_FOUND

    # Alice's task is still RUNNING — bob's cancel did not affect it.
    alice_refreshed = await alice.get(alice_task.id)
    assert alice_refreshed.status == TaskStatus.RUNNING
    await db.close()


async def test_coding_tasks_persist_across_restart_within_principal(tmp_path):
    """A3-4 + A3-2: alice's tasks survive a restart and are loaded only
    by alice's TaskManager.  Bob's TaskManager loading from the same DB
    never surfaces alice's tasks."""
    db = await _db(tmp_path)
    alice = TaskManager(db=db, principal_id="alice")
    alice_task = await alice.create("long work")
    await alice.update_status(alice_task.id, TaskStatus.RUNNING)
    await db.close()

    # Reopen the DB and construct fresh managers.
    db2 = Database(tmp_path / "khaos.db")
    await db2.connect()
    await db2.run_migrations()
    alice_reloaded = TaskManager(db=db2, principal_id="alice")
    bob_reloaded = TaskManager(db=db2, principal_id="bob")
    await alice_reloaded.load()
    await bob_reloaded.load()

    # Alice sees her task (interrupted → BLOCKED by load()).
    alice_loaded = await alice_reloaded.get(alice_task.id)
    assert alice_loaded is not None
    assert alice_loaded.status == TaskStatus.BLOCKED
    assert alice_loaded.goal == "long work"

    # Bob still sees nothing.
    assert await bob_reloaded.get(alice_task.id) is None
    assert all(item["id"] != alice_task.id for item in await bob_reloaded.list_all())
    await db2.close()


# ---------------------------------------------------------------------------
# 8. Coding task legacy quarantine (A3)
# ---------------------------------------------------------------------------


async def test_legacy_coding_tasks_are_invisible_and_quarantined(tmp_path):
    """A3-1 + A3-7: coding tasks persisted before A3
    (``principal_id='legacy'``) are quarantined to ``status='failed'``
    at migration time and invisible to an authenticated principal's
    TaskManager.  An attacker who compromised the pre-A3 DB cannot
    pre-place a 'legacy' task that an authenticated principal would
    load and execute."""
    db = await _db(tmp_path)

    # Simulate a pre-A3 row by inserting directly with principal_id='legacy'.
    # Use the public DB API so the row is formatted correctly.
    await db.insert_coding_task(
        {
            "id": "legacy-1",
            "goal": "attacker's task",
            "status": "running",  # pre-quarantine: would be active
            "state_json": "{}",
            "created_at": "2026-01-01T00:00:00",
            "updated_at": "2026-01-01T00:00:00",
        },
        principal_id="legacy",
    )

    # Re-run migrations to trigger the quarantine UPDATE.  ``run_migrations``
    # is idempotent — the ALTER TABLE is a no-op (column already exists),
    # but the quarantine UPDATE runs unconditionally and catches our
    # freshly-inserted legacy row.
    await db.run_migrations()

    # Alice's TaskManager loads nothing — legacy is filtered out by
    # ``list_coding_tasks(principal_id='alice')``.
    alice = TaskManager(db=db, principal_id="alice")
    await alice.load()
    assert await alice.get("legacy-1") is None
    assert all(item["id"] != "legacy-1" for item in await alice.list_all())

    # Direct DB probe: the legacy row still exists but is quarantined to
    # ``status='failed'`` so even if a future bug caused it to be loaded,
    # it could not enter the active lifecycle (``ACTIVE_STATUSES`` excludes
    # ``FAILED``).
    admin_view = await db.list_coding_tasks(principal_id=None)
    assert len(admin_view) == 1
    assert admin_view[0]["status"] == "failed"
    assert "quarantined" in (admin_view[0].get("error") or "")
    await db.close()
