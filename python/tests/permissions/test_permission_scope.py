"""Phase-1 Authority Scope Closure regression tests."""

from khaos.db import Database
from khaos.permissions import (
    ApprovalMode,
    GrantLifetime,
    PermissionEngine,
    PermissionRule,
    TransportClass,
)


async def _engine(tmp_path) -> tuple[Database, PermissionEngine]:
    db = Database(tmp_path / "permissions.db")
    await db.connect()
    await db.run_migrations()
    return db, PermissionEngine(db)


async def test_interactive_project_grant_cannot_be_used_by_webhook(tmp_path):
    db, engine = await _engine(tmp_path)
    await engine.grant_rule(
        PermissionRule(
            id=None,
            pattern="/workspace/*",
            permission_level="read",
            approval=ApprovalMode.AUTO_APPROVE,
            mode="all",
        )
    )

    interactive = await engine.check(
        "read_file",
        {"path": "/workspace/a.txt"},
        "read",
        "office",
        source_transport="cli",
    )
    unattended = await engine.check(
        "read_file",
        {"path": "/workspace/a.txt"},
        "read",
        "office",
        source_transport="webhook",
    )

    assert interactive.approved is ApprovalMode.AUTO_APPROVE
    assert unattended.approved is ApprovalMode.ASK_EVERY
    await db.close()


async def test_session_and_task_grants_cannot_cross_scope(tmp_path):
    db, engine = await _engine(tmp_path)
    await engine.grant_rule(
        PermissionRule(
            id=None,
            pattern="/workspace/*",
            permission_level="write",
            approval=ApprovalMode.AUTO_APPROVE,
            mode="all",
            transport_class=TransportClass.INTERACTIVE.value,
            grant_lifetime=GrantLifetime.SESSION.value,
            session_id="session-a",
        )
    )
    await engine.grant_rule(
        PermissionRule(
            id=None,
            pattern="/repo/*",
            permission_level="write",
            approval=ApprovalMode.AUTO_APPROVE,
            mode="all",
            transport_class=TransportClass.INTERACTIVE.value,
            grant_lifetime=GrantLifetime.TASK.value,
            task_id="task-a",
            workspace_id="workspace-a",
        )
    )

    session_match = await engine.check(
        "write_file",
        {"path": "/workspace/a.txt"},
        "write",
        "coding",
        source_transport="tui",
        session_id="session-a",
    )
    session_miss = await engine.check(
        "write_file",
        {"path": "/workspace/a.txt"},
        "write",
        "coding",
        source_transport="tui",
        session_id="session-b",
    )
    task_match = await engine.check(
        "write_file",
        {"path": "/repo/a.txt"},
        "write",
        "coding",
        source_transport="cli",
        task_id="task-a",
        workspace_id="workspace-a",
    )
    task_miss = await engine.check(
        "write_file",
        {"path": "/repo/a.txt"},
        "write",
        "coding",
        source_transport="cli",
        task_id="task-b",
        workspace_id="workspace-a",
    )

    assert session_match.approved is ApprovalMode.AUTO_APPROVE
    assert session_miss.approved is ApprovalMode.ASK_EVERY
    assert task_match.approved is ApprovalMode.AUTO_APPROVE
    assert task_miss.approved is ApprovalMode.ASK_EVERY
    await db.close()


async def test_expired_scope_and_invalid_scope_are_fail_closed(tmp_path):
    db, engine = await _engine(tmp_path)
    await engine.grant_rule(
        PermissionRule(
            id=None,
            pattern="/expired/*",
            permission_level="read",
            approval=ApprovalMode.AUTO_APPROVE,
            mode="all",
            expires_at=1.0,
        )
    )
    # Bypass the Python grant API to model a restored/tampered row. Loading
    # must quarantine the malformed session scope rather than matching it.
    await db.insert_permission_rule(
        " /invalid/*",
        "read",
        ApprovalMode.AUTO_APPROVE.value,
        "all",
        principal_id="legacy",
        transport_class=TransportClass.INTERACTIVE.value,
        grant_lifetime=GrantLifetime.SESSION.value,
    )
    await engine.load_rules()

    expired = await engine.check(
        "read_file",
        {"path": "/expired/a.txt"},
        "read",
        "office",
        source_transport="cli",
    )
    assert expired.approved is ApprovalMode.ASK_EVERY
    assert all(rule.pattern != " /invalid/*" for rule in engine._rules)
    await db.close()
