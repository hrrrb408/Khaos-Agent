from __future__ import annotations

import pytest

from khaos.db import Database
from khaos.exceptions import PermissionDeniedError
from khaos.permissions.engine import ApprovalMode, PermissionEngine, PermissionRule


def _engine(db: Database, digest: str) -> PermissionEngine:
    return PermissionEngine(
        db,
        principal_id="api:alice",
        project_id="project-1",
        policy_digest=digest,
    )


async def test_cross_runtime_grant_and_revoke_refresh_before_next_check(tmp_path) -> None:
    state_path = tmp_path / "state.db"
    db_a = Database(state_path)
    db_b = Database(state_path)
    await db_a.connect()
    await db_a.run_migrations()
    await db_b.connect()
    await db_b.run_migrations()
    runtime_a = _engine(db_a, "policy-a")
    runtime_b = _engine(db_b, "policy-a")
    await runtime_a.load_rules()
    await runtime_b.load_rules()

    rule = await runtime_a.grant_rule(
        PermissionRule(
            id=None,
            pattern="https://example.com",
            permission_level="network",
            approval=ApprovalMode.AUTO_APPROVE,
            mode="all",
        )
    )
    granted = await runtime_b.check(
        "web_fetch", {"url": "https://example.com/a"}, "network", "office"
    )
    assert granted.approved is ApprovalMode.AUTO_APPROVE
    assert granted.matched_rule is not None

    await runtime_a.revoke_rule(rule.id or 0)
    revoked = await runtime_b.check(
        "web_fetch", {"url": "https://example.com/a"}, "network", "office"
    )
    assert revoked.approved is ApprovalMode.ASK_EVERY
    assert revoked.matched_rule is None
    await db_a.close()
    await db_b.close()


async def test_policy_digest_change_invalidates_old_runtime_and_rules(tmp_path) -> None:
    db = Database(tmp_path / "state.db")
    await db.connect()
    await db.run_migrations()
    old_runtime = _engine(db, "policy-a")
    await old_runtime.load_rules()
    await old_runtime.grant_rule(
        PermissionRule(
            id=None,
            pattern="https://example.com",
            permission_level="network",
            approval=ApprovalMode.AUTO_APPROVE,
            mode="all",
        )
    )

    new_runtime = _engine(db, "policy-b")
    await new_runtime.load_rules()
    stale = await old_runtime.check(
        "web_fetch", {"url": "https://example.com"}, "network", "office"
    )
    restarted = await new_runtime.check(
        "web_fetch", {"url": "https://example.com"}, "network", "office"
    )
    assert stale.approved is ApprovalMode.DENY
    assert "stale" in stale.reason
    assert restarted.approved is ApprovalMode.ASK_EVERY
    await db.close()


async def test_permission_query_is_bound_to_digest_and_epoch(tmp_path) -> None:
    db = Database(tmp_path / "state.db")
    await db.connect()
    await db.run_migrations()
    engine = _engine(db, "policy-a")
    await engine.load_rules()
    rule = await engine.grant_rule(
        PermissionRule(None, "*", "read", ApprovalMode.AUTO_APPROVE, "all")
    )
    rows = await db.list_permission_rules(
        principal_id="api:alice",
        project_id="project-1",
        policy_digest="policy-a",
        generation=rule.generation,
    )
    assert [row["id"] for row in rows] == [rule.id]
    assert await db.list_permission_rules(
        principal_id="api:alice",
        project_id="project-1",
        policy_digest="policy-b",
        generation=rule.generation,
    ) == []
    await db.close()


async def test_revoke_between_check_and_dispatch_invalidates_snapshot(tmp_path) -> None:
    db = Database(tmp_path / "state.db")
    await db.connect()
    await db.run_migrations()
    runtime = _engine(db, "policy-a")
    await runtime.load_rules()
    rule = await runtime.grant_rule(
        PermissionRule(None, "*", "write", ApprovalMode.AUTO_APPROVE, "all")
    )
    snapshot = await runtime.authorization_snapshot()
    await runtime.revoke_rule(rule.id or 0)
    with pytest.raises(PermissionDeniedError, match="before tool dispatch"):
        await runtime.validate_dispatch_epoch(snapshot)
    await db.close()
