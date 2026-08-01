"""Round-14 §3: overbroad auto-approve rule patterns must be rejected.

A remembered ``AUTO_APPROVE`` / ``SUGGEST`` rule whose pattern matches
every target for its permission level silently disables the approval
gate, voiding the ask-every default (ADR-003).  These tests pin the
``validate_rule_pattern`` contract: blanket globs are rejected for
relaxing approvals, accepted for ``ASK_EVERY`` / ``DENY``, and sensible
broad-but-anchored patterns are accepted for all approvals.
"""

import pytest

from khaos.db import Database
from khaos.permissions import ApprovalMode, PermissionEngine, PermissionRule
from khaos.permissions.engine import (
    MIN_RULE_SPECIFICITY,
    validate_rule_pattern,
)


@pytest.mark.parametrize("pattern", ["*", "**", "?", "?*", "/*", "[a-z]*", " * "])
def test_overbroad_auto_approve_patterns_rejected(pattern: str) -> None:
    with pytest.raises(ValueError, match="too broad"):
        validate_rule_pattern(pattern, ApprovalMode.AUTO_APPROVE)


def test_overbroad_suggest_patterns_rejected() -> None:
    with pytest.raises(ValueError):
        validate_rule_pattern("**", ApprovalMode.SUGGEST)


@pytest.mark.parametrize(
    "pattern",
    [
        "/home/user/*",
        "terminal:git *",
        "https://api.example.com/*",
        "/tmp/specific/*",
        "read_file:/etc/hosts",
    ],
)
def test_anchored_auto_approve_patterns_accepted(pattern: str) -> None:
    # Must not raise — these have a concrete prefix before the first glob.
    validate_rule_pattern(pattern, ApprovalMode.AUTO_APPROVE)


@pytest.mark.parametrize("approval", [ApprovalMode.ASK_EVERY, ApprovalMode.DENY])
def test_overbroad_patterns_allowed_for_non_relaxing_approvals(approval: ApprovalMode) -> None:
    # A blanket DENY (or ASK_EVERY) never relaxes enforcement, so "*"
    # is a legitimate way to say "always ask / always deny".
    validate_rule_pattern("*", approval)


def test_empty_pattern_rejected() -> None:
    with pytest.raises(ValueError):
        validate_rule_pattern("", ApprovalMode.AUTO_APPROVE)
    with pytest.raises(ValueError):
        validate_rule_pattern("   ", ApprovalMode.AUTO_APPROVE)


async def test_grant_rule_rejects_overbroad_auto_approve(tmp_path) -> None:
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    engine = PermissionEngine(db)
    with pytest.raises(ValueError, match="too broad"):
        await engine.grant_rule(
            PermissionRule(None, "*", "read", ApprovalMode.AUTO_APPROVE, "all")
        )
    await db.close()


def test_specificity_constant_is_at_least_two() -> None:
    # Guards against an accidental relaxation to 0/1 which would let
    # "/*" or "?" through.
    assert MIN_RULE_SPECIFICITY >= 2


def test_materialize_rules_quarantines_overbroad_db_rows() -> None:
    """Round-15 A-1: a ``"*"`` AUTO_APPROVE row loaded from the DB (e.g. via
    a restored backup or direct SQL) must be quarantined by
    ``_materialize_rules`` rather than loaded into ``_rules`` where it would
    auto-approve every target.  The ``validate_rule_pattern`` guard in
    ``grant_rule`` only blocks the Python write path; the DB row is the real
    trust boundary and must be validated on read too.
    """
    engine = PermissionEngine.__new__(PermissionEngine)  # bypass __init__
    rows = [
        # Overbroad AUTO_APPROVE — must be quarantined.
        {"id": 1, "pattern": "*", "permission_level": "read",
         "approval": "auto-approve", "mode": "all", "granted_at": 0,
         "policy_digest": "d", "generation": 0},
        # Specific AUTO_APPROVE — must be kept.
        {"id": 2, "pattern": "/home/me/*", "permission_level": "read",
         "approval": "auto-approve", "mode": "all", "granted_at": 0,
         "policy_digest": "d", "generation": 0},
        # Overbroad DENY — must be kept (a blanket deny is legitimate).
        {"id": 3, "pattern": "*", "permission_level": "read",
         "approval": "deny", "mode": "all", "granted_at": 0,
         "policy_digest": "d", "generation": 0},
    ]
    rules = engine._materialize_rules(rows)
    ids = {rule.id for rule in rules}
    assert 1 not in ids, "overbroad AUTO_APPROVE rule must be quarantined"
    assert 2 in ids, "specific AUTO_APPROVE rule must be kept"
    assert 3 in ids, "blanket DENY rule must be kept"


async def test_load_rules_quarantines_db_inserted_overbroad_rule(tmp_path) -> None:
    """Round-15 A-1: end-to-end — a ``"*"`` rule written directly to the DB
    (bypassing ``grant_rule``) is quarantined on ``load_rules``."""
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    engine = PermissionEngine(
        db, principal_id="p1", project_id="proj", policy_digest="dig"
    )
    await engine.load_rules()  # binds the authorization context / epoch
    epoch = engine._authorization_epoch
    # Insert both an overbroad and a specific rule at the bound epoch,
    # bypassing grant_rule (the path an attacker with DB access would use).
    await db.insert_permission_rule(
        "*", "read", "auto-approve", "all",
        principal_id="p1", project_id="proj", policy_digest="dig",
    )
    await db.insert_permission_rule(
        "/home/me/*", "read", "auto-approve", "all",
        principal_id="p1", project_id="proj", policy_digest="dig",
    )
    # insert_permission_rule bumps the epoch; trigger a reload through check(),
    # which detects the epoch drift and re-materializes the rules (validating).
    await engine.check("read_file", {"path": "/x"}, "read", "coding")
    patterns = {rule.pattern for rule in engine._rules}
    assert "*" not in patterns, "overbroad rule must be quarantined on load"
    assert "/home/me/*" in patterns, "specific rule must be loaded"
    await db.close()
