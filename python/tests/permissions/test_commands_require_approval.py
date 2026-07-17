"""H3: commands_require_approval enforcement in PermissionEngine.

The policy field was previously parsed but never consumed.  This test file
proves the PermissionEngine now honors it as a pre-rule gate: a command on
the approval list always requires confirmation, even when a persistent
auto-approve rule would otherwise match.
"""

import pytest

from khaos.db import Database
from khaos.permissions import ApprovalMode, PermissionEngine, PermissionRule


async def _engine_with(
    tmp_path, *, approval_list, auto_approve_command=None
) -> PermissionEngine:
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    await db.create_session("s1")
    engine = PermissionEngine(
        db, commands_require_approval=approval_list
    )
    if auto_approve_command is not None:
        await engine.grant_rule(
            PermissionRule(
                id=None,
                pattern=auto_approve_command,
                permission_level="write",
                approval=ApprovalMode.AUTO_APPROVE,
                mode="coding",
            )
        )
        await engine.load_rules()
    return engine


async def test_policy_requires_approval_for_listed_command(tmp_path):
    engine = await _engine_with(
        tmp_path, approval_list=frozenset({"rm", "git push"})
    )
    decision = await engine.check(
        "terminal", {"command": "rm -rf /tmp/junk"}, "write", "coding"
    )
    assert decision.requires_user_confirm is True
    assert decision.approved is ApprovalMode.ASK_EVERY


async def test_policy_requires_approval_overrides_auto_approve_rule(tmp_path):
    """H3 core: a remembered auto-approve rule cannot bypass policy approval."""
    engine = await _engine_with(
        tmp_path,
        approval_list=frozenset({"rm"}),
        # A user previously chose "always allow rm".
        auto_approve_command="rm*",
    )
    decision = await engine.check(
        "terminal", {"command": "rm oldfile"}, "write", "coding"
    )
    assert decision.requires_user_confirm is True, (
        "policy commands_require_approval must override persistent auto-approve"
    )
    assert decision.approved is ApprovalMode.ASK_EVERY


async def test_unlisted_command_unaffected(tmp_path):
    engine = await _engine_with(
        tmp_path, approval_list=frozenset({"rm"})
    )
    decision = await engine.check(
        "terminal", {"command": "ls -la"}, "write", "coding"
    )
    # ls is not on the approval list; falls through to default ask-every.
    assert "Policy requires approval" not in decision.reason


async def test_multi_word_entry_matches_with_args(tmp_path):
    """``git push origin main`` matches the ``git push`` entry."""
    engine = await _engine_with(
        tmp_path, approval_list=frozenset({"git push"})
    )
    decision = await engine.check(
        "terminal", {"command": "git push origin main"}, "write", "coding"
    )
    assert decision.requires_user_confirm is True


async def test_pipeline_segment_matches(tmp_path):
    """A chained command ``ls; rm x`` is caught via the rm segment."""
    engine = await _engine_with(
        tmp_path, approval_list=frozenset({"rm"})
    )
    decision = await engine.check(
        "terminal", {"command": "ls -la; rm leaked"}, "write", "coding"
    )
    assert decision.requires_user_confirm is True


async def test_empty_approval_list_no_effect(tmp_path):
    engine = await _engine_with(tmp_path, approval_list=frozenset())
    decision = await engine.check(
        "terminal", {"command": "rm anything"}, "write", "coding"
    )
    assert "Policy requires approval" not in decision.reason


async def test_process_tool_also_gated(tmp_path):
    engine = await _engine_with(
        tmp_path, approval_list=frozenset({"curl"})
    )
    decision = await engine.check(
        "process", {"command": "curl http://example.com"}, "write", "coding"
    )
    assert decision.requires_user_confirm is True
