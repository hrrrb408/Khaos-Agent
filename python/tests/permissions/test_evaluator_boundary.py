"""Pure decision tests for the permission evaluator seam."""

from __future__ import annotations

from khaos.permissions import ApprovalMode, PermissionRule
from khaos.permissions.evaluator import PermissionEvaluator


def _rule(approval: ApprovalMode) -> PermissionRule:
    return PermissionRule(
        id=1,
        pattern="cat*",
        permission_level="execute",
        approval=approval,
        mode="coding",
        transport_class="all",
        grant_lifetime="project_all_transports",
    )


def test_evaluator_has_no_database_dependency() -> None:
    evaluator = PermissionEvaluator(
        rules=(),
        default_mode=ApprovalMode.DENY,
        commands_require_approval=frozenset(),
    )
    assert not hasattr(evaluator, "db")
    assert evaluator.evaluate(
        "read_file",
        {"path": "/tmp/a"},
        "read",
        "coding",
        "/tmp/a",
    ).approved is ApprovalMode.DENY


def test_required_approval_precedes_default_and_rules() -> None:
    evaluator = PermissionEvaluator(
        rules=(_rule(ApprovalMode.AUTO_APPROVE),),
        default_mode=ApprovalMode.AUTO_APPROVE,
        commands_require_approval=frozenset({"cat"}),
        exec_tool_names=frozenset({"terminal"}),
    )
    decision = evaluator.evaluate(
        "terminal",
        {"command": "cat ~/.ssh/id_rsa"},
        "execute",
        "coding",
        "cat ~/.ssh/id_rsa",
        source_transport="cli",
    )
    assert decision.approved is ApprovalMode.ASK_EVERY
    assert decision.requires_user_confirm


def test_deny_rule_precedes_interactive_read_only_shortcut() -> None:
    evaluator = PermissionEvaluator(
        rules=(_rule(ApprovalMode.DENY),),
        default_mode=ApprovalMode.AUTO_APPROVE,
        commands_require_approval=frozenset(),
    )
    decision = evaluator.evaluate(
        "terminal",
        {"command": "cat file"},
        "execute",
        "coding",
        "cat file",
        source_transport="cli",
    )
    assert decision.approved is ApprovalMode.DENY


def test_evaluator_captures_rule_snapshot() -> None:
    rules = [_rule(ApprovalMode.DENY)]
    evaluator = PermissionEvaluator(
        rules=rules,
        default_mode=ApprovalMode.AUTO_APPROVE,
        commands_require_approval=frozenset(),
    )
    rules.clear()
    decision = evaluator.evaluate(
        "terminal",
        {"command": "echo ok"},
        "execute",
        "coding",
        "echo ok",
        source_transport="rpc",
    )
    assert decision.approved is ApprovalMode.AUTO_APPROVE
