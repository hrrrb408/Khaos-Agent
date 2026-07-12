from __future__ import annotations

from khaos.coding.planning.contracts import GoalIntent, ImpactStatus
from test_planning_contracts import planner  # noqa: F401


def test_goal_classifier_is_explicit_and_rejects_unsafe_path(planner):
    service, _ = planner
    result = service.classify_goal(repository_id="repo", user_goal="rename symbol public_api")
    assert result.intents == (GoalIntent.RENAME_SYMBOL,)
    unsafe = service.classify_goal(repository_id="repo", user_goal="modify file ../outside.py")
    assert unsafe.diagnostics[0].code == "unsafe-path"


def test_impact_analysis_is_deterministic_and_bounded(planner):
    service, _ = planner
    plan = service.plan(repository_id="repo", task_id="t", workspace_id="ws", user_goal="modify function public_api", base_sha="abc")
    symbol = plan.affected_symbols[0].stable_symbol_id
    if symbol is None:
        return
    first = service.analyze_impacts(repository_id="repo", target_symbols=(symbol,), max_nodes=1)
    second = service.analyze_impacts(repository_id="repo", target_symbols=(symbol,), max_nodes=1)
    assert first.content_hash == second.content_hash
    assert first.truncated or all(edge.status in (ImpactStatus.DIRECT, ImpactStatus.INDIRECT) for edge in first.direct_impacts)
