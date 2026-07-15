from __future__ import annotations

from dataclasses import replace

import pytest

from khaos.coding.planning.contracts import GoalIntent, PlanOperation
from khaos.coding.planning.dag import InvalidPlanDagError, topologically_sort_steps, validate_steps
from test_planning_contracts import planner  # noqa: F401


def _codes(steps):
    return [item.code for item in validate_steps(tuple(steps))]


def test_goal_target_queries_preserve_case_and_evidence_token(planner):
    service, store = planner
    rows = [
        ("one", "one", "repo", "python_lib.py", "python", "class", "APIClient", "pkg.APIClient", 0, 1, 0, 1),
        ("two", "two", "repo", "python_lib.py", "python", "class", "ApiClient", "pkg.ApiClient", 2, 3, 1, 1),
        ("three", "three", "repo", "python_lib.py", "python", "function", "Foo", "pkg.Foo", 4, 5, 2, 1),
        ("four", "four", "repo", "python_lib.py", "python", "function", "foo", "pkg.foo", 6, 7, 3, 1),
    ]
    store._conn.executemany("INSERT INTO repository_symbols VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", rows)
    upper = service.classify_goal(repository_id="repo", user_goal="MODIFY symbol pkg.APIClient")
    lower = service.classify_goal(repository_id="repo", user_goal="modify symbol pkg.ApiClient")
    assert upper.intents == lower.intents == (GoalIntent.MODIFY_SYMBOL,)
    assert upper.targets[0].raw_text == "pkg.APIClient"
    assert lower.targets[0].raw_text == "pkg.ApiClient"
    assert upper.targets[0].candidate_symbols != lower.targets[0].candidate_symbols
    assert upper.targets[0].evidence[0].query == "pkg.APIClient"
    assert service.classify_goal(repository_id="repo", user_goal="modify function Foo").targets[0].candidate_symbols != service.classify_goal(repository_id="repo", user_goal="modify function foo").targets[0].candidate_symbols


@pytest.mark.parametrize("goal", [
    "modify file /etc/passwd", "modify file ../outside.py", "modify file src/../../outside.py",
    r"modify file C:\Windows\system.ini", r"modify file \\server\share\x.py", "modify file //server/share/x.py",
])
def test_unsafe_paths_are_rejected(planner, goal):
    service, _ = planner
    result = service.classify_goal(repository_id="repo", user_goal=goal)
    assert result.targets[0].resolved_status == "rejected"
    assert result.diagnostics[0].code == "unsafe-path"


def test_explicit_target_kinds_do_not_use_dot_heuristic(planner):
    service, _ = planner
    assert service._parse_target("modify symbol pkg.module.APIClient").requested_symbol == "pkg.module.APIClient"
    assert service._parse_target("modify function APIClient.run").requested_path is None
    assert service._parse_target("modify file src/api.ts").requested_path == "src/api.ts"
    assert service._parse_target("modify file src//./config").requested_path == "src/config"
    assert service._parse_target("modify file 资料/配置").requested_path == "资料/配置"


def test_dag_diagnostics_are_specific_and_stable(planner):
    service, _ = planner
    plan = service.plan(repository_id="repo", task_id="t", workspace_id="ws", user_goal="delete file python_lib.py", base_sha="abc")
    inspect, delete, verify = plan.steps
    no_dep = replace(delete, depends_on=())
    assert "destructive-without-inspection" in _codes((inspect, no_dep))
    test_dep = replace(delete, depends_on=(verify.step_id,))
    assert "destructive-without-inspection" in _codes((inspect, test_dep, verify))
    assert not validate_steps((inspect, delete, verify))
    missing = replace(delete, depends_on=("missing",))
    assert _codes((inspect, missing)) == ["destructive-without-inspection", "missing-step-dependency"]
    self_dep = replace(delete, depends_on=(delete.step_id,))
    assert "step-cycle" not in _codes((inspect, self_dep))
    modify_without_inspect = replace(delete, operation=PlanOperation.MODIFY, depends_on=())
    assert "invalid-operation-order" in _codes((inspect, modify_without_inspect))


def test_topological_sort_is_stable_and_rejects_invalid(planner):
    service, _ = planner
    plan = service.plan(repository_id="repo", task_id="t", workspace_id="ws", user_goal="modify function public_api", base_sha="abc")
    assert [item.step_id for item in topologically_sort_steps(tuple(reversed(plan.steps)))] == ["inspect-1", "modify-1", "verify-1"]
    with pytest.raises(InvalidPlanDagError):
        topologically_sort_steps((replace(plan.steps[1], depends_on=("missing",)),))
