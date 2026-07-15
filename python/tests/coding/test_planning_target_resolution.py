from __future__ import annotations

from dataclasses import replace

import pytest

from khaos.coding.planning.contracts import GoalIntent, PlanOperation, PlanStatus
from khaos.coding.planning.dag import validate_steps
from test_planning_contracts import planner  # noqa: F401


def _plan(service, goal):
    return service.plan(repository_id="repo", task_id="t", workspace_id="ws", user_goal=goal, base_sha="abc")


@pytest.mark.parametrize(("goal", "operation", "status"), [
    ("modify file python_lib.py", PlanOperation.MODIFY, PlanStatus.READY),
    ("inspect file python_lib.py", PlanOperation.INSPECT, PlanStatus.READY),
    ("test file python_test.py", PlanOperation.TEST, PlanStatus.READY),
    ("document file python_lib.py", PlanOperation.DOCUMENT, PlanStatus.READY),
    ("configure file python_lib.py", PlanOperation.CONFIGURE, PlanStatus.READY),
    ("delete file python_lib.py", PlanOperation.DELETE, PlanStatus.READY),
    ("rename file python_lib.py to renamed.py", PlanOperation.RENAME, PlanStatus.READY),
    ("move file python_lib.py to moved.py", PlanOperation.RENAME, PlanStatus.READY),
    ("create file missing.py", PlanOperation.CREATE, PlanStatus.READY),
    ("create file python_lib.py", PlanOperation.CREATE, PlanStatus.BLOCKED),
    ("modify file absent.py", PlanOperation.MODIFY, PlanStatus.BLOCKED),
])
def test_explicit_file_operation_matrix(planner, goal, operation, status):
    service, _ = planner
    plan = _plan(service, goal)
    assert plan.status is status
    assert all(step.operation in (PlanOperation.INSPECT, operation, PlanOperation.TEST) for step in plan.steps)
    if status is PlanStatus.BLOCKED:
        assert all(step.operation is PlanOperation.INSPECT for step in plan.steps)


def test_classify_and_plan_share_resolution(planner):
    service, _ = planner
    for goal in ("modify file python_lib.py", "modify file absent.py", "modify function public_api", "rename file python_lib.py"):
        classification = service.classify_goal(repository_id="repo", user_goal=goal)
        plan = _plan(service, goal)
        assert (classification.targets[0].resolved_status == "resolved") == (plan.status is PlanStatus.READY)


def test_untyped_file_and_symbol_resolution_and_conflict(planner):
    service, store = planner
    assert _plan(service, "modify python_lib.py").affected_files[0].path == "python_lib.py"
    assert _plan(service, "modify public_api").affected_symbols[0].qualified_name.endswith("public_api")
    store._conn.execute("INSERT INTO repository_symbols VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", ("conflict","conflict","repo","python_lib.py","python","function","python_lib.py","python_lib.py",0,1,0,1))
    conflict = _plan(service, "modify python_lib.py")
    assert conflict.status is PlanStatus.BLOCKED and "ambiguous-target" in {item.code for item in conflict.diagnostics}


def test_explicit_kind_is_authoritative(planner):
    service, store = planner
    store._conn.execute("INSERT INTO repository_symbols VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", ("class-id","class-id","repo","python_lib.py","python","class","OnlyClass","pkg.OnlyClass",0,1,0,1))
    assert service.classify_goal(repository_id="repo", user_goal="modify function pkg.OnlyClass").diagnostics[0].code == "kind-mismatch"
    assert service.classify_goal(repository_id="repo", user_goal="modify type pkg.OnlyClass").targets[0].resolved_status == "resolved"
    assert service.classify_goal(repository_id="repo", user_goal="modify file public_api").targets[0].resolved_status == "unresolved"


@pytest.mark.parametrize("goal", ["contest file python_lib.py", "deleteHandler file python_lib.py", "inspect file tests/delete/config.py", "configureServer symbol public_api"])
def test_operation_lexing_uses_independent_prefix_tokens(planner, goal):
    service, _ = planner
    result = service.classify_goal(repository_id="repo", user_goal=goal)
    assert result.intents == (GoalIntent.UNKNOWN,) or result.intents == (GoalIntent.INSPECT,)
    assert result.targets[0].requested_operation == PlanOperation.INSPECT.value


def test_verification_transitive_and_target_semantics(planner):
    service, _ = planner
    plan = _plan(service, "modify file python_lib.py")
    inspect, modify, verify = plan.steps
    bridge = replace(modify, step_id="dependent-1", depends_on=(modify.step_id,))
    indirect_verify = replace(verify, depends_on=(bridge.step_id,))
    assert not validate_steps((inspect, modify, bridge, indirect_verify))
    unrelated = replace(indirect_verify, target_files=("other.py",))
    assert "unrelated-verification-target" in {item.code for item in validate_steps((inspect, modify, bridge, unrelated))}
    backwards = replace(modify, depends_on=(verify.step_id,))
    assert "invalid-operation-order" in {item.code for item in validate_steps((inspect, backwards, verify))}


def test_candidate_order_does_not_change_resolution(planner, monkeypatch):
    service, store = planner
    rows = [
        ("z", "z", "repo", "python_lib.py", "python", "function", "Same", "z.Same", 0, 1, 0, 1),
        ("a", "a", "repo", "python_lib.py", "python", "function", "Same", "a.Same", 2, 3, 1, 1),
    ]
    store._conn.executemany("INSERT INTO repository_symbols VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", rows)
    first = service.classify_goal(repository_id="repo", user_goal="modify function Same")
    original = service._query.find_symbol_targets
    monkeypatch.setattr(service._query, "find_symbol_targets", lambda repository_id, name: list(reversed(original(repository_id, name))))
    second = service.classify_goal(repository_id="repo", user_goal="modify function Same")
    assert first.targets[0].candidate_symbols == second.targets[0].candidate_symbols
    assert first.diagnostics == second.diagnostics
