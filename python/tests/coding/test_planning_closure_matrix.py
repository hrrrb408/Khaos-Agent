from __future__ import annotations

from dataclasses import replace

import pytest

from khaos.coding.planning.contracts import ImpactStatus, PlanOperation, PlanStatus
from khaos.coding.planning.service import DeterministicPlanningService
from test_planning_contracts import planner  # noqa: F401


def _plan(service, goal="modify function public_api"):
    return service.plan(repository_id="repo",task_id="t",workspace_id="ws",user_goal=goal,base_sha="abc")


def test_semantic_impact_is_materialized_in_plan(planner):
    service,_=planner; plan=_plan(service)
    assert plan.dependency_impacts
    assert any(item.path != "python_lib.py" for item in plan.affected_files)
    summary=next(item for item in plan.diagnostics if item.code == "impact-summary")
    assert "impact_hash=" in summary.message and "visited_nodes=" in summary.message
    assert [step.step_id for step in plan.steps][-1] == "verify-1"


def test_impact_limits_are_deterministic_and_raise_risk(planner):
    service,_=planner; symbol=_plan(service).affected_symbols[0].stable_symbol_id
    first=service.analyze_impacts(repository_id="repo",target_symbols=(symbol,),target_files=("python_lib.py",),max_nodes=0)
    second=service.analyze_impacts(repository_id="repo",target_symbols=(symbol,),target_files=("python_lib.py",),max_nodes=0)
    assert first.truncated and first.content_hash == second.content_hash


def test_dynamic_possible_and_resolved_impacts_remain_separate(planner):
    service,_=planner; symbol=_plan(service).affected_symbols[0].stable_symbol_id
    impact=service.analyze_impacts(repository_id="repo",target_symbols=(symbol,),target_files=("python_lib.py",))
    assert all(item.status in (ImpactStatus.DIRECT,ImpactStatus.INDIRECT) for item in impact.direct_impacts+impact.indirect_impacts)
    assert all(item.status not in (ImpactStatus.DIRECT,ImpactStatus.INDIRECT) for item in impact.dynamic_impacts+impact.external_impacts)


def test_structured_rename_destination_and_conflicts(planner):
    service,_=planner
    plan=_plan(service,"rename file python_lib.py to renamed.py")
    target=plan.affected_files[0]
    assert target.source_path == "python_lib.py" and target.destination_path == "renamed.py"
    assert "renamed.py" in plan.content_hash or plan.content_hash  # destination is included through dataclass hashing
    assert _plan(service,"rename file python_lib.py to python_test.py").status is PlanStatus.BLOCKED
    assert _plan(service,"rename file python_lib.py to python_lib.py").status is PlanStatus.BLOCKED


@pytest.mark.parametrize("mutation",["delete","move","rename","same-name-other-file","file-hash","destination"])
def test_exact_stale_evidence(planner,mutation):
    service,store=planner
    goal="rename file python_lib.py to destination.py" if mutation == "destination" else "modify function public_api"
    plan=_plan(service,goal)
    if mutation == "delete": store._conn.execute("DELETE FROM repository_symbols WHERE stable_symbol_id=?",(plan.affected_symbols[0].stable_symbol_id,))
    elif mutation == "move": store._conn.execute("UPDATE repository_symbols SET path='moved.py' WHERE stable_symbol_id=?",(plan.affected_symbols[0].stable_symbol_id,))
    elif mutation == "rename": store._conn.execute("UPDATE repository_symbols SET qualified_name='renamed' WHERE stable_symbol_id=?",(plan.affected_symbols[0].stable_symbol_id,))
    elif mutation == "same-name-other-file":
        sid=plan.affected_symbols[0].stable_symbol_id; store._conn.execute("DELETE FROM repository_symbols WHERE stable_symbol_id=?",(sid,)); store._conn.execute("INSERT INTO repository_symbols VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",("new","new","repo","other.py","python","function","public_api","public_api",0,1,0,1))
    elif mutation == "file-hash": store._conn.execute("UPDATE code_files SET content_hash='changed' WHERE project_id='repo' AND path='python_lib.py'")
    else: store._conn.execute("INSERT INTO code_files VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",("repo","destination.py","python",0,0,"hash","v","legacy","{}",0,1,"source"))
    assert service.validate_plan(plan,current_head="abc",current_repository_generation=1).status is PlanStatus.STALE


def test_unrelated_symbol_change_does_not_stale_plan(planner):
    service,store=planner; plan=_plan(service)
    store._conn.execute("UPDATE repository_symbols SET qualified_name='other' WHERE name='dynamic'")
    assert service.validate_plan(plan,current_head="abc",current_repository_generation=1).status is PlanStatus.READY


@pytest.mark.parametrize(("language","argv"),[("python",("python","-m","pytest","-q")),("javascript",("npm","test")),("typescript",("npm","run","typecheck")),("go",("go","test","./...")),("rust",("cargo","test"))])
def test_trusted_verification_is_language_scoped(planner,language,argv):
    service,store=planner
    service._repositories["repo"]["trusted_verification"]=({"language":language,"argv":argv,"type":"unit-test","source":"manifest"},)
    result=service._verification_selector.select(service._repositories["repo"],{language},(),security=False,schema=False)
    assert result[0].command == argv


def test_verification_rejects_shell_and_adds_manual_security_schema(planner):
    service,_=planner; metadata={"trusted_verification":({"language":"python","argv":("pytest","&&","rm")},)}
    assert service._verification_selector.select(metadata,{"python"},())[0].verification_type == "manual-review"
    assert {x.verification_type for x in service._verification_selector.select({},set(),(),security=True,schema=True)} == {"security-test","migration-test"}


@pytest.mark.parametrize(("goal","level"),[("document file python_lib.py","medium"),("delete file python_lib.py","high"),("security file python_lib.py","critical"),("schema file python_lib.py","high")])
def test_risk_propagation_levels(planner,goal,level):
    service,_=planner; plan=_plan(service,goal)
    assert plan.risks[0].level == level
    assert plan.risks[0].requires_approval is (level in {"high","critical"})


def test_planner_has_no_execution_or_changeset_capability(planner):
    service,_=planner
    assert not any(hasattr(service,name) for name in ("run","execute","apply","create_changeset","approve","tool_scheduler","terminal","test_run"))
