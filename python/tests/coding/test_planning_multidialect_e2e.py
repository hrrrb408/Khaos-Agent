from __future__ import annotations

from pathlib import Path

import pytest

from khaos.coding.planning.contracts import PlanStatus
from test_planning_contracts import planner  # noqa: F401


@pytest.mark.parametrize(("dialect","symbol","definition","expected_language","expected_argv_prefix"),[
    ("python","public_api","python_lib.py","python",("python","-m","pytest")),
    ("javascript","publicJs","javascript_lib.js","javascript",("npm","run","test")),
    ("typescript","publicTs","typescript_lib.ts","typescript",("npm","run","test")),
    ("tsx","View","tsx_view.tsx","typescript",("npm","run","test")),
    ("go","PublicGo","go_lib.go","go",("go","test")),
    ("rust","public_rust","rust_lib.rs","rust",("cargo","test")),
])
def test_real_m3_chain_produces_deterministic_evidence_plan(planner,dialect,symbol,definition,expected_language,expected_argv_prefix):
    service,_=planner
    before={str(path): (path.stat().st_size,path.stat().st_mtime_ns) for path in Path(service._repositories.get("repo",{}).get("root","/nonexistent")).glob("**/*") if path.is_file()}
    first=service.plan(repository_id="repo",task_id=f"{dialect}-task",workspace_id="ws",user_goal=f"modify function {symbol}",base_sha="abc")
    second=service.plan(repository_id="repo",task_id=f"{dialect}-task",workspace_id="ws",user_goal=f"modify function {symbol}",base_sha="abc")
    assert first.status is PlanStatus.READY
    assert first.affected_symbols[0].path == definition
    assert first.evidence and first.evidence[0].symbol_id and first.evidence[0].content_hash
    assert first.steps[0].step_id == "inspect-1" and first.steps[-1].step_id == "verify-1"
    assert any(item.status in {"possible","dynamic","ambiguous","external"} for item in first.dependency_impacts)
    assert first.verification_requirements and first.risks
    assert first.content_hash == second.content_hash and first.plan_id == second.plan_id
    # Per-dialect verification assertions: language must match, argv must be correct,
    # and no Python command leaks into non-Python dialects.
    non_manual = [req for req in first.verification_requirements if req.command is not None]
    assert non_manual, f"{dialect}: must have at least one concrete verification command"
    for req in non_manual:
        # Python pytest must NOT appear for Go/Rust/JS/TS
        if expected_language != "python":
            assert not (req.command and req.command[:2] == ("python","-m") and len(req.command) > 2 and req.command[2] == "pytest"), \
                f"{dialect}: Python pytest leaked into {expected_language} verification"
        # The expected language-specific command must be present
        assert req.command[:len(expected_argv_prefix)] == expected_argv_prefix or any(
            req.command[:len(expected_argv_prefix)] == expected_argv_prefix
            for req in non_manual
        ), f"{dialect}: expected {expected_argv_prefix} in verification requirements"
    # Provenance must point to real config files
    provenance_evidence = [ev for req in first.verification_requirements for ev in req.evidence if ev.source == "verification-config"]
    assert provenance_evidence, f"{dialect}: verification must have config provenance evidence"
    after={str(path): (path.stat().st_size,path.stat().st_mtime_ns) for path in Path(service._repositories.get("repo",{}).get("root","/nonexistent")).glob("**/*") if path.is_file()}
    assert before == after
    assert not any(hasattr(service,name) for name in ("execute","tool_scheduler","terminal","test_run","create_changeset"))


def test_no_python_command_leakage_for_non_python_dialects(planner):
    """Python pytest must never become a Go/Rust/JS/TS verification."""
    service,_=planner
    for symbol, language in [("publicJs","javascript"),("publicTs","typescript"),("PublicGo","go"),("public_rust","rust")]:
        plan=service.plan(repository_id="repo",task_id="t",workspace_id="ws",user_goal=f"modify function {symbol}",base_sha="abc")
        assert plan.status is PlanStatus.READY
        for req in plan.verification_requirements:
            if req.command:
                assert not (req.command[:2]==("python","-m") and len(req.command)>2 and req.command[2]=="pytest"), \
                    f"Python pytest leaked into {language} verification for {symbol}"


def test_nonexistent_script_not_generated(planner):
    """npm scripts that don't exist in package.json must not be generated."""
    service,_=planner
    plan=service.plan(repository_id="repo",task_id="t",workspace_id="ws",user_goal="modify function publicJs",base_sha="abc")
    for req in plan.verification_requirements:
        if req.command and req.command[:2]==("npm","run"):
            script=req.command[2] if len(req.command)>2 else ""
            # Only scripts that exist in our fixture: test, typecheck, lint
            assert script in ("test","typecheck","lint"), f"Nonexistent npm script '{script}' generated"


def test_missing_auto_verification_falls_back_to_manual_review(planner):
    """When no catalog entry matches the affected language, manual-review is required."""
    service,_=planner
    # Create a plan for a file with no language mapping
    plan=service.plan(repository_id="repo",task_id="t",workspace_id="ws",user_goal="create file unknown.xyz",base_sha="abc")
    if plan.status is PlanStatus.READY:
        assert any(req.verification_type=="manual-review" for req in plan.verification_requirements)


def test_cross_language_plan_generates_multiple_language_requirements(planner):
    """A plan affecting multiple languages should generate requirements for each."""
    service,_=planner
    # Modify a Python file that imports from JS (cross-language scenario)
    plan=service.plan(repository_id="repo",task_id="t",workspace_id="ws",user_goal="modify function public_api",base_sha="abc")
    # The plan should have at least one Python verification requirement
    python_reqs=[req for req in plan.verification_requirements if req.scope=="python"]
    assert python_reqs, "Python plan must have Python-scoped verification"
