from __future__ import annotations

from pathlib import Path

import pytest

from khaos.coding.planning.contracts import PlanStatus
from test_planning_contracts import planner  # noqa: F401


@pytest.mark.parametrize(("dialect","symbol","definition"),[
    ("python","public_api","python_lib.py"),
    ("javascript","publicJs","javascript_lib.js"),
    ("typescript","publicTs","typescript_lib.ts"),
    ("tsx","View","tsx_view.tsx"),
    ("go","PublicGo","go_lib.go"),
    ("rust","public_rust","rust_lib.rs"),
])
def test_real_m3_chain_produces_deterministic_evidence_plan(planner,dialect,symbol,definition):
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
    after={str(path): (path.stat().st_size,path.stat().st_mtime_ns) for path in Path(service._repositories.get("repo",{}).get("root","/nonexistent")).glob("**/*") if path.is_file()}
    assert before == after
    assert not any(hasattr(service,name) for name in ("execute","tool_scheduler","terminal","test_run","create_changeset"))
