from __future__ import annotations

import sqlite3
import time
from pathlib import Path

import pytest

from khaos.coding.intelligence.index import IndexStore, RepositoryIndexer
from khaos.coding.intelligence.query import CodeQueryService
from khaos.coding.intelligence.resolution.service import ResolutionService
from khaos.coding.planning.contracts import PlanStatus
from khaos.coding.planning.service import DeterministicPlanningService


@pytest.mark.asyncio
async def test_large_repository_planning_matrix_is_bounded_deterministic_and_read_only(tmp_path: Path):
    for index in range(1000):
        if index == 0: content="def PublicRoot(): return 1\n"
        elif index <= 40: content=f"from file_0 import PublicRoot\ndef caller_{index}(): return PublicRoot()\n"
        else: content=f"def leaf_{index}(): return {index}\n"
        (tmp_path/f"file_{index}.py").write_text(content)
    conn=sqlite3.connect(":memory:",check_same_thread=False); store=IndexStore(conn); resolver=ResolutionService(conn)
    report=await RepositoryIndexer(store,resolution_service=resolver).index("large",tmp_path,full_reindex=True)
    query=CodeQueryService(store); service=DeterministicPlanningService(query,repositories={"large":{"repository_id":"large","workspace_id":"ws","head":"sha","generation":1,"trusted_verification":({"language":"python","argv":("python","-m","pytest","-q"),"type":"unit-test","source":"pyproject"},)}})
    snapshot={path.name:path.read_bytes() for path in tmp_path.iterdir()}
    started=time.perf_counter(); leaf=service.plan(repository_id="large",task_id="leaf",workspace_id="ws",user_goal="modify function leaf_999",base_sha="sha"); leaf_ms=(time.perf_counter()-started)*1000
    started=time.perf_counter(); public=service.plan(repository_id="large",task_id="public",workspace_id="ws",user_goal="modify function PublicRoot",base_sha="sha"); public_ms=(time.perf_counter()-started)*1000
    rename=service.plan(repository_id="large",task_id="rename",workspace_id="ws",user_goal="rename function PublicRoot to RenamedRoot",base_sha="sha")
    missing=service.plan(repository_id="large",task_id="missing",workspace_id="ws",user_goal="modify function absent",base_sha="sha")
    started=time.perf_counter(); repeated=service.plan(repository_id="large",task_id="public",workspace_id="ws",user_goal="modify function PublicRoot",base_sha="sha"); repeated_ms=(time.perf_counter()-started)*1000
    assert report["scanned_files"] == 1000 and leaf.status is PlanStatus.READY and public.status is PlanStatus.READY and rename.status is PlanStatus.READY and missing.status is PlanStatus.BLOCKED
    leaf_summary=next(x.message for x in leaf.diagnostics if x.code=="impact-summary"); public_summary=next(x.message for x in public.diagnostics if x.code=="impact-summary")
    assert "visited_nodes=1" in leaf_summary and len(leaf.affected_files) < 10
    assert len(public.affected_files) < 1000 and "visited_nodes=" in public_summary
    assert public.content_hash == repeated.content_hash and public.plan_id == repeated.plan_id
    assert snapshot == {path.name:path.read_bytes() for path in tmp_path.iterdir()}
    assert not any(hasattr(service,name) for name in ("execute","tool_scheduler","terminal","test_run","create_changeset"))
    metrics={"files":1000,"symbols":conn.execute("SELECT COUNT(*) FROM repository_symbols WHERE repository_id='large'").fetchone()[0],"edges":conn.execute("SELECT COUNT(*) FROM resolved_call_edges WHERE repository_id='large'").fetchone()[0],"leaf_ms":leaf_ms,"public_ms":public_ms,"repeated_ms":repeated_ms,"leaf_files":len(leaf.affected_files),"public_files":len(public.affected_files),"public_steps":len(public.steps),"risk":public.risks[0].level,"hash_equal":public.content_hash==repeated.content_hash}
    assert metrics["symbols"] >= 1000 and metrics["hash_equal"]
