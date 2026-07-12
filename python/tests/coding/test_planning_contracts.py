from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from khaos.coding.intelligence.index import IndexStore, RepositoryIndexer
from khaos.coding.intelligence.query import CodeQueryService
from khaos.coding.intelligence.resolution.service import ResolutionService
from khaos.coding.planning.contracts import PlanStatus
from khaos.coding.planning.service import DeterministicPlanningService


@pytest.fixture
async def planner(tmp_path: Path):
    # Offline six-dialect fixture: each source exposes a public symbol, import,
    # caller/test shape, and a deliberately dynamic/ambiguous call form.
    # Real per-language config files are included so the VerificationCatalog
    # produces language-scoped trusted verification commands.
    files = {
        "python_lib.py": "def public_api(): return 1\ndef dynamic(name): return globals()[name]()\n",
        "python_test.py": "from python_lib import public_api\ndef test_public_api(): assert public_api() == 1\n",
        "javascript_lib.js": "export function publicJs(){return 1}; export const dyn=(x)=>globalThis[x]()\n",
        "javascript_test.js": "import {publicJs} from './javascript_lib.js'; publicJs();\n",
        "typescript_lib.ts": "export function publicTs():number{return 1}; const dyn=(x:string)=>(globalThis as any)[x]()\n",
        "tsx_view.tsx": "import {publicTs} from './typescript_lib'; export const View=()=> <button>{publicTs()}</button>\n",
        "tsx_view_test.tsx": "import {View} from './tsx_view'; export const TestView=()=> <View/>; const dyn=(x:string)=>(globalThis as any)[x]()\n",
        "go_lib.go": "package fixture\nfunc PublicGo() int { return 1 }\nfunc DynamicGo() { UnknownGo() }\n",
        "go_test.go": "package fixture\nfunc TestPublicGo() { PublicGo() }\n",
        "rust_lib.rs": "pub fn public_rust()->i32 {1}\npub fn dynamic(_: &str)->i32 { unknown_rust() }\n",
        "rust_test.rs": "use crate::public_rust; fn test_public_rust(){ public_rust(); }\n",
        # Real per-language config files for VerificationCatalog
        "pyproject.toml": "[tool.pytest]\ntestpaths = [\".\"]\n[tool.mypy]\npython_version = \"3.11\"\n[tool.ruff]\nline-length = 120\n",
        "package.json": '{"name":"fixture","scripts":{"test":"jest","typecheck":"tsc --noEmit","lint":"eslint ."},"devDependencies":{"typescript":"^5.0.0"}}\n',
        "go.mod": "module fixture\n\ngo 1.21\n",
        "Cargo.toml": "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\n[lints.clippy]\nall = \"warn\"\n",
    }
    for name, content in files.items(): (tmp_path / name).write_text(content)
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    store = IndexStore(conn); resolver = ResolutionService(conn)
    await RepositoryIndexer(store, resolution_service=resolver).index("repo", tmp_path, full_reindex=True)
    return DeterministicPlanningService(CodeQueryService(store), repositories={"repo": {"repository_id": "repo", "workspace_id": "ws", "head": "abc", "generation": 1, "root": str(tmp_path), "trusted_verification": ({"language": "python", "argv": ("python", "-m", "pytest", "-q"), "type": "unit-test", "source": "pyproject"},)}}), store


@pytest.mark.asyncio
async def test_unique_plan_is_deterministic_and_evidence_bound(planner):
    service, _ = planner
    first = service.plan(repository_id="repo", task_id="task", workspace_id="ws", user_goal="Modify function public_api", base_sha="abc")
    second = service.plan(repository_id="repo", task_id="task", workspace_id="ws", user_goal=" Modify  function public_api ", base_sha="abc")
    assert first.status is PlanStatus.READY
    assert first.content_hash == second.content_hash and first.plan_id == second.plan_id
    assert first.evidence[0].content_hash
    assert first.created_at == 0.0 and first.steps[0].requires_approval


@pytest.mark.asyncio
async def test_failure_matrix_rejects_inputs_and_never_approves(planner):
    service, _ = planner
    for kwargs in ({"user_goal": ""}, {"user_goal": "x" * 4097}, {"repository_id": "missing"}, {"workspace_id": "other"}, {"base_sha": "wrong"}):
        args = dict(repository_id="repo", task_id="t", workspace_id="ws", user_goal="modify public_api", base_sha="abc"); args.update(kwargs)
        assert service.plan(**args).status is PlanStatus.BLOCKED
    plan = service.plan(repository_id="repo", task_id="t", workspace_id="ws", user_goal="delete file python_lib.py", base_sha="abc")
    assert plan.status is PlanStatus.READY and plan.risks[0].level == "high" and plan.risks[0].requires_approval
    assert plan.status is not PlanStatus.APPROVED


@pytest.mark.asyncio
async def test_stale_when_head_generation_file_or_symbol_drifts(planner):
    service, store = planner
    plan = service.plan(repository_id="repo", task_id="t", workspace_id="ws", user_goal="modify public_api", base_sha="abc")
    assert service.validate_plan(plan, current_head="changed", current_repository_generation=1).status is PlanStatus.STALE
    assert service.validate_plan(plan, current_head="abc", current_repository_generation=2).status is PlanStatus.STALE
    await store.remove("repo", "python_lib.py")
    assert service.validate_plan(plan, current_head="abc", current_repository_generation=1).status is PlanStatus.STALE


@pytest.mark.asyncio
async def test_ambiguous_and_missing_targets_do_not_invent_symbols(planner):
    service, _ = planner
    missing = service.plan(repository_id="repo", task_id="t", workspace_id="ws", user_goal="modify function absent", base_sha="abc")
    assert missing.status is PlanStatus.BLOCKED and not missing.affected_symbols
    ambiguous = service.plan(repository_id="repo", task_id="t", workspace_id="ws", user_goal="modify function dynamic", base_sha="abc")
    assert ambiguous.status is PlanStatus.BLOCKED and not ambiguous.affected_symbols
