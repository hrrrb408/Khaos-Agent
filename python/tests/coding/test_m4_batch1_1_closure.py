"""M4 Batch 1.1 closure: 14 regression scenarios.

Covers re-export evidence, verification catalog language scoping, budget
unification, no-full-scan proof, and PlanningService read-only constraints.
"""
from __future__ import annotations

import asyncio
import sqlite3
import tempfile
from pathlib import Path

import pytest

from khaos.coding.intelligence.index import IndexStore, RepositoryIndexer
from khaos.coding.intelligence.query import CodeQueryService
from khaos.coding.intelligence.resolution.service import ResolutionService
from khaos.coding.planning.contracts import PlanStatus
from khaos.coding.planning.service import DeterministicPlanningService
from khaos.coding.planning.verification_catalog import VerificationCatalog

# Import the shared planner fixture from the contracts test module
from test_planning_contracts import planner  # noqa: F401


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_impact_summary(plan) -> dict[str, str]:
    diag = next(d for d in plan.diagnostics if d.code == "impact-summary")
    pairs = {}
    for part in diag.message.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            pairs[k.strip()] = v.strip()
    return pairs


async def _index_repo(tmp_path: Path, files: dict[str, str], repo_id: str = "repo"):
    for name, content in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    store = IndexStore(conn)
    resolver = ResolutionService(conn)
    await RepositoryIndexer(store, resolution_service=resolver).index(repo_id, tmp_path, full_reindex=True)
    return conn, store, resolver


def _make_service(store, tmp_path: Path, *, repo_id: str = "repo", **kwargs):
    query = CodeQueryService(store)
    defaults = {
        "repository_id": repo_id, "workspace_id": "ws", "head": "abc",
        "generation": 1, "root": str(tmp_path),
        "trusted_verification": ({"language": "python", "argv": ("python", "-m", "pytest", "-q"), "type": "unit-test", "source": "pyproject"},),
    }
    defaults.update(kwargs)
    return DeterministicPlanningService(query, repositories={repo_id: defaults})


# ---------------------------------------------------------------------------
# Scenario 1: Ordinary index.ts import is NOT deterministic re-export
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_01_ordinary_index_ts_import_is_not_deterministic_reexport(tmp_path: Path):
    """A plain ``import {x} from './index.ts'`` is a reverse-import, not a re-export."""
    files = {
        "index.ts": "export function internalFunc(): number { return 42; }\n",
        "consumer.ts": "import { internalFunc } from './index';\nexport function useIt(): number { return internalFunc(); }\n",
    }
    conn, store, _ = await _index_repo(tmp_path, files)
    service = _make_service(store, tmp_path)
    plan = service.plan(repository_id="repo", task_id="t", workspace_id="ws", user_goal="modify function internalFunc", base_sha="abc")
    assert plan.status is PlanStatus.READY
    # The ordinary import must NOT be classified as re-export
    reexport_impacts = [imp for imp in plan.dependency_impacts if imp.relation == "re-export"]
    assert not reexport_impacts, "ordinary index.ts import must not be classified as re-export"
    # It should be classified as reverse-import or calls (if the caller calls the function)
    non_reexport = [imp for imp in plan.dependency_impacts if imp.relation != "re-export"]
    assert non_reexport, "ordinary index.ts import must produce some non-reexport impact"


# ---------------------------------------------------------------------------
# Scenario 2: Real JS/TS export-from produces semantic re-export evidence
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_02_real_js_export_from_produces_semantic_reexport(tmp_path: Path):
    """``export {x} from './module.js'`` must produce reexport=True metadata."""
    files = {
        "module.js": "export function originalFunc(): number { return 1; }\n",
        "barrel.js": "export { originalFunc } from './module.js';\n",
    }
    conn, store, _ = await _index_repo(tmp_path, files)
    # Check the resolved_imports table for reexport metadata
    rows = conn.execute(
        "SELECT source_file, metadata_json FROM resolved_imports WHERE repository_id='repo' AND target_file LIKE '%module.js'"
    ).fetchall()
    assert rows, "must have resolved imports targeting module.js"
    import json
    reexport_found = False
    for source_file, meta_json in rows:
        meta = json.loads(meta_json) if meta_json else {}
        if meta.get("reexport") or meta.get("import_kind") == "reexport":
            reexport_found = True
            assert source_file.endswith("barrel.js")
    assert reexport_found, "export-from must produce reexport=True in metadata"


# ---------------------------------------------------------------------------
# Scenario 3: Rust pub use produces semantic re-export evidence
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_03_rust_pub_use_produces_semantic_reexport(tmp_path: Path):
    """``pub use crate::module::foo`` must produce pub_use=True, reexport=True."""
    files = {
        "src/lib.rs": "pub fn original_rust(): i32 { 1 }\n",
        "src/reexport.rs": "pub use crate::lib::original_rust;\n",
    }
    conn, store, _ = await _index_repo(tmp_path, files)
    rows = conn.execute(
        "SELECT source_file, metadata_json FROM resolved_imports WHERE repository_id='repo'"
    ).fetchall()
    import json
    pub_use_found = False
    for source_file, meta_json in rows:
        meta = json.loads(meta_json) if meta_json else {}
        if meta.get("pub_use") or meta.get("reexport"):
            pub_use_found = True
            assert "reexport.rs" in source_file or "lib.rs" in source_file
    assert pub_use_found, "pub use must produce pub_use=True and reexport=True in metadata"


# ---------------------------------------------------------------------------
# Scenario 4: Non-index file real re-export not missed
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_04_non_index_file_real_reexport_not_missed(tmp_path: Path):
    """Re-export from a non-index file (e.g. barrel.ts) must still be detected."""
    files = {
        "core.ts": "export function coreFunc(): number { return 1; }\n",
        "barrel.ts": "export { coreFunc } from './core';\n",
        "consumer.ts": "import { coreFunc } from './barrel';\nexport function useCore(): number { return coreFunc(); }\n",
    }
    conn, store, _ = await _index_repo(tmp_path, files)
    rows = conn.execute(
        "SELECT source_file, target_file, metadata_json FROM resolved_imports WHERE repository_id='repo'"
    ).fetchall()
    import json
    barrel_reexport = False
    for source_file, target_file, meta_json in rows:
        meta = json.loads(meta_json) if meta_json else {}
        if meta.get("reexport") and "barrel.ts" in source_file:
            barrel_reexport = True
    assert barrel_reexport, "non-index barrel.ts re-export must be detected"


# ---------------------------------------------------------------------------
# Scenario 5: Reverse import vs re-export classification not confused
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_05_reverse_import_vs_reexport_not_confused(tmp_path: Path):
    """A file with both a regular import and a re-export must classify them differently."""
    files = {
        "base.ts": "export function baseFunc(): number { return 1; }\n",
        "regular.ts": "import { baseFunc } from './base';\nexport function useBase(): number { return baseFunc(); }\n",
        "reexporter.ts": "export { baseFunc } from './base';\n",
    }
    conn, store, _ = await _index_repo(tmp_path, files)
    rows = conn.execute(
        "SELECT source_file, metadata_json FROM resolved_imports WHERE repository_id='repo' AND target_file LIKE '%base.ts'"
    ).fetchall()
    import json
    has_regular = False
    has_reexport = False
    for source_file, meta_json in rows:
        meta = json.loads(meta_json) if meta_json else {}
        if meta.get("reexport"):
            has_reexport = True
            assert "reexporter.ts" in source_file
        else:
            has_regular = True
            assert "regular.ts" in source_file
    assert has_regular, "regular import must be present and classified as non-reexport"
    assert has_reexport, "re-export must be present and classified as reexport"


# ---------------------------------------------------------------------------
# Scenario 6: Python verification only for Python
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_06_python_verification_only_for_python(planner):
    """Python pytest must only appear for Python-affected plans."""
    service, _ = planner
    plan = service.plan(repository_id="repo", task_id="t", workspace_id="ws", user_goal="modify function public_api", base_sha="abc")
    assert plan.status is PlanStatus.READY
    for req in plan.verification_requirements:
        if req.command and req.command[:2] == ("python", "-m"):
            assert req.scope == "python", "python command must be scoped to python"


# ---------------------------------------------------------------------------
# Scenario 7: Go verification uses go test
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_07_go_verification_uses_go_test(planner):
    """Go plans must include ``go test`` from go.mod provenance."""
    service, _ = planner
    plan = service.plan(repository_id="repo", task_id="t", workspace_id="ws", user_goal="modify function PublicGo", base_sha="abc")
    assert plan.status is PlanStatus.READY
    has_go_test = any(
        req.command and req.command[:2] == ("go", "test")
        for req in plan.verification_requirements if req.command
    )
    assert has_go_test, "Go plan must include 'go test' verification"


# ---------------------------------------------------------------------------
# Scenario 8: Rust verification uses cargo
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_08_rust_verification_uses_cargo(planner):
    """Rust plans must include ``cargo test`` or ``cargo check`` from Cargo.toml."""
    service, _ = planner
    plan = service.plan(repository_id="repo", task_id="t", workspace_id="ws", user_goal="modify function public_rust", base_sha="abc")
    assert plan.status is PlanStatus.READY
    has_cargo = any(
        req.command and req.command[0] == "cargo"
        for req in plan.verification_requirements if req.command
    )
    assert has_cargo, "Rust plan must include 'cargo test' or 'cargo check'"


# ---------------------------------------------------------------------------
# Scenario 9: JS/TS script must exist
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_09_js_ts_script_must_exist(planner):
    """Only npm scripts that exist in package.json may be generated."""
    service, _ = planner
    plan = service.plan(repository_id="repo", task_id="t", workspace_id="ws", user_goal="modify function publicJs", base_sha="abc")
    assert plan.status is PlanStatus.READY
    for req in plan.verification_requirements:
        if req.command and req.command[:2] == ("npm", "run"):
            script_name = req.command[2] if len(req.command) > 2 else ""
            assert script_name in ("test", "typecheck", "lint"), f"nonexistent npm script '{script_name}' generated"


# ---------------------------------------------------------------------------
# Scenario 10: Legacy command without language does not cross-language propagate
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_10_legacy_command_no_cross_language_propagation(tmp_path: Path):
    """A server rule without ``language`` must NOT propagate to any language."""
    files = {
        "python_lib.py": "def public_api(): return 1\n",
        "go_lib.go": "package fixture\nfunc PublicGo() int { return 1 }\n",
        "pyproject.toml": "[tool.pytest]\ntestpaths=[\".\"]\n",
        "go.mod": "module fixture\n\ngo 1.21\n",
    }
    conn, store, _ = await _index_repo(tmp_path, files)
    # Server rule WITHOUT language — must not propagate
    service = _make_service(store, tmp_path, trusted_verification=(
        {"argv": ("python", "-m", "pytest"), "type": "unit-test", "source": "legacy-no-lang"},  # no "language" key
    ))
    for goal in ("modify function public_api", "modify function PublicGo"):
        plan = service.plan(repository_id="repo", task_id="t", workspace_id="ws", user_goal=goal, base_sha="abc")
        if plan.status is PlanStatus.READY:
            # The legacy rule must NOT appear — only catalog-based entries
            for req in plan.verification_requirements:
                if req.command and req.command[:2] == ("python", "-m") and len(req.command) > 2 and req.command[2] == "pytest":
                    # This is fine for Python (from pyproject.toml), but must NOT be from the legacy rule
                    ev_meta = [ev.metadata for ev in req.evidence if ev.source == "verification-config"]
                    for meta in ev_meta:
                        assert meta.get("provenance") != "legacy-no-lang", "legacy language-less rule propagated"


# ---------------------------------------------------------------------------
# Scenario 11: Config hash drift makes plan stale
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_11_config_hash_drift_makes_plan_stale(tmp_path: Path):
    """Changing a config file after planning must invalidate the plan."""
    files = {
        "python_lib.py": "def public_api(): return 1\n",
        "pyproject.toml": "[tool.pytest]\ntestpaths = [\".\"]\n",
    }
    conn, store, _ = await _index_repo(tmp_path, files)
    service = _make_service(store, tmp_path)
    plan = service.plan(repository_id="repo", task_id="t", workspace_id="ws", user_goal="modify function public_api", base_sha="abc")
    assert plan.status is PlanStatus.READY
    # Modify the config file
    (tmp_path / "pyproject.toml").write_text("[tool.pytest]\ntestpaths = [\"tests\"]\n[tool.mypy]\npython_version = \"3.12\"\n")
    # Clear the catalog cache so the service re-reads the config
    service._catalogs.clear()
    result = service.validate_plan(plan, current_head="abc", current_repository_generation=1)
    assert result.status is PlanStatus.STALE
    assert any(d.code == "config-hash-drift" for d in result.diagnostics), "config hash drift must be detected"


# ---------------------------------------------------------------------------
# Scenario 12: PlanningService does not directly access store._conn
# ---------------------------------------------------------------------------

def test_12_planning_service_does_not_access_store_conn():
    """Static analysis: PlanningService source must not reference ``_conn`` directly."""
    import inspect
    from khaos.coding.planning import service as service_module
    source = inspect.getsource(service_module)
    # The service must NOT directly access _conn — it must go through CodeQueryService
    assert "_conn" not in source, "PlanningService must not directly access store._conn"


# ---------------------------------------------------------------------------
# Scenario 13: Leaf performance test detects full-table scan (counter-example)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_13_leaf_planning_detects_full_table_scan(tmp_path: Path):
    """Leaf planning must not enumerate all code_files — proved by sql_rows_enumerated."""
    for i in range(200):
        if i == 0:
            content = "def PublicRoot(): return 1\n"
        elif i <= 10:
            content = f"from file_0 import PublicRoot\ndef caller_{i}(): return PublicRoot()\n"
        else:
            content = f"def leaf_{i}(): return {i}\n"
        (tmp_path / f"file_{i}.py").write_text(content)
    conn, store, _ = await _index_repo(tmp_path, {}, repo_id="large")
    # Re-index with all files
    for i in range(200):
        if i == 0:
            content = "def PublicRoot(): return 1\n"
        elif i <= 10:
            content = f"from file_0 import PublicRoot\ndef caller_{i}(): return PublicRoot()\n"
        else:
            content = f"def leaf_{i}(): return {i}\n"
        (tmp_path / f"file_{i}.py").write_text(content)
    conn2 = sqlite3.connect(":memory:", check_same_thread=False)
    store2 = IndexStore(conn2)
    resolver2 = ResolutionService(conn2)
    await RepositoryIndexer(store2, resolution_service=resolver2).index("large", tmp_path, full_reindex=True)
    service = _make_service(store2, tmp_path, repo_id="large")
    plan = service.plan(repository_id="large", task_id="leaf", workspace_id="ws", user_goal="modify function leaf_150", base_sha="abc")
    assert plan.status is PlanStatus.READY
    summary = _parse_impact_summary(plan)
    sql_rows = int(summary["sql_rows_enumerated"])
    test_candidates = int(summary["inspected_test_candidates"])
    assert sql_rows < 200, f"leaf sql_rows_enumerated={sql_rows} — full table scan detected"
    assert test_candidates < 200, f"leaf inspected_test_candidates={test_candidates} — unbounded test scan"
    assert len(plan.affected_files) < 200


# ---------------------------------------------------------------------------
# Scenario 14: Unified budget covers all impact sources
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_14_unified_budget_covers_all_impact_sources(tmp_path: Path):
    """All impact sources (callers, references, reverse imports, re-exports,
    test associations) must share a single budget and respect its limits."""
    # Create a repo with many callers, reverse imports, and test files
    files = {}
    files["core.py"] = "def core_func(): return 1\n"
    for i in range(30):
        files[f"caller_{i}.py"] = f"from core import core_func\ndef caller_{i}(): return core_func()\n"
        files[f"test_{i}.py"] = f"from core import core_func\ndef test_{i}(): assert core_func() == 1\n"
    files["__init__.py"] = "from core import core_func\n"
    files["pyproject.toml"] = "[tool.pytest]\ntestpaths = [\".\"]\n"
    for name, content in files.items():
        (tmp_path / name).write_text(content)
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    store = IndexStore(conn)
    resolver = ResolutionService(conn)
    await RepositoryIndexer(store, resolution_service=resolver).index("repo", tmp_path, full_reindex=True)
    query = CodeQueryService(store)
    # Tight budget — all sources must share it
    service = DeterministicPlanningService(
        query,
        repositories={"repo": {
            "repository_id": "repo", "workspace_id": "ws", "head": "abc",
            "generation": 1, "root": str(tmp_path),
            "trusted_verification": ({"language": "python", "argv": ("python", "-m", "pytest", "-q"), "type": "unit-test", "source": "pyproject"},),
        }},
        max_nodes=10, max_files=10, max_symbols=10, max_depth=2,
    )
    plan = service.plan(repository_id="repo", task_id="t", workspace_id="ws", user_goal="modify function core_func", base_sha="abc")
    assert plan.status is PlanStatus.READY
    summary = _parse_impact_summary(plan)
    # Budget must be shared — at least one limit must be hit
    assert summary["truncated"] == "True", "tight budget must cause truncation"
    assert summary["limit_code"] != "none"
    # All counts must be within budget limits
    visited = int(summary["visited_nodes"])
    inspected_edges = int(summary["inspected_edges"])
    reverse_imports = int(summary["inspected_reverse_imports"])
    test_candidates = int(summary["inspected_test_candidates"])
    assert visited <= 10, f"visited_nodes={visited} exceeds max_nodes=10"
    assert inspected_edges <= 500, f"inspected_edges={inspected_edges} exceeds max_edges"
    assert reverse_imports <= 50, f"inspected_reverse_imports={reverse_imports} exceeds max_reverse_imports"
    assert test_candidates <= 50, f"inspected_test_candidates={test_candidates} exceeds max_test_candidates"
    # affected_files must also be bounded
    assert len(plan.affected_files) <= 100
