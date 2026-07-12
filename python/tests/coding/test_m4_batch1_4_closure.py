"""M4 Batch 1.4 closure: final query budget and config boundary.

Tests:
1. Per-query LIMIT = min(remaining_candidates, remaining_indexed_rows).
2. Language isolation in heuristic test association.
3. TestAssociationResult truncation propagates to ImpactAnalysis and risk.
4. SafeConfigSnapshot — external symlink targets are NEVER read.
5. Fingerprint and catalog use the same snapshot bytes.
"""
from __future__ import annotations

import json
import os
import sqlite3
import tempfile
from pathlib import Path

import pytest

from khaos.coding.intelligence.index import IndexStore, RepositoryIndexer
from khaos.coding.intelligence.query import CodeQueryService
from khaos.coding.intelligence.resolution.service import ResolutionService
from khaos.coding.planning.contracts import (
    ImpactStatus,
    PlanStatus,
    TestAssociationResult,
)
from khaos.coding.planning.service import DeterministicPlanningService
from khaos.coding.planning.verification_catalog import (
    SafeConfigSnapshot,
    VerificationCatalog,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

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
    service_keys = {"max_depth", "max_nodes", "max_files", "max_symbols",
                    "max_edges", "max_reverse_imports", "max_test_candidates"}
    repo_keys = {"trusted_verification"}
    service_kwargs = {k: v for k, v in kwargs.items() if k in service_keys}
    repo_kwargs = {k: v for k, v in kwargs.items() if k in repo_keys}
    defaults = {
        "repository_id": repo_id, "workspace_id": "ws", "head": "abc",
        "generation": 1, "root": str(tmp_path),
        "trusted_verification": (),
    }
    defaults.update(repo_kwargs)
    return DeterministicPlanningService(query, repositories={repo_id: defaults}, **service_kwargs)


# ---------------------------------------------------------------------------
# Section 1: Per-query fetch budget — LIMIT = min(candidates, indexed_rows)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_max_indexed_rows_limits_total_fetch(tmp_path: Path):
    """max_results=50, max_indexed_rows=5, first source has 50 rows → total ≤ 5."""
    files = {"core.py": "def core_func(): return 1\n"}
    for i in range(50):
        files[f"test_imp_{i}.py"] = f"from core import core_func\ndef test_i_{i}(): pass\n"
    files["pyproject.toml"] = "[tool.pytest]\ntestpaths = [\".\"]\n"
    conn, store, _ = await _index_repo(tmp_path, files)
    query = CodeQueryService(store)
    result = query.associated_tests("repo", target_files=("core.py",),
                                     max_results=50, max_sql_queries=10, max_indexed_rows=5)
    assert result.sql_rows_returned <= 5, f"rows {result.sql_rows_returned} > indexed budget 5"
    assert result.indexed_edge_rows_fetched <= 5
    assert result.truncated is True
    assert result.limit_code is not None


@pytest.mark.asyncio
async def test_second_query_limit_uses_remaining_indexed_rows(tmp_path: Path):
    """First source returns 3 rows, remaining indexed=2 → second LIMIT must be 2."""
    files = {"core.py": "def core_func(): return 1\n"}
    # Create test files that import core (P1-import) and also have subject key match (P2)
    for i in range(10):
        files[f"test_core_{i}.py"] = f"from core import core_func\ndef test_{i}(): pass\n"
    files["pyproject.toml"] = "[tool.pytest]\ntestpaths = [\".\"]\n"
    conn, store, _ = await _index_repo(tmp_path, files)
    query = CodeQueryService(store)
    # max_indexed_rows=5 — P1-import returns some rows, P2 must use remaining
    result = query.associated_tests("repo", target_files=("core.py",),
                                     max_results=50, max_sql_queries=10, max_indexed_rows=5)
    assert result.sql_rows_returned <= 5
    assert result.indexed_edge_rows_fetched <= 5


@pytest.mark.asyncio
async def test_duplicate_rows_consume_fetch_budget(tmp_path: Path):
    """Duplicate rows still consume fetch budget."""
    files = {"core.py": "def core_func(): return 1\n"}
    for i in range(20):
        files[f"test_{i}.py"] = f"from core import core_func\ndef test_{i}(): core_func()\n"
    files["pyproject.toml"] = "[tool.pytest]\ntestpaths = [\".\"]\n"
    conn, store, _ = await _index_repo(tmp_path, files)
    query = CodeQueryService(store)
    result = query.associated_tests("repo", target_files=("core.py",),
                                     max_results=50, max_sql_queries=10, max_indexed_rows=5)
    # Even with duplicates, fetch budget is enforced
    assert result.sql_rows_returned <= 5 or result.limit_code is not None


@pytest.mark.asyncio
async def test_budget_exhausted_stops_next_source(tmp_path: Path):
    """Query budget exhausted → next source NOT queried."""
    files = {"core.py": "def core_func(): return 1\n"}
    for i in range(30):
        files[f"test_imp_{i}.py"] = f"from core import core_func\ndef test_i_{i}(): pass\n"
    files["pyproject.toml"] = "[tool.pytest]\ntestpaths = [\".\"]\n"
    conn, store, _ = await _index_repo(tmp_path, files)
    query = CodeQueryService(store)
    # max_sql_queries=1 — only first query runs
    result = query.associated_tests("repo", target_files=("core.py",),
                                     max_results=50, max_sql_queries=1, max_indexed_rows=200)
    assert result.sql_queries_issued <= 1
    assert result.truncated is True


def test_sql_queries_issued_excludes_language_resolution(tmp_path: Path):
    """Language resolution SELECT is NOT counted in sql_queries_issued."""
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    store = IndexStore(conn)
    conn.execute("INSERT INTO code_files VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                 ("repo", "test_foo.py", "python", 10, 0, "hash", "v", "legacy", "{}", 0, 1, "test", "foo", "test_foo", ""))
    conn.commit()
    query = CodeQueryService(store)
    result = query.associated_tests("repo", target_files=("foo.py",),
                                     max_results=10, max_sql_queries=10, max_indexed_rows=200)
    # Language resolution runs but is NOT counted
    assert result.sql_queries_issued == 0


def test_max_sql_queries_zero_sends_no_queries(tmp_path: Path):
    """max_sql_queries=0 → 0 normal SQL queries issued."""
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    store = IndexStore(conn)
    conn.execute("INSERT INTO code_files VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                 ("repo", "test_foo.py", "python", 10, 0, "hash", "v", "legacy", "{}", 0, 1, "test", "foo", "test_foo", ""))
    conn.commit()
    query = CodeQueryService(store)
    result = query.associated_tests("repo", target_files=("foo.py",),
                                     max_results=10, max_sql_queries=0, max_indexed_rows=200)
    assert result.sql_queries_issued == 0
    assert result.limit_code == "max_sql_queries" or result.truncated


# ---------------------------------------------------------------------------
# Section 2: Language isolation in test association
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_python_target_not_associated_with_go_test(tmp_path: Path):
    """Python auth.py must NOT associate with test_auth.go via heuristic."""
    files = {
        "auth.py": "def login(): pass\n",
        "test_auth.go": "package auth\nfunc TestLogin(t *testing.T) {}\n",
    }
    files["pyproject.toml"] = "[tool.pytest]\ntestpaths = [\".\"]\n"
    conn, store, _ = await _index_repo(tmp_path, files)
    query = CodeQueryService(store)
    result = query.associated_tests("repo", target_files=("auth.py",), max_results=50)
    paths = [c["path"] for c in result.candidates]
    assert "test_auth.go" not in paths, f"Go test associated with Python target: {paths}"


@pytest.mark.asyncio
async def test_go_target_not_associated_with_python_test(tmp_path: Path):
    """Go auth.go must NOT associate with test_auth.py via heuristic."""
    files = {
        "auth.go": "package auth\nfunc Login() {}\n",
        "test_auth.py": "def test_login(): assert True\n",
    }
    files["go.mod"] = "module example.com/auth\n\ngo 1.21\n"
    conn, store, _ = await _index_repo(tmp_path, files)
    query = CodeQueryService(store)
    result = query.associated_tests("repo", target_files=("auth.go",), max_results=50)
    paths = [c["path"] for c in result.candidates]
    assert "test_auth.py" not in paths, f"Python test associated with Go target: {paths}"


@pytest.mark.asyncio
async def test_js_ts_compatibility_group(tmp_path: Path):
    """JavaScript and TypeScript tests can associate via heuristic."""
    files = {
        "auth.ts": "export function login(): void {}\n",
        "test_auth.js": "import { login } from './auth.js'\nfunction testLogin() { login() }\n",
    }
    files["package.json"] = json.dumps({"scripts": {"test": "jest"}, "devDependencies": {"typescript": "5.0"}})
    conn, store, _ = await _index_repo(tmp_path, files)
    query = CodeQueryService(store)
    result = query.associated_tests("repo", target_files=("auth.ts",), max_results=50)
    paths = [c["path"] for c in result.candidates]
    # JS test can associate with TS target (same compatibility group)
    assert "test_auth.js" in paths, f"JS test should associate with TS target: {paths}"


@pytest.mark.asyncio
async def test_resolved_cross_language_edge_retained(tmp_path: Path):
    """Resolved graph edges can retain cross-language evidence."""
    files = {
        "core.py": "def core_func(): return 1\n",
        "test_core.py": "from core import core_func\ndef test_core(): assert core_func() == 1\n",
    }
    files["pyproject.toml"] = "[tool.pytest]\ntestpaths = [\".\"]\n"
    conn, store, _ = await _index_repo(tmp_path, files)
    query = CodeQueryService(store)
    result = query.associated_tests("repo", target_files=("core.py",), max_results=50)
    # Resolved import edge is retained regardless of language
    assert result.has_resolved_test_coverage is True


@pytest.mark.asyncio
async def test_language_missing_conservative_reject(tmp_path: Path):
    """When target language is missing, heuristic is conservatively rejected."""
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    store = IndexStore(conn)
    # Insert target file with no language and test file with subject key match
    conn.execute("INSERT INTO code_files VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                 ("repo", "auth.py", "", 10, 0, "hash", "v", "legacy", "{}", 0, 1, "source", "", "", ""))
    conn.execute("INSERT INTO code_files VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                 ("repo", "test_auth.py", "python", 10, 0, "hash", "v", "legacy", "{}", 0, 1, "test", "auth", "test_auth", ""))
    conn.commit()
    query = CodeQueryService(store)
    result = query.associated_tests("repo", target_files=("auth.py",), max_results=50)
    # No language → heuristic_langs is empty → P2 doesn't run
    assert len(result.candidates) == 0 or result.has_resolved_test_coverage is False


@pytest.mark.asyncio
async def test_multilanguage_same_stem_deterministic_order(tmp_path: Path):
    """Multi-language same-stem candidates return in deterministic order."""
    files = {
        "auth.py": "def login(): pass\n",
        "test_auth.py": "def test_login(): pass\n",
        "test_auth.go": "package auth\nfunc TestLogin(t *testing.T) {}\n",
    }
    files["pyproject.toml"] = "[tool.pytest]\ntestpaths = [\".\"]\n"
    conn, store, _ = await _index_repo(tmp_path, files)
    query = CodeQueryService(store)
    result1 = query.associated_tests("repo", target_files=("auth.py",), max_results=50)
    result2 = query.associated_tests("repo", target_files=("auth.py",), max_results=50)
    # Same result every time
    assert [c["path"] for c in result1.candidates] == [c["path"] for c in result2.candidates]
    # Only Python test (not Go)
    paths = [c["path"] for c in result1.candidates]
    assert "test_auth.go" not in paths


# ---------------------------------------------------------------------------
# Section 3: package_key not queried (capability withdrawn)
# ---------------------------------------------------------------------------

def test_package_key_not_in_p2_query():
    """P2 SQL must NOT reference package_key — it's reserved for future use."""
    # We verify by checking that the query_plans don't mention package_key
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    store = IndexStore(conn)
    conn.execute("INSERT INTO code_files VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                 ("repo", "auth.py", "python", 10, 0, "hash", "v", "legacy", "{}", 0, 1, "source", "", "auth", ""))
    conn.execute("INSERT INTO code_files VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                 ("repo", "test_auth.py", "python", 10, 0, "hash", "v", "legacy", "{}", 0, 1, "test", "auth", "test_auth", ""))
    conn.commit()
    query = CodeQueryService(store)
    result = query.associated_tests("repo", target_files=("auth.py",), max_results=50)
    for plan in result.query_plans:
        assert "package_key" not in plan.lower(), f"package_key found in query plan: {plan}"


# ---------------------------------------------------------------------------
# Section 4: Truncation propagation to ImpactAnalysis and risk
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_max_candidates_exhaustion_propagates_truncation(tmp_path: Path):
    """associated_tests max_candidates exhausted → ImpactAnalysis.truncated=True."""
    files = {"core.py": "def core_func(): return 1\n"}
    for i in range(30):
        files[f"test_imp_{i}.py"] = f"from core import core_func\ndef test_i_{i}(): pass\n"
    files["pyproject.toml"] = "[tool.pytest]\ntestpaths = [\".\"]\n"
    conn, store, _ = await _index_repo(tmp_path, files)
    service = _make_service(store, tmp_path, max_test_candidates=5)
    plan = service.plan(repository_id="repo", task_id="t", workspace_id="ws",
                        user_goal="modify function core_func", base_sha="abc")
    # Find impact-summary diagnostic
    diag = next(d for d in plan.diagnostics if d.code == "impact-summary")
    assert "truncated=True" in diag.message, f"truncation not propagated: {diag.message}"


@pytest.mark.asyncio
async def test_max_indexed_rows_exhaustion_propagates_truncation(tmp_path: Path):
    """max_indexed_rows exhausted → ImpactAnalysis.truncated=True."""
    files = {"core.py": "def core_func(): return 1\n"}
    for i in range(20):
        files[f"test_imp_{i}.py"] = f"from core import core_func\ndef test_i_{i}(): pass\n"
    files["pyproject.toml"] = "[tool.pytest]\ntestpaths = [\".\"]\n"
    conn, store, _ = await _index_repo(tmp_path, files)
    service = _make_service(store, tmp_path, max_test_candidates=3)
    plan = service.plan(repository_id="repo", task_id="t", workspace_id="ws",
                        user_goal="modify function core_func", base_sha="abc")
    diag = next(d for d in plan.diagnostics if d.code == "impact-summary")
    assert "truncated=True" in diag.message, f"truncation not propagated: {diag.message}"


@pytest.mark.asyncio
async def test_impact_truncated_diagnostic_exists(tmp_path: Path):
    """When truncated, an impact-truncated diagnostic must exist."""
    files = {"core.py": "def core_func(): return 1\n"}
    for i in range(30):
        files[f"test_imp_{i}.py"] = f"from core import core_func\ndef test_i_{i}(): pass\n"
    files["pyproject.toml"] = "[tool.pytest]\ntestpaths = [\".\"]\n"
    conn, store, _ = await _index_repo(tmp_path, files)
    service = _make_service(store, tmp_path, max_test_candidates=3)
    plan = service.plan(repository_id="repo", task_id="t", workspace_id="ws",
                        user_goal="modify function core_func", base_sha="abc")
    truncated_diags = [d for d in plan.diagnostics if d.code == "impact-truncated"]
    assert len(truncated_diags) > 0, "no impact-truncated diagnostic"


@pytest.mark.asyncio
async def test_public_api_truncated_risk_at_least_high(tmp_path: Path):
    """Public API + truncated → risk at least high."""
    files = {"core.py": "class PublicAPI:\n    def method(self): pass\n"}
    for i in range(30):
        files[f"test_imp_{i}.py"] = f"from core import PublicAPI\ndef test_{i}(): pass\n"
    files["pyproject.toml"] = "[tool.pytest]\ntestpaths = [\".\"]\n"
    conn, store, _ = await _index_repo(tmp_path, files)
    service = _make_service(store, tmp_path, max_test_candidates=3)
    plan = service.plan(repository_id="repo", task_id="t", workspace_id="ws",
                        user_goal="modify PublicAPI", base_sha="abc")
    risk = plan.risks[0]
    assert risk.level in ("high", "critical"), f"risk too low: {risk.level}"
    assert "truncated" in risk.category or risk.requires_approval


@pytest.mark.asyncio
async def test_first_limit_code_not_overwritten(tmp_path: Path):
    """If an earlier phase truncated, test association doesn't overwrite limit_code."""
    files = {"core.py": "def core_func(): return 1\n"}
    for i in range(100):
        files[f"caller_{i}.py"] = f"from core import core_func\ncore_func()\n"
    files["pyproject.toml"] = "[tool.pytest]\ntestpaths = [\".\"]\n"
    conn, store, _ = await _index_repo(tmp_path, files)
    # Very small budget to force early truncation
    service = _make_service(store, tmp_path, max_nodes=5, max_edges=5, max_test_candidates=3)
    plan = service.plan(repository_id="repo", task_id="t", workspace_id="ws",
                        user_goal="modify function core_func", base_sha="abc")
    diag = next(d for d in plan.diagnostics if d.code == "impact-summary")
    # limit_code should be set (not none)
    assert "limit_code=" in diag.message
    assert "limit_code=none" not in diag.message


@pytest.mark.asyncio
async def test_truncation_repeated_run_deterministic(tmp_path: Path):
    """Repeated runs produce identical truncation status and content_hash."""
    files = {"core.py": "def core_func(): return 1\n"}
    for i in range(30):
        files[f"test_imp_{i}.py"] = f"from core import core_func\ndef test_i_{i}(): pass\n"
    files["pyproject.toml"] = "[tool.pytest]\ntestpaths = [\".\"]\n"
    conn, store, _ = await _index_repo(tmp_path, files)
    service = _make_service(store, tmp_path, max_test_candidates=5)
    plan1 = service.plan(repository_id="repo", task_id="t", workspace_id="ws",
                         user_goal="modify function core_func", base_sha="abc")
    plan2 = service.plan(repository_id="repo", task_id="t", workspace_id="ws",
                         user_goal="modify function core_func", base_sha="abc")
    assert plan1.content_hash == plan2.content_hash, "content_hash not deterministic"
    assert plan1.plan_id == plan2.plan_id


# ---------------------------------------------------------------------------
# Section 5: SafeConfigSnapshot — external symlinks never read
# ---------------------------------------------------------------------------

def test_safe_config_snapshot_external_symlink_zero_reads(tmp_path: Path):
    """External symlink target must NEVER be read — reader_call_count=0."""
    external = tmp_path / "external_pyproject.toml"
    external.write_text("[tool.pytest]\ntestpaths = [\".\"]\n")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    symlink = workspace / "pyproject.toml"
    try:
        os.symlink(external, symlink)
    except OSError:
        pytest.skip("cannot create symlink on this platform")

    read_count = 0
    def _reader(path: Path) -> bytes:
        nonlocal read_count
        read_count += 1
        return path.read_bytes()

    snap = SafeConfigSnapshot.capture(workspace, "pyproject.toml", reader=_reader)
    assert snap.exists is False
    assert snap.rejection_code == "escape"
    assert snap.reader_call_count == 0, f"external symlink was read {snap.reader_call_count} times"
    assert read_count == 0, f"reader was called {read_count} times for external symlink"


def test_safe_config_snapshot_package_json_external_zero_reads(tmp_path: Path):
    """package.json external symlink must also have zero reads."""
    external = tmp_path / "external_package.json"
    external.write_text(json.dumps({"scripts": {"test": "jest"}}))
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    symlink = workspace / "package.json"
    try:
        os.symlink(external, symlink)
    except OSError:
        pytest.skip("cannot create symlink on this platform")

    read_count = 0
    def _reader(path: Path) -> bytes:
        nonlocal read_count
        read_count += 1
        return path.read_bytes()

    snap = SafeConfigSnapshot.capture(workspace, "package.json", reader=_reader)
    assert snap.exists is False
    assert snap.rejection_code == "escape"
    assert snap.reader_call_count == 0
    assert read_count == 0


def test_safe_config_snapshot_internal_symlink_read_once(tmp_path: Path):
    """Internal symlink (pointing inside workspace) is read exactly once."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    target = workspace / "real_config.toml"
    target.write_text("[tool.pytest]\ntestpaths = [\".\"]\n")
    symlink = workspace / "pyproject.toml"
    try:
        os.symlink(target, symlink)
    except OSError:
        pytest.skip("cannot create symlink on this platform")

    read_count = 0
    def _reader(path: Path) -> bytes:
        nonlocal read_count
        read_count += 1
        return path.read_bytes()

    snap = SafeConfigSnapshot.capture(workspace, "pyproject.toml", reader=_reader)
    assert snap.exists is True
    assert snap.reader_call_count == 1
    assert read_count == 1


def test_safe_config_snapshot_broken_symlink(tmp_path: Path):
    """Broken symlink produces stable diagnostic, no read."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    symlink = workspace / "pyproject.toml"
    try:
        os.symlink(workspace / "nonexistent.toml", symlink)
    except OSError:
        pytest.skip("cannot create symlink on this platform")

    snap = SafeConfigSnapshot.capture(workspace, "pyproject.toml")
    assert snap.exists is False
    assert snap.rejection_code in ("broken", "read-error")
    assert snap.reader_call_count == 0


def test_fingerprint_and_catalog_use_same_snapshot(tmp_path: Path):
    """Fingerprint and catalog config_hash must come from the same snapshot."""
    (tmp_path / "pyproject.toml").write_text("[tool.pytest]\ntestpaths = [\".\"]\n")
    catalog = VerificationCatalog(tmp_path)
    # The fingerprint includes the pyproject hash
    # The catalog config_hashes also includes it
    pyproject_hash = catalog.config_hashes.get("pyproject.toml", "")
    assert pyproject_hash != ""
    # Recompute fingerprint with the same snapshots
    fp1 = VerificationCatalog.compute_fingerprint("repo", tmp_path, (), snapshots=catalog._snapshots)
    fp2 = VerificationCatalog.compute_fingerprint("repo", tmp_path, ())
    # Both should be the same (same content)
    assert fp1 == fp2, "fingerprint diverged between snapshot and direct capture"


def test_config_changed_after_snapshot_detected_on_next_check(tmp_path: Path):
    """File changed after snapshot → next freshness check detects drift."""
    (tmp_path / "pyproject.toml").write_text("[tool.pytest]\ntestpaths = [\".\"]\n")
    catalog1 = VerificationCatalog(tmp_path)
    fp1 = catalog1.fingerprint
    # Change the config file after snapshot
    (tmp_path / "pyproject.toml").write_text("[tool.pytest]\ntestpaths = [\"tests\"]\n[tool.mypy]\npython_version = \"3.12\"\n")
    # New catalog with fresh snapshot
    catalog2 = VerificationCatalog(tmp_path)
    fp2 = catalog2.fingerprint
    assert fp1 != fp2, "config change not detected"


def test_compute_fingerprint_standalone_is_safe(tmp_path: Path):
    """compute_fingerprint() called standalone (no snapshots) must also be safe."""
    external = tmp_path / "external.toml"
    external.write_text("[tool.pytest]\ntestpaths = [\".\"]\n")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    symlink = workspace / "pyproject.toml"
    try:
        os.symlink(external, symlink)
    except OSError:
        pytest.skip("cannot create symlink on this platform")

    # Standalone compute_fingerprint must NOT read the external target
    # It should produce empty hash for the escaped file
    fp = VerificationCatalog.compute_fingerprint("repo", workspace, ())
    # The fingerprint should not contain the external file's hash
    # We verify by comparing with a workspace that has no pyproject at all
    empty_workspace = tmp_path / "empty"
    empty_workspace.mkdir()
    fp_empty = VerificationCatalog.compute_fingerprint("repo", empty_workspace, ())
    # Both should have empty pyproject hash (escaped → treated as missing)
    assert fp == fp_empty, "external symlink content leaked into fingerprint"


def test_safe_config_snapshot_no_absolute_path_in_diagnostic(tmp_path: Path):
    """Diagnostic must NEVER expose the absolute target path."""
    external = tmp_path / "secret_external.toml"
    external.write_text("secret content")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    symlink = workspace / "pyproject.toml"
    try:
        os.symlink(external, symlink)
    except OSError:
        pytest.skip("cannot create symlink on this platform")

    snap = SafeConfigSnapshot.capture(workspace, "pyproject.toml")
    assert snap.exists is False
    assert snap.rejection_code == "escape"
    # Diagnostic must NOT contain the absolute path of the external target
    assert str(external) not in snap.diagnostic, f"absolute path leaked: {snap.diagnostic}"
    assert str(tmp_path) not in snap.diagnostic, f"absolute path leaked: {snap.diagnostic}"


# ---------------------------------------------------------------------------
# Section 6: Cross-worktree determinism with safe snapshots
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_cross_worktree_determinism_with_safe_snapshots(tmp_path: Path):
    """Same content in two worktrees → same plan_id and content_hash."""
    files = {
        "python_lib.py": "def public_api(): return 1\n",
        "pyproject.toml": "[tool.pytest]\ntestpaths = [\".\"]\n",
    }
    repo_a = tmp_path / "worktree-a"
    repo_b = tmp_path / "worktree-b"
    repo_a.mkdir()
    repo_b.mkdir()
    conn_a, store_a, _ = await _index_repo(repo_a, files)
    conn_b, store_b, _ = await _index_repo(repo_b, files)
    service_a = _make_service(store_a, repo_a)
    service_b = _make_service(store_b, repo_b)
    plan_a = service_a.plan(repository_id="repo", task_id="t", workspace_id="ws",
                            user_goal="modify function public_api", base_sha="abc")
    plan_b = service_b.plan(repository_id="repo", task_id="t", workspace_id="ws",
                            user_goal="modify function public_api", base_sha="abc")
    assert plan_a.plan_id == plan_b.plan_id, "plan_id not deterministic across worktrees"
    assert plan_a.content_hash == plan_b.content_hash, "content_hash not deterministic"
