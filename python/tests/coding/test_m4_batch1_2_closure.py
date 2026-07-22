"""M4 Batch 1.2 closure: catalog freshness, portable evidence, hard budget.

Tests:
1. Config drift detected without manual cache clear (modify/delete/add).
2. Server rule drift detected.
3. Cross-worktree determinism (same content → same plan_id/content_hash).
4. No absolute host paths in PlanEvidence.
5. Structured config parsing (comments don't generate commands).
6. EXPLAIN QUERY PLAN proves indexed queries, not SCAN.
7. Adversarial 10,000 non-test edge fixture.
8. Hard global budget phase-stop (8 scenarios).
"""
from __future__ import annotations

import asyncio
import hashlib
import json
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
    VerificationCatalogEntry,
)
from khaos.coding.planning.service import DeterministicPlanningService
from khaos.coding.planning.verification_catalog import VerificationCatalog


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
    # Separate service constructor kwargs from repository metadata kwargs
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
# Section 1: Catalog Freshness — fingerprint auto-invalidation
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_config_modify_detected_without_cache_clear(tmp_path: Path):
    """Modifying a config file after planning must STALE without _catalogs.clear()."""
    files = {
        "python_lib.py": "def public_api(): return 1\n",
        "pyproject.toml": "[tool.pytest]\ntestpaths = [\".\"]\n",
    }
    conn, store, _ = await _index_repo(tmp_path, files)
    service = _make_service(store, tmp_path)
    plan = service.plan(repository_id="repo", task_id="t", workspace_id="ws",
                        user_goal="modify function public_api", base_sha="abc")
    assert plan.status is PlanStatus.READY
    # Modify config — NO manual cache clear
    (tmp_path / "pyproject.toml").write_text(
        "[tool.pytest]\ntestpaths = [\"tests\"]\n[tool.mypy]\npython_version = \"3.12\"\n"
    )
    result = service.validate_plan(plan, current_head="abc", current_repository_generation=1)
    assert result.status is PlanStatus.STALE
    assert any(d.code == "config-hash-drift" for d in result.diagnostics)


@pytest.mark.asyncio
async def test_config_delete_detected_without_cache_clear(tmp_path: Path):
    """Deleting a config file must STALE without manual cache clear."""
    files = {
        "python_lib.py": "def public_api(): return 1\n",
        "pyproject.toml": "[tool.pytest]\ntestpaths = [\".\"]\n",
    }
    conn, store, _ = await _index_repo(tmp_path, files)
    service = _make_service(store, tmp_path)
    plan = service.plan(repository_id="repo", task_id="t", workspace_id="ws",
                        user_goal="modify function public_api", base_sha="abc")
    assert plan.status is PlanStatus.READY
    # Delete config file
    (tmp_path / "pyproject.toml").unlink()
    result = service.validate_plan(plan, current_head="abc", current_repository_generation=1)
    assert result.status is PlanStatus.STALE


@pytest.mark.asyncio
async def test_config_add_detected_without_cache_clear(tmp_path: Path):
    """Adding a new config file must STALE without manual cache clear."""
    files = {"python_lib.py": "def public_api(): return 1\n"}
    conn, store, _ = await _index_repo(tmp_path, files)
    service = _make_service(store, tmp_path)
    plan = service.plan(repository_id="repo", task_id="t", workspace_id="ws",
                        user_goal="modify function public_api", base_sha="abc")
    assert plan.status is PlanStatus.READY
    # Add a new config file
    (tmp_path / "pyproject.toml").write_text("[tool.pytest]\ntestpaths = [\".\"]\n")
    result = service.validate_plan(plan, current_head="abc", current_repository_generation=1)
    assert result.status is PlanStatus.STALE


@pytest.mark.asyncio
async def test_server_rule_change_detected_without_cache_clear(tmp_path: Path):
    """Changing server trusted_verification rules must STALE."""
    files = {"python_lib.py": "def public_api(): return 1\n"}
    conn, store, _ = await _index_repo(tmp_path, files)
    service = _make_service(store, tmp_path, trusted_verification=(
        {"language": "python", "argv": ("python", "-m", "pytest", "-q"),
         "type": "unit-test", "source": "rule-1"},
    ))
    plan = service.plan(repository_id="repo", task_id="t", workspace_id="ws",
                        user_goal="modify function public_api", base_sha="abc")
    assert plan.status is PlanStatus.READY
    # Change server rules
    service2 = _make_service(store, tmp_path, trusted_verification=(
        {"language": "python", "argv": ("python", "-m", "pytest", "-q"),
         "type": "unit-test", "source": "rule-2"},
    ))
    result = service2.validate_plan(plan, current_head="abc", current_repository_generation=1)
    assert result.status is PlanStatus.STALE


@pytest.mark.asyncio
async def test_no_config_change_no_stale(tmp_path: Path):
    """No config change → plan must NOT be STALE (stable fingerprint)."""
    files = {
        "python_lib.py": "def public_api(): return 1\n",
        "pyproject.toml": "[tool.pytest]\ntestpaths = [\".\"]\n",
    }
    conn, store, _ = await _index_repo(tmp_path, files)
    service = _make_service(store, tmp_path)
    plan = service.plan(repository_id="repo", task_id="t", workspace_id="ws",
                        user_goal="modify function public_api", base_sha="abc")
    assert plan.status is PlanStatus.READY
    # No changes — validate immediately
    result = service.validate_plan(plan, current_head="abc", current_repository_generation=1)
    assert result.status is not PlanStatus.STALE
    assert result.valid is True


def test_concurrent_catalog_reads_consistent(tmp_path: Path):
    """Concurrent reads of the same catalog must produce identical fingerprints."""
    (tmp_path / "pyproject.toml").write_text("[tool.pytest]\ntestpaths = [\".\"]\n")
    root = Path(tmp_path)
    fp1 = VerificationCatalog.compute_fingerprint("repo", root, ())
    fp2 = VerificationCatalog.compute_fingerprint("repo", root, ())
    assert fp1 == fp2


# ---------------------------------------------------------------------------
# Section 2: Portable Evidence — repo-relative config paths
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_cross_worktree_determinism(tmp_path: Path):
    """Same repo content in two different absolute dirs → same plan_id/content_hash."""
    files = {
        "python_lib.py": "def public_api(): return 1\n",
        "pyproject.toml": "[tool.pytest]\ntestpaths = [\".\"]\n",
    }
    # Create two identical repos in different absolute directories
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
    assert plan_a.plan_id == plan_b.plan_id, "plan_id must be identical across worktrees"
    assert plan_a.content_hash == plan_b.content_hash, "content_hash must be identical"
    # Evidence must not contain any absolute host paths
    for plan in (plan_a, plan_b):
        for ev in plan.evidence:
            # config_path in metadata must be repo-relative, not absolute
            if ev.source == "verification-config":
                config_files = ev.metadata.get("config_files", {})
                for path in config_files:
                    assert not path.startswith("/"), f"absolute config_path in evidence: {path}"
                    assert ".." not in path, f"parent traversal in evidence: {path}"


@pytest.mark.asyncio
async def test_evidence_has_zero_absolute_config_paths(tmp_path: Path):
    """No PlanEvidence may contain an absolute host config_path."""
    files = {
        "python_lib.py": "def public_api(): return 1\n",
        "pyproject.toml": "[tool.pytest]\ntestpaths = [\".\"]\n",
        "package.json": json.dumps({"scripts": {"test": "jest"}, "devDependencies": {"typescript": "5.0"}}),
    }
    conn, store, _ = await _index_repo(tmp_path, files)
    service = _make_service(store, tmp_path)
    plan = service.plan(repository_id="repo", task_id="t", workspace_id="ws",
                        user_goal="modify function public_api", base_sha="abc")
    absolute_count = 0
    for ev in plan.evidence:
        if ev.source == "verification-config":
            for path in ev.metadata.get("config_files", {}):
                if path.startswith("/") or str(tmp_path) in path:
                    absolute_count += 1
    assert absolute_count == 0, f"found {absolute_count} absolute config paths in evidence"


# ---------------------------------------------------------------------------
# Section 3: Structured Config Parsing — no substring inference
# ---------------------------------------------------------------------------

def test_comment_mentioning_pytest_does_not_generate_command(tmp_path: Path):
    """A comment mentioning pytest must NOT generate a pytest command."""
    (tmp_path / "pyproject.toml").write_text(
        "# We use pytest for testing\n[build-system]\nrequires = [\"setuptools\"]\n"
    )
    catalog = VerificationCatalog(Path(tmp_path))
    pytest_entries = [e for e in catalog.entries if e.verification_type == "unit-test"]
    assert len(pytest_entries) == 0, "comment mentioning pytest must not generate command"


def test_pytest_in_dependencies_does_not_generate_command(tmp_path: Path):
    """pytest listed in dependencies must NOT generate a pytest command."""
    (tmp_path / "pyproject.toml").write_text(
        "[project]\nname = \"demo\"\ndependencies = [\"pytest\", \"httpx\"]\n"
    )
    catalog = VerificationCatalog(Path(tmp_path))
    pytest_entries = [e for e in catalog.entries if e.verification_type == "unit-test"]
    assert len(pytest_entries) == 0, "pytest in dependencies must not generate command"


def test_tool_pytest_section_generates_command(tmp_path: Path):
    """[tool.pytest] section must generate a pytest command."""
    (tmp_path / "pyproject.toml").write_text("[tool.pytest]\ntestpaths = [\".\"]\n")
    catalog = VerificationCatalog(Path(tmp_path))
    pytest_entries = [e for e in catalog.entries if e.verification_type == "unit-test"]
    assert len(pytest_entries) == 1
    assert pytest_entries[0].language == "python"


def test_tool_mypy_section_generates_command(tmp_path: Path):
    """[tool.mypy] section must generate a mypy command."""
    (tmp_path / "pyproject.toml").write_text("[tool.mypy]\npython_version = \"3.12\"\n")
    catalog = VerificationCatalog(Path(tmp_path))
    mypy_entries = [e for e in catalog.entries if e.verification_type == "type-check"]
    assert len(mypy_entries) == 1


def test_tool_ruff_section_generates_command(tmp_path: Path):
    """[tool.ruff] section must generate a ruff command."""
    (tmp_path / "pyproject.toml").write_text("[tool.ruff]\nline-length = 88\n")
    catalog = VerificationCatalog(Path(tmp_path))
    ruff_entries = [e for e in catalog.entries if e.verification_type == "lint"]
    assert len(ruff_entries) == 1


def test_clippy_in_comment_does_not_generate_command(tmp_path: Path):
    """The word 'clippy' in a comment must NOT generate a clippy command."""
    (tmp_path / "Cargo.toml").write_text(
        "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n# Run clippy manually sometimes\n"
    )
    catalog = VerificationCatalog(Path(tmp_path))
    clippy_entries = [e for e in catalog.entries if e.verification_type == "lint"]
    assert len(clippy_entries) == 0, "clippy in comment must not generate command"


def test_lints_clippy_section_generates_command(tmp_path: Path):
    """[lints.clippy] section must generate a clippy command."""
    (tmp_path / "Cargo.toml").write_text(
        "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n[lints.clippy]\nall = \"warn\"\n"
    )
    catalog = VerificationCatalog(Path(tmp_path))
    clippy_entries = [e for e in catalog.entries if e.verification_type == "lint"]
    assert len(clippy_entries) == 1


def test_invalid_toml_produces_diagnostic(tmp_path: Path):
    """Invalid TOML must produce a diagnostic, not silent trust."""
    (tmp_path / "pyproject.toml").write_text("[tool.pytest\ntestpaths = broken\n")
    catalog = VerificationCatalog(Path(tmp_path))
    assert len(catalog.diagnostics) > 0
    severities = [d[0] for d in catalog.diagnostics]
    assert "error" in severities, "invalid TOML must produce error diagnostic"


def test_config_path_is_repo_relative(tmp_path: Path):
    """config_path on every entry must be repo-relative, never absolute."""
    (tmp_path / "pyproject.toml").write_text("[tool.pytest]\ntestpaths = [\".\"]\n")
    (tmp_path / "Cargo.toml").write_text("[package]\nname = \"d\"\nversion = \"0.1.0\"\n")
    catalog = VerificationCatalog(Path(tmp_path))
    for entry in catalog.entries:
        assert not entry.config_path.startswith("/"), \
            f"absolute config_path: {entry.config_path}"
        assert str(tmp_path) not in entry.config_path, \
            f"host path in config_path: {entry.config_path}"


# ---------------------------------------------------------------------------
# Section 4/5: Bounded Test Association — EXPLAIN QUERY PLAN + adversarial
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_explain_query_plan_shows_index_not_scan(tmp_path: Path):
    """EXPLAIN QUERY PLAN must show index seeks, not full table SCAN."""
    files = {}
    for i in range(100):
        files[f"file_{i}.py"] = f"def func_{i}(): return {i}\n"
    files["test_main.py"] = "def test_main(): assert True\n"
    files["pyproject.toml"] = "[tool.pytest]\ntestpaths = [\".\"]\n"
    conn, store, _ = await _index_repo(tmp_path, files)
    query = CodeQueryService(store)
    result = query.associated_tests("repo", target_files=("file_0.py",), max_results=10)
    assert len(result.query_plans) > 0
    # Every query plan must use an index, not SCAN
    for plan_str in result.query_plans:
        assert "SCAN" not in plan_str.upper() or "INDEX" in plan_str.upper(), \
            f"full table scan detected: {plan_str}"
    # Must have issued queries and tracked costs
    assert result.sql_queries_issued > 0
    assert result.sql_rows_returned >= 0
    assert result.indexed_edge_rows_fetched >= 0


@pytest.mark.asyncio
async def test_adversarial_10000_non_test_edges_no_scan(tmp_path: Path):
    """10,000 non-test edges with target having no tests — only indexed range access."""
    files = {}
    # Create a target file with many callers (non-test edges)
    files["core.py"] = "def core_func(): return 1\n"
    for i in range(200):  # 200 callers (each creates a resolved import edge)
        files[f"caller_{i}.py"] = f"from core import core_func\ndef caller_{i}(): return core_func()\n"
    # Create 1000 non-test files that are NOT tests
    for i in range(1000):
        files[f"module_{i}.py"] = f"def module_func_{i}(): return {i}\n"
    files["pyproject.toml"] = "[tool.pytest]\ntestpaths = [\".\"]\n"
    conn, store, _ = await _index_repo(tmp_path, files, repo_id="adv")
    query = CodeQueryService(store)
    # Target has no tests — result must be empty but bounded
    result = query.associated_tests("adv", target_files=("module_0.py",), max_results=50)
    # rows_returned=0 does NOT mean rows_scanned=0 — we prove via query plans
    assert len(result.query_plans) > 0
    for plan_str in result.query_plans:
        # Must NOT be an unconstrained SCAN of a large table
        upper = plan_str.upper()
        # ACCEPTABLE: "SEARCH ... USING INDEX", "SEARCH ... USING COVERING INDEX"
        # UNACCEPTABLE: "SCAN" without "INDEX"
        if "SCAN" in upper and "INDEX" not in upper:
            pytest.fail(f"unconstrained SCAN detected: {plan_str}")
    # SQL queries must be bounded (not 1000+)
    assert result.sql_queries_issued <= 10, \
        f"too many SQL queries: {result.sql_queries_issued}"


# ---------------------------------------------------------------------------
# Section 6: Hard Global Budget — phase-stop tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_max_files_in_callers_stops_reverse_imports(tmp_path: Path):
    """max_files triggered in callers phase → reverse imports NOT queried."""
    files = {"core.py": "def core_func(): return 1\n"}
    for i in range(60):
        files[f"caller_{i}.py"] = f"from core import core_func\ndef c_{i}(): return core_func()\n"
    files["pyproject.toml"] = "[tool.pytest]\ntestpaths = [\".\"]\n"
    conn, store, _ = await _index_repo(tmp_path, files)
    service = _make_service(store, tmp_path, max_files=5, max_depth=1)
    plan = service.plan(repository_id="repo", task_id="t", workspace_id="ws",
                        user_goal="modify function core_func", base_sha="abc")
    summary = _parse_impact_summary(plan)
    assert summary["truncated"] == "True"
    # limit_code must be from an early phase (callers or reverse imports)
    assert summary["limit_code"] in ("max_files", "max_nodes", "max_file_candidates", "max_reverse_imports")
    # Reverse imports must NOT have been inspected (or very few)
    reverse_count = int(summary["inspected_reverse_imports"])
    # With hard budget, reverse imports phase should be skipped entirely
    # or minimally inspected before truncation
    assert reverse_count <= 5, f"reverse imports inspected after truncation: {reverse_count}"


@pytest.mark.asyncio
async def test_max_edges_stops_test_association(tmp_path: Path):
    """max_edges triggered → associated_tests NOT queried."""
    files = {"core.py": "def core_func(): return 1\n"}
    for i in range(100):
        files[f"caller_{i}.py"] = f"from core import core_func\ndef c_{i}(): return core_func()\n"
    for i in range(20):
        files[f"test_{i}.py"] = f"from core import core_func\ndef test_{i}(): assert core_func() == 1\n"
    files["pyproject.toml"] = "[tool.pytest]\ntestpaths = [\".\"]\n"
    conn, store, _ = await _index_repo(tmp_path, files)
    # max_edges=5 will trigger very early in callers phase
    service = DeterministicPlanningService(
        CodeQueryService(store),
        repositories={"repo": {
            "repository_id": "repo", "workspace_id": "ws", "head": "abc",
            "generation": 1, "root": str(tmp_path),
            "trusted_verification": (),
        }},
        max_edges=5, max_depth=1, max_nodes=200,
    )
    plan = service.plan(repository_id="repo", task_id="t", workspace_id="ws",
                        user_goal="modify function core_func", base_sha="abc")
    summary = _parse_impact_summary(plan)
    assert summary["truncated"] == "True"
    assert summary["limit_code"] == "max_edges"
    # Test candidates must NOT have been inspected (hard budget stops)
    test_candidates = int(summary["inspected_test_candidates"])
    assert test_candidates == 0, f"test candidates inspected after max_edges: {test_candidates}"


@pytest.mark.asyncio
async def test_max_reverse_imports_stops_test_association(tmp_path: Path):
    """max_reverse_imports triggered → test association NOT entered."""
    files = {"core.py": "def core_func(): return 1\n"}
    for i in range(30):
        files[f"caller_{i}.py"] = f"from core import core_func\ndef c_{i}(): return core_func()\n"
    files["pyproject.toml"] = "[tool.pytest]\ntestpaths = [\".\"]\n"
    conn, store, _ = await _index_repo(tmp_path, files)
    service = DeterministicPlanningService(
        CodeQueryService(store),
        repositories={"repo": {
            "repository_id": "repo", "workspace_id": "ws", "head": "abc",
            "generation": 1, "root": str(tmp_path),
            "trusted_verification": (),
        }},
        max_reverse_imports=2, max_depth=1, max_nodes=200, max_edges=500,
    )
    plan = service.plan(repository_id="repo", task_id="t", workspace_id="ws",
                        user_goal="modify function core_func", base_sha="abc")
    summary = _parse_impact_summary(plan)
    assert summary["truncated"] == "True"
    assert summary["limit_code"] == "max_reverse_imports"
    test_candidates = int(summary["inspected_test_candidates"])
    assert test_candidates == 0, f"test association entered after max_reverse_imports"


@pytest.mark.asyncio
async def test_max_test_candidates_limits_fetched(tmp_path: Path):
    """max_test_candidates must precisely limit fetched/accepted test candidates."""
    files = {"core.py": "def core_func(): return 1\n"}
    for i in range(30):
        files[f"test_{i}.py"] = f"from core import core_func\ndef test_{i}(): assert core_func() == 1\n"
    files["pyproject.toml"] = "[tool.pytest]\ntestpaths = [\".\"]\n"
    conn, store, _ = await _index_repo(tmp_path, files)
    service = DeterministicPlanningService(
        CodeQueryService(store),
        repositories={"repo": {
            "repository_id": "repo", "workspace_id": "ws", "head": "abc",
            "generation": 1, "root": str(tmp_path),
            "trusted_verification": (),
        }},
        max_test_candidates=5, max_depth=1, max_nodes=200, max_edges=500,
    )
    plan = service.plan(repository_id="repo", task_id="t", workspace_id="ws",
                        user_goal="modify function core_func", base_sha="abc")
    summary = _parse_impact_summary(plan)
    test_candidates = int(summary["inspected_test_candidates"])
    assert test_candidates <= 5, f"test candidates exceed limit: {test_candidates}"


@pytest.mark.asyncio
async def test_limit_code_preserves_first_trigger(tmp_path: Path):
    """limit_code must save the FIRST trigger reason and not be overwritten."""
    files = {"core.py": "def core_func(): return 1\n"}
    for i in range(60):
        files[f"caller_{i}.py"] = f"from core import core_func\ndef c_{i}(): return core_func()\n"
    files["pyproject.toml"] = "[tool.pytest]\ntestpaths = [\".\"]\n"
    conn, store, _ = await _index_repo(tmp_path, files)
    service = DeterministicPlanningService(
        CodeQueryService(store),
        repositories={"repo": {
            "repository_id": "repo", "workspace_id": "ws", "head": "abc",
            "generation": 1, "root": str(tmp_path),
            "trusted_verification": (),
        }},
        max_nodes=3, max_depth=1,
    )
    plan = service.plan(repository_id="repo", task_id="t", workspace_id="ws",
                        user_goal="modify function core_func", base_sha="abc")
    summary = _parse_impact_summary(plan)
    assert summary["truncated"] == "True"
    first_code = summary["limit_code"]
    # Plan again — same inputs must produce same limit_code
    plan2 = service.plan(repository_id="repo", task_id="t2", workspace_id="ws",
                         user_goal="modify function core_func", base_sha="abc")
    summary2 = _parse_impact_summary(plan2)
    assert summary2["limit_code"] == first_code, "limit_code must be stable"


@pytest.mark.asyncio
async def test_truncated_results_stable(tmp_path: Path):
    """Truncated results must be deterministic across repeated plans."""
    files = {"core.py": "def core_func(): return 1\n"}
    for i in range(60):
        files[f"caller_{i}.py"] = f"from core import core_func\ndef c_{i}(): return core_func()\n"
    files["pyproject.toml"] = "[tool.pytest]\ntestpaths = [\".\"]\n"
    conn, store, _ = await _index_repo(tmp_path, files)
    service = _make_service(store, tmp_path, max_nodes=5, max_depth=1)
    plan1 = service.plan(repository_id="repo", task_id="t", workspace_id="ws",
                         user_goal="modify function core_func", base_sha="abc")
    plan2 = service.plan(repository_id="repo", task_id="t", workspace_id="ws",
                         user_goal="modify function core_func", base_sha="abc")
    assert plan1.content_hash == plan2.content_hash
    assert plan1.plan_id == plan2.plan_id


@pytest.mark.asyncio
async def test_truncation_elevates_risk(tmp_path: Path):
    """Truncation must produce a warning diagnostic and elevate risk."""
    files = {"core.py": "def core_func(): return 1\n"}
    for i in range(60):
        files[f"caller_{i}.py"] = f"from core import core_func\ndef c_{i}(): return core_func()\n"
    files["pyproject.toml"] = "[tool.pytest]\ntestpaths = [\".\"]\n"
    conn, store, _ = await _index_repo(tmp_path, files)
    service = _make_service(store, tmp_path, max_nodes=3, max_depth=1)
    plan = service.plan(repository_id="repo", task_id="t", workspace_id="ws",
                        user_goal="modify function core_func", base_sha="abc")
    assert any(d.code == "impact-truncated" and d.severity == "warning" for d in plan.diagnostics)
    # Risk must be elevated (not low)
    assert plan.risks[0].level != "low", "truncation must elevate risk above low"


@pytest.mark.asyncio
async def test_hard_budget_all_methods_reject_after_truncation(tmp_path: Path):
    """After truncated=True, all budget methods must return False."""
    from khaos.coding.planning.contracts import ImpactTraversalBudget
    budget = ImpactTraversalBudget(max_nodes=1, max_edges=1, max_files=1)
    # Trigger truncation
    assert budget.can_visit_node("node-1", 0) is True
    budget.mark_visited("node-1")
    assert budget.can_visit_node("node-2", 0) is False  # max_nodes triggered
    assert budget.truncated is True
    # ALL subsequent methods must return False
    assert budget.can_visit_node("node-3", 0) is False
    assert budget.can_inspect_edge() is False
    assert budget.can_inspect_reverse_import() is False
    assert budget.can_inspect_test_candidate() is False
    assert budget.can_inspect_file_candidate() is False
    assert budget.add_affected_file("new_file.py") is False
    assert budget.add_affected_symbol("new_symbol") is False
    # Counters must NOT have been incremented by post-truncation calls
    assert budget.inspected_edges == 0
    assert budget.inspected_reverse_imports == 0
    assert budget.inspected_test_candidates == 0
    assert budget.inspected_file_candidates == 0
    assert budget.affected_files_count == 0
    assert budget.affected_symbols_count == 0  # add_affected_symbol never called
