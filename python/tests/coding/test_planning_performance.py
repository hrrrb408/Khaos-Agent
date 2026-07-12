"""Performance evidence: bounded planning without repository-wide scans.

Proves that leaf and public-symbol planning do NOT enumerate all code_files
or inspect all test candidates. Uses real inspection counts from the
impact-summary diagnostic — not just visited_nodes or affected_files.
"""
from __future__ import annotations

import asyncio
import re
import sqlite3
import time
from pathlib import Path

import pytest

from khaos.coding.intelligence.index import IndexStore, RepositoryIndexer
from khaos.coding.intelligence.query import CodeQueryService
from khaos.coding.intelligence.resolution.service import ResolutionService
from khaos.coding.planning.contracts import PlanStatus
from khaos.coding.planning.service import DeterministicPlanningService

_TOTAL_FILES = 1000


def _parse_impact_summary(plan) -> dict[str, str]:
    """Extract inspection counts from the impact-summary diagnostic."""
    diag = next(d for d in plan.diagnostics if d.code == "impact-summary")
    pairs = {}
    for part in diag.message.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            pairs[k.strip()] = v.strip()
    return pairs


def _build_large_repo(tmp_path: Path):
    """Build a 1000-file repository with one public root and many leaves."""
    for index in range(_TOTAL_FILES):
        if index == 0:
            content = "def PublicRoot(): return 1\n"
        elif index <= 40:
            content = f"from file_0 import PublicRoot\ndef caller_{index}(): return PublicRoot()\n"
        else:
            content = f"def leaf_{index}(): return {index}\n"
        (tmp_path / f"file_{index}.py").write_text(content)
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    store = IndexStore(conn)
    resolver = ResolutionService(conn)
    report = asyncio.get_event_loop().run_until_complete(
        RepositoryIndexer(store, resolution_service=resolver).index("large", tmp_path, full_reindex=True)
    )
    query = CodeQueryService(store)
    service = DeterministicPlanningService(
        query,
        repositories={"large": {
            "repository_id": "large", "workspace_id": "ws", "head": "sha",
            "generation": 1, "root": str(tmp_path),
            "trusted_verification": ({"language": "python", "argv": ("python", "-m", "pytest", "-q"), "type": "unit-test", "source": "pyproject"},)},
        },
    )
    return conn, store, query, service, report


def test_large_repository_planning_matrix_is_bounded_deterministic_and_read_only(tmp_path: Path):
    conn, store, query, service, report = _build_large_repo(tmp_path)
    snapshot = {path.name: path.read_bytes() for path in tmp_path.iterdir()}

    started = time.perf_counter()
    leaf = service.plan(repository_id="large", task_id="leaf", workspace_id="ws", user_goal="modify function leaf_999", base_sha="sha")
    leaf_ms = (time.perf_counter() - started) * 1000

    started = time.perf_counter()
    public = service.plan(repository_id="large", task_id="public", workspace_id="ws", user_goal="modify function PublicRoot", base_sha="sha")
    public_ms = (time.perf_counter() - started) * 1000

    rename = service.plan(repository_id="large", task_id="rename", workspace_id="ws", user_goal="rename function PublicRoot to RenamedRoot", base_sha="sha")
    missing = service.plan(repository_id="large", task_id="missing", workspace_id="ws", user_goal="modify function absent", base_sha="sha")

    started = time.perf_counter()
    repeated = service.plan(repository_id="large", task_id="public", workspace_id="ws", user_goal="modify function PublicRoot", base_sha="sha")
    repeated_ms = (time.perf_counter() - started) * 1000

    assert report["scanned_files"] == _TOTAL_FILES
    assert leaf.status is PlanStatus.READY
    assert public.status is PlanStatus.READY
    assert rename.status is PlanStatus.READY
    assert missing.status is PlanStatus.BLOCKED

    leaf_summary = _parse_impact_summary(leaf)
    public_summary = _parse_impact_summary(public)

    # --- Leaf planning: must NOT scan the entire repository ---
    # The spec says: "测试不得只用 visited_nodes=1 affected_files<10 来推断没有全仓扫描"
    # We must prove via sql_rows_enumerated and inspected_test_candidates.
    leaf_sql = int(leaf_summary["sql_rows_enumerated"])
    leaf_test_candidates = int(leaf_summary["inspected_test_candidates"])
    leaf_file_candidates = int(leaf_summary["inspected_file_candidates"])
    leaf_edges = int(leaf_summary["inspected_edges"])
    leaf_visited_nodes = int(leaf_summary["visited_nodes"])
    leaf_affected_files = len(leaf.affected_files)
    leaf_affected_symbols = len(leaf.affected_symbols)

    # Leaf_999 has no callers, no reverse imports, no references — it's a true leaf.
    # SQL rows enumerated must be MUCH less than 1000 (the total file count).
    assert leaf_sql < _TOTAL_FILES, f"leaf sql_rows_enumerated={leaf_sql} must be < {_TOTAL_FILES}"
    assert leaf_test_candidates < _TOTAL_FILES, f"leaf inspected_test_candidates={leaf_test_candidates} must be < {_TOTAL_FILES}"
    # Affected files must be distinguished from scanned files.
    assert leaf_affected_files < _TOTAL_FILES
    # visited_nodes alone is not sufficient — we also check sql_rows and test_candidates.
    assert leaf_visited_nodes >= 1
    assert leaf_edges >= 0

    # --- Public symbol: bounded dependency closure ---
    public_sql = int(public_summary["sql_rows_enumerated"])
    public_test_candidates = int(public_summary["inspected_test_candidates"])
    public_visited_nodes = int(public_summary["visited_nodes"])
    public_edges = int(public_summary["inspected_edges"])
    public_affected_files = len(public.affected_files)
    public_affected_symbols = len(public.affected_symbols)
    public_truncated = public_summary["truncated"] == "True"

    # PublicRoot has 40 callers (file_1..file_40), so visited_nodes should be
    # bounded but > 1. The closure must not enumerate all 1000 files.
    assert public_visited_nodes > 1, "public symbol must visit callers"
    assert public_sql < _TOTAL_FILES, f"public sql_rows_enumerated={public_sql} must be < {_TOTAL_FILES}"
    assert public_test_candidates < _TOTAL_FILES, f"public inspected_test_candidates={public_test_candidates} must be < {_TOTAL_FILES}"
    assert public_affected_files < _TOTAL_FILES, f"public affected_files={public_affected_files} must be < {_TOTAL_FILES}"

    # --- Determinism ---
    assert public.content_hash == repeated.content_hash
    assert public.plan_id == repeated.plan_id

    # --- Read-only: no files modified ---
    assert snapshot == {path.name: path.read_bytes() for path in tmp_path.iterdir()}

    # --- No execution capabilities ---
    assert not any(hasattr(service, name) for name in ("execute", "tool_scheduler", "terminal", "test_run", "create_changeset"))

    # --- Performance metrics ---
    symbols_count = conn.execute("SELECT COUNT(*) FROM repository_symbols WHERE repository_id='large'").fetchone()[0]
    edges_count = conn.execute("SELECT COUNT(*) FROM resolved_call_edges WHERE repository_id='large'").fetchone()[0]
    assert symbols_count >= _TOTAL_FILES

    metrics = {
        "files": _TOTAL_FILES,
        "symbols": symbols_count,
        "edges": edges_count,
        "leaf_ms": round(leaf_ms, 1),
        "public_ms": round(public_ms, 1),
        "repeated_ms": round(repeated_ms, 1),
        "leaf_visited_nodes": leaf_visited_nodes,
        "leaf_inspected_edges": leaf_edges,
        "leaf_inspected_file_candidates": leaf_file_candidates,
        "leaf_inspected_test_candidates": leaf_test_candidates,
        "leaf_sql_rows_enumerated": leaf_sql,
        "leaf_affected_files": leaf_affected_files,
        "leaf_affected_symbols": leaf_affected_symbols,
        "public_visited_nodes": public_visited_nodes,
        "public_inspected_edges": public_edges,
        "public_inspected_test_candidates": public_test_candidates,
        "public_sql_rows_enumerated": public_sql,
        "public_affected_files": public_affected_files,
        "public_affected_symbols": public_affected_symbols,
        "public_truncated": public_truncated,
        "hash_equal": public.content_hash == repeated.content_hash,
    }
    # Print for CI capture
    print(f"\nPERF_METRICS: {metrics}")
    assert metrics["hash_equal"]


def test_leaf_planning_detects_full_table_scan_counterexample(tmp_path: Path):
    """If the planner accidentally does a full table scan, this test catches it.

    Creates a repo where the leaf file has NO connections at all. Any non-zero
    SQL row enumeration beyond the bounded test-association query proves the
    planner is scanning the whole repository.
    """
    conn, store, query, service, report = _build_large_repo(tmp_path)
    leaf = service.plan(repository_id="large", task_id="leaf", workspace_id="ws", user_goal="modify function leaf_500", base_sha="sha")
    assert leaf.status is PlanStatus.READY
    summary = _parse_impact_summary(leaf)
    sql_rows = int(summary["sql_rows_enumerated"])
    test_candidates = int(summary["inspected_test_candidates"])
    # leaf_500 is a true leaf — no callers, no imports, no references.
    # The only SQL should be from bounded test association (max_test_candidates=50).
    # If sql_rows > 100, we're likely scanning the whole repo.
    assert sql_rows <= 100, f"leaf_500 sql_rows_enumerated={sql_rows} —疑似全表扫描"
    assert test_candidates <= 50, f"leaf_500 inspected_test_candidates={test_candidates} —超过 max_test_candidates"
    # affected_files must not equal scanned_files (1000)
    assert len(leaf.affected_files) < _TOTAL_FILES


def test_budget_truncation_produces_stable_results_and_risk(tmp_path: Path):
    """When budget limits are hit, results must be truncated, stable, and risk-elevated."""
    conn, store, query, service, report = _build_large_repo(tmp_path)
    # Plan with very tight budget — should truncate
    tight_service = DeterministicPlanningService(
        query,
        repositories={"large": {
            "repository_id": "large", "workspace_id": "ws", "head": "sha",
            "generation": 1, "root": str(tmp_path),
            "trusted_verification": ({"language": "python", "argv": ("python", "-m", "pytest", "-q"), "type": "unit-test", "source": "pyproject"},)},
        },
        max_nodes=5, max_files=5, max_symbols=5, max_depth=1,
    )
    first = tight_service.plan(repository_id="large", task_id="tight", workspace_id="ws", user_goal="modify function PublicRoot", base_sha="sha")
    second = tight_service.plan(repository_id="large", task_id="tight", workspace_id="ws", user_goal="modify function PublicRoot", base_sha="sha")
    summary = _parse_impact_summary(first)
    assert summary["truncated"] == "True"
    assert summary["limit_code"] != "none"
    # Truncated results must be deterministic
    assert first.content_hash == second.content_hash
    assert first.plan_id == second.plan_id
    # Truncation must produce a warning diagnostic
    assert any(d.code == "impact-truncated" and d.severity == "warning" for d in first.diagnostics)
