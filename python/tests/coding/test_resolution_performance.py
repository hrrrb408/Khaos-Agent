"""Performance scenarios for repository semantic resolution.

Generates a 1,000-file fixture repository with layered dependencies,
linear chains, a small cycle, static imports and static calls. Then
exercises the six scenarios required by M3 Batch 5 Section 20:

  A. First full resolution
  B. No-modification refresh
  C. Modify a leaf file
  D. Modify a heavily-depended-upon common file
  E. Delete a target file
  F. Full rebuild comparison

Assertions (no strict absolute time gate):
  - No-modification does NOT recompute the entire graph
  - Leaf modification does NOT affect unrelated files
  - Incremental result equals full rebuild
  - No dangling resolved edges after deletion

CI does not enforce a hard time threshold; the test asserts structural
correctness and incrementality, not absolute speed.
"""
from __future__ import annotations

import asyncio
import os
import sqlite3
import sys
import tempfile
import time
from pathlib import Path

import pytest

from khaos.coding.intelligence.index import IndexStore
from khaos.coding.intelligence.index.repository import RepositoryIndexer
from khaos.coding.intelligence.query import CodeQueryService
from khaos.coding.intelligence.resolution import ResolutionService
from khaos.coding.intelligence.resolution.persistence import resolution_counts


# ---- Ground truth helpers (Section 6) ----

_STATUSES = ("resolved", "ambiguous", "unresolved", "external", "dynamic", "invalid")


def _raw_candidate_counts(conn: sqlite3.Connection, repo_id: str) -> dict[str, int]:
    """Count raw pre-resolution candidates from code_imports/calls/references."""
    return {
        "imports": int(conn.execute(
            "SELECT COUNT(*) FROM code_imports WHERE project_id=?", (repo_id,)
        ).fetchone()[0]),
        "calls": int(conn.execute(
            "SELECT COUNT(*) FROM code_calls WHERE project_id=?", (repo_id,)
        ).fetchone()[0]),
        "references": int(conn.execute(
            "SELECT COUNT(*) FROM code_references WHERE project_id=?", (repo_id,)
        ).fetchone()[0]),
    }


def _assert_mutual_exclusivity(counts: dict[str, int]) -> None:
    """Verify candidate_total == resolved + ambiguous + unresolved + external + dynamic + invalid.

    Each persisted edge has exactly one final status, so the sum of
    per-status counts must equal the total edge count for each type.
    This catches the "candidate_total=4, classification_sum=5" bug.
    """
    for edge_type, total_key in (
        ("imports", "imports"),
        ("calls", "call_edges"),
        ("references", "reference_edges"),
    ):
        total = counts[total_key]
        status_sum = sum(counts[f"{edge_type}_{s}"] for s in _STATUSES)
        assert total == status_sum, (
            f"{edge_type} mutual exclusivity violated: "
            f"total={total} != status_sum={status_sum} "
            f"(resolved={counts[f'{edge_type}_resolved']}, "
            f"ambiguous={counts[f'{edge_type}_ambiguous']}, "
            f"unresolved={counts[f'{edge_type}_unresolved']}, "
            f"external={counts[f'{edge_type}_external']}, "
            f"dynamic={counts[f'{edge_type}_dynamic']}, "
            f"invalid={counts[f'{edge_type}_invalid']})"
        )


def _ground_truth_metrics(store: IndexStore, repo_id: str, counts: dict[str, int]) -> dict[str, float | int]:
    """Compute TP/FP/precision/eligible/coverage.

    - TP: resolved edges pointing to real targets (no dangling edges)
    - FP: resolved edges pointing to missing targets (must be 0)
    - precision: TP / (TP + FP)
    - eligible: candidates that can be resolved (resolved + ambiguous + unresolved);
      external/dynamic/invalid are excluded from the denominator
    - coverage: resolved / eligible
    """
    conn = store._conn
    # FP: resolved edges whose target_file doesn't exist in code_files
    fp_imports = int(conn.execute(
        "SELECT COUNT(*) FROM resolved_imports WHERE repository_id=? AND status='resolved' "
        "AND target_file IS NOT NULL AND target_file NOT IN "
        "(SELECT path FROM code_files WHERE project_id=?)",
        (repo_id, repo_id),
    ).fetchone()[0])
    fp_calls = int(conn.execute(
        "SELECT COUNT(*) FROM resolved_call_edges WHERE repository_id=? AND status='resolved' "
        "AND target_file IS NOT NULL AND target_file NOT IN "
        "(SELECT path FROM code_files WHERE project_id=?)",
        (repo_id, repo_id),
    ).fetchone()[0])
    fp_refs = int(conn.execute(
        "SELECT COUNT(*) FROM resolved_reference_edges WHERE repository_id=? AND status='resolved' "
        "AND target_file IS NOT NULL AND target_file NOT IN "
        "(SELECT path FROM code_files WHERE project_id=?)",
        (repo_id, repo_id),
    ).fetchone()[0])
    fp = fp_imports + fp_calls + fp_refs

    tp = counts["imports_resolved"] + counts["calls_resolved"] + counts["references_resolved"]
    precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0

    # Eligible: resolved + ambiguous + unresolved (external/dynamic/invalid cannot be resolved)
    eligible = (
        counts["imports_resolved"] + counts["imports_ambiguous"] + counts["imports_unresolved"]
        + counts["calls_resolved"] + counts["calls_ambiguous"] + counts["calls_unresolved"]
        + counts["references_resolved"] + counts["references_ambiguous"] + counts["references_unresolved"]
    )
    coverage = tp / eligible if eligible > 0 else 0.0

    return {
        "tp": tp,
        "fp": fp,
        "precision": precision,
        "eligible": eligible,
        "resolved": tp,
        "coverage": coverage,
    }


# ---- Fixture generation ----


def _generate_repository(root: Path) -> dict[str, list[str]]:
    """Generate a 1,000-file Python repository.

    Layout:
      commons/commons_000.py .. commons_049.py  (50 base files, each defines a function)
      mid/mid_000.py .. mid_499.py              (500 middle files, each imports one commons)
      leaf/leaf_000.py .. leaf_447.py           (448 leaf files, each imports one mid)
      chain/chain_000.py .. chain_000.py        (1 self-contained — see below)
      cycle/cycle_a.py, cycle/cycle_b.py        (2 circular import files)

    Total: 50 + 500 + 448 + 1 + 2 = 1001 files (>= 1,000)

    Returns a dict mapping layer name → list of relative paths.
    """
    commons_dir = root / "commons"
    mid_dir = root / "mid"
    leaf_dir = root / "leaf"
    chain_dir = root / "chain"
    cycle_dir = root / "cycle"
    for d in (commons_dir, mid_dir, leaf_dir, chain_dir, cycle_dir):
        d.mkdir(parents=True, exist_ok=True)

    # Need __init__.py for Python relative imports to work as packages
    for d in (commons_dir, mid_dir, leaf_dir, chain_dir, cycle_dir):
        (d / "__init__.py").write_text("", encoding="utf-8")

    commons_paths: list[str] = []
    for i in range(50):
        fname = f"commons_{i:03d}.py"
        (commons_dir / fname).write_text(
            f"def commons_func_{i}():\n    return {i}\n",
            encoding="utf-8",
        )
        commons_paths.append(f"commons/{fname}")

    mid_paths: list[str] = []
    for i in range(500):
        commons_idx = i % 50
        fname = f"mid_{i:03d}.py"
        (mid_dir / fname).write_text(
            f"from commons.commons_{commons_idx:03d} import commons_func_{commons_idx}\n"
            f"def mid_func_{i}():\n    return commons_func_{commons_idx}()\n",
            encoding="utf-8",
        )
        mid_paths.append(f"mid/{fname}")

    leaf_paths: list[str] = []
    for i in range(448):
        mid_idx = i % 500
        fname = f"leaf_{i:03d}.py"
        (leaf_dir / fname).write_text(
            f"from mid.mid_{mid_idx:03d} import mid_func_{mid_idx}\n"
            f"def leaf_func_{i}():\n    return mid_func_{mid_idx}()\n",
            encoding="utf-8",
        )
        leaf_paths.append(f"leaf/{fname}")

    # Linear chain: chain_000 imports chain_001, chain_001 imports chain_002, ... (length 1 here
    # to keep total small but still exercise a chain). We make a 10-step chain.
    chain_length = 10
    for i in range(chain_length):
        fname = f"chain_{i:03d}.py"
        if i + 1 < chain_length:
            (chain_dir / fname).write_text(
                f"from chain.chain_{i + 1:03d} import chain_func_{i + 1}\n"
                f"def chain_func_{i}():\n    return chain_func_{i + 1}()\n",
                encoding="utf-8",
            )
        else:
            (chain_dir / fname).write_text(
                f"def chain_func_{i}():\n    return {i}\n",
                encoding="utf-8",
            )

    # Circular import pair
    (cycle_dir / "cycle_a.py").write_text(
        "from cycle.cycle_b import cycle_b_func\ndef cycle_a_func():\n    return cycle_b_func()\n",
        encoding="utf-8",
    )
    (cycle_dir / "cycle_b.py").write_text(
        "from cycle.cycle_a import cycle_a_func\ndef cycle_b_func():\n    return cycle_a_func()\n",
        encoding="utf-8",
    )

    return {
        "commons": commons_paths,
        "mid": mid_paths,
        "leaf": leaf_paths,
        "chain": [f"chain/chain_{i:03d}.py" for i in range(chain_length)],
        "cycle": ["cycle/cycle_a.py", "cycle/cycle_b.py"],
    }


def _total_files(layout: dict[str, list[str]]) -> int:
    # Add __init__.py files (5 packages)
    return sum(len(v) for v in layout.values()) + 5


# ---- Tests ----


@pytest.mark.skipif(sys.platform == "win32", reason="path separator assumptions")
def test_1000_file_resolution_performance_and_incremental_correctness():
    """End-to-end 1,000-file performance + incrementality test.

    Exercises all six scenarios from Section 20. The test asserts:
      - No-modification does not recompute the graph
      - Leaf modification does not affect unrelated files
      - Incremental result equals full rebuild
      - No dangling resolved edges
    """
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        layout = _generate_repository(root)
        total_files = _total_files(layout)
        assert total_files >= 1000, f"expected >= 1000 files, got {total_files}"

        store = IndexStore(sqlite3.connect(":memory:"))
        svc = ResolutionService(store._conn, persist=True)
        indexer = RepositoryIndexer(store, resolution_service=svc)

        # --- A. First full resolution ---
        t0 = time.perf_counter()
        report_a = asyncio.run(indexer.index("perf", root))
        first_ms = (time.perf_counter() - t0) * 1000
        res_a = report_a["resolution"]
        assert res_a["symbol_count"] > 0
        assert res_a["import_count"] > 0
        assert res_a["resolved_imports"] > 0
        # No dangling resolved edges: every resolved edge must have a target
        qs = CodeQueryService(store)
        _assert_no_dangling_edges(store, "perf")

        # --- Ground truth verification (Section 5 + 6) ---
        counts_a = resolution_counts(store._conn, "perf")
        raw_a = _raw_candidate_counts(store._conn, "perf")
        # Spec Section 5: CallCandidate > 0, resolved_call_edges > 0
        assert raw_a["calls"] > 0, f"CallCandidate count must be > 0, got {raw_a['calls']}"
        assert counts_a["call_edges"] > 0, f"resolved_call_edges count must be > 0, got {counts_a['call_edges']}"
        assert counts_a["calls_resolved"] > 0, f"resolved call edges must be > 0, got {counts_a['calls_resolved']}"
        # Spec Section 5: ReferenceCandidate > 0, resolved/unresolved reference edge > 0
        assert raw_a["references"] > 0, f"ReferenceCandidate count must be > 0, got {raw_a['references']}"
        assert counts_a["reference_edges"] > 0, f"reference edge count must be > 0, got {counts_a['reference_edges']}"
        assert counts_a["references_resolved"] + counts_a["references_unresolved"] > 0, (
            "resolved/unresolved reference edge count must be > 0"
        )
        # Spec Section 6: mutual exclusivity
        _assert_mutual_exclusivity(counts_a)

        # --- B. No-modification refresh ---
        t0 = time.perf_counter()
        report_b = asyncio.run(indexer.index("perf", root))
        nomod_ms = (time.perf_counter() - t0) * 1000
        res_b = report_b["resolution"]
        # No-modification must NOT recompute the graph
        assert res_b["affected_files"] == [], (
            f"no-mod refresh should not affect any files, got {len(res_b['affected_files'])}"
        )

        # --- C. Modify a leaf file ---
        leaf_path = layout["leaf"][0]
        leaf_file = root / leaf_path
        original_leaf = leaf_file.read_text(encoding="utf-8")
        leaf_file.write_text(
            original_leaf + "\ndef extra_leaf_func():\n    return 999\n",
            encoding="utf-8",
        )
        t0 = time.perf_counter()
        report_c = asyncio.run(indexer.index("perf", root))
        leafmod_ms = (time.perf_counter() - t0) * 1000
        res_c = report_c["resolution"]
        affected_c = set(res_c["affected_files"])
        # Leaf modification should only affect the leaf itself (and possibly its import target
        # via reverse-dep, but leaf has no dependents so only itself should be affected)
        assert leaf_path in affected_c, "leaf file should be in affected set"
        # Unrelated mid files should NOT be affected
        unrelated_mids = {p for p in layout["mid"][:10] if p != leaf_path}
        assert not (affected_c & unrelated_mids), (
            f"leaf modification should not affect unrelated mid files: {affected_c & unrelated_mids}"
        )
        # Restore leaf
        leaf_file.write_text(original_leaf, encoding="utf-8")
        asyncio.run(indexer.index("perf", root))

        # --- D. Modify a heavily-depended-upon common file ---
        # commons_000 is imported by 10 mid files (i % 50 == 0 for i in 0..499 → 10 dependents)
        commons_path = layout["commons"][0]
        commons_file = root / commons_path
        original_commons = commons_file.read_text(encoding="utf-8")
        commons_file.write_text(
            original_commons + "\ndef extra_commons_func():\n    return -1\n",
            encoding="utf-8",
        )
        t0 = time.perf_counter()
        report_d = asyncio.run(indexer.index("perf", root))
        commonmod_ms = (time.perf_counter() - t0) * 1000
        res_d = report_d["resolution"]
        affected_d = set(res_d["affected_files"])
        # commons_000 must be affected
        assert commons_path in affected_d, "commons file should be in affected set"
        # At least one mid file that imports commons_000 should be affected (reverse dep)
        mid_dependents = {
            f"mid/mid_{i:03d}.py" for i in range(500) if i % 50 == 0
        }
        assert len(affected_d & mid_dependents) >= 1, (
            f"commons modification should affect at least one mid dependent, "
            f"got {affected_d & mid_dependents}"
        )
        # Restore commons
        commons_file.write_text(original_commons, encoding="utf-8")
        asyncio.run(indexer.index("perf", root))

        # --- E. Delete a target file ---
        # Delete a commons file that has dependents — dependents should become unresolved/external
        delete_path = layout["commons"][1]  # commons_001
        delete_file = root / delete_path
        delete_file.unlink()
        t0 = time.perf_counter()
        report_e = asyncio.run(indexer.index("perf", root))
        delete_ms = (time.perf_counter() - t0) * 1000
        res_e = report_e["resolution"]
        # The deleted file should be in affected (as deleted)
        affected_e = set(res_e["affected_files"])
        assert delete_path in affected_e, "deleted file should be in affected set"
        # No dangling resolved edges after deletion
        _assert_no_dangling_edges(store, "perf")
        # Dependents of the deleted file should now have unresolved/external imports
        mid_dependents_of_deleted = {
            f"mid/mid_{i:03d}.py" for i in range(500) if i % 50 == 1
        }
        at_least_one_recomputed = bool(affected_e & mid_dependents_of_deleted)
        assert at_least_one_recomputed, (
            f"deleting commons_001 should trigger recomputation of its dependents, "
            f"affected={affected_e}"
        )

        # NOTE: We do NOT restore the deleted file. The full-rebuild comparison
        # below compares the incremental state (with the file deleted) against
        # a fresh rebuild of the SAME state (also with the file deleted).

        # --- F. Full rebuild comparison ---
        # Snapshot the current state (with the file deleted)
        counts_incremental = resolution_counts(store._conn, "perf")
        targets_incremental = qs.find_symbol_targets("perf", "commons_func_0")
        imports_incremental = qs.resolved_imports("perf", layout["mid"][0])
        calls_incremental = qs.call_edges_for_file("perf", layout["mid"][0])
        refs_incremental = qs.reference_edges_for_file("perf", layout["mid"][0])
        # Collect stable_symbol_ids for all symbols in the incremental store
        stable_ids_incremental = {
            row[0] for row in store._conn.execute(
                "SELECT stable_symbol_id FROM repository_symbols WHERE repository_id=?", ("perf",)
            ).fetchall()
        }

        # Fresh rebuild from scratch (same on-disk state — file is deleted)
        store2 = IndexStore(sqlite3.connect(":memory:"))
        svc2 = ResolutionService(store2._conn, persist=True)
        indexer2 = RepositoryIndexer(store2, resolution_service=svc2)
        t0 = time.perf_counter()
        asyncio.run(indexer2.index("perf", root))
        rebuild_ms = (time.perf_counter() - t0) * 1000
        qs2 = CodeQueryService(store2)
        counts_rebuild = resolution_counts(store2._conn, "perf")
        targets_rebuild = qs2.find_symbol_targets("perf", "commons_func_0")
        imports_rebuild = qs2.resolved_imports("perf", layout["mid"][0])
        calls_rebuild = qs2.call_edges_for_file("perf", layout["mid"][0])
        refs_rebuild = qs2.reference_edges_for_file("perf", layout["mid"][0])
        stable_ids_rebuild = {
            row[0] for row in store2._conn.execute(
                "SELECT stable_symbol_id FROM repository_symbols WHERE repository_id=?", ("perf",)
            ).fetchall()
        }

        # Incremental result must equal full rebuild.
        # Spec Section 5: incremental results and full rebuild produce identical
        # stable IDs, statuses, and targets.
        assert counts_incremental == counts_rebuild, (
            f"incremental counts != rebuild counts:\n"
            f"incremental={counts_incremental}\nrebuild={counts_rebuild}"
        )
        # stable_symbol_id set must be identical (stable across rebuilds)
        assert stable_ids_incremental == stable_ids_rebuild, (
            f"stable_symbol_id set mismatch: "
            f"only-incremental={stable_ids_incremental - stable_ids_rebuild}, "
            f"only-rebuild={stable_ids_rebuild - stable_ids_incremental}"
        )
        assert len(targets_incremental) == len(targets_rebuild), (
            f"target count mismatch: incremental={len(targets_incremental)} "
            f"rebuild={len(targets_rebuild)}"
        )
        if targets_incremental and targets_rebuild:
            # Same target path, language, and stable_symbol_id
            assert targets_incremental[0]["path"] == targets_rebuild[0]["path"], (
                f"target path mismatch: incremental={targets_incremental[0]['path']} "
                f"rebuild={targets_rebuild[0]['path']}"
            )
            assert targets_incremental[0]["stable_symbol_id"] == targets_rebuild[0]["stable_symbol_id"], (
                f"stable_symbol_id mismatch: "
                f"incremental={targets_incremental[0]['stable_symbol_id']} "
                f"rebuild={targets_rebuild[0]['stable_symbol_id']}"
            )
        # Import edges: same count, status, target_file, target_symbol_id
        assert len(imports_incremental) == len(imports_rebuild), (
            f"import count mismatch: incremental={len(imports_incremental)} "
            f"rebuild={len(imports_rebuild)}"
        )
        if imports_incremental and imports_rebuild:
            assert imports_incremental[0]["status"] == imports_rebuild[0]["status"]
            assert imports_incremental[0]["target_file"] == imports_rebuild[0]["target_file"]
            assert imports_incremental[0]["target_symbol_id"] == imports_rebuild[0]["target_symbol_id"], (
                f"import target_symbol_id mismatch: "
                f"incremental={imports_incremental[0]['target_symbol_id']} "
                f"rebuild={imports_rebuild[0]['target_symbol_id']}"
            )
        # Call edges: same count, status, target_file, target_symbol_id
        assert len(calls_incremental) == len(calls_rebuild), (
            f"call edge count mismatch: incremental={len(calls_incremental)} "
            f"rebuild={len(calls_rebuild)}"
        )
        if calls_incremental and calls_rebuild:
            assert calls_incremental[0]["status"] == calls_rebuild[0]["status"]
            assert calls_incremental[0]["target_file"] == calls_rebuild[0]["target_file"]
            assert calls_incremental[0]["target_symbol_id"] == calls_rebuild[0]["target_symbol_id"], (
                f"call target_symbol_id mismatch: "
                f"incremental={calls_incremental[0]['target_symbol_id']} "
                f"rebuild={calls_rebuild[0]['target_symbol_id']}"
            )
        # Reference edges: same count, status, target_file, target_symbol_id
        assert len(refs_incremental) == len(refs_rebuild), (
            f"reference edge count mismatch: incremental={len(refs_incremental)} "
            f"rebuild={len(refs_rebuild)}"
        )
        if refs_incremental and refs_rebuild:
            assert refs_incremental[0]["status"] == refs_rebuild[0]["status"]
            assert refs_incremental[0]["target_file"] == refs_rebuild[0]["target_file"]
            assert refs_incremental[0]["target_symbol_id"] == refs_rebuild[0]["target_symbol_id"], (
                f"reference target_symbol_id mismatch: "
                f"incremental={refs_incremental[0]['target_symbol_id']} "
                f"rebuild={refs_rebuild[0]['target_symbol_id']}"
            )

        # --- Report (printed to stdout for visibility, not asserted on absolute values) ---
        gt = _ground_truth_metrics(store, "perf", counts_rebuild)
        # Sum counts across all edge types for the report
        total_ambiguous = sum(counts_rebuild.get(f"{t}_ambiguous", 0) for t in ("imports", "calls", "references"))
        total_unresolved = sum(counts_rebuild.get(f"{t}_unresolved", 0) for t in ("imports", "calls", "references"))
        total_external = sum(counts_rebuild.get(f"{t}_external", 0) for t in ("imports", "calls", "references"))
        total_dynamic = sum(counts_rebuild.get(f"{t}_dynamic", 0) for t in ("imports", "calls", "references"))
        total_invalid = sum(counts_rebuild.get(f"{t}_invalid", 0) for t in ("imports", "calls", "references"))
        print(
            f"\n=== 1,000-file resolution performance report ===\n"
            f"Total files: {total_files}\n"
            f"Symbols: {counts_rebuild.get('symbols', 0)}\n"
            f"Raw candidates: imports={raw_a['imports']}, calls={raw_a['calls']}, references={raw_a['references']}\n"
            f"Import edges: {counts_rebuild.get('imports', 0)}\n"
            f"Call edges: {counts_rebuild.get('call_edges', 0)}\n"
            f"Reference edges: {counts_rebuild.get('reference_edges', 0)}\n"
            f"Resolved imports: {counts_rebuild.get('imports_resolved', 0)}\n"
            f"Resolved calls: {counts_rebuild.get('calls_resolved', 0)}\n"
            f"Resolved references: {counts_rebuild.get('references_resolved', 0)}\n"
            f"Ambiguous: {total_ambiguous}\n"
            f"Unresolved: {total_unresolved}\n"
            f"External: {total_external}\n"
            f"Dynamic: {total_dynamic}\n"
            f"Invalid: {total_invalid}\n"
            f"Ground truth: TP={gt['tp']}, FP={gt['fp']}, precision={gt['precision']:.4f}, "
            f"eligible={gt['eligible']}, resolved={gt['resolved']}, coverage={gt['coverage']:.4f}\n"
            f"A. First resolution: {first_ms:.1f} ms\n"
            f"B. No-mod refresh: {nomod_ms:.1f} ms (affected={len(res_b['affected_files'])})\n"
            f"C. Leaf modify: {leafmod_ms:.1f} ms (affected={len(affected_c)})\n"
            f"D. Common modify: {commonmod_ms:.1f} ms (affected={len(affected_d)})\n"
            f"E. Delete target: {delete_ms:.1f} ms (affected={len(affected_e)})\n"
            f"F. Full rebuild: {rebuild_ms:.1f} ms\n"
        )


def _assert_no_dangling_edges(store: IndexStore, repo_id: str) -> None:
    """Assert that no resolved edge points to a missing target file/symbol."""
    conn = store._conn
    # Check resolved_imports: every resolved edge must have a target_file that exists in code_files
    dangling_imports = conn.execute(
        "SELECT COUNT(*) FROM resolved_imports ri "
        "WHERE ri.repository_id=? AND ri.status='resolved' AND ri.target_file IS NOT NULL "
        "AND ri.target_file NOT IN (SELECT path FROM code_files WHERE project_id=?)",
        (repo_id, repo_id),
    ).fetchone()[0]
    assert dangling_imports == 0, f"{dangling_imports} dangling resolved import edges"

    # Check resolved_call_edges
    dangling_calls = conn.execute(
        "SELECT COUNT(*) FROM resolved_call_edges rce "
        "WHERE rce.repository_id=? AND rce.status='resolved' AND rce.target_file IS NOT NULL "
        "AND rce.target_file NOT IN (SELECT path FROM code_files WHERE project_id=?)",
        (repo_id, repo_id),
    ).fetchone()[0]
    assert dangling_calls == 0, f"{dangling_calls} dangling resolved call edges"

    # Check resolved_reference_edges
    dangling_refs = conn.execute(
        "SELECT COUNT(*) FROM resolved_reference_edges rre "
        "WHERE rre.repository_id=? AND rre.status='resolved' AND rre.target_file IS NOT NULL "
        "AND rre.target_file NOT IN (SELECT path FROM code_files WHERE project_id=?)",
        (repo_id, repo_id),
    ).fetchone()[0]
    assert dangling_refs == 0, f"{dangling_refs} dangling resolved reference edges"


def test_incremental_does_not_recompute_unaffected_files():
    """Targeted test: modifying one leaf file does not recompute unrelated files.

    This is a smaller, faster version of the leaf-modification assertion
    in the big performance test — useful for CI without the 1,000-file
    fixture.
    """
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "a.py").write_text("def a_func():\n    return 1\n", encoding="utf-8")
        (root / "b.py").write_text(
            "from a import a_func\ndef b_func():\n    return a_func()\n", encoding="utf-8"
        )
        (root / "c.py").write_text(
            "def c_func():\n    return 3\n", encoding="utf-8"
        )

        store = IndexStore(sqlite3.connect(":memory:"))
        svc = ResolutionService(store._conn, persist=True)
        indexer = RepositoryIndexer(store, resolution_service=svc)
        asyncio.run(indexer.index("r", root))

        # Modify only c.py (unrelated to a.py and b.py)
        (root / "c.py").write_text("def c_func():\n    return 99\n", encoding="utf-8")
        report = asyncio.run(indexer.index("r", root))
        affected = set(report["resolution"]["affected_files"])
        assert "c.py" in affected
        assert "a.py" not in affected, "unrelated file a.py should not be affected"
        assert "b.py" not in affected, "unrelated file b.py should not be affected"


def test_generation_prevents_stale_resolution_overwrite():
    """A stale resolution (older generation) must not overwrite a newer one.

    This complements test_25 in the correctness matrix by verifying the
    behavior at the persistence layer with multiple generations.
    """
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "app.py").write_text("def func():\n    return 1\n", encoding="utf-8")
        store = IndexStore(sqlite3.connect(":memory:"))
        svc = ResolutionService(store._conn, persist=True)
        indexer = RepositoryIndexer(store, resolution_service=svc)
        asyncio.run(indexer.index("r", root))

        # Modify the file — new generation
        (root / "app.py").write_text("def renamed():\n    return 2\n", encoding="utf-8")
        asyncio.run(indexer.index("r", root))

        qs = CodeQueryService(store)
        # Old symbol should be gone
        assert len(qs.find_symbol_targets("r", "func")) == 0
        # New symbol should exist
        new_targets = qs.find_symbol_targets("r", "renamed")
        assert len(new_targets) == 1
        # No dangling edges
        _assert_no_dangling_edges(store, "r")


def test_ground_truth_mutual_exclusivity_and_no_false_positives():
    """Ground truth metrics: mutual exclusivity, TP/FP/precision/coverage.

    Builds a small controlled repository with known resolvable, external,
    dynamic, and unresolved candidates. Verifies:
      1. candidate_total == resolved + ambiguous + unresolved + external + dynamic + invalid
      2. No false positives (all resolved edges point to real targets)
      3. precision == 1.0 (no FP)
      4. coverage = resolved / eligible (eligible = resolved + ambiguous + unresolved)
    """
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        # util.py: defines helper (resolvable target)
        (root / "util.py").write_text(
            "def helper():\n    return 42\n",
            encoding="utf-8",
        )
        # app.py: imports helper (resolvable), os (external), nonexistent (unresolved);
        #         calls helper() (resolvable), obj.method() (dynamic)
        (root / "app.py").write_text(
            "from util import helper\n"
            "import os\n"
            "from nonexistent import thing\n"
            "def main():\n"
            "    helper()\n"
            "    os.getcwd()\n"
            "    obj.method()\n"
            "    thing()\n",
            encoding="utf-8",
        )

        store = IndexStore(sqlite3.connect(":memory:"))
        svc = ResolutionService(store._conn, persist=True)
        indexer = RepositoryIndexer(store, resolution_service=svc)
        asyncio.run(indexer.index("gt", root))

        counts = resolution_counts(store._conn, "gt")
        # Mutual exclusivity per edge type
        _assert_mutual_exclusivity(counts)

        # Ground truth metrics
        gt = _ground_truth_metrics(store, "gt", counts)
        # No false positives: all resolved edges point to real targets
        assert gt["fp"] == 0, f"Expected 0 false positives, got {gt['fp']}"
        # Precision must be 1.0 (no FP)
        assert gt["precision"] == 1.0, f"Expected precision 1.0, got {gt['precision']}"
        # At least one resolved edge (helper import + helper call)
        assert gt["tp"] >= 1, f"Expected at least 1 TP, got {gt['tp']}"
        # At least one external (os import)
        assert counts["imports_external"] + counts["calls_external"] >= 1, "Expected at least 1 external"
        # At least one dynamic (obj.method)
        assert counts["calls_dynamic"] >= 1, f"Expected at least 1 dynamic call, got {counts['calls_dynamic']}"
        # Coverage in [0, 1]
        assert 0.0 <= gt["coverage"] <= 1.0
        # Eligible = resolved + ambiguous + unresolved (excludes external/dynamic/invalid)
        eligible_computed = (
            counts["imports_resolved"] + counts["imports_ambiguous"] + counts["imports_unresolved"]
            + counts["calls_resolved"] + counts["calls_ambiguous"] + counts["calls_unresolved"]
            + counts["references_resolved"] + counts["references_ambiguous"] + counts["references_unresolved"]
        )
        assert gt["eligible"] == eligible_computed

        print(
            f"\n=== Ground truth metrics ===\n"
            f"Counts: {counts}\n"
            f"TP={gt['tp']}, FP={gt['fp']}, precision={gt['precision']:.4f}, "
            f"eligible={gt['eligible']}, resolved={gt['resolved']}, coverage={gt['coverage']:.4f}\n"
        )
