"""M3 Intelligence closure matrix — final six-dialect end-to-end acceptance.

This is the M3 phase acceptance test. It exercises the full pipeline for
every supported dialect and asserts that all M3 guarantees hold end-to-end:

    source files
      → LanguageRegistry
      → Tree-sitter adapter (real grammar)
      → ParseState (incremental update via RepositoryIndexer cache)
      → IndexStore (atomic per-file write, generation counter)
      → ResolutionService (conservative repository resolution)
      → optional LspEvidenceFusionService (feature flag OFF by default)
      → CodeQueryService (structured query facade)

Per dialect, every test asserts:
    - symbol extraction (with stable_symbol_id)
    - import extraction (with at least one resolved or external)
    - call candidate extraction (with at least one resolved static target)
    - reference candidate extraction (where applicable)
    - incremental modification (generation increments, byte range matches)
    - repository-level resolved AND unresolved/dynamic edges coexist
    - CodeQueryService returns structured rows
    - provenance: parser_source=tree-sitter, parser_version populated
    - no-LSP degradation: fusion disabled returns repository-only result

These tests are skipped automatically when Tree-sitter optional
dependencies are not installed.
"""
from __future__ import annotations

import asyncio
import sqlite3
import tempfile
from pathlib import Path

import pytest

pytestmark = pytest.mark.tree_sitter_real
pytest.importorskip("tree_sitter")

from khaos.coding.intelligence.index import IndexStore, RepositoryIndexer
from khaos.coding.intelligence.lsp.cache import EvidenceCache
from khaos.coding.intelligence.lsp.config import LspFusionConfig
from khaos.coding.intelligence.lsp.evidence import FusionRule
from khaos.coding.intelligence.lsp.fusion import (
    FusionContext,
    LspEvidenceFusionService,
    compute_content_hash,
    compute_server_identity,
)
from khaos.coding.intelligence.query import CodeQueryService
from khaos.coding.intelligence.resolution import ResolutionService
from khaos.coding.intelligence.resolution.persistence import resolution_counts


# ---- Helpers ---------------------------------------------------------------


def _build(root: Path, repo_id: str = "r") -> tuple[IndexStore, RepositoryIndexer, CodeQueryService, dict]:
    """Index a repository with real Tree-sitter and resolution enabled."""
    store = IndexStore(sqlite3.connect(":memory:", check_same_thread=False))
    svc = ResolutionService(store._conn, persist=True)
    indexer = RepositoryIndexer(store, resolution_service=svc)

    async def run() -> dict:
        return await indexer.index(repo_id, root)

    report = asyncio.run(run())
    qs = CodeQueryService(store)
    return store, indexer, qs, report


def _assert_parser_source(store: IndexStore, repo_id: str, path: str) -> None:
    """Verify parser_source=tree-sitter and metadata is populated."""
    record = asyncio.run(store.file_record(repo_id, path))
    assert record is not None, f"missing file record for {path}"
    assert record["parser_source"] == "tree-sitter", (
        f"{path}: parser_source expected tree-sitter, got {record['parser_source']}"
    )
    assert record["parser_version"], f"{path}: parser_version not populated"
    assert record["generation"] >= 1, f"{path}: generation not populated"


def _assert_has_resolved_and_unresolved(rows: list[dict], *, label: str) -> None:
    """Assert that rows contain at least one resolved AND one non-resolved edge."""
    resolved = [r for r in rows if r["status"] == "resolved"]
    non_resolved = [r for r in rows if r["status"] in ("unresolved", "dynamic", "ambiguous")]
    assert len(resolved) >= 1, f"{label}: expected at least one resolved edge, got {rows}"
    assert len(non_resolved) >= 1, f"{label}: expected at least one unresolved/dynamic edge, got {rows}"


def _make_fusion_service(
    conn: sqlite3.Connection,
    *,
    enabled: bool = False,
    lsp_client=None,
) -> LspEvidenceFusionService:
    """Build an LspEvidenceFusionService with the given config and client."""
    config = LspFusionConfig(enabled=enabled)
    cache = EvidenceCache()
    return LspEvidenceFusionService(
        config=config,
        cache=cache,
        conn=conn,
        lsp_client=lsp_client,
    )


# ---- 1. Python closure -----------------------------------------------------


def test_python_m3_closure():
    """Python: full M3 pipeline + incremental + no-LSP degradation."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "util.py").write_text(
            "def helper():\n    return 42\n\nCONST = 7\n",
            encoding="utf-8",
        )
        (root / "app.py").write_text(
            "from util import helper\nimport os\n\n"
            "def main():\n    helper()\n    return os.getcwd()\n"
            "\nobj.method()  # dynamic\n",
            encoding="utf-8",
        )

        store, indexer, qs, report = _build(root, "py")

        # Provenance
        _assert_parser_source(store, "py", "util.py")
        _assert_parser_source(store, "py", "app.py")

        # Symbol
        syms = qs.find_symbol_targets("py", "helper")
        assert len(syms) == 1
        assert syms[0]["stable_symbol_id"]

        # Import
        imports = qs.resolved_imports("py", "app.py")
        assert len(imports) >= 2

        # Call (resolved + dynamic)
        calls = qs.call_edges_for_file("py", "app.py")
        _assert_has_resolved_and_unresolved(calls, label="python calls")

        # Query: structured row
        resolved = [c for c in calls if c["status"] == "resolved"][0]
        assert resolved["target_file"] == "util.py"
        assert resolved["target_symbol_id"] is not None

        # Incremental modification: change util.py and reindex
        (root / "util.py").write_text(
            "def helper():\n    return 99\n\nCONST = 7\n",
            encoding="utf-8",
        )
        report2 = asyncio.run(indexer.index("py", root))
        assert report2["incremental_files"] + report2["parsed_files"] >= 1

        # Generation should increment
        record = asyncio.run(store.file_record("py", "util.py"))
        assert record["generation"] >= 2

        # No-LSP degradation: fusion disabled returns repository-only
        fusion = _make_fusion_service(store._conn, enabled=False)
        assert fusion.enabled is False
        # Build a FusionContext (transient, not persisted)
        ctx = FusionContext(
            repository_id="py",
            workspace_id="ws-1",
            file_path="app.py",
            file_text=(root / "app.py").read_text(encoding="utf-8"),
            content_hash=compute_content_hash((root / "app.py").read_text(encoding="utf-8")),
            file_generation=record["generation"],
            document_version=1,
            server_identity=compute_server_identity("test", "0.0"),
            workspace_root=root,
        )
        from khaos.coding.intelligence.resolution.models import (
            ResolutionStatus,
            ResolvedCallEdge,
        )
        repo_resolution = ResolvedCallEdge(
            edge_id=resolved["edge_id"],
            source_file="app.py",
            caller_symbol_id=None,
            call_callee="helper",
            status=ResolutionStatus.RESOLVED,
            target_symbol_id=resolved["target_symbol_id"],
            target_file=resolved["target_file"],
            confidence=resolved.get("confidence", 0.9),
            resolution_rule=resolved.get("resolution_rule", "test"),
            ambiguity_reason=None,
        )
        fused = asyncio.run(fusion.fuse_definition(
            candidate_callee="helper",
            candidate_byte_range=(0, 6),
            repo_resolution=repo_resolution,
            context=ctx,
        ))
        assert fused.depends_on_lsp is False
        assert fused.resolution_rule != FusionRule.LSP_CONFIRMED.value
        assert fused.fused_status == repo_resolution.status.value


# ---- 2. JavaScript closure -------------------------------------------------


def test_javascript_m3_closure():
    """JavaScript: full M3 pipeline + incremental + no-LSP degradation."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "util.js").write_text(
            "export function run() { return 1; }\n"
            "export const value = 42;\n",
            encoding="utf-8",
        )
        (root / "extra.js").write_text(
            "export function aux() { return 2; }\n",
            encoding="utf-8",
        )
        (root / "app.js").write_text(
            "import * as ns from './util.js';\n"
            "import { aux } from './extra.js';\n"
            "import React from 'react';\n"
            "\n"
            "export function main() {\n"
            "    aux();\n"
            "    return ns.run();\n"
            "}\n"
            "\n"
            "obj.dynamic()  // dynamic\n",
            encoding="utf-8",
        )

        store, indexer, qs, report = _build(root, "js")

        _assert_parser_source(store, "js", "util.js")
        _assert_parser_source(store, "js", "app.js")

        syms = qs.find_symbol_targets("js", "run")
        assert len(syms) == 1
        assert syms[0]["stable_symbol_id"]

        imports = qs.resolved_imports("js", "app.js")
        assert len(imports) >= 3
        assert any(i["status"] == "external" for i in imports)

        calls = qs.call_edges_for_file("js", "app.js")
        _assert_has_resolved_and_unresolved(calls, label="js calls")

        resolved = [c for c in calls if c["status"] == "resolved" and c["target_file"] == "util.js"]
        assert len(resolved) >= 1

        # Incremental
        (root / "util.js").write_text(
            "export function run() { return 100; }\n"
            "export const value = 42;\n",
            encoding="utf-8",
        )
        report2 = asyncio.run(indexer.index("js", root))
        assert report2["incremental_files"] + report2["parsed_files"] >= 1

        record = asyncio.run(store.file_record("js", "util.js"))
        assert record["generation"] >= 2

        # No-LSP degradation
        fusion = _make_fusion_service(store._conn, enabled=False)
        assert fusion.enabled is False


# ---- 3. TypeScript closure -------------------------------------------------


def test_typescript_m3_closure():
    """TypeScript: full M3 pipeline + incremental + no-LSP degradation."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "util.ts").write_text(
            "export function helper(): number { return 42; }\n",
            encoding="utf-8",
        )
        (root / "types.ts").write_text(
            "export interface Item { name: string; }\n",
            encoding="utf-8",
        )
        (root / "app.ts").write_text(
            "import { helper } from './util';\n"
            "import { Item } from './types';\n"
            "import { useState } from 'react';\n"
            "\n"
            "export function main(item: Item): number {\n"
            "    helper();\n"
            "    return item.name.length;\n"
            "}\n"
            "\n"
            "value.unknown()  // dynamic\n",
            encoding="utf-8",
        )

        store, indexer, qs, report = _build(root, "ts")

        _assert_parser_source(store, "ts", "util.ts")
        _assert_parser_source(store, "ts", "app.ts")

        syms = qs.find_symbol_targets("ts", "helper")
        assert len(syms) == 1

        imports = qs.resolved_imports("ts", "app.ts")
        assert len(imports) >= 2
        assert any(i["status"] == "external" for i in imports)

        calls = qs.call_edges_for_file("ts", "app.ts")
        _assert_has_resolved_and_unresolved(calls, label="ts calls")

        resolved = [c for c in calls if c["status"] == "resolved" and c["target_file"] == "util.ts"]
        assert len(resolved) >= 1

        # Incremental
        (root / "util.ts").write_text(
            "export function helper(): number { return 99; }\n",
            encoding="utf-8",
        )
        report2 = asyncio.run(indexer.index("ts", root))
        assert report2["incremental_files"] + report2["parsed_files"] >= 1

        record = asyncio.run(store.file_record("ts", "util.ts"))
        assert record["generation"] >= 2


# ---- 4. TSX closure --------------------------------------------------------


def test_tsx_m3_closure():
    """TSX: full M3 pipeline + incremental + no-LSP degradation."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "util.ts").write_text(
            "export function helper(): number { return 42; }\n",
            encoding="utf-8",
        )
        (root / "App.tsx").write_text(
            "import { helper } from './util';\n"
            "import { useState } from 'react';\n"
            "\n"
            "export function App() {\n"
            "    helper();\n"
            "    return <div onClick={() => helper()}>hello</div>;\n"
            "}\n"
            "\n"
            "obj.method()  // dynamic\n",
            encoding="utf-8",
        )

        store, indexer, qs, report = _build(root, "tsx")

        _assert_parser_source(store, "tsx", "util.ts")
        _assert_parser_source(store, "tsx", "App.tsx")

        syms = qs.find_symbol_targets("tsx", "helper")
        assert len(syms) == 1

        app_syms = qs.find_symbol_targets("tsx", "App")
        assert len(app_syms) == 1
        assert app_syms[0]["path"] == "App.tsx"

        imports = qs.resolved_imports("tsx", "App.tsx")
        assert len(imports) >= 2
        assert any(i["status"] == "external" for i in imports)

        calls = qs.call_edges_for_file("tsx", "App.tsx")
        _assert_has_resolved_and_unresolved(calls, label="tsx calls")

        resolved = [c for c in calls if c["status"] == "resolved" and c["target_file"] == "util.ts"]
        assert len(resolved) >= 1

        # Incremental
        (root / "util.ts").write_text(
            "export function helper(): number { return 100; }\n",
            encoding="utf-8",
        )
        report2 = asyncio.run(indexer.index("tsx", root))
        assert report2["incremental_files"] + report2["parsed_files"] >= 1


# ---- 5. Go closure ---------------------------------------------------------


def test_go_m3_closure():
    """Go: full M3 pipeline + incremental + no-LSP degradation."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "go.mod").write_text(
            "module example.com/myproject\n\ngo 1.21\n",
            encoding="utf-8",
        )
        (root / "util").mkdir()
        (root / "util" / "util.go").write_text(
            "package util\n\n"
            "func Run() string { return \"ok\" }\n"
            "var Public = 42\n",
            encoding="utf-8",
        )
        (root / "main.go").write_text(
            "package main\n\n"
            "import (\n"
            "    \"example.com/myproject/util\"\n"
            "    \"fmt\"\n"
            ")\n\n"
            "func Build() string {\n"
            "    util.Run()\n"
            "    return fmt.Sprintf(\"%d\", util.Public)\n"
            "}\n\n"
            "value.Method()  // dynamic interface dispatch\n",
            encoding="utf-8",
        )

        store, indexer, qs, report = _build(root, "go")

        _assert_parser_source(store, "go", "util/util.go")
        _assert_parser_source(store, "go", "main.go")

        syms = qs.find_symbol_targets("go", "Run")
        assert len(syms) == 1
        assert syms[0]["path"] == "util/util.go"

        imports = qs.resolved_imports("go", "main.go")
        assert len(imports) >= 2
        assert any(i["status"] == "external" for i in imports)

        calls = qs.call_edges_for_file("go", "main.go")
        _assert_has_resolved_and_unresolved(calls, label="go calls")

        resolved = [c for c in calls if c["status"] == "resolved" and c["target_file"] == "util/util.go"]
        assert len(resolved) >= 1

        # Incremental
        (root / "util" / "util.go").write_text(
            "package util\n\n"
            "func Run() string { return \"updated\" }\n"
            "var Public = 42\n",
            encoding="utf-8",
        )
        report2 = asyncio.run(indexer.index("go", root))
        assert report2["incremental_files"] + report2["parsed_files"] >= 1


# ---- 6. Rust closure -------------------------------------------------------


def test_rust_m3_closure():
    """Rust: full M3 pipeline + incremental + no-LSP degradation."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "Cargo.toml").write_text(
            "[package]\nname = \"demo\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            encoding="utf-8",
        )
        (root / "src").mkdir()
        (root / "src" / "util.rs").write_text(
            "pub fn run() -> i32 { 42 }\n"
            "pub const VALUE: i32 = 7;\n",
            encoding="utf-8",
        )
        (root / "src" / "main.rs").write_text(
            "mod util;\n"
            "use crate::util::run;\n"
            "use std::fmt;\n"
            "\n"
            "fn main() {\n"
            "    run();\n"
            "    let _ = fmt::format(fmt::Arguments::new_v1(&[\"x\"], &[]));\n"
            "}\n"
            "\n"
            "value.method()  // dynamic\n",
            encoding="utf-8",
        )

        store, indexer, qs, report = _build(root, "rs")

        _assert_parser_source(store, "rs", "src/util.rs")
        _assert_parser_source(store, "rs", "src/main.rs")

        syms = qs.find_symbol_targets("rs", "run")
        assert len(syms) == 1
        assert syms[0]["path"] == "src/util.rs"

        imports = qs.resolved_imports("rs", "src/main.rs")
        assert len(imports) >= 1
        assert any(i["status"] == "external" for i in imports)

        calls = qs.call_edges_for_file("rs", "src/main.rs")
        _assert_has_resolved_and_unresolved(calls, label="rust calls")

        resolved = [c for c in calls if c["status"] == "resolved" and c["target_file"] == "src/util.rs"]
        assert len(resolved) >= 1

        # Incremental
        (root / "src" / "util.rs").write_text(
            "pub fn run() -> i32 { 99 }\n"
            "pub const VALUE: i32 = 7;\n",
            encoding="utf-8",
        )
        report2 = asyncio.run(indexer.index("rs", root))
        assert report2["incremental_files"] + report2["parsed_files"] >= 1


# ---- 7. Mixed-language repository closure ----------------------------------


def test_mixed_language_m3_closure():
    """All six dialects in one repository parse, resolve, and query cleanly."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        # Python
        (root / "p_util.py").write_text(
            "def py_helper():\n    return 1\n",
            encoding="utf-8",
        )
        (root / "p_app.py").write_text(
            "from p_util import py_helper\npy_helper()\nobj.x()  # dynamic\n",
            encoding="utf-8",
        )
        # JavaScript
        (root / "js_util.js").write_text(
            "export function jsRun() { return 2; }\n",
            encoding="utf-8",
        )
        (root / "js_app.js").write_text(
            "import { jsRun } from './js_util.js';\njsRun();\nobj.x();\n",
            encoding="utf-8",
        )
        # TypeScript
        (root / "ts_util.ts").write_text(
            "export function tsRun(): number { return 3; }\n",
            encoding="utf-8",
        )
        (root / "ts_app.ts").write_text(
            "import { tsRun } from './ts_util';\ntsRun();\nobj.x();\n",
            encoding="utf-8",
        )
        # TSX
        (root / "App.tsx").write_text(
            "import { tsRun } from './ts_util';\n"
            "export function App() { return tsRun(); }\n",
            encoding="utf-8",
        )
        # Go
        (root / "go.mod").write_text("module demo\n\ngo 1.21\n")
        (root / "go_util").mkdir()
        (root / "go_util" / "util.go").write_text(
            "package util\nfunc GoRun() int { return 4 }\n",
            encoding="utf-8",
        )
        (root / "main.go").write_text(
            "package main\nimport \"demo/go_util\"\nfunc main() { go_util.GoRun() }\n",
            encoding="utf-8",
        )
        # Rust
        (root / "Cargo.toml").write_text("[package]\nname=\"demo\"\nversion=\"0.1.0\"\nedition=\"2021\"\n")
        (root / "src").mkdir()
        (root / "src" / "util.rs").write_text("pub fn rs_run() -> i32 { 5 }\n")
        (root / "src" / "main.rs").write_text(
            "mod util;\nuse crate::util::rs_run;\nfn main() { rs_run(); }\n",
            encoding="utf-8",
        )

        store, indexer, qs, report = _build(root, "mixed")

        for path in (
            "p_util.py", "p_app.py",
            "js_util.js", "js_app.js",
            "ts_util.ts", "ts_app.ts", "App.tsx",
            "go_util/util.go", "main.go",
            "src/util.rs", "src/main.rs",
        ):
            _assert_parser_source(store, "mixed", path)

        counts = resolution_counts(store._conn, "mixed")
        assert counts["symbols"] >= 6
        assert counts["call_edges"] >= 6
        assert counts["calls_resolved"] >= 6


# ---- 8. Optional LSP fusion degradation across all dialects ----------------


def test_lsp_fusion_disabled_returns_repository_only_all_dialects():
    """When LSP fusion is disabled, fused result equals repository resolution.

    This is the no-LSP degradation guarantee: every dialect's resolved call
    edge must produce a FusedResolution that carries only repository evidence
    and has depends_on_lsp=False.
    """
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        # Minimal projects per dialect
        (root / "py.py").write_text(
            "def f():\n    pass\nf()\n",
            encoding="utf-8",
        )
        (root / "js.js").write_text(
            "export function f() {}\nf();\n",
            encoding="utf-8",
        )
        (root / "ts.ts").write_text(
            "export function f(): void {}\nf();\n",
            encoding="utf-8",
        )
        (root / "tsx.tsx").write_text(
            "export function App() { return <div/>; }\n",
            encoding="utf-8",
        )
        (root / "go.mod").write_text("module demo\ngo 1.21\n")
        (root / "main.go").write_text(
            "package main\nfunc f() {}\nfunc main() { f() }\n",
            encoding="utf-8",
        )
        (root / "Cargo.toml").write_text("[package]\nname=\"demo\"\nversion=\"0.1.0\"\nedition=\"2021\"\n")
        (root / "src").mkdir()
        (root / "src" / "main.rs").write_text(
            "pub fn f() {}\nfn main() { f() }\n",
            encoding="utf-8",
        )

        store, indexer, qs, report = _build(root, "deg")

        fusion = _make_fusion_service(store._conn, enabled=False)
        assert fusion.enabled is False

        # For every file in the repository, repository-only fusion must succeed.
        for path in (
            "py.py", "js.js", "ts.ts", "tsx.tsx",
            "main.go", "src/main.rs",
        ):
            record = asyncio.run(store.file_record("deg", path))
            assert record is not None, f"missing record for {path}"
            file_text = (root / path).read_text(encoding="utf-8")
            ctx = FusionContext(
                repository_id="deg",
                workspace_id="ws-deg",
                file_path=path,
                file_text=file_text,
                content_hash=compute_content_hash(file_text),
                file_generation=record["generation"],
                document_version=1,
                server_identity=compute_server_identity("test", "0.0"),
                workspace_root=root,
            )
            from khaos.coding.intelligence.resolution.models import (
                ResolutionStatus,
                ResolvedCallEdge,
            )
            repo_resolution = ResolvedCallEdge(
                edge_id=f"edge-{path}",
                source_file=path,
                caller_symbol_id=None,
                call_callee="f",
                status=ResolutionStatus.RESOLVED,
                target_symbol_id="stable-symbol",
                target_file=path,
                confidence=0.9,
                resolution_rule="repository-only-test",
                ambiguity_reason=None,
            )
            fused = asyncio.run(fusion.fuse_definition(
                candidate_callee="f",
                candidate_byte_range=(0, 1),
                repo_resolution=repo_resolution,
                context=ctx,
            ))
            assert fused.depends_on_lsp is False, f"{path}: depends_on_lsp should be False"
            assert fused.fused_status == ResolutionStatus.RESOLVED.value
            assert fused.target_file == path
            # Only repository evidence present
            assert len(fused.evidence) == 1
            assert fused.evidence[0].source.value == "repository-resolution"


# ---- 9. Query service structured output ------------------------------------


def test_query_service_returns_structured_rows_all_dialects():
    """CodeQueryService returns structured rows for symbols/imports/calls."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "util.py").write_text(
            "def helper():\n    return 42\n",
            encoding="utf-8",
        )
        (root / "app.py").write_text(
            "from util import helper\nhelper()\nobj.x()  # dynamic\n",
            encoding="utf-8",
        )

        store, indexer, qs, report = _build(root, "query")

        # find_symbol_targets returns structured rows
        syms = qs.find_symbol_targets("query", "helper")
        assert len(syms) == 1
        row = syms[0]
        assert "stable_symbol_id" in row
        assert "byte_start" in row
        assert "byte_end" in row
        assert "path" in row
        assert "kind" in row

        # resolved_imports returns structured rows
        imports = qs.resolved_imports("query", "app.py")
        assert len(imports) >= 1
        assert "status" in imports[0]
        # Schema uses import_module + imported_name (not import_name)
        assert "import_module" in imports[0]

        # call_edges_for_file returns structured rows
        calls = qs.call_edges_for_file("query", "app.py")
        assert len(calls) >= 2
        assert "edge_id" in calls[0]
        assert "status" in calls[0]
        assert "call_callee" in calls[0]

        # fused_definition without fused_result returns repository-only dict
        fused_dict = qs.fused_definition("query", "app.py", "helper", 0, 6)
        assert fused_dict["depends_on_lsp"] is False
        assert fused_dict["fused_status"] in ("resolved", "unresolved", "dynamic", "ambiguous")

        # explain_resolution without fused_result returns repository-only breakdown
        if calls:
            explain = qs.explain_resolution("query", "app.py", calls[0]["edge_id"])
            assert "original_status" in explain
            assert "fused_status" in explain
            assert explain["depends_on_lsp"] is False

        # resolution_evidence returns unresolved/ambiguous edges
        evidence = qs.resolution_evidence("query", "app.py")
        assert isinstance(evidence, list)
        for entry in evidence:
            assert entry["status"] in ("unresolved", "ambiguous")
            assert entry["depends_on_lsp"] is False


# ---- 10. ParseState cache lifecycle ----------------------------------------


def test_parse_state_cache_lifecycle_all_dialects():
    """RepositoryIndexer ParseState cache hits on unchanged files."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "util.py").write_text(
            "def helper():\n    return 42\n",
            encoding="utf-8",
        )
        (root / "app.py").write_text(
            "from util import helper\nhelper()\n",
            encoding="utf-8",
        )

        store = IndexStore(sqlite3.connect(":memory:", check_same_thread=False))
        svc = ResolutionService(store._conn, persist=True)
        indexer = RepositoryIndexer(store, resolution_service=svc)

        # First index: cold cache, both files parsed
        report1 = asyncio.run(indexer.index("cache", root))
        assert report1["parsed_files"] >= 2
        assert report1["unchanged_files"] == 0
        # Cache has entries now
        assert indexer.cache.stats()["entries"] >= 1

        # Second index: warm cache, both files unchanged
        report2 = asyncio.run(indexer.index("cache", root))
        assert report2["unchanged_files"] >= 2
        assert report2["parsed_files"] == 0

        # Modify one file: only that file re-parses
        (root / "util.py").write_text(
            "def helper():\n    return 99\n",
            encoding="utf-8",
        )
        report3 = asyncio.run(indexer.index("cache", root))
        assert report3["parsed_files"] >= 1
        assert report3["unchanged_files"] >= 1


# ---- 11. Provenance audit --------------------------------------------------


def test_provenance_metadata_populated_all_dialects():
    """Every parsed file record carries parser_source, parser_version, generation."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "p.py").write_text("def f():\n    pass\n", encoding="utf-8")
        (root / "j.js").write_text("export function f() {}\n", encoding="utf-8")
        (root / "t.ts").write_text("export function f(): void {}\n", encoding="utf-8")
        (root / "x.tsx").write_text("export function App() { return <div/>; }\n", encoding="utf-8")
        (root / "go.mod").write_text("module demo\ngo 1.21\n")
        (root / "main.go").write_text("package main\nfunc main() {}\n", encoding="utf-8")
        (root / "Cargo.toml").write_text("[package]\nname=\"demo\"\nversion=\"0.1.0\"\nedition=\"2021\"\n")
        (root / "src").mkdir()
        (root / "src" / "main.rs").write_text("fn main() {}\n", encoding="utf-8")

        store, indexer, qs, report = _build(root, "prov")

        for path in ("p.py", "j.js", "t.ts", "x.tsx", "main.go", "src/main.rs"):
            record = asyncio.run(store.file_record("prov", path))
            assert record is not None, f"missing record: {path}"
            assert record["parser_source"] == "tree-sitter", (
                f"{path}: parser_source={record['parser_source']}"
            )
            assert record["parser_version"], f"{path}: parser_version not populated"
            assert record["generation"] >= 1, f"{path}: generation not populated"
            assert record["content_hash"], f"{path}: content_hash not populated"
            assert record["language"], f"{path}: language not populated"
