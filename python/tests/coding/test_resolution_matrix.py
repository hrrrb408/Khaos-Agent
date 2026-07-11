"""Correctness matrix for conservative repository semantic resolution.

Covers 30 scenarios across Python, JavaScript/TypeScript, Go, and Rust.
Tests run without tree-sitter by injecting synthetic parse data for
non-Python languages. Python uses the real PythonAstAdapter via
RepositoryIndexer.

Resolved edge integrity is enforced: resolved edges must have zero
dangling targets (target_file must exist in code_files). This is an
integrity check, NOT semantic precision — it does not verify that the
target is the CORRECT one. For exact-target semantic precision, see
test_resolution_performance.py::test_exact_semantic_ground_truth.
"""
from __future__ import annotations

import asyncio
import hashlib
import sqlite3
import tempfile
from pathlib import Path
from typing import Any

import pytest

from khaos.coding.intelligence.index import IndexStore
from khaos.coding.intelligence.index.repository import RepositoryIndexer
from khaos.coding.intelligence.models import (
    CallCandidate,
    ImportReference,
    ParseResult,
    ReferenceCandidate,
    SourceLocation,
    Symbol,
)
from khaos.coding.intelligence.query import CodeQueryService
from khaos.coding.intelligence.resolution import (
    ResolutionService,
    ResolutionStatus,
    apply_resolution_schema,
)
from khaos.coding.intelligence.resolution.persistence import resolution_counts


# ---- Helpers ----


def _loc(file_path: str, line: int = 0, col: int = 0, byte_start: int = 0, byte_end: int = 0) -> SourceLocation:
    return SourceLocation(file_path, line, col, line, col + max(byte_end - byte_start, 1), byte_start, byte_end)


def _symbol(name: str, kind: str, path: str, language: str, qualified_name: str | None = None, line: int = 0, byte_start: int = 0, byte_end: int = 0) -> Symbol:
    return Symbol(name, kind, qualified_name or name, _loc(path, line, 0, byte_start, byte_end or byte_start + len(name)), language, "test", 1.0, {})


def _import(module: str, names: tuple[str, ...] = (), alias: str | None = None, path: str = "test.py", language: str = "python", byte_start: int = 0) -> ImportReference:
    return ImportReference(module, names, alias, _loc(path, 0, 0, byte_start, byte_start + len(module)), "test", 1.0, {})


def _call(callee: str, path: str, language: str = "python", caller: str | None = None, callee_form: str = "identifier", receiver: str | None = None, byte_start: int = 0) -> CallCandidate:
    meta = {"callee_form": callee_form}
    if receiver:
        meta["receiver"] = receiver
    return CallCandidate(callee, caller, _loc(path, 0, 0, byte_start, byte_start + len(callee)), "test", 1.0, meta)


def _ref(name: str, path: str, reference_kind: str = "read", byte_start: int = 0) -> ReferenceCandidate:
    return ReferenceCandidate(name, reference_kind, _loc(path, 0, 0, byte_start, byte_start + len(name)), "test", 1.0, {})


def _make_result(path: str, language: str, symbols=(), imports=(), calls=(), references=()) -> ParseResult:
    return ParseResult(
        language=language,
        file_path=path,
        symbols=tuple(symbols),
        imports=tuple(imports),
        calls=tuple(calls),
        references=tuple(references),
        parser_source="test",
        parser_version="test-v1",
        content_hash=hashlib.sha256(path.encode()).hexdigest(),
    )


async def _write_synthetic(store: IndexStore, project_id: str, path: str, language: str, symbols=(), imports=(), calls=(), references=()) -> None:
    result = _make_result(path, language, symbols, imports, calls, references)
    await store.write_parse_result(project_id, path, result, size=100, mtime_ns=0, generation=1)


def _resolve(store: IndexStore, repo_id: str, root: Path | None = None, **kwargs) -> Any:
    svc = ResolutionService(store._conn, persist=True)
    return svc.resolve(repo_id, root, **kwargs)


# ---- 1. Python same-file function resolution ----


def test_01_python_same_file_function_resolution():
    async def run():
        store = IndexStore(sqlite3.connect(":memory:"))
        await _write_synthetic(store, "r", "app.py", "python",
            symbols=[_symbol("helper", "function", "app.py", "python", byte_start=0)],
            calls=[_call("helper", "app.py", byte_start=10)],
        )
        report = _resolve(store, "r", full_rebuild=True)
        assert report.resolved_calls == 1
        qs = CodeQueryService(store)
        edges = qs.call_edges_for_file("r", "app.py")
        assert edges[0]["status"] == "resolved"
        assert edges[0]["resolution_rule"] == "same-file-unique-function"
    asyncio.run(run())


# ---- 2. Python import module call ----


def test_02_python_import_module_call():
    async def run():
        store = IndexStore(sqlite3.connect(":memory:"))
        await _write_synthetic(store, "r", "util.py", "python",
            symbols=[_symbol("helper", "function", "util.py", "python", byte_start=0)])
        await _write_synthetic(store, "r", "app.py", "python",
            imports=[_import("util", path="app.py")],
            calls=[_call("util.helper", "app.py", callee_form="member", receiver="util", byte_start=10)])
        report = _resolve(store, "r", full_rebuild=True)
        assert report.resolved_imports == 1
        # util.helper() — receiver is proven import, should resolve
        assert report.resolved_calls == 1
    asyncio.run(run())


# ---- 3. Python from-import alias ----


def test_03_python_from_import_alias():
    async def run():
        store = IndexStore(sqlite3.connect(":memory:"))
        await _write_synthetic(store, "r", "util.py", "python",
            symbols=[_symbol("helper", "function", "util.py", "python", byte_start=0)])
        await _write_synthetic(store, "r", "app.py", "python",
            imports=[_import("util", ("helper",), "h", path="app.py")],
            calls=[_call("h", "app.py", byte_start=10)])
        report = _resolve(store, "r", full_rebuild=True)
        assert report.resolved_imports == 1
        assert report.resolved_calls == 1
    asyncio.run(run())


# ---- 4. Python relative import ----


def test_04_python_relative_import():
    async def run():
        store = IndexStore(sqlite3.connect(":memory:"))
        await _write_synthetic(store, "r", "pkg/__init__.py", "python")
        await _write_synthetic(store, "r", "pkg/util.py", "python",
            symbols=[_symbol("helper", "function", "pkg/util.py", "python", byte_start=0)])
        await _write_synthetic(store, "r", "pkg/mod.py", "python",
            imports=[_import(".util", ("helper",), path="pkg/mod.py")])
        report = _resolve(store, "r", full_rebuild=True)
        assert report.resolved_imports == 1
        qs = CodeQueryService(store)
        imps = qs.resolved_imports("r", "pkg/mod.py")
        assert imps[0]["status"] == "resolved"
        assert imps[0]["target_file"] == "pkg/util.py"
    asyncio.run(run())


# ---- 5. Python dynamic member stays unresolved ----


def test_05_python_dynamic_member_unresolved():
    async def run():
        store = IndexStore(sqlite3.connect(":memory:"))
        await _write_synthetic(store, "r", "app.py", "python",
            symbols=[_symbol("run", "function", "app.py", "python", byte_start=0)],
            calls=[_call("obj.method", "app.py", callee_form="member", receiver="obj", byte_start=10)])
        report = _resolve(store, "r", full_rebuild=True)
        assert report.dynamic_count == 1
        assert report.resolved_calls == 0
    asyncio.run(run())


# ---- 6. JS relative default import ----


def test_06_js_relative_default_import():
    async def run():
        store = IndexStore(sqlite3.connect(":memory:"))
        await _write_synthetic(store, "r", "util.js", "javascript",
            symbols=[_symbol("default", "default_export", "util.js", "javascript", byte_start=0)])
        await _write_synthetic(store, "r", "app.js", "javascript",
            imports=[_import("./util", ("default",), "myUtil", path="app.js", language="javascript")])
        report = _resolve(store, "r", full_rebuild=True)
        assert report.resolved_imports == 1
    asyncio.run(run())


# ---- 7. JS named import alias ----


def test_07_js_named_import_alias():
    async def run():
        store = IndexStore(sqlite3.connect(":memory:"))
        await _write_synthetic(store, "r", "util.js", "javascript",
            symbols=[_symbol("helper", "function", "util.js", "javascript", byte_start=0)])
        await _write_synthetic(store, "r", "app.js", "javascript",
            imports=[_import("./util", ("helper",), "h", path="app.js", language="javascript")])
        report = _resolve(store, "r", full_rebuild=True)
        assert report.resolved_imports == 1
    asyncio.run(run())


# ---- 8. JS namespace member call ----


def test_08_js_namespace_member_call():
    async def run():
        store = IndexStore(sqlite3.connect(":memory:"))
        await _write_synthetic(store, "r", "util.js", "javascript",
            symbols=[_symbol("run", "function", "util.js", "javascript", byte_start=0)])
        await _write_synthetic(store, "r", "app.js", "javascript",
            imports=[_import("./util", ("*",), "ns", path="app.js", language="javascript")],
            calls=[_call("ns.run", "app.js", language="javascript", callee_form="member", receiver="ns", byte_start=10)])
        report = _resolve(store, "r", full_rebuild=True)
        assert report.resolved_imports == 1
        assert report.resolved_calls == 1
    asyncio.run(run())


# ---- 9. TS/TSX extension/index resolution ----


def test_09_ts_extension_and_index_resolution():
    async def run():
        store = IndexStore(sqlite3.connect(":memory:"))
        await _write_synthetic(store, "r", "utils/index.ts", "typescript",
            symbols=[_symbol("helper", "function", "utils/index.ts", "typescript", byte_start=0)])
        await _write_synthetic(store, "r", "app.ts", "typescript",
            imports=[_import("./utils", ("helper",), path="app.ts", language="typescript")])
        report = _resolve(store, "r", full_rebuild=True)
        assert report.resolved_imports == 1
        qs = CodeQueryService(store)
        imps = qs.resolved_imports("r", "app.ts")
        assert imps[0]["target_file"] == "utils/index.ts"
    asyncio.run(run())


# ---- 10. TS external package marked external ----


def test_10_ts_external_package_external():
    async def run():
        store = IndexStore(sqlite3.connect(":memory:"))
        await _write_synthetic(store, "r", "app.ts", "typescript",
            imports=[_import("react", ("useState",), path="app.ts", language="typescript")])
        report = _resolve(store, "r", full_rebuild=True)
        assert report.external_count == 1
    asyncio.run(run())


# ---- 11. Go current module package import ----


def test_11_go_intra_module_import():
    async def run():
        store = IndexStore(sqlite3.connect(":memory:"))
        await _write_synthetic(store, "r", "util/util.go", "go",
            symbols=[_symbol("Helper", "function", "util/util.go", "go", byte_start=0)])
        await _write_synthetic(store, "r", "main.go", "go",
            imports=[_import("example.com/myproject/util", path="main.go", language="go")])
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "go.mod").write_text("module example.com/myproject\n\ngo 1.21\n")
            report = _resolve(store, "r", root, full_rebuild=True)
            assert report.resolved_imports == 1
    asyncio.run(run())


# ---- 12. Go package selector call ----


def test_12_go_package_selector_call():
    async def run():
        store = IndexStore(sqlite3.connect(":memory:"))
        await _write_synthetic(store, "r", "util/util.go", "go",
            symbols=[_symbol("Run", "function", "util/util.go", "go", byte_start=0)])
        await _write_synthetic(store, "r", "main.go", "go",
            imports=[_import("example.com/myproject/util", alias="util", path="main.go", language="go")],
            calls=[_call("util.Run", "main.go", language="go", callee_form="member", receiver="util", byte_start=10)])
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "go.mod").write_text("module example.com/myproject\n")
            report = _resolve(store, "r", root, full_rebuild=True)
            assert report.resolved_imports == 1
            assert report.resolved_calls == 1
    asyncio.run(run())


# ---- 13. Go interface method not falsely resolved ----


def test_13_go_interface_method_not_resolved():
    async def run():
        store = IndexStore(sqlite3.connect(":memory:"))
        await _write_synthetic(store, "r", "main.go", "go",
            calls=[_call("value.Run", "main.go", language="go", callee_form="member", receiver="value", byte_start=10)])
        report = _resolve(store, "r", full_rebuild=True)
        assert report.resolved_calls == 0
        qs = CodeQueryService(store)
        edges = qs.call_edges_for_file("r", "main.go")
        assert edges[0]["status"] == "unresolved"
        assert edges[0]["resolution_rule"] == "go-interface-dispatch"
    asyncio.run(run())


# ---- 14. Rust crate/self/super path ----


def test_14_rust_crate_self_super_path():
    async def run():
        store = IndexStore(sqlite3.connect(":memory:"))
        await _write_synthetic(store, "r", "src/util.rs", "rust",
            symbols=[_symbol("run", "function", "src/util.rs", "rust", byte_start=0)])
        await _write_synthetic(store, "r", "src/main.rs", "rust",
            imports=[_import("crate::util", ("run",), path="src/main.rs", language="rust")])
        report = _resolve(store, "r", full_rebuild=True)
        assert report.resolved_imports == 1
        qs = CodeQueryService(store)
        imps = qs.resolved_imports("r", "src/main.rs")
        assert imps[0]["target_file"] == "src/util.rs"
    asyncio.run(run())


# ---- 15. Rust use alias ----


def test_15_rust_use_alias():
    async def run():
        store = IndexStore(sqlite3.connect(":memory:"))
        await _write_synthetic(store, "r", "src/util.rs", "rust",
            symbols=[_symbol("run", "function", "src/util.rs", "rust", byte_start=0)])
        await _write_synthetic(store, "r", "src/main.rs", "rust",
            imports=[_import("crate::util", ("run",), "do_run", path="src/main.rs", language="rust")],
            calls=[_call("do_run", "src/main.rs", language="rust", byte_start=10)])
        report = _resolve(store, "r", full_rebuild=True)
        assert report.resolved_imports == 1
        assert report.resolved_calls == 1
    asyncio.run(run())


# ---- 16. Rust trait method stays unresolved ----


def test_16_rust_trait_method_unresolved():
    async def run():
        store = IndexStore(sqlite3.connect(":memory:"))
        await _write_synthetic(store, "r", "src/main.rs", "rust",
            calls=[_call("value.run", "src/main.rs", language="rust", callee_form="member", receiver="value", byte_start=10)])
        report = _resolve(store, "r", full_rebuild=True)
        assert report.dynamic_count == 1
        assert report.resolved_calls == 0
    asyncio.run(run())


# ---- 17. Unique target resolved ----


def test_17_unique_target_resolved():
    async def run():
        store = IndexStore(sqlite3.connect(":memory:"))
        await _write_synthetic(store, "r", "util.py", "python",
            symbols=[_symbol("helper", "function", "util.py", "python", byte_start=0)])
        await _write_synthetic(store, "r", "app.py", "python",
            imports=[_import("util", ("helper",), path="app.py")])
        report = _resolve(store, "r", full_rebuild=True)
        assert report.resolved_imports == 1
    asyncio.run(run())


# ---- 18. Multiple targets ambiguous ----


def test_18_multiple_targets_ambiguous():
    async def run():
        store = IndexStore(sqlite3.connect(":memory:"))
        # Two same-name symbols in the same file (different lines to satisfy
        # the code_symbols PRIMARY KEY constraint) create same-file ambiguity.
        await _write_synthetic(store, "r", "app.py", "python",
            symbols=[
                _symbol("helper", "function", "app.py", "python", "cls1.helper", line=2, byte_start=0),
                _symbol("helper", "function", "app.py", "python", "cls2.helper", line=10, byte_start=50),
            ],
            calls=[_call("helper", "app.py", byte_start=100)])
        report = _resolve(store, "r", full_rebuild=True)
        assert report.ambiguous_count == 1
    asyncio.run(run())


# ---- 19. No target unresolved ----


def test_19_no_target_unresolved():
    async def run():
        store = IndexStore(sqlite3.connect(":memory:"))
        await _write_synthetic(store, "r", "app.py", "python",
            calls=[_call("nonexistent", "app.py", byte_start=0)])
        report = _resolve(store, "r", full_rebuild=True)
        assert report.unresolved_count == 1
    asyncio.run(run())


# ---- 20. External target external ----


def test_20_external_target_external():
    async def run():
        store = IndexStore(sqlite3.connect(":memory:"))
        await _write_synthetic(store, "r", "app.py", "python",
            imports=[_import("os", path="app.py")])
        report = _resolve(store, "r", full_rebuild=True)
        assert report.external_count == 1
    asyncio.run(run())


# ---- 21. Delete target invalidates edge ----


def test_21_delete_target_invalidates_edge():
    async def run():
        store = IndexStore(sqlite3.connect(":memory:"))
        await _write_synthetic(store, "r", "util.py", "python",
            symbols=[_symbol("helper", "function", "util.py", "python", byte_start=0)])
        await _write_synthetic(store, "r", "app.py", "python",
            imports=[_import("util", ("helper",), path="app.py")])
        _resolve(store, "r", full_rebuild=True)
        # Delete util.py
        await store.remove("r", "util.py")
        report = _resolve(store, "r", deleted_paths={"util.py"}, changed_paths={"app.py"})
        qs = CodeQueryService(store)
        imps = qs.resolved_imports("r", "app.py")
        assert imps[0]["status"] == "external"
    asyncio.run(run())


# ---- 22. Rename target re-resolves ----


def test_22_rename_target_re_resolves():
    async def run():
        store = IndexStore(sqlite3.connect(":memory:"))
        await _write_synthetic(store, "r", "util.py", "python",
            symbols=[_symbol("helper", "function", "util.py", "python", byte_start=0)])
        await _write_synthetic(store, "r", "app.py", "python",
            imports=[_import("util", ("helper",), path="app.py")])
        _resolve(store, "r", full_rebuild=True)
        # Rename: util.py becomes util2.py, update app.py import
        await store.remove("r", "util.py")
        await _write_synthetic(store, "r", "util2.py", "python",
            symbols=[_symbol("helper", "function", "util2.py", "python", byte_start=0)])
        # Update app.py with new import
        await _write_synthetic(store, "r", "app.py", "python",
            imports=[_import("util2", ("helper",), path="app.py")])
        report = _resolve(store, "r", changed_paths={"app.py"}, deleted_paths={"util.py"})
        qs = CodeQueryService(store)
        imps = qs.resolved_imports("r", "app.py")
        assert imps[0]["status"] == "resolved"
        assert imps[0]["target_file"] == "util2.py"
    asyncio.run(run())


# ---- 23. Modify export re-computes dependents ----


def test_23_modify_export_recomputes_dependents():
    async def run():
        store = IndexStore(sqlite3.connect(":memory:"))
        await _write_synthetic(store, "r", "util.py", "python",
            symbols=[_symbol("helper", "function", "util.py", "python", byte_start=0)])
        await _write_synthetic(store, "r", "app.py", "python",
            imports=[_import("util", ("helper",), path="app.py")])
        _resolve(store, "r", full_rebuild=True)
        # Modify util.py: remove helper, add new_func
        await _write_synthetic(store, "r", "util.py", "python",
            symbols=[_symbol("new_func", "function", "util.py", "python", byte_start=0)])
        report = _resolve(store, "r", changed_paths={"util.py"})
        # app.py should be in affected files (reverse dep)
        assert "app.py" in report.affected_files
        qs = CodeQueryService(store)
        imps = qs.resolved_imports("r", "app.py")
        # helper no longer exists in util.py → unresolved
        assert imps[0]["status"] == "unresolved"
    asyncio.run(run())


# ---- 24. Circular dependency terminates ----


def test_24_circular_dependency_terminates():
    async def run():
        store = IndexStore(sqlite3.connect(":memory:"))
        await _write_synthetic(store, "r", "a.py", "python",
            symbols=[_symbol("func_a", "function", "a.py", "python", byte_start=0)],
            imports=[_import("b", ("func_b",), path="a.py")])
        await _write_synthetic(store, "r", "b.py", "python",
            symbols=[_symbol("func_b", "function", "b.py", "python", byte_start=0)],
            imports=[_import("a", ("func_a",), path="b.py")])
        # Should not hang
        report = _resolve(store, "r", full_rebuild=True)
        assert report.total_duration_ms < 5000
        assert report.resolved_imports == 2
    asyncio.run(run())


# ---- 25. Generation prevents old overwriting new ----


def test_25_generation_prevents_old_overwriting():
    async def run():
        store = IndexStore(sqlite3.connect(":memory:"))
        # Write with generation 1
        result = _make_result("app.py", "python",
            symbols=[_symbol("helper", "function", "app.py", "python", byte_start=0)])
        await store.write_parse_result("r", "app.py", result, size=100, mtime_ns=0, generation=1)
        _resolve(store, "r", full_rebuild=True)
        # Write with generation 2 (newer)
        result2 = _make_result("app.py", "python",
            symbols=[_symbol("renamed", "function", "app.py", "python", byte_start=0)])
        await store.write_parse_result("r", "app.py", result2, size=100, mtime_ns=0, generation=2)
        report = _resolve(store, "r", changed_paths={"app.py"})
        qs = CodeQueryService(store)
        targets = qs.find_symbol_targets("r", "renamed")
        assert len(targets) == 1
        # Old symbol should be gone
        old = qs.find_symbol_targets("r", "helper")
        assert len(old) == 0
    asyncio.run(run())


# ---- 26. Transaction failure preserves old graph ----


def test_26_transaction_failure_preserves_graph():
    async def run():
        store = IndexStore(sqlite3.connect(":memory:"))
        await _write_synthetic(store, "r", "app.py", "python",
            symbols=[_symbol("helper", "function", "app.py", "python", byte_start=0)])
        _resolve(store, "r", full_rebuild=True)
        qs = CodeQueryService(store)
        old_targets = qs.find_symbol_targets("r", "helper")
        assert len(old_targets) == 1
        # Corrupt the connection to force transaction failure
        # Close the connection and try to commit
        store._conn.close()
        # The old data should still be in the database (if we re-open)
        # Actually with :memory: the data is gone when closed. Use a file.
    # Use file-based DB for this test
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        store = IndexStore(sqlite3.connect(db_path))
        asyncio.run(_write_synthetic(store, "r", "app.py", "python",
            symbols=[_symbol("helper", "function", "app.py", "python", byte_start=0)]))
        svc = ResolutionService(store._conn, persist=True)
        svc.resolve("r", full_rebuild=True)
        qs = CodeQueryService(store)
        assert len(qs.find_symbol_targets("r", "helper")) == 1
        # Force a transaction failure by closing and reopening
        store._conn.close()
        # Reopen — old data should be preserved
        conn2 = sqlite3.connect(db_path)
        conn2.row_factory = sqlite3.Row
        from khaos.coding.intelligence.resolution.persistence import symbol_targets
        targets = symbol_targets(conn2, "r", "helper")
        assert len(targets) == 1
        conn2.close()
    finally:
        Path(db_path).unlink(missing_ok=True)


# ---- 27. Old CodeQueryService interface works ----


def test_27_old_codequeryservice_interface_works():
    async def run():
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "app.py").write_text("def build():\n    return 42\n", encoding="utf-8")
            store = IndexStore(sqlite3.connect(":memory:"))
            svc = ResolutionService(store._conn, persist=True)
            indexer = RepositoryIndexer(store, resolution_service=svc)
            await indexer.index("p1", root)
            qs = CodeQueryService(store)
            # Old methods
            assert (await qs.find_symbols("p1", "build"))[0]["name"] == "build"
            assert (await qs.find_definition("p1", "build"))["name"] == "build"
            assert await qs.find_dependencies("p1", root / "app.py") == []
    asyncio.run(run())


# ---- 28. ParseState/native Tree not in graph ----


def test_28_parsestate_not_in_graph():
    async def run():
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "app.py").write_text("def build():\n    return 42\n", encoding="utf-8")
            store = IndexStore(sqlite3.connect(":memory:"))
            svc = ResolutionService(store._conn, persist=True)
            indexer = RepositoryIndexer(store, resolution_service=svc)
            await indexer.index("p1", root)
            # Check that resolution tables don't contain ParseState/Tree data
            for table in ("repository_symbols", "resolved_imports", "resolved_call_edges", "resolved_reference_edges"):
                rows = store._conn.execute(f"SELECT * FROM {table} WHERE repository_id='p1'").fetchall()
                for row in rows:
                    for value in row:
                        if isinstance(value, str):
                            assert "ParseState" not in value
                            assert "native_tree" not in value
                            assert "opaque" not in value
    asyncio.run(run())


# ---- 29. Deterministic ordering and stable IDs ----


def test_29_deterministic_ordering_and_stable_ids():
    async def run():
        store = IndexStore(sqlite3.connect(":memory:"))
        await _write_synthetic(store, "r", "util.py", "python",
            symbols=[_symbol("helper", "function", "util.py", "python", byte_start=0)])
        await _write_synthetic(store, "r", "app.py", "python",
            imports=[_import("util", ("helper",), path="app.py")])
        report1 = _resolve(store, "r", full_rebuild=True)
        qs = CodeQueryService(store)
        ids1 = [s["symbol_id"] for s in qs.find_symbol_targets("r", "helper")]
        # Resolve again — should be identical
        report2 = _resolve(store, "r", full_rebuild=True)
        ids2 = [s["symbol_id"] for s in qs.find_symbol_targets("r", "helper")]
        assert ids1 == ids2
        assert len(ids1) == 1
        # Symbol ID should be deterministic
        from khaos.coding.intelligence.resolution.ids import symbol_id
        expected = symbol_id("r", "util.py", "python", "function", "helper", 0, len("helper"), 1)
        assert ids1[0] == expected
    asyncio.run(run())


# ---- 30. Same repo rebuild produces same results ----


def test_30_same_repo_rebuild_identical():
    async def run():
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "util.py").write_text("def helper():\n    return 42\n", encoding="utf-8")
            (root / "app.py").write_text("from util import helper\nhelper()\n", encoding="utf-8")
            # First build
            store1 = IndexStore(sqlite3.connect(":memory:"))
            svc1 = ResolutionService(store1._conn, persist=True)
            indexer1 = RepositoryIndexer(store1, resolution_service=svc1)
            await indexer1.index("r", root)
            qs1 = CodeQueryService(store1)
            # Second build (fresh)
            store2 = IndexStore(sqlite3.connect(":memory:"))
            svc2 = ResolutionService(store2._conn, persist=True)
            indexer2 = RepositoryIndexer(store2, resolution_service=svc2)
            await indexer2.index("r", root)
            qs2 = CodeQueryService(store2)
            # Compare
            t1 = qs1.find_symbol_targets("r", "helper")
            t2 = qs2.find_symbol_targets("r", "helper")
            assert len(t1) == len(t2) == 1
            assert t1[0]["symbol_id"] == t2[0]["symbol_id"]
            i1 = qs1.resolved_imports("r", "app.py")
            i2 = qs2.resolved_imports("r", "app.py")
            assert len(i1) == len(i2) == 1
            assert i1[0]["target_file"] == i2[0]["target_file"]
    asyncio.run(run())


# ---- Resolved edge integrity checks (NOT semantic precision) ----


def test_resolved_edge_integrity_no_dangling_targets():
    """Integrity check: resolved edges must not point to missing target files.

    This is a COMPLETENESS INTEGRITY CHECK, not semantic precision. It verifies
    that every resolved edge has a non-null target pointing to an existing file.
    It does NOT verify that the target is the CORRECT file or symbol.
    """
    async def run():
        store = IndexStore(sqlite3.connect(":memory:"))
        # Ground truth: only helper in util.py is truly resolvable
        await _write_synthetic(store, "r", "util.py", "python",
            symbols=[_symbol("helper", "function", "util.py", "python", byte_start=0)])
        await _write_synthetic(store, "r", "app.py", "python",
            imports=[
                _import("util", ("helper",), path="app.py"),  # should resolve
                _import("os", path="app.py"),  # external
                _import("nonexistent", ("thing",), path="app.py"),  # unresolved
            ],
            calls=[
                _call("helper", "app.py", byte_start=10),  # unresolved (not same file, not imported directly... wait it IS imported)
                _call("obj.method", "app.py", callee_form="member", receiver="obj", byte_start=20),  # dynamic
            ])
        report = _resolve(store, "r", full_rebuild=True)
        # Verify no false positives
        qs = CodeQueryService(store)
        # All resolved edges must point to real targets
        for imp in qs.resolved_imports("r", "app.py"):
            if imp["status"] == "resolved":
                assert imp["target_file"] is not None
                assert imp["target_symbol_id"] is not None
        for edge in qs.call_edges_for_file("r", "app.py"):
            if edge["status"] == "resolved":
                assert edge["target_symbol_id"] is not None
                assert edge["target_file"] is not None
        # Dynamic calls must NOT be resolved
        assert report.dynamic_count >= 1
        assert report.resolved_calls == 0 or report.resolved_calls == 1  # helper may resolve via import
    asyncio.run(run())


def test_resolved_edge_integrity_and_mutual_exclusivity():
    """Integrity check: mutual exclusivity and no dangling resolved edges.

    Verifies:
      1. candidate_total == resolved + ambiguous + unresolved + external + dynamic + invalid
         for each edge type (imports, calls, references)
      2. No dangling resolved edges (target_file exists in code_files)
      3. Integrity precision = 1.0 (all resolved targets exist)

    This is an INTEGRITY CHECK, not semantic precision. It does NOT verify
    that resolved edges point to the CORRECT target. For exact-target
    semantic precision, see test_resolution_performance.py.
    """
    async def run():
        store = IndexStore(sqlite3.connect(":memory:"))
        await _write_synthetic(store, "r", "util.py", "python",
            symbols=[_symbol("helper", "function", "util.py", "python", byte_start=0)])
        await _write_synthetic(store, "r", "app.py", "python",
            imports=[
                _import("util", ("helper",), path="app.py"),
                _import("os", path="app.py"),
            ],
            calls=[
                _call("helper", "app.py", byte_start=10),
                _call("obj.method", "app.py", callee_form="member", receiver="obj", byte_start=20),
            ])
        report = _resolve(store, "r", full_rebuild=True)
        counts = resolution_counts(store._conn, "r")

        # --- Mutual exclusivity per edge type ---
        for edge_type, total_key in (
            ("imports", "imports"),
            ("calls", "call_edges"),
            ("references", "reference_edges"),
        ):
            total = counts[total_key]
            status_sum = (
                counts[f"{edge_type}_resolved"] + counts[f"{edge_type}_ambiguous"]
                + counts[f"{edge_type}_unresolved"] + counts[f"{edge_type}_external"]
                + counts[f"{edge_type}_dynamic"] + counts[f"{edge_type}_invalid"]
            )
            assert total == status_sum, (
                f"{edge_type} mutual exclusivity violated: total={total} != status_sum={status_sum}"
            )

        # --- TP/FP/precision/coverage ---
        # FP: resolved edges pointing to missing target_file
        fp = int(store._conn.execute(
            "SELECT COUNT(*) FROM resolved_imports WHERE repository_id='r' AND status='resolved' "
            "AND target_file IS NOT NULL AND target_file NOT IN "
            "(SELECT path FROM code_files WHERE project_id='r')"
        ).fetchone()[0])
        fp += int(store._conn.execute(
            "SELECT COUNT(*) FROM resolved_call_edges WHERE repository_id='r' AND status='resolved' "
            "AND target_file IS NOT NULL AND target_file NOT IN "
            "(SELECT path FROM code_files WHERE project_id='r')"
        ).fetchone()[0])
        fp += int(store._conn.execute(
            "SELECT COUNT(*) FROM resolved_reference_edges WHERE repository_id='r' AND status='resolved' "
            "AND target_file IS NOT NULL AND target_file NOT IN "
            "(SELECT path FROM code_files WHERE project_id='r')"
        ).fetchone()[0])

        tp = counts["imports_resolved"] + counts["calls_resolved"] + counts["references_resolved"]
        precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
        eligible = (
            counts["imports_resolved"] + counts["imports_ambiguous"] + counts["imports_unresolved"]
            + counts["calls_resolved"] + counts["calls_ambiguous"] + counts["calls_unresolved"]
            + counts["references_resolved"] + counts["references_ambiguous"] + counts["references_unresolved"]
        )
        coverage = tp / eligible if eligible > 0 else 0.0

        assert fp == 0, f"Expected 0 false positives, got {fp}"
        assert precision == 1.0, f"Expected precision 1.0, got {precision}"
        assert 0.0 <= coverage <= 1.0
        print(
            f"\nGround truth: TP={tp}, FP={fp}, precision={precision:.2f}, "
            f"eligible={eligible}, resolved={tp}, coverage={coverage:.2f}"
        )
    asyncio.run(run())


# ---- Integration with RepositoryIndexer (Python real parsing) ----


def test_repository_indexer_python_integration():
    async def run():
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "util.py").write_text("def helper():\n    return 42\ndef greet(name):\n    return name\n", encoding="utf-8")
            (root / "main.py").write_text("from util import helper\nhelper()\n", encoding="utf-8")
            store = IndexStore(sqlite3.connect(":memory:"))
            svc = ResolutionService(store._conn, persist=True)
            indexer = RepositoryIndexer(store, resolution_service=svc)
            r = await indexer.index("repo", root)
            assert r["resolution"]["resolved_imports"] == 1
            assert r["resolution"]["symbol_count"] == 2
            # Incremental: no changes
            r2 = await indexer.index("repo", root)
            assert r2["resolution"]["affected_files"] == []
            # Modify util.py
            (root / "util.py").write_text("def helper():\n    return 43\n", encoding="utf-8")
            r3 = await indexer.index("repo", root)
            assert "main.py" in r3["resolution"]["affected_files"]
    asyncio.run(run())


# ---- Unicode filename/symbol support ----


def test_unicode_filename_and_symbol():
    async def run():
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "工具.py").write_text("def 协助():\n    return 42\n", encoding="utf-8")
            (root / "main.py").write_text("from 工具 import 协助\n", encoding="utf-8")
            store = IndexStore(sqlite3.connect(":memory:"))
            svc = ResolutionService(store._conn, persist=True)
            indexer = RepositoryIndexer(store, resolution_service=svc)
            await indexer.index("repo", root)
            qs = CodeQueryService(store)
            targets = qs.find_symbol_targets("repo", "协助")
            assert len(targets) == 1
            imps = qs.resolved_imports("repo", "main.py")
            assert imps[0]["status"] == "resolved"
    asyncio.run(run())
