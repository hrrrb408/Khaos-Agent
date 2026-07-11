from __future__ import annotations

import concurrent.futures
import importlib.resources
from dataclasses import replace
from pathlib import Path

import pytest

pytestmark = pytest.mark.tree_sitter_real

tree_sitter = pytest.importorskip("tree_sitter")

from khaos.coding.intelligence import LanguageRegistry
from khaos.coding.intelligence.adapters import GRAMMARS, TreeSitterAdapter
import khaos.coding.intelligence.adapters as adapter_module


FIXTURES = Path(__file__).parents[1] / "fixtures" / "intelligence"


@pytest.mark.parametrize(("extension", "dialect", "abi"), [("py", "python", 15), ("js", "javascript", 15), ("ts", "typescript", 14), ("tsx", "tsx", 14), ("go", "go", 15), ("rs", "rust", 15)])
def test_real_parser_initializes_and_records_locked_metadata(extension: str, dialect: str, abi: int) -> None:
    path = FIXTURES / (f"sample.{extension}" if extension != "tsx" else "sample.ts")
    result = LanguageRegistry().parse(file_path=f"sample.{extension}", content=path.read_bytes())
    assert result.parser_source == "tree-sitter"
    assert result.parser_version == "0.26.0"
    assert result.metadata.grammar_version != result.parser_version
    assert result.metadata.grammar_dialect == dialect
    assert result.metadata.grammar_abi == abi
    assert tree_sitter.MIN_COMPATIBLE_LANGUAGE_VERSION <= abi <= tree_sitter.LANGUAGE_VERSION
    assert result.calls == () and result.references == ()


@pytest.mark.parametrize("extension", ["py", "js", "ts", "go", "rs"])
def test_real_fixtures_extract_stable_symbols_imports_and_offsets(extension: str) -> None:
    path = FIXTURES / f"sample.{extension}"
    content = path.read_bytes()
    result = LanguageRegistry().parse(file_path=str(path), content=content)
    assert result.symbols and result.imports
    assert all(item.source == "tree-sitter" for item in (*result.symbols, *result.imports))
    assert list(result.symbols) == sorted(result.symbols, key=lambda item: (item.location.byte_start, item.location.byte_end, item.kind, item.name))
    for symbol in result.symbols:
        assert content[symbol.location.byte_start:symbol.location.byte_end].decode() == symbol.name
    again = LanguageRegistry().parse(file_path=str(path), content=content)
    assert result.to_dict(include_duration=False) == again.to_dict(include_duration=False)


def test_symbol_coverage_and_qualified_names() -> None:
    cases = {
        "py": b"class C:\n def m(self):\n  def nested(): pass\nasync def af(): pass\n",
        "js": b"export class C { *gen() {} m() {} }\nconst arrow = () => 1; function f() {}",
        "ts": b"interface I{} type T=string; enum E{A}; namespace N { export function f(){} } class C { m(){} } const arrow=()=>1;",
        "tsx": b"interface P{}; const App = (p:P) => <div/>;",
        "go": b"package p\ntype S struct{}\ntype I interface{ M() }\ntype N string\nfunc (S) M(){}\nfunc F(){}\nconst Public=1\nvar Value=2\n",
        "rs": b"mod m { pub struct S; enum E{A} trait T{} type A=u8; impl S { fn method(&self){} } macro_rules! mac {()=>{}} }",
    }
    for extension, content in cases.items():
        result = LanguageRegistry().parse(file_path=f"x.{extension}", content=content)
        assert result.parser_source == "tree-sitter"
        assert len(result.symbols) >= 2
    python = LanguageRegistry().parse(file_path="x.py", content=cases["py"])
    assert {item.qualified_name for item in python.symbols} >= {"C.m", "C.m.nested", "af"}


@pytest.mark.parametrize(("extension", "content", "module", "alias"), [
    ("py", b"import os as operating\nfrom .x import y\nfrom pkg import *\n", "os", "operating"),
    ("js", b'import value from "pkg"; import * as ns from "space"; import "side"; export {x} from "other";', "space", "ns"),
    ("ts", b'import {A as B} from "pkg"; export * from "other";', "pkg", "B"),
    ("go", b'package p\nimport ( alias "one"\n_ "two"\n. "three" )', "one", "alias"),
    ("rs", b"use crate::{a, b::C};\nuse other::*;\nuse thing::X as Y;\nextern crate core;", "thing::X", "Y"),
])
def test_import_coverage_alias_group_and_nested(extension: str, content: bytes, module: str, alias: str | None) -> None:
    result = LanguageRegistry().parse(file_path=f"x.{extension}", content=content)
    assert any(item.module == module and item.alias == alias for item in result.imports)
    assert list(result.imports) == sorted(result.imports, key=lambda item: (item.location.byte_start, int(item.metadata.get("item_byte_start", item.location.byte_start)), item.module, item.alias or ""))


@pytest.mark.parametrize("content", ["😀 = 1\ndef 函数(): pass", "e\u0301 = 1\r\ndef 函数(): pass", "前缀 = '😀'; def 函数(): pass"])
def test_unicode_code_point_columns_crlf_and_byte_offsets(content: str) -> None:
    raw = content.encode()
    result = LanguageRegistry().parse(file_path="unicode.py", content=raw)
    target = next(item for item in result.symbols if item.name == "函数")
    assert raw[target.location.byte_start:target.location.byte_end] == "函数".encode()
    line = raw[:target.location.byte_start].split(b"\n")[-1].decode()
    assert target.location.start_column == len(line)


def test_error_node_returns_partial_results_and_diagnostic() -> None:
    content = b"import os\ndef safe(): pass\ndef broken(:\ndef later(): pass\n"
    result = LanguageRegistry().parse(file_path="broken.py", content=content)
    assert result.parser_source == "tree-sitter"
    assert any(item.name == "safe" for item in result.symbols)
    assert any(item.code == "parse-error" and item.recoverable for item in result.diagnostics)
    assert result.metadata.skipped_error_regions > 0
    assert all(item.confidence < 0.9 for item in result.symbols if item.name == "broken")


def test_empty_file_is_real_tree_sitter_result() -> None:
    result = LanguageRegistry().parse(file_path="empty.rs", content=b"")
    assert result.parser_source == "tree-sitter" and result.symbols == ()


def test_queries_are_packaged_resources_only() -> None:
    root = importlib.resources.files("khaos.coding.intelligence")
    for spec in GRAMMARS.values():
        assert root.joinpath(spec.query_resource_path, "symbols.scm").is_file()
        assert root.joinpath(spec.query_resource_path, "imports.scm").is_file()
    pyproject = Path("pyproject.toml").read_text(encoding="utf-8")
    assert '"khaos.coding.intelligence" = ["queries/**/*.scm"]' in pyproject


def test_loader_missing_version_abi_and_query_failures_are_structured(monkeypatch: pytest.MonkeyPatch) -> None:
    adapter = TreeSitterAdapter("python", frozenset({".py"}))
    original = GRAMMARS["python"]
    monkeypatch.setitem(GRAMMARS, "python", replace(original, loader_name="not_a_loader"))
    assert adapter.availability("x.py").code == "grammar-loader-missing"
    monkeypatch.setitem(GRAMMARS, "python", replace(original, expected_package_version="0.0.0"))
    assert TreeSitterAdapter("python", frozenset({".py"})).availability("x.py").code == "grammar-version-mismatch"
    monkeypatch.setitem(GRAMMARS, "python", original)
    monkeypatch.setattr(tree_sitter, "MIN_COMPATIBLE_LANGUAGE_VERSION", 16)
    assert TreeSitterAdapter("python", frozenset({".py"})).availability("x.py").code == "grammar-abi-incompatible"
    monkeypatch.setattr(tree_sitter, "MIN_COMPATIBLE_LANGUAGE_VERSION", 13)
    monkeypatch.setattr(adapter_module, "_query_text", lambda *_args: "(definitely_not_a_node) @x")
    assert TreeSitterAdapter("python", frozenset({".py"})).availability("x.py").code == "query-invalid"


def test_concurrent_real_parsing_is_isolated_and_deterministic() -> None:
    registry = LanguageRegistry()
    paths = [FIXTURES / f"sample.{ext}" for ext in ("py", "js", "ts", "go", "rs")]
    work = paths * 5
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
        results = list(pool.map(lambda path: registry.parse(file_path=str(path), content=path.read_bytes()), work))
    assert all(result.parser_source == "tree-sitter" for result in results)
    for index in range(5):
        group = [results[index + offset * 5].to_dict(include_duration=False) for offset in range(5)]
        assert all(item == group[0] for item in group)


def test_legacy_symbol_mapping_compatibility_with_real_parser() -> None:
    result = LanguageRegistry().for_path(Path("x.py")).parse(Path("x.py"), b"def run(): pass")
    assert result.symbols[0]["name"] == "run"
    assert result.symbols[0]["line"] == 1
