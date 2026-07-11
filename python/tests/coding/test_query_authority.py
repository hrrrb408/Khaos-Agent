from __future__ import annotations

import inspect
from pathlib import Path

import pytest

pytestmark = pytest.mark.tree_sitter_real
pytest.importorskip("tree_sitter")

from khaos.coding.intelligence import LanguageRegistry
from khaos.coding.intelligence.adapters import TreeSitterAdapter
import khaos.coding.intelligence.adapters as adapter_module


QUERY_ROOT = Path(__file__).resolve().parents[2] / "khaos" / "coding" / "intelligence" / "queries"


def test_symbol_queries_have_no_wildcard_candidate() -> None:
    for path in QUERY_ROOT.glob("*/symbols.scm"):
        text = path.read_text(encoding="utf-8")
        assert "(_) @candidate" not in text
        assert "@definition." in text and "@name" in text


def test_query_is_authoritative_when_class_pattern_is_removed(monkeypatch: pytest.MonkeyPatch) -> None:
    original = adapter_module._query_text

    def without_class(spec, name):
        text = original(spec, name)
        if name == "symbols.scm":
            return "\n".join(line for line in text.splitlines() if "class_definition" not in line)
        return text

    monkeypatch.setattr(adapter_module, "_query_text", without_class)
    adapter = TreeSitterAdapter("python", frozenset({".py"}))
    result = adapter.parse(file_path="x.py", content=b"class Hidden: pass\ndef visible(): pass\n")
    assert {item.name for item in result.symbols} == {"visible"}


def test_non_declaration_nodes_never_become_symbols() -> None:
    content = b"value = call(other.attr)\nitems = [x for x in range(100)]\nclass Real: pass\n"
    result = LanguageRegistry().parse(file_path="x.py", content=content)
    assert [item.name for item in result.symbols] == ["Real"]
    assert result.metadata.symbol_query_match_count == 1


@pytest.mark.parametrize("extension", ["py", "js", "ts", "tsx", "go", "rs"])
def test_every_symbol_is_backed_by_name_and_definition_capture(extension: str) -> None:
    content = {
        "py": b"class C: pass\ndef f(): pass\n",
        "js": b"class C {} function f() {}",
        "ts": b"interface I {} function f() {}",
        "tsx": b"interface P {} const App = () => <div/>;",
        "go": b"package p\ntype S struct{}\nfunc F(){}",
        "rs": b"struct S; fn f() {}",
    }[extension]
    result = LanguageRegistry().parse(file_path=f"x.{extension}", content=content)
    for symbol in result.symbols:
        assert symbol.metadata["definition_byte_start"] <= symbol.location.byte_start
        assert symbol.metadata["definition_byte_end"] >= symbol.location.byte_end
        assert isinstance(symbol.metadata["query_pattern"], int)
        assert content[symbol.location.byte_start:symbol.location.byte_end].decode() == symbol.name
    assert len(result.symbols) <= result.metadata.symbol_query_match_count


def test_tree_sitter_import_path_has_no_text_regex_parser() -> None:
    source = inspect.getsource(adapter_module)
    assert "def _parse_import_text" not in source
    assert "_parse_import_text(" not in source


def test_python_multi_import_aliases_are_structured_and_stable() -> None:
    content = b"import os, sys as system\nfrom .pkg import one as first, two\n"
    first = LanguageRegistry().parse(file_path="x.py", content=content)
    second = LanguageRegistry().parse(file_path="x.py", content=content)
    values = [(item.module, item.imported_names, item.alias) for item in first.imports]
    assert values == [("os", (), None), ("sys", (), "system"), (".pkg", ("one",), "first"), (".pkg", ("two",), None)]
    assert first.to_dict(include_duration=False) == second.to_dict(include_duration=False)


def test_javascript_typescript_import_metadata_and_aliases() -> None:
    js = LanguageRegistry().parse(file_path="x.js", content=b'import {old as renamed} from "pkg"; import "side";')
    assert any(item.imported_names == ("old",) and item.alias == "renamed" for item in js.imports)
    assert any(item.module == "side" and item.metadata["side_effect"] for item in js.imports)
    ts = LanguageRegistry().parse(file_path="x.ts", content=b'import type {Thing as Alias} from "types";')
    assert ts.imports[0].alias == "Alias" and ts.imports[0].metadata["type_only"] is True


def test_go_and_rust_import_trees_expand_structurally() -> None:
    go = LanguageRegistry().parse(file_path="x.go", content=b'package p\nimport (_ "blank"\n. "dot"\nalias "pkg")')
    assert {(item.module, item.alias) for item in go.imports} == {("blank", "_"), ("dot", "."), ("pkg", "alias")}
    rust = LanguageRegistry().parse(file_path="x.rs", content=b"use crate::{a, b::C}; use other::*; use thing::X as Y;")
    assert {(item.module, item.alias) for item in rust.imports} >= {("crate::a", None), ("crate::b::C", None), ("thing::X", "Y")}
    assert any(item.module == "other" and item.metadata["glob"] for item in rust.imports)


def test_large_file_query_matches_scale_with_declarations_not_ast_nodes() -> None:
    expressions = "\n".join(f"value_{index} = ({index} + 1) * 2" for index in range(2000))
    source = f"import os\n{expressions}\nclass OnlyClass: pass\ndef only_function(): pass\n".encode()
    result = LanguageRegistry().parse(file_path="large.py", content=source)
    assert result.metadata.ast_node_count > 10_000
    assert result.metadata.symbol_query_match_count == 2
    assert result.metadata.import_query_match_count == 1
    assert len(result.symbols) == 2 and len(result.imports) == 1
    assert result.metadata.symbol_query_match_count / result.metadata.ast_node_count < 0.001


def test_syntax_error_preserves_query_matches_outside_error_region() -> None:
    result = LanguageRegistry().parse(file_path="broken.py", content=b"import os\ndef safe(): pass\ndef broken(:\ndef later(): pass\n")
    assert result.parser_source == "tree-sitter"
    assert any(item.name == "safe" for item in result.symbols)
    assert any(item.module == "os" for item in result.imports)
    assert any(item.code == "parse-error" for item in result.diagnostics)
