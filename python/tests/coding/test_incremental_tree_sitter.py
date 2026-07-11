from __future__ import annotations

import concurrent.futures
import json
import pickle
from dataclasses import replace

import pytest

pytestmark = pytest.mark.tree_sitter_real
pytest.importorskip("tree_sitter")

from khaos.coding.intelligence import LanguageRegistry
from khaos.coding.intelligence.adapters import LegacyRegexAdapter, PythonAstAdapter, TreeSitterAdapter, byte_offset_to_tree_sitter_point, canonical_edit
from khaos.coding.intelligence.models import ParseState


def _assert_semantics_equal(incremental, full) -> None:
    assert incremental.symbols == full.symbols
    assert incremental.imports == full.imports
    assert incremental.calls == full.calls
    assert incremental.references == full.references
    assert incremental.diagnostics == full.diagnostics
    assert incremental.parser_source == full.parser_source
    assert incremental.parser_version == full.parser_version
    for name in ("grammar_name", "grammar_version", "grammar_abi", "grammar_dialect", "query_version", "semantic_refresh_mode"):
        assert getattr(incremental.metadata, name) == getattr(full.metadata, name)


def test_first_parse_returns_safe_non_pickleable_state() -> None:
    result = LanguageRegistry().parse(file_path="x.py", content=b"def f(): pass\n")
    assert result.parse_state is not None
    assert "opaque" not in repr(result.parse_state) and "def f" not in repr(result)
    with pytest.raises(TypeError):
        pickle.dumps(result.parse_state)
    default = result.to_dict()
    assert "parse_state" not in default
    summary = result.to_dict(include_parse_state=True)["parse_state"]
    assert set(summary) == {"adapter_source", "content_hash", "language", "dialect", "generation", "state_version"}
    json.dumps(summary)


def test_adapter_incremental_capabilities_are_truthful() -> None:
    assert TreeSitterAdapter("python", frozenset({".py"})).supports_incremental is True
    assert PythonAstAdapter.supports_incremental is False
    assert LegacyRegexAdapter("go", frozenset({".go"})).supports_incremental is False
    fake = ParseState("tree-sitter", "fake")
    assert PythonAstAdapter().parse(file_path="x.py", content=b"pass", previous_state=fake).metadata.incremental_used is False
    assert LegacyRegexAdapter("go", frozenset({".go"})).parse(file_path="x.go", content=b"package p", previous_state=fake).metadata.incremental_used is False


@pytest.mark.parametrize(("old", "new"), [
    (b"abc", b"abXc"), (b"abc", b"ac"), (b"abc", b"axc"),
    (b"a\nb\n", b"a\nx\ny\nb\n"), (b"a\nx\ny\nb\n", b"a\nb\n"),
    (b"abc", b"Xabc"), (b"abc", b"abcX"), (b"abc", b"XYZ"),
    (b"", b"text"), (b"text", b""),
    ("中文".encode(), "中X文".encode()), ("😀a".encode(), "😀b".encode()),
    ("e\u0301".encode(), "e\u0301x".encode()), (b"a\r\nb", b"a\r\nXb"),
])
def test_canonical_edit_and_byte_points(old: bytes, new: bytes) -> None:
    edit = canonical_edit(old, new)
    rebuilt = old[:edit.start_byte] + new[edit.start_byte:edit.new_end_byte] + old[edit.old_end_byte:]
    assert rebuilt == new
    for data, offset, point in ((old, edit.start_byte, edit.start_point), (old, edit.old_end_byte, edit.old_end_point), (new, edit.new_end_byte, edit.new_end_point)):
        prefix = data[:offset]
        assert point[0] == prefix.count(b"\n")
        assert point[1] == len(prefix.rsplit(b"\n", 1)[-1])


def test_byte_point_rejects_mid_codepoint_and_bounds() -> None:
    raw = "中😀e\u0301".encode()
    assert byte_offset_to_tree_sitter_point(raw, 0)[1] == 0
    assert byte_offset_to_tree_sitter_point(raw, len(raw))[1] == len(raw)
    with pytest.raises(ValueError):
        byte_offset_to_tree_sitter_point(raw, 1)
    with pytest.raises(ValueError):
        byte_offset_to_tree_sitter_point(raw, len(raw) + 1)


@pytest.mark.parametrize(("extension", "old", "new"), [
    ("py", b"def f():\n return 1\n", b"def f():\n return 2\n"),
    ("js", b"function f(){return 1}", b"function f(){return 2}"),
    ("ts", b"function f():number{return 1}", b"function f():number{return 2}"),
    ("tsx", b"const F=()=> <div>{1}</div>", b"const F=()=> <div>{2}</div>"),
    ("go", b"package p\nfunc F() int{return 1}", b"package p\nfunc F() int{return 2}"),
    ("rs", b"fn f()->i32{1}", b"fn f()->i32{2}"),
])
def test_six_dialect_incremental_equals_full(extension: str, old: bytes, new: bytes) -> None:
    registry = LanguageRegistry()
    first = registry.parse(file_path=f"x.{extension}", content=old)
    incremental = registry.parse(file_path=f"x.{extension}", content=new, previous_state=first.parse_state)
    full = registry.parse(file_path=f"x.{extension}", content=new)
    assert incremental.metadata.incremental_used is True
    assert incremental.metadata.parse_mode == "incremental"
    assert incremental.metadata.changed_range_count >= 1
    assert incremental.metadata.semantic_refresh_mode == "full-file"
    _assert_semantics_equal(incremental, full)


@pytest.mark.parametrize(("old", "new"), [
    (b"def f():\n return 1\n", b"def f():\n x=1\n y=2\n return x+y\n"),
    (b"def f():\n x=1\n y=2\n return x+y\n", b"def f():\n return 1\n"),
    (b"def f(): pass\n", b"# head\ndef f(): pass\n"),
    (b"def f(): pass", b"def f(): pass\n# end"),
])
def test_multiline_boundary_and_no_final_newline_edits(old: bytes, new: bytes) -> None:
    registry = LanguageRegistry()
    first = registry.parse(file_path="x.py", content=old)
    result = registry.parse(file_path="x.py", content=new, previous_state=first.parse_state)
    _assert_semantics_equal(result, registry.parse(file_path="x.py", content=new))


def test_noop_has_no_edit_or_changed_ranges() -> None:
    registry = LanguageRegistry(); content = b"def f(): return 1\n"
    first = registry.parse(file_path="x.py", content=content)
    result = registry.parse(file_path="x.py", content=content, previous_state=first.parse_state)
    assert result.metadata.parse_mode == "noop"
    assert result.metadata.incremental_used is False
    assert result.metadata.changed_ranges == ()
    assert result.metadata.edit_start_byte is None
    _assert_semantics_equal(result, registry.parse(file_path="x.py", content=content))


def test_syntax_error_introduction_repair_and_movement_equal_full() -> None:
    registry = LanguageRegistry(); path = "x.py"
    valid = b"def safe(): good()\ndef later(): final()\n"
    broken = b"def safe(): good()\ndef broken(: bad(\ndef later(): final()\n"
    moved = b"# inserted\ndef safe(): good()\ndef broken(: bad(\ndef later(): final()\n"
    state = registry.parse(file_path=path, content=valid)
    for content in (broken, moved, valid):
        result = registry.parse(file_path=path, content=content, previous_state=state.parse_state)
        full = registry.parse(file_path=path, content=content)
        _assert_semantics_equal(result, full)
        state = result


@pytest.mark.parametrize("mutation", ["opaque", "version", "grammar", "query", "hash"])
def test_corrupt_states_trigger_safe_full_fallback(mutation: str) -> None:
    registry = LanguageRegistry(); first = registry.parse(file_path="x.py", content=b"def f(): return 1\n")
    state = first.parse_state; internal = state.opaque
    if mutation == "opaque": bad = ParseState("tree-sitter", state.content_hash, object())
    elif mutation == "version": bad = ParseState("tree-sitter", state.content_hash, replace(internal, state_version=999))
    elif mutation == "grammar": bad = ParseState("tree-sitter", state.content_hash, replace(internal, grammar_version="bad"))
    elif mutation == "query": bad = ParseState("tree-sitter", state.content_hash, replace(internal, query_version="bad"))
    else: bad = ParseState("tree-sitter", "tampered", internal)
    result = registry.parse(file_path="x.py", content=b"def f(): return 2\n", previous_state=bad)
    assert result.metadata.parse_mode == "full-fallback"
    assert result.metadata.incremental_used is False
    assert any(item.code.startswith("incremental-state-") for item in result.diagnostics)


def test_file_language_and_ts_dialect_mismatch_rejected() -> None:
    registry = LanguageRegistry()
    py = registry.parse(file_path="a.py", content=b"pass\n")
    file_mismatch = registry.parse(file_path="b.py", content=b"pass\n", previous_state=py.parse_state)
    assert any(item.code == "incremental-state-file-mismatch" for item in file_mismatch.diagnostics)
    cross_language = ParseState("tree-sitter", py.parse_state.content_hash, replace(py.parse_state.opaque, file_path="a.go"))
    language_mismatch = registry.parse(file_path="a.go", content=b"package p\n", previous_state=cross_language)
    assert any(item.code == "incremental-state-incompatible" for item in language_mismatch.diagnostics)
    ts = registry.parse(file_path="x.ts", content=b"const x:number=1")
    cross_dialect = ParseState("tree-sitter", ts.parse_state.content_hash, replace(ts.parse_state.opaque, file_path="x.tsx"))
    tsx = registry.parse(file_path="x.tsx", content=b"const x=<div/>", previous_state=cross_dialect)
    assert any(item.code == "incremental-state-dialect-mismatch" for item in tsx.diagnostics)


def test_large_replacement_uses_full_fallback_not_legacy() -> None:
    registry = LanguageRegistry(); old = b"def f():\n return 1\n" * 20; new = b"class CompletelyDifferent:\n pass\n" * 20
    first = registry.parse(file_path="x.py", content=old)
    result = registry.parse(file_path="x.py", content=new, previous_state=first.parse_state)
    assert result.parser_source == "tree-sitter"
    assert result.metadata.parse_mode == "full-fallback"
    assert result.metadata.full_reparse_reason == "changed-ratio-exceeded"


def test_old_state_is_reusable_and_not_mutated() -> None:
    registry = LanguageRegistry(); old = b"def f(): return 1\n"
    first = registry.parse(file_path="x.py", content=old); before = first.parse_state.safe_summary()
    one = registry.parse(file_path="x.py", content=b"def f(): return 2\n", previous_state=first.parse_state)
    two = registry.parse(file_path="x.py", content=b"def f(): return 3\n", previous_state=first.parse_state)
    assert first.parse_state.safe_summary() == before
    _assert_semantics_equal(one, registry.parse(file_path="x.py", content=b"def f(): return 2\n"))
    _assert_semantics_equal(two, registry.parse(file_path="x.py", content=b"def f(): return 3\n"))


def test_same_state_concurrent_forks_are_safe() -> None:
    registry = LanguageRegistry(); old = b"def f(): return 1\n"; first = registry.parse(file_path="x.py", content=old)
    contents = [f"def f(): return {index}\n".encode() for index in range(2, 10)]
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda content: registry.parse(file_path="x.py", content=content, previous_state=first.parse_state), contents))
    for result, content in zip(results, contents):
        assert result.metadata.incremental_used
        _assert_semantics_equal(result, registry.parse(file_path="x.py", content=content))
    assert first.parse_state.opaque.source_bytes == old


def test_medium_file_incremental_telemetry_and_equivalence() -> None:
    functions = [f"def f_{index}():\n    return {index}\n" for index in range(1000)]
    old = ("import os\n" + "".join(functions) + "def caller():\n    return f_500()\n").encode()
    new = old.replace(b"return 500", b"return 501", 1)
    registry = LanguageRegistry(); full_old = registry.parse(file_path="medium.py", content=old)
    incremental = registry.parse(file_path="medium.py", content=new, previous_state=full_old.parse_state)
    oracle = registry.parse(file_path="medium.py", content=new)
    assert incremental.metadata.incremental_used is True
    assert incremental.metadata.changed_byte_count < len(new) // 100
    assert incremental.metadata.changed_range_count >= 1
    _assert_semantics_equal(incremental, oracle)
