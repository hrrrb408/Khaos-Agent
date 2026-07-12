from __future__ import annotations

import concurrent.futures
import importlib.resources

import pytest

pytestmark = pytest.mark.tree_sitter_real
pytest.importorskip("tree_sitter")

from khaos.coding.intelligence import LanguageRegistry
from khaos.coding.intelligence.adapters import TreeSitterAdapter
import khaos.coding.intelligence.adapters as adapter_module


@pytest.mark.parametrize(("extension", "dialect"), [("py", "python"), ("js", "javascript"), ("ts", "typescript"), ("tsx", "tsx"), ("go", "go"), ("rs", "rust")])
def test_six_dialect_call_reference_queries_compile(extension: str, dialect: str) -> None:
    language = "typescript" if extension in {"ts", "tsx"} else {"py": "python", "js": "javascript", "go": "go", "rs": "rust"}[extension]
    adapter = LanguageRegistry().adapters(language)[0]
    assert adapter.availability(f"x.{extension}").available
    root = importlib.resources.files("khaos.coding.intelligence").joinpath(f"queries/{dialect}")
    for name in ("calls.scm", "references.scm"):
        text = root.joinpath(name).read_text(encoding="utf-8")
        assert "(_)" not in text and "@candidate" not in text


@pytest.mark.parametrize(("extension", "content", "callees"), [
    ("py", b"@decorate(factory())\ndef f():\n await foo()\n obj.method()\n module.run()\n", {"decorate", "factory", "foo", "obj.method", "module.run"}),
    ("js", b"function f(){ foo(); obj.m(); obj?.m(); new C(); }", {"foo", "obj.m", "obj?.m", "C"}),
    ("ts", b"function f(){ generic<string>(); obj?.m(); new C(); }", {"generic", "obj?.m", "C"}),
    ("tsx", b"const App=()=> <button onClick={()=>run()}/>;", {"run"}),
    ("go", b"package p\nfunc F(){foo(); pkg.Bar(); obj.M(); len(nil); T(1)}", {"foo", "pkg.Bar", "obj.M", "len", "T"}),
    ("rs", b'fn f(){ foo(); Type::make(); obj.m(); println!("x"); future.await.m(); }', {"foo", "Type::make", "obj.m", "println!", "future.await.m"}),
])
def test_real_call_matrix(extension: str, content: bytes, callees: set[str]) -> None:
    result = LanguageRegistry().parse(file_path=f"x.{extension}", content=content)
    assert {item.callee for item in result.calls} == callees
    assert all(item.metadata["resolution"] == "unresolved" for item in result.calls)
    assert all(item.metadata["capture_byte_start"] == item.location.byte_start for item in result.calls)
    assert all(content[item.location.byte_start:item.location.byte_end].decode().rstrip("!") in item.callee for item in result.calls)


def test_nested_and_top_level_caller_attribution() -> None:
    content = b"top()\nclass A:\n def outer(self):\n  def inner(): target()\n  inner()\n"
    result = LanguageRegistry().parse(file_path="x.py", content=content)
    callers = {item.callee: item.caller for item in result.calls}
    assert callers == {"top": None, "target": "A.outer.inner", "inner": "A.outer"}


def test_reference_contexts_and_exclusions() -> None:
    content = b"import pkg as alias\nclass Base: pass\nclass C(Base):\n def f(self, param: Base):\n  value = param\n  value += 1\n  obj.member()\n  return value\n"
    result = LanguageRegistry().parse(file_path="x.py", content=content)
    values = {(item.name, item.reference_kind) for item in result.references}
    assert ("param", "read") in values
    assert ("value", "write") in values
    assert ("value", "readwrite") in values
    assert ("member", "member") in values
    assert ("Base", "annotation") in values or ("Base", "read") in values
    assert "alias" not in {item.name for item in result.references}
    assert not {"C", "f"} & {item.name for item in result.references}


def test_js_property_key_string_comment_and_binding_exclusions() -> None:
    content = b"// hiddenName\nconst local = source; const obj = {staticKey: local}; obj.member(); 'stringName';"
    result = LanguageRegistry().parse(file_path="x.js", content=content)
    names = {item.name for item in result.references}
    assert "hiddenName" not in names and "stringName" not in names and "staticKey" not in names
    assert {"local", "source", "obj", "member"} <= names


def test_go_ambiguity_and_rust_macro_policy() -> None:
    go = LanguageRegistry().parse(file_path="x.go", content=b"package p\nfunc F(){ T(1); foo() }")
    assert all(item.metadata["ambiguity"] == "possible-type-conversion" for item in go.calls)
    rust = LanguageRegistry().parse(file_path="x.rs", content=b'fn f(){ println!("x"); foo(); }')
    macro = next(item for item in rust.calls if item.callee == "println!")
    assert macro.metadata["call_kind"] == "macro"


def test_query_authority_removing_patterns_removes_results(monkeypatch: pytest.MonkeyPatch) -> None:
    original = adapter_module._query_text
    def stripped(spec, name):
        if name == "calls.scm": return "(call function: (attribute) @callee) @call"
        if name == "references.scm": return "(attribute attribute: (identifier) @reference.member)"
        return original(spec, name)
    monkeypatch.setattr(adapter_module, "_query_text", stripped)
    result = TreeSitterAdapter("python", frozenset({".py"})).parse(file_path="x.py", content=b"def f(): target()\nvalue = source\n")
    assert result.calls == () and result.references == ()


def test_call_reference_metadata_dedup_sort_unicode_crlf() -> None:
    content = "def 函数():\r\n    变量 = 对象.方法()\r\n    return 变量\r\n".encode()
    first = LanguageRegistry().parse(file_path="unicode.py", content=content)
    second = LanguageRegistry().parse(file_path="unicode.py", content=content)
    assert first.to_dict(include_duration=False) == second.to_dict(include_duration=False)
    assert list(first.calls) == sorted(first.calls, key=lambda item: (item.location.byte_start, item.location.byte_end, item.callee, item.caller or "", item.metadata["call_kind"]))
    assert list(first.references) == sorted(first.references, key=lambda item: (item.location.byte_start, item.location.byte_end, item.name, item.reference_kind))
    for item in (*first.calls, *first.references):
        assert content[item.location.byte_start:item.location.byte_end].decode()


def test_syntax_error_keeps_outside_candidates() -> None:
    result = LanguageRegistry().parse(file_path="broken.py", content=b"def safe(): good()\ndef broken(: bad(\ndef later(): final()\n")
    assert result.parser_source == "tree-sitter"
    assert {item.callee for item in result.calls} >= {"good", "final"}
    assert any(item.code == "parse-error" for item in result.diagnostics)


def test_large_file_candidate_queries_are_sparse() -> None:
    body = "\n".join(f"{index}\n'payload {index}'\n# comment {index}" for index in range(4000))
    source = f"def run():\n target = source\n first()\n obj.second()\n return target\n{body}\n".encode()
    result = LanguageRegistry().parse(file_path="large.py", content=source)
    assert result.metadata.ast_node_count > 12_000
    assert result.metadata.call_query_match_count == 2
    assert len(result.calls) == 2
    assert result.metadata.reference_query_match_count < 20
    assert result.metadata.reference_query_match_count / result.metadata.ast_node_count < 0.001


def test_concurrent_call_reference_parsing_is_deterministic() -> None:
    registry = LanguageRegistry()
    cases = [("x.py", b"def f(): foo()"), ("x.js", b"function f(){foo()}"), ("x.ts", b"function f(){foo()}"), ("x.tsx", b"const F=()=> <b onClick={()=>foo()}/>") , ("x.go", b"package p\nfunc F(){foo()}"), ("x.rs", b"fn f(){foo();}")]
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(lambda item: registry.parse(file_path=item[0], content=item[1]), cases * 4))
    assert all(result.calls for result in results)
    for index in range(6):
        group = [results[index + offset * 6].to_dict(include_duration=False) for offset in range(4)]
        assert all(value == group[0] for value in group)
