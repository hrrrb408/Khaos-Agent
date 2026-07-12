from __future__ import annotations

import inspect
from pathlib import Path

import pytest

from khaos.coding.intelligence import LanguageRegistry
from khaos.coding.intelligence.adapters import AdapterAvailability, LegacyRegexAdapter
from khaos.coding.intelligence.models import ParseDiagnostic, ParseResult, SourceLocation


FIXTURES = Path(__file__).parents[1] / "fixtures" / "intelligence"


@pytest.mark.parametrize(
    ("path", "language"),
    [
        ("main.py", "python"), ("APP.PY", "python"),
        ("main.js", "javascript"), ("view.jsx", "javascript"),
        ("main.ts", "typescript"), ("view.tsx", "typescript"),
        ("main.go", "go"), ("main.rs", "rust"),
    ],
)
def test_resolve_supported_extensions(path: str, language: str) -> None:
    resolution = LanguageRegistry().resolve(Path("nested") / path)
    assert resolution.supported is True
    assert resolution.language == language


def test_unknown_extension_is_structured_unsupported() -> None:
    resolution = LanguageRegistry().resolve("README.weird")
    assert resolution.supported is False
    assert resolution.language is None
    assert resolution.diagnostic.code == "unsupported-language"


def test_registry_rejects_adapter_conflicts_and_untrusted_language_strings() -> None:
    registry = LanguageRegistry()
    with pytest.raises(ValueError, match="already registered"):
        registry.register(LegacyRegexAdapter("python", frozenset({".py"})))
    assert registry.get("../../python") is None


def test_adapter_availability_is_queryable() -> None:
    status = LanguageRegistry().availability("python")
    assert status
    assert all(isinstance(item, AdapterAvailability) for item in status)


def test_tree_sitter_missing_or_grammar_missing_falls_back(monkeypatch: pytest.MonkeyPatch) -> None:
    registry = LanguageRegistry()
    tree = registry.adapters("javascript")[0]
    monkeypatch.setattr(tree, "availability", lambda _path=None: AdapterAvailability(False, "grammar-missing", "missing"))
    result = registry.parse(file_path="sample.js", content=b"function run() {}")
    assert result.parser_source == "legacy-regex"
    assert any(item.code == "grammar-missing" for item in result.diagnostics)


def test_tree_sitter_initialization_failure_falls_back(monkeypatch: pytest.MonkeyPatch) -> None:
    registry = LanguageRegistry()
    tree = registry.adapters("go")[0]
    monkeypatch.setattr(tree, "availability", lambda _path=None: AdapterAvailability(True, "available", "ok"))
    monkeypatch.setattr(tree, "parse", lambda **kwargs: (_ for _ in ()).throw(RuntimeError("boom")))
    result = registry.parse(file_path="sample.go", content=b"package main\nfunc run() {}")
    assert result.parser_source == "legacy-regex"
    assert any(item.code == "parser-initialization-failed" for item in result.diagnostics)


def test_python_fallback_order_reaches_ast_then_legacy(monkeypatch: pytest.MonkeyPatch) -> None:
    registry = LanguageRegistry()
    tree, python_ast, _legacy = registry.adapters("python")
    monkeypatch.setattr(tree, "availability", lambda _path=None: AdapterAvailability(False, "dependency-missing", "missing"))
    ast_result = registry.parse(file_path="sample.py", content=b"def run():\n    return 1\n")
    assert ast_result.parser_source == "python-ast"
    monkeypatch.setattr(python_ast, "parse", lambda **kwargs: (_ for _ in ()).throw(SyntaxError("bad")))
    legacy_result = registry.parse(file_path="sample.py", content=b"def run():\n    return 1\n")
    assert legacy_result.parser_source == "legacy-regex"
    assert {item.code for item in legacy_result.diagnostics} >= {"dependency-missing", "parse-failed"}


@pytest.mark.parametrize("extension", ["js", "ts", "go", "rs"])
def test_non_python_tree_sitter_unavailable_uses_legacy(extension: str, monkeypatch: pytest.MonkeyPatch) -> None:
    registry = LanguageRegistry()
    language = registry.resolve(f"sample.{extension}").language
    tree = registry.adapters(language)[0]
    monkeypatch.setattr(tree, "availability", lambda _path=None: AdapterAvailability(False, "grammar-missing", "missing"))
    result = registry.parse(file_path=f"sample.{extension}", content=b"")
    assert result.parser_source == "legacy-regex"


def test_syntax_error_empty_binary_oversized_and_hash_contract() -> None:
    registry = LanguageRegistry(max_file_bytes=32)
    syntax = registry.parse(file_path="bad.py", content=b"def broken(:\n")
    assert isinstance(syntax, ParseResult)
    assert syntax.diagnostics
    empty = registry.parse(file_path="empty.py", content=b"")
    assert empty.symbols == () and len(empty.content_hash) == 64
    binary = registry.parse(file_path="bad.py", content=b"a\x00b")
    assert binary.parser_source == "rejected"
    assert binary.diagnostics[0].code == "binary-content"
    oversized = registry.parse(file_path="big.py", content=b"x" * 33)
    assert oversized.parser_source == "rejected"
    assert oversized.diagnostics[0].code == "file-too-large"
    same = registry.parse(file_path="empty.py", content=b"")
    assert empty.content_hash == same.content_hash
    assert empty.to_dict(include_duration=False) == same.to_dict(include_duration=False)


def test_unicode_locations_use_utf8_bytes_and_code_point_columns() -> None:
    content = "变量 = '😀'\ndef 函数():\n    return 变量\n".encode()
    result = LanguageRegistry().parse(file_path="unicode.py", content=content)
    symbol = next(item for item in result.symbols if item.name == "函数")
    assert symbol.location.start_line == 1
    assert symbol.location.start_column == 4
    assert symbol.location.byte_start == len("变量 = '😀'\ndef ".encode())


def test_result_fields_are_immutable_from_callers() -> None:
    result = LanguageRegistry().parse(file_path="empty.py", content=b"")
    with pytest.raises(Exception):
        result.parser_source = "caller-controlled"  # type: ignore[misc]
    location = SourceLocation("x.py", 0, 0, 0, 1, 0, 1)
    diagnostic = ParseDiagnostic("x", "warning", "x", location, True, "test")
    assert diagnostic.location == location


def test_no_runtime_network_or_installer_paths() -> None:
    import khaos.coding.intelligence.adapters as adapters
    source = inspect.getsource(adapters)
    for forbidden in ("pip install", "npm install", "git clone", "urlopen(", "requests.get("):
        assert forbidden not in source


def test_old_registry_and_result_interfaces_remain_compatible() -> None:
    registry = LanguageRegistry()
    adapter = registry.for_path(Path("main.py"))
    assert adapter is not None and adapter.language_id == "python"
    result = adapter.parse(Path("main.py"), b"def run():\n    pass\n")
    assert result.path == Path("main.py")
    assert result.symbols[0]["name"] == "run"
    assert result.symbols[0]["line"] == 1


@pytest.mark.parametrize("language", ["python", "javascript", "typescript", "go", "rust"])
def test_five_language_offline_fixtures_load(language: str) -> None:
    extension = {"python": "py", "javascript": "js", "typescript": "ts", "go": "go", "rust": "rs"}[language]
    path = FIXTURES / f"sample.{extension}"
    result = LanguageRegistry().parse(file_path=str(path), content=path.read_bytes())
    assert result.language == language
    assert result.symbols


@pytest.mark.parametrize("prefix", ["syntax_error", "empty", "unicode"])
@pytest.mark.parametrize("extension", ["py", "js", "ts", "go", "rs"])
def test_failure_fixture_matrix_is_offline(prefix: str, extension: str) -> None:
    path = FIXTURES / f"{prefix}.{extension}"
    assert path.is_file()
    result = LanguageRegistry().parse(file_path=str(path), content=path.read_bytes())
    assert isinstance(result, ParseResult)
