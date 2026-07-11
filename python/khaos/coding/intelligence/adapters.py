"""Offline language adapters and optional Tree-sitter dependency probing."""

from __future__ import annotations

import ast
import hashlib
import importlib
import importlib.metadata
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from khaos.coding.intelligence.models import (
    ImportReference, ParseDiagnostic, ParseResult, ParseState, SourceLocation, Symbol,
)


@dataclass(frozen=True)
class AdapterAvailability:
    available: bool
    code: str
    message: str
    version: str = "unknown"


@dataclass(frozen=True)
class GrammarSpec:
    """Allowlisted grammar package metadata; never a filesystem library path."""

    language: str
    package: str
    distribution: str


GRAMMARS = {
    language: GrammarSpec(language, f"tree_sitter_{language}", f"tree-sitter-{language}")
    for language in ("python", "javascript", "typescript", "go", "rust")
}


class ParseAdapter(Protocol):
    language: str
    source_name: str
    supports_incremental: bool
    version: str
    extensions: frozenset[str]

    def availability(self) -> AdapterAvailability: ...
    def parse(self, *, file_path: str, content: bytes, previous_state: ParseState | None = None) -> ParseResult: ...


def _hash(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _location(file_path: str, text: str, line: int, column: int, end_line: int, end_column: int) -> SourceLocation:
    lines = text.splitlines(keepends=True)
    start = sum(len(item.encode("utf-8")) for item in lines[:line]) + len(lines[line][:column].encode("utf-8")) if lines else 0
    end = sum(len(item.encode("utf-8")) for item in lines[:end_line]) + len(lines[end_line][:end_column].encode("utf-8")) if lines and end_line < len(lines) else len(text.encode("utf-8"))
    return SourceLocation(file_path, line, column, end_line, end_column, start, end)


class TreeSitterAdapter:
    """Optional parser skeleton; query implementations intentionally deferred."""

    source_name = "tree-sitter"
    supports_incremental = True

    def __init__(self, language: str, extensions: frozenset[str]) -> None:
        self.language = language
        self.language_id = language
        self.extensions = extensions
        try:
            self.version = importlib.metadata.version("tree-sitter")
        except importlib.metadata.PackageNotFoundError:
            self.version = "unavailable"

    def availability(self) -> AdapterAvailability:
        if importlib.util.find_spec("tree_sitter") is None:
            return AdapterAvailability(False, "dependency-missing", "tree-sitter is not installed", self.version)
        grammar_package = GRAMMARS[self.language].package
        if importlib.util.find_spec(grammar_package) is None:
            return AdapterAvailability(False, "grammar-missing", f"locked grammar package {grammar_package} is not installed", self.version)
        return AdapterAvailability(False, "queries-unavailable", "grammar detected but M3 Batch 0 queries are not implemented", self.version)

    def parse(self, *, file_path: str, content: bytes, previous_state: ParseState | None = None) -> ParseResult:
        raise RuntimeError("Tree-sitter query parsing is not implemented in M3 Batch 0")


class PythonAstAdapter:
    language = "python"
    language_id = "python"
    source_name = "python-ast"
    supports_incremental = False
    version = "stdlib-ast"
    extensions = frozenset({".py"})

    def availability(self) -> AdapterAvailability:
        return AdapterAvailability(True, "available", "Python stdlib ast is available", self.version)

    def parse(self, *, file_path: str, content: bytes, previous_state: ParseState | None = None) -> ParseResult:
        started = time.perf_counter()
        text = content.decode("utf-8")
        tree = ast.parse(text, filename=file_path)
        symbols: list[Symbol] = []
        imports: list[ImportReference] = []
        parents: dict[ast.AST, ast.AST] = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
        for node in ast.walk(tree):
            if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                parent = parents.get(node)
                owner = parent.name if isinstance(parent, ast.ClassDef) else None
                kind = "class" if isinstance(node, ast.ClassDef) else "method" if owner else "async_function" if isinstance(node, ast.AsyncFunctionDef) else "function"
                line_index = node.lineno - 1
                source_line = text.splitlines()[line_index]
                name_column = source_line.find(node.name, node.col_offset)
                location = _location(file_path, text, line_index, name_column, line_index, name_column + len(node.name))
                symbols.append(Symbol(node.name, kind, f"{owner}.{node.name}" if owner else node.name, location, self.language, self.source_name, 1.0, {"signature": _signature(node)}))
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                location = _location(file_path, text, node.lineno - 1, node.col_offset, getattr(node, "end_lineno", node.lineno) - 1, getattr(node, "end_col_offset", node.col_offset))
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.append(ImportReference(alias.name, (), alias.asname, location, self.source_name, 1.0))
                else:
                    imports.append(ImportReference("." * node.level + (node.module or ""), tuple(alias.name for alias in node.names), node.names[0].asname if len(node.names) == 1 else None, location, self.source_name, 1.0))
        symbols.sort(key=lambda item: item.location.byte_start)
        return ParseResult(self.language, file_path, tuple(symbols), tuple(imports), parser_source=self.source_name, parser_version=self.version, content_hash=_hash(content), parse_duration_ms=(time.perf_counter() - started) * 1000)

    def parse_legacy(self, path: Path, content: bytes) -> ParseResult:
        return self.parse(file_path=str(path), content=content)


def _signature(node: ast.AST) -> str:
    if isinstance(node, ast.ClassDef):
        return f"class {node.name}"
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        prefix = "async " if isinstance(node, ast.AsyncFunctionDef) else ""
        return f"{prefix}def {node.name}({', '.join(arg.arg for arg in node.args.args)})"
    return ""


class LegacyRegexAdapter:
    source_name = "legacy-regex"
    supports_incremental = False
    version = "legacy-v2"

    def __init__(self, language: str, extensions: frozenset[str]) -> None:
        self.language = language
        self.language_id = language
        self.extensions = extensions

    def availability(self) -> AdapterAvailability:
        return AdapterAvailability(True, "available", "bundled offline fallback", self.version)

    def parse(self, path: Path | None = None, content: bytes = b"", *, file_path: str | None = None, previous_state: ParseState | None = None) -> ParseResult:
        actual_path = file_path or str(path)
        started = time.perf_counter()
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError as exc:
            diagnostic = ParseDiagnostic("decode-error", "error", str(exc), None, True, self.source_name)
            return ParseResult(self.language, actual_path, diagnostics=(diagnostic,), parser_source=self.source_name, parser_version=self.version, content_hash=_hash(content))
        patterns = {
            "python": r"(?m)^([ \t]*)(?:async\s+)?(class|def)\s+([^\W\d]\w*)",
            "javascript": r"(?m)^([ \t]*)(?:export\s+)?(?:async\s+)?(class|function)\s+([^\W\d]\w*)",
            "typescript": r"(?m)^([ \t]*)(?:export\s+)?(?:async\s+)?(class|interface|function)\s+([^\W\d]\w*)",
            "go": r"(?m)^([ \t]*)(type|func)\s+(?:\([^)]*\)\s*)?([^\W\d]\w*)",
            "rust": r"(?m)^([ \t]*)(?:pub\s+)?(struct|trait|fn)\s+([^\W\d]\w*)",
        }
        symbols = []
        lines = text.splitlines()
        for match in re.finditer(patterns[self.language], text):
            line = text.count("\n", 0, match.start(3))
            column = match.start(3) - (text.rfind("\n", 0, match.start(3)) + 1)
            location = _location(actual_path, text, line, column, line, column + len(match.group(3)))
            raw_kind = match.group(2)
            kind = {"def": "function", "func": "function", "fn": "function", "type": "struct"}.get(raw_kind, raw_kind)
            symbols.append(Symbol(match.group(3), kind, match.group(3), location, self.language, self.source_name, 0.55, {}))
        import_patterns = {"python": r"(?m)^\s*(?:from\s+([\w.]+)\s+import|import\s+([\w.]+))", "javascript": r"(?m)^\s*import.*?from\s+[\"']([^\"']+)", "typescript": r"(?m)^\s*import(?:\s+type)?.*?from\s+[\"']([^\"']+)", "go": r"(?m)^\s*[\"']([^\"']+)[\"']", "rust": r"(?m)^\s*use\s+([^;]+)"}
        imports = []
        for match in re.finditer(import_patterns[self.language], text):
            module = next((group for group in match.groups() if group), "")
            line = text.count("\n", 0, match.start())
            imports.append(ImportReference(module, (), None, _location(actual_path, text, line, 0, line, len(lines[line]) if lines else 0), self.source_name, 0.55))
        diagnostics = []
        pairs = (("(", ")"), ("{", "}"), ("[", "]"))
        if any(text.count(left) != text.count(right) for left, right in pairs):
            diagnostics.append(ParseDiagnostic("syntax-error", "warning", "unbalanced delimiters in legacy parse", None, True, self.source_name))
        return ParseResult(self.language, actual_path, tuple(symbols), tuple(imports), diagnostics=tuple(diagnostics), parser_source=self.source_name, parser_version=self.version, content_hash=_hash(content), parse_duration_ms=(time.perf_counter() - started) * 1000)
