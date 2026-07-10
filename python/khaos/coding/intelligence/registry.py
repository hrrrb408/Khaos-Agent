"""Language registry with offline Legacy parser adapters."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Callable

from khaos.coding.contracts import ParsedFile
from khaos.coding.parser import CodeParser


class LegacyLanguageAdapter:
    """Small deterministic adapter used when optional parsers are absent."""

    def __init__(self, language_id: str, extensions: frozenset[str]) -> None:
        self.language_id = language_id
        self.extensions = extensions

    def parse(self, path: Path, content: bytes) -> ParsedFile:
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError as exc:
            return ParsedFile(path, self.language_id, diagnostics=(f"decode-error: {exc}",))
        symbols = tuple(_line_symbols(text, self.language_id))
        imports = tuple(_line_imports(text, self.language_id))
        return ParsedFile(path, self.language_id, symbols=symbols, imports=imports)


class LegacyPythonAdapter(LegacyLanguageAdapter):
    def __init__(self) -> None:
        super().__init__("python", frozenset({".py", ".pyi"}))
        self._parser = CodeParser()

    def parse(self, path: Path, content: bytes) -> ParsedFile:
        try:
            source = content.decode("utf-8")
            symbols = tuple(self._parser.parse_symbols_from_source(source))
            imports = tuple(self._parser.parse_imports_from_source(source))
            return ParsedFile(path, self.language_id, symbols=symbols, imports=imports)
        except (SyntaxError, UnicodeDecodeError) as exc:
            return ParsedFile(path, self.language_id, diagnostics=(f"parse-error: {exc}",))


class LanguageRegistry:
    """Resolve language adapters without downloading grammars."""

    def __init__(self) -> None:
        self._adapters = {
            "python": LegacyPythonAdapter(),
            "javascript": LegacyLanguageAdapter("javascript", frozenset({".js", ".jsx", ".mjs"})),
            "typescript": LegacyLanguageAdapter("typescript", frozenset({".ts", ".tsx"})),
            "go": LegacyLanguageAdapter("go", frozenset({".go"})),
            "rust": LegacyLanguageAdapter("rust", frozenset({".rs"})),
        }
        self._by_extension = {extension: adapter for adapter in self._adapters.values() for extension in adapter.extensions}

    def get(self, language_id: str) -> LegacyLanguageAdapter | None:
        return self._adapters.get(language_id.lower())

    def for_path(self, path: Path) -> LegacyLanguageAdapter | None:
        return self._by_extension.get(path.suffix.lower())

    def languages(self) -> tuple[str, ...]:
        return tuple(self._adapters)


def _line_symbols(text: str, language: str) -> list[dict[str, object]]:
    patterns: dict[str, str] = {
        "javascript": r"^\s*(?:export\s+)?(?:async\s+)?function\s+(\w+)",
        "typescript": r"^\s*(?:export\s+)?(?:async\s+)?function\s+(\w+)",
        "go": r"^\s*func\s+(?:\([^)]*\)\s*)?(\w+)",
        "rust": r"^\s*(?:pub\s+)?(?:async\s+)?fn\s+(\w+)",
    }
    pattern = patterns[language]
    return [{"name": match.group(1), "kind": "function", "line": line} for line, text_line in enumerate(text.splitlines()) if (match := re.search(pattern, text_line))]


def _line_imports(text: str, language: str) -> list[str]:
    patterns: dict[str, str] = {
        "javascript": r"^\s*import\s+.*?from\s+[\"']([^\"']+)",
        "typescript": r"^\s*import\s+.*?from\s+[\"']([^\"']+)",
        "go": r"^\s*\"([^\"]+)\"$",
        "rust": r"^\s*use\s+([^;]+)",
    }
    pattern = patterns[language]
    return [match.group(1) for text_line in text.splitlines() if (match := re.search(pattern, text_line))]
