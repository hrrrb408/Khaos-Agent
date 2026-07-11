"""Trusted language resolution and deterministic offline parser fallback."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, replace
from pathlib import Path

from khaos.coding.intelligence.adapters import AdapterAvailability, LegacyRegexAdapter, ParseAdapter, PythonAstAdapter, TreeSitterAdapter
from khaos.coding.intelligence.models import ParseDiagnostic, ParseResult, ParseState


EXTENSIONS = {".py": "python", ".js": "javascript", ".jsx": "javascript", ".ts": "typescript", ".tsx": "typescript", ".go": "go", ".rs": "rust"}


@dataclass(frozen=True)
class LanguageResolution:
    supported: bool
    language: str | None
    extension: str
    diagnostic: ParseDiagnostic | None = None


class _LegacyAdapterView:
    """Old positional ``parse(Path, bytes)`` facade over registry fallback."""
    def __init__(self, registry: "LanguageRegistry", language: str, extensions: frozenset[str]) -> None:
        self._registry = registry
        self.language_id = language
        self.language = language
        self.extensions = extensions

    def parse(self, path: Path, content: bytes) -> ParseResult:
        return self._registry.parse(file_path=str(path), content=content)


class LanguageRegistry:
    def __init__(self, *, max_file_bytes: int = 2 * 1024 * 1024) -> None:
        self.max_file_bytes = max_file_bytes
        self._chains: dict[str, list[ParseAdapter]] = {}
        for language in ("python", "javascript", "typescript", "go", "rust"):
            extensions = frozenset(key for key, value in EXTENSIONS.items() if value == language)
            self._chains[language] = [TreeSitterAdapter(language, extensions)]
            if language == "python":
                self._chains[language].append(PythonAstAdapter())
            self._chains[language].append(LegacyRegexAdapter(language, extensions))

    def resolve(self, path: str | Path, content_hint: bytes | str | None = None) -> LanguageResolution:
        del content_hint
        extension = Path(str(path).replace("\\", "/")).suffix.lower()
        language = EXTENSIONS.get(extension)
        if language:
            return LanguageResolution(True, language, extension)
        diagnostic = ParseDiagnostic("unsupported-language", "warning", f"unsupported source extension: {extension or '<none>'}", None, True, "language-registry")
        return LanguageResolution(False, None, extension, diagnostic)

    def register(self, adapter: ParseAdapter) -> None:
        language = adapter.language
        if language not in self._chains:
            raise ValueError(f"untrusted language id: {language}")
        if any(item.source_name == adapter.source_name for item in self._chains[language]):
            raise ValueError(f"adapter already registered: {language}/{adapter.source_name}")
        self._chains[language].insert(0, adapter)

    def adapters(self, language: str | None) -> tuple[ParseAdapter, ...]:
        return tuple(self._chains.get(language or "", ()))

    def availability(self, language: str) -> tuple[AdapterAvailability, ...]:
        return tuple(adapter.availability() for adapter in self.adapters(language))

    def get(self, language_id: str) -> _LegacyAdapterView | None:
        if language_id not in self._chains:
            return None
        extensions = frozenset(key for key, value in EXTENSIONS.items() if value == language_id)
        return _LegacyAdapterView(self, language_id, extensions)

    def for_path(self, path: Path) -> _LegacyAdapterView | None:
        resolution = self.resolve(path)
        return self.get(resolution.language) if resolution.supported and resolution.language else None

    def languages(self) -> tuple[str, ...]:
        return tuple(self._chains)

    def parse(self, *, file_path: str, content: bytes, previous_state: ParseState | None = None) -> ParseResult:
        resolution = self.resolve(file_path)
        digest = hashlib.sha256(content).hexdigest()
        if not resolution.supported or resolution.language is None:
            return ParseResult("unsupported", file_path, diagnostics=(resolution.diagnostic,), parser_source="rejected", parser_version="registry-v1", content_hash=digest)
        if b"\x00" in content[:8192]:
            return self._rejected(resolution.language, file_path, digest, "binary-content", "binary content is not parsed")
        if len(content) > self.max_file_bytes:
            return self._rejected(resolution.language, file_path, digest, "file-too-large", f"file exceeds {self.max_file_bytes} byte parse limit")
        diagnostics: list[ParseDiagnostic] = []
        for adapter in self._chains[resolution.language]:
            status = adapter.availability()
            if not status.available:
                diagnostics.append(ParseDiagnostic(status.code, "warning", status.message, None, True, adapter.source_name))
                continue
            try:
                result = adapter.parse(file_path=file_path, content=content, previous_state=previous_state)
                return replace(result, diagnostics=tuple(diagnostics) + result.diagnostics, content_hash=digest)
            except SyntaxError as exc:
                diagnostics.append(ParseDiagnostic("parse-failed", "warning", str(exc), None, True, adapter.source_name))
            except (RuntimeError, UnicodeDecodeError, ValueError) as exc:
                code = "parser-initialization-failed" if adapter.source_name == "tree-sitter" else "parse-failed"
                diagnostics.append(ParseDiagnostic(code, "warning", str(exc), None, True, adapter.source_name))
        return ParseResult(resolution.language, file_path, diagnostics=tuple(diagnostics), parser_source="unavailable", parser_version="registry-v1", content_hash=digest)

    @staticmethod
    def _rejected(language: str, file_path: str, digest: str, code: str, message: str) -> ParseResult:
        diagnostic = ParseDiagnostic(code, "error", message, None, True, "language-registry")
        return ParseResult(language, file_path, diagnostics=(diagnostic,), parser_source="rejected", parser_version="registry-v1", content_hash=digest)
