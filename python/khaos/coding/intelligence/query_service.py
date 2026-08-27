"""Workspace-bound context retrieval for the M7.2 control plane.

This module is the production adapter between the typed M7.2 context
contracts and the existing parser registry.  It intentionally does not use
the older path-oriented indexer as a source reader: all current source bytes
come through :class:`SafeWorkspaceFS` after the workspace owner has been
validated.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import posixpath
import re
import stat
import threading
import uuid
from collections import OrderedDict
from collections.abc import Iterable
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Protocol

from khaos.agent.control.goal import GoalSpec
from khaos.coding.intelligence.context import (
    ContextBundle,
    ContextDocument,
    ContextEvidence,
    ContextEvidenceKind,
    ContextFreshness,
    ContextRequest,
    ContextSourceKind,
    ContextSymbol,
)
from khaos.coding.intelligence.models import ParseResult, Symbol
from khaos.coding.intelligence.registry import LanguageRegistry
from khaos.coding.workspace.boundary import SafeWorkspaceFS, WorkspaceBoundaryError
from khaos.coding.workspace.models import TaskWorkspace
from khaos.security.protocol_boundary import canonical_digest

logger = logging.getLogger(__name__)

_HASH_FILE_BYTES = 4 * 1024 * 1024
_MAX_CAPTURE_RETRIES = 2
_MAX_SCAN_ENTRIES = 10_000
_MAX_SCAN_DEPTH = 32
_TEXT_SUFFIXES = frozenset(
    {
        ".c",
        ".cc",
        ".cpp",
        ".go",
        ".h",
        ".hpp",
        ".java",
        ".js",
        ".jsx",
        ".json",
        ".md",
        ".py",
        ".rs",
        ".sh",
        ".sql",
        ".toml",
        ".ts",
        ".tsx",
        ".txt",
        ".yaml",
        ".yml",
    }
)
_CONFIG_NAMES = frozenset(
    {
        "cargo.toml",
        "go.mod",
        "package.json",
        "pyproject.toml",
        "requirements.txt",
        "setup.cfg",
        "setup.py",
        "tsconfig.json",
    }
)
_TEST_PARTS = frozenset({"test", "tests", "spec", "specs"})
_TERM_RE = re.compile(r"[^\W_]+", re.UNICODE)


class ContextQueryError(RuntimeError):
    """Base error for workspace-bound context retrieval failures."""


class ContextInputError(ContextQueryError, ValueError):
    """The request or GoalSpec binding is malformed or stale."""


class ContextUnavailableError(ContextQueryError):
    """The owner-scoped workspace or its safe source boundary is unavailable."""


class ContextStaleError(ContextQueryError):
    """A repository mutation raced a bounded context capture."""


class WorkspaceProvider(Protocol):
    """Minimum owner used by the context service to resolve workspaces."""

    def get(self, workspace_id: str) -> TaskWorkspace | None:
        """Return a registered workspace projection, if present."""


@dataclass(frozen=True, slots=True)
class _FileSnapshot:
    relative_path: str
    digest: str
    file_size: int
    device: int
    inode: int
    mode: int
    content: bytes | None
    text: str | None
    lexical_matches: tuple[str, ...]
    parse_result: ParseResult | None
    oversized: bool


@dataclass(frozen=True, slots=True)
class _WorkspaceSnapshot:
    files: tuple[_FileSnapshot, ...]
    repository_generation: str
    index_generation: str
    structure_paths: tuple[str, ...]
    truncated: bool
    truncation_reasons: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _CacheKey:
    request_digest: str
    repository_id: str
    workspace_id: str
    base_revision: str | None
    repository_generation: str
    index_schema_version: str
    parser_version: str


class _ContextBundleCache:
    """Small process-local LRU; freshness remains the correctness fence."""

    def __init__(self, *, max_entries: int = 128, max_bytes: int = 32 * 1024 * 1024) -> None:
        self._max_entries = max_entries
        self._max_bytes = max_bytes
        self._entries: OrderedDict[_CacheKey, tuple[ContextBundle, int]] = OrderedDict()
        self._bytes = 0
        self._lock = threading.RLock()

    def get(self, key: _CacheKey) -> ContextBundle | None:
        with self._lock:
            value = self._entries.get(key)
            if value is None:
                return None
            self._entries.move_to_end(key)
            return value[0]

    def put(self, key: _CacheKey, bundle: ContextBundle) -> None:
        size = len(bundle.canonical_json().encode("utf-8"))
        if size > self._max_bytes:
            return
        with self._lock:
            old = self._entries.pop(key, None)
            if old is not None:
                self._bytes -= old[1]
            self._entries[key] = (bundle, size)
            self._bytes += size
            while self._entries and (
                len(self._entries) > self._max_entries or self._bytes > self._max_bytes
            ):
                _, (_, evicted_size) = self._entries.popitem(last=False)
                self._bytes -= evicted_size

    def invalidate_workspace(self, workspace_id: str) -> None:
        with self._lock:
            removed = [key for key in self._entries if key.workspace_id == workspace_id]
            for key in removed:
                _, size = self._entries.pop(key)
                self._bytes -= size


def repository_id_for_workspace(workspace: TaskWorkspace) -> str:
    """Return a stable repository identity without reading repository content.

    Linked workspaces carry the repository ``.git`` device/inode captured by
    the workspace authority.  Non-Git or test workspaces fall back to the
    authority-validated worktree identity; the workspace id is still included
    separately in every request/cache key.
    """

    identity = getattr(workspace, "git_identity", None)
    repository_identity = getattr(identity, "repository_git_identity", None)
    if (
        isinstance(repository_identity, tuple)
        and len(repository_identity) == 2
        and all(type(value) is int for value in repository_identity)
    ):
        return f"git:{repository_identity[0]}:{repository_identity[1]}"
    try:
        info = os.stat(workspace.worktree_path, follow_symlinks=False)
    except OSError as exc:
        raise ContextUnavailableError("TaskWorkspace root is unavailable") from exc
    if not stat.S_ISDIR(info.st_mode):
        raise ContextUnavailableError("TaskWorkspace root is not a directory")
    return f"worktree:{info.st_dev}:{info.st_ino}"


def _path_tokens(value: str) -> tuple[str, ...]:
    return tuple(sorted({token.casefold() for token in _TERM_RE.findall(value)}))


def _language_for_path(path: str) -> str:
    suffix = Path(path).suffix.casefold()
    return {
        ".js": "javascript",
        ".jsx": "javascript",
        ".py": "python",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".go": "go",
        ".rs": "rust",
    }.get(suffix, "text")


def _is_text_path(path: str) -> bool:
    return Path(path).suffix.casefold() in _TEXT_SUFFIXES or Path(path).name.casefold() in _CONFIG_NAMES


def _safe_text(raw: bytes) -> str | None:
    if b"\x00" in raw[:8192]:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _bounded_text_prefix(raw: bytes, max_bytes: int) -> tuple[bytes, str] | None:
    """Return a UTF-8-safe bounded prefix without weakening its digest."""

    if max_bytes <= 0:
        return None
    prefix = raw[:max_bytes]
    try:
        text = prefix.decode("utf-8")
    except UnicodeDecodeError:
        text = prefix.decode("utf-8", errors="ignore")
    if not text:
        return None
    return text.encode("utf-8"), text


def _stat_fingerprint(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        int(info.st_dev),
        int(info.st_ino),
        int(info.st_mode),
        int(info.st_size),
        int(info.st_mtime_ns),
    )


def _manifest_digest(files: tuple[_FileSnapshot, ...]) -> str:
    return canonical_digest(
        [
            {
                "path": item.relative_path,
                "digest": item.digest,
                "size": item.file_size,
                "device": item.device,
                "inode": item.inode,
                "mode": item.mode,
            }
            for item in files
        ]
    )


def _normalized_parse_result(result: ParseResult) -> ParseResult:
    """Drop adapter-owned parser state before it can escape the service."""

    return replace(result, parse_state=None, parse_duration_ms=0.0)


def _is_same_file(before: os.stat_result, after: os.stat_result) -> bool:
    return _stat_fingerprint(before) == _stat_fingerprint(after)


def _capture_workspace_snapshot(
    fs: SafeWorkspaceFS,
    request: ContextRequest,
    registry: LanguageRegistry,
) -> _WorkspaceSnapshot:
    """Capture one bounded, coherent safe-file snapshot.

    Content hashing is independent from prompt byte limits.  That lets a
    cache key notice changes to files that were not selected for this bundle.
    Retained content is still bounded by the request's context limits.
    """

    try:
        paths = tuple(
            fs.iter_files(
                max_entries=_MAX_SCAN_ENTRIES,
                max_depth=_MAX_SCAN_DEPTH,
            )
        )
    except (OSError, WorkspaceBoundaryError) as exc:
        raise ContextUnavailableError("workspace file enumeration failed") from exc

    # A missing explicit target is a normal deleted/renamed-file result, but
    # an existing unsafe target must be rejected rather than silently treated
    # as an ordinary cache miss.
    for target_path in request.target_files:
        try:
            target_info = fs.lstat(target_path)
        except (OSError, WorkspaceBoundaryError) as exc:
            raise ContextUnavailableError(
                f"explicit context target is not safely readable: {target_path}"
            ) from exc
        if target_info is not None and (
            not stat.S_ISREG(target_info.st_mode) or target_info.st_nlink != 1
        ):
            raise ContextUnavailableError(
                f"explicit context target is not a single-link regular file: {target_path}"
            )

    retained_bytes = 0
    context_byte_limit = min(request.max_bytes, max(1, request.token_budget * 4))
    query_terms = _path_tokens(request.query)
    files: list[_FileSnapshot] = []
    reasons: set[str] = set()
    for relative_path in paths:
        try:
            before = fs.stat(relative_path)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                continue
            if before.st_size > _HASH_FILE_BYTES:
                digest = canonical_digest(
                    {
                        "oversized": True,
                        "size": int(before.st_size),
                        "mtime_ns": int(before.st_mtime_ns),
                        "device": int(before.st_dev),
                        "inode": int(before.st_ino),
                    }
                )
                after = fs.stat(relative_path)
                if not _is_same_file(before, after):
                    raise ContextStaleError("workspace changed during context capture")
                files.append(
                    _FileSnapshot(
                        relative_path=relative_path,
                        digest=digest,
                        file_size=int(before.st_size),
                        device=int(before.st_dev),
                        inode=int(before.st_ino),
                        mode=int(before.st_mode),
                        content=None,
                        text=None,
                        lexical_matches=(),
                        parse_result=None,
                        oversized=True,
                    )
                )
                reasons.add("file_hash_bound")
                continue
            raw = fs.read_bytes(relative_path, max_bytes=_HASH_FILE_BYTES)
            after = fs.stat(relative_path)
            if not _is_same_file(before, after):
                raise ContextStaleError("workspace changed during context capture")
            digest = hashlib.sha256(raw).hexdigest()
            text = _safe_text(raw)
            lexical_matches = (
                tuple(
                    sorted(
                        term
                        for term in query_terms
                        if text is not None and term in text.casefold()
                    )
                )
                if text is not None
                else ()
            )
            retained = None
            retained_text = None
            parse_result = None
            if text is not None and _is_text_path(relative_path):
                remaining_bytes = context_byte_limit - retained_bytes
                excerpt = _bounded_text_prefix(
                    raw,
                    min(request.max_file_bytes, max(0, remaining_bytes)),
                )
                if excerpt is not None:
                    retained, retained_text = excerpt
                    retained_bytes += len(retained)
                resolution = registry.resolve(relative_path)
                if resolution.supported:
                    parse_result = _normalized_parse_result(
                        registry.parse(file_path=relative_path, content=raw)
                    )
                if len(raw) > request.max_file_bytes:
                    reasons.add("file_excerpt_bound")
                if len(raw) > remaining_bytes:
                    reasons.add("context_byte_bound")
                    if context_byte_limit < request.max_bytes:
                        reasons.add("token_budget_bound")
            files.append(
                _FileSnapshot(
                    relative_path=relative_path,
                    digest=digest,
                    file_size=int(before.st_size),
                    device=int(before.st_dev),
                    inode=int(before.st_ino),
                    mode=int(before.st_mode),
                    content=retained,
                    text=retained_text,
                    lexical_matches=lexical_matches,
                    parse_result=parse_result,
                    oversized=False,
                )
            )
        except FileNotFoundError as exc:
            raise ContextStaleError("workspace changed during context capture") from exc
        except (OSError, WorkspaceBoundaryError) as exc:
            raise ContextUnavailableError(
                f"workspace read failed for {relative_path}"
            ) from exc

    captured = tuple(sorted(files, key=lambda item: item.relative_path))
    try:
        current_paths = tuple(
            fs.iter_files(
                max_entries=_MAX_SCAN_ENTRIES,
                max_depth=_MAX_SCAN_DEPTH,
            )
        )
    except (OSError, WorkspaceBoundaryError) as exc:
        raise ContextUnavailableError("workspace changed during enumeration") from exc
    if current_paths != paths:
        raise ContextStaleError("workspace file set changed during context capture")

    repository_generation = _manifest_digest(captured)
    index_generation = canonical_digest(
        {
            "repository_generation": repository_generation,
            "index_schema_version": request.index_schema_version,
            "parser_version": request.parser_version,
        }
    )
    structure_paths = tuple(paths[: request.max_structure_entries])
    if len(paths) > request.max_structure_entries:
        reasons.add("structure_entry_bound")
    return _WorkspaceSnapshot(
        files=captured,
        repository_generation=repository_generation,
        index_generation=index_generation,
        structure_paths=structure_paths,
        truncated=bool(reasons),
        truncation_reasons=tuple(sorted(reasons)),
    )


@dataclass(frozen=True, slots=True)
class _Candidate:
    file: _FileSnapshot
    score: int
    matching_terms: tuple[str, ...]


def _symbol_name(symbol: Symbol) -> str:
    return symbol.qualified_name or symbol.name


def _symbol_matches(symbol: Symbol, targets: tuple[str, ...], terms: tuple[str, ...]) -> bool:
    names = (_symbol_name(symbol).casefold(), symbol.name.casefold())
    return any(
        target.casefold() in names or target.casefold() in names[0]
        for target in targets
    ) or any(term in name for term in terms for name in names)


def _path_is_test(path: str) -> bool:
    parts = {part.casefold() for part in Path(path).parts}
    stem = Path(path).stem.casefold()
    return bool(parts & _TEST_PARTS) or stem.startswith("test_") or stem.endswith("_test")


def _is_config(path: str) -> bool:
    return Path(path).name.casefold() in _CONFIG_NAMES or Path(path).suffix.casefold() in {
        ".toml",
        ".yaml",
        ".yml",
        ".ini",
        ".cfg",
    }


def _score_candidate(
    file: _FileSnapshot,
    *,
    query_terms: tuple[str, ...],
    target_files: tuple[str, ...],
    changed_files: tuple[str, ...],
    target_symbols: tuple[str, ...],
) -> _Candidate:
    path_casefold = file.relative_path.casefold()
    matching = tuple(
        sorted(
            term
            for term in query_terms
            if term in path_casefold or term in file.lexical_matches
        )
    )
    score = 0
    if file.relative_path in target_files:
        score += 100_000
    if file.relative_path in changed_files:
        score += 80_000
    score += sum(5_000 for target in target_files if target.casefold() in path_casefold)
    score += sum(250 for term in query_terms if term in path_casefold)
    score += sum(100 for term in query_terms if term in file.lexical_matches)
    if _path_is_test(file.relative_path) and any(
        term in path_casefold for term in ("test", "spec")
    ):
        score += 75
    if _is_config(file.relative_path) and any(
        term in path_casefold for term in ("config", "dependency", "build", "project")
    ):
        score += 50
    if file.parse_result is not None:
        score += sum(
            3_000
            for symbol in file.parse_result.symbols
            if _symbol_matches(symbol, target_symbols, query_terms)
        )
    return _Candidate(file=file, score=score, matching_terms=matching)


def _evidence_unique(values: Iterable[ContextEvidence]) -> tuple[ContextEvidence, ...]:
    unique: dict[tuple[str, str, str, str, str], ContextEvidence] = {}
    for value in values:
        key = (
            value.kind.value,
            value.ref_id,
            value.subject_path or "",
            value.digest or "",
            value.generation,
        )
        unique[key] = value
    return tuple(sorted(unique.values(), key=lambda item: (
        item.kind.value,
        item.ref_id,
        item.subject_path or "",
        item.digest or "",
        item.generation,
    )))


def _evidence_for_file(
    file: _FileSnapshot,
    *,
    request: ContextRequest,
    snapshot: _WorkspaceSnapshot,
    matching_terms: tuple[str, ...],
) -> list[ContextEvidence]:
    evidence = [
        ContextEvidence(
            kind=ContextEvidenceKind.FILE_CONTENT,
            ref_id=file.digest,
            subject_path=file.relative_path,
            digest=file.digest,
            generation=snapshot.repository_generation,
        )
    ]
    if matching_terms:
        evidence.append(
            ContextEvidence(
                kind=ContextEvidenceKind.LEXICAL_SEARCH,
                ref_id=canonical_digest(
                    {
                        "path": file.relative_path,
                        "terms": list(matching_terms),
                        "query": request.query,
                    }
                ),
                subject_path=file.relative_path,
                generation=snapshot.index_generation,
            )
        )
    if file.parse_result is not None:
        evidence.append(
            ContextEvidence(
                kind=ContextEvidenceKind.STRUCTURAL_SEARCH,
                ref_id=canonical_digest(
                    {
                        "path": file.relative_path,
                        "symbols": [
                            _symbol_name(symbol)
                            for symbol in file.parse_result.symbols
                        ],
                    }
                ),
                subject_path=file.relative_path,
                generation=snapshot.index_generation,
            )
        )
    return evidence


def _resolve_import_path(module: str, source_path: str, paths: frozenset[str]) -> str | None:
    normalized = module.replace(".", "/").strip("/")
    if not normalized:
        return None
    source_parent = posixpath.dirname(source_path)
    candidates = (
        posixpath.join(source_parent, normalized) if source_parent else normalized,
        normalized,
    )
    for candidate in candidates:
        for suffix in ("", ".py", ".js", ".ts", ".tsx", ".go", ".rs"):
            full = f"{candidate}{suffix}"
            if full in paths:
                return full
    return None


def _context_symbol(
    symbol: Symbol,
    *,
    file: _FileSnapshot,
    snapshot: _WorkspaceSnapshot,
    evidence: tuple[ContextEvidence, ...],
) -> ContextSymbol:
    location = symbol.location
    qualified_name = _symbol_name(symbol)
    symbol_id = canonical_digest(
        {
            "path": file.relative_path,
            "language": symbol.language,
            "qualified_name": qualified_name,
            "kind": symbol.kind,
            "start_line": location.start_line,
            "start_column": location.start_column,
            "end_line": location.end_line,
            "end_column": location.end_column,
            "byte_start": location.byte_start,
            "byte_end": location.byte_end,
            "content_digest": file.digest,
            "index_generation": snapshot.index_generation,
        }
    )
    return ContextSymbol(
        symbol_id=symbol_id,
        relative_path=file.relative_path,
        language=symbol.language,
        qualified_name=qualified_name,
        kind=symbol.kind,
        start_line=location.start_line,
        start_column=location.start_column,
        end_line=location.end_line,
        end_column=location.end_column,
        byte_start=location.byte_start,
        byte_end=location.byte_end,
        content_digest=file.digest,
        index_generation=snapshot.index_generation,
        evidence=evidence,
    )


def _build_bundle(
    request: ContextRequest,
    snapshot: _WorkspaceSnapshot,
) -> ContextBundle:
    """Rank a captured snapshot and build one deterministic bounded bundle."""

    query_terms = _path_tokens(request.query)
    target_files = request.target_files
    changed_files = request.changed_files
    target_symbols = request.target_symbols
    candidates = [
        _score_candidate(
            file,
            query_terms=query_terms,
            target_files=target_files,
            changed_files=changed_files,
            target_symbols=target_symbols,
        )
        for file in snapshot.files
        if file.content is not None and file.text is not None
    ]
    candidates.sort(key=lambda item: (-item.score, item.file.relative_path))
    reasons = set(snapshot.truncation_reasons)
    if len(candidates) > request.max_query_results:
        candidates = candidates[: request.max_query_results]
        reasons.add("query_result_bound")
    selected = candidates[: request.max_files]
    if len(candidates) > request.max_files:
        reasons.add("file_count_bound")
    selected_paths = {item.file.relative_path for item in selected}
    for path in (*target_files, *changed_files):
        if path not in selected_paths:
            reasons.add("target_not_available")

    all_paths = frozenset(item.relative_path for item in snapshot.files)
    document_evidence: dict[str, tuple[ContextEvidence, ...]] = {}
    for candidate in selected:
        values = _evidence_for_file(
            candidate.file,
            request=request,
            snapshot=snapshot,
            matching_terms=candidate.matching_terms,
        )
        document_evidence[candidate.file.relative_path] = _evidence_unique(values)

    # Resolve local parser relationships only inside the captured workspace
    # snapshot.  No repository-wide path or host filesystem lookup is used.
    by_name: dict[str, list[tuple[_FileSnapshot, Symbol]]] = {}
    for file in snapshot.files:
        if file.parse_result is None:
            continue
        for symbol in file.parse_result.symbols:
            symbol_entry = (file, symbol)
            symbol_names = {
                symbol.name.casefold(),
                _symbol_name(symbol).casefold(),
            }
            for symbol_name in symbol_names:
                entries = by_name.setdefault(symbol_name, [])
                if symbol_entry not in entries:
                    entries.append(symbol_entry)
    relation_values: dict[str, list[ContextEvidence]] = {
        path: list(values) for path, values in document_evidence.items()
    }
    for candidate in selected:
        result = candidate.file.parse_result
        if result is None:
            continue
        for imported in result.imports:
            target_path = _resolve_import_path(imported.module, candidate.file.relative_path, all_paths)
            if target_path is None:
                continue
            if target_path in selected_paths:
                relation_values.setdefault(candidate.file.relative_path, []).append(
                    ContextEvidence(
                        kind=ContextEvidenceKind.IMPORT,
                        ref_id=canonical_digest(
                            {"source": candidate.file.relative_path, "target": target_path}
                        ),
                        subject_path=target_path,
                        generation=snapshot.index_generation,
                    )
                )
                relation_values.setdefault(target_path, []).append(
                    ContextEvidence(
                        kind=ContextEvidenceKind.REVERSE_IMPORT,
                        ref_id=canonical_digest(
                            {"source": candidate.file.relative_path, "target": target_path}
                        ),
                        subject_path=candidate.file.relative_path,
                        generation=snapshot.index_generation,
                    )
                )
        for call in result.calls:
            matches = by_name.get(call.callee.casefold(), [])
            if len(matches) == 1:
                target_file, target_symbol = matches[0]
                if target_file.relative_path in selected_paths:
                    relation_id = canonical_digest(
                        {
                            "caller": candidate.file.relative_path,
                            "callee": target_symbol.qualified_name,
                            "byte_start": call.location.byte_start,
                        }
                    )
                    relation_values.setdefault(candidate.file.relative_path, []).append(
                        ContextEvidence(
                            kind=ContextEvidenceKind.CALLEE,
                            ref_id=relation_id,
                            subject_path=target_file.relative_path,
                            generation=snapshot.index_generation,
                        )
                    )
                    relation_values.setdefault(target_file.relative_path, []).append(
                        ContextEvidence(
                            kind=ContextEvidenceKind.CALLER,
                            ref_id=relation_id,
                            subject_path=candidate.file.relative_path,
                            generation=snapshot.index_generation,
                        )
                    )
        for reference in result.references:
            matches = by_name.get(reference.name.casefold(), [])
            if len(matches) == 1:
                target_file, target_symbol = matches[0]
                if target_file.relative_path in selected_paths:
                    relation_id = canonical_digest(
                        {
                            "source": candidate.file.relative_path,
                            "target": target_symbol.qualified_name,
                            "byte_start": reference.location.byte_start,
                        }
                    )
                    relation_values.setdefault(candidate.file.relative_path, []).append(
                        ContextEvidence(
                            kind=ContextEvidenceKind.SYMBOL_REFERENCE,
                            ref_id=relation_id,
                            subject_path=target_file.relative_path,
                            generation=snapshot.index_generation,
                        )
                    )
        if _path_is_test(candidate.file.relative_path):
            relation_values.setdefault(candidate.file.relative_path, []).append(
                ContextEvidence(
                    kind=ContextEvidenceKind.RELATED_TEST,
                    ref_id=canonical_digest({"path": candidate.file.relative_path}),
                    subject_path=candidate.file.relative_path,
                    generation=snapshot.index_generation,
                )
            )
        if _is_config(candidate.file.relative_path):
            relation_values.setdefault(candidate.file.relative_path, []).append(
                ContextEvidence(
                    kind=ContextEvidenceKind.REPOSITORY_CONFIG,
                    ref_id=canonical_digest({"path": candidate.file.relative_path}),
                    subject_path=candidate.file.relative_path,
                    generation=snapshot.index_generation,
                )
            )

    documents: list[ContextDocument] = []
    all_evidence: list[ContextEvidence] = []
    for candidate in selected[: request.max_excerpts]:
        file = candidate.file
        values = _evidence_unique(relation_values.get(file.relative_path, ()))
        document = ContextDocument(
            relative_path=file.relative_path,
            language=_language_for_path(file.relative_path),
            content=file.text or "",
            content_digest=file.digest,
            file_size=file.file_size,
            source_kind=ContextSourceKind.WORKSPACE_SNAPSHOT,
            workspace_id=request.workspace_id,
            repository_id=request.repository_id,
            base_revision=request.base_revision,
            repository_generation=snapshot.repository_generation,
            index_generation=snapshot.index_generation,
            excerpt_start=0,
            excerpt_end=len(file.content or b""),
            truncated=len(file.content or b"") < file.file_size,
            relevance_score=candidate.score,
            evidence=values,
        )
        documents.append(document)
        all_evidence.extend(values)
    if len(selected) > request.max_excerpts:
        reasons.add("excerpt_count_bound")

    symbols: list[ContextSymbol] = []
    for candidate in selected:
        result = candidate.file.parse_result
        if result is None:
            continue
        values = _evidence_unique(relation_values.get(candidate.file.relative_path, ()))
        for parsed_symbol in result.symbols:
            symbol_evidence = list(values)
            if _symbol_matches(parsed_symbol, target_symbols, query_terms):
                symbol_evidence.append(
                    ContextEvidence(
                        kind=ContextEvidenceKind.SYMBOL_DEFINITION,
                        ref_id=canonical_digest(
                            {
                                "path": candidate.file.relative_path,
                                "symbol": _symbol_name(parsed_symbol),
                            }
                        ),
                        subject_path=candidate.file.relative_path,
                        digest=candidate.file.digest,
                        generation=snapshot.index_generation,
                    )
                )
            symbols.append(
                _context_symbol(
                    parsed_symbol,
                    file=candidate.file,
                    snapshot=snapshot,
                    evidence=_evidence_unique(symbol_evidence),
                )
            )
    symbols.sort(key=lambda item: (
        0 if any(e.kind is ContextEvidenceKind.SYMBOL_DEFINITION for e in item.evidence) else 1,
        item.relative_path,
        item.qualified_name,
        item.byte_start,
        item.byte_end,
        item.symbol_id,
    ))
    if len(symbols) > request.max_symbols:
        symbols = symbols[: request.max_symbols]
        reasons.add("symbol_count_bound")

    return ContextBundle(
        bundle_id=uuid.uuid4().hex,
        task_id=request.task_id,
        principal_id=request.principal_id,
        project_id=request.project_id,
        goal_spec_id=request.goal_spec_id,
        goal_spec_digest=request.goal_spec_digest,
        workspace_id=request.workspace_id,
        repository_id=request.repository_id,
        base_revision=request.base_revision,
        request_digest=request.request_digest,
        repository_generation=snapshot.repository_generation,
        index_generation=snapshot.index_generation,
        freshness=ContextFreshness.FRESH,
        documents=tuple(documents),
        symbols=tuple(symbols),
        evidence=_evidence_unique(all_evidence),
        structure_paths=snapshot.structure_paths,
        truncated=bool(reasons),
        truncation_reasons=tuple(sorted(reasons)),
    )


def _stale_bundle(request: ContextRequest, *, generation: str = "stale") -> ContextBundle:
    """Return an explicit stale projection after a bounded race retry."""

    index_generation = canonical_digest(
        {
            "repository_generation": generation,
            "index_schema_version": request.index_schema_version,
            "parser_version": request.parser_version,
        }
    )
    return ContextBundle(
        bundle_id=uuid.uuid4().hex,
        task_id=request.task_id,
        principal_id=request.principal_id,
        project_id=request.project_id,
        goal_spec_id=request.goal_spec_id,
        goal_spec_digest=request.goal_spec_digest,
        workspace_id=request.workspace_id,
        repository_id=request.repository_id,
        base_revision=request.base_revision,
        request_digest=request.request_digest,
        repository_generation=generation,
        index_generation=index_generation,
        freshness=ContextFreshness.STALE,
        structure_paths=(),
        truncated=True,
        truncation_reasons=("workspace_mutation_race",),
    )


def _snapshot_by_path(snapshot: _WorkspaceSnapshot) -> dict[str, _FileSnapshot]:
    return {item.relative_path: item for item in snapshot.files}


def _cached_bundle_matches_snapshot(
    bundle: ContextBundle,
    *,
    request: ContextRequest,
    snapshot: _WorkspaceSnapshot,
) -> bool:
    """Check identity and every retained document's current content digest."""

    if (
        bundle.task_id != request.task_id
        or bundle.principal_id != request.principal_id
        or bundle.project_id != request.project_id
        or bundle.goal_spec_id != request.goal_spec_id
        or bundle.goal_spec_digest != request.goal_spec_digest
        or bundle.workspace_id != request.workspace_id
        or bundle.repository_id != request.repository_id
        or bundle.request_digest != request.request_digest
        or bundle.repository_generation != snapshot.repository_generation
        or bundle.index_generation != snapshot.index_generation
        or bundle.freshness is not ContextFreshness.FRESH
    ):
        return False
    files = _snapshot_by_path(snapshot)
    return all(
        files.get(document.relative_path) is not None
        and files[document.relative_path].digest == document.content_digest
        for document in bundle.documents
    )


class ContextIntelligenceService:
    """Build deterministic context from one owner-scoped TaskWorkspace.

    ``WorkspaceManager`` is deliberately the only injected owner.  The
    production runtime constructs this service itself, while tests may use a
    small provider implementing ``get`` and ``require``.  The service has no
    permission or execution authority and never falls back to a host path.
    """

    def __init__(
        self,
        workspace_manager: WorkspaceProvider,
        *,
        registry: LanguageRegistry | None = None,
        cache: _ContextBundleCache | None = None,
    ) -> None:
        self._workspace_manager = workspace_manager
        self._registry = registry or LanguageRegistry()
        self._cache = cache or _ContextBundleCache()
        self._query_lock = asyncio.Lock()

    @staticmethod
    def repository_id_for_workspace(workspace: TaskWorkspace) -> str:
        """Expose the same repository identity used by cache validation."""

        return repository_id_for_workspace(workspace)

    def invalidate(self, workspace_id: str, changed_files: tuple[str, ...] = ()) -> None:
        """Invalidate cached context after a committed workspace mutation.

        The current cache is intentionally invalidated at workspace scope.
        Path-level invalidation would be an optimization only and could not
        safely account for imports, reverse imports, or ranking changes.
        ``changed_files`` is accepted as typed observability input but is not
        trusted to narrow the invalidation boundary.
        """

        del changed_files
        self._cache.invalidate_workspace(workspace_id)

    def invalidate_from_tool_result(
        self,
        *,
        workspace_id: str,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
    ) -> None:
        """Invalidate after a known mutation tool reports success.

        This hook is only a freshness optimization.  It never authorizes the
        tool and never trusts model-controlled paths as a filesystem boundary.
        Digest/generation validation remains mandatory on the next query.
        """

        mutation_tools = frozenset(
            {
                "write_file",
                "patch",
                "multi_edit",
                "copy_file",
                "move_file",
                "delete_file",
                "make_directory",
                "mkdir",
            }
        )
        if tool_name in mutation_tools:
            del arguments
            self.invalidate(workspace_id)

    def _resolve_workspace(self, request: ContextRequest) -> TaskWorkspace:
        try:
            workspace = self._workspace_manager.get(request.workspace_id)
        except (AttributeError, KeyError, TypeError) as exc:
            raise ContextUnavailableError("workspace owner is unavailable") from exc
        if workspace is None:
            raise ContextUnavailableError("TaskWorkspace is unavailable")
        if (
            getattr(workspace, "id", None) != request.workspace_id
            or getattr(workspace, "task_id", None) != request.task_id
            or getattr(workspace, "principal_id", None) != request.principal_id
            or getattr(workspace, "project_id", None) != request.project_id
        ):
            raise ContextUnavailableError("TaskWorkspace owner binding mismatch")
        require = getattr(self._workspace_manager, "require", None)
        if require is not None:
            runtime_id = request.runtime_id or getattr(workspace, "creator_runtime_id", "")
            try:
                required = require(
                    request.workspace_id,
                    task_id=request.task_id,
                    principal_id=request.principal_id,
                    project_id=request.project_id,
                    runtime_id=runtime_id,
                )
            except (OSError, PermissionError, RuntimeError, TypeError) as exc:
                raise ContextUnavailableError(
                    "TaskWorkspace owner or root identity validation failed"
                ) from exc
            if required is None:
                raise ContextUnavailableError("TaskWorkspace is unavailable")
            workspace = required
        return workspace

    @staticmethod
    def _validate_goal_binding(request: ContextRequest, goal_spec: GoalSpec) -> None:
        if not isinstance(goal_spec, GoalSpec):
            raise ContextInputError("canonical GoalSpec is required")
        if (
            goal_spec.goal_spec_id != request.goal_spec_id
            or goal_spec.semantic_digest != request.goal_spec_digest
        ):
            raise ContextInputError("ContextRequest GoalSpec binding is stale")

    def _validate_workspace_binding(
        self,
        request: ContextRequest,
        workspace: TaskWorkspace,
    ) -> None:
        expected_repository = repository_id_for_workspace(workspace)
        if expected_repository != request.repository_id:
            raise ContextInputError("ContextRequest repository identity is stale")
        workspace_base = getattr(workspace, "base_sha", None)
        if request.base_revision is not None and request.base_revision != workspace_base:
            raise ContextInputError("ContextRequest base revision is stale")
        if workspace_base is not None and not isinstance(workspace_base, str):
            raise ContextUnavailableError("TaskWorkspace base revision is malformed")

    def _retrieve_sync(
        self,
        request: ContextRequest,
        goal_spec: GoalSpec,
    ) -> ContextBundle:
        self._validate_goal_binding(request, goal_spec)
        workspace = self._resolve_workspace(request)
        self._validate_workspace_binding(request, workspace)
        try:
            with SafeWorkspaceFS(workspace.worktree_path) as fs:
                last_snapshot: _WorkspaceSnapshot | None = None
                for _ in range(_MAX_CAPTURE_RETRIES):
                    try:
                        snapshot = _capture_workspace_snapshot(
                            fs, request, self._registry
                        )
                        last_snapshot = snapshot
                        key = _CacheKey(
                            request_digest=request.request_digest,
                            repository_id=request.repository_id,
                            workspace_id=request.workspace_id,
                            base_revision=request.base_revision,
                            repository_generation=snapshot.repository_generation,
                            index_schema_version=request.index_schema_version,
                            parser_version=request.parser_version,
                        )
                        cached = self._cache.get(key)
                        if cached is not None and _cached_bundle_matches_snapshot(
                            cached, request=request, snapshot=snapshot
                        ):
                            return cached
                        bundle = _build_bundle(request, snapshot)
                        # Recapture the manifest after ranking/serialization so
                        # a mutation racing a query cannot be relabelled as
                        # the new generation.
                        final_snapshot = _capture_workspace_snapshot(
                            fs, request, self._registry
                        )
                        if (
                            final_snapshot.repository_generation
                            != snapshot.repository_generation
                        ):
                            last_snapshot = final_snapshot
                            continue
                        self._cache.put(key, bundle)
                        return bundle
                    except ContextStaleError:
                        continue
                generation = (
                    last_snapshot.repository_generation
                    if last_snapshot is not None
                    else "stale"
                )
                return _stale_bundle(request, generation=generation)
        except ContextQueryError:
            raise
        except (OSError, WorkspaceBoundaryError) as exc:
            raise ContextUnavailableError("safe workspace context is unavailable") from exc

    async def retrieve(self, request: ContextRequest, goal_spec: GoalSpec) -> ContextBundle:
        """Return one fresh, bounded bundle or an explicit stale projection."""

        # Serializing captures within one service prevents its in-process cache
        # from publishing two competing snapshots.  Cross-runtime races are
        # still protected by the second capture and digest generation fence.
        async with self._query_lock:
            return await asyncio.to_thread(self._retrieve_sync, request, goal_spec)

    async def query(self, request: ContextRequest, goal_spec: GoalSpec) -> ContextBundle:
        """Compatibility alias for callers that name retrieval ``query``."""

        return await self.retrieve(request, goal_spec)

    async def build_context(
        self, request: ContextRequest, goal_spec: GoalSpec
    ) -> ContextBundle:
        """Compatibility alias for callers that name retrieval ``build_context``."""

        return await self.retrieve(request, goal_spec)


WorkspaceCodeQueryService = ContextIntelligenceService


__all__ = [
    "ContextInputError",
    "ContextIntelligenceService",
    "ContextQueryError",
    "ContextStaleError",
    "ContextUnavailableError",
    "WorkspaceCodeQueryService",
    "repository_id_for_workspace",
]
