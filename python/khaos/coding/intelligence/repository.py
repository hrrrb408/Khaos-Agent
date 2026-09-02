"""Unified, workspace-bound repository intelligence for Coding mode.

This module is the M8.1 convergence point.  It owns the workspace/repository
generation projection and exposes typed query results while delegating parsing,
incremental state, and semantic graph construction to the existing M3
``RepositoryIndexer``/``IndexStore``/``ResolutionService`` stack.

The service is deliberately advisory.  It does not grant filesystem,
permission, approval, execution, verification, or completion authority.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import os
import sqlite3
import stat
import threading
import time
from collections import OrderedDict
from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import Enum
from fnmatch import fnmatch
from pathlib import Path, PurePosixPath
from typing import Any

from khaos.coding.intelligence.index import (
    IndexStore,
    RepositoryIndexer,
    RepositoryIndexLimits,
    SafeWorkspaceSourceAccess,
)
from khaos.coding.intelligence.models import ParseResult, ParserMetadata
from khaos.coding.intelligence.query import CodeQueryService
from khaos.coding.intelligence.registry import LanguageRegistry
from khaos.coding.intelligence.resolution.ids import stable_symbol_id, symbol_id
from khaos.coding.intelligence.resolution.service import ResolutionService
from khaos.coding.planning.safe_workspace_path import SafePathError
from khaos.security.protocol_boundary import canonical_digest


class RepoContractError(ValueError):
    """A typed repository-intelligence request or event is malformed."""


class RepoIntelligenceUnavailableError(RuntimeError):
    """The requested freshness or workspace boundary cannot be satisfied."""


class RepoIntelligenceIndexUnavailableError(RepoIntelligenceUnavailableError):
    """The derived index backend is unavailable but the workspace is bound."""


def _workspace_safety_types() -> tuple[type[Any], type[Exception]]:
    """Load workspace-bound readers lazily to keep package imports acyclic."""

    from khaos.coding.workspace.boundary import SafeWorkspaceFS, WorkspaceBoundaryError

    return SafeWorkspaceFS, WorkspaceBoundaryError


class IntelligenceFreshness(str, Enum):
    """Freshness of derived intelligence relative to one workspace root."""

    CURRENT = "current"
    STALE = "stale"
    PARTIAL = "partial"
    UNAVAILABLE = "unavailable"


class FreshnessPolicy(str, Enum):
    """How a query may use a dirty or bounded index."""

    REQUIRE_CURRENT = "require_current"
    PREFER_CURRENT = "prefer_current"
    ALLOW_STALE = "allow_stale"


class MutationType(str, Enum):
    """Workspace mutation classes that can invalidate repository intelligence."""

    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    RENAME = "rename"
    MOVE = "move"
    COPY = "copy"
    RESTORE = "restore"
    ROLLBACK = "rollback"


class RepoQueryKind(str, Enum):
    """Supported typed repository queries."""

    SYMBOLS = "symbols"
    DEFINITIONS = "definitions"
    REFERENCES = "references"
    CALLERS = "callers"
    CALLEES = "callees"
    IMPORTERS = "importers"
    IMPORTS = "imports"
    RELATED_FILES = "related_files"
    SEARCH_TEXT = "search_text"
    REPOSITORY_OVERVIEW = "repository_overview"
    RELATED_TESTS = "related_tests"


def _require_text(value: object, label: str, *, allow_empty: bool = False) -> str:
    if type(value) is not str or (not allow_empty and not value):
        raise RepoContractError(f"{label} must be a string")
    if "\x00" in value:
        raise RepoContractError(f"{label} contains a NUL byte")
    if len(value) > 16 * 1024:
        raise RepoContractError(f"{label} exceeds its bound")
    return value


def normalize_repo_path(value: str, *, label: str = "path") -> str:
    """Validate one workspace-relative POSIX path without resolving it."""
    _require_text(value, label=label)
    candidate = PurePosixPath(value.replace("\\", "/"))
    if candidate.is_absolute() or not candidate.parts:
        raise RepoContractError(f"{label} must be workspace-relative")
    if any(part in {"", ".", ".."} for part in candidate.parts):
        raise RepoContractError(f"{label} is not normalized")
    if any(
        part.casefold()
        in {".git", ".agents", ".codex", ".khaos", "khaos_policy.yaml"}
        for part in candidate.parts
    ):
        raise RepoContractError(f"{label} reaches protected metadata")
    return candidate.as_posix()


def _normalize_paths(values: tuple[str, ...], *, label: str) -> tuple[str, ...]:
    if type(values) is not tuple:
        raise RepoContractError(f"{label} must be a tuple")
    if len(values) > 256:
        raise RepoContractError(f"{label} exceeds its path-count bound")
    return tuple(sorted({normalize_repo_path(value, label=label) for value in values}))


@dataclass(frozen=True, slots=True)
class RepositoryGeneration:
    """Owner-scoped generation and persisted manifest identity."""

    workspace_id: str
    generation: int
    manifest_digest: str
    indexed_at: float | None = None
    source_revision: str | None = None

    def __post_init__(self) -> None:
        _require_text(self.workspace_id, "workspace_id")
        if type(self.generation) is not int or self.generation < 0:
            raise RepoContractError("generation must be a non-negative integer")
        _require_text(self.manifest_digest, "manifest_digest")
        if (
            len(self.manifest_digest) != 64
            or any(character not in "0123456789abcdef" for character in self.manifest_digest)
        ):
            raise RepoContractError("manifest_digest must be a lowercase SHA-256 digest")
        if self.indexed_at is not None and type(self.indexed_at) not in (int, float):
            raise RepoContractError("indexed_at must be numeric")
        if self.indexed_at is not None and (
            not math.isfinite(float(self.indexed_at)) or self.indexed_at < 0
        ):
            raise RepoContractError("indexed_at must be finite and non-negative")
        if self.source_revision is not None:
            _require_text(self.source_revision, "source_revision")

    def as_id(self) -> str:
        return f"{self.generation}:{self.manifest_digest}"


@dataclass(frozen=True, slots=True)
class MutationEvent:
    """A narrow observer event; it never authorizes the mutation itself."""

    workspace_id: str
    mutation_type: MutationType
    paths: tuple[str, ...] = ()
    source_revision: str | None = None

    def __post_init__(self) -> None:
        _require_text(self.workspace_id, "workspace_id")
        mutation = self.mutation_type
        if isinstance(mutation, str):
            try:
                mutation = MutationType(mutation)
            except ValueError as exc:
                raise RepoContractError("unknown mutation type") from exc
            object.__setattr__(self, "mutation_type", mutation)
        if type(mutation) is not MutationType:
            raise RepoContractError("mutation_type must be a MutationType")
        object.__setattr__(self, "paths", _normalize_paths(self.paths, label="mutation paths"))
        if self.source_revision is not None:
            _require_text(self.source_revision, "source_revision")


@dataclass(frozen=True, slots=True)
class RepoResourceLimits:
    """Bound all index, query, and context work performed by the facade."""

    max_files: int = 10_000
    max_index_bytes: int = 256 * 1024 * 1024
    max_file_bytes: int = 2 * 1024 * 1024
    max_symbols: int = 100_000
    max_relations: int = 200_000
    max_depth: int = 32
    max_query_results: int = 256
    max_index_duration_seconds: float = 30.0

    def __post_init__(self) -> None:
        for name in (
            "max_files",
            "max_index_bytes",
            "max_file_bytes",
            "max_symbols",
            "max_relations",
            "max_query_results",
        ):
            value = getattr(self, name)
            if type(value) is not int or value <= 0:
                raise RepoContractError(f"{name} must be a positive integer")
        if type(self.max_depth) is not int or self.max_depth < 0:
            raise RepoContractError("max_depth must be non-negative")
        if type(self.max_index_duration_seconds) not in (int, float) or self.max_index_duration_seconds <= 0:
            raise RepoContractError("max_index_duration_seconds must be positive")

    def indexer_limits(self) -> RepositoryIndexLimits:
        return RepositoryIndexLimits(
            max_files=self.max_files,
            max_bytes=self.max_index_bytes,
            max_file_bytes=self.max_file_bytes,
            max_depth=self.max_depth,
            max_duration_seconds=self.max_index_duration_seconds,
        )


@dataclass(frozen=True, slots=True)
class RepoQueryRequest:
    """Owner-bound typed query request."""

    workspace_id: str
    task_id: str
    principal_id: str
    project_id: str
    kind: RepoQueryKind
    query: str = ""
    path: str = ""
    symbol_id: str = ""
    target_files: tuple[str, ...] = ()
    target_symbols: tuple[str, ...] = ()
    freshness_policy: FreshnessPolicy = FreshnessPolicy.PREFER_CURRENT
    limit: int = 32
    max_bytes: int = 256 * 1024
    max_file_bytes: int = 64 * 1024
    request_digest: str = ""
    path_prefix: str = ""
    path_glob: str = "*"
    language: str = ""

    def __post_init__(self) -> None:
        for name in ("workspace_id", "task_id", "principal_id", "project_id"):
            _require_text(getattr(self, name), name)
        kind = self.kind
        if isinstance(kind, str):
            try:
                kind = RepoQueryKind(kind)
            except ValueError as exc:
                raise RepoContractError("unknown repository query kind") from exc
            object.__setattr__(self, "kind", kind)
        if type(kind) is not RepoQueryKind:
            raise RepoContractError("kind must be a RepoQueryKind")
        policy = self.freshness_policy
        if isinstance(policy, str):
            try:
                policy = FreshnessPolicy(policy)
            except ValueError as exc:
                raise RepoContractError("unknown freshness policy") from exc
            object.__setattr__(self, "freshness_policy", policy)
        if type(policy) is not FreshnessPolicy:
            raise RepoContractError("freshness_policy must be a FreshnessPolicy")
        _require_text(self.query, "query", allow_empty=True)
        if self.path:
            object.__setattr__(self, "path", normalize_repo_path(self.path))
        if self.path_prefix:
            object.__setattr__(
                self,
                "path_prefix",
                normalize_repo_path(self.path_prefix, label="path_prefix"),
            )
        _require_text(self.path_glob, "path_glob", allow_empty=True)
        if len(self.path_glob) > 256:
            raise RepoContractError("path_glob exceeds its bound")
        _require_text(self.language, "language", allow_empty=True)
        if self.symbol_id:
            _require_text(self.symbol_id, "symbol_id")
        object.__setattr__(self, "target_files", _normalize_paths(self.target_files, label="target_files"))
        target_symbols = _normalize_text_tuple(self.target_symbols, "target_symbols")
        object.__setattr__(self, "target_symbols", target_symbols)
        for name in ("limit", "max_bytes", "max_file_bytes"):
            value = getattr(self, name)
            if type(value) is not int or value <= 0:
                raise RepoContractError(f"{name} must be a positive integer")
        payload = {
            "workspace_id": self.workspace_id,
            "task_id": self.task_id,
            "principal_id": self.principal_id,
            "project_id": self.project_id,
            "kind": kind.value,
            "query": self.query,
            "path": self.path,
            "symbol_id": self.symbol_id,
            "target_files": self.target_files,
            "target_symbols": self.target_symbols,
            "freshness_policy": policy.value,
            "limit": self.limit,
            "max_bytes": self.max_bytes,
            "max_file_bytes": self.max_file_bytes,
            "path_prefix": self.path_prefix,
            "path_glob": self.path_glob,
            "language": self.language,
        }
        expected = canonical_digest(payload)
        if self.request_digest:
            if self.request_digest != expected:
                raise RepoContractError("request_digest does not match request semantics")
        else:
            object.__setattr__(self, "request_digest", expected)


def _normalize_text_tuple(values: tuple[str, ...], label: str) -> tuple[str, ...]:
    if type(values) is not tuple or any(type(value) is not str for value in values):
        raise RepoContractError(f"{label} must be a tuple of strings")
    if len(values) > 256:
        raise RepoContractError(f"{label} exceeds its item-count bound")
    return tuple(sorted({_require_text(value, label) for value in values}))


@dataclass(frozen=True, slots=True)
class RepoFile:
    path: str
    language: str
    size: int
    mtime_ns: int
    content_digest: str
    generation: int
    path_role: str = "source"
    semantic_support: bool = False
    parser_source: str = "unknown"


@dataclass(frozen=True, slots=True)
class RepoSymbol:
    symbol_id: str
    stable_symbol_id: str
    path: str
    language: str
    kind: str
    name: str
    qualified_name: str
    byte_start: int
    byte_end: int
    start_line: int
    end_line: int
    start_column: int = 0
    end_column: int = 0
    generation: int = 0
    content_digest: str = ""


@dataclass(frozen=True, slots=True)
class RepoRelation:
    kind: str
    source_path: str
    target_path: str | None = None
    source_symbol_id: str | None = None
    target_symbol_id: str | None = None
    name: str = ""
    status: str = "resolved"
    confidence: float = 0.0
    evidence_id: str = ""


@dataclass(frozen=True, slots=True)
class RepoTextMatch:
    path: str
    line: int
    text: str
    language: str = "text"


@dataclass(frozen=True, slots=True)
class RepoOverview:
    file_count: int
    symbol_count: int
    relation_count: int
    languages: tuple[str, ...]
    truncated: bool = False
    important_roots: tuple[str, ...] = ()
    package_roots: tuple[str, ...] = ()
    entry_points: tuple[str, ...] = ()
    test_roots: tuple[str, ...] = ()
    build_files: tuple[str, ...] = ()
    config_files: tuple[str, ...] = ()
    top_symbols: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class RepoQueryResult:
    generation: RepositoryGeneration
    freshness: IntelligenceFreshness
    kind: RepoQueryKind
    files: tuple[RepoFile, ...] = ()
    symbols: tuple[RepoSymbol, ...] = ()
    relations: tuple[RepoRelation, ...] = ()
    text_matches: tuple[RepoTextMatch, ...] = ()
    overview: RepoOverview | None = None
    truncated: bool = False
    truncation_reasons: tuple[str, ...] = ()
    semantic_support: bool = False
    lexical_fallback: bool = False


@dataclass(frozen=True, slots=True)
class RepoRefreshReport:
    generation: RepositoryGeneration
    freshness: IntelligenceFreshness
    full_reindex: bool
    scanned_files: int
    parsed_files: int
    reparsed_files: int
    incremental_files: int
    unchanged_files: int
    deleted_files: int
    unsupported_files: int
    failed_files: int
    truncated: bool
    duration_ms: float


@dataclass(frozen=True, slots=True)
class RepoIntelligenceMetrics:
    query_count: int = 0
    cache_hit_count: int = 0
    cache_miss_count: int = 0
    full_index_count: int = 0
    incremental_refresh_count: int = 0
    parsed_file_count: int = 0
    reparsed_file_count: int = 0
    semantic_query_count: int = 0
    lexical_fallback_count: int = 0
    stale_query_count: int = 0
    context_candidate_file_count: int = 0
    context_selected_file_count: int = 0
    context_selected_symbol_count: int = 0

    # Friendly aliases used by telemetry adapters and evaluation reports.
    @property
    def full_refresh_count(self) -> int:
        return self.full_index_count

    @property
    def incremental_file_count(self) -> int:
        return self.reparsed_file_count


@dataclass(frozen=True, slots=True)
class RepoContextRequest:
    workspace_id: str
    task_id: str
    principal_id: str
    project_id: str
    query: str
    target_files: tuple[str, ...] = ()
    target_symbols: tuple[str, ...] = ()
    changed_files: tuple[str, ...] = ()
    freshness_policy: FreshnessPolicy = FreshnessPolicy.PREFER_CURRENT
    max_files: int = 16
    max_symbols: int = 128
    max_bytes: int = 256 * 1024
    max_file_bytes: int = 64 * 1024
    max_structure_entries: int = 512

    def __post_init__(self) -> None:
        for name in ("workspace_id", "task_id", "principal_id", "project_id"):
            _require_text(getattr(self, name), name)
        _require_text(self.query, "query", allow_empty=True)
        object.__setattr__(self, "target_files", _normalize_paths(self.target_files, label="target_files"))
        object.__setattr__(self, "target_symbols", _normalize_text_tuple(self.target_symbols, "target_symbols"))
        object.__setattr__(self, "changed_files", _normalize_paths(self.changed_files, label="changed_files"))
        policy = self.freshness_policy
        if isinstance(policy, str):
            policy = FreshnessPolicy(policy)
            object.__setattr__(self, "freshness_policy", policy)
        if type(policy) is not FreshnessPolicy:
            raise RepoContractError("freshness_policy must be a FreshnessPolicy")
        for name in ("max_files", "max_symbols", "max_bytes", "max_file_bytes", "max_structure_entries"):
            if type(getattr(self, name)) is not int or getattr(self, name) <= 0:
                raise RepoContractError(f"{name} must be a positive integer")

    @property
    def request_digest(self) -> str:
        """Return a stable digest for the bounded context query semantics."""
        return canonical_digest(
            {
                "workspace_id": self.workspace_id,
                "task_id": self.task_id,
                "principal_id": self.principal_id,
                "project_id": self.project_id,
                "query": self.query,
                "target_files": self.target_files,
                "target_symbols": self.target_symbols,
                "changed_files": self.changed_files,
                "freshness_policy": self.freshness_policy.value,
                "max_files": self.max_files,
                "max_symbols": self.max_symbols,
                "max_bytes": self.max_bytes,
                "max_file_bytes": self.max_file_bytes,
                "max_structure_entries": self.max_structure_entries,
            }
        )


@dataclass(frozen=True, slots=True)
class RepoContextFile:
    path: str
    language: str
    content: str
    content_digest: str
    file_size: int
    relevance_score: int
    generation: int
    evidence: tuple[RepoRelation, ...] = ()
    truncated: bool = False


@dataclass(frozen=True, slots=True)
class RepoContextResult:
    generation: RepositoryGeneration
    freshness: IntelligenceFreshness
    files: tuple[RepoContextFile, ...]
    symbols: tuple[RepoSymbol, ...]
    relations: tuple[RepoRelation, ...]
    structure_paths: tuple[str, ...]
    truncated: bool = False
    truncation_reasons: tuple[str, ...] = ()
    candidate_file_count: int = 0
    lexical_fallback: bool = False


@dataclass
class _PendingState:
    paths: set[str] = field(default_factory=set)
    deleted_paths: set[str] = field(default_factory=set)
    full_refresh_required: bool = False
    source_revision: str | None = None


@dataclass
class _WorkspaceHandle:
    workspace_id: str
    project_id: str
    repository_id: str
    index_project_id: str
    root: Path
    root_identity: str
    store: IndexStore
    indexer: RepositoryIndexer
    query_service: CodeQueryService
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    state_loaded: bool = False
    generation: int = 0
    manifest_digest: str = ""
    freshness: IntelligenceFreshness = IntelligenceFreshness.UNAVAILABLE
    indexed_at: float | None = None
    source_revision: str | None = None
    pending_paths: set[str] = field(default_factory=set)
    deleted_paths: set[str] = field(default_factory=set)
    full_refresh_required: bool = False
    truncated: bool = False
    truncation_reasons: tuple[str, ...] = ()


def _matches_path_scope(
    path: str,
    *,
    path_prefix: str,
    path_glob: str,
    language: str,
    symbol_language: str,
) -> bool:
    """Apply the same bounded root/glob/language scope to semantic rows."""
    if path_prefix:
        prefix = path_prefix.rstrip("/")
        if path == prefix:
            display_path = ""
        elif path.startswith(prefix + "/"):
            display_path = path[len(prefix) + 1 :]
        else:
            return False
    else:
        display_path = path
    if not fnmatch(display_path, path_glob):
        return False
    return not language or symbol_language.casefold() == language.casefold()


class RepoIntelligenceService:
    """One owner-scoped facade over the M3 parser/index/semantic graph."""

    def __init__(
        self,
        workspace_manager: Any,
        *,
        registry: LanguageRegistry | None = None,
        database: sqlite3.Connection | str | Path | None = None,
        limits: RepoResourceLimits | None = None,
    ) -> None:
        self._workspace_manager = workspace_manager
        self._registry = registry or LanguageRegistry()
        self._database = database
        self._limits = limits or RepoResourceLimits()
        self._handles: dict[str, _WorkspaceHandle] = {}
        self._pending: dict[str, _PendingState] = {}
        self._handles_lock = threading.RLock()
        self._metrics_lock = threading.RLock()
        self._metrics = RepoIntelligenceMetrics()
        self._result_cache: OrderedDict[tuple[str, int, str], RepoQueryResult] = OrderedDict()
        self._context_cache: OrderedDict[tuple[str, int, str], RepoContextResult] = OrderedDict()
        self._cache_lock = threading.RLock()
        self._shared_store: IndexStore | None = None
        self._closed = False

    def _add_metric(self, **increments: int) -> None:
        with self._metrics_lock:
            values = {name: getattr(self._metrics, name) + int(value) for name, value in increments.items()}
            self._metrics = RepoIntelligenceMetrics(**{field_name: values.get(field_name, getattr(self._metrics, field_name)) for field_name in self._metrics.__dataclass_fields__})

    def _record_context_metrics(self, *, candidates: int, files: int, symbols: int) -> None:
        self._add_metric(
            context_candidate_file_count=candidates,
            context_selected_file_count=files,
            context_selected_symbol_count=symbols,
        )

    def metrics_snapshot(self) -> RepoIntelligenceMetrics:
        with self._metrics_lock:
            return self._metrics

    def record_lexical_fallback(self) -> None:
        """Record an explicit bounded lexical fallback at a tool boundary."""
        self._add_metric(lexical_fallback_count=1)

    def _persist_dirty_state(self, handle: _WorkspaceHandle) -> None:
        """Durably make one workspace projection non-current after a mutation."""
        try:
            handle.store.mark_repository_state_dirty(
                workspace_id=handle.workspace_id,
                repository_id=handle.repository_id,
                index_project_id=handle.index_project_id,
                root_identity=handle.root_identity,
                pending_paths=tuple(sorted(handle.pending_paths | handle.deleted_paths)),
                full_refresh_required=handle.full_refresh_required,
                source_revision=handle.source_revision,
            )
        except (RuntimeError, sqlite3.Error, TypeError, ValueError) as exc:
            # Do not leave an in-memory current projection after a failed
            # durable invalidation.  Callers may continue, but the next query
            # must fail closed until a fresh index can be established.
            handle.freshness = IntelligenceFreshness.UNAVAILABLE
            handle.full_refresh_required = True
            raise RepoIntelligenceUnavailableError(
                "repository intelligence invalidation could not be persisted"
            ) from exc

    def mark_dirty(self, event: MutationEvent) -> None:
        """Record a mutation observation without performing filesystem I/O."""
        if not isinstance(event, MutationEvent):
            raise RepoContractError("mark_dirty requires a MutationEvent")
        with self._handles_lock:
            pending = self._pending.setdefault(event.workspace_id, _PendingState())
            if event.paths:
                pending.paths.update(event.paths)
                if event.mutation_type is MutationType.DELETE:
                    pending.deleted_paths.update(event.paths)
                elif event.mutation_type in {MutationType.RENAME, MutationType.MOVE}:
                    # A rename/move event may carry both old and new paths.  A
                    # missing path is removed by the incremental refresh; an
                    # existing path is parsed.  Keeping both is conservative.
                    pending.deleted_paths.update(event.paths)
            else:
                pending.full_refresh_required = True
            if event.mutation_type in {MutationType.ROLLBACK, MutationType.RESTORE}:
                pending.full_refresh_required = True
            if event.source_revision is not None:
                pending.source_revision = event.source_revision
            handle = self._handles.get(event.workspace_id)
            if handle is None and self._database is not None:
                try:
                    workspace = self._workspace_for_ids(event.workspace_id, None, None, None)
                    handle = self._handle_for(workspace, repository_id_for_workspace(workspace))
                except RepoIntelligenceUnavailableError:
                    # There is no safely addressable workspace to bind a
                    # durable marker to.  Keep the in-memory observation for
                    # a later owner-bound query; never invent a root or index
                    # identity here.
                    handle = None
            if handle is not None:
                self._apply_pending(handle, pending)
                if handle.freshness is IntelligenceFreshness.CURRENT:
                    handle.freshness = IntelligenceFreshness.STALE
                self._persist_dirty_state(handle)
                self._invalidate_cache(event.workspace_id)

    def mark_dirty_paths(self, workspace_id: str, paths: tuple[str, ...] = ()) -> None:
        """Compatibility observer hook for callers that have no event type."""
        self.mark_dirty(MutationEvent(workspace_id, MutationType.UPDATE, paths))

    async def refresh(
        self,
        workspace_id: str,
        *,
        task_id: str,
        principal_id: str,
        project_id: str,
        paths: tuple[str, ...] = (),
        full_reindex: bool = False,
        source_revision: str | None = None,
    ) -> RepoRefreshReport:
        """Explicitly refresh one owner-scoped repository projection."""
        workspace = self._workspace_for_ids(
            workspace_id, task_id, principal_id, project_id
        )
        repository_id = repository_id_for_workspace(workspace)
        handle = self._handle_for(workspace, repository_id)
        async with handle.lock:
            await self._load_state(handle)
            if full_reindex:
                handle.full_refresh_required = True
            handle.pending_paths.update(_normalize_paths(paths, label="refresh paths"))
            if source_revision is not None:
                handle.source_revision = _require_text(source_revision, "source_revision")
            return await self._refresh_locked(handle, workspace, full_reindex=full_reindex)

    async def query(self, request: RepoQueryRequest) -> RepoQueryResult:
        """Run a bounded typed query against the current repository projection."""
        if self._closed:
            raise RepoIntelligenceIndexUnavailableError(
                "repository intelligence is closed"
            )
        self._add_metric(query_count=1)
        workspace = self._workspace_for_request(request)
        repository_id = repository_id_for_workspace(workspace)
        handle = self._handle_for(workspace, repository_id)
        async with handle.lock:
            await self._load_state(handle)
            freshness = await self._prepare_locked(handle, workspace, request)
            if request.freshness_policy is FreshnessPolicy.REQUIRE_CURRENT and freshness is not IntelligenceFreshness.CURRENT:
                raise RepoIntelligenceUnavailableError(
                    f"repository intelligence is {freshness.value}; current evidence is required"
                )
            generation = self._generation(handle)
            cache_key = (request.workspace_id, handle.generation, request.request_digest)
            if freshness is IntelligenceFreshness.CURRENT:
                cached = self._cache_get(cache_key)
                if cached is not None:
                    self._add_metric(cache_hit_count=1)
                    return cached
                self._add_metric(cache_miss_count=1)
            # SEARCH_TEXT also probes the indexed symbol graph before its
            # explicit lexical fallback, so it is an observed semantic query
            # even when the eventual result is lexical.
            self._add_metric(semantic_query_count=1)
            result = await self._execute_query(handle, request, generation, freshness)
            if result.lexical_fallback:
                self._add_metric(lexical_fallback_count=1)
            if result.freshness is IntelligenceFreshness.STALE:
                self._add_metric(stale_query_count=1)
            if result.freshness is IntelligenceFreshness.CURRENT:
                self._cache_put(cache_key, result)
            return result

    async def search_text(self, request: RepoQueryRequest) -> RepoQueryResult:
        if request.kind is not RepoQueryKind.SEARCH_TEXT:
            raise RepoContractError("search_text requires SEARCH_TEXT")
        return await self.query(request)

    async def symbols(self, request: RepoQueryRequest) -> RepoQueryResult:
        if request.kind not in {RepoQueryKind.SYMBOLS, RepoQueryKind.DEFINITIONS}:
            raise RepoContractError("symbols requires SYMBOLS or DEFINITIONS")
        return await self.query(request)

    async def find_symbols(self, request: RepoQueryRequest) -> RepoQueryResult:
        """Find symbols through the canonical typed query boundary."""
        if request.kind is not RepoQueryKind.SYMBOLS:
            raise RepoContractError("find_symbols requires SYMBOLS")
        return await self.query(request)

    async def find_definitions(self, request: RepoQueryRequest) -> RepoQueryResult:
        """Find definitions without guessing unresolved targets."""
        if request.kind is not RepoQueryKind.DEFINITIONS:
            raise RepoContractError("find_definitions requires DEFINITIONS")
        return await self.query(request)

    async def find_references(self, request: RepoQueryRequest) -> RepoQueryResult:
        """Find conservative reference edges for a typed target request."""
        if request.kind is not RepoQueryKind.REFERENCES:
            raise RepoContractError("find_references requires REFERENCES")
        return await self.query(request)

    async def find_callers(self, request: RepoQueryRequest) -> RepoQueryResult:
        """Find bounded callers of a symbol or query target."""
        if request.kind is not RepoQueryKind.CALLERS:
            raise RepoContractError("find_callers requires CALLERS")
        return await self.query(request)

    async def find_callees(self, request: RepoQueryRequest) -> RepoQueryResult:
        """Find bounded callees of a symbol or query target."""
        if request.kind is not RepoQueryKind.CALLEES:
            raise RepoContractError("find_callees requires CALLEES")
        return await self.query(request)

    async def find_importers(self, request: RepoQueryRequest) -> RepoQueryResult:
        """Find files that import a target file or module."""
        if request.kind is not RepoQueryKind.IMPORTERS:
            raise RepoContractError("find_importers requires IMPORTERS")
        return await self.query(request)

    async def find_imports(self, request: RepoQueryRequest) -> RepoQueryResult:
        """Find imports of a target file."""
        if request.kind is not RepoQueryKind.IMPORTS:
            raise RepoContractError("find_imports requires IMPORTS")
        return await self.query(request)

    async def related_files(self, request: RepoQueryRequest) -> RepoQueryResult:
        """Find bounded dependency/reverse-dependency file relations."""
        if request.kind is not RepoQueryKind.RELATED_FILES:
            raise RepoContractError("related_files requires RELATED_FILES")
        return await self.query(request)

    async def find_related_files(self, request: RepoQueryRequest) -> RepoQueryResult:
        """Compatibility alias for callers using verb-first query names."""
        return await self.related_files(request)

    async def related_tests(self, request: RepoQueryRequest) -> RepoQueryResult:
        """Find bounded tests associated with a target file."""
        if request.kind is not RepoQueryKind.RELATED_TESTS:
            raise RepoContractError("related_tests requires RELATED_TESTS")
        return await self.query(request)

    async def find_related_tests(self, request: RepoQueryRequest) -> RepoQueryResult:
        """Find bounded related tests through the canonical query path."""
        return await self.related_tests(request)

    async def repository_overview(self, request: RepoQueryRequest) -> RepoQueryResult:
        """Return a bounded repository overview projection."""
        if request.kind is not RepoQueryKind.REPOSITORY_OVERVIEW:
            raise RepoContractError("repository_overview requires REPOSITORY_OVERVIEW")
        return await self.query(request)

    async def select_context(self, request: RepoContextRequest) -> RepoContextResult:
        """Select and safely capture context from indexed candidates.

        Parsing and relation discovery come from the persisted index.  Only
        the final, bounded text projection reads source bytes, and the read is
        recaptured when file identity changes during selection.
        """
        if self._closed:
            raise RepoIntelligenceUnavailableError("repository intelligence is closed")
        self._add_metric(query_count=1)
        workspace = self._workspace_for_context_request(request)
        repository_id = repository_id_for_workspace(workspace)
        handle = self._handle_for(workspace, repository_id)
        SafeWorkspaceFS, WorkspaceBoundaryError = _workspace_safety_types()
        for attempt in range(2):
            async with handle.lock:
                await self._load_state(handle)
                freshness = await self._prepare_context_locked(handle, workspace, request)
                if request.freshness_policy is FreshnessPolicy.REQUIRE_CURRENT and freshness is not IntelligenceFreshness.CURRENT:
                    raise RepoIntelligenceUnavailableError(
                        f"repository intelligence is {freshness.value}; current context is required"
                    )
                generation = self._generation(handle)
                cache_key = (
                    request.workspace_id,
                    generation.generation,
                    request.request_digest,
                )
                if freshness is IntelligenceFreshness.CURRENT:
                    cached = self._context_cache_get(cache_key)
                    if cached is not None:
                        self._add_metric(cache_hit_count=1)
                        return cached
                    self._add_metric(cache_miss_count=1)
                records = await handle.store.file_records(handle.index_project_id, limit=self._limits.max_files)
                max_context_files = min(request.max_files, self._limits.max_files)
                max_context_symbols = min(request.max_symbols, self._limits.max_symbols)
                max_context_bytes = min(request.max_bytes, self._limits.max_index_bytes)
                max_context_file_bytes = min(request.max_file_bytes, self._limits.max_file_bytes)
                max_structure_entries = min(
                    request.max_structure_entries, self._limits.max_relations
                )
                symbols = await self._context_symbols(
                    handle, request, max_symbols=max_context_symbols
                )
                relation_scores = self._context_relation_scores(
                    handle,
                    request,
                    symbols,
                    max_relations=max_structure_entries,
                )
                candidates = self._rank_context_files(
                    records,
                    symbols,
                    request,
                    relation_scores=relation_scores,
                )
                self._record_context_metrics(candidates=len(candidates), files=0, symbols=0)
                selected = candidates[:max_context_files]
                projected: list[RepoContextFile] = []
                selected_symbols: list[RepoSymbol] = []
                relations: list[RepoRelation] = []
                structure = tuple(
                    item[0]["path"] for item in candidates[:max_structure_entries]
                )
                reasons: list[str] = list(handle.truncation_reasons)
                if request.max_files > max_context_files:
                    reasons.append("service_max_context_files")
                if request.max_symbols > max_context_symbols:
                    reasons.append("service_max_context_symbols")
                if request.max_bytes > max_context_bytes:
                    reasons.append("service_max_context_bytes")
                if request.max_file_bytes > max_context_file_bytes:
                    reasons.append("service_max_context_file_bytes")
                if request.max_structure_entries > max_structure_entries:
                    reasons.append("service_max_structure_entries")
                total_bytes = 0
                raced = False
                try:
                    with SafeWorkspaceFS(handle.root) as fs:
                        for record, score in selected:
                            path = str(record["path"])
                            if not _is_context_text_record(record, path):
                                # Binary/generated metadata is retained in the
                                # repository overview but is never promoted to
                                # a context source, even when a caller names
                                # it explicitly.  Ignoring it here prevents
                                # binary/metadata rows from being served as
                                # source content.
                                if path in request.target_files or path in request.changed_files:
                                    reasons.append(f"metadata_only:{path}")
                                continue
                            try:
                                before = fs.stat(path)
                                raw = fs.read_bytes(
                                    path, max_bytes=max_context_file_bytes
                                )
                                after = fs.stat(path)
                            except (OSError, WorkspaceBoundaryError):
                                reasons.append(f"unreadable:{path}")
                                continue
                            if (before.st_dev, before.st_ino, before.st_mtime_ns, before.st_size) != (after.st_dev, after.st_ino, after.st_mtime_ns, after.st_size):
                                raced = True
                                break
                            if total_bytes + len(raw) > max_context_bytes:
                                reasons.append("max_context_bytes")
                                break
                            try:
                                content = raw.decode("utf-8")
                            except UnicodeDecodeError:
                                reasons.append(f"non_utf8:{path}")
                                continue
                            digest = hashlib.sha256(raw).hexdigest()
                            if (
                                before.st_mtime_ns != int(record["mtime_ns"])
                                or before.st_size != int(record["size"])
                                or digest != str(record["content_hash"])
                            ):
                                # The source changed since this index row was
                                # produced.  Do not return a new source body
                                # stamped with the old repository generation.
                                raced = True
                                break
                            total_bytes += len(raw)
                            projected.append(RepoContextFile(path, str(record["language"]), content, digest, int(record["size"]), score, int(record["generation"])))
                            remaining_symbols = max_context_symbols - len(selected_symbols)
                            if remaining_symbols > 0:
                                selected_symbols.extend(
                                    await self._symbols_for_paths(
                                        handle, (path,), remaining_symbols
                                    )
                                )
                            relations.extend(
                                self._relations_for_path(
                                    handle, path, max_structure_entries
                                )
                            )
                except (OSError, WorkspaceBoundaryError, SafePathError) as exc:
                    if request.freshness_policy is FreshnessPolicy.REQUIRE_CURRENT:
                        raise RepoIntelligenceUnavailableError("safe context source is unavailable") from exc
                    reasons.append("safe_source_unavailable")
                if raced:
                    handle.pending_paths.update(
                        str(record["path"]) for record, _ in selected
                    )
                    handle.freshness = IntelligenceFreshness.STALE
                    await self._save_state_projection(
                        handle,
                        freshness=IntelligenceFreshness.STALE,
                        full_refresh_required=handle.full_refresh_required,
                        pending_paths=tuple(sorted(handle.pending_paths | handle.deleted_paths)),
                    )
                    if attempt == 0:
                        continue
                    freshness = IntelligenceFreshness.STALE
                    reasons.append("source_changed_during_capture")
                truncated = bool(reasons) or len(candidates) > len(selected)
                if len(candidates) > len(selected):
                    reasons.append("max_context_files")
                selected_symbols = _dedupe_symbols(selected_symbols)[:max_context_symbols]
                relations = _dedupe_relations(relations)[
                    : min(self._limits.max_relations, max_structure_entries)
                ]
                if truncated and freshness is IntelligenceFreshness.CURRENT:
                    freshness = IntelligenceFreshness.PARTIAL
                if request.freshness_policy is FreshnessPolicy.REQUIRE_CURRENT and freshness is not IntelligenceFreshness.CURRENT:
                    raise RepoIntelligenceUnavailableError(
                        "bounded context could not satisfy current freshness"
                    )
                self._record_context_metrics(candidates=0, files=len(projected), symbols=len(selected_symbols))
                result = RepoContextResult(
                    generation,
                    freshness,
                    tuple(projected),
                    tuple(selected_symbols),
                    tuple(relations),
                    structure,
                    truncated,
                    tuple(sorted(set(reasons))),
                    len(candidates),
                    any(relation.kind == "LEXICAL_SEARCH" for relation in relations),
                )
                if result.freshness is IntelligenceFreshness.CURRENT:
                    self._context_cache_put(cache_key, result)
                return result
        raise RepoIntelligenceUnavailableError("context source changed during bounded capture")

    async def close(self) -> None:
        self._closed = True
        with self._handles_lock:
            handles = list(self._handles.values())
            self._handles.clear()
        with self._cache_lock:
            self._result_cache.clear()
            self._context_cache.clear()
        with self._handles_lock:
            self._pending.clear()
        closed_stores: set[int] = set()
        for handle in handles:
            store_identity = id(handle.store)
            if store_identity in closed_stores:
                continue
            await handle.indexer.close()
            closed_stores.add(store_identity)

    def _workspace_for_request(self, request: RepoQueryRequest) -> Any:
        return self._workspace_for_ids(request.workspace_id, request.task_id, request.principal_id, request.project_id)

    def _workspace_for_context_request(self, request: RepoContextRequest) -> Any:
        return self._workspace_for_ids(request.workspace_id, request.task_id, request.principal_id, request.project_id)

    def _workspace_for_ids(self, workspace_id: str, task_id: str | None, principal_id: str | None, project_id: str | None) -> Any:
        try:
            workspace = self._workspace_manager.get(workspace_id)
        except (AttributeError, KeyError, TypeError) as exc:
            raise RepoIntelligenceUnavailableError("TaskWorkspace is unavailable") from exc
        if workspace is None:
            raise RepoIntelligenceUnavailableError("TaskWorkspace is unavailable")
        for name, expected in (("id", workspace_id), ("task_id", task_id), ("principal_id", principal_id), ("project_id", project_id)):
            if expected is not None and (
                not hasattr(workspace, name) or getattr(workspace, name) != expected
            ):
                raise RepoIntelligenceUnavailableError("TaskWorkspace owner binding mismatch")
        require = getattr(self._workspace_manager, "require", None)
        if callable(require) and task_id is not None:
            try:
                required = require(
                    workspace_id,
                    task_id=task_id,
                    principal_id=principal_id or "",
                    project_id=project_id or "",
                    runtime_id=str(getattr(workspace, "creator_runtime_id", "") or ""),
                )
            except (OSError, PermissionError, RuntimeError, TypeError) as exc:
                raise RepoIntelligenceUnavailableError("TaskWorkspace owner validation failed") from exc
            if required is None:
                raise RepoIntelligenceUnavailableError("TaskWorkspace is unavailable")
            workspace = required
        root_value = getattr(workspace, "worktree_path", None)
        if root_value is None:
            raise RepoIntelligenceUnavailableError("TaskWorkspace root is unavailable")
        try:
            root = Path(root_value).expanduser().resolve(strict=True)
            info = os.stat(root, follow_symlinks=False)
        except (OSError, RuntimeError) as exc:
            raise RepoIntelligenceUnavailableError("TaskWorkspace root is unavailable") from exc
        if not stat.S_ISDIR(info.st_mode):
            raise RepoIntelligenceUnavailableError("TaskWorkspace root is not a directory")
        return workspace

    def _handle_for(self, workspace: Any, repository_id: str) -> _WorkspaceHandle:
        workspace_id = str(getattr(workspace, "id", ""))
        if not workspace_id:
            raise RepoIntelligenceUnavailableError("TaskWorkspace id is unavailable")
        project_id = str(getattr(workspace, "project_id", ""))
        if not project_id:
            raise RepoIntelligenceUnavailableError("TaskWorkspace project is unavailable")
        root = Path(workspace.worktree_path).expanduser().resolve(strict=True)
        info = os.stat(root, follow_symlinks=False)
        root_identity = f"{root}:{info.st_dev}:{info.st_ino}"
        with self._handles_lock:
            existing = self._handles.get(workspace_id)
            if existing is not None:
                if (
                    existing.project_id != project_id
                    or existing.repository_id != repository_id
                    or existing.root_identity != root_identity
                ):
                    raise RepoIntelligenceUnavailableError("workspace repository identity changed")
                return existing
            index_project_id = (
                f"workspace:{workspace_id}|project:{project_id}|repository:{repository_id}"
            )
            try:
                database = self._database
                if isinstance(database, sqlite3.Connection):
                    # One caller-provided connection is one physical DB owner.
                    # Share its IndexStore/async lock across workspace projections
                    # while project IDs keep every row workspace-isolated.
                    if self._shared_store is None:
                        self._shared_store = IndexStore(database)
                    store = self._shared_store
                elif database is None:
                    database = sqlite3.connect(":memory:", check_same_thread=False)
                    store = IndexStore(database)
                else:
                    store = IndexStore(str(database))
                resolution = ResolutionService(store._conn)
            except (OSError, RuntimeError, sqlite3.Error, TypeError, ValueError) as exc:
                raise RepoIntelligenceIndexUnavailableError(
                    "repository intelligence index backend is unavailable"
                ) from exc
            indexer = RepositoryIndexer(
                store,
                registry=self._registry,
                resolution_service=resolution,
                limits=self._limits.indexer_limits(),
                source_access=SafeWorkspaceSourceAccess(),
            )
            mutation_fence = getattr(self._workspace_manager, "_mutation_fence", None)
            if mutation_fence is not None:
                indexer.set_mutation_fence(
                    mutation_fence,
                    workspace_resolver=self._resolve_fenced_workspace,
                )
            handle = _WorkspaceHandle(
                workspace_id,
                project_id,
                repository_id,
                index_project_id,
                root,
                root_identity,
                store,
                indexer,
                CodeQueryService(store),
            )
            pending = self._pending.get(workspace_id)
            if pending is not None:
                self._apply_pending(handle, pending)
            self._handles[workspace_id] = handle
            return handle

    def _resolve_fenced_workspace(
        self, _repository_id: str, workspace_id: str
    ) -> str | None:
        try:
            workspace = self._workspace_manager.get(workspace_id)
        except (AttributeError, KeyError, TypeError):
            return None
        return workspace_id if workspace is not None else None

    def _apply_pending(self, handle: _WorkspaceHandle, pending: _PendingState) -> None:
        handle.pending_paths.update(pending.paths)
        handle.deleted_paths.update(pending.deleted_paths)
        handle.full_refresh_required = handle.full_refresh_required or pending.full_refresh_required
        if pending.source_revision is not None:
            handle.source_revision = pending.source_revision

    async def _load_state(self, handle: _WorkspaceHandle) -> None:
        if handle.state_loaded:
            return
        try:
            state = await handle.store.get_repository_state(
                handle.workspace_id, handle.repository_id
            )
        except (OSError, RuntimeError, sqlite3.Error) as exc:
            raise RepoIntelligenceIndexUnavailableError(
                "repository intelligence state is unavailable"
            ) from exc
        state_matches = bool(
            state is not None
            and state.get("root_identity") == handle.root_identity
            and state.get("index_project_id") == handle.index_project_id
        )
        if state_matches and state is not None:
            pending_state_invalid = False
            try:
                generation = state.get("generation", 0)
                if type(generation) is not int or generation < 0:
                    raise ValueError("persisted repository generation is malformed")
                manifest_digest = state.get("manifest_digest", "")
                if (
                    type(manifest_digest) is not str
                    or len(manifest_digest) != 64
                    or any(character not in "0123456789abcdef" for character in manifest_digest)
                ):
                    raise ValueError("persisted repository manifest is malformed")
                handle.generation = generation
                handle.manifest_digest = manifest_digest
                handle.freshness = IntelligenceFreshness(
                    str(state.get("freshness", IntelligenceFreshness.UNAVAILABLE.value))
                )
                source_revision = state.get("source_revision")
                if source_revision is not None and type(source_revision) is not str:
                    raise ValueError("persisted source revision is malformed")
                handle.source_revision = source_revision
                indexed_at = state.get("indexed_at", 0)
                indexed_at_value = float(indexed_at)
                if not math.isfinite(indexed_at_value) or indexed_at_value < 0:
                    raise ValueError("persisted index timestamp is malformed")
                handle.indexed_at = indexed_at_value or None
                pending_payload = json.loads(state.get("pending_paths_json", "[]"))
                if not isinstance(pending_payload, list):
                    raise ValueError("persisted pending paths are malformed")
                handle.pending_paths.update(
                    _normalize_paths(tuple(pending_payload), label="persisted pending paths")
                )
            except (TypeError, ValueError, json.JSONDecodeError):
                handle.generation = 0
                handle.manifest_digest = ""
                handle.freshness = IntelligenceFreshness.UNAVAILABLE
                handle.source_revision = None
                handle.indexed_at = None
                pending_state_invalid = True
            handle.full_refresh_required = bool(state.get("full_refresh_required", 0)) or pending_state_invalid
            if not pending_state_invalid:
                try:
                    actual_manifest = await handle.store.manifest_digest(handle.index_project_id)
                    semantic_gaps = await handle.store.semantic_generation_gaps(
                        handle.index_project_id
                    )
                    integrity_gaps = await handle.store.semantic_integrity_gaps(
                        handle.index_project_id
                    )
                except (OSError, RuntimeError, sqlite3.Error) as exc:
                    raise RepoIntelligenceIndexUnavailableError(
                        "repository intelligence manifest is unavailable"
                    ) from exc
                if actual_manifest != handle.manifest_digest:
                    # The persisted index rows and the durable generation
                    # projection no longer describe the same derived state.
                    # Rebuild before serving any result as current.
                    handle.freshness = IntelligenceFreshness.UNAVAILABLE
                    handle.full_refresh_required = True
                if semantic_gaps or integrity_gaps:
                    handle.freshness = IntelligenceFreshness.UNAVAILABLE
                    handle.full_refresh_required = True
        else:
            handle.generation = 0
            handle.manifest_digest = ""
            handle.freshness = IntelligenceFreshness.UNAVAILABLE
            handle.full_refresh_required = True
        if state is not None and state.get("root_identity") != handle.root_identity:
            handle.full_refresh_required = True
            handle.manifest_digest = ""
        pending = self._pending.get(handle.workspace_id)
        if pending is not None:
            self._apply_pending(handle, pending)
        handle.state_loaded = True

    async def _prepare_locked(self, handle: _WorkspaceHandle, workspace: Any, request: RepoQueryRequest) -> IntelligenceFreshness:
        probe_paths = set(request.target_files)
        if request.path:
            probe_paths.add(request.path)
        if request.kind in {RepoQueryKind.RELATED_FILES, RepoQueryKind.IMPORTS, RepoQueryKind.IMPORTERS, RepoQueryKind.RELATED_TESTS} and request.path:
            probe_paths.add(request.path)
        await self._probe_paths(handle, probe_paths)
        if request.freshness_policy is FreshnessPolicy.ALLOW_STALE and handle.freshness is not IntelligenceFreshness.UNAVAILABLE and (handle.freshness is IntelligenceFreshness.STALE or handle.pending_paths or handle.deleted_paths or handle.full_refresh_required):
            handle.freshness = IntelligenceFreshness.STALE
            return IntelligenceFreshness.STALE
        if handle.freshness is IntelligenceFreshness.STALE and not (
            handle.pending_paths or handle.deleted_paths or handle.full_refresh_required
        ):
            handle.full_refresh_required = True
        needs_refresh = handle.full_refresh_required or bool(handle.pending_paths or handle.deleted_paths) or handle.freshness is IntelligenceFreshness.UNAVAILABLE
        if not needs_refresh:
            return handle.freshness
        return (await self._refresh_locked(handle, workspace, full_reindex=handle.full_refresh_required)).freshness

    async def _prepare_context_locked(self, handle: _WorkspaceHandle, workspace: Any, request: RepoContextRequest) -> IntelligenceFreshness:
        await self._probe_paths(handle, set(request.target_files) | set(request.changed_files))
        repo_request = RepoQueryRequest(handle.workspace_id, request.task_id, request.principal_id, request.project_id, RepoQueryKind.REPOSITORY_OVERVIEW, freshness_policy=request.freshness_policy)
        return await self._prepare_locked(handle, workspace, repo_request)

    async def _probe_paths(self, handle: _WorkspaceHandle, paths: set[str]) -> None:
        if not paths:
            return
        SafeWorkspaceFS, WorkspaceBoundaryError = _workspace_safety_types()
        records = {str(item["path"]): item for item in await handle.store.file_records(handle.index_project_id, paths=tuple(sorted(paths)), limit=len(paths) + 1)}
        dirty_observed = False
        try:
            with SafeWorkspaceFS(handle.root) as fs:
                for relative in sorted(paths):
                    try:
                        info = fs.lstat(relative)
                    except (OSError, WorkspaceBoundaryError) as exc:
                        raise RepoIntelligenceUnavailableError("safe workspace probe failed") from exc
                    record = records.get(relative)
                    if info is None:
                        if record is not None:
                            handle.pending_paths.add(relative)
                            handle.deleted_paths.add(relative)
                            dirty_observed = True
                        continue
                    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                        raise RepoIntelligenceUnavailableError("workspace target is not a safe regular file")
                    if record is None or int(record["mtime_ns"]) != int(info.st_mtime_ns) or int(record["size"]) != int(info.st_size):
                        handle.pending_paths.add(relative)
                        dirty_observed = True
                        if record is not None:
                            handle.deleted_paths.discard(relative)
        except RepoIntelligenceUnavailableError:
            raise
        except (OSError, WorkspaceBoundaryError, SafePathError) as exc:
            raise RepoIntelligenceUnavailableError("safe workspace probe failed") from exc
        if dirty_observed:
            if handle.freshness is IntelligenceFreshness.CURRENT:
                handle.freshness = IntelligenceFreshness.STALE
            await self._save_state_projection(
                handle,
                freshness=handle.freshness,
                full_refresh_required=handle.full_refresh_required,
                pending_paths=tuple(sorted(handle.pending_paths | handle.deleted_paths)),
            )

    async def _save_state_projection(
        self,
        handle: _WorkspaceHandle,
        *,
        freshness: IntelligenceFreshness,
        full_refresh_required: bool,
        pending_paths: tuple[str, ...],
    ) -> None:
        """Persist state even when the surrounding operation is cancelled."""
        await asyncio.shield(
            handle.store.save_repository_state(
                workspace_id=handle.workspace_id,
                repository_id=handle.repository_id,
                index_project_id=handle.index_project_id,
                generation=handle.generation,
                manifest_digest=handle.manifest_digest or canonical_digest([]),
                freshness=freshness.value,
                source_revision=handle.source_revision,
                root_identity=handle.root_identity,
                pending_paths=pending_paths,
                full_refresh_required=full_refresh_required,
                indexed_at=handle.indexed_at,
            )
        )

    async def _refresh_locked(self, handle: _WorkspaceHandle, workspace: Any, *, full_reindex: bool) -> RepoRefreshReport:
        started = time.perf_counter()
        do_full = full_reindex or handle.full_refresh_required or handle.generation == 0
        # Mark the durable projection non-current before any per-file writes.
        # If indexing is cancelled or the process dies mid-refresh, a later
        # process must rebuild/reconcile instead of trusting a partial index.
        handle.freshness = (
            IntelligenceFreshness.UNAVAILABLE
            if handle.generation == 0
            else IntelligenceFreshness.STALE
        )
        handle.full_refresh_required = True
        await self._save_state_projection(
            handle,
            freshness=handle.freshness,
            full_refresh_required=True,
            pending_paths=tuple(sorted(handle.pending_paths | handle.deleted_paths)),
        )
        if do_full:
            report = await handle.indexer.index(handle.index_project_id, handle.root, workspace_id=handle.workspace_id, full_reindex=True)
            self._add_metric(full_index_count=1)
        else:
            report = await handle.indexer.refresh_paths(
                handle.index_project_id,
                handle.root,
                tuple(sorted(handle.pending_paths)),
                workspace_id=handle.workspace_id,
                deleted_paths=tuple(sorted(handle.deleted_paths)),
            )
            self._add_metric(incremental_refresh_count=1)
        await self._supplement_metadata(handle, report)
        manifest = await handle.store.manifest_digest(handle.index_project_id)
        if do_full or not handle.manifest_digest or manifest != handle.manifest_digest:
            handle.generation = max(1, handle.generation + 1)
        handle.manifest_digest = manifest
        handle.indexed_at = time.time()
        handle.pending_paths.clear()
        handle.deleted_paths.clear()
        handle.full_refresh_required = False
        handle.truncated = bool(report.get("truncated"))
        handle.truncation_reasons = tuple(sorted(set(str(item) for item in report.get("truncation_reasons", ()))))
        if report.get("failed_files", 0) or report.get("resolution_error"):
            handle.freshness = IntelligenceFreshness.PARTIAL
        elif handle.truncated:
            handle.freshness = IntelligenceFreshness.PARTIAL
        else:
            handle.freshness = IntelligenceFreshness.CURRENT
        handle.source_revision = handle.source_revision or getattr(workspace, "base_sha", None)
        try:
            await self._save_state_projection(
                handle,
                freshness=handle.freshness,
                full_refresh_required=handle.full_refresh_required,
                pending_paths=tuple(sorted(handle.pending_paths)),
            )
        except asyncio.CancelledError:
            handle.freshness = IntelligenceFreshness.STALE
            handle.full_refresh_required = True
            raise
        except (RuntimeError, sqlite3.Error, TypeError, ValueError) as exc:
            handle.freshness = IntelligenceFreshness.UNAVAILABLE
            handle.full_refresh_required = True
            raise RepoIntelligenceUnavailableError(
                "repository intelligence state could not be committed"
            ) from exc
        self._invalidate_cache(handle.workspace_id)
        parsed = int(report.get("parsed_files", 0))
        # ``reparsed_file_count`` describes incremental work only; the
        # initial/full batch is represented separately by full_index_count.
        if not do_full:
            self._add_metric(parsed_file_count=parsed, reparsed_file_count=parsed)
        else:
            self._add_metric(parsed_file_count=parsed)
        return RepoRefreshReport(
            self._generation(handle),
            handle.freshness,
            do_full,
            int(report.get("scanned_files", 0)),
            parsed,
            parsed,
            int(report.get("incremental_files", 0)),
            int(report.get("unchanged_files", 0)),
            int(report.get("deleted_files", 0)),
            int(report.get("unsupported_files", 0)),
            int(report.get("failed_files", 0)),
            handle.truncated,
            (time.perf_counter() - started) * 1000,
        )

    async def _supplement_metadata(self, handle: _WorkspaceHandle, report: dict[str, Any]) -> None:
        _SafeWorkspaceFS, WorkspaceBoundaryError = _workspace_safety_types()
        candidates = sorted(
            path for path, status in report.get("statuses", {}).items()
            if status in {"unsupported", "rejected-binary", "rejected-oversized"}
        )
        for relative in candidates:
            try:
                await self._write_metadata_record(handle, relative)
            except (OSError, UnicodeError, WorkspaceBoundaryError, RepoContractError):
                continue

    async def _write_metadata_record(self, handle: _WorkspaceHandle, relative: str) -> None:
        SafeWorkspaceFS, WorkspaceBoundaryError = _workspace_safety_types()
        relative = normalize_repo_path(relative)
        with SafeWorkspaceFS(handle.root) as fs:
            info = fs.lstat(relative)
            if info is None:
                await handle.store.remove(handle.index_project_id, relative)
                return
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise WorkspaceBoundaryError("metadata target is not a safe regular file")
            read_bound = min(int(info.st_size), self._limits.max_file_bytes)
            try:
                raw = fs.read_bytes(relative, max_bytes=max(1, read_bound))
                digest = hashlib.sha256(raw).hexdigest() if len(raw) == info.st_size else _metadata_digest(info)
            except WorkspaceBoundaryError:
                digest = _metadata_digest(info)
            resolution = self._registry.resolve(relative)
            language = resolution.language or "text"
            result = ParseResult(
                language=language,
                file_path=relative,
                parser_source="metadata",
                parser_version="repo-intelligence-metadata-v1",
                content_hash=digest,
                metadata=ParserMetadata(parse_mode="metadata-only"),
            )
            existing = await handle.store.file_record(handle.index_project_id, relative)
            if (
                existing is not None
                and existing["content_hash"] == digest
                and int(existing["size"]) == int(info.st_size)
                and str(existing.get("parser_source", "")) == "metadata"
            ):
                return
            generation = int(existing["generation"] + 1) if existing else 1
            await handle.store.write_parse_result(
                handle.index_project_id,
                relative,
                result,
                size=int(info.st_size),
                mtime_ns=int(info.st_mtime_ns),
                generation=generation,
            )

    async def _execute_query(self, handle: _WorkspaceHandle, request: RepoQueryRequest, generation: RepositoryGeneration, freshness: IntelligenceFreshness) -> RepoQueryResult:
        limit = min(request.limit, self._limits.max_query_results)
        files = await handle.store.file_records(handle.index_project_id, limit=self._limits.max_files)
        file_map = {str(item["path"]): self._file_from_record(item) for item in files}
        query = request.query
        symbols: tuple[RepoSymbol, ...] = ()
        relations: tuple[RepoRelation, ...] = ()
        matches: tuple[RepoTextMatch, ...] = ()
        lexical = False
        semantic = False
        overview = None
        if request.kind in {RepoQueryKind.SYMBOLS, RepoQueryKind.DEFINITIONS}:
            symbols = tuple(
                await self._symbols_for(
                    handle,
                    query,
                    request.target_files or ((request.path,) if request.path else ()),
                    limit,
                    path_prefix=request.path_prefix,
                    path_glob=request.path_glob,
                    language=request.language,
                )
            )
            semantic = bool(symbols)
        elif request.kind in {RepoQueryKind.CALLERS, RepoQueryKind.CALLEES, RepoQueryKind.REFERENCES}:
            symbols_for_target = await self._resolve_target_symbols(handle, request, limit)
            relations = tuple(self._relations_for_symbol_query(handle, request.kind, symbols_for_target, limit))
            semantic = True
        elif request.kind in {RepoQueryKind.IMPORTS, RepoQueryKind.IMPORTERS, RepoQueryKind.RELATED_FILES, RepoQueryKind.RELATED_TESTS}:
            path = request.path or (request.target_files[0] if request.target_files else "")
            relations = tuple(self._relations_for_file_query(handle, request.kind, path, request.target_files, limit))
            semantic = True
        elif request.kind is RepoQueryKind.SEARCH_TEXT:
            symbols = tuple(
                await self._symbols_for(
                    handle,
                    query,
                    request.target_files or ((request.path,) if request.path else ()),
                    limit,
                    path_prefix=request.path_prefix,
                    path_glob=request.path_glob,
                    language=request.language,
                )
            )
            if symbols:
                semantic = True
            else:
                matches = tuple(await self._lexical_search(handle, request, file_map, limit))
                lexical = True
        elif request.kind is RepoQueryKind.REPOSITORY_OVERVIEW:
            symbol_count = _count_rows(handle.store._conn, "repository_symbols", "repository_id", handle.index_project_id)
            relation_count = sum(_count_rows(handle.store._conn, table, "repository_id", handle.index_project_id) for table in ("resolved_imports", "resolved_call_edges", "resolved_reference_edges"))
            languages = tuple(sorted({item.language for item in file_map.values()}))
            overview = _build_overview(
                file_map.values(),
                await self._symbols_for_paths(handle, (), min(self._limits.max_symbols, 32)),
                symbol_count=symbol_count,
                relation_count=relation_count,
                languages=languages,
                truncated=handle.truncated,
            )
            semantic = symbol_count > 0
        return RepoQueryResult(
            generation,
            freshness,
            request.kind,
            tuple(file_map.values()) if request.kind is RepoQueryKind.REPOSITORY_OVERVIEW else (),
            symbols,
            relations,
            matches,
            overview,
            handle.truncated,
            handle.truncation_reasons,
            semantic,
            lexical,
        )

    async def _symbols_for(
        self,
        handle: _WorkspaceHandle,
        query: str,
        paths: tuple[str, ...],
        limit: int,
        *,
        exact_name: str | None = None,
        path_prefix: str = "",
        path_glob: str = "*",
        language: str = "",
    ) -> list[RepoSymbol]:
        if limit <= 0:
            return []
        bounded_limit = min(limit, self._limits.max_symbols)
        records = await handle.store.symbol_records(
            handle.index_project_id,
            query=query if exact_name is None else "",
            exact_name=exact_name,
            paths=paths,
            path_prefix=path_prefix,
            path_glob=path_glob,
            limit=bounded_limit,
        )
        graph_rows: list[dict[str, Any]] = []
        clauses = ["repository_id=?"]
        params: list[Any] = [handle.index_project_id]
        if exact_name is not None:
            clauses.append("name=?")
            params.append(exact_name)
        elif query:
            clauses.append("name LIKE ?")
            params.append(f"%{query}%")
        if paths:
            clauses.append("path IN (" + ",".join("?" for _ in paths) + ")")
            params.extend(paths)
        if path_prefix:
            clauses.append("(path=? OR substr(path, 1, ?) = ?)")
            params.extend((path_prefix, len(path_prefix) + 1, f"{path_prefix}/"))
        if path_glob != "*":
            glob_prefix = f"{path_prefix.rstrip('/')}/" if path_prefix else ""
            clauses.append("path GLOB ?")
            params.append(f"{glob_prefix}{path_glob}")
        if language:
            clauses.append("language=?")
            params.append(language)
        try:
            graph_rows = [
                dict(row)
                for row in handle.store._conn.execute(
                    "SELECT * FROM repository_symbols WHERE "
                    + " AND ".join(clauses)
                    + " ORDER BY path,start_line,name LIMIT ?",
                    (*params, bounded_limit),
                ).fetchall()
            ]
        except sqlite3.Error:
            graph_rows = []
        candidate_paths = tuple(
            sorted({str(row["path"]) for row in (*records, *graph_rows)})
        )
        file_records = {
            str(item["path"]): item
            for item in await handle.store.file_records(
                handle.index_project_id,
                paths=candidate_paths,
                limit=max(1, len(candidate_paths)),
            )
        }
        graph_symbols = [self._symbol_from_graph(row, file_records) for row in graph_rows]
        scoped_graph_symbols = [
            symbol
            for symbol in graph_symbols
            if _matches_path_scope(
                symbol.path,
                path_prefix=path_prefix,
                path_glob=path_glob,
                language=language,
                symbol_language=symbol.language,
            )
        ]
        if scoped_graph_symbols:
            return scoped_graph_symbols[:bounded_limit]
        code_symbols = [
            self._symbol_from_code(row, file_records, handle.index_project_id)
            for row in records
        ]
        return [
            symbol
            for symbol in code_symbols
            if _matches_path_scope(
                symbol.path,
                path_prefix=path_prefix,
                path_glob=path_glob,
                language=language,
                symbol_language=symbol.language,
            )
        ][:bounded_limit]

    async def _symbols_for_paths(self, handle: _WorkspaceHandle, paths: tuple[str, ...], limit: int) -> list[RepoSymbol]:
        return await self._symbols_for(handle, "", paths, limit)

    async def _context_symbols(
        self,
        handle: _WorkspaceHandle,
        request: RepoContextRequest,
        *,
        max_symbols: int | None = None,
    ) -> list[RepoSymbol]:
        """Resolve only context-relevant symbols for candidate ranking."""
        symbol_limit = min(
            request.max_symbols,
            self._limits.max_symbols,
        ) if max_symbols is None else max_symbols
        if symbol_limit <= 0:
            return []
        values: list[RepoSymbol] = []
        paths = request.target_files
        for target in request.target_symbols:
            if len(values) >= symbol_limit:
                break
            # Explicit symbol targets are identity-bearing inputs.  Resolve
            # them before the free-form query and discard substring matches;
            # otherwise a broad query can consume the bounded symbol budget
            # and leave the exact definition out of candidate ranking.
            values.extend(
                await self._symbols_for_target(
                    handle,
                    target,
                    paths,
                    symbol_limit - len(values),
                )
            )
        if request.query and len(values) < symbol_limit:
            values.extend(
                await self._symbols_for(
                    handle,
                    request.query,
                    paths,
                    symbol_limit - len(values),
                )
            )
        if not values and paths:
            values.extend(
                await self._symbols_for_paths(handle, paths, symbol_limit)
            )
        return _dedupe_symbols(values)[:symbol_limit]

    async def _symbols_for_target(
        self,
        handle: _WorkspaceHandle,
        target: str,
        paths: tuple[str, ...],
        limit: int,
    ) -> list[RepoSymbol]:
        """Resolve one explicit symbol by exact leaf/qualified identity."""
        if limit <= 0:
            return []
        leaf = target.rsplit(".", 1)[-1]
        candidates = await self._symbols_for(
            handle,
            leaf,
            paths,
            limit,
            exact_name=leaf,
        )
        return [
            symbol
            for symbol in candidates
            if symbol.name == target or symbol.qualified_name == target
        ]

    def _context_relation_scores(
        self,
        handle: _WorkspaceHandle,
        request: RepoContextRequest,
        symbols: list[RepoSymbol],
        *,
        max_relations: int,
    ) -> dict[str, int]:
        """Return bounded semantic relation scores for context candidates.

        Candidate ranking must happen before source capture, but it must still
        account for the indexed graph.  This helper therefore reads only a
        bounded set of relations rooted at explicit files, explicit symbols,
        and the highest-priority semantic symbols.  It never enumerates source
        files and it treats unresolved relations as non-ranking evidence.
        """
        if max_relations <= 0:
            return {}

        relation_weights = {
            "CALLER": 520,
            "CALLEE": 520,
            "REFERENCE": 500,
            "IMPORT": 480,
            "REVERSE_IMPORT": 480,
            "DEPENDENCY": 460,
            "REVERSE_DEPENDENCY": 460,
            "RELATED_TEST": 440,
        }
        relation_scores: dict[str, int] = {}
        seen_relations: set[tuple[object, ...]] = set()
        remaining = max_relations

        def add_relations(values: list[RepoRelation]) -> None:
            nonlocal remaining
            for relation in values:
                if remaining <= 0:
                    return
                if relation.status not in {"resolved", "possible"}:
                    continue
                key = (
                    relation.kind,
                    relation.source_path,
                    relation.target_path,
                    relation.source_symbol_id,
                    relation.target_symbol_id,
                    relation.name,
                )
                if key in seen_relations:
                    continue
                seen_relations.add(key)
                weight = relation_weights.get(relation.kind)
                if weight is None:
                    continue
                if relation.status == "possible":
                    weight = min(weight, 440)
                for path in (relation.source_path, relation.target_path):
                    if path:
                        relation_scores[path] = max(
                            relation_scores.get(path, 0), weight
                        )
                remaining -= 1

        relation_paths: list[str] = []
        for path in request.target_files + request.changed_files:
            if path not in relation_paths:
                relation_paths.append(path)
        for symbol in symbols[:16]:
            if symbol.path not in relation_paths:
                relation_paths.append(symbol.path)

        for path in relation_paths[:32]:
            if remaining <= 0:
                break
            add_relations(
                self._relations_for_path(
                    handle,
                    path,
                    min(remaining, self._limits.max_relations),
                )
            )
            if remaining <= 0:
                break
            # Reverse dependencies are not part of _relations_for_path's
            # source-file projection, but they are useful strong evidence for
            # a changed or explicitly targeted file.
            add_relations(
                self._relations_for_file_query(
                    handle,
                    RepoQueryKind.RELATED_FILES,
                    path,
                    (),
                    min(remaining, self._limits.max_relations),
                )
            )

        # A target symbol may have references/callers in files unrelated to
        # its definition's own outgoing edges.  Query those directions with a
        # fixed symbol cap so a large symbol fan-out cannot turn ranking into
        # an unbounded graph walk.
        for symbol in symbols[:16]:
            if remaining <= 0:
                break
            for kind in (
                RepoQueryKind.CALLERS,
                RepoQueryKind.CALLEES,
                RepoQueryKind.REFERENCES,
            ):
                if remaining <= 0:
                    break
                add_relations(
                    self._relations_for_symbol_query(
                        handle,
                        kind,
                        [symbol],
                        min(remaining, self._limits.max_relations),
                    )
                )
        return relation_scores

    async def _resolve_target_symbols(self, handle: _WorkspaceHandle, request: RepoQueryRequest, limit: int) -> list[RepoSymbol]:
        if request.symbol_id:
            rows = handle.store._conn.execute("SELECT * FROM repository_symbols WHERE repository_id=? AND (stable_symbol_id=? OR symbol_id=?) LIMIT 1", (handle.index_project_id, request.symbol_id, request.symbol_id)).fetchall()
            if rows:
                records = {str(item["path"]): item for item in await handle.store.file_records(handle.index_project_id, limit=self._limits.max_files)}
                return [self._symbol_from_graph(dict(rows[0]), records)]
        targets: list[RepoSymbol] = []
        for name in request.target_symbols:
            targets.extend(
                await self._symbols_for_target(
                    handle, name, request.target_files, limit
                )
            )
        if not targets and request.query:
            targets.extend(await self._symbols_for(handle, request.query, request.target_files, limit))
        return _dedupe_symbols(targets)[:limit]

    def _relations_for_symbol_query(self, handle: _WorkspaceHandle, kind: RepoQueryKind, symbols: list[RepoSymbol], limit: int) -> list[RepoRelation]:
        relations: list[RepoRelation] = []
        for symbol in symbols:
            if kind is RepoQueryKind.CALLERS:
                rows = handle.query_service.callers_of(handle.index_project_id, symbol.stable_symbol_id)
                relations.extend(_call_relations(rows, "CALLER"))
            elif kind is RepoQueryKind.CALLEES:
                # Call-edge persistence addresses the caller by its
                # generation-specific symbol_id, while target edges use the
                # stable target identity.  Keep that distinction explicit so
                # both directions remain conservative and resolvable.
                rows = handle.query_service.callees_of(handle.index_project_id, symbol.symbol_id)
                relations.extend(_call_relations(rows, "CALLEE"))
            else:
                rows = handle.query_service.references_to(handle.index_project_id, symbol.stable_symbol_id)
                relations.extend(_reference_relations(rows))
        return _dedupe_relations(relations)[:limit]

    def _relations_for_file_query(self, handle: _WorkspaceHandle, kind: RepoQueryKind, path: str, target_files: tuple[str, ...], limit: int) -> list[RepoRelation]:
        if not path and target_files:
            path = target_files[0]
        if not path:
            return []
        if kind is RepoQueryKind.IMPORTS:
            rows = handle.query_service.resolved_imports(handle.index_project_id, path)
            return [RepoRelation("IMPORT", str(row.get("source_file", path)), row.get("target_file"), target_symbol_id=row.get("target_symbol_id"), name=str(row.get("import_module", "")), status=str(row.get("status", "resolved")), confidence=float(row.get("confidence", 0.0)), evidence_id=str(row.get("reason", ""))) for row in rows[:limit]]
        if kind is RepoQueryKind.IMPORTERS:
            rows = handle.query_service.reverse_imports_to(handle.index_project_id, path)
            return [RepoRelation("REVERSE_IMPORT", str(row.get("source_file", "")), path, target_symbol_id=row.get("target_symbol_id"), name=str(row.get("import_module", "")), status=str(row.get("status", "resolved")), confidence=float(row.get("confidence", 0.0)), evidence_id=str(row.get("reason", ""))) for row in rows[:limit]]
        if kind is RepoQueryKind.RELATED_TESTS:
            result = handle.query_service.associated_tests(handle.index_project_id, target_files=tuple(target_files or (path,)), max_results=limit)
            candidates = getattr(result, "candidates", ())
            return [RepoRelation("RELATED_TEST", str(row.get("path", "")), path, name=str(row.get("reason", "")), status=str(row.get("status", "possible")), confidence=float(row.get("confidence", 0.0)), evidence_id=str(row.get("source", ""))) for row in candidates[:limit] if isinstance(row, dict)]
        if kind is RepoQueryKind.RELATED_FILES:
            related = handle.query_service.dependency_files(handle.index_project_id, path)
            reverse = handle.query_service.reverse_dependency_files(handle.index_project_id, path)
            return [RepoRelation("DEPENDENCY", path, item, evidence_id="semantic-graph") for item in related[:limit]] + [RepoRelation("REVERSE_DEPENDENCY", item, path, evidence_id="semantic-graph") for item in reverse[:limit]]
        return []

    def _relations_for_path(self, handle: _WorkspaceHandle, path: str, limit: int) -> list[RepoRelation]:
        relations = self._relations_for_file_query(handle, RepoQueryKind.IMPORTS, path, (), limit)
        call_rows = handle.query_service.call_edges_for_file(handle.index_project_id, path)
        relations.extend(_call_relations(call_rows, "CALLEE"))
        # The same persisted call edge is valid evidence for both the callee
        # relation of the source file and the caller relation of its caller
        # symbol.  Context consumers use the kind to explain why a file was
        # selected; they do not treat either relation as authority.
        relations.extend(_call_relations(call_rows, "CALLER"))
        relations.extend(_reference_relations(handle.query_service.reference_edges_for_file(handle.index_project_id, path)))
        relations.extend(self._relations_for_file_query(handle, RepoQueryKind.RELATED_TESTS, path, (path,), limit))
        return _dedupe_relations(relations)[:limit]

    async def _lexical_search(self, handle: _WorkspaceHandle, request: RepoQueryRequest, file_map: dict[str, RepoFile], limit: int) -> list[RepoTextMatch]:
        if not request.query:
            return []
        SafeWorkspaceFS, WorkspaceBoundaryError = _workspace_safety_types()
        paths = request.target_files or ((request.path,) if request.path else tuple(sorted(file_map)))
        remaining_bytes = request.max_bytes
        matches: list[RepoTextMatch] = []
        with SafeWorkspaceFS(handle.root) as fs:
            for relative in paths:
                if len(matches) >= limit or remaining_bytes <= 0:
                    break
                indexed_file = file_map.get(relative)
                if not _matches_path_scope(
                    relative,
                    path_prefix=request.path_prefix,
                    path_glob=request.path_glob,
                    language=request.language,
                    symbol_language=indexed_file.language if indexed_file else "text",
                ):
                    continue
                try:
                    raw = fs.read_bytes(relative, max_bytes=min(request.max_file_bytes, remaining_bytes, self._limits.max_file_bytes))
                except (OSError, WorkspaceBoundaryError):
                    continue
                remaining_bytes -= len(raw)
                try:
                    text = raw.decode("utf-8")
                except UnicodeDecodeError:
                    continue
                for line_number, line in enumerate(text.splitlines(), start=1):
                    if request.query in line:
                        language = (
                            file_map[relative].language
                            if relative in file_map
                            else "text"
                        )
                        matches.append(
                            RepoTextMatch(relative, line_number, line[:4096], language)
                        )
                        break
        return matches

    def _rank_context_files(
        self,
        records: list[dict[str, Any]],
        symbols: list[RepoSymbol],
        request: RepoContextRequest,
        *,
        relation_scores: dict[str, int] | None = None,
    ) -> list[tuple[dict[str, Any], int]]:
        symbol_paths = {symbol.path for symbol in symbols if not request.target_symbols or symbol.name in request.target_symbols or symbol.qualified_name in request.target_symbols}
        terms = {term.casefold() for term in request.query.replace("/", " ").replace(".", " ").split() if term}
        scored: list[tuple[dict[str, Any], int]] = []
        relation_scores = relation_scores or {}
        for record in records:
            path = str(record["path"])
            score = 0
            if path in request.target_files:
                score += 1000
            if path in request.changed_files:
                score += 900
            if path in symbol_paths:
                score += 700
            score += relation_scores.get(path, 0)
            score += sum(20 for term in terms if term in path.casefold())
            if str(record.get("path_role", "")) == "test" and ("test" in request.query.casefold() or request.changed_files):
                score += 10
            scored.append((record, score))
        scored.sort(key=lambda item: (-item[1], str(item[0]["path"])))
        return scored

    def _generation(self, handle: _WorkspaceHandle) -> RepositoryGeneration:
        return RepositoryGeneration(handle.workspace_id, handle.generation, handle.manifest_digest or canonical_digest([]), handle.indexed_at, handle.source_revision)

    def _file_from_record(self, record: dict[str, Any]) -> RepoFile:
        parser_source = str(record.get("parser_source", "unknown"))
        semantic = parser_source not in {"metadata", "rejected", "unavailable", "unknown", "legacy"} and str(record.get("language", "")) in set(self._registry.languages())
        return RepoFile(str(record["path"]), str(record["language"]), int(record["size"]), int(record["mtime_ns"]), str(record["content_hash"]), int(record["generation"]), str(record.get("path_role", "source")), semantic, parser_source)

    def _symbol_from_graph(self, row: dict[str, Any], file_records: dict[str, dict[str, Any]]) -> RepoSymbol:
        path = str(row["path"])
        return RepoSymbol(str(row["symbol_id"]), str(row["stable_symbol_id"]), path, str(row["language"]), str(row["kind"]), str(row["name"]), str(row["qualified_name"]), int(row.get("byte_start", 0)), int(row.get("byte_end", 0)), int(row.get("start_line", 0)), int(row.get("start_line", 0)), content_digest=str(file_records.get(path, {}).get("content_hash", "")), generation=int(row.get("generation", 0)))

    def _symbol_from_code(self, row: dict[str, Any], file_records: dict[str, dict[str, Any]], project_id: str) -> RepoSymbol:
        path = str(row["path"])
        payload = _json_object(row.get("payload_json"))
        location = payload.get("location", {}) if isinstance(payload.get("location", {}), dict) else {}
        language = str(payload.get("language", file_records.get(path, {}).get("language", "unknown")))
        kind = str(row.get("kind", "unknown"))
        qualified = str(payload.get("qualified_name", row.get("name", "")))
        byte_start = int(location.get("byte_start", 0) or 0)
        byte_end = int(location.get("byte_end", byte_start) or byte_start)
        start_line = max(0, int(location.get("start_line", int(row.get("line", 1)) - 1) or 0))
        generation = int(file_records.get(path, {}).get("generation", 0))
        return RepoSymbol(
            symbol_id=symbol_id(project_id, path, language, kind, qualified, byte_start, byte_end, generation),
            stable_symbol_id=stable_symbol_id(project_id, path, language, kind, qualified, byte_start, byte_end),
            path=path,
            language=language,
            kind=kind,
            name=str(row.get("name", "")),
            qualified_name=qualified,
            byte_start=byte_start,
            byte_end=byte_end,
            start_line=start_line,
            end_line=int(location.get("end_line", start_line) or start_line),
            start_column=int(location.get("start_column", 0) or 0),
            end_column=int(location.get("end_column", 0) or 0),
            generation=generation,
            content_digest=str(file_records.get(path, {}).get("content_hash", "")),
        )

    def _cache_get(self, key: tuple[str, int, str]) -> RepoQueryResult | None:
        with self._cache_lock:
            result = self._result_cache.pop(key, None)
            if result is not None:
                self._result_cache[key] = result
            return result

    def _cache_put(self, key: tuple[str, int, str], result: RepoQueryResult) -> None:
        with self._cache_lock:
            self._result_cache[key] = result
            while len(self._result_cache) > 256:
                self._result_cache.popitem(last=False)

    def _context_cache_get(
        self, key: tuple[str, int, str]
    ) -> RepoContextResult | None:
        with self._cache_lock:
            result = self._context_cache.pop(key, None)
            if result is not None:
                self._context_cache[key] = result
            return result

    def _context_cache_put(
        self, key: tuple[str, int, str], result: RepoContextResult
    ) -> None:
        with self._cache_lock:
            self._context_cache[key] = result
            while len(self._context_cache) > 128:
                self._context_cache.popitem(last=False)

    def _invalidate_cache(self, workspace_id: str) -> None:
        with self._cache_lock:
            for key in [key for key in self._result_cache if key[0] == workspace_id]:
                self._result_cache.pop(key, None)
            for key in [key for key in self._context_cache if key[0] == workspace_id]:
                self._context_cache.pop(key, None)


def repository_id_for_workspace(workspace: Any) -> str:
    """Derive repository identity from authority-captured git/root identity."""
    identity = getattr(workspace, "git_identity", None)
    repository_identity = getattr(identity, "repository_git_identity", None)
    if isinstance(repository_identity, tuple) and len(repository_identity) == 2 and all(type(value) is int for value in repository_identity):
        return f"git:{repository_identity[0]}:{repository_identity[1]}"
    try:
        info = os.stat(workspace.worktree_path, follow_symlinks=False)
    except OSError as exc:
        raise RepoIntelligenceUnavailableError("TaskWorkspace root is unavailable") from exc
    if not stat.S_ISDIR(info.st_mode):
        raise RepoIntelligenceUnavailableError("TaskWorkspace root is not a directory")
    return f"worktree:{info.st_dev}:{info.st_ino}"


def _metadata_digest(info: os.stat_result) -> str:
    return hashlib.sha256(f"metadata:{info.st_dev}:{info.st_ino}:{info.st_size}:{info.st_mtime_ns}".encode()).hexdigest()


def _is_context_text_record(record: dict[str, Any], path: str) -> bool:
    """Return whether an indexed file is a bounded text context candidate."""
    if str(record.get("parser_source", "")) in {"metadata", "rejected"}:
        return False
    if str(record.get("language", "")) in {"python", "javascript", "typescript", "go", "rust"}:
        return True
    return Path(path).suffix.casefold() in {
        ".c", ".cc", ".cpp", ".h", ".hpp", ".java", ".json", ".md",
        ".rst", ".sh", ".sql", ".toml", ".txt", ".yaml", ".yml",
    }


def _build_overview(
    files: Iterable[RepoFile],
    symbols: Iterable[RepoSymbol],
    *,
    symbol_count: int,
    relation_count: int,
    languages: tuple[str, ...],
    truncated: bool,
) -> RepoOverview:
    """Build a bounded orientation projection from indexed metadata."""

    file_values = tuple(files)
    roots: set[str] = set()
    package_roots: set[str] = set()
    test_roots: set[str] = set()
    entry_points: set[str] = set()
    build_files: set[str] = set()
    config_files: set[str] = set()
    build_names = {
        "makefile",
        "pyproject.toml",
        "setup.py",
        "requirements.txt",
        "cargo.toml",
        "go.mod",
        "go.work",
        "package.json",
        "tsconfig.json",
        "dockerfile",
        "pom.xml",
        "build.gradle",
    }
    entry_names = {
        "main.py",
        "__main__.py",
        "main.go",
        "main.rs",
        "index.js",
        "index.ts",
        "index.tsx",
        "cli.py",
    }
    config_suffixes = {".json", ".toml", ".ini", ".yaml", ".yml", ".conf"}
    for item in file_values:
        path = PurePosixPath(item.path)
        root = path.parts[0] if len(path.parts) > 1 else "."
        roots.add(root)
        parts = {part.casefold() for part in path.parts[:-1]}
        if item.path_role == "test" or parts.intersection(
            {"test", "tests", "__tests__", "spec", "specs"}
        ):
            test_roots.add(root)
        if path.name.casefold() in build_names:
            build_files.add(item.path)
            package_roots.add(path.parent.as_posix() if path.parent.parts else ".")
        if path.name.casefold() in entry_names or (
            len(path.parts) > 1 and path.parts[-2].casefold() == "cmd"
        ):
            entry_points.add(item.path)
        if path.suffix.casefold() in config_suffixes:
            config_files.add(item.path)
    top_symbols: list[str] = []
    seen_symbols: set[str] = set()
    for symbol in symbols:
        if symbol.qualified_name in seen_symbols:
            continue
        seen_symbols.add(symbol.qualified_name)
        top_symbols.append(symbol.qualified_name)
        if len(top_symbols) >= 32:
            break
    return RepoOverview(
        file_count=len(file_values),
        symbol_count=symbol_count,
        relation_count=relation_count,
        languages=languages,
        truncated=truncated,
        important_roots=tuple(sorted(roots))[:32],
        package_roots=tuple(sorted(package_roots))[:32],
        entry_points=tuple(sorted(entry_points))[:32],
        test_roots=tuple(sorted(test_roots))[:32],
        build_files=tuple(sorted(build_files))[:64],
        config_files=tuple(sorted(config_files))[:64],
        top_symbols=tuple(top_symbols),
    )


def _json_object(value: object) -> dict[str, Any]:
    if not isinstance(value, str):
        return {}
    try:
        result = json.loads(value)
    except (TypeError, ValueError, json.JSONDecodeError):
        return {}
    return result if isinstance(result, dict) else {}


def _count_rows(conn: Any, table: str, column: str, value: str) -> int:
    try:
        return int(conn.execute(f"SELECT COUNT(*) FROM {table} WHERE {column}=?", (value,)).fetchone()[0])
    except sqlite3.Error:
        return 0


def _call_relations(rows: list[dict[str, Any]], kind: str) -> list[RepoRelation]:
    return [RepoRelation(kind, str(row.get("source_file", "")), row.get("target_file"), row.get("caller_symbol_id"), row.get("target_symbol_id"), str(row.get("call_callee", "")), str(row.get("status", "resolved")), float(row.get("confidence", 0.0)), str(row.get("edge_id", ""))) for row in rows]


def _reference_relations(rows: list[dict[str, Any]]) -> list[RepoRelation]:
    return [RepoRelation("REFERENCE", str(row.get("source_file", "")), row.get("target_file"), target_symbol_id=row.get("target_symbol_id"), name=str(row.get("name", "")), status=str(row.get("status", "resolved")), confidence=float(row.get("confidence", 0.0)), evidence_id=str(row.get("edge_id", ""))) for row in rows]


def _dedupe_symbols(values: list[RepoSymbol]) -> list[RepoSymbol]:
    seen: set[str] = set()
    result: list[RepoSymbol] = []
    for value in values:
        if value.stable_symbol_id in seen:
            continue
        seen.add(value.stable_symbol_id)
        result.append(value)
    return result


def _dedupe_relations(values: list[RepoRelation]) -> list[RepoRelation]:
    seen: set[tuple[str, str, str | None, str | None, str | None]] = set()
    result: list[RepoRelation] = []
    for value in values:
        key = (value.kind, value.source_path, value.target_path, value.source_symbol_id, value.target_symbol_id)
        if key in seen:
            continue
        seen.add(key)
        result.append(value)
    return result


# Compatibility names used by early M8.1 integration experiments.
RepositoryIntelligenceService = RepoIntelligenceService
RepositoryQueryRequest = RepoQueryRequest
RepositoryQueryKind = RepoQueryKind


__all__ = [
    "FreshnessPolicy",
    "IntelligenceFreshness",
    "MutationEvent",
    "MutationType",
    "RepoContextFile",
    "RepoContextRequest",
    "RepoContextResult",
    "RepoContractError",
    "RepoFile",
    "RepoIntelligenceIndexUnavailableError",
    "RepoIntelligenceMetrics",
    "RepoIntelligenceService",
    "RepoIntelligenceUnavailableError",
    "RepoOverview",
    "RepoQueryKind",
    "RepoQueryRequest",
    "RepoQueryResult",
    "RepoRelation",
    "RepoRefreshReport",
    "RepoResourceLimits",
    "RepoSymbol",
    "RepoTextMatch",
    "RepositoryGeneration",
    "RepositoryIntelligenceService",
    "repository_id_for_workspace",
]
