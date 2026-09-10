"""M7 context adapter backed by the unified M8.1 repository intelligence.

``ContextIntelligenceService`` remains the stable GoalSpec/context contract
used by AgentLoop and planning. Repository enumeration, parsing, generation
tracking, semantic relations, and safe bounded source capture are delegated to
``RepoIntelligenceService``; this module only validates owner/goal binding and
projects the typed repository result into ``ContextBundle``.
"""

from __future__ import annotations

import logging
import stat
import threading
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Protocol, cast

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
from khaos.coding.intelligence.repository import (
    FreshnessPolicy,
    IntelligenceFreshness,
    MutationEvent,
    MutationType,
    RepoContextRequest,
    RepoContextResult,
    RepoIntelligenceService,
    RepoIntelligenceUnavailableError,
    RepoResourceLimits,
    repository_id_for_workspace,
)
from khaos.coding.workspace.models import TaskWorkspace
from khaos.security.protocol_boundary import canonical_digest

logger = logging.getLogger(__name__)


class ContextQueryError(RuntimeError):
    """Base error for workspace-bound context retrieval failures."""


class ContextInputError(ContextQueryError, ValueError):
    """The request or GoalSpec binding is malformed or stale."""


class ContextUnavailableError(ContextQueryError):
    """The owner-scoped workspace or its safe source boundary is unavailable."""


class ContextStaleError(ContextQueryError):
    """A repository mutation raced a bounded context capture."""


class WorkspaceProvider(Protocol):
    def get(self, workspace_id: str) -> TaskWorkspace | None:
        """Return one registered workspace projection."""


@dataclass(frozen=True, slots=True)
class _ContextCacheKey:
    request_digest: str
    workspace_id: str
    repository_generation: str
    index_schema_version: str
    parser_version: str


class _ContextBundleCache:
    """Bounded process-local projection cache; generation remains the fence."""

    def __init__(self, *, max_entries: int = 128, max_bytes: int = 32 * 1024 * 1024) -> None:
        self._max_entries = max_entries
        self._max_bytes = max_bytes
        self._entries: OrderedDict[_ContextCacheKey, tuple[ContextBundle, int]] = OrderedDict()
        self._bytes = 0
        self._lock = threading.RLock()

    def get(self, key: _ContextCacheKey) -> ContextBundle | None:
        with self._lock:
            value = self._entries.pop(key, None)
            if value is None:
                return None
            self._entries[key] = value
            return value[0]

    def put(self, key: _ContextCacheKey, bundle: ContextBundle) -> None:
        size = len(bundle.canonical_json().encode("utf-8"))
        if size > self._max_bytes:
            return
        with self._lock:
            old = self._entries.pop(key, None)
            if old is not None:
                self._bytes -= old[1]
            self._entries[key] = (bundle, size)
            self._bytes += size
            while len(self._entries) > self._max_entries or self._bytes > self._max_bytes:
                _, (_, old_size) = self._entries.popitem(last=False)
                self._bytes -= old_size

    def invalidate_workspace(self, workspace_id: str) -> None:
        with self._lock:
            for key in [item for item in self._entries if item.workspace_id == workspace_id]:
                _, size = self._entries.pop(key)
                self._bytes -= size


class ContextIntelligenceService:
    """GoalSpec-bound adapter over one unified repository intelligence service."""

    def __init__(
        self,
        workspace_manager: WorkspaceProvider,
        *,
        registry: Any | None = None,
        cache: _ContextBundleCache | None = None,
        repo_intelligence: RepoIntelligenceService | None = None,
        index_database: Any | None = None,
        limits: RepoResourceLimits | None = None,
    ) -> None:
        self._workspace_manager = workspace_manager
        self._cache = cache or _ContextBundleCache()
        self.repo_intelligence = repo_intelligence or RepoIntelligenceService(
            workspace_manager,
            registry=registry,
            database=index_database,
            limits=limits,
        )
        self._owns_repo_intelligence = repo_intelligence is None

    @staticmethod
    def repository_id_for_workspace(workspace: TaskWorkspace) -> str:
        return repository_id_for_workspace(workspace)

    def invalidate(self, workspace_id: str, changed_files: tuple[str, ...] = ()) -> None:
        """Observe a successful mutation and invalidate only derived state."""
        from khaos.coding.intelligence.repository import MutationEvent, MutationType

        self._cache.invalidate_workspace(workspace_id)
        try:
            self.repo_intelligence.mark_dirty(
                MutationEvent(workspace_id, MutationType.UPDATE, changed_files)
            )
        except (RepoIntelligenceUnavailableError, ValueError):
            logger.debug("repository intelligence mutation observation unavailable", exc_info=True)

    def invalidate_from_tool_result(
        self,
        *,
        workspace_id: str,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
    ) -> None:
        mutation_type_by_tool = {
            "write_file": MutationType.UPDATE,
            "patch": MutationType.UPDATE,
            "multi_edit": MutationType.UPDATE,
            "apply_edit_transaction": MutationType.UPDATE,
            "copy_file": MutationType.COPY,
            "move_file": MutationType.MOVE,
            "delete_file": MutationType.DELETE,
            "restore_file": MutationType.RESTORE,
            "restore": MutationType.RESTORE,
            "rollback": MutationType.ROLLBACK,
            "rollback_workspace": MutationType.ROLLBACK,
        }
        mutation_type = mutation_type_by_tool.get(tool_name)
        if mutation_type is None:
            return

        transaction_events: tuple[MutationEvent, ...] | None = None
        raw_paths: list[object]
        if tool_name in {"apply_edit_transaction"}:
            transaction_events = self._transaction_mutation_events(
                workspace_id, arguments
            )
            # ``None`` means the typed projection was not safely recoverable;
            # retain the existing no-path full-refresh fallback.
            raw_paths = []
        elif tool_name in {"copy_file"}:
            raw_paths = [arguments.get("dst")] if isinstance(arguments, dict) else []
        elif tool_name in {"move_file"}:
            raw_paths = (
                [arguments.get("src"), arguments.get("dst")]
                if isinstance(arguments, dict)
                else []
            )
        elif tool_name in {"restore_file"}:
            raw_paths = [arguments.get("path")] if isinstance(arguments, dict) else []
        elif tool_name in {"restore", "rollback", "rollback_workspace"}:
            raw_paths = []
        else:
            raw_paths = [arguments.get("path")] if isinstance(arguments, dict) else []

        # Tool arguments may be either workspace-relative or absolute.  Resolve
        # them through the same no-follow workspace boundary used by file
        # tools; never hand an untrusted host path to the indexer.  If a
        # successful mutation has no safely recoverable path, deliberately
        # request a bounded full refresh as the conservative fallback.
        paths: list[str] = []
        try:
            workspace = self._workspace_manager.get(workspace_id)
            if workspace is not None:
                from khaos.coding.workspace.boundary import SafeWorkspaceFS

                with SafeWorkspaceFS(workspace.worktree_path) as filesystem:
                    for raw_path in raw_paths:
                        if not isinstance(raw_path, str) or not raw_path:
                            continue
                        relative = filesystem.relative(raw_path)
                        info = filesystem.lstat(relative)
                        if info is not None and not stat.S_ISREG(info.st_mode):
                            # Directory copies/moves are not safely expressible
                            # as one file path; a full bounded refresh will
                            # reconcile their descendants.
                            paths = []
                            break
                        paths.append(relative)
        except (OSError, PermissionError, ValueError):
            paths = []

        try:
            self._cache.invalidate_workspace(workspace_id)
            if transaction_events is not None:
                for event in transaction_events:
                    self.repo_intelligence.mark_dirty(event)
            else:
                self.repo_intelligence.mark_dirty(
                    MutationEvent(
                        workspace_id,
                        mutation_type,
                        tuple(paths),
                    )
                )
        except (RepoIntelligenceUnavailableError, ValueError):
            logger.debug("repository intelligence mutation observation unavailable", exc_info=True)

    def _transaction_mutation_events(
        self,
        workspace_id: str,
        arguments: dict[str, Any] | None,
    ) -> tuple[MutationEvent, ...] | None:
        """Project a successful edit transaction into exact observer events.

        The transaction service is the mutation authority; this helper only
        describes an already-successful effect to the derived repository
        index.  Invalid or unsafe observer input deliberately falls back to a
        bounded full refresh instead of inventing a partial event set.
        """
        if not isinstance(arguments, dict):
            return None
        operations = arguments.get("operations")
        if not isinstance(operations, list) or not operations or len(operations) > 64:
            return None
        operation_types = {
            "create": MutationType.CREATE,
            "update": MutationType.UPDATE,
            "delete": MutationType.DELETE,
            "rename": MutationType.RENAME,
        }
        raw_events: list[tuple[MutationType, tuple[object, ...]]] = []
        for operation in operations:
            if not isinstance(operation, dict):
                return None
            kind = operation.get("operation")
            mutation_type = operation_types.get(kind.casefold() if isinstance(kind, str) else "")
            path = operation.get("path")
            if mutation_type is None or not isinstance(path, str) or not path:
                return None
            if mutation_type is MutationType.RENAME:
                destination = operation.get("destination_path")
                if not isinstance(destination, str) or not destination:
                    return None
                raw_events.append((mutation_type, (path, destination)))
            else:
                raw_events.append((mutation_type, (path,)))

        workspace = self._workspace_manager.get(workspace_id)
        if workspace is None:
            return None
        try:
            from khaos.coding.workspace.boundary import SafeWorkspaceFS

            with SafeWorkspaceFS(workspace.worktree_path) as filesystem:
                events: list[MutationEvent] = []
                for mutation_type, raw_paths in raw_events:
                    paths: list[str] = []
                    for raw_path in raw_paths:
                        relative = filesystem.relative(raw_path)
                        info = filesystem.lstat(relative)
                        if info is not None and not stat.S_ISREG(info.st_mode):
                            return None
                        paths.append(relative)
                    events.append(MutationEvent(workspace_id, mutation_type, tuple(paths)))
                return tuple(events)
        except (OSError, PermissionError, ValueError):
            return None

    async def close(self) -> None:
        if self._owns_repo_intelligence:
            await self.repo_intelligence.close()

    def _resolve_workspace(self, request: ContextRequest) -> Any:
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
        if callable(require):
            try:
                required = require(
                    request.workspace_id,
                    task_id=request.task_id,
                    principal_id=request.principal_id,
                    project_id=request.project_id,
                    runtime_id=request.runtime_id or str(getattr(workspace, "creator_runtime_id", "") or ""),
                )
            except (OSError, PermissionError, RuntimeError, TypeError) as exc:
                raise ContextUnavailableError("TaskWorkspace owner or root identity validation failed") from exc
            if required is None:
                raise ContextUnavailableError("TaskWorkspace is unavailable")
            workspace = cast(TaskWorkspace, required)
        return workspace

    @staticmethod
    def _validate_goal_binding(request: ContextRequest, goal_spec: GoalSpec) -> None:
        if not isinstance(goal_spec, GoalSpec):
            raise ContextInputError("canonical GoalSpec is required")
        if goal_spec.goal_spec_id != request.goal_spec_id or goal_spec.semantic_digest != request.goal_spec_digest:
            raise ContextInputError("ContextRequest GoalSpec binding is stale")

    def _validate_workspace_binding(self, request: ContextRequest, workspace: TaskWorkspace) -> None:
        try:
            expected_repository = repository_id_for_workspace(workspace)
        except RepoIntelligenceUnavailableError as exc:
            raise ContextUnavailableError("TaskWorkspace root is unavailable") from exc
        if expected_repository != request.repository_id:
            raise ContextInputError("ContextRequest repository identity is stale")
        workspace_base = getattr(workspace, "base_sha", None)
        if workspace_base is not None and not isinstance(workspace_base, str):
            raise ContextUnavailableError("TaskWorkspace base revision is malformed")
        if request.base_revision != workspace_base:
            raise ContextInputError("ContextRequest base revision is stale")

    async def retrieve(self, request: ContextRequest, goal_spec: GoalSpec) -> ContextBundle:
        """Return a generation-bound bounded bundle or explicit stale data."""
        self._validate_goal_binding(request, goal_spec)
        workspace = self._resolve_workspace(request)
        self._validate_workspace_binding(request, workspace)
        cache_request = request
        try:
            repo_request = RepoContextRequest(
                workspace_id=request.workspace_id,
                task_id=request.task_id,
                principal_id=request.principal_id,
                project_id=request.project_id,
                query=request.query,
                target_files=request.target_files,
                target_symbols=request.target_symbols,
                changed_files=request.changed_files,
                freshness_policy=FreshnessPolicy.PREFER_CURRENT,
                max_files=request.max_files,
                max_symbols=request.max_symbols,
                max_bytes=request.max_bytes,
                max_file_bytes=request.max_file_bytes,
                max_structure_entries=request.max_structure_entries,
            )
            # The repository service cache is keyed by its typed request. The
            # context cache below is keyed by the resulting generation too.
            result = await self.repo_intelligence.select_context(repo_request)
        except RepoIntelligenceUnavailableError as exc:
            raise ContextUnavailableError("safe workspace context is unavailable") from exc
        bundle = self._bundle_from_result(request, result)
        if bundle.freshness is ContextFreshness.FRESH:
            key = _ContextCacheKey(
                cache_request.request_digest,
                request.workspace_id,
                bundle.repository_generation,
                request.index_schema_version,
                request.parser_version,
            )
            cached = self._cache.get(key)
            if cached is not None:
                return cached
            self._cache.put(key, bundle)
        return bundle

    async def query(self, request: ContextRequest, goal_spec: GoalSpec) -> ContextBundle:
        return await self.retrieve(request, goal_spec)

    async def build_context(self, request: ContextRequest, goal_spec: GoalSpec) -> ContextBundle:
        return await self.retrieve(request, goal_spec)

    def metrics_snapshot(self) -> Any:
        return self.repo_intelligence.metrics_snapshot()

    def _bundle_from_result(self, request: ContextRequest, result: RepoContextResult) -> ContextBundle:
        repository_generation = result.generation.as_id()
        index_generation = canonical_digest(
            {
                "repository_generation": repository_generation,
                "index_schema_version": request.index_schema_version,
                "parser_version": request.parser_version,
            }
        )
        freshness = {
            IntelligenceFreshness.CURRENT: ContextFreshness.FRESH,
            IntelligenceFreshness.STALE: ContextFreshness.STALE,
            IntelligenceFreshness.PARTIAL: ContextFreshness.MIXED_GENERATION,
            IntelligenceFreshness.UNAVAILABLE: ContextFreshness.UNAVAILABLE,
        }[result.freshness]
        digest_by_path = {item.path: item.content_digest for item in result.files}
        relation_evidence = _relation_evidence(result, digest_by_path, repository_generation)
        documents = tuple(
            ContextDocument(
                relative_path=item.path,
                language=item.language,
                content=item.content,
                content_digest=item.content_digest,
                file_size=item.file_size,
                source_kind=ContextSourceKind.WORKSPACE_SNAPSHOT,
                workspace_id=request.workspace_id,
                repository_id=request.repository_id,
                base_revision=request.base_revision,
                repository_generation=repository_generation,
                index_generation=index_generation,
                excerpt_start=0,
                excerpt_end=len(item.content),
                truncated=item.truncated,
                relevance_score=item.relevance_score,
                evidence=tuple(evidence for evidence in relation_evidence if evidence.subject_path in {item.path, None}),
            )
            for item in result.files
        )
        symbols = tuple(
            ContextSymbol(
                symbol_id=item.symbol_id,
                relative_path=item.path,
                language=item.language,
                qualified_name=item.qualified_name,
                kind=item.kind,
                start_line=item.start_line,
                start_column=item.start_column,
                end_line=item.end_line,
                end_column=item.end_column,
                byte_start=item.byte_start,
                byte_end=item.byte_end,
                content_digest=item.content_digest,
                index_generation=index_generation,
                evidence=tuple(evidence for evidence in relation_evidence if evidence.subject_path in {item.path, None}),
            )
            for item in result.symbols
            if item.content_digest
        )
        return ContextBundle(
            bundle_id=f"bundle:{request.workspace_id}:{request.request_digest}:{repository_generation}",
            task_id=request.task_id,
            principal_id=request.principal_id,
            project_id=request.project_id,
            goal_spec_id=request.goal_spec_id,
            goal_spec_digest=request.goal_spec_digest,
            workspace_id=request.workspace_id,
            repository_id=request.repository_id,
            base_revision=request.base_revision,
            request_digest=request.request_digest,
            repository_generation=repository_generation,
            index_generation=index_generation,
            freshness=freshness,
            documents=documents,
            symbols=symbols,
            evidence=relation_evidence,
            structure_paths=result.structure_paths,
            truncated=result.truncated,
            truncation_reasons=result.truncation_reasons,
        )


def _relation_evidence(result: RepoContextResult, digests: dict[str, str], generation: str) -> tuple[ContextEvidence, ...]:
    mapping = {
        "CALLER": ContextEvidenceKind.CALLER,
        "CALLEE": ContextEvidenceKind.CALLEE,
        "REFERENCE": ContextEvidenceKind.SYMBOL_REFERENCE,
        "IMPORT": ContextEvidenceKind.IMPORT,
        "REVERSE_IMPORT": ContextEvidenceKind.REVERSE_IMPORT,
        "RELATED_TEST": ContextEvidenceKind.RELATED_TEST,
        "DEPENDENCY": ContextEvidenceKind.IMPORT,
        "REVERSE_DEPENDENCY": ContextEvidenceKind.REVERSE_IMPORT,
        "LEXICAL_SEARCH": ContextEvidenceKind.LEXICAL_SEARCH,
    }
    values: list[ContextEvidence] = []
    for relation in result.relations:
        kind = mapping.get(relation.kind, ContextEvidenceKind.STRUCTURAL_SEARCH)
        ref_id = relation.evidence_id or canonical_digest(
            {
                "kind": relation.kind,
                "source": relation.source_path,
                "target": relation.target_path,
                "target_symbol": relation.target_symbol_id,
                "name": relation.name,
            }
        )
        subject = relation.source_path or relation.target_path
        digest = digests.get(subject or "")
        values.append(ContextEvidence(kind, ref_id, subject or None, digest, generation))
    for path in sorted(digests):
        values.append(ContextEvidence(ContextEvidenceKind.FILE_CONTENT, path, path, digests[path], generation))
    unique: dict[tuple[str, str, str | None, str | None], ContextEvidence] = {}
    for value in values:
        unique[(value.kind.value, value.ref_id, value.subject_path, value.digest)] = value
    return tuple(sorted(unique.values(), key=lambda item: (item.kind.value, item.ref_id, item.subject_path or "")))


WorkspaceCodeQueryService = ContextIntelligenceService


__all__ = [
    "ContextInputError",
    "ContextIntelligenceService",
    "ContextQueryError",
    "ContextStaleError",
    "ContextUnavailableError",
    "WorkspaceCodeQueryService",
    "_ContextBundleCache",
    "repository_id_for_workspace",
]
