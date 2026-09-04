"""Edit-impact derivation backed by the existing M8.1 intelligence owner."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath
from typing import Any

from khaos.coding.edit_transaction import (
    EditOperationKind,
    EditOperationResult,
    EditTransaction,
    EditTransactionResult,
)
from khaos.coding.intelligence.repository import (
    FreshnessPolicy,
    IntelligenceFreshness,
    RepoQueryKind,
    RepoQueryRequest,
)
from khaos.coding.verification.contracts import VerificationContractError
from khaos.security.protocol_boundary import canonical_digest

_MAX_PATHS = 256
_MAX_SYMBOLS = 256
_MAX_TESTS = 256
_MAX_MODULES = 256
_MAX_IMPACT_QUERY_PATHS = 32
_MAX_RELATION_SYMBOLS = 16
_DIGEST_CHARS = frozenset("0123456789abcdef")
_BUILD_NAMES = frozenset(
    {
        "build.gradle",
        "build.gradle.kts",
        "cargo.toml",
        "go.mod",
        "go.work",
        "makefile",
        "meson.build",
        "package.json",
        "pyproject.toml",
        "setup.cfg",
        "setup.py",
        "tsconfig.json",
        "webpack.config.js",
        "vite.config.js",
    }
)
_CONFIG_NAMES = frozenset(
    {
        ".env.example",
        "cargo.toml",
        "go.mod",
        "go.work",
        "package.json",
        "pyproject.toml",
        "pytest.ini",
        "setup.cfg",
        "tox.ini",
        "tsconfig.json",
    }
)


def _path(value: str) -> str:
    normalized = str(value).replace("\\", "/")
    candidate = PurePosixPath(normalized)
    if (
        not normalized
        or normalized.startswith("/")
        or (len(normalized) >= 2 and normalized[1] == ":")
        or not candidate.parts
        or any(part in {"", ".", ".."} for part in candidate.parts)
        or any(part.casefold() in {".git", ".agents", ".codex", ".khaos"} for part in candidate.parts)
    ):
        raise VerificationContractError("impact path must be normalized and workspace-relative")
    return candidate.as_posix()


def _paths(values: tuple[str, ...], *, limit: int = _MAX_PATHS) -> tuple[str, ...]:
    if type(values) is not tuple:
        raise VerificationContractError("impact paths must be an immutable tuple")
    normalized = tuple(sorted({_path(value) for value in values}))
    if len(normalized) > limit:
        raise VerificationContractError("impact path set exceeds its bound")
    return normalized


@dataclass(frozen=True, slots=True)
class ChangedRange:
    """One bounded source range from an edit transaction."""

    path: str
    start: int
    end: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "path", _path(self.path))
        if type(self.start) is not int or type(self.end) is not int:
            raise VerificationContractError("changed range offsets must be integers")
        if self.start < 0 or self.end < self.start:
            raise VerificationContractError("changed range offsets are invalid")

    def to_payload(self) -> dict[str, object]:
        return {"path": self.path, "start": self.start, "end": self.end}


def edit_transaction_result_from_tool_output(output: object) -> EditTransactionResult:
    """Decode one exact, successful M8.2 result at the AgentLoop boundary.

    Tool output is model-visible observation data.  Coercion such as
    ``bool(value)`` or ``int(value)`` would let malformed data masquerade as a
    successful edit and trigger verification against the wrong generation, so
    every field is checked before the typed result is constructed.
    """
    payload: object = output
    if isinstance(output, str):
        try:
            payload = json.loads(output)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise VerificationContractError("edit result output is not JSON") from exc
    if not isinstance(payload, Mapping) or payload.get("status") != "applied":
        raise VerificationContractError("tool output is not an applied edit result")

    transaction_id = _result_text(payload.get("transaction_id"), "transaction_id")
    workspace_id = _result_text(payload.get("workspace_id"), "workspace_id")
    base_generation = _result_generation(payload.get("base_generation"), "base_generation")
    resulting_generation = _result_generation(
        payload.get("resulting_generation"), "resulting_generation"
    )
    if resulting_generation <= base_generation:
        raise VerificationContractError("resulting_generation must advance the base generation")
    transaction_digest = _result_digest(
        payload.get("transaction_digest"), "transaction_digest"
    )
    before_workspace_digest = _result_digest(
        payload.get("before_workspace_digest"), "before_workspace_digest"
    )
    after_workspace_digest = _result_digest(
        payload.get("after_workspace_digest"), "after_workspace_digest"
    )
    operations_value = payload.get("operations")
    if not isinstance(operations_value, list) or not operations_value:
        raise VerificationContractError("applied edit result has no operations")
    if len(operations_value) > 256:
        raise VerificationContractError("applied edit result exceeds its operation bound")

    operations: list[EditOperationResult] = []
    indices: list[int] = []
    for item in operations_value:
        if not isinstance(item, Mapping):
            raise VerificationContractError("edit operation result is malformed")
        index = _result_index(item.get("index"))
        operation_value = item.get("operation")
        if type(operation_value) is not str:
            raise VerificationContractError("edit operation kind is invalid")
        try:
            operation_kind = EditOperationKind(operation_value)
        except ValueError as exc:
            raise VerificationContractError("edit operation kind is invalid") from exc
        path = _result_text(item.get("path"), "operation.path")
        destination_value = item.get("destination_path")
        if destination_value is not None and type(destination_value) is not str:
            raise VerificationContractError("operation.destination_path is invalid")
        destination_path = (
            _result_text(destination_value, "operation.destination_path")
            if destination_value is not None
            else None
        )
        before_exists = _result_bool(item.get("before_exists"), "before_exists")
        after_exists = _result_bool(item.get("after_exists"), "after_exists")
        before_digest = _result_optional_digest(item.get("before_digest"), "before_digest")
        after_digest = _result_optional_digest(item.get("after_digest"), "after_digest")
        operations.append(
            EditOperationResult(
                index=index,
                operation=operation_kind,
                path=path,
                destination_path=destination_path,
                before_exists=before_exists,
                after_exists=after_exists,
                before_digest=before_digest,
                after_digest=after_digest,
            )
        )
        indices.append(index)
    if sorted(indices) != list(range(len(indices))):
        raise VerificationContractError("edit operation indexes are not contiguous")
    return EditTransactionResult(
        transaction_id=transaction_id,
        workspace_id=workspace_id,
        base_generation=base_generation,
        resulting_generation=resulting_generation,
        transaction_digest=transaction_digest,
        before_workspace_digest=before_workspace_digest,
        after_workspace_digest=after_workspace_digest,
        operations=tuple(operations),
    )


def _result_text(value: object, label: str) -> str:
    if type(value) is not str or not value or len(value) > 512 or "\x00" in value:
        raise VerificationContractError(f"{label} is invalid")
    return value


def _result_generation(value: object, label: str) -> int:
    if type(value) is not int or value <= 0:
        raise VerificationContractError(f"{label} is invalid")
    return value


def _result_index(value: object) -> int:
    if type(value) is not int or value < 0:
        raise VerificationContractError("operation index is invalid")
    return value


def _result_bool(value: object, label: str) -> bool:
    if type(value) is not bool:
        raise VerificationContractError(f"{label} must be a bool")
    return value


def _result_digest(value: object, label: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in _DIGEST_CHARS for character in value)
    ):
        raise VerificationContractError(f"{label} must be a SHA-256 digest")
    return value


def _result_optional_digest(value: object, label: str) -> str | None:
    if value is None:
        return None
    return _result_digest(value, label)


@dataclass(frozen=True, slots=True)
class EditImpact:
    """Immutable impact facts derived from an applied edit and repo queries."""

    workspace_id: str
    transaction_id: str
    transaction_digest: str
    base_generation: int
    resulting_generation: int
    repository_generation: int
    changed_paths: tuple[str, ...]
    operations: tuple[str, ...]
    changed_ranges: tuple[ChangedRange, ...] = ()
    changed_symbols: tuple[str, ...] = ()
    affected_modules: tuple[str, ...] = ()
    related_tests: tuple[str, ...] = ()
    build_config_paths: tuple[str, ...] = ()
    config_paths: tuple[str, ...] = ()
    public_api_changed: bool = False
    uncertainty: tuple[str, ...] = ()
    after_workspace_digest: str = ""

    def __post_init__(self) -> None:
        for label, value in (
            ("workspace_id", self.workspace_id),
            ("transaction_id", self.transaction_id),
        ):
            if type(value) is not str or not value:
                raise VerificationContractError(f"{label} must be non-empty")
        if (
            type(self.transaction_digest) is not str
            or len(self.transaction_digest) != 64
            or any(character not in _DIGEST_CHARS for character in self.transaction_digest)
        ):
            raise VerificationContractError("transaction_digest must be a SHA-256 digest")
        for label, value in (
            ("base_generation", self.base_generation),
            ("resulting_generation", self.resulting_generation),
            ("repository_generation", self.repository_generation),
        ):
            if type(value) is not int or value < 0:
                raise VerificationContractError(f"{label} must be non-negative")
        object.__setattr__(self, "changed_paths", _paths(self.changed_paths))
        object.__setattr__(self, "operations", _string_values(self.operations, "operations"))
        object.__setattr__(self, "changed_symbols", _string_values(self.changed_symbols, "changed_symbols", _MAX_SYMBOLS))
        object.__setattr__(self, "affected_modules", _paths(self.affected_modules, limit=_MAX_MODULES))
        object.__setattr__(self, "related_tests", _paths(self.related_tests, limit=_MAX_TESTS))
        object.__setattr__(self, "build_config_paths", _paths(self.build_config_paths))
        object.__setattr__(self, "config_paths", _paths(self.config_paths))
        if type(self.changed_ranges) is not tuple or any(type(item) is not ChangedRange for item in self.changed_ranges):
            raise VerificationContractError("changed_ranges must contain ChangedRange values")
        if type(self.public_api_changed) is not bool:
            raise VerificationContractError("public_api_changed must be a bool")
        object.__setattr__(self, "uncertainty", _string_values(self.uncertainty, "uncertainty", 64))
        if self.after_workspace_digest:
            _result_digest(self.after_workspace_digest, "after_workspace_digest")

    @classmethod
    def from_result(
        cls,
        result: EditTransactionResult,
        *,
        transaction: EditTransaction | None = None,
        repository_generation: int = 0,
    ) -> EditImpact:
        """Create direct impact facts from a successful edit result."""
        if type(result) is not EditTransactionResult:
            raise TypeError("result must be an EditTransactionResult")
        changed_paths: set[str] = set()
        operations: list[str] = []
        changed_ranges: list[ChangedRange] = []
        for operation in result.operations:
            changed_paths.add(_path(operation.path))
            if operation.destination_path is not None:
                changed_paths.add(_path(operation.destination_path))
            operations.append(operation.operation.value)
        if transaction is not None:
            if type(transaction) is not EditTransaction:
                raise TypeError("transaction must be an EditTransaction or None")
            if (
                transaction.transaction_id != result.transaction_id
                or transaction.workspace_id != result.workspace_id
                or transaction.transaction_digest != result.transaction_digest
            ):
                raise VerificationContractError("transaction/result identity mismatch")
            for operation in transaction.operations:
                for edit in operation.text_edits:
                    changed_ranges.append(ChangedRange(operation.path, edit.start, edit.end))
        build_config = tuple(
            sorted(path for path in changed_paths if Path(path).name.casefold() in _BUILD_NAMES)
        )
        config_paths = tuple(
            sorted(path for path in changed_paths if Path(path).name.casefold() in _CONFIG_NAMES)
        )
        uncertainty: set[str] = set()
        if any(operation in {EditOperationKind.RENAME.value, EditOperationKind.DELETE.value} for operation in operations):
            uncertainty.add("rename-or-delete")
        if not changed_paths:
            uncertainty.add("empty-change-set")
        return cls(
            workspace_id=result.workspace_id,
            transaction_id=result.transaction_id,
            transaction_digest=result.transaction_digest,
            base_generation=result.base_generation,
            resulting_generation=result.resulting_generation,
            repository_generation=repository_generation,
            changed_paths=tuple(sorted(changed_paths)),
            operations=tuple(operations),
            changed_ranges=tuple(changed_ranges),
            build_config_paths=build_config,
            config_paths=config_paths,
            public_api_changed=False,
            uncertainty=tuple(sorted(uncertainty)),
            after_workspace_digest=result.after_workspace_digest,
        )

    @classmethod
    def from_tool_output(cls, output: object) -> EditImpact:
        """Decode only the typed applied-result projection from a tool result.

        The output is an observation boundary, so a malformed or non-applied
        payload is rejected rather than guessed into a verification trigger.
        """
        return cls.from_result(edit_transaction_result_from_tool_output(output))

    @property
    def digest(self) -> str:
        """Return a portable digest of all impact facts."""
        return canonical_digest(self.to_payload())

    @property
    def is_docs_only(self) -> bool:
        """Return whether every changed path is documentation-like."""
        return bool(self.changed_paths) and all(
            Path(path).suffix.casefold() in {".md", ".rst", ".txt", ".adoc"}
            or Path(path).name.casefold() in {"changelog", "license", "notice"}
            for path in self.changed_paths
        )

    @property
    def is_test_only(self) -> bool:
        """Return whether every changed path is conventionally a test."""
        return bool(self.changed_paths) and all(_looks_like_test(path) for path in self.changed_paths)

    @property
    def languages(self) -> tuple[str, ...]:
        """Return languages inferred from changed file suffixes."""
        mapping = {
            ".py": "python",
            ".js": "javascript",
            ".jsx": "javascript",
            ".mjs": "javascript",
            ".cjs": "javascript",
            ".ts": "typescript",
            ".tsx": "typescript",
            ".go": "go",
            ".rs": "rust",
        }
        return tuple(sorted({mapping[Path(path).suffix.casefold()] for path in self.changed_paths if Path(path).suffix.casefold() in mapping}))

    def to_payload(self) -> dict[str, object]:
        return {
            "workspace_id": self.workspace_id,
            "transaction_id": self.transaction_id,
            "transaction_digest": self.transaction_digest,
            "base_generation": self.base_generation,
            "resulting_generation": self.resulting_generation,
            "repository_generation": self.repository_generation,
            "changed_paths": self.changed_paths,
            "operations": self.operations,
            "changed_ranges": tuple(item.to_payload() for item in self.changed_ranges),
            "changed_symbols": self.changed_symbols,
            "affected_modules": self.affected_modules,
            "related_tests": self.related_tests,
            "build_config_paths": self.build_config_paths,
            "config_paths": self.config_paths,
            "public_api_changed": self.public_api_changed,
            "uncertainty": self.uncertainty,
            "after_workspace_digest": self.after_workspace_digest,
        }


class VerificationImpactAnalyzer:
    """Enrich direct edit facts through the canonical M8.1 query facade."""

    async def analyze(
        self,
        result: EditTransactionResult,
        *,
        repo_intelligence: Any | None,
        task_id: str,
        principal_id: str,
        project_id: str,
        transaction: EditTransaction | None = None,
    ) -> EditImpact:
        """Analyze one applied edit through the shared impact path."""
        impact = EditImpact.from_result(result, transaction=transaction)
        return await self.analyze_impact(
            impact,
            repo_intelligence=repo_intelligence,
            task_id=task_id,
            principal_id=principal_id,
            project_id=project_id,
        )

    async def analyze_impact(
        self,
        impact: EditImpact,
        *,
        repo_intelligence: Any | None,
        task_id: str,
        principal_id: str,
        project_id: str,
    ) -> EditImpact:
        """Enrich an existing impact, including a union merge impact."""
        if type(impact) is not EditImpact:
            raise TypeError("impact must be an EditImpact")
        if repo_intelligence is None:
            return replace(impact, uncertainty=tuple(sorted(set(impact.uncertainty) | {"repository-intelligence-unavailable"})))
        overview = await self._query(
            repo_intelligence,
            workspace_id=impact.workspace_id,
            task_id=task_id,
            principal_id=principal_id,
            project_id=project_id,
            kind=RepoQueryKind.REPOSITORY_OVERVIEW,
        )
        if overview is None:
            return replace(impact, uncertainty=tuple(sorted(set(impact.uncertainty) | {"repository-intelligence-unavailable"})))
        overview_freshness = getattr(overview, "freshness", None)
        if (
            overview_freshness is not None
            and getattr(overview_freshness, "value", overview_freshness) != "current"
        ):
            return replace(
                impact,
                uncertainty=tuple(
                    sorted(
                        set(impact.uncertainty)
                        | {"repository-overview-not-current"}
                    )
                ),
            )
        repository_generation = overview.generation.generation
        related_tests: set[str] = set()
        related_files: set[str] = set()
        changed_symbols: set[str] = set()
        symbol_targets: list[tuple[str, str]] = []
        symbol_target_ids: set[str] = set()
        uncertainty = set(impact.uncertainty)
        public_api_changed = impact.public_api_changed
        analysis_paths = impact.changed_paths[:_MAX_IMPACT_QUERY_PATHS]
        if len(impact.changed_paths) > _MAX_IMPACT_QUERY_PATHS:
            uncertainty.add("impact-path-query-truncated")
        for path in analysis_paths:
            related = await self._query(
                repo_intelligence,
                workspace_id=impact.workspace_id,
                task_id=task_id,
                principal_id=principal_id,
                project_id=project_id,
                kind=RepoQueryKind.RELATED_TESTS,
                path=path,
            )
            if related is None:
                uncertainty.add("related-test-query-unavailable")
            else:
                repository_generation = max(repository_generation, related.generation.generation)
                if related.truncated or related.freshness is not IntelligenceFreshness.CURRENT:
                    uncertainty.add("related-test-evidence-partial")
                for relation in related.relations:
                    for candidate in (relation.source_path, relation.target_path):
                        if candidate:
                            try:
                                candidate_path = _path(candidate)
                            except VerificationContractError:
                                continue
                            if _looks_like_test(candidate_path):
                                related_tests.add(candidate_path)
                            related_files.add(candidate_path)
            related_file_result = await self._query(
                repo_intelligence,
                workspace_id=impact.workspace_id,
                task_id=task_id,
                principal_id=principal_id,
                project_id=project_id,
                kind=RepoQueryKind.RELATED_FILES,
                path=path,
            )
            if related_file_result is None:
                uncertainty.add("related-file-query-unavailable")
            else:
                repository_generation = max(
                    repository_generation,
                    related_file_result.generation.generation,
                )
                if (
                    related_file_result.truncated
                    or related_file_result.freshness is not IntelligenceFreshness.CURRENT
                ):
                    uncertainty.add("related-file-evidence-partial")
                for relation in related_file_result.relations:
                    for candidate in (relation.source_path, relation.target_path):
                        if candidate:
                            try:
                                related_files.add(_path(candidate))
                            except VerificationContractError:
                                continue
            symbols = await self._query(
                repo_intelligence,
                workspace_id=impact.workspace_id,
                task_id=task_id,
                principal_id=principal_id,
                project_id=project_id,
                kind=RepoQueryKind.SYMBOLS,
                path=path,
            )
            definitions = symbols
            if symbols is None or not getattr(symbols, "symbols", ()):
                # Some intelligence implementations expose definitions as a
                # distinct query despite sharing the same backing index.  Use
                # it as a bounded fallback rather than treating a missing
                # SYMBOLS projection as proof that the file has no symbols.
                definitions = await self._query(
                    repo_intelligence,
                    workspace_id=impact.workspace_id,
                    task_id=task_id,
                    principal_id=principal_id,
                    project_id=project_id,
                    kind=RepoQueryKind.DEFINITIONS,
                    path=path,
                )
            if definitions is None:
                uncertainty.add("symbol-and-definition-impact-unavailable")
            else:
                repository_generation = max(
                    repository_generation,
                    definitions.generation.generation,
                )
                if (
                    definitions.truncated
                    or definitions.freshness is not IntelligenceFreshness.CURRENT
                ):
                    uncertainty.add("symbol-and-definition-impact-partial")
                for symbol in definitions.symbols:
                    identifier = symbol.stable_symbol_id or symbol.qualified_name
                    if identifier:
                        changed_symbols.add(str(identifier))
                        if (
                            identifier not in symbol_target_ids
                            and len(symbol_targets) < _MAX_RELATION_SYMBOLS
                        ):
                            symbol_targets.append((str(identifier), path))
                            symbol_target_ids.add(str(identifier))
                    if symbol.name and not symbol.name.startswith("_"):
                        public_api_changed = True
            importers = await self._query(
                repo_intelligence,
                workspace_id=impact.workspace_id,
                task_id=task_id,
                principal_id=principal_id,
                project_id=project_id,
                kind=RepoQueryKind.IMPORTERS,
                path=path,
            )
            if importers is None:
                uncertainty.add("importer-query-unavailable")
            else:
                repository_generation = max(
                    repository_generation,
                    importers.generation.generation,
                )
                if (
                    importers.truncated
                    or importers.freshness is not IntelligenceFreshness.CURRENT
                ):
                    uncertainty.add("importer-evidence-partial")
                for relation in importers.relations:
                    for candidate in (relation.source_path, relation.target_path):
                        if candidate:
                            try:
                                related_files.add(_path(candidate))
                            except VerificationContractError:
                                continue

        for symbol_id, symbol_path in symbol_targets:
            for relation_kind, unavailable_reason, partial_reason in (
                (
                    RepoQueryKind.CALLERS,
                    "caller-query-unavailable",
                    "caller-evidence-partial",
                ),
                (
                    RepoQueryKind.REFERENCES,
                    "reference-query-unavailable",
                    "reference-evidence-partial",
                ),
            ):
                relations = await self._query(
                    repo_intelligence,
                    workspace_id=impact.workspace_id,
                    task_id=task_id,
                    principal_id=principal_id,
                    project_id=project_id,
                    kind=relation_kind,
                    path=symbol_path,
                    symbol_id=symbol_id,
                    target_files=(symbol_path,),
                    target_symbols=(symbol_id,),
                )
                if relations is None:
                    uncertainty.add(unavailable_reason)
                    continue
                repository_generation = max(
                    repository_generation,
                    relations.generation.generation,
                )
                if (
                    relations.truncated
                    or relations.freshness is not IntelligenceFreshness.CURRENT
                ):
                    uncertainty.add(partial_reason)
                for relation in relations.relations:
                    for candidate in (relation.source_path, relation.target_path):
                        if candidate:
                            try:
                                candidate_path = _path(candidate)
                            except VerificationContractError:
                                continue
                            related_files.add(candidate_path)
                            if _looks_like_test(candidate_path):
                                related_tests.add(candidate_path)
        if overview.truncated:
            uncertainty.add("repository-overview-truncated")
        for relation in overview.relations:
            for candidate in (relation.source_path, relation.target_path):
                if candidate:
                    try:
                        related_files.add(_path(candidate))
                    except VerificationContractError:
                        continue
        modules = {
            PurePosixPath(path).parent.as_posix()
            if PurePosixPath(path).parent.parts
            else "."
            for path in (*impact.changed_paths, *sorted(related_files))
        }
        # A repository-root source file has ``.`` as its parent.  The typed
        # impact path contract intentionally excludes the workspace root, so
        # omit that sentinel instead of turning a valid root edit into a
        # malformed impact.
        modules.difference_update({"", "."})
        if not changed_symbols and not impact.is_docs_only:
            uncertainty.add("semantic-symbols-unresolved")
        return replace(
            impact,
            repository_generation=repository_generation,
            changed_symbols=tuple(sorted(changed_symbols))[:_MAX_SYMBOLS],
            affected_modules=tuple(sorted(modules))[:_MAX_MODULES],
            related_tests=tuple(sorted(related_tests))[:_MAX_TESTS],
            public_api_changed=public_api_changed,
            uncertainty=tuple(sorted(uncertainty)),
        )

    @staticmethod
    async def _query(
        service: Any,
        *,
        workspace_id: str,
        task_id: str,
        principal_id: str,
        project_id: str,
        kind: RepoQueryKind,
        path: str = "",
        symbol_id: str = "",
        target_files: tuple[str, ...] = (),
        target_symbols: tuple[str, ...] = (),
    ) -> Any | None:
        try:
            request = RepoQueryRequest(
                workspace_id=workspace_id,
                task_id=task_id,
                principal_id=principal_id,
                project_id=project_id,
                kind=kind,
                path=path,
                symbol_id=symbol_id,
                target_files=target_files or ((path,) if path else ()),
                target_symbols=target_symbols,
                freshness_policy=FreshnessPolicy.REQUIRE_CURRENT,
                limit=64,
            )
            return await service.query(request)
        except Exception:  # noqa: BLE001 - unavailable intelligence widens impact
            return None


def _string_values(values: tuple[str, ...], label: str, limit: int = 256) -> tuple[str, ...]:
    if type(values) is not tuple or any(type(value) is not str or not value for value in values):
        raise VerificationContractError(f"{label} must be a tuple of non-empty strings")
    normalized = tuple(sorted(set(values)))
    if len(normalized) > limit:
        raise VerificationContractError(f"{label} exceeds its bound")
    return normalized


def _looks_like_test(path: str) -> bool:
    name = Path(path).name.casefold()
    return (
        "/test/" in f"/{path.casefold()}/"
        or "/tests/" in f"/{path.casefold()}/"
        or name.startswith("test_")
        or name.endswith(("_test.py", "_test.go", "_test.rs"))
        or ".test." in name
        or ".spec." in name
    )


__all__ = [
    "ChangedRange",
    "EditImpact",
    "VerificationImpact",
    "VerificationImpactAnalyzer",
    "edit_transaction_result_from_tool_output",
]


# Public vocabulary used by the M8.3 milestone text.  The implementation
# keeps ``EditImpact`` as the canonical class name because it is explicitly
# tied to the M8.2 edit transaction result.
VerificationImpact = EditImpact
