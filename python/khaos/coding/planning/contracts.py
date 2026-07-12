"""Immutable, deterministic contracts for read-only implementation planning."""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Protocol


class PlanStatus(str, Enum):
    DRAFT = "draft"; READY = "ready"; BLOCKED = "blocked"; STALE = "stale"
    APPROVED = "approved"; REJECTED = "rejected"; EXECUTING = "executing"
    COMPLETED = "completed"; FAILED = "failed"


class PlanOperation(str, Enum):
    INSPECT = "inspect"; MODIFY = "modify"; CREATE = "create"; DELETE = "delete"
    RENAME = "rename"; TEST = "test"; DOCUMENT = "document"; CONFIGURE = "configure"; UNKNOWN = "unknown"

class GoalIntent(str, Enum):
    INSPECT="inspect"; MODIFY_SYMBOL="modify_symbol"; RENAME_SYMBOL="rename_symbol"; CREATE_FILE="create_file"; DELETE_FILE="delete_file"; MOVE_FILE="move_file"; UPDATE_IMPORT="update_import"; UPDATE_CONFIGURATION="update_configuration"; UPDATE_TEST="update_test"; UPDATE_DOCUMENTATION="update_documentation"; SCHEMA_CHANGE="schema_change"; SECURITY_CHANGE="security_change"; DEPENDENCY_CHANGE="dependency_change"; UNKNOWN="unknown"

class ImpactStatus(str, Enum):
    DIRECT="direct"; INDIRECT="indirect"; POSSIBLE="possible"; AMBIGUOUS="ambiguous"; DYNAMIC="dynamic"; EXTERNAL="external"; EXCLUDED="excluded"

@dataclass(frozen=True)
class GoalTarget:
    raw_text: str; target_type: str; requested_name: str | None; requested_path: str | None; requested_language: str | None; requested_operation: str; resolved_status: str; candidate_files: tuple[str, ...]; candidate_symbols: tuple[str, ...]; evidence: tuple[PlanEvidence, ...]; diagnostics: tuple[PlanDiagnostic, ...] = ()

@dataclass(frozen=True)
class GoalIntentResult:
    normalized_goal: str; intents: tuple[GoalIntent, ...]; targets: tuple[GoalTarget, ...]; confidence: float; diagnostics: tuple[PlanDiagnostic, ...] = ()

@dataclass(frozen=True)
class ImpactEdge:
    source_file: str; source_symbol: str | None; target_file: str; target_symbol: str | None; relation: str; depth: int; status: ImpactStatus; confidence: float; reason: str; evidence: tuple[PlanEvidence, ...]

@dataclass(frozen=True)
class ImpactAnalysis:
    target_files: tuple[str, ...]; target_symbols: tuple[str, ...]; direct_impacts: tuple[ImpactEdge, ...]; indirect_impacts: tuple[ImpactEdge, ...]; external_impacts: tuple[ImpactEdge, ...]; dynamic_impacts: tuple[ImpactEdge, ...]; excluded_impacts: tuple[ImpactEdge, ...]; diagnostics: tuple[PlanDiagnostic, ...]; traversal_depth: int; truncated: bool; content_hash: str
    visited_nodes: int = 0; visited_files: int = 0; visited_symbols: int = 0
    inspected_edges: int = 0; inspected_file_candidates: int = 0; inspected_test_candidates: int = 0
    inspected_reverse_imports: int = 0; sql_rows_returned: int = 0; sql_queries_issued: int = 0; indexed_edge_rows_fetched: int = 0; limit_code: str | None = None
    has_resolved_test_coverage: bool = False


class ImpactTraversalBudget:
    """Unified, mutable budget tracker shared across ALL impact sources.

    Every source (callers, references, reverse imports, re-exports, module
    dependencies, unresolved/dynamic candidates, test associations) must
    consult this single object before inspecting or adding any edge/file/symbol.
    Reaching ANY limit stops further expansion, sets ``truncated=True``,
    records a concrete ``limit_code``, and leaves results in stable sort order.

    HARD GLOBAL BUDGET: once ``truncated`` is set, ALL subsequent methods
    (can_visit_node, can_inspect_edge, can_inspect_reverse_import,
    can_inspect_test_candidate, can_inspect_file_candidate, add_affected_file,
    add_affected_symbol) immediately return False without incrementing any
    counter. This prevents later phases from continuing to their own local
    limits after an earlier phase already triggered truncation.
    """

    __slots__ = (
        "max_depth", "max_nodes", "max_edges", "max_files", "max_symbols",
        "max_reverse_imports", "max_test_candidates",
        "_visited_nodes", "_inspected_edges", "_inspected_file_candidates",
        "_inspected_test_candidates", "_inspected_reverse_imports",
        "_sql_rows_returned", "_sql_queries_issued", "_indexed_edge_rows_fetched",
        "_affected_files", "_affected_symbols",
        "_truncated", "_limit_code",
    )

    def __init__(self, *, max_depth: int = 3, max_nodes: int = 200, max_edges: int = 500,
                 max_files: int = 100, max_symbols: int = 100,
                 max_reverse_imports: int = 50, max_test_candidates: int = 50) -> None:
        self.max_depth = max_depth
        self.max_nodes = max_nodes
        self.max_edges = max_edges
        self.max_files = max_files
        self.max_symbols = max_symbols
        self.max_reverse_imports = max_reverse_imports
        self.max_test_candidates = max_test_candidates
        self._visited_nodes: set[str] = set()
        self._inspected_edges = 0
        self._inspected_file_candidates = 0
        self._inspected_test_candidates = 0
        self._inspected_reverse_imports = 0
        self._sql_rows_returned = 0
        self._sql_queries_issued = 0
        self._indexed_edge_rows_fetched = 0
        self._affected_files: set[str] = set()
        self._affected_symbols: set[str] = set()
        self._truncated = False
        self._limit_code: str | None = None

    @property
    def truncated(self) -> bool: return self._truncated
    @property
    def limit_code(self) -> str | None: return self._limit_code
    @property
    def visited_nodes_count(self) -> int: return len(self._visited_nodes)
    @property
    def inspected_edges(self) -> int: return self._inspected_edges
    @property
    def inspected_file_candidates(self) -> int: return self._inspected_file_candidates
    @property
    def inspected_test_candidates(self) -> int: return self._inspected_test_candidates
    @property
    def inspected_reverse_imports(self) -> int: return self._inspected_reverse_imports
    @property
    def sql_rows_returned(self) -> int: return self._sql_rows_returned
    @property
    def sql_queries_issued(self) -> int: return self._sql_queries_issued
    @property
    def indexed_edge_rows_fetched(self) -> int: return self._indexed_edge_rows_fetched
    @property
    def affected_files_count(self) -> int: return len(self._affected_files)
    @property
    def affected_symbols_count(self) -> int: return len(self._affected_symbols)
    @property
    def affected_files(self) -> tuple[str, ...]: return tuple(sorted(self._affected_files))
    @property
    def affected_symbols(self) -> tuple[str, ...]: return tuple(sorted(self._affected_symbols))

    def record_sql_query(self, *, rows_returned: int, indexed_rows: int = 0) -> None:
        """Record one SQL query and its returned/indexed row counts for audit.

        ``rows_returned`` is the number of rows actually returned to the caller
        (not the number of rows scanned). ``indexed_rows`` is the number of
        rows fetched via an index seek (not a full table scan).
        """
        self._sql_queries_issued += 1
        self._sql_rows_returned += rows_returned
        self._indexed_edge_rows_fetched += indexed_rows

    def record_sql_batch(self, *, queries_issued: int, rows_returned: int, indexed_rows_fetched: int) -> None:
        """Record multiple SQL queries at once (e.g., from associated_tests).

        This is the batch variant of :meth:`record_sql_query` — use it when a
        single logical operation (such as :meth:`CodeQueryService.associated_tests`)
        issues multiple SQL queries internally. The PlanningService must NOT
        record a :class:`TestAssociationResult` as a single SQL query.
        """
        self._sql_queries_issued += queries_issued
        self._sql_rows_returned += rows_returned
        self._indexed_edge_rows_fetched += indexed_rows_fetched

    def can_visit_node(self, sid: str, depth: int) -> bool:
        if self._truncated: return False
        if sid in self._visited_nodes: return False
        if len(self._visited_nodes) >= self.max_nodes:
            self._truncate("max_nodes"); return False
        if depth > self.max_depth:
            self._truncate("max_depth"); return False
        return True

    def mark_visited(self, sid: str) -> None:
        self._visited_nodes.add(sid)

    def can_inspect_edge(self) -> bool:
        if self._truncated: return False
        if self._inspected_edges >= self.max_edges:
            self._truncate("max_edges"); return False
        self._inspected_edges += 1
        return True

    def can_inspect_reverse_import(self) -> bool:
        if self._truncated: return False
        if self._inspected_reverse_imports >= self.max_reverse_imports:
            self._truncate("max_reverse_imports"); return False
        self._inspected_reverse_imports += 1
        return True

    def can_inspect_test_candidate(self) -> bool:
        if self._truncated: return False
        if self._inspected_test_candidates >= self.max_test_candidates:
            self._truncate("max_test_candidates"); return False
        self._inspected_test_candidates += 1
        return True

    def can_inspect_file_candidate(self) -> bool:
        if self._truncated: return False
        if self._inspected_file_candidates >= self.max_files:
            self._truncate("max_file_candidates"); return False
        self._inspected_file_candidates += 1
        return True

    def add_affected_file(self, path: str) -> bool:
        if path in self._affected_files: return True
        if self._truncated: return False
        if len(self._affected_files) >= self.max_files:
            self._truncate("max_files"); return False
        self._affected_files.add(path); return True

    def add_affected_symbol(self, sid: str) -> bool:
        if sid in self._affected_symbols: return True
        if self._truncated: return False
        if len(self._affected_symbols) >= self.max_symbols:
            self._truncate("max_symbols"); return False
        self._affected_symbols.add(sid); return True

    def _truncate(self, code: str) -> None:
        if not self._truncated:
            self._truncated = True
            self._limit_code = code


@dataclass(frozen=True)
class TestAssociationResult:
    """Bounded result from test association lookup.

    ``status`` is always ``possible`` for heuristic results — never ``resolved``.
    ``inspected_candidates`` reports how many candidates were examined;
    ``max_candidates`` is the bounded limit that was enforced.

    Query cost fields:
    - ``sql_queries_issued``: number of SQL statements executed (EXPLAIN excluded)
    - ``sql_rows_returned``: rows actually returned (not rows scanned)
    - ``indexed_edge_rows_fetched``: rows fetched via index seeks
    - ``query_plans``: EXPLAIN QUERY PLAN output for each query, for audit
    - ``fetch_budget``: the total row budget that was enforced across ALL queries
    - ``limit_code``: first budget trigger (e.g. ``max_candidates``, ``max_sql_queries``, ``max_indexed_rows``)

    Coverage fields:
    - ``has_resolved_test_coverage``: True only when a resolved graph test edge,
      trusted mapping, or exact subject/module key match was found. This is the
      ONLY field that may trigger ``has_tests=True`` in risk evaluation.
    - ``possible_test_coverage``: True when only weak/possible candidates exist.
      Must NOT eliminate ``test-gap`` risk.
    """
    candidates: tuple[dict[str, Any], ...]
    status: str  # "possible" for heuristic, "resolved" for graph-evidenced
    confidence: float
    inspected_candidates: int
    max_candidates: int
    evidence_sources: tuple[str, ...]  # which priority levels produced candidates
    truncated: bool
    sql_queries_issued: int = 0
    sql_rows_returned: int = 0
    indexed_edge_rows_fetched: int = 0
    query_plans: tuple[str, ...] = ()
    fetch_budget: int = 0
    limit_code: str | None = None
    has_resolved_test_coverage: bool = False
    possible_test_coverage: bool = False


@dataclass(frozen=True)
class VerificationCatalogEntry:
    """A single trusted verification command from repository configuration.

    Every entry is bound to a specific language and backed by a real config
    file (provenance + config_path + config_hash). Legacy commands without a
    language are NOT allowed to propagate across languages.
    """
    language: str  # "python","javascript","typescript","go","rust","repository"
    verification_type: str  # "unit-test","type-check","lint","build"
    argv: tuple[str, ...]
    scope: str  # "repository","package","file"
    provenance: str  # "pyproject.toml","package.json","go.mod","Cargo.toml","server-rule"
    config_path: str
    config_hash: str
    trust_level: str  # "high","medium","low"


@dataclass(frozen=True)
class PlanEvidence:
    source: str; repository_id: str; path: str | None = None; symbol_id: str | None = None
    generation: int | None = None; content_hash: str | None = None; query: str = ""
    confidence: float = 0.0; metadata: dict[str, Any] = field(default_factory=dict)

@dataclass(frozen=True)
class AffectedFile:
    path: str; operation: PlanOperation; reason: str; confidence: float; exists: bool
    language: str | None; evidence: tuple[PlanEvidence, ...]
    source_path: str | None = None; destination_path: str | None = None

@dataclass(frozen=True)
class AffectedSymbol:
    stable_symbol_id: str | None; qualified_name: str; kind: str; path: str
    impact_type: str; confidence: float; evidence: tuple[PlanEvidence, ...]
    requested_new_name: str | None = None

@dataclass(frozen=True)
class DependencyImpact:
    source: str; target: str; relation: str; status: str; confidence: float; reason: str

@dataclass(frozen=True)
class VerificationRequirement:
    command: tuple[str, ...] | None; verification_type: str; scope: str; expected_result: str
    required: bool; risk_level: str; evidence: tuple[PlanEvidence, ...]

@dataclass(frozen=True)
class RiskAssessment:
    level: str; category: str; description: str; affected_scope: tuple[str, ...]
    mitigation: str; requires_approval: bool

@dataclass(frozen=True)
class PlanDiagnostic:
    code: str; severity: str; message: str; recoverable: bool; evidence: tuple[PlanEvidence, ...] = ()

@dataclass(frozen=True)
class PlanStep:
    step_id: str; title: str; description: str; operation: PlanOperation
    target_files: tuple[str, ...]; target_symbols: tuple[str, ...]; depends_on: tuple[str, ...]
    expected_outcome: str; verification_requirements: tuple[VerificationRequirement, ...]
    risk: RiskAssessment; requires_approval: bool; evidence: tuple[PlanEvidence, ...]

@dataclass(frozen=True)
class ImplementationPlan:
    plan_id: str; repository_id: str; task_id: str; workspace_id: str; user_goal: str; normalized_goal: str
    base_sha: str; repository_generation: int; status: PlanStatus; summary: str
    steps: tuple[PlanStep, ...]; affected_files: tuple[AffectedFile, ...] = ()
    affected_symbols: tuple[AffectedSymbol, ...] = (); dependency_impacts: tuple[DependencyImpact, ...] = ()
    verification_requirements: tuple[VerificationRequirement, ...] = (); risks: tuple[RiskAssessment, ...] = ()
    diagnostics: tuple[PlanDiagnostic, ...] = (); evidence: tuple[PlanEvidence, ...] = ()
    content_hash: str = ""; created_at: float = 0.0

    @staticmethod
    def digest(payload: dict[str, Any]) -> str:
        return hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()

@dataclass(frozen=True)
class PlanValidationResult:
    valid: bool; status: PlanStatus; diagnostics: tuple[PlanDiagnostic, ...] = ()


class PlanningService(Protocol):
    def plan(self, *, repository_id: str, task_id: str, workspace_id: str, user_goal: str, base_sha: str) -> ImplementationPlan: ...
    def validate_plan(self, plan: ImplementationPlan, *, current_head: str, current_repository_generation: int) -> PlanValidationResult: ...
