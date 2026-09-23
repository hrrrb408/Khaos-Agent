"""Bounded black-box effort and outcome metrics for Coding evaluation."""

from __future__ import annotations

import hashlib
import math
import time
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import cast

from khaos.coding.context_engine.observability import (
    CONTEXT_SELECTION_OBSERVABILITY_SCHEMA_VERSION,
    project_context_selection,
)
from khaos.evaluation.coding.contracts import CodingVerdict
from khaos.evaluation.coding.observability import (
    SEMANTIC_ATTRIBUTION_SCHEMA_VERSION,
    project_review_findings,
)
from khaos.evaluation.coding.oracle import ReviewFinding
from khaos.security.protocol_boundary import canonical_digest, canonical_json_bytes
from khaos.security.secret_redaction import SecretRedactor

TOOL_CATEGORIES = frozenset(
    {
        # Historical aggregate names remain accepted when reading old runs.
        "editing",
        "context",
        # Trace v2 uses these non-overlapping categories for new observations.
        "edit",
        "verification",
        "recovery",
        "content_search",
        "navigation",
        "metadata",
        "file_read",
        "execution",
        "browser",
        "subagent",
        "other",
    }
)
OBSERVABILITY_SCHEMA_VERSION = 1
# The typed context-selection projection is capped at 128 items and carries
# only bounded identifiers/digests.  Keep the enclosing observation bound
# finite while allowing the full projection to survive the durable firewall.
_MAX_OBSERVABILITY_BYTES = 256 * 1024
_MAX_CONTEXT_SELECTION_HISTORY = 128
_MAX_PROVIDER_OBSERVATIONS = 64
_OBSERVABILITY_SENSITIVE_KEY_MARKERS = (
    "api_key",
    "access_token",
    "authorization",
    "cookie",
    "password",
    "private_key",
    "secret_value",
    "token_value",
)
_COMPLETION_GATE_REJECTION_STATUSES = frozenset(
    {
        "not_complete",
        "stale",
        "authority_insufficient",
        "already_terminal",
        "delegated_child_active",
        "rejected",
        "error",
    }
)
_DETAILED_TOOL_NAMES = frozenset(
    {
        "read_file",
        "search_files",
        "code_search",
        "code_symbols",
        "write_file",
        "patch",
        "multi_edit",
        "preview_edit_transaction",
        "apply_edit_transaction",
        "terminal_argv",
        "terminal_shell",
        "process",
        "sandbox_exec",
        "sandbox_build",
        "test_run",
        "git",
        "browser",
        "subagent",
    }
)


def classify_tool(name: str) -> str:
    """Map a tool name to a stable, non-content Trace v2 category."""

    lowered = name.casefold()
    if "browser" in lowered:
        return "browser"
    if any(token in lowered for token in ("subagent", "spawn", "delegate")):
        return "subagent"
    if any(token in lowered for token in ("write", "patch", "edit", "delete", "move", "copy")):
        return "edit"
    if any(token in lowered for token in ("test", "verify", "lint", "format", "build", "check")):
        return "verification"
    if any(token in lowered for token in ("recover", "retry", "replan", "cancel")):
        return "recovery"
    if lowered in {"search_files", "file_search_content", "code_search"}:
        return "content_search"
    if lowered in {"list_directory", "tree_view"}:
        return "navigation"
    if lowered in {"file_info", "git_diff", "git_log", "git_status", "git_pr_body"}:
        return "metadata"
    if lowered in {"read_file", "file_read"}:
        return "file_read"
    if any(
        token in lowered
        for token in ("terminal", "process", "sandbox", "git_", "command", "exec")
    ):
        return "execution"
    if "read" in lowered:
        return "file_read"
    return "other"


def _detailed_tool_name(name: str) -> str:
    """Preserve the exact bounded tool name for accounting and replay."""

    if not isinstance(name, str):
        return "unknown"
    lowered = name.strip().casefold()
    if not lowered or len(lowered.encode("utf-8", errors="replace")) > 128:
        return "unknown"
    return lowered


@dataclass(frozen=True, slots=True)
class CodingTraceEvent:
    """A sanitized Trace v2 event with legacy fields kept for compatibility."""

    sequence: int
    kind: str
    name: str
    success: bool | None = None
    duration_ms: int | None = None
    operation_digest: str = ""
    schema_version: int = 2
    run_id: str = ""
    event_id: str = ""
    turn_id: str = "turn:unknown"
    event_sequence: int = 0
    event_type: str = ""
    tool_call_id: str = ""
    tool_name: str = ""
    tool_category: str = ""
    safe_argument_summary: Mapping[str, object] = field(default_factory=dict)
    safe_argument_digest: str = ""
    workspace_relative_scope: str = ""
    tool_success: bool | None = None
    tool_error_class: str | None = None
    result_count: int | None = None
    result_limit: int | None = None
    result_truncated: bool | None = None
    safe_result_digest: str = ""
    tool_state: str = ""
    terminal_reason: str | None = None
    safe_event_metadata: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if type(self.sequence) is not int or self.sequence <= 0:
            raise ValueError("coding trace sequence is invalid")
        if not isinstance(self.kind, str) or not self.kind.strip():
            raise ValueError("coding trace kind is invalid")
        if (
            not isinstance(self.name, str)
            or not self.name.strip()
            or len(self.name.encode("utf-8")) > 512
        ):
            raise ValueError("coding trace name is invalid")
        if self.success is not None and type(self.success) is not bool:
            raise ValueError("coding trace success is invalid")
        if self.duration_ms is not None and (
            type(self.duration_ms) is not int or self.duration_ms < 0
        ):
            raise ValueError("coding trace duration is invalid")
        if not isinstance(self.operation_digest, str) or len(self.operation_digest) > 128:
            raise ValueError("coding trace operation digest is invalid")
        if type(self.schema_version) is not int or self.schema_version != 2:
            raise ValueError("coding trace schema version is invalid")
        for name in ("run_id", "event_id", "turn_id", "event_type", "tool_call_id", "tool_name", "tool_category", "workspace_relative_scope", "tool_state"):
            value = getattr(self, name)
            if not isinstance(value, str) or len(value.encode("utf-8", errors="replace")) > 512:
                raise ValueError(f"coding trace {name} is invalid")
        if type(self.event_sequence) is not int or self.event_sequence < 0:
            raise ValueError("coding trace event_sequence is invalid")
        if not isinstance(self.safe_argument_summary, Mapping):
            raise TypeError("coding trace argument summary is invalid")
        if self.tool_success is not None and type(self.tool_success) is not bool:
            raise ValueError("coding trace tool success is invalid")
        if self.tool_error_class is not None and not isinstance(self.tool_error_class, str):
            raise ValueError("coding trace error class is invalid")
        for name in ("result_count", "result_limit"):
            value = getattr(self, name)
            if value is not None and (type(value) is not int or value < 0):
                raise ValueError(f"coding trace {name} is invalid")
        if self.result_truncated is not None and type(self.result_truncated) is not bool:
            raise ValueError("coding trace result truncation is invalid")
        if self.terminal_reason is not None and not isinstance(self.terminal_reason, str):
            raise ValueError("coding trace terminal reason is invalid")
        object.__setattr__(
            self,
            "safe_event_metadata",
            _safe_observation_mapping(self.safe_event_metadata, "trace event metadata"),
        )
        object.__setattr__(self, "event_sequence", self.event_sequence or self.sequence)
        object.__setattr__(self, "event_type", self.event_type or self.kind)
        object.__setattr__(self, "run_id", self.run_id or "legacy-run")
        object.__setattr__(self, "event_id", self.event_id or f"{self.run_id}:event:{self.sequence}")
        object.__setattr__(self, "tool_name", self.tool_name or (self.name if self.kind.startswith("tool") else ""))
        if self.tool_success is None and self.kind == "tool_result":
            object.__setattr__(self, "tool_success", self.success)
        object.__setattr__(self, "safe_argument_summary", dict(self.safe_argument_summary))

    def to_payload(self) -> dict[str, object]:
        return {
            "sequence": self.sequence,
            "kind": self.kind,
            "name": self.name,
            "success": self.success,
            "duration_ms": self.duration_ms,
            "operation_digest": self.operation_digest,
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "event_id": self.event_id,
            "turn_id": self.turn_id,
            "event_sequence": self.event_sequence,
            "event_type": self.event_type,
            "tool_call_id": self.tool_call_id,
            "tool_name": self.tool_name,
            "tool_category": self.tool_category,
            "safe_argument_summary": dict(self.safe_argument_summary),
            "safe_argument_digest": self.safe_argument_digest,
            "workspace_relative_scope": self.workspace_relative_scope,
            "tool_success": self.tool_success,
            "tool_error_class": self.tool_error_class,
            "result_count": self.result_count,
            "result_limit": self.result_limit,
            "result_truncated": self.result_truncated,
            "safe_result_digest": self.safe_result_digest,
            "tool_state": self.tool_state,
            "terminal_reason": self.terminal_reason,
            "safe_event_metadata": dict(self.safe_event_metadata),
        }


@dataclass(frozen=True, slots=True)
class CodingMetrics:
    """Canonical metrics payload independent of any completion authority."""

    verdict: CodingVerdict
    agent_status: str
    completion_status: str | None
    wall_clock_ms: int
    model_messages: int
    tool_calls: int
    tool_calls_by_category: Mapping[str, int]
    files_viewed: int
    files_modified: int
    tests_run: int
    tests_passed: int
    input_tokens: int | None
    output_tokens: int | None
    trace_event_count: int
    trace_digest: str
    task_success: bool = False
    oracle_pass_count: int = 0
    oracle_fail_count: int = 0
    oracle_total: int = 0
    failed_tool_calls: int = 0
    approval_count: int = 0
    permission_denials: int = 0
    repair_cycles: int = 0
    model_calls: int = 0
    model_turns: int = 0
    cached_tokens: int | None = None
    total_tokens: int | None = None
    provider_requests: int = 0
    provider_usage_status: str = "PROVIDER_NOT_REPORTED"
    tool_calls_by_name: Mapping[str, int] = field(default_factory=dict)
    extension_calls: int = 0
    mcp_calls: int = 0
    mcp_failures: int = 0
    hook_invocations: int = 0
    hook_failures: int = 0
    read_file_calls: int = 0
    search_calls: int = 0
    code_search_calls: int = 0
    symbol_calls: int = 0
    write_calls: int = 0
    patch_calls: int = 0
    terminal_calls: int = 0
    test_calls: int = 0
    git_calls: int = 0
    browser_calls: int = 0
    subagent_calls: int = 0
    editing_calls: int = 0
    verification_calls: int = 0
    recovery_calls: int = 0
    first_edit_turn: int | None = None
    edit_attempts: int = 0
    failed_edit_attempts: int = 0
    reverted_edits: int = 0
    unrelated_changed_files: int = 0
    failed_test_runs: int = 0
    successful_test_runs: int = 0
    verification_commands: int = 0
    final_green: bool | None = None
    time_to_first_tool_ms: int | None = None
    time_to_first_read_ms: int | None = None
    time_to_first_edit_ms: int | None = None
    time_to_first_test_ms: int | None = None
    time_to_first_green_ms: int | None = None
    context_build_count: int | None = None
    context_bundle_count: int | None = None
    context_tokens: int | None = None
    context_bytes: int | None = None
    context_files: int | None = None
    context_symbols: int | None = None
    context_truncated_count: int | None = None
    context_stale_count: int | None = None
    context_cache_hits: int | None = None
    context_cache_misses: int | None = None
    repo_intelligence_queries: int | None = None
    repo_intelligence_cache_hits: int | None = None
    repo_intelligence_cache_misses: int | None = None
    repo_index_full_refreshes: int | None = None
    repo_index_incremental_refreshes: int | None = None
    repo_files_parsed: int | None = None
    repo_files_reparsed: int | None = None
    semantic_queries: int | None = None
    lexical_fallback_queries: int | None = None
    stale_query_count: int | None = None
    context_candidate_count: int | None = None
    context_selected_file_count: int | None = None
    context_selected_symbol_count: int | None = None
    # M8.4 bounded context-engine observations.  ``None`` means the adapter
    # did not expose that measurement; it is never interpreted as zero by an
    # evaluation oracle.
    context_builds: int | None = None
    context_input_tokens: int | None = None
    context_input_bytes: int | None = None
    context_l0_tokens: int | None = None
    context_l1_tokens: int | None = None
    context_l2_tokens: int | None = None
    context_l3_tokens: int | None = None
    context_items_selected: int | None = None
    context_items_evicted: int | None = None
    context_items_compressed: int | None = None
    context_stale_retries: int | None = None
    context_partial_builds: int | None = None
    context_compactions: int | None = None
    context_stable_prefix_tokens: int | None = None
    context_stable_prefix_bytes: int | None = None
    context_memory_items_selected: int | None = None
    context_repo_items_selected: int | None = None
    context_diagnostics_selected: int | None = None
    context_selection_id: str | None = None
    context_selection_sequence: int | None = None
    context_selection_reason: str | None = None
    context_selection_count: int | None = None
    context_initial_selection_id: str | None = None
    context_rebalance_count: int | None = None
    tool_schema_tokens: int | None = None
    tool_schema_bytes: int | None = None
    deferred_tool_discoveries: int | None = None
    deferred_skill_discoveries: int | None = None
    deferred_skill_loads: int | None = None
    skill_tokens: int | None = None
    tool_output_tokens: int | None = None
    tool_output_bytes: int | None = None
    tool_output_truncated_count: int | None = None
    active_skills: int | None = None
    extension_context_bytes: int | None = None
    extension_tool_schema_bytes: int | None = None
    # M8.0 keeps these aggregate names as part of the stable evaluation
    # vocabulary; the context-engine-prefixed fields above remain the
    # collision-free internal projection.
    memory_items_selected: int | None = None
    repo_items_selected: int | None = None
    diagnostics_selected: int | None = None
    compaction_count: int | None = None
    replan_count: int = 0
    recovery_count: int = 0
    no_progress_count: int = 0
    completion_rejections: int = 0
    completion_acceptances: int = 0
    human_intervention_count: int = 0
    approval_intervention_count: int = 0
    manual_message_count: int = 0
    diff_changed_files: int = 0
    diff_insertions: int = 0
    diff_deletions: int = 0
    # M8.3 planner/executor observations.  These counters describe selection
    # effort and bounded outcomes; they never authorize completion.
    autonomous_verification_plan_count: int = 0
    autonomous_verification_check_count: int = 0
    autonomous_verification_executed_check_count: int = 0
    autonomous_verification_structural_count: int = 0
    autonomous_verification_static_count: int = 0
    autonomous_verification_typecheck_count: int = 0
    autonomous_verification_targeted_count: int = 0
    autonomous_verification_module_count: int = 0
    autonomous_verification_integration_count: int = 0
    autonomous_verification_regression_count: int = 0
    autonomous_verification_pass_count: int = 0
    autonomous_verification_failure_count: int = 0
    autonomous_verification_timeout_count: int = 0
    autonomous_verification_stale_count: int = 0
    autonomous_verification_infrastructure_error_count: int = 0
    autonomous_verification_unknown_count: int = 0
    autonomous_verification_diagnostic_count: int = 0
    autonomous_verification_repair_count: int = 0
    autonomous_verification_time_to_final_green_ms: int | None = None
    # Stable M8.3/M8.0 vocabulary.  The autonomous-prefixed fields above keep
    # the source explicit while these names are the public evaluation schema.
    verification_plans: int = 0
    verification_checks_planned: int = 0
    verification_checks_executed: int = 0
    targeted_test_runs: int = 0
    package_test_runs: int = 0
    integration_test_runs: int = 0
    build_runs: int = 0
    lint_runs: int = 0
    typecheck_runs: int = 0
    verification_passes: int = 0
    verification_failures: int = 0
    verification_timeouts: int = 0
    verification_infra_errors: int = 0
    verification_plan_rebuilds: int = 0
    diagnostics_count: int = 0
    time_to_final_green_ms: int | None = None
    verification_required_checks: int = 0
    # Trace v2 / budget observations.  These fields are observations only;
    # execution limits remain owned by ToolBudget and ToolScheduler.
    trace_schema_version: int = 2
    trace_truncated: bool = False
    trace_dropped_event_count: int = 0
    tool_calls_by_exact_name: Mapping[str, int] = field(default_factory=dict)
    pending_tool_calls: int = 0
    tool_call_states: Mapping[str, int] = field(default_factory=dict)
    terminal_reason: str | None = None
    observability_schema_version: int = OBSERVABILITY_SCHEMA_VERSION
    observability: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.verdict, CodingVerdict):
            raise TypeError("coding metric verdict is invalid")
        if not isinstance(self.agent_status, str) or not self.agent_status.strip():
            raise ValueError("coding metric agent status is invalid")
        if self.completion_status is not None and not isinstance(self.completion_status, str):
            raise ValueError("coding metric completion status is invalid")
        if type(self.wall_clock_ms) is not int or self.wall_clock_ms < 0:
            raise ValueError("coding wall clock metric is invalid")
        count_fields = (
            "model_messages",
            "tool_calls",
            "files_viewed",
            "files_modified",
            "tests_run",
            "tests_passed",
            "trace_event_count",
            "oracle_pass_count",
            "oracle_fail_count",
            "oracle_total",
            "failed_tool_calls",
            "approval_count",
            "permission_denials",
            "repair_cycles",
            "model_calls",
            "model_turns",
            "provider_requests",
            "read_file_calls",
            "search_calls",
            "code_search_calls",
            "symbol_calls",
            "write_calls",
            "patch_calls",
            "terminal_calls",
            "test_calls",
            "git_calls",
            "browser_calls",
            "subagent_calls",
            "extension_calls",
            "mcp_calls",
            "mcp_failures",
            "hook_invocations",
            "hook_failures",
            "editing_calls",
            "verification_calls",
            "recovery_calls",
            "edit_attempts",
            "failed_edit_attempts",
            "reverted_edits",
            "unrelated_changed_files",
            "failed_test_runs",
            "successful_test_runs",
            "verification_commands",
            "replan_count",
            "recovery_count",
            "no_progress_count",
            "completion_rejections",
            "completion_acceptances",
            "human_intervention_count",
            "approval_intervention_count",
            "manual_message_count",
            "diff_changed_files",
            "diff_insertions",
            "diff_deletions",
            "autonomous_verification_plan_count",
            "autonomous_verification_check_count",
            "autonomous_verification_executed_check_count",
            "autonomous_verification_structural_count",
            "autonomous_verification_static_count",
            "autonomous_verification_typecheck_count",
            "autonomous_verification_targeted_count",
            "autonomous_verification_module_count",
            "autonomous_verification_integration_count",
            "autonomous_verification_regression_count",
            "autonomous_verification_pass_count",
            "autonomous_verification_failure_count",
            "autonomous_verification_timeout_count",
            "autonomous_verification_stale_count",
            "autonomous_verification_infrastructure_error_count",
            "autonomous_verification_unknown_count",
            "autonomous_verification_diagnostic_count",
            "autonomous_verification_repair_count",
            "verification_plans",
            "verification_checks_planned",
            "verification_checks_executed",
            "targeted_test_runs",
            "package_test_runs",
            "integration_test_runs",
            "build_runs",
            "lint_runs",
            "typecheck_runs",
            "verification_passes",
            "verification_failures",
            "verification_timeouts",
            "verification_infra_errors",
            "verification_plan_rebuilds",
            "diagnostics_count",
            "verification_required_checks",
            "trace_dropped_event_count",
            "pending_tool_calls",
        )
        if any(
            type(getattr(self, name)) is not int or getattr(self, name) < 0
            for name in count_fields
        ):
            raise ValueError("coding metrics contain a negative or malformed count")
        if not isinstance(self.tool_calls_by_category, Mapping):
            raise TypeError("coding tool category metrics are invalid")
        if not isinstance(self.tool_calls_by_name, Mapping):
            raise TypeError("coding tool name metrics are invalid")
        if not isinstance(self.tool_calls_by_exact_name, Mapping):
            raise TypeError("coding exact tool name metrics are invalid")
        if not isinstance(self.tool_call_states, Mapping):
            raise TypeError("coding tool call state metrics are invalid")
        unknown = set(self.tool_calls_by_category) - TOOL_CATEGORIES
        if unknown or any(type(value) is not int or value < 0 for value in self.tool_calls_by_category.values()):
            raise ValueError("coding tool category metrics are invalid")
        if any(
            not isinstance(name, str) or not name or type(value) is not int or value < 0
            for name, value in self.tool_calls_by_name.items()
        ):
            raise ValueError("coding tool name metrics are invalid")
        if any(
            not isinstance(name, str) or not name or type(value) is not int or value < 0
            for name, value in self.tool_calls_by_exact_name.items()
        ):
            raise ValueError("coding exact tool name metrics are invalid")
        if any(
            not isinstance(name, str) or not name or type(value) is not int or value < 0
            for name, value in self.tool_call_states.items()
        ):
            raise ValueError("coding tool call state metrics are invalid")
        object.__setattr__(self, "tool_calls_by_category", dict(self.tool_calls_by_category))
        object.__setattr__(self, "tool_calls_by_name", dict(self.tool_calls_by_name))
        object.__setattr__(
            self,
            "tool_calls_by_exact_name",
            dict(self.tool_calls_by_exact_name or self.tool_calls_by_name),
        )
        object.__setattr__(self, "tool_call_states", dict(self.tool_call_states))
        if type(self.trace_schema_version) is not int or self.trace_schema_version != 2:
            raise ValueError("coding trace schema version metric is invalid")
        if type(self.trace_truncated) is not bool:
            raise ValueError("coding trace truncation metric is invalid")
        if self.terminal_reason is not None and not isinstance(self.terminal_reason, str):
            raise ValueError("coding terminal reason metric is invalid")
        if type(self.observability_schema_version) is not int or (
            self.observability_schema_version != OBSERVABILITY_SCHEMA_VERSION
        ):
            raise ValueError("coding observability schema version is invalid")
        object.__setattr__(
            self,
            "observability",
            _safe_observation_mapping(self.observability, "coding observability"),
        )
        if type(self.task_success) is not bool:
            raise ValueError("coding task_success metric is invalid")
        if self.oracle_pass_count + self.oracle_fail_count != self.oracle_total:
            raise ValueError("oracle pass/fail counts do not add up to total")
        if self.tests_passed > self.tests_run or self.successful_test_runs > self.tests_run:
            raise ValueError("passed tests cannot exceed tests run")
        if self.failed_test_runs + self.successful_test_runs > self.tests_run:
            raise ValueError("test outcome counts exceed tests run")
        if self.input_tokens is not None and (type(self.input_tokens) is not int or self.input_tokens < 0):
            raise ValueError("input token metric is invalid")
        if self.output_tokens is not None and (type(self.output_tokens) is not int or self.output_tokens < 0):
            raise ValueError("output token metric is invalid")
        if not isinstance(self.provider_usage_status, str) or not self.provider_usage_status.strip():
            raise ValueError("provider usage status metric is invalid")
        for name in (
            "cached_tokens",
            "total_tokens",
            "time_to_first_tool_ms",
            "time_to_first_read_ms",
            "time_to_first_edit_ms",
            "time_to_first_test_ms",
            "time_to_first_green_ms",
            "context_build_count",
            "context_bundle_count",
            "context_tokens",
            "context_bytes",
            "context_files",
            "context_symbols",
            "context_truncated_count",
            "context_stale_count",
            "context_cache_hits",
            "context_cache_misses",
            "repo_intelligence_queries",
            "repo_intelligence_cache_hits",
            "repo_intelligence_cache_misses",
            "repo_index_full_refreshes",
            "repo_index_incremental_refreshes",
            "repo_files_parsed",
            "repo_files_reparsed",
            "semantic_queries",
            "lexical_fallback_queries",
            "stale_query_count",
            "context_candidate_count",
            "context_selected_file_count",
            "context_selected_symbol_count",
            "context_builds",
            "context_input_tokens",
            "context_input_bytes",
            "context_l0_tokens",
            "context_l1_tokens",
            "context_l2_tokens",
            "context_l3_tokens",
            "context_items_selected",
            "context_items_evicted",
            "context_items_compressed",
            "context_stale_retries",
            "context_partial_builds",
            "context_compactions",
            "context_stable_prefix_tokens",
            "context_stable_prefix_bytes",
            "context_memory_items_selected",
            "context_repo_items_selected",
            "context_diagnostics_selected",
            "context_selection_sequence",
            "context_selection_count",
            "context_rebalance_count",
            "tool_schema_tokens",
            "tool_schema_bytes",
            "deferred_tool_discoveries",
            "deferred_skill_discoveries",
            "deferred_skill_loads",
            "skill_tokens",
            "tool_output_tokens",
            "tool_output_bytes",
            "tool_output_truncated_count",
            "active_skills",
            "extension_context_bytes",
            "extension_tool_schema_bytes",
            "memory_items_selected",
            "repo_items_selected",
            "diagnostics_selected",
            "compaction_count",
            "autonomous_verification_time_to_final_green_ms",
            "time_to_final_green_ms",
        ):
            value = getattr(self, name)
            if value is not None and (type(value) is not int or value < 0):
                raise ValueError(f"coding metric {name} is invalid")
        for name in (
            "context_selection_id",
            "context_selection_reason",
            "context_initial_selection_id",
        ):
            value = getattr(self, name)
            if value is not None and (
                not isinstance(value, str)
                or not value
                or len(value.encode("utf-8", errors="replace")) > 512
            ):
                raise ValueError(f"coding metric {name} is invalid")
        if self.final_green is not None and type(self.final_green) is not bool:
            raise ValueError("coding metric final_green is invalid")
        if self.model_calls == 0 and self.model_messages:
            object.__setattr__(self, "model_calls", self.model_messages)
        if self.model_turns == 0 and self.model_messages:
            object.__setattr__(self, "model_turns", self.model_messages)
        if self.total_tokens is None and self.input_tokens is not None and self.output_tokens is not None:
            object.__setattr__(self, "total_tokens", self.input_tokens + self.output_tokens)

    def to_payload(self) -> dict[str, object]:
        return {
            "verdict": self.verdict.value,
            "agent_status": self.agent_status,
            "completion_status": self.completion_status,
            "wall_clock_ms": self.wall_clock_ms,
            "model_messages": self.model_messages,
            "tool_calls": self.tool_calls,
            "tool_calls_by_category": dict(sorted(self.tool_calls_by_category.items())),
            "files_viewed": self.files_viewed,
            "files_modified": self.files_modified,
            "tests_run": self.tests_run,
            "tests_passed": self.tests_passed,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "trace_event_count": self.trace_event_count,
            "trace_digest": self.trace_digest,
            "task_success": self.task_success,
            "oracle_pass_count": self.oracle_pass_count,
            "oracle_fail_count": self.oracle_fail_count,
            "oracle_total": self.oracle_total,
            "failed_tool_calls": self.failed_tool_calls,
            "approval_count": self.approval_count,
            "permission_denials": self.permission_denials,
            "repair_cycles": self.repair_cycles,
            "model_calls": self.model_calls,
            "model_turns": self.model_turns,
            "cached_tokens": self.cached_tokens,
            "total_tokens": self.total_tokens,
            "provider_requests": self.provider_requests,
            "provider_usage_status": self.provider_usage_status,
            "tool_calls_by_name": dict(sorted(self.tool_calls_by_name.items())),
            "extension_calls": self.extension_calls,
            "mcp_calls": self.mcp_calls,
            "mcp_failures": self.mcp_failures,
            "hook_invocations": self.hook_invocations,
            "hook_failures": self.hook_failures,
            "read_file_calls": self.read_file_calls,
            "search_calls": self.search_calls,
            "code_search_calls": self.code_search_calls,
            "symbol_calls": self.symbol_calls,
            "write_calls": self.write_calls,
            "patch_calls": self.patch_calls,
            "terminal_calls": self.terminal_calls,
            "test_calls": self.test_calls,
            "git_calls": self.git_calls,
            "browser_calls": self.browser_calls,
            "subagent_calls": self.subagent_calls,
            "editing_calls": self.editing_calls,
            "verification_calls": self.verification_calls,
            "recovery_calls": self.recovery_calls,
            "first_edit_turn": self.first_edit_turn,
            "edit_attempts": self.edit_attempts,
            "failed_edit_attempts": self.failed_edit_attempts,
            "reverted_edits": self.reverted_edits,
            "unrelated_changed_files": self.unrelated_changed_files,
            "failed_test_runs": self.failed_test_runs,
            "successful_test_runs": self.successful_test_runs,
            "verification_commands": self.verification_commands,
            "final_green": self.final_green,
            "time_to_first_tool_ms": self.time_to_first_tool_ms,
            "time_to_first_read_ms": self.time_to_first_read_ms,
            "time_to_first_edit_ms": self.time_to_first_edit_ms,
            "time_to_first_test_ms": self.time_to_first_test_ms,
            "time_to_first_green_ms": self.time_to_first_green_ms,
            "context_build_count": self.context_build_count,
            "context_bundle_count": self.context_bundle_count,
            "context_tokens": self.context_tokens,
            "context_bytes": self.context_bytes,
            "context_files": self.context_files,
            "context_symbols": self.context_symbols,
            "context_truncated_count": self.context_truncated_count,
            "context_stale_count": self.context_stale_count,
            "context_cache_hits": self.context_cache_hits,
            "context_cache_misses": self.context_cache_misses,
            "repo_intelligence_queries": self.repo_intelligence_queries,
            "repo_intelligence_cache_hits": self.repo_intelligence_cache_hits,
            "repo_intelligence_cache_misses": self.repo_intelligence_cache_misses,
            "repo_index_full_refreshes": self.repo_index_full_refreshes,
            "repo_index_incremental_refreshes": self.repo_index_incremental_refreshes,
            "repo_files_parsed": self.repo_files_parsed,
            "repo_files_reparsed": self.repo_files_reparsed,
            "semantic_queries": self.semantic_queries,
            "lexical_fallback_queries": self.lexical_fallback_queries,
            "stale_query_count": self.stale_query_count,
            "context_candidate_count": self.context_candidate_count,
            "context_selected_file_count": self.context_selected_file_count,
            "context_selected_symbol_count": self.context_selected_symbol_count,
            "context_builds": self.context_builds,
            "context_input_tokens": self.context_input_tokens,
            "context_input_bytes": self.context_input_bytes,
            "context_l0_tokens": self.context_l0_tokens,
            "context_l1_tokens": self.context_l1_tokens,
            "context_l2_tokens": self.context_l2_tokens,
            "context_l3_tokens": self.context_l3_tokens,
            "context_items_selected": self.context_items_selected,
            "context_items_evicted": self.context_items_evicted,
            "context_items_compressed": self.context_items_compressed,
            "context_stale_retries": self.context_stale_retries,
            "context_partial_builds": self.context_partial_builds,
            "context_compactions": self.context_compactions,
            "context_stable_prefix_tokens": self.context_stable_prefix_tokens,
            "context_stable_prefix_bytes": self.context_stable_prefix_bytes,
            "context_memory_items_selected": self.context_memory_items_selected,
            "context_repo_items_selected": self.context_repo_items_selected,
            "context_diagnostics_selected": self.context_diagnostics_selected,
            "context_selection_id": self.context_selection_id,
            "context_selection_sequence": self.context_selection_sequence,
            "context_selection_reason": self.context_selection_reason,
            "context_selection_count": self.context_selection_count,
            "context_initial_selection_id": self.context_initial_selection_id,
            "context_rebalance_count": self.context_rebalance_count,
            "tool_schema_tokens": self.tool_schema_tokens,
            "tool_schema_bytes": self.tool_schema_bytes,
            "deferred_tool_discoveries": self.deferred_tool_discoveries,
            "deferred_skill_discoveries": self.deferred_skill_discoveries,
            "deferred_skill_loads": self.deferred_skill_loads,
            "skill_tokens": self.skill_tokens,
            "tool_output_tokens": self.tool_output_tokens,
            "tool_output_bytes": self.tool_output_bytes,
            "tool_output_truncated_count": self.tool_output_truncated_count,
            "active_skills": self.active_skills,
            "extension_context_bytes": self.extension_context_bytes,
            "extension_tool_schema_bytes": self.extension_tool_schema_bytes,
            "memory_items_selected": self.memory_items_selected,
            "repo_items_selected": self.repo_items_selected,
            "diagnostics_selected": self.diagnostics_selected,
            "compaction_count": self.compaction_count,
            "replan_count": self.replan_count,
            "recovery_count": self.recovery_count,
            "no_progress_count": self.no_progress_count,
            "completion_rejections": self.completion_rejections,
            "completion_acceptances": self.completion_acceptances,
            "human_intervention_count": self.human_intervention_count,
            "approval_intervention_count": self.approval_intervention_count,
            "manual_message_count": self.manual_message_count,
            "diff_changed_files": self.diff_changed_files,
            "diff_insertions": self.diff_insertions,
            "diff_deletions": self.diff_deletions,
            "autonomous_verification_plan_count": self.autonomous_verification_plan_count,
            "autonomous_verification_check_count": self.autonomous_verification_check_count,
            "autonomous_verification_executed_check_count": self.autonomous_verification_executed_check_count,
            "autonomous_verification_structural_count": self.autonomous_verification_structural_count,
            "autonomous_verification_static_count": self.autonomous_verification_static_count,
            "autonomous_verification_typecheck_count": self.autonomous_verification_typecheck_count,
            "autonomous_verification_targeted_count": self.autonomous_verification_targeted_count,
            "autonomous_verification_module_count": self.autonomous_verification_module_count,
            "autonomous_verification_integration_count": self.autonomous_verification_integration_count,
            "autonomous_verification_regression_count": self.autonomous_verification_regression_count,
            "autonomous_verification_pass_count": self.autonomous_verification_pass_count,
            "autonomous_verification_failure_count": self.autonomous_verification_failure_count,
            "autonomous_verification_timeout_count": self.autonomous_verification_timeout_count,
            "autonomous_verification_stale_count": self.autonomous_verification_stale_count,
            "autonomous_verification_infrastructure_error_count": self.autonomous_verification_infrastructure_error_count,
            "autonomous_verification_unknown_count": self.autonomous_verification_unknown_count,
            "autonomous_verification_diagnostic_count": self.autonomous_verification_diagnostic_count,
            "autonomous_verification_repair_count": self.autonomous_verification_repair_count,
            "autonomous_verification_time_to_final_green_ms": self.autonomous_verification_time_to_final_green_ms,
            "verification_plans": self.verification_plans,
            "verification_checks_planned": self.verification_checks_planned,
            "verification_checks_executed": self.verification_checks_executed,
            "targeted_test_runs": self.targeted_test_runs,
            "package_test_runs": self.package_test_runs,
            "integration_test_runs": self.integration_test_runs,
            "build_runs": self.build_runs,
            "lint_runs": self.lint_runs,
            "typecheck_runs": self.typecheck_runs,
            "verification_passes": self.verification_passes,
            "verification_failures": self.verification_failures,
            "verification_timeouts": self.verification_timeouts,
            "verification_infra_errors": self.verification_infra_errors,
            "verification_plan_rebuilds": self.verification_plan_rebuilds,
            "diagnostics_count": self.diagnostics_count,
            "time_to_final_green_ms": self.time_to_final_green_ms,
            "verification_required_checks": self.verification_required_checks,
            "trace_schema_version": self.trace_schema_version,
            "trace_truncated": self.trace_truncated,
            "trace_dropped_event_count": self.trace_dropped_event_count,
            "tool_calls_by_exact_name": dict(sorted(self.tool_calls_by_exact_name.items())),
            "pending_tool_calls": self.pending_tool_calls,
            "tool_call_states": dict(sorted(self.tool_call_states.items())),
            "terminal_reason": self.terminal_reason,
            "observability_schema_version": self.observability_schema_version,
            "observability": dict(self.observability),
        }


class CodingTraceCollector:
    """Collect bounded operation metadata from the real AgentLoop stream."""

    def __init__(
        self,
        *,
        max_events: int = 2048,
        max_model_turns: int = 128,
        max_tool_calls: int = 512,
        run_id: str | None = None,
        secret_redactor: SecretRedactor | None = None,
    ) -> None:
        if type(max_events) is not int or max_events <= 0:
            raise ValueError("coding trace max_events is invalid")
        if type(max_model_turns) is not int or max_model_turns <= 0:
            raise ValueError("coding trace max_model_turns is invalid")
        if type(max_tool_calls) is not int or max_tool_calls <= 0:
            raise ValueError("coding trace max_tool_calls is invalid")
        self.max_events = max_events
        self.max_model_turns = max_model_turns
        self.max_tool_calls = max_tool_calls
        self.run_id = run_id or "coding-run-unbound"
        if not isinstance(self.run_id, str) or not self.run_id.strip():
            raise ValueError("coding trace run_id is invalid")
        self._secret_redactor = secret_redactor
        self._events: list[CodingTraceEvent] = []
        self._event_sequence = 0
        self._trace_truncated = False
        self._dropped_event_count = 0
        self._terminal_reason: str | None = None
        self._model_calls = 0
        self._model_turns = 0
        self._provider_requests = 0
        self._provider_usage_status = "PROVIDER_NOT_REPORTED"
        self._seen_model_response_ids: set[str] = set()
        self._tool_calls = 0
        self._seen_tool_call_ids: set[str] = set()
        self._pending_tool_calls: dict[str, dict[str, object]] = {}
        self._tool_call_states: Counter[str] = Counter()
        self._tool_categories: Counter[str] = Counter()
        self._tool_names: Counter[str] = Counter()
        self._files_viewed = 0
        self._files_modified = 0
        self._tests_run = 0
        self._tests_passed = 0
        self._failed_test_runs = 0
        self._successful_test_runs = 0
        self._failed_tool_calls = 0
        self._approval_count = 0
        self._edit_attempts = 0
        self._failed_edit_attempts = 0
        self._first_edit_turn: int | None = None
        self._first_tool_ms: int | None = None
        self._first_read_ms: int | None = None
        self._first_edit_ms: int | None = None
        self._first_test_ms: int | None = None
        self._first_green_ms: int | None = None
        self._replan_count = 0
        self._recovery_count = 0
        self._no_progress_count = 0
        self._completion_rejections = 0
        self._completion_acceptances = 0
        self._permission_denials = 0
        self._autonomous_verification_plan_count = 0
        self._autonomous_verification_check_count = 0
        self._autonomous_verification_executed_check_count = 0
        self._autonomous_verification_stage_counts: Counter[str] = Counter()
        self._autonomous_verification_kind_counts: Counter[str] = Counter()
        self._autonomous_verification_required_checks = 0
        self._autonomous_verification_pass_count = 0
        self._autonomous_verification_failure_count = 0
        self._autonomous_verification_timeout_count = 0
        self._autonomous_verification_stale_count = 0
        self._autonomous_verification_infrastructure_error_count = 0
        self._autonomous_verification_unknown_count = 0
        self._autonomous_verification_diagnostic_count = 0
        self._autonomous_verification_repair_count = 0
        self._autonomous_verification_time_to_final_green_ms: int | None = None
        self._repo_metrics: dict[str, int] | None = None
        self._context_metrics: dict[str, int | None] = {}
        self._extension_metrics: dict[str, int] = {}
        self._observability: dict[str, object] = _default_observability()
        self._started = time.monotonic()

    @property
    def events(self) -> tuple[CodingTraceEvent, ...]:
        return tuple(self._events)

    def set_secret_redactor(self, redactor: SecretRedactor | None) -> None:
        """Attach the runtime-owned redactor used at the trace boundary."""

        if redactor is not None and not isinstance(redactor, SecretRedactor):
            raise TypeError("coding trace secret redactor is invalid")
        self._secret_redactor = redactor

    @property
    def trace_truncated(self) -> bool:
        """Whether the bounded observer dropped one or more events."""

        return self._trace_truncated

    @property
    def dropped_event_count(self) -> int:
        """Return the number of events omitted by the storage bound."""

        return self._dropped_event_count

    def record_message(self, message: object) -> None:
        """Observe an AgentLoop message without retaining model-controlled text."""

        role = str(getattr(message, "role", "message") or "message")
        event = str(getattr(message, "event", "") or "")
        raw_metadata = getattr(message, "metadata", {}) or {}
        metadata = raw_metadata if isinstance(raw_metadata, Mapping) else {}
        turn_id = _bounded_identifier(metadata.get("turn_id"), "turn:unknown")

        # Tool-only model responses are exposed as streamed ``tool_call``
        # projections.  Their server-owned response identity lets us dedupe
        # chunks without confusing observability with execution authority.
        if role == "assistant":
            self._record_model_turn(
                metadata,
                require_identity=event == "tool_call",
                final=str(getattr(message, "stop_reason", "") or "") in {"end_turn", "stop"},
            )

        calls = getattr(message, "tool_calls", ()) or ()
        for call in calls:
            function = call.get("function") if isinstance(call, dict) else None
            function_name = function.get("name") if isinstance(function, dict) else None
            name = (
                str(call.get("name") or function_name or "unknown")
                if isinstance(call, dict)
                else "unknown"
            )
            call_id = ""
            arguments: object = {}
            if isinstance(call, dict):
                call_id = str(call.get("id") or call.get("tool_call_id") or "")
                arguments = call.get("arguments")
                if arguments is None and isinstance(function, dict):
                    arguments = function.get("arguments", {})
            if not call_id:
                unbound_digest = canonical_digest(
                    {"name": name, "args": _safe_digest(arguments), "n": self._event_sequence}
                )
                call_id = f"unbound:{unbound_digest[:24]}"
            if call_id in self._seen_tool_call_ids:
                continue
            self._seen_tool_call_ids.add(call_id)
            category = classify_tool(name)
            exact_name = _detailed_tool_name(name)
            self._tool_calls += 1
            self._tool_categories[category] += 1
            self._tool_names[exact_name] += 1
            self._pending_tool_calls[call_id] = {
                "name": exact_name,
                "category": category,
                "arguments": arguments,
                "turn_id": turn_id,
            }
            self._mark_first("tool")
            self._record(
                "tool_call",
                exact_name,
                operation_digest=canonical_digest({"name": exact_name, "call_id": call_id}),
                event_type="tool_call",
                turn_id=turn_id,
                tool_call_id=call_id,
                tool_category=category,
                arguments=arguments,
                tool_state="PENDING",
            )

        if role == "tool":
            raw_call_id = getattr(message, "tool_call_id", None) or metadata.get("id")
            call_id = str(raw_call_id or "")
            pending = self._pending_tool_calls.get(call_id) if call_id else None
            if pending is None and not call_id:
                candidate_names = {
                    _detailed_tool_name(str(item.get("name", "")))
                    for item in self._pending_tool_calls.values()
                }
                candidate_name = _detailed_tool_name(str(metadata.get("name", "tool")))
                matches = [
                    item_id
                    for item_id, item in self._pending_tool_calls.items()
                    if item_id and item.get("name") == candidate_name
                ]
                if len(matches) == 1:
                    call_id = matches[0]
                    pending = self._pending_tool_calls.get(call_id)
                elif candidate_name not in candidate_names:
                    unbound_digest = canonical_digest(
                        {"name": candidate_name, "n": self._event_sequence}
                    )
                    call_id = f"unbound-result:{unbound_digest[:24]}"
            name = _detailed_tool_name(str(metadata.get("name") or (pending or {}).get("name") or "tool"))
            success = metadata.get("success") if isinstance(metadata.get("success"), bool) else None
            duration = metadata.get("duration_ms")
            category = str((pending or {}).get("category") or classify_tool(name))
            arguments = metadata.get("arguments", (pending or {}).get("arguments", {}))
            error_code = _bounded_error_class(metadata.get("error_code"))
            error_text = str(metadata.get("error") or "").casefold()
            matched_pending = pending is not None
            tool_state = (
                "SUCCESS"
                if success is True and matched_pending
                else "FAILURE"
                if matched_pending
                else "MISSING_RESULT"
            )
            self._record(
                "tool_result",
                name,
                success=success,
                duration_ms=duration if type(duration) is int and duration >= 0 else None,
                event_type="tool_result",
                turn_id=_bounded_identifier((pending or {}).get("turn_id"), turn_id),
                tool_call_id=call_id,
                tool_category=category,
                arguments=arguments,
                result_metadata=metadata,
                tool_state=tool_state,
            )
            self._tool_call_states[tool_state] += 1
            if pending is not None:
                self._pending_tool_calls.pop(call_id, None)
            if tool_state != "SUCCESS":
                self._failed_tool_calls += 1
            if any(token in (error_code or "").casefold() for token in ("permission", "denied", "forbidden")) or "permission" in error_text or "denied" in error_text:
                self._permission_denials += 1
            # Legacy result counters describe observed tool outcomes and are
            # intentionally independent from call/result binding.  A
            # MISSING_RESULT state remains explicit in Trace v2 while older
            # test/verification aggregates continue to report the observed
            # outcome for backward-compatible summaries.
            self._record_tool_result_metrics(name, category, success, metadata)
        elif event and not (role == "assistant" and event == "tool_call"):
            self._record_agent_event(event, metadata)
            self._record_autonomous_verification_event(event, metadata)
            event_type = _event_type_for_message(event)
            event_metadata = self._event_observation(event, metadata)
            self._record(
                "agent_event",
                event,
                event_type=event_type,
                turn_id=turn_id,
                result_metadata=metadata,
                event_metadata=event_metadata,
            )
            if event in {"done", "error"}:
                reason = metadata.get("terminal_status") or metadata.get("code") or event
                self.record_terminal(_bounded_identifier(reason, event))

    def _record_model_turn(
        self,
        metadata: Mapping[str, object],
        *,
        require_identity: bool = False,
        final: bool = False,
    ) -> None:
        """Count one bounded model response without retaining its content."""

        turn_id = str(metadata.get("turn_id") or "")
        attempt_id = str(metadata.get("attempt_id") or "")
        response_id = str(metadata.get("model_response_id") or "")
        if not response_id:
            response_id = f"{turn_id}:{attempt_id}" if turn_id or attempt_id else ""
        if require_identity and not response_id:
            return
        if response_id and response_id in self._seen_model_response_ids:
            return
        if response_id:
            self._seen_model_response_ids.add(response_id)
        self._model_calls += 1
        self._model_turns += 1
        self._record(
            "model_response",
            "model_final_response" if final else "model_response",
            event_type="model_final_response" if final else "model_response",
            turn_id=_bounded_identifier(turn_id, "turn:unknown"),
            tool_state="",
            safe_result_digest=_safe_digest(response_id or self._model_calls),
        )
        if final:
            completion = self._observability_section("completion")
            completion["model_finalized"] = True
            self._observability["completion"] = completion

    def record_repository_metrics(self, metrics: object) -> None:
        """Attach a bounded repository-intelligence metrics snapshot.

        Only numeric counters are retained; source text, paths, and query
        payloads never enter the evaluation ledger.
        """
        fields = {
            "repo_intelligence_queries": "query_count",
            "repo_intelligence_cache_hits": "cache_hit_count",
            "repo_intelligence_cache_misses": "cache_miss_count",
            "repo_index_full_refreshes": "full_index_count",
            "repo_index_incremental_refreshes": "incremental_refresh_count",
            "repo_files_parsed": "parsed_file_count",
            "repo_files_reparsed": "reparsed_file_count",
            "semantic_queries": "semantic_query_count",
            "lexical_fallback_queries": "lexical_fallback_count",
            "stale_query_count": "stale_query_count",
            "context_candidate_count": "context_candidate_file_count",
            "context_selected_file_count": "context_selected_file_count",
            "context_selected_symbol_count": "context_selected_symbol_count",
        }
        observed: dict[str, int] = {}
        for destination, source in fields.items():
            value = getattr(metrics, source, None)
            if type(value) is not int or value < 0:
                return
            observed[destination] = value
        self._repo_metrics = observed

    def record_context_metrics(self, metrics: object) -> None:
        """Attach bounded M8.4 context-engine metrics.

        The collector accepts either the typed snapshot or a mapping so test
        adapters can remain small.  Only the closed public metric vocabulary
        is copied; content, paths, and prompt text never enter the trace.
        """

        names = (
            "context_builds",
            "context_input_tokens",
            "context_input_bytes",
            "context_l0_tokens",
            "context_l1_tokens",
            "context_l2_tokens",
            "context_l3_tokens",
            "context_items_selected",
            "context_items_evicted",
            "context_items_compressed",
            "context_truncated_count",
            "context_stale_retries",
            "context_partial_builds",
            "context_compactions",
            "context_cache_hits",
            "context_cache_misses",
            "context_stable_prefix_tokens",
            "context_stable_prefix_bytes",
            "context_selected_file_count",
            "context_selected_symbol_count",
            "context_memory_items_selected",
            "context_repo_items_selected",
            "context_diagnostics_selected",
            "tool_schema_tokens",
            "tool_schema_bytes",
            "deferred_tool_discoveries",
            "deferred_skill_discoveries",
            "deferred_skill_loads",
            "skill_tokens",
            "tool_output_tokens",
            "tool_output_bytes",
            "tool_output_truncated_count",
            "active_skills",
            "extension_context_bytes",
            "extension_tool_schema_bytes",
            "memory_items_selected",
            "repo_items_selected",
            "diagnostics_selected",
            "compaction_count",
        )
        observed: dict[str, int | None] = {}
        for name in names:
            value = metrics.get(name) if isinstance(metrics, Mapping) else getattr(metrics, name, None)
            if value is None:
                observed[name] = None
            elif type(value) is int and value >= 0:
                observed[name] = value
            else:
                return
        self._context_metrics = observed
        selection_digest = _bounded_digest(
            metrics.get("context_selection_digest")
            if isinstance(metrics, Mapping)
            else getattr(metrics, "context_selection_digest", None)
        )
        if selection_digest is not None:
            context_observation = self._observability_section("context")
            selection_id = _selection_id(
                metrics.get("context_selection_id")
                if isinstance(metrics, Mapping)
                else getattr(metrics, "context_selection_id", None)
            )
            selection_sequence = _selection_sequence(
                metrics.get("context_selection_sequence")
                if isinstance(metrics, Mapping)
                else getattr(metrics, "context_selection_sequence", None)
            )
            selection_reason = _selection_reason(
                metrics.get("context_selection_reason")
                if isinstance(metrics, Mapping)
                else getattr(metrics, "context_selection_reason", None)
            )
            selection_count = _optional_nonnegative(
                metrics.get("context_selection_count")
                if isinstance(metrics, Mapping)
                else getattr(metrics, "context_selection_count", None)
            )
            initial_selection_id = _selection_id(
                metrics.get("context_initial_selection_id")
                if isinstance(metrics, Mapping)
                else getattr(metrics, "context_initial_selection_id", None)
            )
            rebalance_count = _optional_nonnegative(
                metrics.get("context_rebalance_count")
                if isinstance(metrics, Mapping)
                else getattr(metrics, "context_rebalance_count", None)
            )
            safe_history = _selection_history(
                metrics.get("context_selection_history")
                if isinstance(metrics, Mapping)
                else getattr(metrics, "context_selection_history", None)
            )
            context_observation.update(
                {
                    "final_context_selection_id": selection_id,
                    "final_context_selection_sequence": selection_sequence,
                    "final_context_selection_reason": selection_reason,
                    "final_context_selection_digest": selection_digest,
                    "context_selection_count": selection_count,
                    "context_initial_selection_id": initial_selection_id,
                    "context_rebalance_count": rebalance_count,
                    "selection_identity_status": (
                        "AVAILABLE"
                        if selection_id is not None
                        else "LEGACY_NO_SELECTION_ID"
                    ),
                    "selection_id": selection_id,
                    "selection_sequence": selection_sequence,
                    "selection_reason": selection_reason,
                    "selection_identity_digest": _selection_identity_digest(
                        selection_id,
                        selection_sequence,
                        selection_reason,
                        selection_digest,
                    ),
                }
            )
            if safe_history is not None:
                context_observation["selection_history"] = safe_history
            context_observation.update(
                {
                    "observed": True,
                    "selection_digest": selection_digest,
                    "selected_repository_paths": _safe_path_list(
                        metrics.get("context_selected_repository_paths")
                        if isinstance(metrics, Mapping)
                        else getattr(metrics, "context_selected_repository_paths", ())
                    ),
                    "automatic_repo_items_selected": _optional_nonnegative(
                        metrics.get("context_automatic_repo_items_selected")
                        if isinstance(metrics, Mapping)
                        else getattr(metrics, "context_automatic_repo_items_selected", None)
                    ),
                    "tool_acquired_items_selected": _optional_nonnegative(
                        metrics.get("context_tool_acquired_items_selected")
                        if isinstance(metrics, Mapping)
                        else getattr(metrics, "context_tool_acquired_items_selected", None)
                    ),
                    "non_repository_items_selected": _optional_nonnegative(
                        metrics.get("context_non_repository_items_selected")
                        if isinstance(metrics, Mapping)
                        else getattr(metrics, "context_non_repository_items_selected", None)
                    ),
                }
            )
            selection_metadata = (
                metrics.get("context_selection_metadata")
                if isinstance(metrics, Mapping)
                else getattr(metrics, "context_selection_metadata", None)
            )
            selection_schema_version = (
                metrics.get("context_selection_observability_schema_version")
                if isinstance(metrics, Mapping)
                else getattr(metrics, "context_selection_observability_schema_version", None)
            )
            selection_detail_status = (
                metrics.get("context_selection_detail_status")
                if isinstance(metrics, Mapping)
                else getattr(metrics, "context_selection_detail_status", None)
            )
            if isinstance(selection_metadata, (list, tuple)):
                projection_truncated = (
                    metrics.get("context_selection_projection_truncated")
                    if isinstance(metrics, Mapping)
                    else getattr(
                        metrics,
                        "context_selection_projection_truncated",
                        None,
                    )
                )
                context_observation.update(
                    {
                        "selection_observability_schema_version": (
                            selection_schema_version
                            if type(selection_schema_version) is int
                            and selection_schema_version
                            == CONTEXT_SELECTION_OBSERVABILITY_SCHEMA_VERSION
                            else None
                        ),
                        "selection_detail_status": (
                            selection_detail_status
                            if isinstance(selection_detail_status, str)
                            and selection_detail_status
                            in {"AVAILABLE", "PROJECTION_ERROR"}
                            else "AVAILABLE"
                        ),
                        "selection_items": list(selection_metadata),
                        "selection_items_original_count": _optional_nonnegative(
                            metrics.get("context_selection_projection_original_count")
                            if isinstance(metrics, Mapping)
                            else getattr(
                                metrics,
                                "context_selection_projection_original_count",
                                None,
                            )
                        ),
                        "selection_items_persisted_count": _optional_nonnegative(
                            metrics.get("context_selection_projection_persisted_count")
                            if isinstance(metrics, Mapping)
                            else getattr(
                                metrics,
                                "context_selection_projection_persisted_count",
                                None,
                            )
                        ),
                        "selection_items_projection_truncated": (
                            projection_truncated
                            if type(projection_truncated) is bool
                            else None
                        ),
                    }
                )
            self._observability["context"] = _safe_observation_mapping(
                context_observation, "context selection observation"
            )

    def record_response_observation(
        self,
        response_text: str,
        metadata: Mapping[str, object] | None = None,
        *,
        turn_id: str = "turn:unknown",
        findings: Iterable[ReviewFinding] | None = None,
    ) -> None:
        """Record final-response parsing metadata without retaining the answer.

        The response body is used only transiently to compute a redacted digest
        when the runtime redactor is available.  Without that redactor the
        digest is deliberately metadata-only, so this observer never becomes a
        second secret-handling boundary.
        """

        text = response_text if isinstance(response_text, str) else ""
        raw_metadata = metadata if isinstance(metadata, Mapping) else {}
        observed = _safe_observation_mapping(raw_metadata, "response observation")
        observed["observed"] = True
        observed["present"] = bool(text)
        observed["byte_count"] = len(text.encode("utf-8", errors="replace"))
        observed.setdefault("format", "UNCLASSIFIED")
        observed.setdefault("parse_attempted", False)
        observed.setdefault("json_decode_status", "NOT_ATTEMPTED")
        observed.setdefault("schema_validation_status", "NOT_ATTEMPTED")
        observed.setdefault("typed_parse_status", "NOT_ATTEMPTED")
        observed.setdefault("truncated", False)
        if findings is not None:
            try:
                observed.update(
                    project_review_findings(
                        findings,
                        redactor=self._secret_redactor,
                    )
                )
            except Exception:  # noqa: BLE001 - telemetry fails closed
                observed.update(
                    {
                        "semantic_attribution_schema_version": SEMANTIC_ATTRIBUTION_SCHEMA_VERSION,
                        "typed_finding_detail_status": "PROJECTION_ERROR",
                        "typed_findings": "NOT_AVAILABLE",
                        "typed_finding_original_count": None,
                        "typed_finding_persisted_count": None,
                        "typed_finding_projection_truncated": None,
                        "typed_finding_values_redacted": None,
                        "typed_finding_projection_digest": None,
                    }
                )
        if self._secret_redactor is not None:
            safe_text = self._secret_redactor.redact_text(text)
            digest = hashlib.sha256(safe_text.encode("utf-8", errors="replace")).hexdigest()
            observed["safe_digest"] = digest
            observed["digest_version"] = "v1:redacted-content"
        else:
            digest_payload = {
                key: value
                for key, value in observed.items()
                if key not in {"safe_digest", "digest_version"}
            }
            observed["safe_digest"] = _safe_digest(digest_payload)
            observed["digest_version"] = "v1:metadata-only"
        self._observability["response_observability"] = observed
        self._record(
            "agent_event",
            "response_parse_evaluated",
            event_type="response_parse_evaluated",
            turn_id=_bounded_identifier(turn_id, "turn:unknown"),
            event_metadata=observed,
            safe_result_digest=str(observed["safe_digest"]),
        )

    def record_repository_context(self, bundle: object) -> None:
        """Record only typed repository-context cardinalities and digests."""

        if bundle is None:
            return
        paths = _safe_path_list(getattr(bundle, "structure_paths", ()))
        observation = {
            "observed": True,
            "bundle_digest": _bounded_digest(getattr(bundle, "bundle_digest", None)),
            "documents": _bounded_count(getattr(bundle, "documents", ())),
            "symbols": _bounded_count(getattr(bundle, "symbols", ())),
            "evidence": _bounded_count(getattr(bundle, "evidence", ())),
            "structure_paths": paths,
            "structure_path_count": len(paths),
            "truncated": getattr(bundle, "truncated", None)
            if type(getattr(bundle, "truncated", None)) is bool
            else None,
            "truncation_reasons": _safe_identifier_list(
                getattr(bundle, "truncation_reasons", ())
            ),
            "repository_generation": _bounded_identifier(
                getattr(bundle, "repository_generation", None), ""
            )
            or None,
            "index_generation": _bounded_identifier(
                getattr(bundle, "index_generation", None), ""
            )
            or None,
        }
        self._observability["repository_context"] = _safe_observation_mapping(
            observation, "repository context observation"
        )

    def record_context_selection(
        self,
        context: object,
        *,
        repo_bundle: object | None = None,
    ) -> None:
        """Record the exact bounded Context Engine selection metadata."""

        selection = getattr(context, "selection", None)
        selected = tuple(getattr(selection, "selected", ()) or ())
        evicted = tuple(getattr(selection, "evicted", ()) or ())
        compressed = tuple(getattr(selection, "compressed", ()) or ())
        projection = project_context_selection(selection)
        selection_id = _selection_id(
            getattr(getattr(context, "selection_identity", None), "selection_id", None)
        )
        selection_sequence = _selection_sequence(
            getattr(getattr(context, "selection_identity", None), "selection_sequence", None)
        )
        selection_reason = _selection_reason(
            getattr(getattr(context, "selection_identity", None), "selection_reason", None)
        )
        selection_digest = _bounded_digest(projection.get("selection_digest"))
        identity_digest = _selection_identity_digest(
            selection_id,
            selection_sequence,
            selection_reason,
            selection_digest,
        )
        history = _selection_history(
            self._observability_section("context").get("selection_history")
        ) or []
        history_entry = _selection_history_entry(
            selection_id,
            selection_sequence,
            selection_reason,
            selection_digest,
        )
        if history_entry is not None:
            history.append(history_entry)
            history = history[-_MAX_CONTEXT_SELECTION_HISTORY:]
        initial_selection_id = _selection_id(
            self._observability_section("context").get("context_initial_selection_id")
        )
        if initial_selection_id is None and selection_reason in {"BUILD", "INITIAL_BUILD"}:
            initial_selection_id = selection_id
        previous_rebalance_count = _optional_nonnegative(
            self._observability_section("context").get("context_rebalance_count")
        ) or 0
        rebalance_count = previous_rebalance_count + (
            1 if selection_reason == "REBALANCE" else 0
        )
        selection_count = len(history) if history else None
        context_observation = {
            "observed": True,
            "semantic_attribution_schema_version": SEMANTIC_ATTRIBUTION_SCHEMA_VERSION,
            "selection_observability_schema_version": projection[
                "context_selection_observability_schema_version"
            ],
            "selection_detail_status": projection["context_selection_detail_status"],
            "selection_digest": selection_digest,
            "selection_id": selection_id,
            "selection_sequence": selection_sequence,
            "selection_reason": selection_reason,
            "selection_identity_digest": identity_digest,
            "selection_identity_status": (
                "AVAILABLE" if selection_id is not None else "LEGACY_NO_SELECTION_ID"
            ),
            "final_context_selection_id": selection_id,
            "final_context_selection_sequence": selection_sequence,
            "final_context_selection_reason": selection_reason,
            "final_context_selection_digest": selection_digest,
            "context_selection_count": selection_count,
            "context_initial_selection_id": initial_selection_id,
            "context_rebalance_count": rebalance_count if history_entry is not None else None,
            "selection_history": history,
            "context_digest": _bounded_digest(getattr(context, "context_digest", None)),
            "requirements_digest": _bounded_digest(
                getattr(context, "requirements_digest", None)
            ),
            "selected_count": len(selected),
            "evicted_count": len(evicted),
            "compressed_count": len(compressed),
            "truncated_count": _nonnegative_int(
                getattr(selection, "truncated_count", None)
            ),
            "selected_repository_paths": projection["selected_repository_paths"],
            "automatic_repo_items_selected": projection[
                "automatic_repo_items_selected"
            ],
            "tool_acquired_items_selected": projection[
                "tool_acquired_items_selected"
            ],
            "non_repository_items_selected": projection[
                "non_repository_items_selected"
            ],
            "selection_items": projection["selection_items"],
            "selection_items_original_count": projection[
                "selection_items_original_count"
            ],
            "selection_items_persisted_count": projection[
                "selection_items_persisted_count"
            ],
            "selection_items_projection_truncated": projection[
                "selection_items_projection_truncated"
            ],
            "cache_hit": getattr(context, "cache_hit", None)
            if type(getattr(context, "cache_hit", None)) is bool
            else None,
            "partial": getattr(context, "partial", None)
            if type(getattr(context, "partial", None)) is bool
            else None,
        }
        self._observability["context"] = _safe_observation_mapping(
            context_observation, "context selection observation"
        )
        self._record(
            "agent_event",
            "context_selected",
            event_type="context_selected",
            event_metadata=context_observation,
            safe_result_digest=str(selection_digest or ""),
        )
        if repo_bundle is not None:
            self.record_repository_context(repo_bundle)

    def record_semantic_review(self, evidence: Mapping[str, object] | None) -> None:
        """Record bounded oracle/review cardinalities, never hidden finding text."""

        source = evidence if isinstance(evidence, Mapping) else {}
        observation = {
            "observed": True,
            "passed": source.get("review_findings_pass", source.get("passed"))
            if type(source.get("review_findings_pass", source.get("passed"))) is bool
            else None,
            "evaluation_layer": source.get("evaluation_layer")
            if isinstance(source.get("evaluation_layer"), str)
            else None,
            "failure_class": source.get("failure_class")
            if isinstance(source.get("failure_class"), str)
            else None,
            "semantic_evaluation": source.get("semantic_evaluation")
            if isinstance(source.get("semantic_evaluation"), str)
            else None,
            "required_count": _first_nonnegative(source, "required_finding_count", "required_count"),
            "submitted_count": _first_nonnegative(source, "submitted_finding_count", "submitted_count"),
            "matched_count": _matched_count(source),
            "unmatched_count": _first_nonnegative(source, "unmatched_count"),
            "extra_count": _first_nonnegative(source, "extra_finding_count", "extra_count"),
        }
        observation["evidence_digest"] = _safe_digest(
            {key: value for key, value in observation.items() if key != "evidence_digest"}
        )
        self._observability["semantic_review"] = _safe_observation_mapping(
            observation, "semantic review observation"
        )
        self._record(
            "agent_event",
            "semantic_review_evaluated",
            event_type="semantic_review_evaluated",
            event_metadata=observation,
            safe_result_digest=str(observation["evidence_digest"]),
        )

    def _event_observation(
        self,
        event: str,
        metadata: Mapping[str, object],
    ) -> dict[str, object]:
        """Project lifecycle metadata into a small safe event vocabulary."""

        if event in {"completion_evaluated", "completion_gated"}:
            observation = self._completion_observation(event, metadata)
            completion = self._observability_section("completion")
            if event == "completion_evaluated":
                completion["proposal_reached"] = True
                completion["proposal_status"] = observation.get("status")
            else:
                completion.update(
                    {
                        "gate_reached": True,
                        "gate_status": observation.get("status"),
                        "gate_reason_code": observation.get("reason_code"),
                        "gate_authority": observation.get("authority"),
                        "gate_generation": observation.get("generation"),
                        "gate_evidence_digest": observation.get("evidence_digest"),
                        "decision_digest": observation.get("decision_digest"),
                    }
                )
            self._observability["completion"] = completion
            return observation
        if event == "model_final_response":
            return {"model_finalized": True}
        if event == "verification_result":
            return _safe_event_metadata(
                metadata,
                allowed={
                    "task_id", "turn_id", "attempt_id", "run_id", "plan_id", "plan_digest",
                    "workspace_generation", "repository_generation", "status",
                    "required_check_count", "passed_check_count", "check_count",
                    "executed_check_count", "diagnostic_count", "repair_attempt",
                },
            )
        return _safe_event_metadata(
            metadata,
            allowed={
                "task_id", "turn_id", "attempt_id", "status", "terminal_status",
                "code", "generation", "workspace_generation", "repository_generation",
            },
        )

    def _completion_observation(
        self,
        event: str,
        metadata: Mapping[str, object],
    ) -> dict[str, object]:
        status = _bounded_identifier(metadata.get("status"), "unknown").casefold()
        evidence_digest = _bounded_digest(
            metadata.get("evidence_digest") or metadata.get("gate_evidence_digest")
        )
        return {
            "event": event,
            "status": status,
            "reason_code": _completion_reason_code(status, metadata.get("reason")),
            "authority": "CompletionGate" if event == "completion_gated" else None,
            "generation": _bounded_identifier(
                metadata.get("generation")
                or metadata.get("workspace_generation")
                or metadata.get("repository_generation"),
                "",
            )
            or None,
            "evidence_digest": evidence_digest,
            "decision_digest": _bounded_digest(metadata.get("decision_digest")),
        }

    def record_extension_metrics(self, metrics: object) -> None:
        """Attach only the bounded MCP/Hook counters to the coding ledger."""

        names = (
            "extension_calls",
            "mcp_calls",
            "mcp_failures",
            "hook_invocations",
            "hook_failures",
        )
        observed: dict[str, int] = {}
        for name in names:
            value = metrics.get(name) if isinstance(metrics, Mapping) else getattr(metrics, name, None)
            if value is None:
                continue
            if type(value) is not int or value < 0:
                return
            observed[name] = value
        self._extension_metrics = observed

    def record_provider_observations(self, observations: Iterable[object]) -> None:
        """Attach bounded, credential-free Provider request observations.

        The regular Coding benchmark uses the same ModelClient observer as the
        qualification path. Only request outcome metadata is retained here;
        provider messages, authorization material, and response bodies never
        enter the Coding metrics payload. Missing provider usage remains an
        explicit unavailable state rather than an invented zero.
        """

        try:
            if isinstance(observations, (list, tuple)):
                observed_count = len(observations)
                values = list(observations[:_MAX_PROVIDER_OBSERVATIONS])
            else:
                iterator = iter(observations)
                values = []
                for _ in range(_MAX_PROVIDER_OBSERVATIONS):
                    try:
                        values.append(next(iterator))
                    except StopIteration:
                        break
                observed_count = len(values)
        except (TypeError, ValueError):
            self._provider_requests = 0
            self._observability["provider"] = {
                "observed": False,
                "detail_status": "PROJECTION_ERROR",
                "provider_requests": 0,
                "provider_request_details_persisted": 0,
                "provider_request_details_truncated": False,
                "usage_status": "PROVIDER_NOT_REPORTED",
                "status_counts": {},
                "error_type_counts": {},
                "requests": [],
            }
            return

        projected: list[dict[str, object]] = []
        status_counts: Counter[str] = Counter()
        error_type_counts: Counter[str] = Counter()
        usage_rows: list[tuple[int | None, int | None, int | None]] = []
        usage_complete_count = 0
        projection_errors = 0
        for raw in values:
            try:
                to_payload = getattr(raw, "to_payload", None)
                payload = to_payload() if callable(to_payload) else raw
                if not isinstance(payload, Mapping):
                    raise TypeError("provider observation payload is not a mapping")
                status_code = payload.get("status_code")
                if not (type(status_code) is int and 100 <= status_code <= 599):
                    status_code = None
                status_counts[
                    str(status_code) if status_code is not None else "NO_HTTP_RESPONSE"
                ] += 1
                error_type = _bounded_identifier(
                    payload.get("provider_error_type"), ""
                ).casefold() or None
                error_type_counts[error_type or "NONE"] += 1
                usage: tuple[int | None, int | None, int | None] = (
                    _optional_nonnegative(payload.get("input_tokens")),
                    _optional_nonnegative(payload.get("output_tokens")),
                    _optional_nonnegative(payload.get("total_tokens")),
                )
                if any(item is not None for item in usage):
                    usage_rows.append(usage)
                if all(item is not None for item in usage):
                    usage_complete_count += 1
                retryable = payload.get("retryable")
                projected.append(
                    {
                        "provider": _bounded_identifier(payload.get("provider"), "unknown"),
                        "model": _bounded_identifier(payload.get("model"), "unknown"),
                        "attempt": _optional_nonnegative(payload.get("attempt")),
                        "max_attempts": _optional_nonnegative(payload.get("max_attempts")),
                        "status_code": status_code,
                        "started_at": _bounded_identifier(payload.get("started_at"), "UNKNOWN"),
                        "latency_ms": _optional_nonnegative(payload.get("latency_ms")),
                        "first_byte_latency_ms": _optional_nonnegative(
                            payload.get("first_byte_latency_ms")
                        ),
                        "retryable": retryable if type(retryable) is bool else None,
                        "provider_error_type": error_type,
                        "provider_error_code": _bounded_identifier(
                            payload.get("provider_error_code"), ""
                        ).casefold() or None,
                        "input_tokens": usage[0],
                        "output_tokens": usage[1],
                        "total_tokens": usage[2],
                        "response_model": _bounded_identifier(
                            payload.get("response_model"), ""
                        ) or None,
                    }
                )
            except (TypeError, ValueError):
                projection_errors += 1

        usage_totals = tuple(
            _sum_optional_ints(row[index] for row in usage_rows)
            for index in range(3)
        )
        usage_status = (
            "PROVIDER_NOT_REPORTED"
            if not usage_rows
            else "PROVIDER_REPORTED"
            if (
                not projection_errors
                and observed_count == len(values)
                and usage_complete_count == observed_count
            )
            else "PROVIDER_PARTIAL"
        )
        section = {
            "observed": observed_count > 0,
            "detail_status": "PROJECTION_ERROR" if projection_errors else "AVAILABLE",
            "provider_requests": observed_count,
            "provider_request_details_persisted": len(projected),
            "provider_request_details_truncated": observed_count > len(values),
            "input_tokens": usage_totals[0],
            "output_tokens": usage_totals[1],
            "total_tokens": usage_totals[2],
            "usage_status": usage_status,
            "status_counts": dict(sorted(status_counts.items())),
            "error_type_counts": dict(sorted(error_type_counts.items())),
            "requests": projected,
        }
        try:
            self._observability["provider"] = _safe_observation_mapping(
                section, "provider observation"
            )
        except (TypeError, ValueError):
            self._observability["provider"] = {
                "observed": observed_count > 0,
                "detail_status": "PROJECTION_ERROR",
                "provider_requests": observed_count,
                "provider_request_details_persisted": 0,
                "provider_request_details_truncated": observed_count > 0,
                "input_tokens": None,
                "output_tokens": None,
                "total_tokens": None,
                "usage_status": "PROVIDER_NOT_REPORTED",
                "status_counts": {},
                "error_type_counts": {},
                "requests": [],
            }
        self._provider_requests = observed_count
        self._provider_usage_status = usage_status

    def _record_tool_result_metrics(
        self,
        name: str,
        category: str,
        success: bool | None,
        metadata: Mapping[str, object],
    ) -> None:
        """Project one result into legacy aggregate counters safely."""

        if category in {"file_read", "content_search", "navigation", "metadata", "context"}:
            raw_count = metadata.get("result_count")
            result_count = raw_count if type(raw_count) is int and raw_count >= 0 else 0
            self._files_viewed += max(1, result_count)
            self._mark_first("read")
        elif category in {"edit", "editing"}:
            if success is True:
                self._files_modified += 1
            self._edit_attempts += 1
            if success is not True:
                self._failed_edit_attempts += 1
            self._mark_first("edit")
        elif category == "verification":
            self._mark_first("test")
            if name == "test_run" or "test" in name.casefold():
                self._tests_run += 1
                if success is True:
                    self._tests_passed += 1
                    self._successful_test_runs += 1
                    self._mark_first("green")
                else:
                    self._failed_test_runs += 1

    def record_terminal(self, reason: str) -> None:
        """Record one terminal marker without making it execution authority."""

        safe_reason = _bounded_identifier(reason, "terminal")
        if self._terminal_reason is None:
            self._terminal_reason = safe_reason
        self._finalize_pending_tool_calls(_pending_terminal_state(safe_reason))
        self._record(
            "terminal",
            "terminal",
            event_type="terminal",
            terminal_reason=safe_reason,
        )

    def record(
        self,
        kind: str,
        name: str,
        *,
        success: bool | None = None,
        duration_ms: int | None = None,
    ) -> None:
        """Record a trusted adapter event such as test or runtime completion."""

        self._record_agent_event(name)
        self._record(
            kind,
            name,
            success=success,
            duration_ms=duration_ms,
            event_type=_event_type_for_message(name) if kind == "agent_event" else kind,
        )

    def finish(
        self,
        *,
        verdict: CodingVerdict,
        agent_status: str,
        completion_status: str | None,
        input_tokens: int | None = None,
        output_tokens: int | None = None,
        oracle_pass_count: int = 0,
        oracle_fail_count: int = 0,
        diff_changed_files: int = 0,
        diff_insertions: int = 0,
        diff_deletions: int = 0,
        unrelated_changed_files: int = 0,
    ) -> CodingMetrics:
        if self._terminal_reason is None:
            self._terminal_reason = _bounded_identifier(
                completion_status or verdict.value,
                "terminal",
            )
        self._finalize_pending_tool_calls("NOT_EXECUTED")
        tool_names = dict(self._tool_names)
        category = dict(self._tool_categories)
        repo_metrics = self._repo_metrics or {}
        context_metrics = self._context_metrics
        extension_metrics = self._extension_metrics
        git_calls = sum(
            count for name, count in tool_names.items()
            if name == "git" or name.startswith("git_")
        )
        browser_calls = sum(
            count for name, count in tool_names.items()
            if name == "browser" or name.startswith("browser_")
        )
        subagent_calls = sum(
            count for name, count in tool_names.items()
            if name == "subagent" or name.startswith(("subagent_", "spawn_", "delegate_"))
        )
        detailed = {
            "read_file_calls": tool_names.get("read_file", 0),
            "search_calls": sum(
                tool_names.get(name, 0)
                for name in ("search_files", "file_search_content")
            ),
            "code_search_calls": tool_names.get("code_search", 0),
            "symbol_calls": tool_names.get("code_symbols", 0),
            "write_calls": tool_names.get("write_file", 0),
            "patch_calls": (
                tool_names.get("patch", 0)
                + tool_names.get("multi_edit", 0)
                + tool_names.get("apply_edit_transaction", 0)
            ),
            "terminal_calls": sum(
                tool_names.get(name, 0)
                for name in (
                    "terminal_argv",
                    "terminal_shell",
                    "process",
                    "sandbox_exec",
                    "sandbox_build",
                )
            ),
            "test_calls": tool_names.get("test_run", 0),
            "git_calls": git_calls,
            "browser_calls": browser_calls,
            "subagent_calls": subagent_calls,
        }
        context_observation = self._observability.get("context")
        context_observation = (
            context_observation if isinstance(context_observation, Mapping) else {}
        )
        context_selection_id = _selection_id(
            context_observation.get(
                "final_context_selection_id",
                context_observation.get("selection_id"),
            )
        )
        context_selection_sequence = _selection_sequence(
            context_observation.get(
                "final_context_selection_sequence",
                context_observation.get("selection_sequence"),
            )
        )
        context_selection_reason = _selection_reason(
            context_observation.get(
                "final_context_selection_reason",
                context_observation.get("selection_reason"),
            )
        )
        context_selection_count = _optional_nonnegative(
            context_metrics.get("context_selection_count")
        )
        if context_selection_count is None:
            context_selection_count = _optional_nonnegative(
                context_observation.get("context_selection_count")
            )
        context_initial_selection_id = _selection_id(
            context_observation.get("context_initial_selection_id")
        )
        context_rebalance_count = _optional_nonnegative(
            context_metrics.get("context_rebalance_count")
        )
        if context_rebalance_count is None:
            context_rebalance_count = _optional_nonnegative(
                context_observation.get("context_rebalance_count")
            )
        provider_observation = self._observability.get("provider")
        provider_usage = (
            provider_observation
            if isinstance(provider_observation, Mapping)
            else {}
        )
        provider_input_tokens = _optional_nonnegative(
            provider_usage.get("input_tokens")
        )
        provider_output_tokens = _optional_nonnegative(
            provider_usage.get("output_tokens")
        )
        provider_total_tokens = _optional_nonnegative(
            provider_usage.get("total_tokens")
        )
        resolved_input_tokens = (
            input_tokens if input_tokens is not None else provider_input_tokens
        )
        resolved_output_tokens = (
            output_tokens if output_tokens is not None else provider_output_tokens
        )
        resolved_total_tokens = (
            provider_total_tokens
            if provider_total_tokens is not None
            else (
                resolved_input_tokens + resolved_output_tokens
                if resolved_input_tokens is not None
                and resolved_output_tokens is not None
                else None
            )
        )
        return CodingMetrics(
            verdict=verdict,
            agent_status=agent_status,
            completion_status=completion_status,
            wall_clock_ms=self._elapsed_ms(),
            model_messages=self._model_calls,
            tool_calls=self._tool_calls,
            tool_calls_by_category=category,
            files_viewed=self._files_viewed,
            files_modified=self._files_modified,
            tests_run=self._tests_run,
            tests_passed=self._tests_passed,
            input_tokens=resolved_input_tokens,
            output_tokens=resolved_output_tokens,
            trace_event_count=len(self._events),
            trace_digest=canonical_digest([event.to_payload() for event in self._events]),
            trace_schema_version=2,
            trace_truncated=self._trace_truncated,
            trace_dropped_event_count=self._dropped_event_count,
            tool_calls_by_exact_name=tool_names,
            pending_tool_calls=0,
            tool_call_states=dict(self._tool_call_states),
            terminal_reason=self._terminal_reason,
            observability_schema_version=OBSERVABILITY_SCHEMA_VERSION,
            observability=_complete_observability(self._observability),
            task_success=verdict is CodingVerdict.PASS,
            oracle_pass_count=oracle_pass_count,
            oracle_fail_count=oracle_fail_count,
            oracle_total=oracle_pass_count + oracle_fail_count,
            failed_tool_calls=self._failed_tool_calls,
            approval_count=self._approval_count,
            permission_denials=self._permission_denials,
            repair_cycles=self._recovery_count,
            model_calls=self._model_calls,
            model_turns=self._model_turns,
            provider_requests=self._provider_requests,
            provider_usage_status=self._provider_usage_status,
            total_tokens=resolved_total_tokens,
            tool_calls_by_name=tool_names,
            extension_calls=extension_metrics.get("extension_calls", 0),
            mcp_calls=extension_metrics.get("mcp_calls", 0),
            mcp_failures=extension_metrics.get("mcp_failures", 0),
            hook_invocations=extension_metrics.get("hook_invocations", 0),
            hook_failures=extension_metrics.get("hook_failures", 0),
            **detailed,
            editing_calls=category.get("editing", 0) + category.get("edit", 0),
            verification_calls=category.get("verification", 0),
            recovery_calls=category.get("recovery", 0),
            first_edit_turn=self._first_edit_turn,
            edit_attempts=self._edit_attempts,
            failed_edit_attempts=self._failed_edit_attempts,
            unrelated_changed_files=unrelated_changed_files,
            failed_test_runs=self._failed_test_runs,
            successful_test_runs=self._successful_test_runs,
            verification_commands=category.get("verification", 0),
            final_green=(self._successful_test_runs > 0 if self._tests_run else None),
            time_to_first_tool_ms=self._first_tool_ms,
            time_to_first_read_ms=self._first_read_ms,
            time_to_first_edit_ms=self._first_edit_ms,
            time_to_first_test_ms=self._first_test_ms,
            time_to_first_green_ms=self._first_green_ms,
            repo_intelligence_queries=repo_metrics.get("repo_intelligence_queries"),
            repo_intelligence_cache_hits=repo_metrics.get("repo_intelligence_cache_hits"),
            repo_intelligence_cache_misses=repo_metrics.get("repo_intelligence_cache_misses"),
            repo_index_full_refreshes=repo_metrics.get("repo_index_full_refreshes"),
            repo_index_incremental_refreshes=repo_metrics.get("repo_index_incremental_refreshes"),
            repo_files_parsed=repo_metrics.get("repo_files_parsed"),
            repo_files_reparsed=repo_metrics.get("repo_files_reparsed"),
            semantic_queries=repo_metrics.get("semantic_queries"),
            lexical_fallback_queries=repo_metrics.get("lexical_fallback_queries"),
            stale_query_count=repo_metrics.get("stale_query_count"),
            context_candidate_count=repo_metrics.get("context_candidate_count"),
            context_selected_file_count=(
                context_metrics.get("context_selected_file_count")
                if context_metrics.get("context_selected_file_count") is not None
                else repo_metrics.get("context_selected_file_count")
            ),
            context_selected_symbol_count=(
                context_metrics.get("context_selected_symbol_count")
                if context_metrics.get("context_selected_symbol_count") is not None
                else repo_metrics.get("context_selected_symbol_count")
            ),
            context_build_count=context_metrics.get("context_builds"),
            context_bundle_count=context_metrics.get("context_builds"),
            context_tokens=context_metrics.get("context_input_tokens"),
            context_bytes=context_metrics.get("context_input_bytes"),
            context_files=context_metrics.get("context_selected_file_count"),
            context_symbols=context_metrics.get("context_selected_symbol_count"),
            context_truncated_count=context_metrics.get("context_truncated_count"),
            context_stale_count=(
                context_metrics.get("context_stale_retries")
                if context_metrics.get("context_stale_retries") is not None
                else repo_metrics.get("stale_query_count")
            ),
            context_cache_hits=context_metrics.get("context_cache_hits"),
            context_cache_misses=context_metrics.get("context_cache_misses"),
            context_builds=context_metrics.get("context_builds"),
            context_input_tokens=context_metrics.get("context_input_tokens"),
            context_input_bytes=context_metrics.get("context_input_bytes"),
            context_l0_tokens=context_metrics.get("context_l0_tokens"),
            context_l1_tokens=context_metrics.get("context_l1_tokens"),
            context_l2_tokens=context_metrics.get("context_l2_tokens"),
            context_l3_tokens=context_metrics.get("context_l3_tokens"),
            context_items_selected=context_metrics.get("context_items_selected"),
            context_items_evicted=context_metrics.get("context_items_evicted"),
            context_items_compressed=context_metrics.get("context_items_compressed"),
            context_stale_retries=context_metrics.get("context_stale_retries"),
            context_partial_builds=context_metrics.get("context_partial_builds"),
            context_compactions=context_metrics.get("context_compactions"),
            context_stable_prefix_tokens=context_metrics.get("context_stable_prefix_tokens"),
            context_stable_prefix_bytes=context_metrics.get("context_stable_prefix_bytes"),
            context_memory_items_selected=context_metrics.get("context_memory_items_selected"),
            context_repo_items_selected=context_metrics.get("context_repo_items_selected"),
            context_diagnostics_selected=context_metrics.get("context_diagnostics_selected"),
            context_selection_id=context_selection_id,
            context_selection_sequence=context_selection_sequence,
            context_selection_reason=context_selection_reason,
            context_selection_count=context_selection_count,
            context_initial_selection_id=context_initial_selection_id,
            context_rebalance_count=context_rebalance_count,
            tool_schema_tokens=context_metrics.get("tool_schema_tokens"),
            tool_schema_bytes=context_metrics.get("tool_schema_bytes"),
            deferred_tool_discoveries=context_metrics.get("deferred_tool_discoveries"),
            deferred_skill_discoveries=context_metrics.get("deferred_skill_discoveries"),
            deferred_skill_loads=context_metrics.get("deferred_skill_loads"),
            skill_tokens=context_metrics.get("skill_tokens"),
            tool_output_tokens=context_metrics.get("tool_output_tokens"),
            tool_output_bytes=context_metrics.get("tool_output_bytes"),
            tool_output_truncated_count=context_metrics.get("tool_output_truncated_count"),
            active_skills=context_metrics.get("active_skills"),
            extension_context_bytes=context_metrics.get("extension_context_bytes"),
            extension_tool_schema_bytes=context_metrics.get("extension_tool_schema_bytes"),
            memory_items_selected=(
                context_metrics.get("memory_items_selected")
                if context_metrics.get("memory_items_selected") is not None
                else context_metrics.get("context_memory_items_selected")
            ),
            repo_items_selected=(
                context_metrics.get("repo_items_selected")
                if context_metrics.get("repo_items_selected") is not None
                else context_metrics.get("context_repo_items_selected")
            ),
            diagnostics_selected=(
                context_metrics.get("diagnostics_selected")
                if context_metrics.get("diagnostics_selected") is not None
                else context_metrics.get("context_diagnostics_selected")
            ),
            compaction_count=(
                context_metrics.get("compaction_count")
                if context_metrics.get("compaction_count") is not None
                else context_metrics.get("context_compactions")
            ),
            replan_count=self._replan_count,
            recovery_count=self._recovery_count,
            no_progress_count=self._no_progress_count,
            completion_rejections=self._completion_rejections,
            completion_acceptances=self._completion_acceptances,
            approval_intervention_count=self._approval_count,
            diff_changed_files=diff_changed_files,
            diff_insertions=diff_insertions,
            diff_deletions=diff_deletions,
            autonomous_verification_plan_count=self._autonomous_verification_plan_count,
            autonomous_verification_check_count=self._autonomous_verification_check_count,
            autonomous_verification_executed_check_count=self._autonomous_verification_executed_check_count,
            autonomous_verification_structural_count=self._autonomous_verification_stage_counts.get("structural", 0),
            autonomous_verification_static_count=self._autonomous_verification_stage_counts.get("static", 0),
            autonomous_verification_typecheck_count=self._autonomous_verification_stage_counts.get("typecheck", 0),
            autonomous_verification_targeted_count=self._autonomous_verification_stage_counts.get("targeted", 0),
            autonomous_verification_module_count=self._autonomous_verification_stage_counts.get("module", 0),
            autonomous_verification_integration_count=self._autonomous_verification_stage_counts.get("integration", 0),
            autonomous_verification_regression_count=self._autonomous_verification_stage_counts.get("regression", 0),
            autonomous_verification_pass_count=self._autonomous_verification_pass_count,
            autonomous_verification_failure_count=self._autonomous_verification_failure_count,
            autonomous_verification_timeout_count=self._autonomous_verification_timeout_count,
            autonomous_verification_stale_count=self._autonomous_verification_stale_count,
            autonomous_verification_infrastructure_error_count=self._autonomous_verification_infrastructure_error_count,
            autonomous_verification_unknown_count=self._autonomous_verification_unknown_count,
            autonomous_verification_diagnostic_count=self._autonomous_verification_diagnostic_count,
            autonomous_verification_repair_count=self._autonomous_verification_repair_count,
            autonomous_verification_time_to_final_green_ms=self._autonomous_verification_time_to_final_green_ms,
            verification_plans=self._autonomous_verification_plan_count,
            verification_checks_planned=self._autonomous_verification_check_count,
            verification_checks_executed=self._autonomous_verification_executed_check_count,
            targeted_test_runs=self._autonomous_verification_kind_counts.get("targeted_test", 0),
            package_test_runs=self._autonomous_verification_kind_counts.get("package_test", 0),
            integration_test_runs=self._autonomous_verification_kind_counts.get("integration_test", 0),
            build_runs=self._autonomous_verification_kind_counts.get("build", 0),
            lint_runs=self._autonomous_verification_kind_counts.get("lint", 0),
            typecheck_runs=self._autonomous_verification_kind_counts.get("typecheck", 0),
            verification_passes=self._autonomous_verification_pass_count,
            verification_failures=self._autonomous_verification_failure_count,
            verification_timeouts=self._autonomous_verification_timeout_count,
            verification_infra_errors=self._autonomous_verification_infrastructure_error_count,
            verification_plan_rebuilds=max(0, self._autonomous_verification_plan_count - 1),
            diagnostics_count=self._autonomous_verification_diagnostic_count,
            time_to_final_green_ms=self._autonomous_verification_time_to_final_green_ms,
            verification_required_checks=self._autonomous_verification_required_checks,
        )

    def reconcile(self, metrics: CodingMetrics) -> dict[str, object]:
        """Compare stored event evidence with its derived metric summary.

        A truncated trace is reported as incomplete evidence rather than as a
        false mismatch.  Any mismatch in a complete trace is an observability
        defect and never changes execution or completion authority.
        """

        if not isinstance(metrics, CodingMetrics):
            raise TypeError("coding metrics reconciliation requires CodingMetrics")
        event_tool_names: Counter[str] = Counter()
        event_categories: Counter[str] = Counter()
        event_model_turns = 0
        for event in self._events:
            if event.event_type == "tool_call":
                event_tool_names[event.tool_name] += 1
                event_categories[event.tool_category] += 1
            if event.event_type in {"model_response", "model_final_response"}:
                event_model_turns += 1
        mismatches: list[str] = []
        if not self._trace_truncated:
            if metrics.tool_calls != sum(event_tool_names.values()):
                mismatches.append("tool_calls")
            if dict(metrics.tool_calls_by_exact_name) != dict(event_tool_names):
                mismatches.append("tool_calls_by_exact_name")
            if dict(metrics.tool_calls_by_category) != dict(event_categories):
                mismatches.append("tool_calls_by_category")
            if metrics.model_turns != event_model_turns:
                mismatches.append("model_turns")
            event_response_observed = any(
                event.event_type == "response_parse_evaluated" for event in self._events
            )
            response_observation = metrics.observability.get("response_observability")
            response_observed = bool(
                response_observation.get("observed", False)
                if isinstance(response_observation, Mapping)
                else False
            )
            if event_response_observed != response_observed:
                mismatches.append("response_observability")
            response_event = next(
                (
                    event
                    for event in reversed(self._events)
                    if event.event_type == "response_parse_evaluated"
                ),
                None,
            )
            if response_observed and isinstance(response_observation, Mapping):
                event_metadata = (
                    response_event.safe_event_metadata
                    if response_event is not None
                    else None
                )
                response_detail_status = response_observation.get(
                    "typed_finding_detail_status"
                )
                event_detail_status = (
                    event_metadata.get("typed_finding_detail_status")
                    if isinstance(event_metadata, Mapping)
                    else None
                )
                has_typed_finding_detail = any(
                    isinstance(status, str)
                    and status in {"AVAILABLE", "PROJECTION_ERROR"}
                    for status in (response_detail_status, event_detail_status)
                )
                if isinstance(event_metadata, Mapping) and has_typed_finding_detail:
                    response_detail_keys = (
                        "typed_finding_detail_status",
                        "typed_findings",
                        "typed_finding_original_count",
                        "typed_finding_persisted_count",
                        "typed_finding_projection_truncated",
                        "typed_finding_values_redacted",
                        "typed_finding_projection_digest",
                    )
                    if any(
                        response_observation.get(key) != event_metadata.get(key)
                        for key in response_detail_keys
                        if key in response_observation or key in event_metadata
                    ):
                        mismatches.append("typed_finding_detail")
                if response_observation.get("typed_finding_detail_status") == "AVAILABLE":
                    original_count = response_observation.get(
                        "typed_finding_original_count"
                    )
                    persisted_count = response_observation.get(
                        "typed_finding_persisted_count"
                    )
                    truncated = response_observation.get(
                        "typed_finding_projection_truncated"
                    )
                    if (
                        type(original_count) is int
                        and type(persisted_count) is int
                        and truncated is False
                        and original_count != persisted_count
                    ):
                        mismatches.append("typed_finding_count")
                    semantic_review = metrics.observability.get("semantic_review")
                    submitted_count = (
                        semantic_review.get("submitted_count")
                        if isinstance(semantic_review, Mapping)
                        else None
                    )
                    if (
                        type(original_count) is int
                        and type(submitted_count) is int
                        and original_count != submitted_count
                    ):
                        mismatches.append("typed_finding_count")
            event_gate_reached = any(
                event.event_type == "completion_gated" for event in self._events
            )
            completion = metrics.observability.get("completion")
            summary_gate_reached = bool(
                completion.get("gate_reached", False)
                if isinstance(completion, Mapping)
                else False
            )
            if event_gate_reached != summary_gate_reached:
                mismatches.append("completion_gate")
            mismatches.extend(self._reconcile_context_selection(metrics))
        status = (
            "INCOMPLETE"
            if self._trace_truncated
            else "OBSERVABILITY_DEFECT"
            if mismatches
            else "PASS"
        )
        return {
            "status": status,
            "trace_truncated": self._trace_truncated,
            "mismatches": mismatches,
            "event_tool_call_count": sum(event_tool_names.values()),
            "summary_tool_call_count": metrics.tool_calls,
            "event_model_turn_count": event_model_turns,
            "summary_model_turn_count": metrics.model_turns,
        }

    def _reconcile_context_selection(self, metrics: CodingMetrics) -> list[str]:
        """Reconcile context events with the pointed-to final selection.

        Context selection is a lifecycle, not a single mutable slot.  The
        final metrics snapshot carries an explicit selection id; all detailed
        comparisons therefore resolve through that id instead of assuming
        that the last retained event is the final build.
        """

        mismatches: list[str] = []

        def add(code: str) -> None:
            if code not in mismatches:
                mismatches.append(code)

        context_events = [
            event for event in self._events if event.event_type == "context_selected"
        ]
        context_observation = metrics.observability.get("context")
        context_observed = bool(
            context_observation.get("observed", False)
            if isinstance(context_observation, Mapping)
            else False
        )
        if bool(context_events) != context_observed:
            add("context_selection")
        if not context_events and not context_observed:
            return mismatches
        if not context_events:
            add("FINAL_SELECTION_EVENT_MISSING")
            return mismatches
        if not isinstance(context_observation, Mapping):
            add("FINAL_SELECTION_ID_MISSING")
            return mismatches

        identity_events: list[tuple[CodingTraceEvent, dict[str, object]]] = []
        legacy_event_count = 0
        for event in context_events:
            metadata = event.safe_event_metadata
            raw_id = metadata.get("selection_id", metadata.get("context_selection_id"))
            if raw_id is None:
                legacy_event_count += 1
                continue
            selection_id = _selection_id(raw_id)
            if selection_id is None:
                add("SELECTION_ID_INVALID")
                continue
            sequence = _selection_sequence(
                metadata.get("selection_sequence", metadata.get("context_selection_sequence"))
            )
            reason = _selection_reason(
                metadata.get("selection_reason", metadata.get("context_selection_reason"))
            )
            digest = _bounded_digest(metadata.get("selection_digest"))
            if sequence is None:
                add("SELECTION_SEQUENCE_INVALID")
            if reason is None:
                add("SELECTION_REASON_INVALID")
            if digest is None:
                add("SELECTION_DIGEST_MISSING")
            identity_events.append(
                (
                    event,
                    {
                        "selection_id": selection_id,
                        "selection_sequence": sequence,
                        "selection_reason": reason,
                        "selection_digest": digest,
                    },
                )
            )

        by_id: dict[str, list[CodingTraceEvent]] = {}
        for event, identity in identity_events:
            by_id.setdefault(str(identity["selection_id"]), []).append(event)
        if any(len(events) > 1 for events in by_id.values()):
            add("DUPLICATE_SELECTION_ID")

        previous_sequence: int | None = None
        for _event, identity in identity_events:
            sequence = identity["selection_sequence"]
            if type(sequence) is not int:
                continue
            if previous_sequence is not None and sequence <= previous_sequence:
                add("SELECTION_SEQUENCE_OUT_OF_ORDER")
            previous_sequence = sequence
        if legacy_event_count:
            add("LEGACY_NO_SELECTION_ID")

        raw_final_id = context_observation.get(
            "final_context_selection_id",
            context_observation.get("selection_id"),
        )
        final_id = _selection_id(raw_final_id)
        if identity_events and final_id is None:
            add(
                "FINAL_SELECTION_ID_MISSING"
                if raw_final_id is None
                else "SELECTION_ID_MISMATCH"
            )
        elif identity_events and final_id is not None:
            matching = [
                (event, identity)
                for event, identity in identity_events
                if identity["selection_id"] == final_id
            ]
            if len(matching) != 1:
                add("FINAL_SELECTION_EVENT_MISSING")
            else:
                event, identity = matching[0]
                event_metadata = event.safe_event_metadata
                summary_sequence = _selection_sequence(
                    context_observation.get(
                        "final_context_selection_sequence",
                        context_observation.get("selection_sequence"),
                    )
                )
                summary_reason = _selection_reason(
                    context_observation.get(
                        "final_context_selection_reason",
                        context_observation.get("selection_reason"),
                    )
                )
                summary_digest = _bounded_digest(
                    context_observation.get(
                        "final_context_selection_digest",
                        context_observation.get("selection_digest"),
                    )
                )
                if summary_sequence != identity["selection_sequence"] or summary_reason != identity["selection_reason"]:
                    add("SELECTION_ID_MISMATCH")
                if summary_digest != identity["selection_digest"]:
                    add("SELECTION_DIGEST_MISMATCH")
                expected_identity_digest = _selection_identity_digest(
                    final_id,
                    _selection_sequence(identity["selection_sequence"]),
                    _selection_reason(identity["selection_reason"]),
                    _bounded_digest(identity["selection_digest"]),
                )
                if (
                    _bounded_digest(context_observation.get("selection_identity_digest"))
                    != expected_identity_digest
                    or _bounded_digest(event_metadata.get("selection_identity_digest"))
                    != expected_identity_digest
                ):
                    add("SELECTION_DIGEST_MISMATCH")
                for key in (
                    "selected_count",
                    "evicted_count",
                    "compressed_count",
                    "truncated_count",
                ):
                    if (
                        key in context_observation
                        and key in event_metadata
                        and context_observation.get(key) != event_metadata.get(key)
                    ):
                        add("SELECTION_COUNT_MISMATCH")
                context_detail_keys = (
                    "selection_observability_schema_version",
                    "selection_detail_status",
                    "selection_digest",
                    "selection_items",
                    "selection_items_original_count",
                    "selection_items_persisted_count",
                    "selection_items_projection_truncated",
                )
                if any(
                    context_observation.get(key) != event_metadata.get(key)
                    for key in context_detail_keys
                    if key in context_observation or key in event_metadata
                ):
                    add("context_selection_detail")

        summary_count = _optional_nonnegative(
            context_observation.get("context_selection_count")
        )
        if summary_count is not None and summary_count != len(context_events):
            add("SELECTION_COUNT_MISMATCH")
        summary_history = _selection_history(context_observation.get("selection_history"))
        if summary_history is not None and identity_events:
            history_ids = [entry["selection_id"] for entry in summary_history]
            event_ids = [
                str(identity["selection_id"])
                for _event, identity in identity_events
            ]
            if final_id is not None and final_id not in history_ids:
                add("SELECTION_HISTORY_MISMATCH")
            if (
                history_ids
                and len(history_ids) <= len(event_ids)
                and history_ids != event_ids[-len(history_ids):]
            ):
                add("SELECTION_HISTORY_MISMATCH")
        return mismatches

    def _finalize_pending_tool_calls(self, state: str) -> None:
        """Give every unreturned call an explicit terminal observation."""

        if state not in {"CANCELLED", "NOT_EXECUTED"}:
            raise ValueError("pending tool terminal state is invalid")
        for call_id, pending in tuple(self._pending_tool_calls.items()):
            name = _detailed_tool_name(str(pending.get("name") or "unknown"))
            category = _bounded_identifier(str(pending.get("category") or ""), "")
            self._tool_call_states[state] += 1
            self._record(
                "tool_result",
                name,
                event_type="tool_result",
                turn_id=_bounded_identifier(pending.get("turn_id"), "turn:unknown"),
                tool_call_id=call_id,
                tool_category=category,
                arguments=pending.get("arguments", {}),
                result_metadata={"error_code": state},
                tool_state=state,
            )
        self._pending_tool_calls.clear()

    def _record_agent_event(
        self,
        event: str,
        metadata: Mapping[str, object] | None = None,
    ) -> None:
        normalized = event.casefold().replace(".", "_")
        if normalized in {"permission_request", "approval_wait"}:
            self._approval_count += 1
        elif normalized in {"completion_rejected", "completion_rejection"}:
            self._completion_rejections += 1
        elif normalized in {"completion_accepted", "completion_acceptance"}:
            self._completion_acceptances += 1
        elif normalized == "completion_gated":
            gate_status = _bounded_identifier(
                metadata.get("status") if isinstance(metadata, Mapping) else None,
                "unknown",
            ).casefold()
            if gate_status == "completed":
                self._completion_acceptances += 1
            elif gate_status in _COMPLETION_GATE_REJECTION_STATUSES:
                self._completion_rejections += 1
        elif "no_progress" in normalized:
            self._no_progress_count += 1
        if "replan" in normalized:
            self._replan_count += 1
        if "recover" in normalized or normalized.startswith("recovery"):
            self._recovery_count += 1

    def _record_autonomous_verification_event(
        self,
        event: str,
        metadata: Mapping[str, object],
    ) -> None:
        """Collect only bounded M8.3 status/count metadata from AgentLoop."""
        normalized = event.casefold().replace(".", "_")
        if normalized == "verification_result":
            self._autonomous_verification_plan_count += 1
            self._autonomous_verification_check_count += _nonnegative_int(
                metadata.get("check_count")
            )
            self._autonomous_verification_executed_check_count += _nonnegative_int(
                metadata.get("executed_check_count")
            )
            self._autonomous_verification_required_checks += _nonnegative_int(
                metadata.get("required_check_count")
            )
            stage_counts = metadata.get("stage_counts")
            if isinstance(stage_counts, Mapping):
                for stage, count in stage_counts.items():
                    if isinstance(stage, str) and stage in {
                        "structural",
                        "static",
                        "typecheck",
                        "targeted",
                        "module",
                        "integration",
                        "regression",
                    }:
                        self._autonomous_verification_stage_counts[stage] += _nonnegative_int(count)
            kind_counts = metadata.get("kind_counts")
            if isinstance(kind_counts, Mapping):
                for kind, count in kind_counts.items():
                    if isinstance(kind, str) and kind in {
                        "targeted_test",
                        "package_test",
                        "integration_test",
                        "build",
                        "lint",
                        "typecheck",
                    }:
                        self._autonomous_verification_kind_counts[kind] += _nonnegative_int(count)
            status = metadata.get("status")
            if status == "passed":
                self._autonomous_verification_pass_count += 1
                self._autonomous_verification_time_to_final_green_ms = self._elapsed_ms()
            elif status == "failed":
                self._autonomous_verification_failure_count += 1
            elif status == "timed_out":
                self._autonomous_verification_timeout_count += 1
            elif status == "stale":
                self._autonomous_verification_stale_count += 1
            elif status == "infrastructure_error":
                self._autonomous_verification_infrastructure_error_count += 1
            elif status == "unknown":
                self._autonomous_verification_unknown_count += 1
            self._autonomous_verification_diagnostic_count += _nonnegative_int(
                metadata.get("diagnostic_count")
            )
            if _nonnegative_int(metadata.get("repair_attempt")) > 0:
                self._autonomous_verification_repair_count += 1
        elif normalized == "verification_unavailable":
            self._autonomous_verification_infrastructure_error_count += 1

    def _mark_first(self, kind: str) -> None:
        elapsed = self._elapsed_ms()
        if kind == "tool" and self._first_tool_ms is None:
            self._first_tool_ms = elapsed
        elif kind == "read" and self._first_read_ms is None:
            self._first_read_ms = elapsed
        elif kind == "edit" and self._first_edit_ms is None:
            self._first_edit_ms = elapsed
            self._first_edit_turn = self._model_turns
        elif kind == "test" and self._first_test_ms is None:
            self._first_test_ms = elapsed
        elif kind == "green" and self._first_green_ms is None:
            self._first_green_ms = elapsed

    def _elapsed_ms(self) -> int:
        return max(0, int((time.monotonic() - self._started) * 1000))

    def _record(
        self,
        kind: str,
        name: str,
        *,
        success: bool | None = None,
        duration_ms: int | None = None,
        operation_digest: str = "",
        event_type: str | None = None,
        turn_id: str = "turn:unknown",
        tool_call_id: str = "",
        tool_category: str = "",
        arguments: object = None,
        result_metadata: Mapping[str, object] | None = None,
        event_metadata: Mapping[str, object] | None = None,
        tool_state: str = "",
        terminal_reason: str | None = None,
        safe_result_digest: str = "",
    ) -> None:
        """Store one bounded event; observer capacity never stops the loop."""

        self._event_sequence += 1
        if len(self._events) >= self.max_events:
            self._trace_truncated = True
            self._dropped_event_count += 1
            return
        safe_kind = _bounded_identifier(kind, "event")
        safe_name = _detailed_tool_name(name) or "unknown"
        safe_event_type = _bounded_identifier(event_type or safe_kind, safe_kind)
        safe_turn_id = _bounded_identifier(turn_id, "turn:unknown")
        safe_call_id = _bounded_identifier(tool_call_id, "")
        safe_category = _bounded_identifier(tool_category, "")
        metadata = result_metadata if isinstance(result_metadata, Mapping) else {}
        safe_event_metadata = (
            _safe_observation_mapping(event_metadata, "trace event metadata")
            if isinstance(event_metadata, Mapping)
            else {}
        )
        result_count = _metadata_nonnegative_int(metadata, "result_count", "count", "items_count")
        result_limit = _metadata_nonnegative_int(metadata, "result_limit", "limit", "max_results")
        result_truncated = _metadata_bool(metadata, "result_truncated", "output_truncated")
        error_class = _bounded_error_class(metadata.get("error_code"))
        summary = _safe_argument_summary(arguments, self._secret_redactor)
        scope = _workspace_relative_scope(arguments, self._secret_redactor)
        result_digest = safe_result_digest or _safe_result_digest(
            metadata,
            success=success,
            error_class=error_class,
            result_count=result_count,
            result_truncated=result_truncated,
            redactor=self._secret_redactor,
        )
        try:
            event = CodingTraceEvent(
                sequence=self._event_sequence,
                kind=safe_kind,
                name=safe_name,
                success=success,
                duration_ms=duration_ms,
                operation_digest=operation_digest if isinstance(operation_digest, str) else "",
                schema_version=2,
                run_id=self.run_id,
                event_id=f"{self.run_id}:event:{self._event_sequence}",
                turn_id=safe_turn_id,
                event_sequence=self._event_sequence,
                event_type=safe_event_type,
                tool_call_id=safe_call_id,
                tool_name=safe_name if safe_kind.startswith("tool") else "",
                tool_category=safe_category,
                safe_argument_summary=summary,
                safe_argument_digest=_safe_digest(summary),
                workspace_relative_scope=scope,
                tool_success=success,
                tool_error_class=error_class,
                result_count=result_count,
                result_limit=result_limit,
                result_truncated=result_truncated,
                safe_result_digest=result_digest,
                tool_state=_bounded_identifier(tool_state, ""),
                terminal_reason=_bounded_identifier(terminal_reason, "") if terminal_reason else None,
                safe_event_metadata=safe_event_metadata,
            )
        except Exception:  # noqa: BLE001 - telemetry must fail closed, never escape AgentLoop
            event = CodingTraceEvent(
                sequence=self._event_sequence,
                kind="observer_error",
                name="observer_error",
                success=None,
                schema_version=2,
                run_id=self.run_id,
                event_id=f"{self.run_id}:event:{self._event_sequence}",
                turn_id="turn:unknown",
                event_sequence=self._event_sequence,
                event_type="observer_error",
                safe_result_digest=_safe_digest("observer_error"),
                safe_event_metadata={"error": "observer_metadata_rejected"},
            )
        self._events.append(event)

    def _observability_section(self, name: str) -> dict[str, object]:
        value = self._observability.get(name)
        if isinstance(value, Mapping):
            return cast(dict[str, object], dict(value))
        return {}


def _bounded_identifier(value: object, default: str = "") -> str:
    """Return an opaque bounded identifier suitable for durable telemetry."""

    if value is None:
        return default
    text = str(value).strip()
    if not text:
        return default
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= 512:
        return text
    return f"{text[:120]}:{hashlib.sha256(encoded).hexdigest()[:24]}"


def _bounded_error_class(value: object) -> str | None:
    """Project an untrusted error code to a short stable class."""

    if value is None:
        return None
    text = str(value).strip().upper().replace(" ", "_")
    if not text:
        return None
    if len(text.encode("utf-8", errors="replace")) > 128:
        return "TOOL_ERROR"
    return text


def _pending_terminal_state(reason: str) -> str:
    """Classify pending calls when an explicit terminal reason is observed."""

    normalized = reason.casefold().replace("-", "_")
    return "CANCELLED" if "cancel" in normalized or normalized == "user_abort" else "NOT_EXECUTED"


def _safe_digest(value: object) -> str:
    """Digest arbitrary adapter data without serializing it into a trace."""

    try:
        return canonical_digest(value)
    except Exception:  # noqa: BLE001 - hostile adapter values become a type digest
        return hashlib.sha256(type(value).__name__.encode("utf-8")).hexdigest()


def _safe_argument_summary(
    arguments: object,
    redactor: SecretRedactor | None,
) -> dict[str, object]:
    """Keep only bounded metadata; source/query/replacement values become digests."""

    if not isinstance(arguments, Mapping):
        return {
            "value_type": type(arguments).__name__,
            "value_digest": _safe_redacted_digest(arguments, redactor),
        }
    summary: dict[str, object] = {}
    path_keys = {"path", "destination_path", "cwd", "root", "workspace", "filename"}
    scalar_keys = {
        "line", "start", "end", "offset", "limit", "max_results", "recursive",
        "expected_exists", "base_generation", "transaction_id",
    }
    for index, (raw_key, value) in enumerate(arguments.items()):
        if index >= 32:
            summary["fields_truncated"] = True
            break
        key = _bounded_identifier(raw_key, "field")
        lowered = key.casefold()
        if lowered in path_keys and isinstance(value, str):
            summary[key] = _safe_relative_path(value, redactor)
        elif lowered in scalar_keys and type(value) in {bool, int, float}:
            summary[key] = value
        elif lowered in {"operation", "action", "name"} and isinstance(value, str):
            summary[key] = _bounded_identifier(value, "value")
        else:
            summary[key] = {
                "type": type(value).__name__,
                "digest": _safe_redacted_digest(value, redactor),
            }
    return summary


def _safe_redacted_digest(value: object, redactor: SecretRedactor | None) -> str:
    """Digest only redacted data; without a redactor, retain type-only evidence."""

    if redactor is None:
        return _safe_digest({"type": type(value).__name__})
    return _safe_digest(redactor.redact_fail_closed(value))


def _safe_relative_path(value: str, redactor: SecretRedactor | None) -> str:
    """Return a workspace-relative path marker without exposing host paths."""

    sanitized = redactor.redact_text(value) if redactor is not None else value
    normalized = sanitized.replace("\\", "/").strip()
    if not normalized or normalized.startswith("/") or "://" in normalized or ":" in normalized.split("/", 1)[0]:
        return "workspace:absolute-or-external"
    parts = [part for part in normalized.split("/") if part not in {"", "."}]
    if any(part == ".." for part in parts):
        return "workspace:parent-reference"
    return "/".join(parts)[:512] or "workspace:root"


def _workspace_relative_scope(
    arguments: object,
    redactor: SecretRedactor | None,
) -> str:
    if not isinstance(arguments, Mapping):
        return "workspace:unknown"
    for key in ("path", "destination_path", "workspace", "root", "cwd"):
        value = arguments.get(key)
        if isinstance(value, str):
            return _safe_relative_path(value, redactor)
    return "workspace:unspecified"


def _metadata_nonnegative_int(
    metadata: Mapping[str, object],
    *keys: str,
) -> int | None:
    for key in keys:
        value = metadata.get(key)
        if type(value) is int and value >= 0:
            return value
    return None


def _metadata_bool(metadata: Mapping[str, object], *keys: str) -> bool | None:
    for key in keys:
        value = metadata.get(key)
        if type(value) is bool:
            return value
    return None


def _safe_result_digest(
    metadata: Mapping[str, object],
    *,
    success: bool | None,
    error_class: str | None,
    result_count: int | None,
    result_truncated: bool | None,
    redactor: SecretRedactor | None,
) -> str:
    return _safe_digest(
        {
            "success": success,
            "error_class": error_class,
            "result_count": result_count,
            "result_truncated": result_truncated,
            "output_type": type(metadata.get("output")).__name__,
            "output_digest": _safe_redacted_digest(metadata.get("output"), redactor),
        }
    )


def _event_type_for_message(event: str) -> str:
    """Keep completion/terminal event distinctions explicit in Trace v2."""

    if event in {
        "completion_evaluated",
        "completion_gated",
        "model_final_response",
        "terminal",
    }:
        return event
    if event == "done" or event == "error":
        return "terminal"
    return _bounded_identifier(event.replace(".", "_"), "agent_event")


def _nonnegative_int(value: object) -> int:
    """Project one untrusted event field into a bounded metric counter."""
    return value if type(value) is int and value >= 0 else 0


def _default_observability() -> dict[str, object]:
    """Return the explicit unavailable state for new observability fields."""

    return {
        "schema_version": OBSERVABILITY_SCHEMA_VERSION,
        "semantic_attribution_schema_version": SEMANTIC_ATTRIBUTION_SCHEMA_VERSION,
        "response_observability": {
            "observed": False,
            "present": False,
            "byte_count": 0,
            "format": "NOT_OBSERVED",
            "safe_digest": None,
            "digest_version": "NOT_OBSERVED",
            "parse_attempted": False,
            "json_decode_status": "NOT_ATTEMPTED",
            "schema_validation_status": "NOT_ATTEMPTED",
            "typed_parse_status": "NOT_ATTEMPTED",
            "typed_finding_count": None,
            "parse_error_code": None,
            "finding_field_count": None,
            "unknown_field_count": None,
            "all_required_fields_present": None,
            "truncated": False,
            "semantic_attribution_schema_version": SEMANTIC_ATTRIBUTION_SCHEMA_VERSION,
            "typed_finding_detail_status": "NOT_AVAILABLE",
            "typed_findings": "NOT_AVAILABLE",
            "typed_finding_original_count": None,
            "typed_finding_persisted_count": None,
            "typed_finding_projection_truncated": None,
            "typed_finding_values_redacted": None,
            "typed_finding_projection_digest": None,
        },
        "completion": {
            "model_finalized": False,
            "proposal_reached": False,
            "proposal_status": None,
            "gate_reached": False,
            "gate_status": "NOT_REACHED",
            "gate_reason_code": None,
            "gate_authority": None,
            "gate_generation": None,
            "gate_evidence_digest": None,
            "decision_digest": None,
        },
        "repository_context": {"observed": False},
        "context": {
            "observed": False,
            "selection_identity_status": "NOT_OBSERVED",
            "selection_id": None,
            "selection_sequence": None,
            "selection_reason": None,
            "selection_identity_digest": None,
            "final_context_selection_id": None,
            "final_context_selection_sequence": None,
            "final_context_selection_reason": None,
            "final_context_selection_digest": None,
            "context_selection_count": None,
            "context_initial_selection_id": None,
            "context_rebalance_count": None,
            "selection_history": [],
            "selection_observability_schema_version": None,
            "selection_detail_status": "NOT_AVAILABLE",
            "selection_items": "NOT_AVAILABLE",
            "selection_items_original_count": None,
            "selection_items_persisted_count": None,
            "selection_items_projection_truncated": None,
        },
        "semantic_review": {
            "observed": False,
            "evaluation_layer": None,
            "failure_class": None,
            "semantic_evaluation": "NOT_OBSERVED",
        },
    }


def _complete_observability(value: Mapping[str, object]) -> dict[str, object]:
    """Normalize the collector's sections before constructing typed metrics."""

    candidate = _default_observability()
    for section, raw in value.items():
        if isinstance(raw, Mapping):
            existing = candidate.get(section)
            merged = dict(existing) if isinstance(existing, Mapping) else {}
            merged.update(raw)
            candidate[section] = merged
        else:
            candidate[section] = raw
    return _safe_observation_mapping(candidate, "coding observability")


def _safe_observation_mapping(value: object, label: str, *, depth: int = 0) -> dict[str, object]:
    """Copy bounded JSON-like metadata and reject credential-shaped fields."""

    if not isinstance(value, Mapping):
        raise TypeError(f"{label} must be a mapping")
    if depth > 6 or len(value) > 128:
        raise ValueError(f"{label} exceeds its bound")
    result: dict[str, object] = {}
    for raw_key, raw_item in value.items():
        if not isinstance(raw_key, str) or not raw_key or len(raw_key) > 128:
            raise ValueError(f"{label} contains an invalid field name")
        lowered = raw_key.casefold()
        if any(marker in lowered for marker in _OBSERVABILITY_SENSITIVE_KEY_MARKERS):
            raise ValueError(f"{label} contains a credential-shaped field")
        if raw_item is None or type(raw_item) in {bool, int, float}:
            if isinstance(raw_item, float) and not math.isfinite(raw_item):
                raise ValueError(f"{label} contains a non-finite number")
            result[raw_key] = raw_item
        elif isinstance(raw_item, str):
            if len(raw_item.encode("utf-8", errors="replace")) > 2048:
                raise ValueError(f"{label} contains oversized text")
            result[raw_key] = raw_item
        elif isinstance(raw_item, Mapping):
            result[raw_key] = _safe_observation_mapping(
                raw_item, f"{label}.{raw_key}", depth=depth + 1
            )
        elif isinstance(raw_item, (list, tuple)):
            if len(raw_item) > 128:
                raise ValueError(f"{label}.{raw_key} exceeds its item bound")
            result[raw_key] = [
                _safe_observation_value(item, f"{label}.{raw_key}[]", depth + 1)
                for item in raw_item
            ]
        else:
            raise ValueError(f"{label} contains an unsupported value")
    encoded = canonical_json_bytes(result)
    if len(encoded) > _MAX_OBSERVABILITY_BYTES:
        raise ValueError(f"{label} exceeds its byte bound")
    return dict(sorted(result.items()))


def _safe_observation_value(value: object, label: str, depth: int) -> object:
    if depth > 6:
        raise ValueError(f"{label} exceeds its nesting bound")
    if value is None or type(value) in {bool, int, float}:
        if isinstance(value, float) and not math.isfinite(value):
            raise ValueError(f"{label} contains a non-finite number")
        return value
    if isinstance(value, str):
        if len(value.encode("utf-8", errors="replace")) > 2048:
            raise ValueError(f"{label} contains oversized text")
        return value
    if isinstance(value, Mapping):
        return _safe_observation_mapping(value, label, depth=depth)
    if isinstance(value, (list, tuple)) and len(value) <= 128:
        return [_safe_observation_value(item, label, depth + 1) for item in value]
    raise ValueError(f"{label} contains an unsupported value")


def _enum_value(value: object) -> str | None:
    raw = getattr(value, "value", value)
    return raw if isinstance(raw, str) and raw else None


def _bounded_digest(value: object) -> str | None:
    if not isinstance(value, str) or len(value) != 64:
        return None
    if any(char not in "0123456789abcdef" for char in value):
        return None
    return value


def _selection_id(value: object) -> str | None:
    """Project one selection invocation id into its bounded safe grammar."""

    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 128:
        return None
    if not value[0].isascii() or not value[0].isalnum():
        return None
    if any(
        not character.isascii() or not character.isalnum() and character not in "_.-"
        for character in value
    ):
        return None
    return value


def _selection_sequence(value: object) -> int | None:
    """Project one positive selection sequence, rejecting booleans."""

    return value if type(value) is int and value > 0 else None


def _selection_reason(value: object) -> str | None:
    """Project the closed Context Engine selection-reason vocabulary."""

    raw = _enum_value(value)
    return (
        raw
        if raw in {"BUILD", "INITIAL_BUILD", "REBALANCE", "CHILD_CONTEXT"}
        else None
    )


def _selection_identity_digest(
    selection_id: str | None,
    selection_sequence: int | None,
    selection_reason: str | None,
    selection_digest: str | None,
) -> str | None:
    """Digest only the safe identity tuple, never context contents."""

    if (
        selection_id is None
        or selection_sequence is None
        or selection_reason is None
        or selection_digest is None
    ):
        return None
    return canonical_digest(
        {
            "selection_id": selection_id,
            "selection_sequence": selection_sequence,
            "selection_reason": selection_reason,
            "selection_digest": selection_digest,
        }
    )


def _selection_history_entry(
    selection_id: str | None,
    selection_sequence: int | None,
    selection_reason: str | None,
    selection_digest: str | None,
) -> dict[str, object] | None:
    """Build one identity-only history row when all fields are valid."""

    if (
        selection_id is None
        or selection_sequence is None
        or selection_reason is None
        or selection_digest is None
    ):
        return None
    return {
        "selection_id": selection_id,
        "selection_sequence": selection_sequence,
        "selection_reason": selection_reason,
        "selection_digest": selection_digest,
    }


def _selection_history(value: object) -> list[dict[str, object]] | None:
    """Validate and copy bounded identity-only selection history."""

    if value is None:
        return None
    if not isinstance(value, (list, tuple)) or len(value) > _MAX_CONTEXT_SELECTION_HISTORY:
        return None
    result: list[dict[str, object]] = []
    for raw_entry in value:
        if not isinstance(raw_entry, Mapping):
            return None
        entry = _selection_history_entry(
            _selection_id(raw_entry.get("selection_id")),
            _selection_sequence(raw_entry.get("selection_sequence")),
            _selection_reason(raw_entry.get("selection_reason")),
            _bounded_digest(raw_entry.get("selection_digest")),
        )
        if entry is None:
            return None
        result.append(entry)
    return result


def _bounded_count(value: object) -> int | None:
    if isinstance(value, (list, tuple)) and len(value) <= 256:
        return len(value)
    return None


def _safe_identifier_list(value: object) -> list[str]:
    if not isinstance(value, (list, tuple)):
        return []
    result: list[str] = []
    for item in value[:32]:
        if isinstance(item, str) and item.strip():
            result.append(_bounded_identifier(item, "reason"))
    return sorted(set(result))


def _safe_path_list(value: object) -> list[str]:
    if isinstance(value, (str, bytes)) or value is None:
        values = [value]
    elif isinstance(value, Iterable):
        values = list(value)
    else:
        values = []
    result = {
        safe
        for item in values[:64]
        if (safe := _safe_relative_path_value(item)) is not None
    }
    return sorted(result)


def _safe_relative_path_value(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.replace("\\", "/").strip()
    if not normalized or normalized.startswith("/") or "://" in normalized:
        return "workspace:unsafe"
    first = normalized.split("/", 1)[0]
    if ":" in first:
        return "workspace:unsafe"
    parts = [part for part in normalized.split("/") if part not in {"", "."}]
    if any(part == ".." for part in parts):
        return "workspace:parent-reference"
    return "/".join(parts)[:512] or "workspace:root"


def _first_nonnegative(source: Mapping[str, object], *names: str) -> int | None:
    for name in names:
        value = source.get(name)
        if type(value) is int and value >= 0:
            return value
    return None


def _optional_nonnegative(value: object) -> int | None:
    return value if type(value) is int and value >= 0 else None


def _sum_optional_ints(values: Iterable[object]) -> int | None:
    """Sum present integer values without treating missing usage as zero."""

    present = [value for value in values if type(value) is int]
    return sum(cast(int, value) for value in present) if present else None


def _matched_count(source: Mapping[str, object]) -> int | None:
    value = _first_nonnegative(source, "matched_count")
    if value is not None:
        return value
    matched = source.get("matched_finding_ids")
    if isinstance(matched, (list, tuple)) and len(matched) <= 128:
        return len(matched)
    return None


def _completion_reason_code(status: str, reason: object) -> str:
    """Map untrusted completion text to a stable non-text reason class."""

    known = {
        "completed": "COMPLETED",
        "not_complete": "NOT_COMPLETE",
        "stale": "STALE",
        "authority_insufficient": "AUTHORITY_INSUFFICIENT",
        "already_terminal": "ALREADY_TERMINAL",
        "delegated_child_active": "DELEGATED_CHILD_ACTIVE",
        "rejected": "REJECTED",
        "error": "ERROR",
    }
    if status in known:
        return known[status]
    if isinstance(reason, str):
        lowered = reason.casefold()
        if "stale" in lowered or "mismatch" in lowered:
            return "STALE_OR_MISMATCH"
        if "authority" in lowered:
            return "AUTHORITY"
        if "decision" in lowered:
            return "DECISION"
        if "child" in lowered:
            return "DELEGATED_CHILD"
    return "UNCLASSIFIED"


def _safe_event_metadata(
    metadata: Mapping[str, object],
    *,
    allowed: set[str],
) -> dict[str, object]:
    """Copy only explicitly safe lifecycle fields from an event."""

    selected: dict[str, object] = {}
    for key in allowed:
        value = metadata.get(key)
        if value is None:
            continue
        if key.endswith("_digest") or key in {"plan_digest", "decision_digest"}:
            digest = _bounded_digest(value)
            if digest is not None:
                selected[key] = digest
        elif type(value) is bool or type(value) is int and value >= 0:
            selected[key] = value
        elif isinstance(value, str):
            selected[key] = _bounded_identifier(value, "value")
    return selected


__all__ = [
    "OBSERVABILITY_SCHEMA_VERSION",
    "TOOL_CATEGORIES",
    "CodingMetrics",
    "CodingTraceCollector",
    "CodingTraceEvent",
    "classify_tool",
]
