"""Bounded black-box effort and outcome metrics for Coding evaluation."""

from __future__ import annotations

import time
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass, field

from khaos.evaluation.coding.contracts import CodingVerdict
from khaos.security.protocol_boundary import canonical_digest


TOOL_CATEGORIES = frozenset({"editing", "verification", "context", "recovery", "other"})
_DETAILED_TOOL_NAMES = frozenset(
    {
        "read_file",
        "search_files",
        "code_search",
        "code_symbols",
        "write_file",
        "patch",
        "multi_edit",
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
    """Map a tool name to a stable, non-content effort category."""

    lowered = name.casefold()
    if any(token in lowered for token in ("write", "patch", "edit", "delete", "move", "copy")):
        return "editing"
    if any(token in lowered for token in ("test", "verify", "lint", "format", "build", "check")):
        return "verification"
    if any(token in lowered for token in ("recover", "retry", "replan", "cancel")):
        return "recovery"
    if any(token in lowered for token in ("read", "search", "list", "tree", "symbol", "file_info", "diff", "log", "status")):
        return "context"
    return "other"


def _detailed_tool_name(name: str) -> str:
    """Normalize related tool names into the bounded report vocabulary."""

    lowered = name.casefold()
    if lowered in _DETAILED_TOOL_NAMES:
        return lowered
    if lowered.startswith("git_"):
        return "git"
    if lowered.startswith("browser_"):
        return "browser"
    if lowered.startswith(("spawn_", "delegate_", "subagent_")):
        return "subagent"
    if lowered in {"file_search_content", "list_directory", "file_info", "tree_view"}:
        return "search_files"
    return "other"


@dataclass(frozen=True, slots=True)
class CodingTraceEvent:
    """A sanitized trace event; arguments and source text are never retained."""

    sequence: int
    kind: str
    name: str
    success: bool | None = None
    duration_ms: int | None = None
    operation_digest: str = ""

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

    def to_payload(self) -> dict[str, object]:
        return {
            "sequence": self.sequence,
            "kind": self.kind,
            "name": self.name,
            "success": self.success,
            "duration_ms": self.duration_ms,
            "operation_digest": self.operation_digest,
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
    tool_calls_by_name: Mapping[str, int] = field(default_factory=dict)
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

    def __post_init__(self) -> None:
        if not isinstance(self.verdict, CodingVerdict):
            raise ValueError("coding metric verdict is invalid")
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
        )
        if any(
            type(getattr(self, name)) is not int or getattr(self, name) < 0
            for name in count_fields
        ):
            raise ValueError("coding metrics contain a negative or malformed count")
        if not isinstance(self.tool_calls_by_category, Mapping):
            raise ValueError("coding tool category metrics are invalid")
        if not isinstance(self.tool_calls_by_name, Mapping):
            raise ValueError("coding tool name metrics are invalid")
        unknown = set(self.tool_calls_by_category) - TOOL_CATEGORIES
        if unknown or any(type(value) is not int or value < 0 for value in self.tool_calls_by_category.values()):
            raise ValueError("coding tool category metrics are invalid")
        if any(
            not isinstance(name, str) or not name or type(value) is not int or value < 0
            for name, value in self.tool_calls_by_name.items()
        ):
            raise ValueError("coding tool name metrics are invalid")
        object.__setattr__(self, "tool_calls_by_category", dict(self.tool_calls_by_category))
        object.__setattr__(self, "tool_calls_by_name", dict(self.tool_calls_by_name))
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
        ):
            value = getattr(self, name)
            if value is not None and (type(value) is not int or value < 0):
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
            "tool_calls_by_name": dict(sorted(self.tool_calls_by_name.items())),
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
        }


class CodingTraceCollector:
    """Collect bounded operation metadata from the real AgentLoop stream."""

    def __init__(
        self,
        *,
        max_events: int = 2048,
        max_model_turns: int = 128,
        max_tool_calls: int = 512,
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
        self._events: list[CodingTraceEvent] = []
        self._model_calls = 0
        self._model_turns = 0
        self._seen_model_response_ids: set[str] = set()
        self._tool_calls = 0
        self._seen_tool_call_ids: set[str] = set()
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
        self._repo_metrics: dict[str, int] | None = None
        self._started = time.monotonic()

    @property
    def events(self) -> tuple[CodingTraceEvent, ...]:
        return tuple(self._events)

    def record_message(self, message: object) -> None:
        """Observe an AgentLoop message without storing content or arguments."""

        role = str(getattr(message, "role", "message"))
        event = str(getattr(message, "event", "") or "")
        # AgentLoop emits a short streamed ``tool_call`` projection and then
        # one complete assistant message for the same model response.  Count
        # the complete response once as both the model call and turn.
        if role == "assistant" and event != "tool_call":
            raw_metadata = getattr(message, "metadata", {}) or {}
            metadata = raw_metadata if isinstance(raw_metadata, Mapping) else {}
            turn_id = str(metadata.get("turn_id") or "")
            attempt_id = str(metadata.get("attempt_id") or "")
            response_id = f"{turn_id}:{attempt_id}" if turn_id or attempt_id else ""
            if not response_id or response_id not in self._seen_model_response_ids:
                if response_id:
                    self._seen_model_response_ids.add(response_id)
                if self._model_turns >= self.max_model_turns:
                    raise ValueError("coding model-turn bound exceeded")
                self._model_calls += 1
                self._model_turns += 1
        calls = getattr(message, "tool_calls", ()) or ()
        for call in calls:
            function = call.get("function") if isinstance(call, dict) else None
            function_name = function.get("name") if isinstance(function, dict) else None
            name = str(call.get("name") or function_name or "unknown") if isinstance(call, dict) else "unknown"
            call_id = ""
            if isinstance(call, dict):
                call_id = str(call.get("id") or call.get("tool_call_id") or "")
            if call_id and call_id in self._seen_tool_call_ids:
                continue
            if call_id:
                self._seen_tool_call_ids.add(call_id)
            if self._tool_calls >= self.max_tool_calls:
                raise ValueError("coding tool-call bound exceeded")
            category = classify_tool(name)
            self._tool_calls += 1
            self._tool_categories[category] += 1
            self._tool_names[_detailed_tool_name(name)] += 1
            self._mark_first("tool")
            self._record(
                "tool_call",
                name,
                operation_digest=canonical_digest({"name": name, "sequence": len(self._events)}),
            )
        if role == "tool":
            raw_metadata = getattr(message, "metadata", {}) or {}
            metadata = raw_metadata if isinstance(raw_metadata, Mapping) else {}
            name = str(metadata.get("name", "tool"))
            success = metadata.get("success")
            duration = metadata.get("duration_ms")
            category = classify_tool(name)
            self._record(
                "tool_result",
                name,
                success=success if isinstance(success, bool) else None,
                duration_ms=duration if type(duration) is int and duration >= 0 else None,
            )
            if success is not True:
                self._failed_tool_calls += 1
            error_code = str(metadata.get("error_code") or "").casefold()
            error_text = str(metadata.get("error") or "").casefold()
            if (
                "permission" in error_code
                or "denied" in error_code
                or "forbidden" in error_code
                or "permission" in error_text
                or "denied" in error_text
            ):
                self._permission_denials += 1
            if category == "context":
                self._files_viewed += 1
                self._mark_first("read")
            elif category == "editing":
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
            self._tool_categories[category] += 0
        elif event:
            self._record_agent_event(event)
            self._record("agent_event", event)

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
        self._record(kind, name, success=success, duration_ms=duration_ms)

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
        tool_names = dict(self._tool_names)
        category = dict(self._tool_categories)
        repo_metrics = self._repo_metrics or {}
        detailed = {
            "read_file_calls": tool_names.get("read_file", 0),
            "search_calls": tool_names.get("search_files", 0),
            "code_search_calls": tool_names.get("code_search", 0),
            "symbol_calls": tool_names.get("code_symbols", 0),
            "write_calls": tool_names.get("write_file", 0),
            "patch_calls": tool_names.get("patch", 0) + tool_names.get("multi_edit", 0),
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
            "git_calls": tool_names.get("git", 0),
            "browser_calls": tool_names.get("browser", 0),
            "subagent_calls": tool_names.get("subagent", 0),
        }
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
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            trace_event_count=len(self._events),
            trace_digest=canonical_digest([event.to_payload() for event in self._events]),
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
            total_tokens=(
                input_tokens + output_tokens
                if input_tokens is not None and output_tokens is not None
                else None
            ),
            tool_calls_by_name=tool_names,
            **detailed,
            editing_calls=category.get("editing", 0),
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
            context_selected_file_count=repo_metrics.get("context_selected_file_count"),
            context_selected_symbol_count=repo_metrics.get("context_selected_symbol_count"),
            replan_count=self._replan_count,
            recovery_count=self._recovery_count,
            no_progress_count=self._no_progress_count,
            completion_rejections=self._completion_rejections,
            completion_acceptances=self._completion_acceptances,
            approval_intervention_count=self._approval_count,
            diff_changed_files=diff_changed_files,
            diff_insertions=diff_insertions,
            diff_deletions=diff_deletions,
        )

    def _record_agent_event(self, event: str) -> None:
        normalized = event.casefold().replace(".", "_")
        if normalized in {"permission_request", "approval_wait"}:
            self._approval_count += 1
        elif normalized in {"completion_rejected", "completion_rejection"}:
            self._completion_rejections += 1
        elif normalized in {"completion_accepted", "completion_acceptance"}:
            self._completion_acceptances += 1
        elif "no_progress" in normalized:
            self._no_progress_count += 1
        if "replan" in normalized:
            self._replan_count += 1
        if "recover" in normalized or normalized.startswith("recovery"):
            self._recovery_count += 1

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

    def _record(self, kind: str, name: str, *, success: bool | None = None, duration_ms: int | None = None, operation_digest: str = "") -> None:
        if len(self._events) >= self.max_events:
            raise ValueError("coding trace event bound exceeded")
        if not name or len(name.encode("utf-8")) > 512:
            raise ValueError("coding trace name is invalid")
        self._events.append(
            CodingTraceEvent(
                sequence=len(self._events) + 1,
                kind=kind,
                name=name,
                success=success,
                duration_ms=duration_ms,
                operation_digest=operation_digest,
            )
        )


__all__ = [
    "CodingMetrics",
    "CodingTraceCollector",
    "CodingTraceEvent",
    "TOOL_CATEGORIES",
    "classify_tool",
]
