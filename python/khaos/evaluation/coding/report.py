"""Machine-readable reports and same-scenario comparisons for M8.0."""

from __future__ import annotations

import json
from dataclasses import dataclass
from statistics import median
from typing import Iterable

from khaos.evaluation.coding.results import CodingEvaluationRun
from khaos.security.protocol_boundary import canonical_json_bytes


@dataclass(frozen=True, slots=True)
class CodingComparison:
    """Metrics delta for two runs of the exact same scenario version."""

    scenario_id: str
    scenario_version: int
    baseline_run_id: str
    candidate_run_id: str
    verdict_changed: bool
    numeric_deltas: dict[str, int]

    def to_payload(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "scenario_id": self.scenario_id,
            "scenario_version": self.scenario_version,
            "baseline_run_id": self.baseline_run_id,
            "candidate_run_id": self.candidate_run_id,
            "verdict_changed": self.verdict_changed,
            "numeric_deltas": dict(sorted(self.numeric_deltas.items())),
        }


def compare_runs(baseline: CodingEvaluationRun, candidate: CodingEvaluationRun) -> CodingComparison:
    """Compare only matching scenario id/version; otherwise fail closed."""

    if (
        baseline.identity.scenario_id != candidate.identity.scenario_id
        or baseline.identity.scenario_version != candidate.identity.scenario_version
        or baseline.identity.scenario_digest != candidate.identity.scenario_digest
    ):
        raise ValueError("coding compare requires the same scenario_id, version, and digest")
    left = baseline.metrics
    right = candidate.metrics
    numeric = {
        "task_success": int(right.task_success) - int(left.task_success),
        "wall_clock_ms": right.wall_clock_ms - left.wall_clock_ms,
        "model_messages": right.model_messages - left.model_messages,
        "model_calls": right.model_calls - left.model_calls,
        "model_turns": right.model_turns - left.model_turns,
        "tool_calls": right.tool_calls - left.tool_calls,
        "failed_tool_calls": right.failed_tool_calls - left.failed_tool_calls,
        "approval_count": right.approval_count - left.approval_count,
        "permission_denials": right.permission_denials - left.permission_denials,
        "repair_cycles": right.repair_cycles - left.repair_cycles,
        "editing_calls": right.editing_calls - left.editing_calls,
        "verification_calls": right.verification_calls - left.verification_calls,
        "recovery_calls": right.recovery_calls - left.recovery_calls,
        "edit_attempts": right.edit_attempts - left.edit_attempts,
        "failed_edit_attempts": right.failed_edit_attempts - left.failed_edit_attempts,
        "files_viewed": right.files_viewed - left.files_viewed,
        "files_modified": right.files_modified - left.files_modified,
        "tests_run": right.tests_run - left.tests_run,
        "tests_passed": right.tests_passed - left.tests_passed,
        "changed_files": len(candidate.diff.changed_files) - len(baseline.diff.changed_files),
        "changed_lines": (
            candidate.diff.insertions + candidate.diff.deletions
            - baseline.diff.insertions - baseline.diff.deletions
        ),
        "oracle_pass_count": right.oracle_pass_count - left.oracle_pass_count,
        "oracle_fail_count": right.oracle_fail_count - left.oracle_fail_count,
    }
    if left.input_tokens is not None and right.input_tokens is not None:
        numeric["input_tokens"] = right.input_tokens - left.input_tokens
    if left.output_tokens is not None and right.output_tokens is not None:
        numeric["output_tokens"] = right.output_tokens - left.output_tokens
    for name in (
        "time_to_first_tool_ms",
        "time_to_first_read_ms",
        "time_to_first_edit_ms",
        "time_to_first_test_ms",
        "time_to_first_green_ms",
    ):
        left_value = getattr(left, name)
        right_value = getattr(right, name)
        if left_value is not None and right_value is not None:
            numeric[name] = right_value - left_value
    return CodingComparison(
        scenario_id=baseline.identity.scenario_id,
        scenario_version=baseline.identity.scenario_version,
        baseline_run_id=baseline.identity.run_id,
        candidate_run_id=candidate.identity.run_id,
        verdict_changed=baseline.verdict != candidate.verdict,
        numeric_deltas=numeric,
    )


def report_payload(runs: Iterable[CodingEvaluationRun]) -> dict[str, object]:
    """Build a report payload from immutable ledger values."""

    values = tuple(runs)
    pass_count = sum(run.verdict.value == "PASS" for run in values)
    durations = [run.metrics.wall_clock_ms for run in values]
    tool_counts = [run.metrics.tool_calls for run in values]
    model_turns = [run.metrics.model_turns for run in values]
    return {
        "schema_version": 1,
        "run_count": len(values),
        "summary": {
            "pass_count": pass_count,
            "success_rate": (pass_count / len(values)) if values else None,
            "verdict_counts": {
                verdict: sum(run.verdict.value == verdict for run in values)
                for verdict in sorted({run.verdict.value for run in values})
            },
            "median_wall_clock_ms": median(durations) if durations else None,
            "median_tool_calls": median(tool_counts) if tool_counts else None,
            "median_model_turns": median(model_turns) if model_turns else None,
            "median_changed_files": median(len(run.diff.changed_files) for run in values) if values else None,
            "median_changed_lines": median(
                run.diff.insertions + run.diff.deletions for run in values
            ) if values else None,
            "median_repair_cycles": median(
                run.metrics.repair_cycles for run in values
            ) if values else None,
        },
        "runs": [run.to_payload() for run in values],
    }


def report_json(runs: Iterable[CodingEvaluationRun], *, pretty: bool = False) -> str:
    """Serialize a report canonically or as human-readable JSON."""

    payload = report_payload(runs)
    if pretty:
        return json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2)
    return canonical_json_bytes(payload).decode("utf-8")


def report_markdown(runs: Iterable[CodingEvaluationRun]) -> str:
    """Render concise Markdown without source text or hidden oracle output."""

    values = tuple(runs)
    pass_count = sum(run.verdict.value == "PASS" for run in values)
    durations = [run.metrics.wall_clock_ms for run in values]
    tool_counts = [run.metrics.tool_calls for run in values]
    model_turns = [run.metrics.model_turns for run in values]
    lines = [
        "# M8.0 Coding Capability Evaluation",
        "",
        f"Overall: PASS {pass_count}/{len(values)}" if values else "Overall: no runs",
        f"Median duration: {int(median(durations))} ms" if durations else "Median duration: N/A",
        f"Median tool calls: {int(median(tool_counts))}" if tool_counts else "Median tool calls: N/A",
        f"Median model turns: {int(median(model_turns))}" if model_turns else "Median model turns: N/A",
        "",
        "| Scenario | Version | Verdict | Failure | Oracle | Tools | Tests | Changed files | Run |",
        "| --- | ---: | --- | --- | --- | ---: | ---: | ---: | --- |",
    ]
    for run in values:
        oracle = run.oracle.verdict.value if run.oracle is not None else "N/A"
        lines.append(
            f"| `{run.identity.scenario_id}` | {run.identity.scenario_version} | "
            f"{run.verdict.value} | {run.failure_reason.value if run.failure_reason else '-'} | "
            f"{oracle} | {run.metrics.tool_calls} | "
            f"{run.metrics.tests_passed}/{run.metrics.tests_run} | "
            f"{len(run.diff.changed_files)} | `{run.identity.run_id}` |"
        )
    lines.extend(("", "Evidence is observation-only; Completion/Verification/Recovery authorities are independent."))
    return "\n".join(lines) + "\n"


__all__ = ["CodingComparison", "compare_runs", "report_json", "report_markdown", "report_payload"]
