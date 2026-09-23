from __future__ import annotations

from pathlib import Path

import pytest

from khaos.evaluation.coding import (
    AgentExecution,
    CodingEvaluationRun,
    CodingMetrics,
    CodingRunIdentity,
    CodingScenarioKind,
    CodingVerdict,
    DiffSummary,
    compare_runs,
)


def _run(*, run_id: str, version: int = 1, tool_calls: int = 1) -> CodingEvaluationRun:
    identity = CodingRunIdentity(
        run_id=run_id,
        scenario_id="report-scenario",
        scenario_version=version,
        scenario_digest="a" * 64,
        oracle_spec_digest="b" * 64,
        fixture_digest="c" * 64,
        source_sha="source-sha",
        model="fake-model",
        provider="fake-provider",
        config_digest="d" * 64,
        runtime_profile="testing",
        runtime_id="runtime",
    )
    metrics = CodingMetrics(
        verdict=CodingVerdict.PASS,
        agent_status="COMPLETED",
        completion_status="completed",
        wall_clock_ms=100,
        model_messages=1,
        tool_calls=tool_calls,
        tool_calls_by_category={"editing": tool_calls},
        files_viewed=0,
        files_modified=tool_calls,
        tests_run=1,
        tests_passed=1,
        input_tokens=10,
        output_tokens=5,
        trace_event_count=0,
        trace_digest="e" * 64,
        task_success=True,
    )
    return CodingEvaluationRun.new(
        identity=identity,
        scenario_kind=CodingScenarioKind.BUG_FIX,
        fixture_base_revision="base",
        fixture_source_digest="f" * 64,
        evaluated_source_digest="0" * 64,
        verdict=CodingVerdict.PASS,
        agent=AgentExecution(
            status="COMPLETED",
            completion_status="completed",
            final_root=Path("<persisted>"),
            runtime_id="runtime",
            model="fake-model",
            provider="fake-provider",
        ),
        metrics=metrics,
        oracle=None,
        diff=DiffSummary(
            changed_files=("src/bug.py",),
            added_files=(),
            deleted_files=(),
            renamed_files=(),
            insertions=2,
            deletions=1,
            binary_files=(),
            digest="1" * 64,
        ),
        trace=(),
        started_at="2026-09-01T00:00:00+00:00",
        finished_at="2026-09-01T00:00:01+00:00",
    )


def test_compare_reports_metric_deltas_for_same_scenario_version() -> None:
    comparison = compare_runs(_run(run_id="m8-baseline"), _run(run_id="m8-candidate", tool_calls=3))

    assert comparison.scenario_id == "report-scenario"
    assert comparison.scenario_version == 1
    assert comparison.numeric_deltas["tool_calls"] == 2
    assert comparison.numeric_deltas["changed_lines"] == 0
    assert comparison.numeric_deltas["input_tokens"] == 0


def test_compare_rejects_scenario_version_mismatch() -> None:
    with pytest.raises(ValueError, match="same scenario_id"):
        compare_runs(_run(run_id="m8-baseline"), _run(run_id="m8-candidate", version=2))
