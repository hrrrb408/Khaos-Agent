from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from khaos.evaluation.coding import (
    AgentExecution,
    BenchmarkRunConfig,
    CodingBenchmarkJsonlWriter,
    CodingBenchmarkResultV1,
    CodingEvaluationRun,
    CodingFailureReason,
    CodingMetrics,
    CodingQualificationJsonlWriter,
    CodingQualificationRecordV1,
    CodingResultState,
    CodingRootCause,
    CodingRunIdentity,
    CodingVerdict,
    DiffSummary,
    aggregate_benchmark_results,
    capture_working_tree_identity,
    infer_root_cause,
    load_builtin_manifest,
)


def _provider_error_run() -> tuple[CodingEvaluationRun, object]:
    scenario = load_builtin_manifest().get("bugfix-python-cache")
    identity = CodingRunIdentity(
        run_id="m8-provider-error",
        scenario_id=scenario.scenario_id,
        scenario_version=scenario.version,
        scenario_digest=scenario.digest,
        oracle_spec_digest="a" * 64,
        fixture_digest="b" * 64,
        source_sha="3c1095ff69b1a5d800d96eb61e8b88a47fceca14",
        model="configured-model",
        provider="configured-provider",
        config_digest="c" * 64,
        runtime_profile="coding-evaluation",
        runtime_id="runtime-provider-error",
    )
    metrics = CodingMetrics(
        verdict=CodingVerdict.AGENT_ERROR,
        agent_status="ERROR",
        completion_status=None,
        wall_clock_ms=100,
        model_messages=0,
        tool_calls=0,
        tool_calls_by_category={},
        files_viewed=0,
        files_modified=0,
        tests_run=0,
        tests_passed=0,
        input_tokens=None,
        output_tokens=None,
        trace_event_count=0,
        trace_digest="d" * 64,
        task_success=False,
    )
    run = CodingEvaluationRun.new(
        identity=identity,
        scenario_kind=scenario.kind,
        fixture_base_revision="fixture-base",
        fixture_source_digest="e" * 64,
        evaluated_source_digest="f" * 64,
        verdict=CodingVerdict.AGENT_ERROR,
        agent=AgentExecution(
            status="ERROR",
            completion_status=None,
            final_root=Path("<persisted>"),
            runtime_id="runtime-provider-error",
            model="configured-model",
            provider="configured-provider",
            error="no available model for function: coding",
        ),
        metrics=metrics,
        oracle=None,
        diff=DiffSummary(
            changed_files=(),
            added_files=(),
            deleted_files=(),
            renamed_files=(),
            insertions=0,
            deletions=0,
            binary_files=(),
            digest="1" * 64,
        ),
        trace=(),
        started_at="2026-09-10T00:00:00+00:00",
        finished_at="2026-09-10T00:00:01+00:00",
        failure_reason=CodingFailureReason.PROVIDER_FAILURE,
    )
    return run, scenario


def _config() -> BenchmarkRunConfig:
    return BenchmarkRunConfig(
        provider="configured-provider",
        model="configured-model",
        khaos_sha="3c1095ff69b1a5d800d96eb61e8b88a47fceca14",
        scenario_manifest_digest=load_builtin_manifest().digest,
        config_digest="c" * 64,
        task_seed="test-seed",
        sampling={"temperature": 0.0},
        max_turns=128,
        task_timeout_seconds=120,
        tool_budget=512,
        network_policy="none",
        approval_policy="benchmark-local-approved",
    )


@pytest.mark.asyncio
async def test_benchmark_result_is_typed_and_secret_free(tmp_path) -> None:
    run, scenario = _provider_error_run()
    result = CodingBenchmarkResultV1.from_run(run, scenario, _config())

    assert result.result_state is CodingResultState.MODEL_ERROR
    assert result.failure_taxonomy.value == "PROVIDER_FAILURE"
    assert result.root_cause is CodingRootCause.PROVIDER_DEFECT
    payload = result.to_payload()
    assert "error" not in payload
    assert payload["schema_version"] == 1

    output = tmp_path / "benchmark.jsonl"
    await CodingBenchmarkJsonlWriter(output).append(result)
    line = output.read_text(encoding="utf-8")
    assert "no available model" not in line
    assert result.result_digest in line


def test_benchmark_result_maps_provider_timeout_to_model_error() -> None:
    run, scenario = _provider_error_run()
    run = replace(
        run,
        verdict=CodingVerdict.TIMEOUT,
        failure_reason=CodingFailureReason.PROVIDER_FAILURE,
        agent=replace(run.agent, status="TIMEOUT"),
        metrics=replace(
            run.metrics,
            verdict=CodingVerdict.TIMEOUT,
            agent_status="TIMEOUT",
        ),
        result_digest="",
    )

    result = CodingBenchmarkResultV1.from_run(run, scenario, _config())

    assert result.result_state is CodingResultState.MODEL_ERROR
    assert result.failure_taxonomy.value == "PROVIDER_FAILURE"
    assert result.root_cause is CodingRootCause.PROVIDER_DEFECT


def test_benchmark_config_binds_optional_working_tree_identity() -> None:
    config = BenchmarkRunConfig(
        provider="configured-provider",
        model="configured-model",
        khaos_sha="3c1095ff69b1a5d800d96eb61e8b88a47fceca14",
        scenario_manifest_digest=load_builtin_manifest().digest,
        config_digest="c" * 64,
        working_tree_identity="d" * 64,
    )

    assert config.to_payload()["working_tree_identity"] == "d" * 64
    without_identity = BenchmarkRunConfig(
        provider=config.provider,
        model=config.model,
        khaos_sha=config.khaos_sha,
        scenario_manifest_digest=config.scenario_manifest_digest,
        config_digest=config.config_digest,
    )
    assert config.digest != without_identity.digest


@pytest.mark.asyncio
async def test_qualification_jsonl_binds_safe_identity_and_is_canonical(tmp_path) -> None:
    manifest = load_builtin_manifest()
    scenario = manifest.get("p4-readonly-authority")
    record = CodingQualificationRecordV1(
        run_id="m8-qualification-offline",
        result_state=CodingResultState.SUCCESS,
        provider="offline-fake",
        model="deterministic-review-model",
        source_sha="3c1095ff69b1a5d800d96eb61e8b88a47fceca14",
        working_tree_identity=None,
        provider_config_digest="c" * 64,
        suite_id="m8-provider-qualification",
        suite_version=2,
        suite_digest="a" * 64,
        scenario_id=scenario.scenario_id,
        scenario_version=scenario.version,
        scenario_digest=scenario.digest,
        fixture_digest="b" * 64,
        prompt_digest="d" * 64,
        system_prompt_digest="e" * 64,
        tool_schema_digest="f" * 64,
        policy_digest="1" * 64,
        budgets={"max_model_turns": 12, "max_tool_calls": 24},
        timeout_seconds=300,
        credential_ref="khaos/providers/offline-fake/default",
        reasoning_configuration={"reasoning_effort": "offline"},
        metrics={"provider_requests": 0, "secret_values_printed": False},
        stages=({"probe": "P4", "result": "PASS"},),
        started_at="2026-09-12T00:00:00+00:00",
        finished_at="2026-09-12T00:00:01+00:00",
    )

    output = tmp_path / "qualification.jsonl"
    await CodingQualificationJsonlWriter(output).append(record)
    raw = output.read_bytes()
    assert raw.endswith(b"\n")
    payload = json.loads(raw)
    assert payload["record_type"] == "coding_qualification"
    assert payload["scenario_id"] == "p4-readonly-authority"
    assert payload["policy_digest"] == "1" * 64
    assert payload["credential_ref"] == "khaos/providers/offline-fake/default"
    assert payload["record_digest"] == record.record_digest
    assert raw.decode("utf-8") == json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ) + "\n"
    restored = CodingQualificationRecordV1.from_payload(payload)
    assert restored.record_digest == record.record_digest
    assert restored.to_payload() == payload


def test_historical_qualification_payload_without_observability_remains_readable() -> None:
    manifest = load_builtin_manifest()
    scenario = manifest.get("p4-readonly-authority")
    record = CodingQualificationRecordV1(
        run_id="m8-qualification-legacy",
        result_state=CodingResultState.FAILURE,
        provider="offline-provider",
        model="offline-model",
        source_sha="3c1095ff69b1a5d800d96eb61e8b88a47fceca14",
        working_tree_identity=None,
        provider_config_digest=None,
        suite_id="m8-provider-qualification",
        suite_version=2,
        suite_digest="a" * 64,
        scenario_id=scenario.scenario_id,
        scenario_version=scenario.version,
        scenario_digest=scenario.digest,
        fixture_digest=None,
        prompt_digest=None,
        system_prompt_digest=None,
        tool_schema_digest=None,
        policy_digest=None,
        budgets={"max_tool_calls": 24},
        timeout_seconds=300,
        credential_ref=None,
        reasoning_configuration={},
        metrics={"provider_requests": 0},
        stages=(),
        started_at="2026-09-12T00:00:00+00:00",
        finished_at="2026-09-12T00:00:01+00:00",
    )

    payload = record.to_payload()
    assert "observability_schema_version" not in payload
    restored = CodingQualificationRecordV1.from_payload(payload)
    assert restored.observability_schema_version is None
    assert restored.record_digest == record.record_digest


def test_qualification_record_rejects_credential_shaped_artifacts() -> None:
    with pytest.raises(ValueError, match="credential-shaped"):
        CodingQualificationRecordV1(
            run_id="m8-qualification-unsafe",
            result_state=CodingResultState.FAILURE,
            provider="offline-fake",
            model="deterministic-model",
            source_sha="3c1095ff69b1a5d800d96eb61e8b88a47fceca14",
            suite_id="m8-provider-qualification",
            suite_version=2,
            suite_digest="a" * 64,
            scenario_id="p4-readonly-authority",
            scenario_version=2,
            scenario_digest="b" * 64,
            working_tree_identity=None,
            provider_config_digest="c" * 64,
            fixture_digest="d" * 64,
            prompt_digest="e" * 64,
            system_prompt_digest="f" * 64,
            tool_schema_digest="0" * 64,
            policy_digest=None,
            budgets={"max_tool_calls": 24},
            timeout_seconds=300,
            credential_ref=None,
            reasoning_configuration={},
            metrics={"api_key": "must never be accepted"},
            stages=(),
            started_at="2026-09-12T00:00:00+00:00",
            finished_at="2026-09-12T00:00:01+00:00",
        )


def test_working_tree_identity_binds_dirty_content_and_respects_exclusions(
    tmp_path,
    monkeypatch,
) -> None:
    tracked = tmp_path / "tracked.py"
    protected = tmp_path / "protected.txt"
    tracked.write_text("before\n", encoding="utf-8")
    protected.write_text("protected-before\n", encoding="utf-8")

    def fake_run(command, **_kwargs):
        if command[1] == "rev-parse":
            return SimpleNamespace(returncode=0, stdout=b"head-sha\n")
        return SimpleNamespace(
            returncode=0,
            stdout=b"tracked.py\0protected.txt\0",
        )

    monkeypatch.setattr(
        "khaos.evaluation.coding.benchmark.subprocess.run",
        fake_run,
    )
    before = capture_working_tree_identity(
        tmp_path,
        excluded_paths=("protected.txt",),
    )
    protected.write_text("protected-after\n", encoding="utf-8")
    assert capture_working_tree_identity(
        tmp_path,
        excluded_paths=("protected.txt",),
    ) == before
    tracked.write_text("after\n", encoding="utf-8")
    assert capture_working_tree_identity(
        tmp_path,
        excluded_paths=("protected.txt",),
    ) != before


def test_benchmark_aggregate_keeps_security_outcome_separate() -> None:
    run, scenario = _provider_error_run()
    config = _config()
    result = CodingBenchmarkResultV1.from_run(run, scenario, config)
    security_result = CodingBenchmarkResultV1.from_run(
        run,
        scenario,
        config,
        root_cause=CodingRootCause.HARNESS_DEFECT,
        security_violation=True,
    )

    summary = aggregate_benchmark_results((result, security_result))

    assert summary["run_count"] == 2
    assert summary["security_failure_count"] == 1
    assert summary["state_counts"] == {"MODEL_ERROR": 1, "SECURITY_FAILURE": 1}
    assert summary["wall_clock_ms"]["p50"] == 100


def test_benchmark_root_cause_supports_provider_defect() -> None:
    run, scenario = _provider_error_run()
    result = CodingBenchmarkResultV1.from_run(
        run,
        scenario,
        _config(),
        root_cause=CodingRootCause.PROVIDER_DEFECT,
    )

    assert result.to_payload()["root_cause"] == "PROVIDER_DEFECT"


@pytest.mark.parametrize(
    ("verdict", "failure_reason", "agent_status", "expected"),
    (
        (
            CodingVerdict.TIMEOUT,
            CodingFailureReason.TIMEOUT,
            "TIMEOUT",
            CodingRootCause.MODEL_REASONING_LIMIT,
        ),
        (
            CodingVerdict.AGENT_ERROR,
            CodingFailureReason.TOOL_BUDGET_EXHAUSTED,
            "TOOL_BUDGET_EXHAUSTED",
            CodingRootCause.MODEL_TOOL_USE_LIMIT,
        ),
        (
            CodingVerdict.INVALID_FIXTURE,
            CodingFailureReason.INVALID_FIXTURE,
            "INVALID_FIXTURE",
            CodingRootCause.BENCHMARK_DEFECT,
        ),
        (
            CodingVerdict.ORACLE_ERROR,
            CodingFailureReason.ORACLE_ERROR,
            "COMPLETED",
            CodingRootCause.UNKNOWN,
        ),
    ),
)
def test_infer_root_cause_is_conservative_and_typed(
    verdict: CodingVerdict,
    failure_reason: CodingFailureReason,
    agent_status: str,
    expected: CodingRootCause,
) -> None:
    run, scenario = _provider_error_run()
    run = replace(
        run,
        verdict=verdict,
        failure_reason=failure_reason,
        agent=replace(run.agent, status=agent_status),
        metrics=replace(run.metrics, verdict=verdict, agent_status=agent_status),
        result_digest="",
    )

    assert infer_root_cause(run) is expected
    result = CodingBenchmarkResultV1.from_run(run, scenario, _config())
    assert result.root_cause is expected
