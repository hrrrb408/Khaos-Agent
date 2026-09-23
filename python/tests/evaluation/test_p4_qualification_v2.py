from __future__ import annotations

import json

import pytest
from khaos.evaluation.coding import (
    CodingQualificationJsonlWriter,
    CodingQualificationRecordV1,
    CodingResultState,
    FixtureManager,
    ReviewFinding,
    builtin_manifest_path,
    evaluate_p4_v2_findings,
    load_builtin_manifest,
)
from khaos.evaluation.coding import qualification as qualification_module
from khaos.evaluation.coding.qualification import (
    _provider_failure_class,
    _qualification_payload,
)
from khaos.evaluation.coding.runtime_invoker import (
    _extract_review_findings,
    _extract_review_findings_with_observation,
)
from khaos.routing.model_client import ProviderRequestObservation


def _correct_findings() -> tuple[ReviewFinding, ...]:
    return (
        ReviewFinding(
            category="authority-definition",
            file="src/authority.py",
            concepts=("AuthorityLease", "issue_lease", "definition"),
        ),
        ReviewFinding(
            category="authority-consumer",
            file="src/consumer.py",
            concepts=("consume_lease", "AuthorityLease", "consumer"),
        ),
        ReviewFinding(
            category="enforcement-boundary",
            file="src/policy.py",
            concepts=("require_active", "project_id", "invariant"),
            severity="high",
        ),
    )


@pytest.mark.parametrize("effort_label", ("efficient", "normal"))
def test_p4_v2_accepts_correct_evidence_without_effort_targets(
    effort_label: str,
) -> None:
    scenario = load_builtin_manifest().get("p4-readonly-authority")

    passed, evidence = evaluate_p4_v2_findings(
        _correct_findings(),
        scenario.oracle,
        completed=True,
        side_effect_free=True,
    )

    assert passed, effort_label
    assert evidence["matched_finding_ids"] == [
        "authority-definition",
        "authority-consumer",
        "enforcement-boundary",
    ]
    assert evidence["extra_finding_count"] == 0


def test_p4_v2_rejects_wrong_answer_and_side_effects() -> None:
    scenario = load_builtin_manifest().get("p4-readonly-authority")
    wrong = (
        ReviewFinding(
            category="unrelated",
            file="src/unrelated.py",
            concepts=("format_label",),
        ),
    )

    wrong_passed, wrong_evidence = evaluate_p4_v2_findings(
        wrong,
        scenario.oracle,
        completed=True,
        side_effect_free=True,
    )
    side_effect_passed, side_effect_evidence = evaluate_p4_v2_findings(
        _correct_findings(),
        scenario.oracle,
        completed=True,
        side_effect_free=False,
    )

    assert wrong_passed is False
    assert wrong_evidence["review_findings_pass"] is False
    assert side_effect_passed is False
    assert side_effect_evidence["read_only_invariant"] is False


def test_review_parser_observation_preserves_typed_result_and_counts() -> None:
    raw = (
        '{"findings":[{"category":"authority-definition",'
        '"file":"src/authority.py","concepts":["AuthorityLease"]}]}'
    )

    findings, observation = _extract_review_findings_with_observation([raw])

    assert findings == _extract_review_findings([raw])
    assert len(findings) == 1
    assert observation["format"] == "PLAIN_JSON_OBJECT"
    assert observation["parse_attempted"] is True
    assert observation["json_decode_status"] == "PASS"
    assert observation["schema_validation_status"] == "PASS"
    assert observation["typed_parse_status"] == "PASS"
    assert observation["typed_finding_count"] == 1
    assert observation["all_required_fields_present"] is True


def test_review_parser_accepts_json_split_across_stream_chunks() -> None:
    raw = (
        '{"findings":[{"category":"authority-definition",'
        '"file":"src/authority.py","concepts":["AuthorityLease"]}]}'
    )
    chunks = [raw[:13], raw[13:]]

    findings, observation = _extract_review_findings_with_observation(chunks)

    assert len(findings) == 1
    assert findings[0].file == "src/authority.py"
    assert observation["format"] == "PLAIN_JSON_OBJECT"
    assert observation["json_decode_status"] == "PASS"
    assert observation["schema_validation_status"] == "PASS"
    assert observation["typed_parse_status"] == "PASS"
    assert observation["typed_finding_count"] == 1


def test_review_parser_accepts_fenced_json_split_across_stream_chunks() -> None:
    raw = (
        "```json\n"
        '{"findings":[{"category":"authority-definition",'
        '"file":"src/authority.py","concepts":["AuthorityLease"]}]}'
        "\n```"
    )
    chunks = [raw[:9], raw[9:31], raw[31:]]

    findings, observation = _extract_review_findings_with_observation(chunks)

    assert len(findings) == 1
    assert observation["format"] == "FENCED_JSON"
    assert observation["json_decode_status"] == "PASS"
    assert observation["schema_validation_status"] == "PASS"
    assert observation["typed_parse_status"] == "PASS"


@pytest.mark.parametrize(
    ("raw", "response_format", "error_code"),
    (
        ("", "EMPTY", "EMPTY_RESPONSE"),
        ("plain answer", "NON_JSON_TEXT", "INVALID_JSON"),
        ('{"findings":', "NON_JSON_TEXT", "INVALID_JSON"),
        ("42", "PLAIN_JSON_VALUE", "WRONG_TOP_LEVEL_TYPE"),
        ('{"answer":true}', "PLAIN_JSON_OBJECT", "MISSING_FINDINGS"),
        (
            '{"findings":[{"category":"x","file":"src/x.py","concepts":[]}]}',
            "PLAIN_JSON_OBJECT",
            "INVALID_FINDING",
        ),
        ("```json\n[]\n```", "FENCED_JSON", None),
        (
            (
                '{"findings":[{"category":"x","file":"src/x.py",'
                '"concepts":["concept"],"unknown":"value"}]}'
            ),
            "PLAIN_JSON_OBJECT",
            "UNKNOWN_FIELD",
        ),
    ),
)
def test_review_parser_observes_shape_only_failure_codes(
    raw: str,
    response_format: str,
    error_code: str | None,
) -> None:
    _findings, observation = _extract_review_findings_with_observation([raw])

    assert observation["format"] == response_format
    assert observation["parse_attempted"] is True
    assert observation["parse_error_code"] == error_code


@pytest.mark.parametrize(
    ("status_code", "provider_error_type", "expected"),
    (
        (401, None, "PROVIDER_AUTHENTICATION"),
        (404, None, "PROVIDER_INVALID_MODEL_OR_ENDPOINT"),
        (413, None, "PROVIDER_CONTEXT_LIMIT"),
        (429, None, "PROVIDER_RATE_LIMIT"),
        (503, "internal_error", "PROVIDER_INTERNAL_ERROR"),
        (None, "transport_error", "PROVIDER_TRANSPORT"),
    ),
)
def test_provider_failure_mapping_preserves_infrastructure_categories(
    status_code: int | None,
    provider_error_type: str | None,
    expected: str,
) -> None:
    observation = ProviderRequestObservation(
        provider="offline-provider",
        model="offline-model",
        attempt=1,
        max_attempts=1,
        status_code=status_code,
        started_at="2026-09-12T00:00:00+00:00",
        latency_ms=1,
        first_byte_latency_ms=None,
        retryable=False,
        provider_error_type=provider_error_type,
    )

    assert _provider_failure_class((observation,)) == expected


def test_provider_failure_mapping_preserves_timeout_category() -> None:
    assert _provider_failure_class((), TimeoutError("offline timeout")) == (
        "PROVIDER_TIMEOUT"
    )


def test_qualification_summary_binds_policy_and_credential_reference() -> None:
    payload = _qualification_payload(
        "m8-qualification-offline",
        "offline-model",
        "offline-provider",
        "c" * 64,
        "3c1095ff69b1a5d800d96eb61e8b88a47fceca14",
        [
            {"probe": "P0", "result": "PASS"},
            {"probe": "P1", "result": "PASS"},
            {
                "probe": "P2",
                "result": "PASS",
                "production_tool_schema_digest": "a" * 64,
            },
            {"probe": "P3", "result": "PASS"},
            {
                "probe": "P4",
                "result": "PASS",
                "fixture_digest": "b" * 64,
                "repository_base_revision": "fixture-base",
            },
        ],
        0.0,
        working_tree_identity="d" * 64,
        policy_digest="e" * 64,
        credential_ref="khaos/providers/offline-provider/default",
    )

    assert payload["qualification_version"] == 2
    assert payload["working_tree_identity"] == "d" * 64
    assert payload["policy_digest"] == "e" * 64
    assert payload["credential_ref"] == "khaos/providers/offline-provider/default"
    assert payload["tool_schema_digest"] == "a" * 64


def test_qualification_payload_binds_distinct_v3_identity() -> None:
    payload = _qualification_payload(
        "m8-qualification-v3-offline",
        "offline-model",
        "offline-provider",
        "c" * 64,
        "3c1095ff69b1a5d800d96eb61e8b88a47fceca14",
        [
            {"probe": "P0", "result": "PASS"},
            {"probe": "P1", "result": "PASS"},
            {"probe": "P2", "result": "PASS"},
            {"probe": "P3", "result": "PASS"},
            {
                "probe": "P4",
                "result": "PASS",
                "fixture_digest": "b" * 64,
                "repository_base_revision": "fixture-base",
            },
        ],
        0.0,
        p4_scenario_id="p4-readonly-authority-v3",
    )

    assert payload["scenario_id"] == "p4-readonly-authority-v3"
    assert payload["scenario_version"] == 5
    assert payload["suite_digest"]
    assert payload["qualification"] == "PASS"


@pytest.mark.asyncio
async def test_v3_identity_survives_typed_qualification_jsonl(tmp_path) -> None:
    scenario = load_builtin_manifest().get("p4-readonly-authority-v3")
    record = CodingQualificationRecordV1(
        run_id="m8-qualification-v3-jsonl",
        result_state=CodingResultState.SUCCESS,
        provider="offline-provider",
        model="offline-model",
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
        credential_ref=None,
        reasoning_configuration={"reasoning_effort": "offline"},
        metrics={"provider_requests": 0, "secret_values_printed": False},
        stages=({"probe": "P4", "result": "PASS"},),
        started_at="2026-09-13T00:00:00+00:00",
        finished_at="2026-09-13T00:00:01+00:00",
    )
    output = tmp_path / "qualification-v3.jsonl"

    await CodingQualificationJsonlWriter(output).append(record)
    payload = json.loads(output.read_text(encoding="utf-8"))
    restored = CodingQualificationRecordV1.from_payload(payload)

    assert payload["scenario_id"] == "p4-readonly-authority-v3"
    assert payload["scenario_version"] == 5
    assert restored.to_payload() == payload


def test_qualification_payload_separates_start_finish_and_monotonic_elapsed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        qualification_module,
        "utc_timestamp",
        lambda: "2026-09-13T00:00:01+00:00",
    )
    monkeypatch.setattr(qualification_module.time, "monotonic", lambda: 4.25)

    payload = _qualification_payload(
        "m8-qualification-timing",
        "offline-model",
        "offline-provider",
        "c" * 64,
        "3c1095ff69b1a5d800d96eb61e8b88a47fceca14",
        [],
        1.25,
        started_at="2026-09-13T00:00:00+00:00",
    )

    assert payload["started_at"] == "2026-09-13T00:00:00+00:00"
    assert payload["finished_at"] == "2026-09-13T00:00:01+00:00"
    assert payload["elapsed_ms"] == 3000


@pytest.mark.asyncio
async def test_p4_v2_materialization_keeps_oracle_directory_out_of_agent_root(
    tmp_path,
) -> None:
    scenario = load_builtin_manifest().get("p4-readonly-authority")
    manager = FixtureManager(
        builtin_manifest_path(),
        private_root=tmp_path / "runs",
    )

    fixture = await manager.materialize(scenario)
    try:
        assert not (fixture.agent_root / ".oracle-hidden").exists()
        assert (fixture.fixture_root / "hidden").is_dir()
        assert fixture.fixture_root / "hidden" not in fixture.agent_root.parents
    finally:
        await fixture.cleanup()
