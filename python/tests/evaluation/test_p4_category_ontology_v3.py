from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from khaos.evaluation.coding import (
    P4_V3_CATEGORY_ROLE_DEFINITIONS,
    P4_V3_REQUIRED_FINDING_COUNT,
    REVIEW_CATEGORY_CONTRACT_V3,
    CodingContractError,
    CodingFailureReason,
    CodingTraceCollector,
    CodingVerdict,
    DiffSummary,
    ReviewCategory,
    ReviewFinding,
    ReviewFindingExpectation,
    ReviewOracleSpec,
    evaluate_p4_v3_findings,
    load_builtin_manifest,
    p4_v3_schema_digest,
    project_review_findings,
    validate_p4_v3_response,
    validate_p4_v3_response_schema,
)
from khaos.evaluation.coding.runner import _classify_failure
from khaos.evaluation.coding.runtime_invoker import (
    _extract_review_findings_with_observation,
)


def _synthetic_oracle() -> ReviewOracleSpec:
    return ReviewOracleSpec(
        required_findings=tuple(
            ReviewFindingExpectation(
                finding_id=f"synthetic-{category.value}",
                category=category,
                file=f"public/{category.value}.py",
                concepts=(f"concept-{category.value}",),
            )
            for category in ReviewCategory
        ),
        allow_extra_findings=False,
        category_contract=REVIEW_CATEGORY_CONTRACT_V3,
    )


def _response(
    *,
    category_overrides: dict[int, str] | None = None,
    file_overrides: dict[int, str] | None = None,
    concept_overrides: dict[int, str] | None = None,
) -> dict[str, object]:
    category_overrides = category_overrides or {}
    file_overrides = file_overrides or {}
    concept_overrides = concept_overrides or {}
    findings = []
    for index, category in enumerate(ReviewCategory):
        findings.append(
            {
                "category": category_overrides.get(index, category.value),
                "file": file_overrides.get(index, f"public/{category.value}.py"),
                "concepts": [
                    concept_overrides.get(index, f"concept-{category.value}")
                ],
            }
        )
    return {"findings": findings}


def test_public_schema_is_derived_from_one_canonical_enum() -> None:
    schema = validate_p4_v3_response_schema()
    category_schema = schema["properties"]["findings"]["items"]["properties"][
        "category"
    ]

    assert list(P4_V3_CATEGORY_ROLE_DEFINITIONS) == [
        category.value for category in ReviewCategory
    ]
    assert category_schema["enum"] == [
        category.value for category in ReviewCategory
    ]
    assert schema["properties"]["findings"]["minItems"] == P4_V3_REQUIRED_FINDING_COUNT
    assert schema["properties"]["findings"]["maxItems"] == P4_V3_REQUIRED_FINDING_COUNT
    assert p4_v3_schema_digest()


def test_public_role_definitions_are_distinguishable_without_answer_leakage() -> None:
    definitions = P4_V3_CATEGORY_ROLE_DEFINITIONS

    assert all(definitions.values())
    assert len(set(definitions.values())) == len(definitions)
    assert "src/authority.py" not in json.dumps(definitions)
    assert "src/consumer.py" not in json.dumps(definitions)
    assert "src/policy.py" not in json.dumps(definitions)


def test_v3_manifest_is_distinct_and_keeps_v2_frozen() -> None:
    manifest = load_builtin_manifest()
    v2 = manifest.get("p4-readonly-authority")
    v3 = manifest.get("p4-readonly-authority-v3")

    assert v2.version == 2
    assert v2.review_category_contract is None
    assert v3.version == 5
    assert v3.review_category_contract == REVIEW_CATEGORY_CONTRACT_V3
    assert v3.scenario_id != v2.scenario_id
    assert v3.repository_fixture == v2.repository_fixture
    assert v3.digest != v2.digest
    assert all(
        isinstance(finding.category, ReviewCategory)
        for finding in v3.oracle.required_findings
    )
    public_values = {category.value for category in ReviewCategory}
    assert all(
        finding.category.value in public_values
        for finding in v3.oracle.required_findings
    )
    assert all(category.value in v3.user_prompt for category in ReviewCategory)
    assert all(
        definition in v3.user_prompt
        for definition in P4_V3_CATEGORY_ROLE_DEFINITIONS.values()
    )


def test_v3_accepts_grounded_concepts_without_redundant_role_labels() -> None:
    """The category already carries the role; concepts must be source-grounded."""

    scenario = load_builtin_manifest().get("p4-readonly-authority-v3")
    findings = (
        ReviewFinding(
            category=ReviewCategory.AUTHORITY_DEFINITION,
            file="src/authority.py",
            concepts=("AuthorityLease", "issue_lease", "project_id", "active"),
        ),
        ReviewFinding(
            category=ReviewCategory.CONSUMER,
            file="src/consumer.py",
            concepts=("consume_lease", "AuthorityLease", "project_id", "PermissionError"),
        ),
        ReviewFinding(
            category=ReviewCategory.ENFORCEMENT_BOUNDARY,
            file="src/policy.py",
            concepts=("require_active", "PermissionError"),
        ),
    )

    passed, evidence = evaluate_p4_v3_findings(
        findings,
        scenario.oracle,
        completed=True,
        side_effect_free=True,
    )

    assert passed is True
    assert evidence["matched_ids"] == [
        "authority-definition",
        "authority-consumer",
        "enforcement-boundary",
    ]


@pytest.mark.parametrize("category", tuple(ReviewCategory))
def test_each_canonical_category_survives_schema_parser_and_typed_model(
    category: ReviewCategory,
) -> None:
    response = _response()
    assert validate_p4_v3_response(response)
    findings, observation = _extract_review_findings_with_observation(
        [json.dumps(response)],
        category_contract=REVIEW_CATEGORY_CONTRACT_V3,
    )

    assert observation["schema_validation_status"] == "PASS"
    assert observation["typed_parse_status"] == "PASS"
    assert any(finding.category is category for finding in findings)


def test_canonical_full_answer_reaches_semantic_evaluator() -> None:
    oracle = _synthetic_oracle()
    response = _response()

    assert validate_p4_v3_response(response)
    findings, observation = _extract_review_findings_with_observation(
        [json.dumps(response)],
        category_contract=REVIEW_CATEGORY_CONTRACT_V3,
    )
    passed, evidence = evaluate_p4_v3_findings(
        findings,
        oracle,
        completed=True,
        side_effect_free=True,
    )

    assert observation["schema_validation_status"] == "PASS"
    assert observation["typed_parse_status"] == "PASS"
    assert all(isinstance(finding.category, ReviewCategory) for finding in findings)
    assert passed is True
    assert evidence["failure_class"] is None


def test_manifest_oracle_and_v3_evaluator_share_the_canonical_enum() -> None:
    scenario = load_builtin_manifest().get("p4-readonly-authority-v3")
    findings = tuple(
        ReviewFinding(
            category=expected.category,
            file=expected.file,
            concepts=expected.concepts,
            line=expected.line,
            severity=expected.severity,
        )
        for expected in scenario.oracle.required_findings
    )

    passed, evidence = evaluate_p4_v3_findings(
        findings,
        scenario.oracle,
        completed=True,
        side_effect_free=True,
    )

    assert passed is True
    assert evidence["required_count"] == P4_V3_REQUIRED_FINDING_COUNT
    assert evidence["submitted_count"] == P4_V3_REQUIRED_FINDING_COUNT
    assert len(evidence["matched_ids"]) == P4_V3_REQUIRED_FINDING_COUNT


@pytest.mark.parametrize(
    ("category_overrides", "file_overrides", "concept_overrides"),
    (
        ({0: ReviewCategory.CONSUMER.value}, {}, {}),
        ({}, {0: "public/wrong.py"}, {}),
        ({}, {}, {0: "wrong-concept"}),
    ),
)
def test_valid_v3_shape_with_role_file_or_concept_mismatch_is_semantic_failure(
    category_overrides: dict[int, str],
    file_overrides: dict[int, str],
    concept_overrides: dict[int, str],
) -> None:
    response = _response(
        category_overrides=category_overrides,
        file_overrides=file_overrides,
        concept_overrides=concept_overrides,
    )
    assert validate_p4_v3_response(response)
    findings, observation = _extract_review_findings_with_observation(
        [json.dumps(response)],
        category_contract=REVIEW_CATEGORY_CONTRACT_V3,
    )
    passed, evidence = evaluate_p4_v3_findings(
        findings,
        _synthetic_oracle(),
        completed=True,
        side_effect_free=True,
    )

    assert observation["schema_validation_status"] == "PASS"
    assert observation["typed_parse_status"] == "PASS"
    assert passed is False
    assert evidence["failure_class"] == "SEMANTIC_REVIEW_FAILURE"


@pytest.mark.parametrize(
    "invalid_category",
    (
        "authority definition",
        "authority-definition",
        "AuthorityDefinition",
        "totally_unknown_role",
    ),
)
def test_v3_rejects_format_aliases_and_unknown_categories_before_semantic_review(
    invalid_category: str,
) -> None:
    response = _response(category_overrides={0: invalid_category})

    assert validate_p4_v3_response(response) is False
    findings, observation = _extract_review_findings_with_observation(
        [json.dumps(response)],
        category_contract=REVIEW_CATEGORY_CONTRACT_V3,
    )

    assert findings == ()
    assert observation["schema_validation_status"] == "FAIL"
    assert observation["typed_parse_status"] == "FAIL"
    assert observation["parse_error_code"] == "RESPONSE_SCHEMA_INVALID"


def test_v3_rejects_non_json_wrapper_while_v2_keeps_legacy_compatibility() -> None:
    response = json.dumps(_response())
    fenced = f"```json\n{response}\n```"

    findings, observation = _extract_review_findings_with_observation(
        [fenced],
        category_contract=REVIEW_CATEGORY_CONTRACT_V3,
    )
    legacy_findings, legacy_observation = _extract_review_findings_with_observation(
        [
            (
                '{"findings":[{"category":"authority-definition",'
                '"file":"src/authority.py","concepts":["AuthorityLease"]}]}'
            )
        ]
    )

    assert findings == ()
    assert observation["format"] == "FENCED_JSON"
    assert observation["parse_error_code"] == "NON_CANONICAL_FORMAT"
    assert legacy_findings
    assert legacy_observation["typed_parse_status"] == "PASS"


def test_v3_oracle_cannot_require_a_hidden_only_category_token() -> None:
    with pytest.raises(CodingContractError):
        ReviewOracleSpec(
            required_findings=(
                ReviewFindingExpectation(
                    finding_id="hidden-category",
                    category="authority-definition",
                    file="public/authority.py",
                    concepts=("concept",),
                ),
            ),
            category_contract=REVIEW_CATEGORY_CONTRACT_V3,
        )


def test_v3_canonical_enum_survives_safe_typed_projection() -> None:
    finding = ReviewFinding.from_mapping_v3(
        {
            "category": ReviewCategory.AUTHORITY_DEFINITION.value,
            "file": "public/authority.py",
            "concepts": ["concept"],
        }
    )

    projection = project_review_findings((finding,))

    assert projection["typed_findings"][0]["category"] == (
        ReviewCategory.AUTHORITY_DEFINITION.value
    )


def test_v3_failure_layers_do_not_collapse_output_and_semantic_errors() -> None:
    scenario = load_builtin_manifest().get("p4-readonly-authority-v3")
    agent = SimpleNamespace(
        status="COMPLETED",
        error=None,
    )
    oracle = SimpleNamespace(
        checks=(
            SimpleNamespace(
                kind=SimpleNamespace(value="REVIEW_FINDING"),
                passed=False,
                evidence={"unmatched_count": 3},
            ),
        )
    )
    diff = DiffSummary(
        changed_files=(),
        added_files=(),
        deleted_files=(),
        renamed_files=(),
        insertions=0,
        deletions=0,
        binary_files=(),
        digest="a" * 64,
    )
    output_contract_trace = CodingTraceCollector(run_id="v3-output-contract")
    output_contract_trace.record_response_observation(
        "{}",
        {
            "json_decode_status": "PASS",
            "schema_validation_status": "FAIL",
            "typed_parse_status": "FAIL",
        },
    )
    semantic_trace = CodingTraceCollector(run_id="v3-semantic")
    semantic_trace.record_response_observation(
        '{"findings":[]}',
        {
            "json_decode_status": "PASS",
            "schema_validation_status": "PASS",
            "typed_parse_status": "PASS",
        },
    )

    output_failure = _classify_failure(
        CodingVerdict.FAIL,
        scenario,
        agent=agent,
        oracle=oracle,
        diff=diff,
        trace=output_contract_trace,
    )
    semantic_failure = _classify_failure(
        CodingVerdict.FAIL,
        scenario,
        agent=agent,
        oracle=oracle,
        diff=diff,
        trace=semantic_trace,
    )

    assert output_failure is CodingFailureReason.OUTPUT_CONTRACT_FAILURE
    assert semantic_failure is CodingFailureReason.SEMANTIC_REVIEW_FAILURE


@pytest.mark.parametrize(
    ("failure_class", "semantic_evaluation"),
    (
        ("OUTPUT_CONTRACT_FAILURE", "NOT_ATTEMPTED"),
        ("SEMANTIC_REVIEW_FAILURE", "PERFORMED"),
    ),
)
def test_v3_failure_layer_is_preserved_in_typed_observability(
    failure_class: str,
    semantic_evaluation: str,
) -> None:
    collector = CodingTraceCollector(run_id=f"v3-{failure_class}")
    collector.record_semantic_review(
        {
            "review_findings_pass": False,
            "failure_class": failure_class,
            "evaluation_layer": "OUTPUT_CONTRACT"
            if failure_class == "OUTPUT_CONTRACT_FAILURE"
            else "SEMANTIC_EVALUATOR",
            "semantic_evaluation": semantic_evaluation,
            "required_finding_count": 3,
            "submitted_finding_count": 3,
        }
    )

    metrics = collector.finish(
        verdict=CodingVerdict.FAIL,
        agent_status="COMPLETED",
        completion_status="completed",
    )

    semantic_review = metrics.observability["semantic_review"]
    assert semantic_review["failure_class"] == failure_class
    assert semantic_review["semantic_evaluation"] == semantic_evaluation
    assert semantic_review["evaluation_layer"] in {
        "OUTPUT_CONTRACT",
        "SEMANTIC_EVALUATOR",
    }
