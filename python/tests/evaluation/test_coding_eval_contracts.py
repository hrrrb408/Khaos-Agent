from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest
from khaos.evaluation.coding import (
    CodingContractError,
    CodingScenario,
    CodingScenarioKind,
    load_builtin_manifest,
)


def test_builtin_pack_has_seventeen_typed_scenarios() -> None:
    manifest = load_builtin_manifest()

    assert len(manifest.scenarios) == 17
    assert {scenario.kind for scenario in manifest.scenarios} == {
        CodingScenarioKind.FRONTEND_BUG,
        CodingScenarioKind.FULLSTACK_BUG,
        CodingScenarioKind.BROWSER_VALIDATED_FEATURE,
        CodingScenarioKind.BUG_FIX,
        CodingScenarioKind.FEATURE,
        CodingScenarioKind.REFACTOR,
        CodingScenarioKind.MULTI_FILE,
        CodingScenarioKind.CROSS_LANGUAGE,
        CodingScenarioKind.CODE_REVIEW,
    }
    assert {
        scenario.scenario_id
        for scenario in manifest.scenarios
        if scenario.kind
        in {
            CodingScenarioKind.FRONTEND_BUG,
            CodingScenarioKind.FULLSTACK_BUG,
            CodingScenarioKind.BROWSER_VALIDATED_FEATURE,
        }
    } == {
        "browser-frontend-bug",
        "browser-fullstack-bug",
        "browser-validated-feature",
    }
    assert sum("smoke" in scenario.tags for scenario in manifest.scenarios) >= 4
    assert all(scenario.digest for scenario in manifest.scenarios)
    assert manifest.digest
    p4 = manifest.get("p4-readonly-authority")
    assert p4.version == 2
    assert p4.kind is CodingScenarioKind.CODE_REVIEW
    assert "When you have enough evidence to answer accurately, stop using tools and answer." in p4.user_prompt
    prompt = p4.user_prompt.casefold()
    assert "complete exactly" not in prompt
    assert "do not finish early" not in prompt
    assert "at least" not in prompt
    assert "minimum" not in prompt
    assert p4.limits.max_model_turns == 12
    assert p4.limits.max_tool_calls == 24
    p4_v3 = manifest.get("p4-readonly-authority-v3")
    assert p4_v3.version == 5
    assert p4_v3.review_category_contract == "p4-review-category-v3"
    assert p4_v3.repository_fixture == p4.repository_fixture
    assert p4_v3.digest != p4.digest


def test_scenario_digest_changes_with_prompt_and_rejects_stale_digest() -> None:
    scenario = load_builtin_manifest().get("bugfix-python-cache")
    changed = replace(scenario, user_prompt="A different bounded task", digest="")

    assert changed.digest != scenario.digest
    with pytest.raises(CodingContractError):
        CodingScenario(
            scenario_id=scenario.scenario_id,
            version=scenario.version,
            kind=scenario.kind,
            repository_fixture=scenario.repository_fixture,
            user_prompt=scenario.user_prompt,
            limits=scenario.limits,
            languages=scenario.languages,
            oracle=scenario.oracle,
            expected_files=scenario.expected_files,
            forbidden_files=scenario.forbidden_files,
            tags=scenario.tags,
            digest="0" * 64,
        )


def test_hard_scenario_oracle_contracts_are_publicly_stated() -> None:
    manifest = load_builtin_manifest()
    required_terms = {
        "feature-rust-parser": ("parse_record", "ParseError"),
        "multifile-go-pipeline": ("Validate", "Accumulator", "Process"),
        "multifile-python-settings": ("from_env", "validate", "monkeypatch"),
        "refactor-python-repository": (
            "RepositoryPort",
            "typing.Protocol",
            "src/repository.py",
        ),
        "refactor-typescript-client": ("interface Transport", "Request", "private transport"),
    }

    expected_versions = {
        "bugfix-go-counter": 2,
        "browser-validated-feature": 4,
        "bugfix-typescript-config": 2,
        "cross-language-python-go-contract": 2,
        "feature-rust-parser": 5,
        "refactor-python-repository": 3,
        "refactor-typescript-client": 3,
        "review-python-cache-race": 5,
    }
    for scenario_id, terms in required_terms.items():
        scenario = manifest.get(scenario_id)
        assert scenario.version == expected_versions.get(scenario_id, 2)
        assert all(term in scenario.user_prompt for term in terms)

    browser = manifest.get("browser-validated-feature")
    assert browser.version == 4
    typescript = manifest.get("bugfix-typescript-config")
    assert typescript.version == 2
    cross_language = manifest.get("cross-language-python-go-contract")
    assert cross_language.version == 2
    assert "Preserve the contract's version on the Go response" in cross_language.user_prompt

    review = manifest.get("review-python-cache-race")
    assert review.version == 5
    assert "exactly one JSON object" in review.user_prompt
    assert "short exact identifiers from the source" in review.user_prompt
    assert "Do not include prose, Markdown, or a code fence" in review.user_prompt

    rust = manifest.get("feature-rust-parser")
    assert rust.version == 5
    assert rust.expected_files == ("src/parser.rs",)
    diff = next(child for child in rust.oracle.children if child.kind.value == "DIFF")
    assert diff.required_changed_files == ("src/parser.rs",)
    assert diff.min_changed_files == 1


def test_browser_validated_feature_fixture_starts_without_the_feature() -> None:
    fixture = (
        Path(__file__).resolve().parents[3]
        / "python/khaos/evaluation/coding/pack/browser-validated-feature/repo/src/app.html"
    )
    text = fixture.read_text(encoding="utf-8")

    assert 'id="filter"' not in text
    assert 'id="result-count"' not in text
    assert "addEventListener" not in text


def test_scenario_contract_supports_final_benchmark_categories_and_long_horizon() -> None:
    source = load_builtin_manifest().get("bugfix-python-cache")

    scenario = replace(
        source,
        kind=CodingScenarioKind.TEST_REPAIR,
        difficulty="long_horizon",
        tags=("long-horizon", "test-repair"),
        digest="",
    )

    assert scenario.kind is CodingScenarioKind.TEST_REPAIR
    assert scenario.difficulty == "long_horizon"
    assert CodingScenarioKind.BUILD_REPAIR.value == "BUILD_REPAIR"
    assert CodingScenarioKind.API_CHANGE.value == "API_CHANGE"
    assert CodingScenarioKind.DEPENDENCY_UPDATE.value == "DEPENDENCY_UPDATE"
    assert CodingScenarioKind.PERFORMANCE_BUG.value == "PERFORMANCE_BUG"


def test_manifest_rejects_duplicate_or_unknown_fields(tmp_path) -> None:
    manifest = tmp_path / "manifest.yaml"
    fixture = tmp_path / "fixture"
    fixture.mkdir()
    manifest.write_text(
        """
manifest_id: local
version: 1
unknown: rejected
scenarios: []
""",
        encoding="utf-8",
    )
    from khaos.evaluation.coding import load_manifest

    with pytest.raises(CodingContractError):
        load_manifest(manifest)


def test_manifest_rejects_symlinked_manifest_and_strict_types(tmp_path) -> None:
    manifest = tmp_path / "manifest.yaml"
    manifest.write_text(
        "manifest_id: local\nversion: 1\nscenarios: []\n",
        encoding="utf-8",
    )
    link = tmp_path / "manifest-link.yaml"
    link.symlink_to(manifest)

    from khaos.evaluation.coding import load_manifest

    with pytest.raises(CodingContractError):
        load_manifest(link)

    manifest.write_text(
        "manifest_id: local\nversion: true\nscenarios: []\n",
        encoding="utf-8",
    )
    with pytest.raises(CodingContractError):
        load_manifest(manifest)
