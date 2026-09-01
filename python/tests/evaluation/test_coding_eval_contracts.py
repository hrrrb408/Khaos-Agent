from __future__ import annotations

from dataclasses import replace

import pytest

from khaos.evaluation.coding import (
    CodingContractError,
    CodingScenario,
    CodingScenarioKind,
    CodingScenarioManifest,
    load_builtin_manifest,
)


def test_builtin_pack_has_twelve_typed_scenarios() -> None:
    manifest = load_builtin_manifest()

    assert len(manifest.scenarios) == 12
    assert {scenario.kind for scenario in manifest.scenarios} == {
        CodingScenarioKind.BUG_FIX,
        CodingScenarioKind.FEATURE,
        CodingScenarioKind.REFACTOR,
        CodingScenarioKind.MULTI_FILE,
        CodingScenarioKind.CROSS_LANGUAGE,
        CodingScenarioKind.CODE_REVIEW,
    }
    assert sum("smoke" in scenario.tags for scenario in manifest.scenarios) >= 4
    assert all(scenario.digest for scenario in manifest.scenarios)
    assert manifest.digest


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
