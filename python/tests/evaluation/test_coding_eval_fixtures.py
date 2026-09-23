from __future__ import annotations

import shutil

import pytest

from khaos.evaluation.coding import (
    FixtureError,
    FixtureManager,
    builtin_manifest_path,
    load_manifest,
    snapshot_tree,
)
from khaos.evaluation.coding.oracle import OracleError


@pytest.mark.asyncio
async def test_fixture_baseline_is_deterministic_and_mutation_is_invalid(tmp_path) -> None:
    pack = tmp_path / "pack"
    shutil.copytree(builtin_manifest_path().parent, pack)
    manifest = load_manifest(pack / "manifest.yaml")
    scenario = manifest.get("bugfix-python-cache")
    manager = FixtureManager(pack / "manifest.yaml", private_root=tmp_path / "runs")

    first = await manager.materialize(scenario)
    first_identity = (first.fixture_digest, first.source_digest, first.base_revision)
    await first.cleanup()
    second = await manager.materialize(scenario)
    try:
        assert (second.fixture_digest, second.source_digest, second.base_revision) == first_identity
        (second.fixture_root / "repo" / "src" / "cache.py").write_text(
            "tampered\n", encoding="utf-8"
        )
        with pytest.raises(FixtureError):
            second.assert_source_unchanged()
    finally:
        await second.cleanup()


@pytest.mark.asyncio
async def test_agent_cannot_create_or_hide_reserved_oracle_directory(tmp_path) -> None:
    manager = FixtureManager(builtin_manifest_path(), private_root=tmp_path)
    fixture = await manager.materialize(
        load_manifest(builtin_manifest_path()).get("bugfix-python-cache")
    )
    try:
        reserved = fixture.agent_root / ".oracle-hidden"
        reserved.mkdir()
        (reserved / "fake.txt").write_text("not a hidden test", encoding="utf-8")
        with pytest.raises(OracleError):
            snapshot_tree(fixture.agent_root)
    finally:
        await fixture.cleanup()
