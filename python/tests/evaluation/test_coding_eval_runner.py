from __future__ import annotations

import asyncio
from dataclasses import replace
import sqlite3

import pytest

from khaos.evaluation.coding import (
    AgentExecution,
    AgentInvokerCallable,
    CodingEvaluationRepository,
    CodingEvaluationRunner,
    CodingOracle,
    DiffOracleSpec,
    FileStateCheck,
    FileStateOracleSpec,
    FixtureManager,
    builtin_manifest_path,
    load_builtin_manifest,
)
from khaos.db import Database


def _local_scenario():
    source = load_builtin_manifest().get("bugfix-python-cache")
    return replace(
        source,
        digest="",
        oracle=__import__(
            "khaos.evaluation.coding", fromlist=["CompositeOracleSpec"]
        ).CompositeOracleSpec(
            (
                FileStateOracleSpec(
                    (FileStateCheck("src/cache.py", contains=("return self._values[key]",)),)
                ),
                DiffOracleSpec(required_changed_files=("src/cache.py",), max_changed_files=2),
            )
        ),
    )


async def _fixed_agent(scenario, fixture, trace):
    target = fixture.agent_root / "src" / "cache.py"
    target.write_text(
        "class Cache:\n"
        "    def __init__(self):\n"
        "        self._values = {}\n"
        "    def put(self, key, value):\n"
        "        self._values[key] = value\n"
        "    def get(self, key, default=None):\n"
        "        if key in self._values:\n"
        "            return self._values[key]\n"
        "        return default\n",
        encoding="utf-8",
    )
    trace.record("tool_result", "write_file", success=True)
    return AgentExecution(
        status="COMPLETED",
        completion_status="completed",
        final_root=fixture.agent_root,
        runtime_id="fake-runtime",
        model="test-model",
        provider="test-provider",
    )


async def _slow_agent(scenario, fixture, trace):
    await asyncio.sleep(1)
    raise AssertionError("timeout test agent should be cancelled")


async def _symlink_final_root_agent(scenario, fixture, trace):
    alias = fixture._private_root / "agent-alias"
    alias.symlink_to(fixture.agent_root, target_is_directory=True)
    return AgentExecution(
        status="COMPLETED",
        completion_status="completed",
        final_root=alias,
        runtime_id="fake-runtime",
        model="test-model",
        provider="test-provider",
    )


@pytest.mark.asyncio
async def test_runner_uses_external_oracle_and_persists_observation_only(tmp_path) -> None:
    db = Database(":memory:")
    await db.connect()
    await db.run_migrations()
    manifest = load_builtin_manifest()
    scenario = _local_scenario()
    repository = CodingEvaluationRepository(
        db,
        principal_id="test-principal",
        project_id="test-project",
    )
    manager = FixtureManager(
        __import__("khaos.evaluation.coding", fromlist=["builtin_manifest_path"]).builtin_manifest_path(),
        private_root=tmp_path,
    )
    runner = CodingEvaluationRunner(
        manifest=replace(manifest, scenarios=tuple(scenario if item.scenario_id == scenario.scenario_id else item for item in manifest.scenarios), digest=""),
        fixture_manager=manager,
        oracle=CodingOracle(),
        agent_invoker=_fixed_agent,
        repository=repository,
        principal_id="test-principal",
        project_id="test-project",
    )
    try:
        result = await runner.run(scenario.scenario_id)
        assert result.verdict.value == "PASS"
        assert result.oracle is not None
        assert result.oracle.verdict.value == "PASS"
        stored = await repository.get_by_id(
            result.identity.run_id,
            principal_id="test-principal",
            project_id="test-project",
        )
        assert stored is not None
        assert stored.result_digest == result.result_digest
        with pytest.raises(sqlite3.IntegrityError):
            async with db.transaction() as conn:
                await conn.execute(
                    "UPDATE coding_evaluation_runs SET verdict = 'FAIL' WHERE run_id = ?",
                    (result.identity.run_id,),
                )
        with pytest.raises(sqlite3.IntegrityError):
            async with db.transaction() as conn:
                await conn.execute(
                    "DELETE FROM coding_evaluation_runs WHERE run_id = ?",
                    (result.identity.run_id,),
                )
        async with db.read_connection() as conn:
            task_projection = await (await conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='coding_tasks'"
            )).fetchone()
        assert task_projection is not None
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_runner_classifies_oracle_execution_as_oracle_error(tmp_path) -> None:
    source = _local_scenario()
    manager = FixtureManager(
        __import__("khaos.evaluation.coding", fromlist=["builtin_manifest_path"]).builtin_manifest_path(),
        private_root=tmp_path,
    )
    manifest = load_builtin_manifest()
    scenario = replace(
        source,
        oracle=__import__("khaos.evaluation.coding", fromlist=["CommandOracleSpec"]).CommandOracleSpec(
            argv=("python3", "verify.py"),
            hidden_files=("verify.py",),
        ),
        digest="",
    )
    runner = CodingEvaluationRunner(
        manifest=replace(manifest, scenarios=tuple(scenario if item.scenario_id == source.scenario_id else item for item in manifest.scenarios), digest=""),
        fixture_manager=manager,
        oracle=CodingOracle(),
        agent_invoker=_fixed_agent,
    )
    result = await runner.run(source.scenario_id)
    assert result.verdict.value == "ORACLE_ERROR"
    assert result.oracle is not None
    assert result.oracle.error


@pytest.mark.asyncio
async def test_runner_persists_invalid_fixture_instead_of_raising(tmp_path) -> None:
    source = replace(
        load_builtin_manifest().get("bugfix-python-cache"),
        repository_fixture="missing-fixture",
        digest="",
    )
    manifest = load_builtin_manifest()
    runner = CodingEvaluationRunner(
        manifest=replace(
            manifest,
            scenarios=tuple(
                source if item.scenario_id == source.scenario_id else item
                for item in manifest.scenarios
            ),
            digest="",
        ),
        fixture_manager=FixtureManager(
            __import__("khaos.evaluation.coding", fromlist=["builtin_manifest_path"]).builtin_manifest_path(),
            private_root=tmp_path,
        ),
        oracle=CodingOracle(),
        agent_invoker=_fixed_agent,
    )

    result = await runner.run(source.scenario_id)

    assert result.verdict.value == "INVALID_FIXTURE"
    assert result.failure_reason.value == "INVALID_FIXTURE"
    assert result.oracle is None


@pytest.mark.asyncio
async def test_runner_records_timeout_and_cleans_private_fixture(tmp_path) -> None:
    source = _local_scenario()
    scenario = replace(
        source,
        limits=replace(source.limits, timeout_seconds=0.01),
        digest="",
    )
    manifest = load_builtin_manifest()
    runner = CodingEvaluationRunner(
        manifest=replace(
            manifest,
            scenarios=tuple(
                scenario if item.scenario_id == source.scenario_id else item
                for item in manifest.scenarios
            ),
            digest="",
        ),
        fixture_manager=FixtureManager(builtin_manifest_path(), private_root=tmp_path),
        oracle=CodingOracle(),
        agent_invoker=_slow_agent,
    )

    result = await runner.run(source.scenario_id)

    assert result.verdict.value == "TIMEOUT"
    assert result.failure_reason.value == "TIMEOUT"
    assert not tuple(tmp_path.glob(".khaos-m8-*"))


@pytest.mark.asyncio
async def test_runner_propagates_external_cancellation_and_cleans_fixture(tmp_path) -> None:
    source = _local_scenario()
    scenario = replace(
        source,
        limits=replace(source.limits, timeout_seconds=5),
        digest="",
    )
    manifest = load_builtin_manifest()
    runner = CodingEvaluationRunner(
        manifest=replace(
            manifest,
            scenarios=tuple(
                scenario if item.scenario_id == source.scenario_id else item
                for item in manifest.scenarios
            ),
            digest="",
        ),
        fixture_manager=FixtureManager(builtin_manifest_path(), private_root=tmp_path),
        oracle=CodingOracle(),
        agent_invoker=_slow_agent,
    )

    started = asyncio.Event()

    async def blocking_agent(_scenario, _fixture, _trace):
        started.set()
        await asyncio.Event().wait()

    runner.agent_invoker = AgentInvokerCallable(blocking_agent)
    task = asyncio.create_task(runner.run(source.scenario_id))
    await asyncio.wait_for(started.wait(), timeout=1)
    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task
    assert not tuple(tmp_path.glob(".khaos-m8-*"))


@pytest.mark.asyncio
async def test_runner_rejects_symlink_final_workspace(tmp_path) -> None:
    source = _local_scenario()
    manifest = load_builtin_manifest()
    runner = CodingEvaluationRunner(
        manifest=replace(
            manifest,
            scenarios=tuple(
                source if item.scenario_id == source.scenario_id else item
                for item in manifest.scenarios
            ),
            digest="",
        ),
        fixture_manager=FixtureManager(builtin_manifest_path(), private_root=tmp_path),
        oracle=CodingOracle(),
        agent_invoker=_symlink_final_root_agent,
    )

    result = await runner.run(source.scenario_id)

    assert result.verdict.value == "INVALID_FIXTURE"
    assert result.failure_reason.value == "INVALID_FIXTURE"
    assert not tuple(tmp_path.glob(".khaos-m8-*"))
