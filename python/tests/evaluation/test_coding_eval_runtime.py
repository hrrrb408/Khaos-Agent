from __future__ import annotations

import sys
from dataclasses import replace

import pytest
from khaos.agent import Message
from khaos.db import Database
from khaos.evaluation.coding import (
    CodingEvaluationRunner,
    CodingOracle,
    CompositeOracleSpec,
    DiffOracleSpec,
    FileStateCheck,
    FileStateOracleSpec,
    FixtureManager,
    RuntimeCodingAgentInvoker,
    builtin_manifest_path,
    load_builtin_manifest,
)


def _patch_local_trusted_git(monkeypatch) -> None:
    """Use an installed Command Line Tools Git only for this test harness.

    This machine has not accepted the Xcode license, while the separately
    installed platform candidate is the same root-owned Apple Git build and
    passes the runner's identity/digest checks.  The override keeps the real
    AgentLoop/workspace path under test without adding a production fallback.
    """

    if sys.platform != "darwin":
        return
    from khaos.coding.workspace.trusted_git_locator import PlatformTrustedGitLocator
    from khaos.coding.workspace.trusted_git_policy import TrustedGitExecutablePolicy

    candidates = PlatformTrustedGitLocator().candidates()
    candidate = next((path for path in candidates[1:] if path.is_file()), None)
    if candidate is None:
        return
    identity = TrustedGitExecutablePolicy().validate(candidate)
    from khaos.coding.workspace import trusted_git

    monkeypatch.setattr(
        trusted_git,
        "resolve_trusted_git",
        lambda: (identity.path, identity.file_identity, identity.sha256),
    )


class ScriptedRouter:
    """Fake model only; the evaluated path still uses the real AgentLoop."""

    def __init__(self) -> None:
        self.calls = 0

    async def call(self, _function, _messages, **_kwargs):
        self.calls += 1
        if self.calls == 1:
            yield Message(
                role="assistant",
                content="",
                tool_calls=[
                    {
                        "id": "write-cache",
                        "name": "write_file",
                        "arguments": {
                            "path": "src/cache.py",
                            "content": (
                                "class Cache:\n"
                                "    def __init__(self):\n"
                                "        self._values = {}\n"
                                "    def put(self, key, value):\n"
                                "        self._values[key] = value\n"
                                "    def get(self, key, default=None):\n"
                                "        if key in self._values:\n"
                                "            return self._values[key]\n"
                                "        return default\n"
                            ),
                        },
                    }
                ],
                stop_reason="tool_use",
            )
        else:
            yield Message(role="assistant", content="implemented", stop_reason="end_turn")


class ReviewScriptedRouter:
    """Try a mutation first; the review runtime must reject it by allowlist."""

    def __init__(self) -> None:
        self.calls = 0

    async def call(self, _function, _messages, **_kwargs):
        self.calls += 1
        if self.calls == 1:
            yield Message(
                role="assistant",
                content="",
                tool_calls=[
                    {
                        "id": "forbidden-write",
                        "name": "write_file",
                        "arguments": {"path": "src/cache.py", "content": "mutate"},
                    }
                ],
                stop_reason="tool_use",
            )
        else:
            yield Message(
                role="assistant",
                content=(
                    '{"findings":[{"category":"concurrency",'
                    '"file":"src/cache.py","line":12,"severity":"high",'
                    '"concepts":["lock","compute","duplicate"]}]}'
                ),
                stop_reason="end_turn",
            )


@pytest.mark.posix_host
@pytest.mark.asyncio
async def test_real_agent_loop_path_with_fake_model(tmp_path, monkeypatch) -> None:
    _patch_local_trusted_git(monkeypatch)
    db = Database(":memory:")
    await db.connect()
    await db.run_migrations()
    base = load_builtin_manifest().get("bugfix-python-cache")
    scenario = replace(
        base,
        digest="",
        oracle=CompositeOracleSpec(
            (
                FileStateOracleSpec(
                    (FileStateCheck("src/cache.py", contains=("return self._values[key]",)),)
                ),
                DiffOracleSpec(required_changed_files=("src/cache.py",), max_changed_files=2),
            )
        ),
    )
    manifest = load_builtin_manifest()
    manifest = replace(
        manifest,
        scenarios=tuple(
            scenario if item.scenario_id == scenario.scenario_id else item
            for item in manifest.scenarios
        ),
        digest="",
    )
    manager = FixtureManager(builtin_manifest_path(), private_root=tmp_path)
    invoker = RuntimeCodingAgentInvoker(
        db,
        ScriptedRouter(),
        principal_id="test-principal",
        project_id="test-project",
        model="fake-model",
        provider="fake-provider",
    )
    runner = CodingEvaluationRunner(
        manifest,
        fixture_manager=manager,
        oracle=CodingOracle(),
        agent_invoker=invoker,
        principal_id="test-principal",
        project_id="test-project",
    )
    try:
        result = await runner.run(scenario.scenario_id)
        assert result.verdict.value in {"PASS", "AGENT_ERROR"}
        assert result.metrics.tool_calls >= 1
        assert result.agent.runtime_id.startswith("m8-runtime-")
    finally:
        await db.close()


@pytest.mark.posix_host
@pytest.mark.asyncio
async def test_review_runtime_is_read_only_even_when_model_requests_write(tmp_path, monkeypatch) -> None:
    _patch_local_trusted_git(monkeypatch)
    db = Database(":memory:")
    await db.connect()
    await db.run_migrations()
    manifest = load_builtin_manifest()
    scenario = manifest.get("review-python-cache-race")
    invoker = RuntimeCodingAgentInvoker(
        db,
        ReviewScriptedRouter(),
        principal_id="test-principal",
        project_id="test-project",
        model="fake-model",
        provider="fake-provider",
    )
    runner = CodingEvaluationRunner(
        manifest,
        fixture_manager=FixtureManager(builtin_manifest_path(), private_root=tmp_path),
        oracle=CodingOracle(),
        agent_invoker=invoker,
        principal_id="test-principal",
        project_id="test-project",
    )

    try:
        result = await runner.run(scenario.scenario_id)
        assert result.verdict.value == "PASS"
        assert result.diff.changed_files == ()
        assert result.metrics.permission_denials >= 1
    finally:
        await db.close()
