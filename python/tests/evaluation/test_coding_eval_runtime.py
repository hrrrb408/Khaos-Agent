from __future__ import annotations

import http.server
import json
import runpy
import sys
from dataclasses import replace
from pathlib import Path

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
from khaos.evaluation.coding.runtime_invoker import (
    _browser_app_profile,
    _coding_tool_allowlist,
    _task_prompt,
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


def test_runtime_invoker_composes_public_browser_app_profiles() -> None:
    manifest = load_builtin_manifest()

    frontend = _browser_app_profile(manifest.get("browser-frontend-bug"))
    fullstack = _browser_app_profile(manifest.get("browser-fullstack-bug"))
    non_browser = _browser_app_profile(manifest.get("bugfix-python-cache"))

    assert frontend is not None
    assert frontend.profile_id == "browser-frontend-bug"
    assert frontend.argv[0] == sys.executable
    assert frontend.argv[-1] == "{port}"
    assert frontend.readiness_path == "/src/app.html"
    assert frontend.provenance == "trusted:evaluation-fixture"
    assert fullstack is not None
    assert fullstack.profile_id == "browser-fullstack-bug"
    assert fullstack.argv[1] == "server.py"
    assert fullstack.readiness_path == "/api/task"
    assert non_browser is None


def test_runtime_invoker_exposes_bounded_coding_tool_surface() -> None:
    manifest = load_builtin_manifest()

    non_browser = _coding_tool_allowlist(manifest.get("bugfix-python-cache"))
    browser = _coding_tool_allowlist(manifest.get("browser-frontend-bug"))

    assert "apply_edit_transaction" in non_browser
    assert "preview_edit_transaction" in non_browser
    assert "terminal_argv" in non_browser
    assert "test_run" in non_browser
    assert "browser_action" not in non_browser
    assert "write_file" not in non_browser
    assert "patch" not in non_browser
    assert "git_push" not in non_browser
    assert set(browser) == set(non_browser) | {
        "browser_app_open",
        "browser_observe",
        "browser_action",
        "browser_session_close",
    }


def test_browser_task_prompt_requires_fresh_browser_verification() -> None:
    scenario = load_builtin_manifest().get("browser-fullstack-bug")
    profile = _browser_app_profile(scenario)

    assert profile is not None
    prompt = _task_prompt(scenario, profile)
    assert "浏览器验证属于本任务的验收步骤" in prompt
    assert "browser_app_open" in prompt
    assert "重新绑定或重启 App" in prompt
    assert profile.profile_id in prompt


def test_fullstack_fixture_honors_profile_port(monkeypatch) -> None:
    """The app fixture must bind the port supplied by its trusted profile."""

    server_path = (
        Path(__file__).resolve().parents[2]
        / "khaos"
        / "evaluation"
        / "coding"
        / "pack"
        / "browser-fullstack-bug"
        / "repo"
        / "server.py"
    )
    addresses: list[tuple[str, int]] = []

    class _FakeHTTPServer:
        def __init__(self, address, _handler) -> None:
            addresses.append(address)

        def serve_forever(self) -> None:
            return

    monkeypatch.setattr(http.server, "HTTPServer", _FakeHTTPServer)
    monkeypatch.setattr(sys, "argv", [str(server_path), "45678"])

    runpy.run_path(str(server_path), run_name="__main__")

    assert addresses == [("127.0.0.1", 45678)]


def test_runtime_invoker_propagates_explicit_task_timeout_to_model_stream() -> None:
    manifest = load_builtin_manifest()
    scenario = manifest.get("multifile-python-settings")
    invoker = RuntimeCodingAgentInvoker(
        Database(":memory:"),
        ScriptedRouter(),
        task_timeout_seconds=600,
    )

    assert scenario.limits.timeout_seconds == 120.0
    assert invoker._agent_timeout_seconds(scenario) == 600.0


def test_runtime_invoker_rejects_invalid_task_timeout_override() -> None:
    with pytest.raises(ValueError, match="task_timeout_seconds"):
        RuntimeCodingAgentInvoker(
            Database(":memory:"),
            ScriptedRouter(),
            task_timeout_seconds=0,
        )


class ScriptedRouter:
    """Fake model only; the evaluated path still uses the real AgentLoop."""

    def __init__(self) -> None:
        self.calls = 0

    @staticmethod
    def _transaction(messages):
        read_result = next(
            message
            for message in reversed(messages)
            if message.role == "tool" and message.metadata.get("name") == "read_file"
        )
        envelope = json.loads(read_result.content)
        output = envelope["output"]
        original = "\n".join(
            line.split(": ", 1)[1]
            for line in str(output["content"]).splitlines()
        )
        replacement = original.replace(
            "return self._values.get(key) or default",
            "return self._values[key] if key in self._values else default",
        )
        operation = {
            "operation": "update",
            "path": "src/cache.py",
            "expected_exists": True,
            "expected_digest": output["content_sha256"],
            "content": None,
            "text_edits": [
                {"start": 0, "end": len(original), "replacement": replacement}
            ],
        }
        return {
            "transaction_id": "scripted-cache-fix",
            "base_generation": output["workspace_generation"],
            "operations": [operation],
            "intent": "preserve falsey cache values",
        }

    async def call(self, _function, messages, **_kwargs):
        self.calls += 1
        if self.calls == 1:
            yield Message(
                role="assistant",
                content="",
                tool_calls=[
                    {
                        "id": "read-cache",
                        "name": "read_file",
                        "arguments": {"path": "src/cache.py"},
                    }
                ],
                stop_reason="tool_use",
            )
        elif self.calls == 2:
            arguments = self._transaction(messages)
            yield Message(
                role="assistant",
                content="",
                tool_calls=[
                    {
                        "id": "preview-cache",
                        "name": "preview_edit_transaction",
                        "arguments": arguments,
                    }
                ],
                stop_reason="tool_use",
            )
        elif self.calls == 3:
            yield Message(
                role="assistant",
                content="",
                tool_calls=[
                    {
                        "id": "apply-cache",
                        "name": "apply_edit_transaction",
                        "arguments": self._transaction(messages),
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
                    '"file":"src/cache.py","line":7,"severity":"high",'
                    '"concepts":["get_or_compute","_values","_compute"]}]}'
                ),
                stop_reason="end_turn",
            )


class P4ScriptedRouter:
    """Deterministic efficient/normal model paths for the P4-v2 gate."""

    _paths = ("src/authority.py", "src/consumer.py", "src/policy.py")

    def __init__(self, *, efficient: bool) -> None:
        self.efficient = efficient
        self.calls = 0

    async def call(self, _function, _messages, **_kwargs):
        self.calls += 1
        if self.calls == 1:
            paths = self._paths if self.efficient else self._paths[:1]
            yield Message(
                role="assistant",
                content="",
                tool_calls=[
                    {
                        "id": f"p4-read-{index}",
                        "name": "read_file",
                        "arguments": {"path": path},
                    }
                    for index, path in enumerate(paths)
                ],
                stop_reason="tool_use",
            )
            return
        if not self.efficient and self.calls <= len(self._paths):
            path = self._paths[self.calls - 1]
            yield Message(
                role="assistant",
                content="",
                tool_calls=[
                    {
                        "id": f"p4-read-{self.calls - 1}",
                        "name": "read_file",
                        "arguments": {"path": path},
                    }
                ],
                stop_reason="tool_use",
            )
            return
        yield Message(
            role="assistant",
            content=(
                '{"findings":['
                '{"category":"authority-definition","file":"src/authority.py",'
                '"concepts":["AuthorityLease","issue_lease","definition"],'
                '"severity":"medium"},'
                '{"category":"authority-consumer","file":"src/consumer.py",'
                '"concepts":["consume_lease","AuthorityLease","consumer"],'
                '"severity":"medium"},'
                '{"category":"enforcement-boundary","file":"src/policy.py",'
                '"concepts":["require_active","project_id","invariant"],'
                '"severity":"high"}'
                ']}'
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
        assert result.agent.task_id is not None
        persisted = await db.list_coding_tasks(
            principal_id="test-principal",
            project_id="test-project",
        )
        task = next(
            item for item in persisted if item["id"] == result.agent.task_id
        )
        assert task["status"] in {"cancelled", "failed", "completed"}
    finally:
        await db.close()


@pytest.mark.posix_host
@pytest.mark.asyncio
async def test_checkpoint_failure_returns_typed_tool_result_without_agent_error(
    tmp_path, monkeypatch
) -> None:
    """A failed pre-edit fence must remain a retryable no-effect observation."""

    _patch_local_trusted_git(monkeypatch)
    from khaos.coding.checkpoints.service import CheckpointService

    async def unavailable_checkpoint(self, **_kwargs):
        raise RuntimeError("synthetic checkpoint backend failure")

    monkeypatch.setattr(
        CheckpointService,
        "create_checkpoint",
        unavailable_checkpoint,
    )

    class CheckpointProbeRouter:
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
                            "id": "apply-1",
                            "name": "apply_edit_transaction",
                            "arguments": {
                                "transaction_id": "checkpoint-probe",
                                "base_generation": 1,
                                "operations": [],
                                "intent": "probe checkpoint rejection",
                            },
                        }
                    ],
                    stop_reason="tool_use",
                )
                return
            yield Message(
                role="assistant",
                content="stopping after typed checkpoint rejection",
                stop_reason="end_turn",
            )

    router = CheckpointProbeRouter()
    db = Database(":memory:")
    await db.connect()
    await db.run_migrations()
    invoker = RuntimeCodingAgentInvoker(
        db,
        router,
        principal_id="test-principal",
        project_id="test-project",
        model="fake-model",
        provider="fake-provider",
    )
    runner = CodingEvaluationRunner(
        load_builtin_manifest(),
        fixture_manager=FixtureManager(builtin_manifest_path(), private_root=tmp_path),
        oracle=CodingOracle(),
        agent_invoker=invoker,
        principal_id="test-principal",
        project_id="test-project",
    )

    try:
        result = await runner.run("bugfix-python-cache")
        assert result.agent.status == "COMPLETED"
        assert router.calls == 2
        assert result.metrics.failed_tool_calls >= 1
        assert result.metrics.trace_truncated is False
    finally:
        await db.close()


@pytest.mark.posix_host
@pytest.mark.asyncio
@pytest.mark.parametrize("efficient", (True, False), ids=("efficient", "normal"))
async def test_p4_v2_fake_efficient_and_normal_paths_pass(tmp_path, monkeypatch, efficient) -> None:
    _patch_local_trusted_git(monkeypatch)
    db = Database(":memory:")
    await db.connect()
    await db.run_migrations()
    scenario = load_builtin_manifest().get("p4-readonly-authority")
    router = P4ScriptedRouter(efficient=efficient)
    invoker = RuntimeCodingAgentInvoker(
        db,
        router,
        principal_id="test-principal",
        project_id="test-project",
        model="fake-model",
        provider="offline-fake-provider",
    )
    runner = CodingEvaluationRunner(
        load_builtin_manifest(),
        fixture_manager=FixtureManager(builtin_manifest_path(), private_root=tmp_path),
        oracle=CodingOracle(),
        agent_invoker=invoker,
        principal_id="test-principal",
        project_id="test-project",
    )

    try:
        result = await runner.run(scenario.scenario_id)
        assert result.verdict.value == "PASS"
        assert result.agent.completed
        assert result.diff.changed_files == ()
        assert result.metrics.editing_calls == 0
        assert result.metrics.tool_calls == 3
        assert result.metrics.trace_schema_version == 2
        assert result.metrics.tool_calls_by_exact_name == {"read_file": 3}
        assert result.metrics.trace_truncated is False
        assert result.metrics.context_selection_id is not None
        assert result.metrics.context_selection_sequence is not None
        assert result.metrics.context_selection_count is not None
        context_observation = result.metrics.observability["context"]
        assert context_observation["selection_identity_status"] == "AVAILABLE"
        assert (
            context_observation["final_context_selection_id"]
            == result.metrics.context_selection_id
        )
        assert router.calls == (2 if efficient else 4)
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
