from __future__ import annotations

from types import SimpleNamespace

from khaos.cli.eval_commands import (
    _benchmark_config_digest,
    _bind_router_to_model,
    _effective_model_output_tokens,
    _optional_positive_int,
    _provider_config_digest_for_evaluation,
)
from khaos.cli.main import build_command_parser
from khaos.routing import ModelRouter
from khaos.routing.provider import ModelSpec, ProviderConfig, ProviderManager
from khaos.routing.table import RoutingRule
from khaos.security.credentials import provider_config_digest


def test_coding_eval_cli_exposes_list_run_report_and_compare() -> None:
    parser = build_command_parser()

    listed = parser.parse_args(["eval", "coding", "list", "--json"])
    run = parser.parse_args(["eval", "coding", "run", "bugfix-python-cache"])
    timeout_run = parser.parse_args(
        [
            "eval",
            "coding",
            "run",
            "bugfix-python-cache",
            "--task-timeout-seconds",
            "240",
        ]
    )
    unlocked_run = parser.parse_args(
        [
            "eval",
            "coding",
            "run",
            "bugfix-python-cache",
            "--model",
            "glm-5.3",
            "--provider",
            "zhipu-coding",
            "--unlock",
            "zhipu-coding",
        ]
    )
    artifact_run = parser.parse_args(
        [
            "eval",
            "coding",
            "run",
            "bugfix-python-cache",
            "--results-jsonl",
            "/tmp/m8-results.jsonl",
            "--task-seed",
            "seed-1",
        ]
    )
    tagged = parser.parse_args(["eval", "coding", "run", "--tag", "smoke"])
    qualification = parser.parse_args(
        [
            "eval",
            "coding",
            "qualify",
            "--model",
            "glm-5.3",
            "--provider",
            "zhipu-coding",
            "--unlock",
            "zhipu-coding",
            "--output",
            "/tmp/m8-qualification.json",
            "--results-jsonl",
            "/tmp/m8-qualification.jsonl",
        ]
    )
    qualification_v3 = parser.parse_args(
        [
            "eval",
            "coding",
            "qualify",
            "--model",
            "glm-5.3-flash",
            "--provider",
            "zhipu-coding",
            "--unlock",
            "zhipu-coding",
            "--p4-scenario",
            "p4-readonly-authority-v3",
        ]
    )
    report = parser.parse_args(["eval", "coding", "report", "m8-run", "--format", "json"])
    compared = parser.parse_args(["eval", "coding", "compare", "m8-a", "m8-b"])

    assert (listed.eval_command, listed.coding_command, listed.as_json) == (
        "coding",
        "list",
        True,
    )
    assert run.scenario_id == "bugfix-python-cache"
    assert timeout_run.task_timeout_seconds == 240.0
    assert (unlocked_run.model, unlocked_run.provider, unlocked_run.unlock_provider) == (
        "glm-5.3",
        "zhipu-coding",
        "zhipu-coding",
    )
    assert str(artifact_run.results_jsonl) == "/tmp/m8-results.jsonl"
    assert artifact_run.task_seed == "seed-1"
    assert tagged.tag == "smoke"
    assert (
        qualification.model,
        qualification.provider,
        qualification.unlock_provider,
        str(qualification.qualification_output),
        str(qualification.results_jsonl),
    ) == (
        "glm-5.3",
        "zhipu-coding",
        "zhipu-coding",
        "/tmp/m8-qualification.json",
        "/tmp/m8-qualification.jsonl",
    )
    assert qualification_v3.p4_scenario == "p4-readonly-authority-v3"
    assert report.format == "json"
    assert report.run_id_positional == "m8-run"
    assert (compared.baseline_run_id, compared.candidate_run_id) == ("m8-a", "m8-b")


def test_timeout_override_gets_a_distinct_benchmark_config_digest() -> None:
    provider_digest = "a" * 64

    assert _benchmark_config_digest(provider_digest, task_timeout_seconds=None) == provider_digest
    assert _benchmark_config_digest(provider_digest, task_timeout_seconds=120) != provider_digest
    assert _benchmark_config_digest(provider_digest, task_timeout_seconds=240) != _benchmark_config_digest(
        provider_digest,
        task_timeout_seconds=120,
    )
    assert _benchmark_config_digest(
        provider_digest,
        task_timeout_seconds=None,
        working_tree_identity="d" * 64,
    ) != provider_digest


def test_qualification_digest_is_provider_scoped_and_secretless(
    tmp_path,
    monkeypatch,
) -> None:
    home = tmp_path / "home"
    config_path = home / ".khaos" / "config.yaml"
    config_path.parent.mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    config_path.write_text(
        """
models:
  providers:
    target:
      type: openai_compatible
      base_url: https://example.test/v1
      models:
        - name: model-b
        - name: model-a
  default_model: model-a
unrelated:
  value: changes-do-not-affect-provider-digest
""",
        encoding="utf-8",
    )
    manager = ProviderManager()
    manager.register_provider(
        ProviderConfig(name="target", base_url="https://example.test/v1")
    )
    router = SimpleNamespace(provider_manager=manager)

    digest = _provider_config_digest_for_evaluation(
        config_path,
        router=router,
        provider_name="target",
    )
    assert digest == provider_config_digest(
        {
            "provider": "target",
            "type": "openai_compatible",
            "base_url": "https://example.test/v1",
            "credential_ref": None,
            "models": ["model-a", "model-b"],
        }
    )
    config_path.write_text(
        config_path.read_text(encoding="utf-8").replace(
            "changes-do-not-affect-provider-digest",
            "a-different-value",
        ),
        encoding="utf-8",
    )
    assert _provider_config_digest_for_evaluation(
        config_path,
        router=router,
        provider_name="target",
    ) == digest


def test_optional_positive_int_preserves_unknown_metric_as_null() -> None:
    assert _optional_positive_int(128) == 128
    assert _optional_positive_int(0) is None
    assert _optional_positive_int(None) is None
    assert _optional_positive_int(False) is None


def test_evaluation_evidence_uses_selected_model_output_ceiling() -> None:
    manager = ProviderManager()
    manager.register_provider(ProviderConfig(name="mock", base_url="mock://local"))
    manager.register_model(
        "model-a",
        ModelSpec(
            provider="mock",
            model="model-a",
            max_context_tokens=128000,
            max_output_tokens=32768,
        ),
    )
    router = ModelRouter(provider_manager=manager)

    assert _effective_model_output_tokens(router, "model-a") == 32768


def test_selected_evaluation_model_replaces_all_runtime_routes_without_fallback() -> None:
    manager = ProviderManager()
    manager.register_provider(ProviderConfig(name="mock", base_url="mock://local"))
    manager.register_model(
        "model-a",
        ModelSpec(provider="mock", model="model-a", max_context_tokens=128000),
    )
    manager.register_model(
        "model-b",
        ModelSpec(provider="mock", model="model-b", max_context_tokens=128000),
    )
    router = ModelRouter(provider_manager=manager)
    router.set_rule(
        "coding",
        RoutingRule(
            function="coding",
            primary_model="model-a",
            fallback_models=("model-b",),
            prefer_coding_model=True,
        ),
    )

    _bind_router_to_model(router, "model-b")

    for function in ("agent_loop", "coding", "compression"):
        rule = router._rules[function]
        assert rule.primary_model == "model-b"
        assert rule.fallback_models == ()
