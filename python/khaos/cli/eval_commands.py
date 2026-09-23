# KHAOS-PRIVILEGED-SPAWN owner=CodingEvaluationCLI threat-model=trusted-source-git-provenance boundary=coding-evaluation-cli
"""CLI handlers for the M8.0 Coding capability evaluation plane."""

from __future__ import annotations

import asyncio
import json
import math
import os
import subprocess
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from khaos.db import Database
from khaos.db.state_root import open_state_db_safely, resolve_state_db_path
from khaos.db.state_root import project_id as compute_project_id
from khaos.evaluation.coding import (
    BenchmarkRunConfig,
    CodingBenchmarkJsonlWriter,
    CodingBenchmarkResultV1,
    CodingEvaluationRepository,
    CodingEvaluationRunner,
    CodingOracle,
    CodingQualificationJsonlWriter,
    CodingQualificationRecordV1,
    CodingResultState,
    ExecutionServiceOracleExecutor,
    FixtureManager,
    builtin_manifest_path,
    capture_working_tree_identity,
    compare_runs,
    load_builtin_manifest,
    load_manifest,
    report_json,
    report_markdown,
)
from khaos.evaluation.coding.contracts import digest_payload
from khaos.evaluation.coding.runtime_invoker import RuntimeCodingAgentInvoker
from khaos.evaluation.coding.sandbox import build_oracle_execution_service
from khaos.evaluation.coding.service import CodingEvaluationService
from khaos.routing.model_client import ModelClient, ProviderRequestObservation
from khaos.routing.table import RoutingRule
from khaos.runtime.context import local_principal_id
from khaos.security.credential_broker import CredentialBroker, CredentialBrokerError
from khaos.security.credentials import CredentialRef
from khaos.security.credentials import (
    provider_config_digest as build_provider_config_digest,
)


class _EvaluationSetupError(RuntimeError):
    """Safe, typed failure before an evaluation is allowed to call a provider."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _payload_text(payload: Mapping[str, object], key: str) -> str:
    """Require one non-empty text identity field from a typed payload."""

    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise _EvaluationSetupError(f"QUALIFICATION_{key.upper()}_INVALID")
    return value


def _payload_optional_text(payload: Mapping[str, object], key: str) -> str | None:
    """Project an optional qualification identity field without coercion."""

    value = payload.get(key)
    return value if isinstance(value, str) else None


def _payload_positive_int(payload: Mapping[str, object], key: str) -> int:
    """Require one positive integer identity field from a typed payload."""

    value = payload.get(key)
    if type(value) is not int or value <= 0:
        raise _EvaluationSetupError(f"QUALIFICATION_{key.upper()}_INVALID")
    return value


def _optional_positive_int(value: object) -> int | None:
    """Project an optional metric without encoding unavailable as zero."""

    return value if type(value) is int and value > 0 else None


def _payload_optional_observability_version(
    payload: Mapping[str, object],
) -> int | None:
    """Read the optional version without coercing malformed JSON values."""

    value = payload.get("observability_schema_version")
    if value is None:
        return None
    if type(value) is not int:
        raise _EvaluationSetupError("QUALIFICATION_OBSERVABILITY_SCHEMA_VERSION_INVALID")
    return value


def _payload_mapping(payload: Mapping[str, object], key: str) -> Mapping[str, object]:
    """Require one object-valued qualification field."""

    value = payload.get(key)
    if not isinstance(value, Mapping):
        raise _EvaluationSetupError(f"QUALIFICATION_{key.upper()}_INVALID")
    return value


def _payload_timeout_seconds(budgets: Mapping[str, object]) -> float:
    """Read the P4 timeout from the bound budget object."""

    p4_budget = budgets.get("p4")
    if not isinstance(p4_budget, Mapping):
        raise _EvaluationSetupError("QUALIFICATION_P4_BUDGET_INVALID")
    value = p4_budget.get("timeout_seconds")
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise _EvaluationSetupError("QUALIFICATION_P4_TIMEOUT_INVALID")
    timeout_seconds = float(value)
    if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
        raise _EvaluationSetupError("QUALIFICATION_P4_TIMEOUT_INVALID")
    return timeout_seconds


def cmd_eval(args: Any) -> int:
    """Dispatch ``khaos eval coding`` and return a process exit code."""

    if getattr(args, "eval_command", None) != "coding":
        print("usage: khaos eval coding {list|qualify|run|report|compare}")
        return 2
    action = getattr(args, "coding_command", None)
    if action == "list":
        return _list(args)
    if action == "run":
        return asyncio.run(_run(args))
    if action == "qualify":
        return asyncio.run(_qualify(args))
    if action == "report":
        return asyncio.run(_report(args))
    if action == "compare":
        return asyncio.run(_compare(args))
    print("usage: khaos eval coding {list|qualify|run|report|compare}")
    return 2


def _manifest(args: Any):
    path = Path(getattr(args, "manifest", None) or builtin_manifest_path())
    return load_builtin_manifest() if path == builtin_manifest_path() else load_manifest(path)


def _list(args: Any) -> int:
    manifest = _manifest(args)
    tag = getattr(args, "tag", None)
    values = manifest.select(tag=tag)
    if getattr(args, "as_json", False):
        print(
            json.dumps(
                {
                    "manifest_id": manifest.manifest_id,
                    "manifest_version": manifest.version,
                    "manifest_digest": manifest.digest,
                    "scenarios": [
                        {
                            "scenario_id": scenario.scenario_id,
                            "version": scenario.version,
                            "kind": scenario.kind.value,
                            "difficulty": scenario.difficulty,
                            "languages": list(scenario.languages),
                            "tags": list(scenario.tags),
                            "digest": scenario.digest,
                        }
                        for scenario in values
                    ],
                },
                ensure_ascii=False,
                sort_keys=True,
            )
        )
        return 0
    print(f"Manifest: {manifest.manifest_id} v{manifest.version}")
    print(f"Digest:   {manifest.digest}")
    for scenario in values:
        print(
            f"{scenario.scenario_id:40} {scenario.kind.value:14} "
            f"{scenario.difficulty:8} {','.join(scenario.languages):20} {' '.join(scenario.tags)}"
        )
    return 0


async def _run(args: Any) -> int:
    root = Path(getattr(args, "project_root", None) or Path.cwd()).expanduser().resolve()
    manifest_path = Path(getattr(args, "manifest", None) or builtin_manifest_path()).expanduser().resolve()
    manifest = _manifest(args)
    principal_id = getattr(args, "principal_id", None) or local_principal_id()
    project = getattr(args, "project_id", None) or compute_project_id(root)
    db_path = open_state_db_safely(resolve_state_db_path(root, getattr(args, "db", None)))
    db = Database(db_path)
    try:
        oracle_execution = await build_oracle_execution_service(
            principal_id=principal_id,
            project_id=project,
        )
    except Exception as exc:  # noqa: BLE001 - sandbox construction is an adapter boundary
        print(f"coding evaluation unavailable: {exc}", file=__import__("sys").stderr)
        return 3
    router = None
    provider_broker: CredentialBroker | None = None
    observations: list[ProviderRequestObservation] = []
    try:
        await db.connect()
        await db.run_migrations()
        config_path = Path(getattr(args, "config", None) or root / "config.yaml").expanduser().resolve()
        task_timeout_override = getattr(args, "task_timeout_seconds", None)
        _validate_task_timeout_override(task_timeout_override)
        from khaos.rpc.composition import load_router_from_config
        from khaos.security.effective_policy import load_effective_policy

        requested_model = getattr(args, "model", None)
        router = load_router_from_config(
            config_path,
            project_root=root,
            model_names={str(requested_model)} if requested_model else None,
        )
        provider_broker = _router_broker(router)
        effective_policy = load_effective_policy(root)
        effective_model, effective_provider = _select_evaluation_identity(
            router,
            requested_model=requested_model,
            requested_provider=getattr(args, "provider", None),
        )
        effective_model_output_tokens = _effective_model_output_tokens(
            router, effective_model
        )
        try:
            working_tree_identity = capture_working_tree_identity(
                _khaos_source_root(),
                excluded_paths=("docs/local-security-closure-report.md",),
            )
        except (OSError, ValueError) as exc:
            raise _EvaluationSetupError(
                "WORKING_TREE_IDENTITY_UNAVAILABLE"
            ) from exc
        await _unlock_evaluation_provider(
            router,
            provider=effective_provider,
            unlock_provider=getattr(args, "unlock_provider", None),
        )
        router.model_client = ModelClient(
            request_observer=observations.append,
            credential_broker=provider_broker,
        )
        provider_config_digest = _provider_config_digest_for_evaluation(
            config_path,
            router=router,
            provider_name=effective_provider,
        )
        benchmark_config_digest = _benchmark_config_digest(
            provider_config_digest,
            task_timeout_seconds=task_timeout_override,
            working_tree_identity=working_tree_identity,
        )
        invoker = RuntimeCodingAgentInvoker(
            db,
            router,
            principal_id=principal_id,
            project_id=project,
            model=effective_model,
            provider=effective_provider,
            task_timeout_seconds=task_timeout_override,
        )
        repository = CodingEvaluationRepository(
            db,
            principal_id=principal_id,
            project_id=project,
        )
        fixture_manager = FixtureManager(
            manifest_path,
            private_root=Path(tempfile.gettempdir()) / "khaos-m8-cli",
        )
        runner = CodingEvaluationRunner(
            manifest,
            fixture_manager=fixture_manager,
            oracle=CodingOracle(ExecutionServiceOracleExecutor(oracle_execution)),
            agent_invoker=invoker,
            repository=repository,
            principal_id=principal_id,
            project_id=project,
            khaos_source_sha=getattr(args, "khaos_source_sha", None) or _git_sha(_khaos_source_root()),
            config_digest=benchmark_config_digest,
            model=effective_model,
            provider=effective_provider,
            task_timeout_seconds=task_timeout_override,
            provider_observations=observations,
        )
        service = CodingEvaluationService(manifest, runner=runner, repository=repository)
        positional_scenario = getattr(args, "scenario_id", None)
        option_scenario = getattr(args, "scenario_option", None)
        if positional_scenario and option_scenario:
            print("choose either SCENARIO_ID or --scenario", file=__import__("sys").stderr)
            return 2
        scenario_id = positional_scenario or option_scenario
        values = await service.run(
            scenario_id=scenario_id,
            tag=getattr(args, "tag", None),
            all_scenarios=bool(getattr(args, "all_scenarios", False)),
        )
        results_path = getattr(args, "results_jsonl", None)
        if results_path is not None:
            provider_broker = getattr(
                getattr(router, "provider_manager", None),
                "credential_broker",
                None,
            )
            writer = CodingBenchmarkJsonlWriter(
                Path(results_path),
                secret_redactor=getattr(provider_broker, "secret_redactor", None),
            )
            for run in values:
                scenario = manifest.get(run.identity.scenario_id)
                config = BenchmarkRunConfig(
                    provider=run.identity.provider,
                    model=run.identity.model,
                    khaos_sha=run.identity.source_sha,
                    scenario_manifest_digest=manifest.digest,
                    config_digest=run.identity.config_digest,
                    task_seed=getattr(args, "task_seed", None) or "default",
                    reasoning_effort=getattr(args, "reasoning_effort", None),
                    max_turns=scenario.limits.max_model_turns,
                    max_tokens=effective_model_output_tokens,
                    task_timeout_seconds=(
                        task_timeout_override
                        if task_timeout_override is not None
                        else scenario.limits.timeout_seconds
                    ),
                    tool_budget=scenario.limits.max_tool_calls,
                    subagent_policy="runtime-default",
                    browser_policy=(
                        "fixture-only" if "browser" in scenario.tags else "not-used"
                    ),
                    network_policy="none",
                    approval_policy="benchmark-local-approved",
                    context_budget_tokens=_optional_positive_int(
                        run.metrics.context_tokens
                    ),
                    policy_digest=effective_policy.digest,
                    platform=run.identity.platform,
                    working_tree_identity=working_tree_identity,
                )
                await writer.append(CodingBenchmarkResultV1.from_run(run, scenario, config))
        payload = [run.to_payload() for run in values]
        if getattr(args, "as_json", False):
            print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
        else:
            for run in values:
                oracle = run.oracle.verdict.value if run.oracle is not None else "N/A"
                print(f"{run.identity.scenario_id}: {run.verdict.value} (oracle={oracle}, run={run.identity.run_id})")
        return 0 if all(run.verdict.value == "PASS" for run in values) else 1
    except _EvaluationSetupError as exc:
        print(f"coding evaluation blocked: {exc.code}", file=__import__("sys").stderr)
        return 2
    finally:
        await oracle_execution.close()
        if provider_broker is not None:
            await provider_broker.aclose()
        await db.close()


async def _qualify(args: Any) -> int:
    """Run the fresh sequential GLM qualification gate only."""

    root = Path(getattr(args, "project_root", None) or Path.cwd()).expanduser().resolve()
    principal_id = getattr(args, "principal_id", None) or local_principal_id()
    project = getattr(args, "project_id", None) or compute_project_id(root)
    router = None
    provider_broker: CredentialBroker | None = None
    try:
        config_path = Path(getattr(args, "config", None) or root / "config.yaml").expanduser().resolve()
        requested_model = str(getattr(args, "model", "") or "")
        requested_provider = str(getattr(args, "provider", "") or "")
        if not requested_model or not requested_provider:
            raise _EvaluationSetupError("MODEL_AND_PROVIDER_REQUIRED")
        from khaos.rpc.composition import load_router_from_config

        router = load_router_from_config(
            config_path,
            project_root=root,
            model_names={requested_model},
        )
        provider_broker = _router_broker(router)
        from khaos.security.effective_policy import load_effective_policy

        effective_policy = load_effective_policy(root)
        effective_model, effective_provider = _select_evaluation_identity(
            router,
            requested_model=requested_model,
            requested_provider=requested_provider,
        )
        provider_config = router.provider_manager.get_provider(effective_provider)
        configured_credential_ref = getattr(provider_config, "credential_ref", None)
        if configured_credential_ref is not None and not isinstance(
            configured_credential_ref,
            CredentialRef,
        ):
            raise _EvaluationSetupError("CREDENTIAL_REF_INVALID")
        credential_ref = (
            configured_credential_ref.to_config()
            if isinstance(configured_credential_ref, CredentialRef)
            else None
        )
        try:
            working_tree_identity = capture_working_tree_identity(
                _khaos_source_root(),
                excluded_paths=("docs/local-security-closure-report.md",),
            )
        except (OSError, ValueError) as exc:
            raise _EvaluationSetupError(
                "WORKING_TREE_IDENTITY_UNAVAILABLE"
            ) from exc
        await _unlock_evaluation_provider(
            router,
            provider=effective_provider,
            unlock_provider=getattr(args, "unlock_provider", None),
        )
        observations: list[ProviderRequestObservation] = []
        router.model_client = ModelClient(
            request_observer=observations.append,
            credential_broker=provider_broker,
        )
        from khaos.evaluation.coding.qualification import run_provider_qualification

        payload = await run_provider_qualification(
            router,
            model=effective_model,
            provider=effective_provider,
            observations=observations,
            principal_id=principal_id,
            project_id=project,
            config_digest=_provider_config_digest_for_evaluation(
                config_path,
                router=router,
                provider_name=effective_provider,
            ),
            source_sha=getattr(args, "khaos_source_sha", None)
            or _git_sha(_khaos_source_root()),
            working_tree_identity=working_tree_identity,
            policy_digest=effective_policy.digest,
            credential_ref=credential_ref,
            p4_scenario_id=(
                getattr(args, "p4_scenario", None)
                or "p4-readonly-authority"
            ),
        )
        output_path = getattr(args, "qualification_output", None)
        results_path = getattr(args, "results_jsonl", None)
        if results_path is not None:
            stages = payload.get("stages", ())
            if not isinstance(stages, (list, tuple)):
                raise _EvaluationSetupError("QUALIFICATION_STAGES_INVALID")
            provider_failure = any(
                isinstance(stage, Mapping)
                and stage.get("provider_failure_class") is not None
                for stage in stages
            )
            qualification_budgets = _payload_mapping(payload, "budgets")
            result = CodingQualificationRecordV1(
                run_id=_payload_text(payload, "run_id"),
                result_state=(
                    CodingResultState.MODEL_ERROR
                    if provider_failure
                    else CodingResultState.SUCCESS
                    if payload.get("qualification") == "PASS"
                    else CodingResultState.FAILURE
                ),
                provider=_payload_text(payload, "provider"),
                model=_payload_text(payload, "model"),
                provider_returned_model_id=str(
                    payload.get("provider_returned_model_id") or "UNKNOWN / PROVIDER_NOT_REPORTED"
                ),
                source_sha=_payload_text(payload, "source_sha"),
                working_tree_identity=_payload_optional_text(payload, "working_tree_identity"),
                provider_config_digest=_payload_optional_text(payload, "provider_config_digest"),
                suite_id=_payload_text(payload, "suite_id"),
                suite_version=_payload_positive_int(payload, "suite_version"),
                suite_digest=_payload_text(payload, "suite_digest"),
                scenario_id=_payload_text(payload, "scenario_id"),
                scenario_version=_payload_positive_int(payload, "scenario_version"),
                scenario_digest=_payload_optional_text(payload, "scenario_digest"),
                fixture_digest=_payload_optional_text(payload, "fixture_digest"),
                prompt_digest=_payload_optional_text(payload, "prompt_digest"),
                system_prompt_digest=_payload_optional_text(payload, "system_prompt_digest"),
                tool_schema_digest=_payload_optional_text(payload, "tool_schema_digest"),
                policy_digest=_payload_optional_text(payload, "policy_digest"),
                budgets=qualification_budgets,
                timeout_seconds=_payload_timeout_seconds(qualification_budgets),
                credential_ref=_payload_optional_text(payload, "credential_ref"),
                reasoning_configuration=_payload_mapping(payload, "reasoning_configuration"),
                metrics={
                    "qualification": payload.get("qualification"),
                    "provider_requests": payload.get("provider_requests"),
                    "stage_count": len(stages),
                    "secret_values_printed": payload.get("secret_values_printed"),
                    "observability_schema_version": payload.get(
                        "observability_schema_version"
                    ),
                    "observability_reconciliation": tuple(
                        stage.get("trace_reconciliation")
                        for stage in stages
                        if isinstance(stage, Mapping)
                        and stage.get("trace_reconciliation") is not None
                    ),
                },
                stages=tuple(stage for stage in stages if isinstance(stage, Mapping)),
                started_at=str(payload.get("started_at") or "UNKNOWN / NOT_REPORTED"),
                finished_at=str(payload.get("finished_at") or "UNKNOWN / NOT_REPORTED"),
                observability_schema_version=_payload_optional_observability_version(payload),
            )
            await CodingQualificationJsonlWriter(Path(results_path)).append(result)
        serialized = json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2)
        if output_path is not None:
            Path(output_path).expanduser().resolve().write_text(
                serialized + "\n",
                encoding="utf-8",
            )
        print(serialized)
        return 0 if payload.get("qualification") == "PASS" else 1
    except _EvaluationSetupError as exc:
        print(f"coding qualification blocked: {exc.code}", file=__import__("sys").stderr)
        return 2
    finally:
        if provider_broker is not None:
            await provider_broker.aclose()


async def _report(args: Any) -> int:
    root = Path(getattr(args, "project_root", None) or Path.cwd()).expanduser().resolve()
    principal_id = getattr(args, "principal_id", None) or local_principal_id()
    project = getattr(args, "project_id", None) or compute_project_id(root)
    db_path = open_state_db_safely(resolve_state_db_path(root, getattr(args, "db", None)))
    db = Database(db_path)
    await db.connect()
    try:
        await db.run_migrations()
        repository = CodingEvaluationRepository(db, principal_id=principal_id, project_id=project)
        positional_run_id = getattr(args, "run_id_positional", None)
        option_run_id = getattr(args, "run_id", None)
        if positional_run_id and option_run_id:
            print("choose either RUN_ID or --run-id", file=__import__("sys").stderr)
            return 2
        run_id = positional_run_id or option_run_id
        if run_id:
            value = await repository.get_by_id(run_id, principal_id=principal_id, project_id=project)
            runs = () if value is None else (value,)
        else:
            runs = await repository.list(
                principal_id=principal_id,
                project_id=project,
                scenario_id=getattr(args, "scenario_id", None),
                limit=getattr(args, "limit", 100),
            )
        if getattr(args, "format", "markdown") == "json":
            print(report_json(runs, pretty=True))
        else:
            print(report_markdown(runs), end="")
        return 0
    finally:
        await db.close()


async def _compare(args: Any) -> int:
    root = Path(getattr(args, "project_root", None) or Path.cwd()).expanduser().resolve()
    principal_id = getattr(args, "principal_id", None) or local_principal_id()
    project = getattr(args, "project_id", None) or compute_project_id(root)
    db_path = open_state_db_safely(resolve_state_db_path(root, getattr(args, "db", None)))
    db = Database(db_path)
    await db.connect()
    try:
        await db.run_migrations()
        repository = CodingEvaluationRepository(db, principal_id=principal_id, project_id=project)
        baseline = await repository.get_by_id(args.baseline_run_id, principal_id=principal_id, project_id=project)
        candidate = await repository.get_by_id(args.candidate_run_id, principal_id=principal_id, project_id=project)
        if baseline is None or candidate is None:
            print("coding evaluation run not found", file=__import__("sys").stderr)
            return 2
        result = compare_runs(baseline, candidate).to_payload()
        print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
        return 0
    finally:
        await db.close()


def _router_identity(router: Any) -> tuple[str, str]:
    rules = getattr(router, "_rules", {})
    rule = rules.get("coding") if isinstance(rules, dict) else None
    model = str(getattr(rule, "primary_model", "configured"))
    provider_manager = getattr(router, "provider_manager", None)
    provider = "configured"
    if provider_manager is not None:
        try:
            provider = str(provider_manager.get_model(model).provider)
        except (AttributeError, KeyError):
            pass
    return model, provider


def _router_broker(router: Any) -> CredentialBroker | None:
    """Return the router-owned broker without constructing a second authority."""

    broker = getattr(getattr(router, "provider_manager", None), "credential_broker", None)
    return broker if isinstance(broker, CredentialBroker) else None


def _select_evaluation_identity(
    router: Any,
    *,
    requested_model: object,
    requested_provider: object,
) -> tuple[str, str]:
    """Validate and bind one explicit model to every runtime model route."""

    manager = getattr(router, "provider_manager", None)
    if manager is None:
        raise _EvaluationSetupError("ROUTER_PROVIDER_MANAGER_UNAVAILABLE")
    configured_model, _configured_provider = _router_identity(router)
    model = str(requested_model or configured_model)
    if not model or model == "configured":
        raise _EvaluationSetupError("MODEL_NOT_CONFIGURED")
    try:
        spec = manager.get_model(model)
        available = manager.is_model_available(model)
    except (AttributeError, KeyError):
        raise _EvaluationSetupError("MODEL_NOT_CONFIGURED") from None
    if not available:
        raise _EvaluationSetupError("MODEL_UNAVAILABLE")
    provider = str(getattr(spec, "provider", ""))
    if not provider:
        raise _EvaluationSetupError("MODEL_PROVIDER_UNAVAILABLE")
    if requested_provider and str(requested_provider).casefold() != provider.casefold():
        raise _EvaluationSetupError("MODEL_PROVIDER_MISMATCH")
    try:
        manager.get_provider(provider)
    except (AttributeError, KeyError):
        raise _EvaluationSetupError("MODEL_PROVIDER_NOT_CONFIGURED") from None
    _bind_router_to_model(router, model)
    return model, provider


def _bind_router_to_model(router: Any, model: str) -> None:
    """Make the selected model the sole route, with no fallback candidate."""

    setter = getattr(router, "set_rule", None)
    if not callable(setter):
        raise _EvaluationSetupError("ROUTER_CANNOT_BIND_MODEL")
    raw_rules = getattr(router, "_rules", {})
    functions = {"agent_loop", "coding", "compression"}
    if isinstance(raw_rules, Mapping):
        functions.update(str(function) for function in raw_rules)
    for function in sorted(functions):
        existing = raw_rules.get(function) if isinstance(raw_rules, Mapping) else None
        setter(
            function,
            RoutingRule(
                function=function,
                primary_model=model,
                fallback_models=(),
                prefer_coding_model=bool(
                    getattr(existing, "prefer_coding_model", function == "coding")
                ),
            ),
        )


async def _unlock_evaluation_provider(
    router: Any,
    *,
    provider: str,
    unlock_provider: object,
) -> None:
    """Require an explicit operator unlock before any real evaluation request."""

    manager = getattr(router, "provider_manager", None)
    if manager is None:
        raise _EvaluationSetupError("ROUTER_PROVIDER_MANAGER_UNAVAILABLE")
    try:
        config = manager.get_provider(provider)
    except (AttributeError, KeyError):
        raise _EvaluationSetupError("MODEL_PROVIDER_NOT_CONFIGURED") from None
    ref = getattr(config, "credential_ref", None)
    if ref is None:
        return
    if not isinstance(ref, CredentialRef):
        raise _EvaluationSetupError("CREDENTIAL_REF_INVALID")
    broker = _router_broker(router)
    if broker is None:
        raise _EvaluationSetupError("CREDENTIAL_BROKER_UNAVAILABLE")
    target = str(unlock_provider or "").casefold()
    if target not in {"all", provider.casefold()}:
        if target:
            raise _EvaluationSetupError("UNLOCK_PROVIDER_MISMATCH")
        raise _EvaluationSetupError("CREDENTIAL_SESSION_UNLOCK_REQUIRED")
    try:
        await asyncio.to_thread(
            broker.credential_session.unlock,
            ref,
            provider=provider,
        )
        status = await asyncio.to_thread(
            broker.credential_session.status,
            ref,
            provider=provider,
        )
    except CredentialBrokerError as exc:
        code = getattr(exc, "code", None)
        safe_code = code if isinstance(code, str) and code.isidentifier() else type(exc).__name__
        raise _EvaluationSetupError(safe_code) from None
    except Exception as exc:  # noqa: BLE001 - credential adapter boundary
        raise _EvaluationSetupError(type(exc).__name__) from None
    if not isinstance(status, Mapping):
        raise _EvaluationSetupError("CREDENTIAL_SESSION_STATUS_INVALID")
    if status.get("session") != "UNLOCKED" or status.get("runtime_credential") != "AVAILABLE":
        raise _EvaluationSetupError("CREDENTIAL_SESSION_NOT_AVAILABLE")


def _provider_config_digest_for_evaluation(
    config_path: Path,
    *,
    router: Any,
    provider_name: str,
) -> str:
    """Build the canonical secret-free digest for one configured Provider."""

    from khaos.config import load_config

    raw_config = load_config(config_path, strict_env=False)
    models_config = raw_config.get("models")
    providers = models_config.get("providers") if isinstance(models_config, Mapping) else None
    provider_data = providers.get(provider_name) if isinstance(providers, Mapping) else None
    if not isinstance(provider_data, Mapping):
        raise _EvaluationSetupError("PROVIDER_CONFIG_DIGEST_UNAVAILABLE")
    model_entries = provider_data.get("models")
    model_names = sorted(
        {
            str(entry.get("name"))
            for entry in model_entries
            if isinstance(entry, Mapping)
            and isinstance(entry.get("name"), str)
            and entry.get("name")
        }
    ) if isinstance(model_entries, list) else []
    if not model_names:
        raise _EvaluationSetupError("PROVIDER_CONFIG_DIGEST_UNAVAILABLE")
    provider_config = router.provider_manager.get_provider(provider_name)
    credential_ref = getattr(provider_config, "credential_ref", None)
    safe_config: dict[str, object] = {
        "provider": provider_config.name,
        "type": provider_config.type,
        "base_url": provider_config.base_url,
        "models": model_names,
        "credential_ref": (
            credential_ref.to_config()
            if isinstance(credential_ref, CredentialRef)
            else None
        ),
    }
    return build_provider_config_digest(safe_config)


def _validate_task_timeout_override(value: object) -> None:
    """Validate an optional run-level timeout without changing scenario identity."""

    if value is None:
        return
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or not 0 < float(value) <= 3600
    ):
        raise ValueError("task_timeout_seconds is outside (0, 3600]")


def _benchmark_config_digest(
    provider_config_digest: str,
    *,
    task_timeout_seconds: float | None,
    working_tree_identity: str | None = None,
) -> str:
    """Bind run-level overrides and worktree provenance to config identity."""

    if task_timeout_seconds is None and working_tree_identity is None:
        return provider_config_digest
    payload: dict[str, object] = {
        "provider_config_digest": provider_config_digest,
    }
    if task_timeout_seconds is not None:
        payload["task_timeout_seconds"] = float(task_timeout_seconds)
    if working_tree_identity is not None:
        payload["working_tree_identity"] = working_tree_identity
    return digest_payload(payload)


def _effective_model_output_tokens(router: Any, model_name: str) -> int:
    """Expose the selected model's effective output ceiling to evidence."""

    model = router.provider_manager.get_model(model_name)
    value = getattr(model, "max_output_tokens", None)
    if type(value) is not int or value <= 0:
        raise ValueError("selected model output token ceiling is invalid")
    return value


def _git_sha(root: Path) -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(root),
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
            env={
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_TERMINAL_PROMPT": "0",
                "LC_ALL": "C",
            },
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    value = result.stdout.strip()
    return value if result.returncode == 0 and value else "unknown"


def _khaos_source_root() -> Path:
    """Locate checked-out Khaos source independently of evaluated repo root."""

    return Path(__file__).resolve().parents[3]


__all__ = ["cmd_eval"]
