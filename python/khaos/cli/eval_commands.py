# KHAOS-PRIVILEGED-SPAWN owner=CodingEvaluationCLI threat-model=trusted-source-git-provenance boundary=coding-evaluation-cli
"""CLI handlers for the M8.0 Coding capability evaluation plane."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from khaos.db import Database
from khaos.db.state_root import open_state_db_safely, resolve_state_db_path
from khaos.evaluation.coding import (
    CodingEvaluationRepository,
    CodingEvaluationRunner,
    CodingOracle,
    ExecutionServiceOracleExecutor,
    FixtureManager,
    builtin_manifest_path,
    compare_runs,
    load_builtin_manifest,
    load_manifest,
    report_json,
    report_markdown,
)
from khaos.evaluation.coding.sandbox import build_oracle_execution_service
from khaos.evaluation.coding.service import CodingEvaluationService
from khaos.evaluation.coding.runtime_invoker import RuntimeCodingAgentInvoker
from khaos.runtime.context import local_principal_id
from khaos.db.state_root import project_id as compute_project_id


def cmd_eval(args: Any) -> int:
    """Dispatch ``khaos eval coding`` and return a process exit code."""

    if getattr(args, "eval_command", None) != "coding":
        print("usage: khaos eval coding {list|run|report|compare}")
        return 2
    action = getattr(args, "coding_command", None)
    if action == "list":
        return _list(args)
    if action == "run":
        return asyncio.run(_run(args))
    if action == "report":
        return asyncio.run(_report(args))
    if action == "compare":
        return asyncio.run(_compare(args))
    print("usage: khaos eval coding {list|run|report|compare}")
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
    except Exception as exc:
        print(f"coding evaluation unavailable: {exc}", file=__import__("sys").stderr)
        return 3
    router = None
    try:
        await db.connect()
        await db.run_migrations()
        config_path = Path(getattr(args, "config", None) or root / "config.yaml").expanduser().resolve()
        from khaos.rpc.composition import load_router_from_config

        router = load_router_from_config(config_path, project_root=root)
        model, provider = _router_identity(router)
        invoker = RuntimeCodingAgentInvoker(
            db,
            router,
            principal_id=principal_id,
            project_id=project,
            model=getattr(args, "model", None) or model,
            provider=getattr(args, "provider", None) or provider,
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
        config_digest = _file_digest(config_path)
        runner = CodingEvaluationRunner(
            manifest,
            fixture_manager=fixture_manager,
            oracle=CodingOracle(ExecutionServiceOracleExecutor(oracle_execution)),
            agent_invoker=invoker,
            repository=repository,
            principal_id=principal_id,
            project_id=project,
            khaos_source_sha=getattr(args, "khaos_source_sha", None) or _git_sha(_khaos_source_root()),
            config_digest=config_digest,
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
        payload = [run.to_payload() for run in values]
        if getattr(args, "as_json", False):
            print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
        else:
            for run in values:
                oracle = run.oracle.verdict.value if run.oracle is not None else "N/A"
                print(f"{run.identity.scenario_id}: {run.verdict.value} (oracle={oracle}, run={run.identity.run_id})")
        return 0 if all(run.verdict.value == "PASS" for run in values) else 1
    finally:
        await oracle_execution.close()
        await db.close()


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


def _file_digest(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return hashlib.sha256(b"missing-config").hexdigest()


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
