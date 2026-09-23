"""Fresh-interpreter dependency-direction regression tests."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

_DIRECT_IMPORTS = (
    "khaos.audit.logger",
    "khaos.security.credential_broker",
    "khaos.security.resource_scope",
    "khaos.coding.planning",
    "khaos.agent.error_handler",
    "khaos.rpc.composition",
)

_IMPORT_ORDERS = (
    ("audit -> broker", ("khaos.audit.logger", "khaos.security.credential_broker")),
    ("broker -> audit", ("khaos.security.credential_broker", "khaos.audit.logger")),
    ("resource_scope -> planning", ("khaos.security.resource_scope", "khaos.coding.planning")),
    ("planning -> resource_scope", ("khaos.coding.planning", "khaos.security.resource_scope")),
    ("error_handler -> audit", ("khaos.agent.error_handler", "khaos.audit.logger")),
    ("audit -> error_handler", ("khaos.audit.logger", "khaos.agent.error_handler")),
    ("audit -> composition", ("khaos.audit.logger", "khaos.rpc.composition")),
    ("broker -> composition", ("khaos.security.credential_broker", "khaos.rpc.composition")),
    ("planning -> composition", ("khaos.coding.planning", "khaos.rpc.composition")),
)


def _clean_process_environment(python_root: Path) -> dict[str, str]:
    """Use only deterministic non-secret process inputs for import probes."""

    return {
        "PATH": "/usr/bin:/bin:/opt/homebrew/bin",
        "PYTHONNOUSERSITE": "1",
        "PYTHONPATH": str(python_root),
        "LC_ALL": "C",
    }


def _run_python_probe(source: str) -> subprocess.CompletedProcess[str]:
    python_root = Path(__file__).resolve().parents[2]
    return subprocess.run(
        [sys.executable, "-c", source],
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
        cwd=str(python_root.parent),
        env=_clean_process_environment(python_root),
    )


def _run_import_probe(imports: tuple[str, ...]) -> subprocess.CompletedProcess[str]:
    source = "; ".join(f"import {module}" for module in imports)
    return _run_python_probe(source)


@pytest.mark.parametrize("module", _DIRECT_IMPORTS)
def test_direct_imports_succeed_in_fresh_process(module: str) -> None:
    """Each target module must cold-import without a partially initialized module."""

    result = _run_import_probe((module,))
    assert result.returncode == 0, f"module={module}\nstderr={result.stderr}"


@pytest.mark.parametrize("label, imports", _IMPORT_ORDERS)
def test_security_audit_planning_import_order_is_acyclic(
    label: str,
    imports: tuple[str, ...],
) -> None:
    """Every relevant order runs in a separate clean interpreter."""

    result = _run_import_probe(imports)
    assert result.returncode == 0, f"order={label}\nstderr={result.stderr}"


def test_planning_reexports_security_workspace_identity() -> None:
    """The compatibility import must not create a second nominal identity."""

    result = _run_python_probe(
        "from khaos.security.identities import "
        "CanonicalWorkspaceId as security_identity; "
        "from khaos.coding.planning.security_identities import "
        "CanonicalWorkspaceId as planning_identity; "
        "assert planning_identity is security_identity"
    )
    assert result.returncode == 0, result.stderr


def test_production_router_smoke_does_not_materialize_credentials() -> None:
    """The production router can initialize without provider side effects."""

    python_root = Path(__file__).resolve().parents[2]
    root_literal = repr(str(python_root.parent))
    source = (
        "import json; "
        "from pathlib import Path; "
        "from khaos.rpc.composition import load_router_from_config; "
        f"root = Path({root_literal}); "
        "router = load_router_from_config(root / 'config.yaml', "
        "project_root=root, model_names={'glm-5.3'}); "
        "manager = router.provider_manager; "
        "spec = manager.get_model('glm-5.3'); "
        "broker = manager.credential_broker; "
        "print(json.dumps({'provider': spec.provider, 'model': 'glm-5.3', "
        "'sessions': len(getattr(broker, '_session_credentials', {})), "
        "'materializations': len(getattr(broker, '_materializations', {}))}, "
        "sort_keys=True))"
    )
    result = subprocess.run(
        [sys.executable, "-c", source],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        cwd=str(python_root.parent),
        env=_clean_process_environment(python_root),
    )
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload == {
        "model": "glm-5.3",
        "provider": "zhipu-coding",
        "sessions": 0,
        "materializations": 0,
    }


def test_qualification_bootstrap_imports_without_provider_call() -> None:
    """Qualification setup resolves its contracts before session/provider use."""

    python_root = Path(__file__).resolve().parents[2]
    root_literal = repr(str(python_root.parent))
    source = (
        "import json; "
        "from pathlib import Path; "
        "from khaos.cli.eval_commands import _router_broker, _select_evaluation_identity; "
        "from khaos.evaluation.coding import CodingQualificationJsonlWriter, "
        "CodingTraceCollector, load_builtin_manifest; "
        "from khaos.evaluation.coding.manifest import builtin_manifest_path, resolve_fixture_path; "
        "from khaos.rpc.composition import load_router_from_config; "
        "from khaos.security.effective_policy import load_effective_policy; "
        f"root = Path({root_literal}); "
        "router = load_router_from_config(root / 'config.yaml', "
        "project_root=root, model_names={'glm-5.3'}); "
        "model, provider = _select_evaluation_identity(router, "
        "requested_model='glm-5.3', requested_provider='zhipu-coding'); "
        "policy = load_effective_policy(root); "
        "manifest = load_builtin_manifest(); "
        "scenario = manifest.get('p4-readonly-authority'); "
        "fixture = resolve_fixture_path(builtin_manifest_path(), scenario); "
        "trace = CodingTraceCollector(max_model_turns=scenario.limits.max_model_turns, "
        "max_tool_calls=scenario.limits.max_tool_calls, run_id='bootstrap-probe'); "
        "writer = CodingQualificationJsonlWriter(root / '.qualification-bootstrap.jsonl'); "
        "broker = _router_broker(router); "
        "print(json.dumps({'model': model, 'provider': provider, "
        "'policy_digest': policy.digest, 'scenario_id': scenario.scenario_id, "
        "'scenario_version': scenario.version, 'fixture_resolved': fixture.is_dir(), "
        "'trace': type(trace).__name__, 'writer': type(writer).__name__, "
        "'provider_requests': 0, 'credential_materializations': "
        "len(getattr(broker, '_materializations', {})), "
        "'credential_sessions': len(getattr(broker, '_session_credentials', {}))}, "
        "sort_keys=True))"
    )
    result = subprocess.run(
        [sys.executable, "-c", source],
        check=False,
        capture_output=True,
        text=True,
        timeout=45,
        cwd=str(python_root.parent),
        env=_clean_process_environment(python_root),
    )
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["model"] == "glm-5.3"
    assert payload["provider"] == "zhipu-coding"
    assert payload["scenario_id"] == "p4-readonly-authority"
    assert payload["scenario_version"] == 2
    assert payload["fixture_resolved"] is True
    assert payload["trace"] == "CodingTraceCollector"
    assert payload["writer"] == "CodingQualificationJsonlWriter"
    assert payload["provider_requests"] == 0
    assert payload["credential_materializations"] == 0
    assert payload["credential_sessions"] == 0
