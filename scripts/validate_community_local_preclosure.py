#!/usr/bin/env python3
"""Validate the Community Local PR pre-closure contract.

The pre-closure check is deliberately structural.  It validates that the
current proof names, producer mappings, artifact names, schemas, policy-digest
bindings, and workflow wiring still agree.  It never runs a producer, reads a
saved evidence record, or issues a release decision.
"""

from __future__ import annotations

import importlib.util
import inspect
import sys
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from types import ModuleType
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[1]
PYTHON_ROOT = ROOT / "python"
PRE_CLOSURE_LABEL = "COMMUNITY_LOCAL_PRE_CLOSURE"
PRE_CLOSURE_STATUSES = ("PASS", "FAIL")


def _load_script_module(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load contract module: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _contract_modules(root: Path) -> tuple[ModuleType, ...]:
    if str(root / "python") not in sys.path:
        sys.path.insert(0, str(root / "python"))
    matrix = _load_script_module(
        "khaos_security_producer_matrix",
        root / "scripts" / "run_security_producer_matrix.py",
    )
    collector = _load_script_module(
        "khaos_collect_local_security_evidence",
        root / "scripts" / "collect_local_security_evidence.py",
    )
    fetcher = _load_script_module(
        "khaos_fetch_security_producer_artifacts",
        root / "scripts" / "fetch_security_producer_artifacts.py",
    )
    release_verifier = _load_script_module(
        "khaos_verify_release_gate_runs",
        root / "scripts" / "verify_release_gate_runs.py",
    )
    from khaos.security import local_closure, producer_evidence

    return matrix, collector, fetcher, release_verifier, local_closure, producer_evidence


def _normalise_artifact_pattern(pattern: object) -> str:
    if not isinstance(pattern, str) or not pattern:
        return ""
    return pattern.replace("{}", "{commit}")


def validate_proof_mapping(
    required_proofs: Iterable[str],
    ordinary_producers: Mapping[str, Sequence[str]],
    producer_artifacts: Mapping[str, str],
    *,
    production_artifact_roles: Mapping[str, str] | None = None,
    root: Path = ROOT,
    require_test_files: bool = True,
) -> list[str]:
    """Validate proof ownership without accepting a caller-supplied result."""

    required = {str(name) for name in required_proofs}
    ordinary = set(ordinary_producers)
    production_roles = dict(production_artifact_roles or {})
    production = set(production_roles)
    errors: list[str] = []

    unknown_ordinary = ordinary - required
    if unknown_ordinary:
        errors.append(
            "producer mapping contains unknown proof(s): "
            + ", ".join(sorted(unknown_ordinary))
        )
    missing_ordinary = (required - production) - ordinary
    if missing_ordinary:
        errors.append(
            "producer mapping is missing proof(s): "
            + ", ".join(sorted(missing_ordinary))
        )
    ordinary_production_overlap = ordinary & production
    if ordinary_production_overlap:
        errors.append(
            "ordinary producer mapping owns production proof(s): "
            + ", ".join(sorted(ordinary_production_overlap))
        )
    unknown_production = production - required
    if unknown_production:
        errors.append(
            "production producer mapping contains unknown proof(s): "
            + ", ".join(sorted(unknown_production))
        )

    if set(producer_artifacts) != required:
        errors.append(
            "producer artifact mapping is not exact: "
            f"missing={sorted(required - set(producer_artifacts))} "
            f"unexpected={sorted(set(producer_artifacts) - required)}"
        )

    allowed_roles = {"ordinary", *production_roles.values()}
    for proof_name, role in producer_artifacts.items():
        expected_role = production_roles.get(proof_name, "ordinary")
        if role != expected_role or role not in allowed_roles:
            errors.append(
                "producer mapping drift for "
                f"{proof_name}: expected={expected_role} actual={role}"
            )

    for proof_name, test_paths in ordinary_producers.items():
        if not isinstance(test_paths, Sequence) or isinstance(test_paths, (str, bytes)):
            errors.append(f"producer tests for {proof_name} are not a sequence")
            continue
        if not test_paths:
            errors.append(f"producer tests for {proof_name} are empty")
        for relative in test_paths:
            if not isinstance(relative, str) or not relative:
                errors.append(f"producer test path for {proof_name} is invalid")
                continue
            candidate = (root / relative).resolve()
            if root.resolve() not in candidate.parents:
                errors.append(f"producer test path escapes repository: {relative}")
            elif require_test_files and not candidate.is_file():
                errors.append(f"producer test path is missing: {relative}")
    return errors


def _facts(root: Path) -> dict[str, Any]:
    value = yaml.safe_load(
        (root / "docs" / "security_facts.yaml").read_text(encoding="utf-8")
    )
    if not isinstance(value, dict):
        raise ValueError("security facts are not a mapping")
    return value


def _require_mapping(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{label} is not a mapping")
    return value


def validate_preclosure(root: Path = ROOT) -> list[str]:
    """Return structural contract violations for the current repository."""

    try:
        facts = _facts(root)
        local_facts = _require_mapping(facts.get("local_security_closure"), "local_security_closure")
        preclosure_facts = _require_mapping(
            local_facts.get("pre_closure"), "local_security_closure.pre_closure"
        )
        matrix, collector, fetcher, verifier, local_closure, producer_evidence = (
            _contract_modules(root)
        )
    except (OSError, ValueError, ImportError, RuntimeError, yaml.YAMLError) as exc:
        return [f"pre-closure contract could not be loaded: {exc}"]

    errors: list[str] = []
    required_from_facts = tuple(local_facts.get("mandatory_proofs", ()))
    required_from_code = tuple(local_closure.COMMUNITY_LOCAL_REQUIRED_PROOFS)
    if set(required_from_facts) != set(required_from_code):
        errors.append(
            "mandatory proof facts drift from local closure evaluator: "
            f"facts={sorted(required_from_facts)} code={sorted(required_from_code)}"
        )

    production_roles = {
        producer_evidence.PRODUCTION_COMPOSITION_PROOF: (
            producer_evidence.PRODUCTION_COMPOSITION_PROOF
        ),
        producer_evidence.PROCESS_TREE_PROOF: "lifecycle",
        producer_evidence.RESOURCE_OWNER_PROOF: "lifecycle",
    }
    errors.extend(
        validate_proof_mapping(
            required_from_code,
            matrix.PRODUCER_TESTS,
            verifier.PRODUCER_PROOF_ARTIFACT,
            production_artifact_roles=production_roles,
            root=root,
        )
    )

    expected_artifact_patterns = {
        _normalise_artifact_pattern(pattern)
        for pattern in fetcher.ARTIFACT_PATTERNS
    }
    collector_patterns = {
        _normalise_artifact_pattern(pattern)
        for pattern in collector.EXPECTED_PRODUCER_ARTIFACTS
    }
    verifier_patterns = {
        _normalise_artifact_pattern(pattern)
        for pattern in verifier.PRODUCER_ARTIFACTS.values()
    }
    for label, actual in (
        ("collector", collector_patterns),
        ("release verifier", verifier_patterns),
    ):
        if actual != expected_artifact_patterns:
            errors.append(
                f"{label} producer artifact names drift: "
                f"expected={sorted(expected_artifact_patterns)} actual={sorted(actual)}"
            )

    if preclosure_facts.get("status_vocabulary") != list(PRE_CLOSURE_STATUSES):
        errors.append("pre-closure status vocabulary must be exactly PASS/FAIL")
    if preclosure_facts.get("gate_job") != "community-local-preclosure":
        errors.append("pre-closure facts must name the community-local-preclosure job")
    if preclosure_facts.get("commit_environment") != "GITHUB_SHA":
        errors.append("pre-closure must bind producer commands to GITHUB_SHA")
    if preclosure_facts.get("accepts_saved_release_record_as_live_provenance") is not False:
        errors.append("pre-closure must reject saved release records as live provenance")
    if preclosure_facts.get("local_evidence_schema") != local_closure.LOCAL_EVIDENCE_SCHEMA:
        errors.append("pre-closure local evidence schema is stale")
    if preclosure_facts.get("producer_evidence_schema") != producer_evidence.PRODUCER_EVIDENCE_SCHEMA:
        errors.append("pre-closure producer evidence schema is stale")

    try:
        validator_signature = inspect.signature(producer_evidence.validate_producer_proof)
    except (TypeError, ValueError) as exc:
        errors.append(f"producer schema validator is not inspectable: {exc}")
    else:
        if "expected_commit" not in validator_signature.parameters:
            errors.append("producer schema validator lacks expected_commit binding")
        if not callable(producer_evidence.validate_producer_proof):
            errors.append("producer schema validator is not callable")

    collector_source = (root / "scripts" / "collect_local_security_evidence.py").read_text(
        encoding="utf-8"
    )
    if "load_effective_policy" not in collector_source or "policy_digest" not in collector_source:
        errors.append("local evidence collector does not bind the effective policy digest")
    if "validate_producer_proof" not in collector_source:
        errors.append("local evidence collector does not validate producer proofs")

    gate_source = (root / ".github" / "workflows" / "security-closure-gate.yml").read_text(
        encoding="utf-8"
    )
    producer_block = gate_source.split("  community-local-producers:\n", 1)
    if len(producer_block) != 2:
        errors.append("Security Closure Gate has no community producer job")
    else:
        producer_block_text = producer_block[1].split("  security-closure-gate:\n", 1)[0]
        for required_text in (
            "run_security_producer_matrix.py",
            '--commit "$GITHUB_SHA"',
            "community-local-preclosure:",
            "community-local-preclosure",
        ):
            if required_text not in gate_source:
                errors.append(f"Security Closure Gate is missing pre-closure wiring: {required_text}")
        if '--commit "$GITHUB_SHA"' not in producer_block_text:
            errors.append("ordinary producer job is not bound to GITHUB_SHA")
    if "COMMUNITY_LOCAL_PRE_CLOSURE" not in gate_source:
        errors.append("Security Closure Gate does not expose the pre-closure contract label")

    closure_workflow = (
        root / ".github" / "workflows" / "community-local-closure.yml"
    ).read_text(encoding="utf-8")
    for required_text in (
        "push:",
        "branches: [main]",
        '--commit "$GITHUB_SHA"',
        "fetch_security_producer_artifacts.py",
        "collect_local_security_evidence.py",
    ):
        if required_text not in closure_workflow:
            errors.append(f"main Community Local workflow is missing: {required_text}")

    report_source = (
        root / "scripts" / "build_local_security_closure_report.py"
    ).read_text(encoding="utf-8")
    for required_text in ("VerifiedGitHubProvenance", "verify_release_gates_for_closure"):
        if required_text not in report_source:
            errors.append(f"final closure evaluator is missing live provenance guard: {required_text}")
    if "--release-evidence" in report_source or "--force" in report_source:
        errors.append("final closure evaluator exposes a caller-controlled evidence override")

    return errors


def render_preclosure_result(errors: Sequence[str]) -> str:
    """Render the only two statuses permitted for the PR structural check."""

    status = "FAIL" if errors else "PASS"
    lines = [f"{PRE_CLOSURE_LABEL}: {status}"]
    lines.extend(f"- {error}" for error in errors)
    return "\n".join(lines)


def main() -> int:
    errors = validate_preclosure()
    print(render_preclosure_result(errors))
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
