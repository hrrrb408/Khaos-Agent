"""Adversarial regressions for producer-owned Community Local evidence."""

from __future__ import annotations

import importlib.util
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from khaos.security.local_closure import LocalEvidenceError
from khaos.security.producer_evidence import (
    PRODUCTION_COMPOSITION_PROOF,
    build_runtime_producer_proof,
    build_test_producer_proof,
    validate_producer_proof,
)


ROOT = Path(__file__).resolve().parents[3]
COMMIT = "a" * 40
POLICY = "b" * 64


def _write_junit(path: Path, *, skipped: bool = False) -> None:
    suite = ET.Element(
        "testsuite",
        {
            "name": "producer",
            "tests": "1",
            "failures": "0",
            "errors": "0",
            "skipped": "1" if skipped else "0",
        },
    )
    case = ET.SubElement(suite, "testcase", {"name": "boundary"})
    if skipped:
        ET.SubElement(case, "skipped", {"message": "native authority unavailable"})
    ET.ElementTree(suite).write(path, encoding="utf-8", xml_declaration=True)


def _producer_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for key, value in {
        "GITHUB_SHA": COMMIT,
        "GITHUB_REPOSITORY": "hrrrb408/Khaos-Agent",
        "GITHUB_EVENT_NAME": "push",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_RUN_ID": "123",
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_WORKFLOW": "Security Closure Gate",
        "RUNNER_OS": "Linux",
        "GITHUB_JOB": "community-local-producers",
    }.items():
        monkeypatch.setenv(key, value)


def test_test_producer_result_is_derived_from_junit_and_skip_reason(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _producer_env(monkeypatch)
    junit = tmp_path / "results.xml"
    stdout = tmp_path / "stdout.log"
    stderr = tmp_path / "stderr.log"
    stdout.write_text("producer output\n", encoding="utf-8")
    stderr.write_text("", encoding="utf-8")
    _write_junit(junit, skipped=True)

    proof = build_test_producer_proof(
        proof_name="community_authority",
        commit=COMMIT,
        repo_root=ROOT,
        junit=junit,
        returncode=0,
        stdout=stdout,
        stderr=stderr,
    )

    assert proof["result"] == "FAIL"
    diagnostics = proof["diagnostics"]
    assert isinstance(diagnostics, dict)
    assert diagnostics["skipped"] == 1
    assert diagnostics["skipped_reasons"] == ["native authority unavailable"]


def test_production_builder_cannot_forge_mode_outside_real_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("KHAOS_DEV_MODE", "1")
    monkeypatch.setenv("KHAOS_AUTHORITY_PROFILE", "community")
    identity = {
        "runtime_composition_digest": "c" * 64,
        "production_composition_manifest_digest": "d" * 64,
        "launcher_digest": "e" * 64,
        "authority_proof_identity": {
            "socket_path": "/run/khaos-authorityd/authorityd.sock",
            "socket_owner_uid": 10003,
            "public_key_digest": "f" * 64,
            "authority_profile": "native-production",
        },
        "authority_proof_digest": "0" * 64,
        "host_backend_absent": True,
        "dev_fallback_absent": True,
        "production_mode": True,
        "authority_profile": "native-production",
    }
    diagnostics = {
        "schema": "khaos.local-security-producer-diagnostics.v1",
        "proof_name": PRODUCTION_COMPOSITION_PROOF,
        "returncode": 0,
        "test_count": 1,
        "passed": 1,
        "skipped": 0,
        "failed": 0,
        "errors": 0,
        "skipped_reasons": [],
        "failure_details": [],
        "error_details": [],
        "junit_digest": "1" * 64,
        "stdout_digest": "2" * 64,
        "stderr_digest": "3" * 64,
    }
    with pytest.raises(LocalEvidenceError, match="native-production environment"):
        build_runtime_producer_proof(
            proof_type=PRODUCTION_COMPOSITION_PROOF,
            commit=COMMIT,
            policy_digest=POLICY,
            workflow={
                "repository": "hrrrb408/Khaos-Agent",
                "workflow": "Security Closure Gate",
                "run_id": "123",
                "run_attempt": 1,
                "event": "push",
                "ref": "refs/heads/main",
                "head_sha": COMMIT,
                "runner_os": "Linux",
                "job": "compose-deployment",
            },
            diagnostics=diagnostics,
            production_identity=identity,
        )


def test_producer_digest_and_authority_identity_tampering_are_rejected(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _producer_env(monkeypatch)
    junit = tmp_path / "results.xml"
    _write_junit(junit)
    proof = build_test_producer_proof(
        proof_name="network_isolation",
        commit=COMMIT,
        repo_root=ROOT,
        junit=junit,
        returncode=0,
    )
    tampered = dict(proof)
    tampered["evidence_digest"] = "0" * 64
    with pytest.raises(LocalEvidenceError, match="digest mismatch"):
        validate_producer_proof(tampered, expected_commit=COMMIT)


def test_missing_authorityd_does_not_fake_production_pass(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("KHAOS_DEV_MODE", "0")
    monkeypatch.setenv("KHAOS_AUTHORITY_PROFILE", "native-production")
    monkeypatch.setenv("KHAOS_AUTHORITYD_SOCKET", "/does/not/exist.sock")
    monkeypatch.setenv("KHAOS_AUTHORITYD_PUBLIC_KEY_PATH", "/does/not/exist.pub")
    monkeypatch.setenv("KHAOS_AUTHORITYD_UID", "10003")
    monkeypatch.setenv("KHAOS_AGENT_UID", str(__import__("os").getuid()))
    with pytest.raises(LocalEvidenceError, match="endpoint is unavailable"):
        # The identity is intentionally complete-looking; only the live
        # authority endpoint may make this production proof constructible.
        build_runtime_producer_proof(
            proof_type=PRODUCTION_COMPOSITION_PROOF,
            commit=COMMIT,
            policy_digest=POLICY,
            workflow={},
            diagnostics={},
            production_identity={
                "runtime_composition_digest": "c" * 64,
                "production_composition_manifest_digest": "d" * 64,
                "launcher_digest": "e" * 64,
                "authority_proof_identity": {
                    "socket_path": "/does/not/exist.sock",
                    "socket_owner_uid": 10003,
                    "public_key_digest": "f" * 64,
                    "authority_profile": "native-production",
                },
                "authority_proof_digest": "0" * 64,
                "host_backend_absent": True,
                "dev_fallback_absent": True,
                "production_mode": True,
                "authority_profile": "native-production",
            },
        )


def test_closure_builder_cli_no_longer_accepts_production_boolean() -> None:
    spec = importlib.util.spec_from_file_location(
        "build_security_closure_evidence",
        ROOT / "scripts" / "build_security_closure_evidence.py",
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    parser = module._build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(
            [
                "test-fragment",
                "--commit",
                COMMIT,
                "--run-id",
                "123",
                "--job",
                "job",
                "--test",
                "workspace_escape",
                "--runner-os",
                "Linux",
                "--production-mode",
                "true",
                "--output",
                "evidence.json",
            ]
        )
