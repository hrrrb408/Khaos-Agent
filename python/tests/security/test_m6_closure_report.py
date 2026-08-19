"""M6 closure reports refuse to turn missing evidence into CLOSED."""

from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "scripts" / "build_m6_closure_report.py"

COMMIT = "a" * 40
POLICY = "b" * 64


def _module():
    spec = importlib.util.spec_from_file_location("m6_report", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_missing_native_and_ci_evidence_cannot_be_closed():
    report = _module().render(commit=COMMIT)
    assert "Status: **NOT CLOSED" in report
    assert "UNKNOWN" in report


def test_local_files_and_booleans_cannot_close():
    """Two arbitrary local files + a CI run string + a green boolean are
    exactly the forged-closure input M6.9 BATCH 5 removes."""
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        mac = Path(tmp) / "mac.json"
        windows = Path(tmp) / "windows.json"
        mac.write_text("{}", encoding="utf-8")
        windows.write_text("{}", encoding="utf-8")
        report = _module().render(
            commit=COMMIT,
            ci_run="12345",
            test_counts="1000 passed",
            native_evidence=(str(mac), str(windows)),
            all_gates_success=True,
        )
        assert "Status: **NOT CLOSED" in report


def _full_manifest_set(commit: str = COMMIT, policy: str = POLICY):
    from khaos.security.security_evidence import SecurityEvidenceManifest

    base = {
        "schema_version": 1,
        "repository": "hrrrb408/Khaos-Agent",
        "commit_sha": commit,
        "workflow_run_id": "9001",
        "job_id": "10001",
        "runner_arch": "x86_64",
        "artifact_name": "proof",
        "artifact_sha256": "c" * 64,
        "proof_schema_version": 1,
        "policy_digest": policy,
        "generated_at": "2026-08-19T00:00:00Z",
        "producer_identity": "github-actions",
        "run_conclusion": "success",
    }
    workflows = {
        "linux-real-kernel": ("Platform Sandbox Security", "Linux"),
        "macos-native-authority": ("Native Authority Production E2E", "macOS"),
        "windows-native-authority": ("Native Authority Production E2E", "Windows"),
        "security-closure-gate": ("Security Closure Gate", "Linux"),
        "product-integrity-gate": ("Product Integrity Gate", "Linux"),
        "resource-owner-proof": ("Security Closure Gate", "Linux"),
        "exact-effect-proof": ("Security Closure Gate", "Linux"),
    }
    return [
        SecurityEvidenceManifest(
            workflow_name=workflow,
            runner_os=os_name,
            artifact_id=str(index),
            proof_type=proof_type,
            **base,
        )
        for index, (proof_type, (workflow, os_name)) in enumerate(workflows.items())
    ]


def _bundle(manifests):
    from khaos.security.security_evidence import (
        build_verified_manifest,
        verify_evidence_manifests,
    )

    verification = verify_evidence_manifests(
        manifests, expected_commit=COMMIT, expected_policy_digest=POLICY
    )
    assert verification.ok, verification.errors
    return build_verified_manifest(manifests, verification=verification)


def test_verified_evidence_bundle_can_close():
    report = _module().render(
        commit=COMMIT,
        policy_digest=POLICY,
        evidence_bundle=_bundle(_full_manifest_set()),
    )
    assert "Status: **CLOSED**" in report


def test_bundle_with_wrong_commit_cannot_close():
    report = _module().render(
        commit="f" * 40,
        policy_digest=POLICY,
        evidence_bundle=_bundle(_full_manifest_set()),
    )
    assert "Status: **NOT CLOSED" in report


def test_tampered_bundle_cannot_close():
    bundle = _bundle(_full_manifest_set())
    bundle["manifests"][0]["commit_sha"] = "f" * 40
    report = _module().render(
        commit=COMMIT,
        policy_digest=POLICY,
        evidence_bundle=bundle,
    )
    assert "Status: **NOT CLOSED" in report


def test_incomplete_bundle_cannot_close():
    manifests = _full_manifest_set()
    # Drop the Windows native proof: the set must not close.
    manifests = [m for m in manifests if m.proof_type != "windows-native-authority"]
    from khaos.security.security_evidence import verify_evidence_manifests

    verification = verify_evidence_manifests(
        manifests, expected_commit=COMMIT, expected_policy_digest=POLICY
    )
    assert not verification.ok
    report = _module().render(
        commit=COMMIT,
        policy_digest=POLICY,
        evidence_bundle={
            "schema_version": 1,
            "status": "VERIFIED",
            "manifests": [m.to_payload() for m in manifests],
            "errors": [],
            "bundle_digest": "0" * 64,
        },
    )
    assert "Status: **NOT CLOSED" in report
