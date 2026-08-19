"""Security evidence provenance adversarial tests (M6.9 BATCH 5).

The old closure rule was ``ci_run != "not-provided"`` + two existing
files + ``--all-gates-success`` = CLOSED, so arbitrary local files could
masquerade as native security proof.  Every manifest now carries full
provenance and verification fails closed on every mismatch.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from khaos.security.security_evidence import (
    REQUIRED_PROOF_TYPES,
    SecurityEvidenceError,
    SecurityEvidenceManifest,
    build_verified_manifest,
    load_verified_bundle,
    verify_artifact_digest,
    verify_evidence_manifests,
)

COMMIT = "a" * 40
POLICY = "b" * 64

WORKFLOWS = {
    "linux-real-kernel": ("Platform Sandbox Security", "Linux"),
    "macos-native-authority": ("Native Authority Production E2E", "macOS"),
    "windows-native-authority": ("Native Authority Production E2E", "Windows"),
    "security-closure-gate": ("Security Closure Gate", "Linux"),
    "product-integrity-gate": ("Product Integrity Gate", "Linux"),
    "resource-owner-proof": ("Security Closure Gate", "Linux"),
    "exact-effect-proof": ("Security Closure Gate", "Linux"),
}


def _manifest(
    proof_type: str,
    *,
    commit: str = COMMIT,
    policy: str = POLICY,
    repository: str = "hrrrb408/Khaos-Agent",
    conclusion: str = "success",
    workflow: str | None = None,
    runner_os: str | None = None,
    artifact_id: str = "1",
    artifact_sha256: str = "c" * 64,
) -> SecurityEvidenceManifest:
    default_workflow, default_os = WORKFLOWS[proof_type]
    return SecurityEvidenceManifest(
        schema_version=1,
        repository=repository,
        commit_sha=commit,
        workflow_name=workflow if workflow is not None else default_workflow,
        workflow_run_id="9001",
        job_id="10001",
        runner_os=runner_os if runner_os is not None else default_os,
        runner_arch="x86_64",
        artifact_id=artifact_id,
        artifact_name=f"proof-{proof_type}",
        artifact_sha256=artifact_sha256,
        proof_type=proof_type,
        proof_schema_version=1,
        policy_digest=policy,
        generated_at="2026-08-19T00:00:00Z",
        producer_identity="github-actions:hrrrb408/Khaos-Agent:run:9001",
        run_conclusion=conclusion,
    )


def _full_set() -> list[SecurityEvidenceManifest]:
    return [
        _manifest(proof_type, artifact_id=str(index))
        for index, proof_type in enumerate(sorted(REQUIRED_PROOF_TYPES))
    ]


def test_full_valid_set_verifies() -> None:
    verification = verify_evidence_manifests(
        _full_set(), expected_commit=COMMIT, expected_policy_digest=POLICY
    )
    assert verification.ok, verification.errors
    assert verification.proof_types == REQUIRED_PROOF_TYPES


def test_fake_run_id_conclusion_fails_closed() -> None:
    """A run that did not conclude success is not evidence."""
    manifests = _full_set()
    manifests[0] = _manifest(manifests[0].proof_type, conclusion="failure")
    verification = verify_evidence_manifests(
        manifests, expected_commit=COMMIT, expected_policy_digest=POLICY
    )
    assert not verification.ok
    assert any("conclusion" in error for error in verification.errors)


def test_two_macos_proofs_cannot_impostor_windows() -> None:
    manifests = _full_set()
    windows_index = next(
        index
        for index, manifest in enumerate(manifests)
        if manifest.proof_type == "windows-native-authority"
    )
    # Replace the Windows proof with a second macOS-shaped proof.
    manifests[windows_index] = _manifest(
        "windows-native-authority",
        runner_os="macOS",
        workflow="Native Authority Production E2E",
    )
    verification = verify_evidence_manifests(
        manifests, expected_commit=COMMIT, expected_policy_digest=POLICY
    )
    assert not verification.ok
    assert any("runner OS" in error for error in verification.errors)


def test_wrong_sha_fails_closed() -> None:
    manifests = _full_set()
    manifests[0] = _manifest(manifests[0].proof_type, commit="f" * 40)
    verification = verify_evidence_manifests(
        manifests, expected_commit=COMMIT, expected_policy_digest=POLICY
    )
    assert not verification.ok
    assert any("release SHA" in error for error in verification.errors)


def test_wrong_repository_fails_closed() -> None:
    manifests = _full_set()
    manifests[0] = _manifest(
        manifests[0].proof_type, repository="attacker/evil-fork"
    )
    verification = verify_evidence_manifests(
        manifests, expected_commit=COMMIT, expected_policy_digest=POLICY
    )
    assert not verification.ok
    assert any("repository" in error for error in verification.errors)


def test_wrong_workflow_fails_closed() -> None:
    manifests = _full_set()
    manifests[0] = _manifest(
        manifests[0].proof_type, workflow="Unrelated Green Workflow"
    )
    verification = verify_evidence_manifests(
        manifests, expected_commit=COMMIT, expected_policy_digest=POLICY
    )
    assert not verification.ok
    assert any("workflow" in error for error in verification.errors)


def test_unknown_proof_type_fails_closed() -> None:
    manifests = _full_set()
    manifests[0] = _manifest(manifests[0].proof_type, artifact_id="0")
    verification = verify_evidence_manifests(
        manifests, expected_commit=COMMIT, expected_policy_digest=POLICY
    )
    # sanity: base set is fine; now inject an unknown type
    assert verification.ok
    from khaos.security.security_evidence import SecurityEvidenceManifest as M

    unknown = M(
        schema_version=1,
        repository="hrrrb408/Khaos-Agent",
        commit_sha=COMMIT,
        workflow_name="Security Closure Gate",
        workflow_run_id="9001",
        job_id="10001",
        runner_os="Linux",
        runner_arch="x86_64",
        artifact_id="999",
        artifact_name="fake",
        artifact_sha256="c" * 64,
        proof_type="totally-fake-proof",
        proof_schema_version=1,
        policy_digest=POLICY,
        generated_at="2026-08-19T00:00:00Z",
        producer_identity="github-actions",
        run_conclusion="success",
    )
    verification = verify_evidence_manifests(
        [*manifests, unknown], expected_commit=COMMIT, expected_policy_digest=POLICY
    )
    assert not verification.ok
    assert any("unknown proof type" in error for error in verification.errors)


def test_wrong_policy_digest_fails_closed() -> None:
    manifests = _full_set()
    manifests[0] = _manifest(manifests[0].proof_type, policy="d" * 64)
    verification = verify_evidence_manifests(
        manifests, expected_commit=COMMIT, expected_policy_digest=POLICY
    )
    assert not verification.ok
    assert any("policy digest" in error for error in verification.errors)


def test_duplicate_evidence_fails_closed() -> None:
    manifests = _full_set()
    duplicates = [*manifests, manifests[0]]
    verification = verify_evidence_manifests(
        duplicates, expected_commit=COMMIT, expected_policy_digest=POLICY
    )
    assert not verification.ok
    assert any("duplicate proof type" in error for error in verification.errors)


def test_missing_required_type_fails_closed() -> None:
    manifests = [
        m for m in _full_set() if m.proof_type != "macos-native-authority"
    ]
    verification = verify_evidence_manifests(
        manifests, expected_commit=COMMIT, expected_policy_digest=POLICY
    )
    assert not verification.ok
    assert any("missing required evidence" in error for error in verification.errors)


def test_malformed_manifest_payloads_fail_closed() -> None:
    base = _manifest("macos-native-authority").to_payload()
    with pytest.raises(SecurityEvidenceError, match="fields mismatch"):
        SecurityEvidenceManifest.from_payload({**base, "extra": "field"})
    with pytest.raises(SecurityEvidenceError, match="fields mismatch"):
        SecurityEvidenceManifest.from_payload(
            {k: v for k, v in base.items() if k != "commit_sha"}
        )
    with pytest.raises(SecurityEvidenceError, match="commit SHA is malformed"):
        SecurityEvidenceManifest.from_payload({**base, "commit_sha": "nothex"})
    with pytest.raises(SecurityEvidenceError, match="schema version"):
        SecurityEvidenceManifest.from_payload({**base, "schema_version": 99})
    with pytest.raises(SecurityEvidenceError, match="is empty"):
        SecurityEvidenceManifest.from_payload({**base, "artifact_name": ""})


def test_tampered_artifact_digest_fails_closed(tmp_path: Path) -> None:
    manifest = _manifest("macos-native-authority")
    artifact = tmp_path / "1.zip"
    artifact.write_bytes(b"original content")
    original_digest = manifest.artifact_sha256
    # Rebind the manifest to the real file content.
    import hashlib

    real = hashlib.sha256(b"original content").hexdigest()
    manifest = _manifest("macos-native-authority", artifact_sha256=real)
    verify_artifact_digest(manifest, artifact)
    artifact.write_bytes(b"tampered content")
    with pytest.raises(SecurityEvidenceError, match="does not match"):
        verify_artifact_digest(manifest, artifact)
    missing = _manifest(
        "macos-native-authority", artifact_sha256=original_digest
    )
    with pytest.raises(SecurityEvidenceError, match="missing on disk"):
        verify_artifact_digest(missing, tmp_path / "absent.zip")


def test_verified_bundle_roundtrip_and_tamper_detection(tmp_path: Path) -> None:
    verification = verify_evidence_manifests(
        _full_set(), expected_commit=COMMIT, expected_policy_digest=POLICY
    )
    bundle = build_verified_manifest(_full_set(), verification=verification)
    path = tmp_path / "verified.json"
    path.write_text(json.dumps(bundle, indent=2, sort_keys=True), encoding="utf-8")
    loaded = load_verified_bundle(path)
    assert loaded["status"] == "VERIFIED"
    # Any post-verification edit is caught by the bundle digest.
    tampered = json.loads(path.read_text(encoding="utf-8"))
    tampered["manifests"][0]["commit_sha"] = "f" * 40
    tampered_path = tmp_path / "tampered.json"
    tampered_path.write_text(
        json.dumps(tampered, indent=2, sort_keys=True), encoding="utf-8"
    )
    with pytest.raises(SecurityEvidenceError, match="digest mismatch"):
        load_verified_bundle(tampered_path)
    # Even an attacker who recomputes the bundle digest cannot smuggle a
    # wrong commit past the closure builder's re-verification.
    recomputed = json.loads(path.read_text(encoding="utf-8"))
    recomputed["manifests"][0]["commit_sha"] = "f" * 40
    recomputed["bundle_digest"] = hashlib.sha256(
        json.dumps(
            recomputed["manifests"], sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    ).hexdigest()
    recomputed_path = tmp_path / "recomputed.json"
    recomputed_path.write_text(
        json.dumps(recomputed, indent=2, sort_keys=True), encoding="utf-8"
    )
    loaded_recomputed = load_verified_bundle(recomputed_path)
    recheck = verify_evidence_manifests(
        [
            SecurityEvidenceManifest.from_payload(payload)
            for payload in loaded_recomputed["manifests"]
        ],
        expected_commit=COMMIT,
        expected_policy_digest=POLICY,
    )
    assert not recheck.ok
    assert any("release SHA" in error for error in recheck.errors)


def test_unverified_set_cannot_be_bundled() -> None:
    verification = verify_evidence_manifests(
        [], expected_commit=COMMIT, expected_policy_digest=POLICY
    )
    assert not verification.ok
    with pytest.raises(SecurityEvidenceError, match="unverified"):
        build_verified_manifest([], verification=verification)


def test_local_file_injection_cannot_become_a_manifest(tmp_path: Path) -> None:
    """An arbitrary local JSON file is not a valid manifest."""
    fake = tmp_path / "fake-proof.json"
    fake.write_text('{"platform":"darwin","ok":true}', encoding="utf-8")
    with pytest.raises(SecurityEvidenceError):
        SecurityEvidenceManifest.from_payload(
            json.loads(fake.read_text(encoding="utf-8"))
        )
