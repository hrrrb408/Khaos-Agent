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
    import hashlib

    from khaos.security.security_evidence import SecurityEvidenceManifest

    workflows = {
        "linux-real-kernel": ("Platform Sandbox Security", "Linux"),
        "macos-native-authority": ("Native Authority Production E2E", "macOS"),
        "windows-native-authority": ("Native Authority Production E2E", "Windows"),
        "security-closure-gate": ("Security Closure Gate", "Linux"),
        "product-integrity-gate": ("Product Integrity Gate", "Linux"),
        "resource-owner-proof": ("Security Closure Gate", "Linux"),
        "exact-effect-proof": ("Security Closure Gate", "Linux"),
    }
    manifests = []
    for index, (proof_type, (workflow, os_name)) in enumerate(workflows.items()):
        artifact_id = str(index)
        # The digest must be recomputable by the fake GitHub API: the
        # recheck hashes the downloaded artifact bytes.
        artifact_sha256 = hashlib.sha256(f"artifact-{artifact_id}".encode()).hexdigest()
        manifests.append(
            SecurityEvidenceManifest(
                schema_version=1,
                repository="hrrrb408/Khaos-Agent",
                commit_sha=commit,
                workflow_name=workflow,
                workflow_run_id=str(9001 + index),
                job_id=str(10001 + index),
                runner_os=os_name,
                runner_arch="x86_64",
                artifact_id=artifact_id,
                artifact_name="proof",
                artifact_sha256=artifact_sha256,
                proof_type=proof_type,
                proof_schema_version=1,
                policy_digest=policy,
                generated_at="2026-08-19T00:00:00Z",
                producer_identity="github-actions",
                run_conclusion="success",
            )
        )
    return manifests


def _faithful_fetchers(manifests):
    """Fake GitHub API that faithfully mirrors the synthetic manifests."""

    def fetch_json(path: str):
        rest = path.split("/actions/runs/", 1)[1]
        parts = [segment.split("?")[0] for segment in rest.split("/")]
        run_id, tail = parts[0], (parts[1] if len(parts) > 1 else "")
        matching = [m for m in manifests if m.workflow_run_id == run_id]
        if not matching:
            raise LookupError(f"HTTP 404: run {run_id} does not exist")
        manifest = matching[0]
        if tail == "":
            return {
                "head_sha": manifest.commit_sha,
                "name": manifest.workflow_name,
                "conclusion": "success",
            }
        if tail == "jobs":
            return {
                "total_count": 1,
                "jobs": [{"id": int(manifest.job_id), "conclusion": "success"}],
            }
        if tail == "artifacts":
            return {
                "artifacts": [
                    {
                        "id": int(manifest.artifact_id),
                        "name": manifest.artifact_name,
                        "expired": False,
                    }
                ]
            }
        raise LookupError(f"HTTP 404: unknown API path {path}")

    def fetch_artifact(artifact_id: str) -> bytes:
        if not any(m.artifact_id == artifact_id for m in manifests):
            raise LookupError(f"HTTP 404: artifact {artifact_id} does not exist")
        return f"artifact-{artifact_id}".encode()

    return fetch_json, fetch_artifact


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


def test_verified_evidence_bundle_can_close_with_live_recheck():
    """CLOSED requires local consistency AND a faithful live-API recheck."""
    manifests = _full_manifest_set()
    fetch_json, fetch_artifact = _faithful_fetchers(manifests)
    report = _module().render(
        commit=COMMIT,
        policy_digest=POLICY,
        evidence_bundle=_bundle(manifests),
        github_fetch_json=fetch_json,
        github_fetch_artifact=fetch_artifact,
    )
    assert "Status: **CLOSED**" in report
    assert "GitHub-provenance rechecked" in report


def test_self_consistent_forged_bundle_cannot_close_without_recheck():
    """The exact forgery from the review: every string locally plausible.

    Without a live GitHub recheck this bundle closed; with the recheck
    unavailable the report must stay NOT CLOSED instead of trusting local
    self-consistency.
    """
    report = _module().render(
        commit=COMMIT,
        policy_digest=POLICY,
        evidence_bundle=_bundle(_full_manifest_set()),
    )
    assert "Status: **NOT CLOSED" in report
    assert "provenance recheck unavailable" in report


def test_forged_bundle_with_nonexistent_run_cannot_close():
    """A well-formed bundle whose runs do not exist on GitHub fails closed."""
    manifests = _full_manifest_set()
    fetch_json, fetch_artifact = _faithful_fetchers(manifests)

    def rejecting_fetch_json(path: str):
        raise LookupError("HTTP 404: not found")

    report = _module().render(
        commit=COMMIT,
        policy_digest=POLICY,
        evidence_bundle=_bundle(manifests),
        github_fetch_json=rejecting_fetch_json,
        github_fetch_artifact=fetch_artifact,
    )
    assert "Status: **NOT CLOSED" in report
    assert "run lookup failed" in report


def test_forged_bundle_with_digest_mismatch_cannot_close():
    """The API exists but the artifact bytes hash differently: rejected."""
    manifests = _full_manifest_set()
    fetch_json, fetch_artifact = _faithful_fetchers(manifests)

    def wrong_bytes_fetch_artifact(artifact_id: str) -> bytes:
        return b"tampered-bytes"

    report = _module().render(
        commit=COMMIT,
        policy_digest=POLICY,
        evidence_bundle=_bundle(manifests),
        github_fetch_json=fetch_json,
        github_fetch_artifact=wrong_bytes_fetch_artifact,
    )
    assert "Status: **NOT CLOSED" in report
    assert "digest does not match" in report


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
