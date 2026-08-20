"""Unit tests for exact release gate and security artifact selection."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location(
    "verify_release_gate_runs",
    ROOT / "scripts" / "verify_release_gate_runs.py",
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


COMMIT = "a" * 40


def _run(*, run_id: int, attempt: int) -> dict[str, object]:
    return {
        "id": run_id,
        "database_id": run_id,
        "head_sha": COMMIT,
        "status": "completed",
        "conclusion": "success",
        "run_attempt": attempt,
        "event": "push",
        "head_branch": "main",
        "run_started_at": f"2026-08-09T00:00:{run_id:02d}Z",
    }


def _security_artifact(*, expired: bool = False, digest: str = "sha256:ok") -> dict[str, object]:
    return {
        "id": 7,
        "name": f"security-evidence-{COMMIT}",
        "size_in_bytes": 42,
        "expired": expired,
        "digest": digest,
    }


def _native_archive(*, proof_type: str, runner_os: str, platform: str, job_name: str) -> bytes:
    record = {
        "github_sha": COMMIT,
        "github_run_id": "1",
        "proof_type": proof_type,
        "policy_digest": "b" * 64,
        "runner_os": runner_os,
        "platform": platform,
        "peer_verified": True,
        "transport_verified": True,
        "protected_key_verified": True,
    }
    record_bytes = json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
    manifest = {
        "schema_version": 1,
        "proof_type": proof_type,
        "github_sha": COMMIT,
        "github_run_id": "1",
        "workflow_name": "Native Authority Production E2E",
        "job_name": job_name,
        "runner_os": runner_os,
        "runner_arch": "x86_64",
        "platform": platform,
        "policy_digest": "b" * 64,
        "files": {"native-proof.json": hashlib.sha256(record_bytes).hexdigest()},
    }
    manifest_bytes = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, value in (
            ("native-proof.json", record_bytes),
            ("proof-manifest.json", manifest_bytes),
        ):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, value)
    return output.getvalue()


def _native_artifacts() -> list[dict[str, object]]:
    macos = _native_archive(
        proof_type="macos-native-authority",
        runner_os="macOS",
        platform="darwin",
        job_name="macOS launchd/XPC authority",
    )
    windows = _native_archive(
        proof_type="windows-native-authority",
        runner_os="Windows",
        platform="win32",
        job_name="Windows Service-SID Named Pipe authority",
    )
    return [
        {
            "id": 8,
            "name": "native-authority-macos-proof",
            "size_in_bytes": len(macos),
            "expired": False,
            "digest": f"sha256:{hashlib.sha256(macos).hexdigest()}",
            "workflow_run": {"id": 1},
        },
        {
            "id": 9,
            "name": "native-authority-windows-proof",
            "size_in_bytes": len(windows),
            "expired": False,
            "digest": f"sha256:{hashlib.sha256(windows).hexdigest()}",
            "workflow_run": {"id": 1},
        },
    ]


def _native_payloads() -> dict[str, bytes]:
    return {
        "8": _native_archive(
            proof_type="macos-native-authority",
            runner_os="macOS",
            platform="darwin",
            job_name="macOS launchd/XPC authority",
        ),
        "9": _native_archive(
            proof_type="windows-native-authority",
            runner_os="Windows",
            platform="win32",
            job_name="Windows Service-SID Named Pipe authority",
        ),
    }


def test_release_selector_never_replaces_attempt_one_with_rerun():
    selected = MODULE._select_successful_run(
        [_run(run_id=1, attempt=1), _run(run_id=2, attempt=2)],
        commit=COMMIT,
        workflow="security-closure-gate.yml",
    )
    assert selected["run_attempt"] == 1
    assert selected["id"] == 1

    with pytest.raises(RuntimeError, match="attempt-1"):
        MODULE._select_successful_run(
            [_run(run_id=2, attempt=2)],
            commit=COMMIT,
            workflow="security-closure-gate.yml",
        )


def test_release_selector_rejects_non_main_or_non_push_runs():
    branch_run = _run(run_id=3, attempt=1) | {"event": "pull_request"}
    with pytest.raises(RuntimeError, match="attempt-1"):
        MODULE._select_successful_run(
            [branch_run],
            commit=COMMIT,
            workflow="security-closure-gate.yml",
        )

    non_main_run = _run(run_id=4, attempt=1) | {"head_branch": "feature"}
    with pytest.raises(RuntimeError, match="attempt-1"):
        MODULE._select_successful_run(
            [non_main_run],
            commit=COMMIT,
            workflow="security-closure-gate.yml",
        )


@pytest.mark.parametrize(
    ("expired", "digest", "message"),
    [
        (True, "sha256:ok", "expired"),
        (False, "", "no digest"),
    ],
)
def test_security_gate_requires_live_digest_bound_artifact(
    monkeypatch: pytest.MonkeyPatch,
    expired: bool,
    digest: str,
    message: str,
):
    def fake_api(_repo: str, endpoint: str) -> dict[str, object]:
        if endpoint.startswith("actions/workflows/"):
            return {"workflow_runs": [_run(run_id=1, attempt=1)]}
        return {
            "artifacts": [
                _security_artifact(expired=expired, digest=digest),
                *_native_artifacts(),
            ]
        }

    monkeypatch.setattr(MODULE, "_run_gh_api", fake_api)
    with pytest.raises(RuntimeError, match=message):
        MODULE._gate_record("owner/repo", "security-closure-gate.yml", COMMIT)


def test_security_gate_records_exact_artifact_and_attempt(monkeypatch: pytest.MonkeyPatch):
    def fake_api(_repo: str, endpoint: str) -> dict[str, object]:
        if endpoint.startswith("actions/workflows/"):
            return {"workflow_runs": [_run(run_id=1, attempt=1)]}
        return {"artifacts": [_security_artifact(), *_native_artifacts()]}

    monkeypatch.setattr(MODULE, "_run_gh_api", fake_api)
    record = MODULE._gate_record("owner/repo", "security-closure-gate.yml", COMMIT)
    assert record["run_attempt"] == 1
    assert any(
        artifact["name"] == f"security-evidence-{COMMIT}"
        for artifact in record["artifacts"]
    )


def test_release_evidence_requires_main_ancestry(monkeypatch: pytest.MonkeyPatch):
    def fake_api(_repo: str, endpoint: str) -> dict[str, object]:
        if endpoint.startswith("compare/"):
            return {
                "status": "ahead",
                "ahead_by": 3,
                "behind_by": 0,
                "html_url": "https://github.com/compare",
            }
        if endpoint.startswith("actions/workflows/"):
            return {"workflow_runs": [_run(run_id=1, attempt=1)]}
        return {"artifacts": [_security_artifact(), *_native_artifacts()]}

    monkeypatch.setattr(MODULE, "_run_gh_api", fake_api)
    monkeypatch.setattr(MODULE, "_verify_native_artifacts", lambda *args, **kwargs: [])
    monkeypatch.setattr(
        MODULE,
        "gh_api_bytes",
        lambda *args, **kwargs: b"native-artifact",
    )
    evidence = MODULE.verify_release_gates("owner/repo", COMMIT)
    assert evidence["main_ancestry"]["behind_by"] == 0

    def diverged_api(_repo: str, endpoint: str) -> dict[str, object]:
        if endpoint.startswith("compare/"):
            return {"status": "diverged", "ahead_by": 1, "behind_by": 1}
        return fake_api(_repo, endpoint)

    monkeypatch.setattr(MODULE, "_run_gh_api", diverged_api)
    with pytest.raises(RuntimeError, match="main ancestry"):
        MODULE.verify_release_gates("owner/repo", COMMIT)


def test_native_release_gate_verifies_job_platform_and_proof_semantics(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    native_artifacts = _native_artifacts()
    payloads = _native_payloads()

    def fake_api(_repo: str, endpoint: str) -> dict[str, object]:
        if endpoint.endswith("/jobs?per_page=100"):
            return {
                "total_count": 2,
                "jobs": [
                    {
                        "id": 101,
                        "status": "completed",
                        "conclusion": "success",
                        "name": "macOS launchd/XPC authority",
                        "labels": ["macos-14"],
                    },
                    {
                        "id": 102,
                        "status": "completed",
                        "conclusion": "success",
                        "name": "Windows Service-SID Named Pipe authority",
                        "labels": ["windows-2025"],
                    },
                ],
            }
        raise AssertionError(f"unexpected API endpoint: {endpoint}")

    monkeypatch.setattr(MODULE, "_run_gh_api", fake_api)
    monkeypatch.setattr(
        MODULE,
        "gh_api_bytes",
        lambda _repo, endpoint, **kwargs: payloads[endpoint.split("/")[2]],
    )
    proofs = MODULE._verify_native_artifacts(
        "owner/repo",
        run_id=1,
        commit=COMMIT,
        artifacts=native_artifacts,
    )
    assert {proof["runner_os"] for proof in proofs} == {"macOS", "Windows"}

    tampered = dict(native_artifacts[0])
    tampered["workflow_run"] = {"id": 99}
    with pytest.raises(RuntimeError, match="not bound to run"):
        MODULE._verify_native_artifacts(
            "owner/repo",
            run_id=1,
            commit=COMMIT,
            artifacts=[tampered, native_artifacts[1]],
        )
