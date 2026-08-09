"""Unit tests for exact release gate and security artifact selection."""

from __future__ import annotations

import importlib.util
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
        return {"artifacts": [_security_artifact(expired=expired, digest=digest)]}

    monkeypatch.setattr(MODULE, "_run_gh_api", fake_api)
    with pytest.raises(RuntimeError, match=message):
        MODULE._gate_record("owner/repo", "security-closure-gate.yml", COMMIT)


def test_security_gate_records_exact_artifact_and_attempt(monkeypatch: pytest.MonkeyPatch):
    def fake_api(_repo: str, endpoint: str) -> dict[str, object]:
        if endpoint.startswith("actions/workflows/"):
            return {"workflow_runs": [_run(run_id=1, attempt=1)]}
        return {"artifacts": [_security_artifact()]}

    monkeypatch.setattr(MODULE, "_run_gh_api", fake_api)
    record = MODULE._gate_record("owner/repo", "security-closure-gate.yml", COMMIT)
    assert record["run_attempt"] == 1
    assert record["artifacts"][0]["name"] == f"security-evidence-{COMMIT}"
