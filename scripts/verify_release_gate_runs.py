#!/usr/bin/env python3
"""Verify that a release commit has exact, successful required gate runs.

The release workflow is allowed to attest only a commit that was independently
accepted by both required aggregate workflows.  This script intentionally
queries the GitHub Actions API instead of trusting the tag event or a nearby
run, and emits the selected run/artifact metadata for the release manifest.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from khaos.security.evidence_provenance import gh_api_bytes
from khaos.security.security_evidence import (
    MAX_ARTIFACT_BYTES,
    parse_proof_archive,
)

REQUIRED_GATES = {
    "security_closure": "security-closure-gate.yml",
    "product_integrity": "product-integrity-gate.yml",
    "native_authority": "native-authority-production-e2e.yml",
}

_NATIVE_ARTIFACT_CONTRACTS = {
    "native-authority-macos-proof": {
        "proof_type": "macos-native-authority",
        "runner_os": "macOS",
        "platform": "darwin",
        "job_name": "macOS launchd/XPC authority",
    },
    "native-authority-windows-proof": {
        "proof_type": "windows-native-authority",
        "runner_os": "Windows",
        "platform": "win32",
        "job_name": "Windows Service-SID Named Pipe authority",
    },
}


def _canonical_digest(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _run_gh_api(repo: str, endpoint: str) -> dict[str, Any]:
    try:
        raw = gh_api_bytes(repo, endpoint)
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"GitHub API returned malformed JSON for {endpoint}") from exc
    if not isinstance(value, dict):
        raise TypeError(f"GitHub API returned a non-object for {endpoint}")
    return value


def _run_sort_key(run: dict[str, Any]) -> tuple[str, int]:
    started = str(run.get("run_started_at") or run.get("created_at") or "")
    return started, int(run.get("database_id") or run.get("id") or 0)


def _select_successful_run(
    runs: list[dict[str, Any]], *, commit: str, workflow: str
) -> dict[str, Any]:
    candidates = [
        run
        for run in runs
        if run.get("head_sha") == commit
        and run.get("event") == "push"
        and run.get("head_branch") == "main"
        and run.get("status") == "completed"
        and run.get("conclusion") == "success"
        # A rerun can be green after an earlier attempt failed.  Release
        # provenance must bind the original exact-commit gate attempt unless
        # an explicit, separately reviewed exception is added to policy.
        and int(run.get("run_attempt") or 0) == 1
    ]
    if not candidates:
        raise RuntimeError(
            f"no successful completed attempt-1 {workflow} run exists for exact commit {commit}"
        )
    return max(candidates, key=_run_sort_key)


def _artifact_records(repo: str, run_id: int) -> list[dict[str, Any]]:
    payload = _run_gh_api(repo, f"actions/runs/{run_id}/artifacts?per_page=100")
    if int(payload.get("total_count", 0) or 0) > 100:
        raise RuntimeError("workflow run has more artifacts than one page can prove")
    raw_artifacts = payload.get("artifacts")
    if not isinstance(raw_artifacts, list):
        raise TypeError("workflow run artifact payload is malformed")
    records: list[dict[str, Any]] = []
    for artifact in raw_artifacts:
        if not isinstance(artifact, dict):
            continue
        records.append(
            {
                "id": artifact.get("id"),
                "name": artifact.get("name"),
                "size_in_bytes": artifact.get("size_in_bytes"),
                "expired": artifact.get("expired"),
                "digest": artifact.get("digest") or "",
                "workflow_run": artifact.get("workflow_run"),
            }
        )
    return sorted(records, key=lambda item: str(item.get("name") or ""))


def _runner_os_from_labels(labels: object) -> str:
    if not isinstance(labels, list):
        raise TypeError("native producer job has no runner labels")
    normalized = [str(label) for label in labels]
    if any(label.startswith("macos-") for label in normalized):
        return "macOS"
    if any(label.startswith("windows-") for label in normalized):
        return "Windows"
    raise RuntimeError("native producer job runner platform is not macOS or Windows")


def _verify_native_artifacts(
    repo: str,
    *,
    run_id: int,
    commit: str,
    artifacts: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Verify native artifact bytes and producer-owned semantic proof data."""
    selected = [
        artifact
        for artifact in artifacts
        if str(artifact.get("name") or "") in _NATIVE_ARTIFACT_CONTRACTS
    ]
    if len(selected) != len(_NATIVE_ARTIFACT_CONTRACTS):
        raise RuntimeError("native gate did not expose exactly two native artifacts")
    artifact_ids = [str(artifact.get("id") or "") for artifact in selected]
    if not all(artifact_ids) or len(set(artifact_ids)) != len(artifact_ids):
        raise RuntimeError("native gate artifact ids are not unique")

    jobs_payload = _run_gh_api(repo, f"actions/runs/{run_id}/jobs?per_page=100")
    jobs = jobs_payload.get("jobs")
    if (
        not isinstance(jobs, list)
        or len(jobs) > 100
        or int(jobs_payload.get("total_count", len(jobs)) or 0) > 100
    ):
        raise RuntimeError("native gate jobs are missing or exceed the verification page")
    successful_jobs = [
        job
        for job in jobs
        if isinstance(job, dict)
        and job.get("status") == "completed"
        and job.get("conclusion") == "success"
    ]
    proofs: list[dict[str, Any]] = []
    for artifact in selected:
        name = str(artifact["name"])
        contract = _NATIVE_ARTIFACT_CONTRACTS[name]
        workflow_run = artifact.get("workflow_run")
        if not isinstance(workflow_run, dict) or str(workflow_run.get("id")) != str(run_id):
            raise RuntimeError(f"native artifact {name} is not bound to run {run_id}")
        if artifact.get("expired") is not False:
            raise RuntimeError(f"native artifact {name} is expired or unverifiable")
        size = artifact.get("size_in_bytes")
        if size is not None and int(size) > MAX_ARTIFACT_BYTES:
            raise RuntimeError(f"native artifact {name} exceeds the download limit")
        matching_jobs = [
            job
            for job in successful_jobs
            if job.get("name") == contract["job_name"]
            and _runner_os_from_labels(job.get("labels")) == contract["runner_os"]
        ]
        if len(matching_jobs) != 1:
            raise RuntimeError(f"native producer job for {name} is not unique")
        job = matching_jobs[0]
        payload = gh_api_bytes(
            repo,
            f"actions/artifacts/{artifact['id']}/zip",
            timeout_seconds=60.0,
            max_output_bytes=MAX_ARTIFACT_BYTES,
        )
        if len(payload) > MAX_ARTIFACT_BYTES:
            raise RuntimeError(f"native artifact {name} exceeds the download limit")
        digest = hashlib.sha256(payload).hexdigest()
        api_digest = str(artifact.get("digest") or "").removeprefix("sha256:")
        if api_digest and api_digest != digest:
            raise RuntimeError(f"native artifact {name} digest does not match GitHub metadata")
        proof_manifest, proof_digest = parse_proof_archive(
            payload,
            expected_proof_type=contract["proof_type"],
            expected_commit=commit,
            expected_run_id=str(run_id),
            expected_workflow="Native Authority Production E2E",
            expected_runner_os=contract["runner_os"],
            expected_platform=contract["platform"],
            expected_policy_digest=None,
            expected_job_name=contract["job_name"],
        )
        if not proof_manifest.get("policy_digest"):
            raise RuntimeError(f"native artifact {name} has no policy digest")
        proofs.append(
            {
                "artifact_id": artifact["id"],
                "artifact_name": name,
                "artifact_sha256": digest,
                "proof_manifest_sha256": proof_digest,
                "job_id": job.get("id"),
                "runner_os": contract["runner_os"],
                "runner_arch": proof_manifest["runner_arch"],
                "policy_digest": proof_manifest["policy_digest"],
            }
        )
    policy_digests = {str(proof["policy_digest"]) for proof in proofs}
    if len(policy_digests) != 1:
        raise RuntimeError("native artifacts do not share one effective policy digest")
    return proofs


def _gate_record(repo: str, workflow: str, commit: str) -> dict[str, Any]:
    payload = _run_gh_api(
        repo,
        f"actions/workflows/{workflow}/runs?head_sha={commit}&per_page=100",
    )
    run = _select_successful_run(
        [item for item in payload.get("workflow_runs", []) if isinstance(item, dict)],
        commit=commit,
        workflow=workflow,
    )
    run_id = int(run.get("database_id") or run["id"])
    artifacts = _artifact_records(repo, run_id)
    if workflow == REQUIRED_GATES["security_closure"]:
        expected_name = f"security-evidence-{commit}"
        matching = [
            artifact for artifact in artifacts
            if artifact.get("name") == expected_name
        ]
        if len(matching) != 1:
            raise RuntimeError(
                f"security gate run {run_id} is missing exact artifact {expected_name}"
            )
        artifact = matching[0]
        if artifact.get("expired") is not False:
            raise RuntimeError(
                f"security evidence artifact {expected_name} is expired or unverifiable"
            )
        if not isinstance(artifact.get("digest"), str) or not artifact["digest"].strip():
            raise RuntimeError(
                f"security evidence artifact {expected_name} has no digest"
            )
    if workflow == REQUIRED_GATES["native_authority"]:
        expected_names = {
            "native-authority-macos-proof",
            "native-authority-windows-proof",
        }
        for expected_name in sorted(expected_names):
            matching = [
                artifact for artifact in artifacts
                if artifact.get("name") == expected_name
            ]
            if len(matching) != 1:
                raise RuntimeError(
                    f"native authority run {run_id} is missing exact artifact {expected_name}"
                )
            artifact = matching[0]
            if artifact.get("expired") is not False:
                raise RuntimeError(
                    f"native authority artifact {expected_name} is expired or unverifiable"
                )
            if not isinstance(artifact.get("digest"), str) or not artifact["digest"].strip():
                raise RuntimeError(
                    f"native authority artifact {expected_name} has no digest"
                )
        native_proofs = _verify_native_artifacts(
            repo,
            run_id=run_id,
            commit=commit,
            artifacts=artifacts,
        )
    else:
        native_proofs = []
    record = {
        "workflow": workflow,
        "run_id": run_id,
        "run_attempt": int(run["run_attempt"]),
        "head_sha": run.get("head_sha"),
        "event": run.get("event"),
        "head_branch": run.get("head_branch"),
        "status": run.get("status"),
        "conclusion": run.get("conclusion"),
        "url": run.get("html_url"),
        "created_at": run.get("created_at"),
        "updated_at": run.get("updated_at"),
        "artifacts": artifacts,
        "native_proofs": native_proofs,
    }
    record["run_evidence_digest"] = _canonical_digest(record)
    return record


def _verify_main_ancestry(repo: str, commit: str) -> dict[str, Any]:
    """Prove the release commit is an ancestor of protected ``main``."""
    payload = _run_gh_api(repo, f"compare/{commit}...main")
    try:
        behind_by = int(payload.get("behind_by"))
        ahead_by = int(payload.get("ahead_by"))
    except (TypeError, ValueError) as exc:
        raise RuntimeError("GitHub main ancestry comparison is incomplete") from exc
    # The comparison uses the release commit as BASE and main as HEAD.  A
    # valid release commit has no commits that are present only on the base;
    # identical is the zero/zero special case.
    if behind_by != 0 or str(payload.get("status")) not in {"ahead", "identical"}:
        raise RuntimeError(
            f"release commit {commit} is not in protected main ancestry"
        )
    return {
        "base": commit,
        "head": "main",
        "status": payload.get("status"),
        "ahead_by": ahead_by,
        "behind_by": behind_by,
        "url": payload.get("html_url"),
    }


def verify_release_gates(repo: str, commit: str) -> dict[str, Any]:
    """Return commit-bound evidence for every required aggregate gate."""
    main_ancestry = _verify_main_ancestry(repo, commit)
    gates = {
        name: _gate_record(repo, workflow, commit)
        for name, workflow in REQUIRED_GATES.items()
    }
    evidence = {
        "schema": "khaos.release-gate-evidence.v1",
        "commit": commit,
        "verified_at": datetime.now(UTC).isoformat(timespec="seconds").replace(
            "+00:00", "Z"
        ),
        "main_ancestry": main_ancestry,
        "gates": gates,
    }
    evidence["evidence_digest"] = _canonical_digest(evidence)
    return evidence


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    evidence = verify_release_gates(args.repo, args.commit)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
