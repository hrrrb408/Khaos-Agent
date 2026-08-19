#!/usr/bin/env python3
"""Fetch real CI security evidence into a manifest bundle.

Uses the GitHub CLI (``gh``) to read an actual workflow run of
``hrrrb408/Khaos-Agent`` and its artifacts, digests every artifact, parses
its proof JSON, and emits one evidence manifest per artifact.  Every step
fails closed: a failed/cancelled run, a wrong repository, a wrong commit,
a wrong workflow, an artifact without a valid bound proof, or a missing
``gh`` authentication produces no manifest and a non-zero exit.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path

from khaos.security.security_evidence import (
    EXPECTED_REPOSITORY,
    SecurityEvidenceError,
    SecurityEvidenceManifest,
)

# proof_type -> the artifact name prefix carrying that proof.
ARTIFACT_PROOF_TYPES = {
    "native-authority-macos-proof": "macos-native-authority",
    "native-authority-windows-proof": "windows-native-authority",
}


def _gh(args: list[str], *, repo: str) -> object:
    result = subprocess.run(
        ["gh", "api", "--repo", repo, *args],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise SecurityEvidenceError(
            f"gh api failed: {result.stderr.strip()[:400]}"
        )
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise SecurityEvidenceError("gh api returned malformed JSON") from exc


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _runner_os_for(job: dict) -> str:
    labels = job.get("labels") or []
    if any(label.startswith("macos-") for label in labels):
        return "macOS"
    if any(label.startswith("windows-") for label in labels):
        return "Windows"
    if any(label.startswith("ubuntu-") for label in labels):
        return "Linux"
    raise SecurityEvidenceError(f"job {job.get('id')} has unknown runner labels")


def fetch_manifests(
    *,
    repo: str,
    run_id: str,
    expected_commit: str,
    expected_workflow: str | None = None,
) -> list[SecurityEvidenceManifest]:
    run = _gh(["actions/runs", run_id], repo=repo)
    if not isinstance(run, dict):
        raise SecurityEvidenceError("workflow run payload is malformed")
    repository_full = run.get("repository", {}).get("full_name", "")
    if repository_full != repo:
        raise SecurityEvidenceError(
            f"run {run_id} belongs to repository {repository_full!r}, not {repo!r}"
        )
    if run.get("head_sha") != expected_commit:
        raise SecurityEvidenceError(
            f"run {run_id} head SHA {run.get('head_sha')!r} is not the release SHA"
        )
    conclusion = run.get("conclusion")
    if conclusion != "success":
        raise SecurityEvidenceError(
            f"run {run_id} conclusion is {conclusion!r}, not success"
        )
    workflow_name = run.get("name", "")
    jobs_payload = _gh([f"actions/runs/{run_id}/jobs"], repo=repo)
    jobs = {
        str(job["id"]): job
        for job in jobs_payload.get("jobs", [])
        if isinstance(job, dict) and job.get("conclusion") == "success"
    }
    if not jobs:
        raise SecurityEvidenceError(f"run {run_id} has no successful jobs")
    artifacts_payload = _gh([f"actions/runs/{run_id}/artifacts"], repo=repo)
    artifacts = artifacts_payload.get("artifacts", [])
    if not artifacts:
        raise SecurityEvidenceError(f"run {run_id} produced no artifacts")
    manifests: list[SecurityEvidenceManifest] = []
    with tempfile.TemporaryDirectory(prefix="khaos-evidence-") as tmp:
        root = Path(tmp)
        for artifact in artifacts:
            if not isinstance(artifact, dict):
                continue
            artifact_id = str(artifact.get("id", ""))
            artifact_name = str(artifact.get("name", ""))
            if not artifact_id or not artifact_name:
                raise SecurityEvidenceError("artifact identity is malformed")
            proof_type = _artifact_proof_type(artifact_name)
            if proof_type is None:
                continue
            archive = root / f"{artifact_id}.zip"
            _download_artifact(repo, artifact_id, archive)
            digest = _sha256(archive)
            proof = _extract_single_proof(archive)
            _validate_proof_binding(proof, expected_commit, run_id, proof_type)
            job = _job_for_artifact(jobs, proof)
            manifest = SecurityEvidenceManifest(
                schema_version=1,
                repository=repo,
                commit_sha=expected_commit,
                workflow_name=workflow_name,
                workflow_run_id=run_id,
                job_id=str(job["id"]),
                runner_os=_runner_os_for(job),
                runner_arch="x86_64",
                artifact_id=artifact_id,
                artifact_name=artifact_name,
                artifact_sha256=digest,
                proof_type=proof_type,
                proof_schema_version=1,
                policy_digest=str(proof.get("policy_digest", "")),
                generated_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                producer_identity=f"github-actions:{repo}:run:{run_id}",
                run_conclusion="success",
            )
            manifests.append(manifest)
    if not manifests:
        raise SecurityEvidenceError(
            f"run {run_id} produced no recognizable security proof artifacts"
        )
    if expected_workflow is not None and workflow_name != expected_workflow:
        raise SecurityEvidenceError(
            f"run {run_id} is workflow {workflow_name!r}, expected {expected_workflow!r}"
        )
    return manifests


def _artifact_proof_type(artifact_name: str) -> str | None:
    for prefix, proof_type in ARTIFACT_PROOF_TYPES.items():
        if artifact_name.startswith(prefix):
            return proof_type
    return None


def _download_artifact(repo: str, artifact_id: str, destination: Path) -> None:
    result = subprocess.run(
        [
            "gh",
            "api",
            "--repo",
            repo,
            f"actions/artifacts/{artifact_id}/zip",
        ],
        check=False,
        capture_output=True,
    )
    if result.returncode != 0 or not result.stdout:
        raise SecurityEvidenceError(f"artifact {artifact_id} could not be downloaded")
    destination.write_bytes(result.stdout)


def _extract_single_proof(archive: Path) -> dict:
    with zipfile.ZipFile(archive) as bundle:
        entries = [name for name in bundle.namelist() if name.endswith(".json")]
        if len(entries) != 1:
            raise SecurityEvidenceError(
                f"artifact must contain exactly one proof JSON, found {len(entries)}"
            )
        try:
            proof = json.loads(bundle.read(entries[0]).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SecurityEvidenceError("proof JSON is malformed") from exc
    if not isinstance(proof, dict):
        raise SecurityEvidenceError("proof JSON is not an object")
    return proof


def _validate_proof_binding(
    proof: dict, expected_commit: str, run_id: str, proof_type: str
) -> None:
    if proof.get("github_sha") != expected_commit:
        raise SecurityEvidenceError(
            f"{proof_type} proof is not bound to the release SHA"
        )
    if str(proof.get("github_run_id", "")) != str(run_id):
        raise SecurityEvidenceError(
            f"{proof_type} proof is not bound to the evidence run"
        )
    platform = str(proof.get("platform", ""))
    expected_platform = {
        "macos-native-authority": "darwin",
        "windows-native-authority": "win32",
    }.get(proof_type)
    if expected_platform and platform != expected_platform:
        raise SecurityEvidenceError(
            f"{proof_type} proof platform is {platform!r}, expected {expected_platform!r}"
        )
    if not str(proof.get("policy_digest", "")):
        raise SecurityEvidenceError(f"{proof_type} proof has no policy digest")


def _job_for_artifact(jobs: dict[str, dict], proof: dict) -> dict:
    # The proof binds itself to the run; the job is resolved by matching
    # the proof's platform to the successful job's runner OS.
    platform = str(proof.get("platform", ""))
    wanted = {"darwin": "macOS", "win32": "Windows"}.get(platform)
    for job in jobs.values():
        if wanted is None or _runner_os_for(job) == wanted:
            return job
    raise SecurityEvidenceError(f"no successful job produced proof platform {platform!r}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default=EXPECTED_REPOSITORY)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--workflow", default=None)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        manifests = fetch_manifests(
            repo=args.repo,
            run_id=args.run_id,
            expected_commit=args.commit,
            expected_workflow=args.workflow,
        )
    except SecurityEvidenceError as exc:
        print(f"evidence fetch failed: {exc}", file=sys.stderr)
        return 1
    payload = {
        "schema_version": 1,
        "status": "FETCHED",
        "manifests": [manifest.to_payload() for manifest in manifests],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"fetched {len(manifests)} evidence manifests -> {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
