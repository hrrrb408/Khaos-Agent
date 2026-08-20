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
import sys
import tempfile
import time
from pathlib import Path

from khaos.security.evidence_provenance import gh_api_bytes
from khaos.security.security_evidence import (
    EXPECTED_REPOSITORY,
    EXPECTED_RUNNER_OS,
    MAX_ARTIFACT_BYTES,
    SecurityEvidenceError,
    SecurityEvidenceManifest,
    parse_proof_archive,
)

# Exact producer artifact name -> proof type.  Prefix matching would allow an
# unrelated artifact to masquerade as native evidence.
ARTIFACT_PROOF_TYPES = {
    "native-authority-macos-proof": "macos-native-authority",
    "native-authority-windows-proof": "windows-native-authority",
}


def _gh(args: list[str], *, repo: str) -> object:
    try:
        return json.loads(gh_api_bytes(repo, *args).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
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
    if run.get("status") != "completed":
        raise SecurityEvidenceError(
            f"run {run_id} status is {run.get('status')!r}, not completed"
        )
    if run.get("event") != "push" or run.get("head_branch") != "main":
        raise SecurityEvidenceError(
            f"run {run_id} is not the protected main push event"
        )
    try:
        run_attempt = int(run.get("run_attempt") or 0)
    except (TypeError, ValueError) as exc:
        raise SecurityEvidenceError("workflow run attempt is malformed") from exc
    if run_attempt != 1:
        raise SecurityEvidenceError(
            f"run {run_id} is rerun attempt {run_attempt}, not the original attempt"
        )
    conclusion = run.get("conclusion")
    if conclusion != "success":
        raise SecurityEvidenceError(
            f"run {run_id} conclusion is {conclusion!r}, not success"
        )
    workflow_name = run.get("name", "")
    if workflow_name != "Native Authority Production E2E":
        raise SecurityEvidenceError(
            f"run {run_id} is workflow {workflow_name!r}, not the native authority workflow"
        )
    if expected_workflow is not None and workflow_name != expected_workflow:
        raise SecurityEvidenceError(
            f"run {run_id} is workflow {workflow_name!r}, expected {expected_workflow!r}"
        )
    jobs_payload = _gh([f"actions/runs/{run_id}/jobs"], repo=repo)
    raw_jobs = jobs_payload.get("jobs")
    if not isinstance(raw_jobs, list) or int(jobs_payload.get("total_count", len(raw_jobs)) or 0) > 100:
        raise SecurityEvidenceError("workflow jobs exceed the bounded verification page")
    jobs = {
        str(job["id"]): job
        for job in raw_jobs
        if isinstance(job, dict) and job.get("conclusion") == "success"
    }
    if not jobs:
        raise SecurityEvidenceError(f"run {run_id} has no successful jobs")
    artifacts_payload = _gh([f"actions/runs/{run_id}/artifacts"], repo=repo)
    artifacts = artifacts_payload.get("artifacts", [])
    if (
        not isinstance(artifacts, list)
        or not artifacts
        or int(artifacts_payload.get("total_count", len(artifacts)) or 0) > 100
    ):
        raise SecurityEvidenceError(f"run {run_id} produced no artifacts")
    artifact_ids = [str(item.get("id", "")) for item in artifacts if isinstance(item, dict)]
    if len(artifact_ids) != len(set(artifact_ids)):
        raise SecurityEvidenceError("workflow artifact ids are not unique")
    manifests: list[SecurityEvidenceManifest] = []
    seen_proof_types: set[str] = set()
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
            if proof_type in seen_proof_types:
                raise SecurityEvidenceError(
                    f"run {run_id} contains duplicate {proof_type} artifacts"
                )
            seen_proof_types.add(proof_type)
            if artifact.get("expired") is not False:
                raise SecurityEvidenceError(
                    f"artifact {artifact_name} is expired or unverifiable"
                )
            workflow_run = artifact.get("workflow_run")
            if not isinstance(workflow_run, dict) or str(workflow_run.get("id")) != str(run_id):
                raise SecurityEvidenceError(
                    f"artifact {artifact_name} is not bound to run {run_id}"
                )
            advertised_size = artifact.get("size_in_bytes")
            if advertised_size is not None and int(advertised_size) > MAX_ARTIFACT_BYTES:
                raise SecurityEvidenceError(
                    f"artifact {artifact_name} exceeds the download limit"
                )
            archive = root / f"{artifact_id}.zip"
            _download_artifact(repo, artifact_id, archive)
            digest = _sha256(archive)
            api_digest = artifact.get("digest")
            if api_digest:
                normalized_api_digest = str(api_digest).removeprefix("sha256:")
                if normalized_api_digest != digest:
                    raise SecurityEvidenceError(
                        f"artifact {artifact_name} digest does not match GitHub metadata"
                    )
            expected_os = EXPECTED_RUNNER_OS[proof_type]
            expected_platform = {
                "macos-native-authority": "darwin",
                "windows-native-authority": "win32",
            }[proof_type]
            proof, proof_manifest_digest = _extract_proof_archive(
                archive,
                proof_type=proof_type,
                expected_commit=expected_commit,
                run_id=run_id,
                workflow_name=workflow_name,
                runner_os=expected_os,
                platform=expected_platform,
            )
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
                runner_arch=str(proof.get("runner_arch", "")),
                artifact_id=artifact_id,
                artifact_name=artifact_name,
                artifact_sha256=digest,
                proof_type=proof_type,
                proof_schema_version=1,
                policy_digest=str(proof.get("policy_digest", "")),
                generated_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                producer_identity=f"github-actions:{repo}:run:{run_id}",
                run_conclusion="success",
                proof_manifest_sha256=proof_manifest_digest,
                producer_job_name=str(proof["job_name"]),
            )
            manifests.append(manifest)
    if not manifests:
        raise SecurityEvidenceError(
            f"run {run_id} produced no recognizable security proof artifacts"
        )
    proof_types = {manifest.proof_type for manifest in manifests}
    if len(manifests) != len(ARTIFACT_PROOF_TYPES) or proof_types != set(ARTIFACT_PROOF_TYPES.values()):
        raise SecurityEvidenceError(
            "native evidence must contain exactly one macOS and one Windows proof"
        )
    return manifests


def _artifact_proof_type(artifact_name: str) -> str | None:
    return ARTIFACT_PROOF_TYPES.get(artifact_name)


def _download_artifact(repo: str, artifact_id: str, destination: Path) -> None:
    try:
        payload = gh_api_bytes(
            repo,
            f"actions/artifacts/{artifact_id}/zip",
            timeout_seconds=60.0,
            max_output_bytes=64 * 1024 * 1024,
        )
    except Exception as exc:
        raise SecurityEvidenceError(
            f"artifact {artifact_id} could not be downloaded: {exc}"
        ) from exc
    if not payload:
        raise SecurityEvidenceError(f"artifact {artifact_id} could not be downloaded")
    destination.write_bytes(payload)


def _extract_proof_archive(
    archive: Path,
    *,
    proof_type: str,
    expected_commit: str,
    run_id: str,
    workflow_name: str,
    runner_os: str,
    platform: str,
) -> tuple[dict[str, object], str]:
    try:
        payload = archive.read_bytes()
    except OSError as exc:
        raise SecurityEvidenceError(f"proof archive cannot be read: {archive}") from exc
    return parse_proof_archive(
        payload,
        expected_proof_type=proof_type,
        expected_commit=expected_commit,
        expected_run_id=run_id,
        expected_workflow=workflow_name,
        expected_runner_os=runner_os,
        expected_platform=platform,
    )


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
    # The proof binds itself to the exact job name.  Platform-only matching
    # allowed another successful job in the same run to impersonate the
    # producer, so both the name and runner OS are required.
    wanted_name = str(proof.get("job_name", ""))
    platform = str(proof.get("platform", ""))
    wanted_os = {"darwin": "macOS", "win32": "Windows"}.get(platform)
    matches = [
        job
        for job in jobs.values()
        if str(job.get("name", "")) == wanted_name
        and wanted_os is not None
        and _runner_os_for(job) == wanted_os
    ]
    if len(matches) != 1:
        raise SecurityEvidenceError(
            f"proof producer job {wanted_name!r} is not uniquely successful"
        )
    return matches[0]


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
