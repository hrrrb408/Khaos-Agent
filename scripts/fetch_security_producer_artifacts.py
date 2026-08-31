#!/usr/bin/env python3
"""Fetch exact producer artifacts from one completed Security Closure run.

The Community Local workflow is triggered by the upstream ``workflow_run``
completion event.  This command therefore consumes the event's run id and
re-validates that run through the GitHub API; it never searches for a latest
successful run and never waits for the upstream workflow to finish.  A short,
bounded retry is retained only for Actions artifact eventual consistency after
the already-completed run becomes observable.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import stat
import time
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

from khaos.security.evidence_provenance import gh_api_bytes
from khaos.security.local_closure import canonical_digest
from khaos.security.producer_evidence import validate_producer_proof

MANIFEST_SCHEMA = "khaos.local-security-producer-artifact-manifest.v1"
ARTIFACT_PATTERNS = (
    "community-local-test-producer-evidence-{commit}",
    "production-composition-evidence-{commit}",
    "production-lifecycle-evidence-{commit}",
)
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_FILE_BYTES = 8 * 1024 * 1024
ARTIFACT_RETRY_ATTEMPTS = 5
ARTIFACT_RETRY_DELAY_SECONDS = 2.0
SECURITY_WORKFLOW_NAME = "Security Closure Gate"
SECURITY_WORKFLOW_PATH = ".github/workflows/security-closure-gate.yml"
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_RUN_ID_RE = re.compile(r"^[1-9][0-9]*$")


def _args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--workflow", default="security-closure-gate.yml")
    return parser.parse_args()


def _json(repo: str, endpoint: str) -> dict[str, Any]:
    value = json.loads(gh_api_bytes(repo, endpoint).decode("utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError(f"GitHub API response is not an object: {endpoint}")
    return value


def _select_security_run(
    repo: str, workflow: str, commit: str, run_id: str
) -> dict[str, Any]:
    """Load and validate the exact upstream run named by the event.

    The run id is an input to identify the event's upstream run, not a trust
    decision.  Every security-relevant field is checked against the live API
    response before any artifact is downloaded.
    """
    if not _COMMIT_RE.fullmatch(commit):
        raise RuntimeError("Security Closure commit must be a full lowercase SHA")
    if not _RUN_ID_RE.fullmatch(run_id):
        raise RuntimeError("Security Closure run id must be a positive integer")
    selected = _json(repo, f"actions/runs/{run_id}")
    selected_id = str(selected.get("id") or "")
    if selected_id != run_id:
        raise RuntimeError("Security Closure API returned a different run id")
    database_id = selected.get("database_id")
    if database_id is not None and str(database_id) != run_id:
        raise RuntimeError("Security Closure API database id differs from run id")
    repository = selected.get("repository")
    head_repository = selected.get("head_repository")
    repository_name = repository.get("full_name") if isinstance(repository, dict) else None
    head_repository_name = (
        head_repository.get("full_name") if isinstance(head_repository, dict) else None
    )
    if repository_name != repo or head_repository_name != repo:
        raise RuntimeError("Security Closure run is not produced by the trusted repository")
    if selected.get("name") != SECURITY_WORKFLOW_NAME:
        raise RuntimeError("Security Closure run has the wrong workflow name")
    if selected.get("path") != SECURITY_WORKFLOW_PATH or workflow != "security-closure-gate.yml":
        raise RuntimeError("Security Closure run has the wrong workflow file")
    workflow_id = selected.get("workflow_id")
    if type(workflow_id) is not int or workflow_id <= 0:
        raise RuntimeError("Security Closure run has no valid workflow id")
    if (
        selected.get("head_sha") != commit
        or selected.get("event") != "push"
        or selected.get("head_branch") != "main"
        or selected.get("status") != "completed"
        or selected.get("conclusion") != "success"
        or type(selected.get("run_attempt")) is not int
        or selected.get("run_attempt") != 1
    ):
        raise RuntimeError(
            "exact Security Closure attempt 1 is not a successful completed main push"
        )
    return {
        "repository": repo,
        "workflow": SECURITY_WORKFLOW_NAME,
        "workflow_name": SECURITY_WORKFLOW_NAME,
        "workflow_file": workflow,
        "workflow_path": selected["path"],
        "workflow_id": workflow_id,
        "run_id": run_id,
        "run_attempt": 1,
        "event": "push",
        "head_branch": "main",
        "head_sha": commit,
        "ref": "refs/heads/main",
        "status": "completed",
        "conclusion": "success",
        "html_url": selected.get("html_url"),
    }


def _artifacts(repo: str, run_id: str) -> list[dict[str, Any]]:
    payload = _json(repo, f"actions/runs/{run_id}/artifacts?per_page=100")
    values = payload.get("artifacts")
    if not isinstance(values, list) or int(payload.get("total_count") or 0) > 100:
        raise RuntimeError("Security Closure artifact list is malformed or paginated")
    return [value for value in values if isinstance(value, dict)]


def _wait_for_expected_artifacts(
    repo: str, run_id: str, expected_names: set[str]
) -> dict[str, dict[str, Any]]:
    """Allow only a short post-completion artifact visibility retry."""
    missing = set(expected_names)
    for attempt in range(ARTIFACT_RETRY_ATTEMPTS):
        available: dict[str, dict[str, Any]] = {}
        for artifact in _artifacts(repo, run_id):
            name = artifact.get("name")
            if not isinstance(name, str):
                continue
            if name in available:
                raise RuntimeError(f"Security Closure artifact name is duplicated: {name}")
            available[name] = artifact
        missing = expected_names - set(available)
        if not missing:
            ids = [str(available[name].get("id") or "") for name in expected_names]
            if any(not _RUN_ID_RE.fullmatch(item) for item in ids):
                raise RuntimeError("Security Closure producer artifact id is malformed")
            if len(ids) != len(set(ids)):
                raise RuntimeError("Security Closure producer artifacts reuse an id")
            return {name: available[name] for name in sorted(expected_names)}
        if attempt + 1 < ARTIFACT_RETRY_ATTEMPTS:
            print(
                "retrying exact completed-run artifact lookup "
                f"({attempt + 1}/{ARTIFACT_RETRY_ATTEMPTS - 1}); missing: "
                + ", ".join(sorted(missing))
            )
            time.sleep(ARTIFACT_RETRY_DELAY_SECONDS)
    raise RuntimeError(
        "Security Closure run is missing producer artifact(s) after bounded "
        "post-completion consistency retries: "
        + ", ".join(sorted(missing))
    )


def _safe_extract(payload: bytes, destination: Path) -> list[str]:
    if len(payload) > MAX_ARCHIVE_BYTES:
        raise RuntimeError("producer artifact archive exceeds the download limit")
    names: list[str] = []
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        seen: set[str] = set()
        for info in archive.infolist():
            name = info.filename
            if name.endswith("/"):
                continue
            relative = PurePosixPath(name)
            if relative.is_absolute() or ".." in relative.parts or not name:
                raise RuntimeError(f"producer artifact contains unsafe path: {name}")
            normalized = relative.as_posix()
            if normalized in seen:
                raise RuntimeError(f"producer artifact contains duplicate path: {name}")
            seen.add(normalized)
            mode = (info.external_attr >> 16) & 0o170000
            if mode == stat.S_IFLNK:
                raise RuntimeError(f"producer artifact contains a symlink: {name}")
            if info.file_size > MAX_FILE_BYTES:
                raise RuntimeError(f"producer artifact file is too large: {name}")
            target = destination.joinpath(*relative.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists() or target.is_symlink():
                raise RuntimeError(f"producer artifact target already exists: {name}")
            with archive.open(info, "r") as source:
                data = source.read(MAX_FILE_BYTES + 1)
            if len(data) > MAX_FILE_BYTES:
                raise RuntimeError(f"producer artifact file exceeds the limit: {name}")
            target.write_bytes(data)
            names.append(normalized)
    return sorted(names)


def _download_one(
    repo: str,
    artifact: dict[str, Any],
    run: dict[str, Any],
    output_dir: Path,
    commit: str,
) -> dict[str, object]:
    name = artifact.get("name")
    artifact_id = str(artifact.get("id") or "")
    if not isinstance(name, str) or not name or not _RUN_ID_RE.fullmatch(artifact_id):
        raise RuntimeError("producer artifact identity is malformed")
    if artifact.get("expired") is not False:
        raise RuntimeError(f"producer artifact {name} is expired or unverifiable")
    workflow_run = artifact.get("workflow_run")
    if not isinstance(workflow_run, dict) or str(workflow_run.get("id")) != str(run["run_id"]):
        raise RuntimeError(f"producer artifact {name} is not bound to Security Closure run")
    advertised = str(artifact.get("digest") or "").removeprefix("sha256:")
    if len(advertised) != 64:
        raise RuntimeError(f"producer artifact {name} has no GitHub digest")
    raw = gh_api_bytes(
        repo,
        f"actions/artifacts/{artifact_id}/zip",
        timeout_seconds=60.0,
        max_output_bytes=MAX_ARCHIVE_BYTES,
    )
    actual = hashlib.sha256(raw).hexdigest()
    if actual != advertised:
        raise RuntimeError(f"producer artifact {name} digest mismatch")
    destination = output_dir / name
    destination.mkdir(parents=True, exist_ok=False)
    files = _safe_extract(raw, destination)
    proof_files: list[dict[str, object]] = []
    diagnostic_files: list[str] = []
    for relative in files:
        candidate = destination / relative
        if not candidate.name.startswith("proof-") and not candidate.name.endswith("proof.json"):
            if (
                candidate.name.startswith("diagnostics-")
                or "diagnostics" in candidate.name
                or candidate.name.startswith("junit-")
                or candidate.name.startswith("stdout-")
                or candidate.name.startswith("stderr-")
                or candidate.name.endswith(".junit.xml")
                or candidate.name.endswith(".stdout.log")
                or candidate.name.endswith(".stderr.log")
            ):
                diagnostic_files.append(f"{name}/{relative}")
            continue
        try:
            value = json.loads(candidate.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"producer proof JSON is malformed: {name}/{relative}") from exc
        proof = validate_producer_proof(value, expected_commit=commit)
        proof_files.append(
            {
                "path": f"{name}/{relative}",
                "proof_type": proof["proof_type"],
                "evidence_digest": proof["evidence_digest"],
            }
        )
    if not diagnostic_files:
        raise RuntimeError(f"producer artifact {name} contains no diagnostics")
    if not proof_files:
        raise RuntimeError(f"producer artifact {name} contains no producer proof")
    return {
        "id": artifact_id,
        "name": name,
        "artifact_sha256": actual,
        "files": proof_files,
        "diagnostics_files": diagnostic_files,
    }


def main() -> int:
    args = _args()
    run = _select_security_run(args.repo, args.workflow, args.commit, args.run_id)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    expected_names = {pattern.format(commit=args.commit) for pattern in ARTIFACT_PATTERNS}
    available = _wait_for_expected_artifacts(args.repo, str(run["run_id"]), expected_names)
    records = [
        _download_one(args.repo, available[name], run, args.output_dir, args.commit)
        for name in sorted(expected_names)
    ]
    manifest: dict[str, object] = {
        "schema": MANIFEST_SCHEMA,
        "commit": args.commit,
        "security_run": run,
        "artifacts": records,
    }
    manifest["manifest_digest"] = canonical_digest(manifest)
    args.manifest.parent.mkdir(parents=True, exist_ok=True)
    args.manifest.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        "downloaded exact producer artifacts: "
        + ", ".join(f"{record['name']} sha256={record['artifact_sha256']}" for record in records)
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
