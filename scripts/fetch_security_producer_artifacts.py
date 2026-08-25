#!/usr/bin/env python3
"""Fetch exact producer artifacts from the Security Closure Gate run.

The Community Local workflow uses this bounded poller to avoid a cross-workflow
race.  It never reruns a failed workflow and records GitHub's artifact digest;
the release verifier downloads and checks the same bytes again later.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
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


def _args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--workflow", default="security-closure-gate.yml")
    parser.add_argument("--poll-seconds", type=float, default=10.0)
    parser.add_argument("--timeout-seconds", type=float, default=1800.0)
    return parser.parse_args()


def _json(repo: str, endpoint: str) -> dict[str, Any]:
    value = json.loads(gh_api_bytes(repo, endpoint).decode("utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError(f"GitHub API response is not an object: {endpoint}")
    return value


def _select_security_run(repo: str, workflow: str, commit: str) -> dict[str, Any]:
    payload = _json(
        repo,
        f"actions/workflows/{workflow}/runs?head_sha={commit}&per_page=100",
    )
    runs = payload.get("workflow_runs")
    if not isinstance(runs, list):
        raise RuntimeError("Security Closure Gate run list is malformed")
    candidates = [
        run
        for run in runs
        if isinstance(run, dict)
        and run.get("head_sha") == commit
        and run.get("event") == "push"
        and run.get("head_branch") == "main"
        and int(run.get("run_attempt") or 0) == 1
    ]
    if not candidates:
        raise RuntimeError("Security Closure Gate run is not available yet")
    active = [run for run in candidates if run.get("status") != "completed"]
    if active:
        raise RuntimeError("Security Closure Gate is still running")
    successful = [run for run in candidates if run.get("conclusion") == "success"]
    if len(successful) > 1:
        raise RuntimeError(
            "multiple successful Security Closure Gate attempt-1 runs exist "
            "for the exact commit"
        )
    if len(successful) != 1:
        conclusions = ",".join(str(run.get("conclusion")) for run in candidates)
        raise RuntimeError(f"exact Security Closure Gate attempt-1 did not succeed: {conclusions}")
    selected = successful[0]
    return {
        "run_id": str(selected.get("database_id") or selected.get("id") or ""),
        "run_attempt": 1,
        "event": "push",
        "head_branch": "main",
        "head_sha": commit,
        "workflow": str(selected.get("name") or workflow),
        "workflow_file": workflow,
        "html_url": selected.get("html_url"),
    }


def _artifacts(repo: str, run_id: str) -> list[dict[str, Any]]:
    payload = _json(repo, f"actions/runs/{run_id}/artifacts?per_page=100")
    values = payload.get("artifacts")
    if not isinstance(values, list) or int(payload.get("total_count") or 0) > 100:
        raise RuntimeError("Security Closure artifact list is malformed or paginated")
    return [value for value in values if isinstance(value, dict)]


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
    if not isinstance(name, str) or not name or not artifact_id.isdigit():
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
    deadline = time.monotonic() + args.timeout_seconds
    while True:
        try:
            run = _select_security_run(args.repo, args.workflow, args.commit)
            break
        except RuntimeError as exc:
            if time.monotonic() >= deadline:
                raise
            if "did not succeed" in str(exc):
                raise
            print(f"waiting for exact Security Closure Gate: {exc}")
            time.sleep(max(0.5, min(args.poll_seconds, 60.0)))
    args.output_dir.mkdir(parents=True, exist_ok=True)
    expected_names = [pattern.format(commit=args.commit) for pattern in ARTIFACT_PATTERNS]
    while True:
        available = {
            str(artifact.get("name")): artifact
            for artifact in _artifacts(args.repo, str(run["run_id"]))
        }
        missing = set(expected_names) - set(available)
        if not missing:
            break
        if time.monotonic() >= deadline:
            raise RuntimeError(
                "Security Closure run is missing producer artifact(s): "
                + ", ".join(sorted(missing))
            )
        print(
            "waiting for exact producer artifacts: "
            + ", ".join(sorted(missing))
        )
        time.sleep(max(0.5, min(args.poll_seconds, 60.0)))
    records = [
        _download_one(args.repo, available[name], run, args.output_dir, args.commit)
        for name in expected_names
    ]
    manifest: dict[str, object] = {
        "schema": "khaos.local-security-producer-artifact-manifest.v1",
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
