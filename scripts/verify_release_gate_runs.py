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
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REQUIRED_GATES = {
    "security_closure": "security-closure-gate.yml",
    "product_integrity": "product-integrity-gate.yml",
}


def _canonical_digest(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _run_gh_api(repo: str, endpoint: str) -> dict[str, Any]:
    raw = subprocess.check_output(
        ["gh", "api", f"repos/{repo}/{endpoint}"], text=True
    )
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError(f"GitHub API returned a non-object for {endpoint}")
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
        and run.get("status") == "completed"
        and run.get("conclusion") == "success"
    ]
    if not candidates:
        raise RuntimeError(
            f"no successful completed {workflow} run exists for exact commit {commit}"
        )
    return max(candidates, key=_run_sort_key)


def _artifact_records(repo: str, run_id: int) -> list[dict[str, Any]]:
    payload = _run_gh_api(repo, f"actions/runs/{run_id}/artifacts?per_page=100")
    records: list[dict[str, Any]] = []
    for artifact in payload.get("artifacts", []):
        if not isinstance(artifact, dict):
            continue
        records.append(
            {
                "id": artifact.get("id"),
                "name": artifact.get("name"),
                "size_in_bytes": artifact.get("size_in_bytes"),
                "expired": artifact.get("expired"),
                "digest": artifact.get("digest") or "",
            }
        )
    return sorted(records, key=lambda item: str(item.get("name") or ""))


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
    record = {
        "workflow": workflow,
        "run_id": run_id,
        "run_attempt": run.get("run_attempt"),
        "head_sha": run.get("head_sha"),
        "event": run.get("event"),
        "status": run.get("status"),
        "conclusion": run.get("conclusion"),
        "url": run.get("html_url"),
        "created_at": run.get("created_at"),
        "updated_at": run.get("updated_at"),
        "artifacts": _artifact_records(repo, run_id),
    }
    record["run_evidence_digest"] = _canonical_digest(record)
    return record


def verify_release_gates(repo: str, commit: str) -> dict[str, Any]:
    """Return commit-bound evidence for every required aggregate gate."""
    gates = {
        name: _gate_record(repo, workflow, commit)
        for name, workflow in REQUIRED_GATES.items()
    }
    evidence = {
        "schema": "khaos.release-gate-evidence.v1",
        "commit": commit,
        "verified_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
            "+00:00", "Z"
        ),
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
