#!/usr/bin/env python3
"""Aggregate producer-owned Community Local evidence.

This command intentionally does not run pytest and cannot manufacture a proof.
It consumes producer files downloaded from the exact Security Closure Gate run,
checks each producer's own digest/result/diagnostics, and emits only the
minimal local bundle consumed by the live release verifier.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from khaos.security.effective_policy import load_effective_policy
from khaos.security.local_closure import (
    COMMUNITY_LOCAL_REQUIRED_PROOFS,
    LOCAL_EVIDENCE_SCHEMA,
    REPOSITORY,
    canonical_digest,
)
from khaos.security.producer_evidence import (
    PROCESS_TREE_PROOF,
    PRODUCTION_COMPOSITION_PROOF,
    PRODUCER_EVIDENCE_SCHEMA,
    RESOURCE_OWNER_PROOF,
    validate_producer_proof,
)


MANIFEST_SCHEMA = "khaos.local-security-producer-artifact-manifest.v1"
EXPECTED_PRODUCER_ARTIFACTS = frozenset(
    {
        "community-local-test-producer-evidence-{commit}",
        "production-composition-evidence-{commit}",
        "production-lifecycle-evidence-{commit}",
    }
)
_PRODUCTION_PROOFS = frozenset(
    {PRODUCTION_COMPOSITION_PROOF, PROCESS_TREE_PROOF, RESOURCE_OWNER_PROOF}
)


def _args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--producer-dir", type=Path, required=True)
    parser.add_argument("--producer-manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    return parser.parse_args()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _identity(commit: str) -> dict[str, object]:
    import os

    expected = {
        "repository": REPOSITORY,
        "event": "push",
        "ref": "refs/heads/main",
        "head_sha": commit,
    }
    actual = {
        "repository": os.environ.get("GITHUB_REPOSITORY", ""),
        "event": os.environ.get("GITHUB_EVENT_NAME", ""),
        "ref": os.environ.get("GITHUB_REF", ""),
        "head_sha": os.environ.get("GITHUB_SHA", ""),
    }
    if actual != expected:
        raise RuntimeError(
            "Community Local aggregator requires the exact main push: "
            + json.dumps(actual, sort_keys=True)
        )
    if os.environ.get("GITHUB_RUN_ATTEMPT") != "1":
        raise RuntimeError("Community Local aggregator requires attempt 1")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    if not run_id.isdigit() or int(run_id) <= 0:
        raise RuntimeError("Community Local aggregator requires a numeric run id")
    for key in ("GITHUB_WORKFLOW", "RUNNER_OS", "GITHUB_JOB"):
        if not os.environ.get(key, "").strip():
            raise RuntimeError(f"Community Local aggregator requires {key}")
    return {
        "repository": REPOSITORY,
        "workflow": os.environ["GITHUB_WORKFLOW"],
        "run_id": run_id,
        "run_attempt": 1,
        "event": "push",
        "ref": "refs/heads/main",
        "head_sha": commit,
        "runner_os": os.environ["RUNNER_OS"],
        "job": os.environ["GITHUB_JOB"],
    }


def _load_manifest(path: Path, commit: str) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"producer artifact manifest is unreadable: {path}") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("producer artifact manifest is not an object")
    supplied = payload.pop("manifest_digest", None)
    if (
        payload.get("schema") != MANIFEST_SCHEMA
        or payload.get("commit") != commit
        or not isinstance(payload.get("security_run"), dict)
        or not isinstance(payload.get("artifacts"), list)
        or not isinstance(supplied, str)
        or supplied != canonical_digest(payload)
    ):
        raise RuntimeError("producer artifact manifest identity or digest is invalid")
    payload["manifest_digest"] = supplied
    security_run = payload["security_run"]
    assert isinstance(security_run, dict)
    if (
        security_run.get("event") != "push"
        or security_run.get("head_branch") != "main"
        or security_run.get("head_sha") != commit
        or security_run.get("run_attempt") != 1
        or not str(security_run.get("run_id") or "").isdigit()
    ):
        raise RuntimeError("producer artifact manifest is not exact-main attempt 1")
    names: set[str] = set()
    for artifact in payload["artifacts"]:
        if not isinstance(artifact, dict):
            raise RuntimeError("producer artifact record is malformed")
        name = artifact.get("name")
        digest = artifact.get("artifact_sha256")
        files = artifact.get("files")
        if (
            not isinstance(name, str)
            or not name
            or name in names
            or not isinstance(digest, str)
            or len(digest) != 64
            or not isinstance(files, list)
            or not files
        ):
            raise RuntimeError("producer artifact record is not exact")
        names.add(name)
        diagnostics_files = artifact.get("diagnostics_files")
        if not isinstance(diagnostics_files, list) or not diagnostics_files:
            raise RuntimeError(f"producer artifact {name} has no diagnostics provenance")
        for file_record in files:
            if not isinstance(file_record, dict):
                raise RuntimeError("producer artifact file record is malformed")
            if not isinstance(file_record.get("path"), str) or not file_record["path"]:
                raise RuntimeError("producer artifact file path is missing")
        for diagnostic_path in diagnostics_files:
            if not isinstance(diagnostic_path, str) or not diagnostic_path:
                raise RuntimeError("producer diagnostic file path is malformed")
    expected_names = {
        pattern.format(commit=commit) for pattern in EXPECTED_PRODUCER_ARTIFACTS
    }
    if names != expected_names:
        raise RuntimeError(
            "producer artifact set is not exact: "
            f"missing={sorted(expected_names - names)} unexpected={sorted(names - expected_names)}"
        )
    return payload


def _producer_files(
    producer_dir: Path,
    manifest: dict[str, Any],
    commit: str,
) -> dict[str, tuple[dict[str, object], dict[str, object]]]:
    artifact_by_path: dict[str, dict[str, object]] = {}
    diagnostic_paths: set[str] = set()
    for artifact in manifest["artifacts"]:
        assert isinstance(artifact, dict)
        for file_record in artifact["files"]:
            assert isinstance(file_record, dict)
            path = str(file_record["path"])
            if path in artifact_by_path:
                raise RuntimeError(f"duplicate producer file provenance: {path}")
            artifact_by_path[path] = artifact
        for diagnostic_path in artifact["diagnostics_files"]:
            if (
                not isinstance(diagnostic_path, str)
                or diagnostic_path in artifact_by_path
                or diagnostic_path in diagnostic_paths
            ):
                raise RuntimeError(f"duplicate producer diagnostic provenance: {diagnostic_path}")
            diagnostic_paths.add(diagnostic_path)
    for relative in diagnostic_paths:
        path = (producer_dir / relative).resolve()
        if producer_dir.resolve() not in path.parents or not path.is_file() or path.is_symlink():
            raise RuntimeError(f"producer diagnostic is missing or escapes producer dir: {relative}")
    found: dict[str, tuple[dict[str, object], dict[str, object]]] = {}
    for relative, artifact in artifact_by_path.items():
        path = (producer_dir / relative).resolve()
        if producer_dir.resolve() not in path.parents or not path.is_file() or path.is_symlink():
            raise RuntimeError(f"producer file is missing or escapes producer dir: {relative}")
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"producer proof is malformed: {relative}") from exc
        if not isinstance(value, dict) or value.get("schema") != PRODUCER_EVIDENCE_SCHEMA:
            raise RuntimeError(f"unexpected producer JSON in manifest: {relative}")
        proof = validate_producer_proof(value, expected_commit=commit)
        name = proof.get("proof_type")
        if not isinstance(name, str) or name in found:
            raise RuntimeError(f"duplicate producer proof: {name}")
        artifact_name = artifact.get("name")
        artifact_digest = artifact.get("artifact_sha256")
        if not isinstance(artifact_name, str) or not isinstance(artifact_digest, str):
            raise RuntimeError("producer artifact binding is malformed")
        workflow = proof.get("workflow")
        if not isinstance(workflow, dict):
            raise RuntimeError("producer workflow provenance is malformed")
        security_run = manifest["security_run"]
        assert isinstance(security_run, dict)
        if (
            str(workflow.get("run_id")) != str(security_run.get("run_id"))
            or workflow.get("event") != "push"
            or workflow.get("ref") != "refs/heads/main"
            or workflow.get("head_sha") != commit
            or workflow.get("run_attempt") != 1
        ):
            raise RuntimeError(f"producer {name} provenance is not exact-main")
        found[name] = (
            proof,
            {
                "name": artifact_name,
                "artifact_digest": artifact_digest,
                "path": relative,
            },
        )
    return found


def _local_proof(
    proof: dict[str, object], artifact: dict[str, object], policy_digest: str
) -> dict[str, object]:
    name = str(proof["proof_type"])
    if proof.get("result") != "PASS":
        diagnostics = proof.get("diagnostics")
        raise RuntimeError(
            f"proof {name} is {proof.get('result')}; diagnostics="
            + json.dumps(diagnostics, sort_keys=True)
        )
    if proof.get("policy_digest") != policy_digest:
        raise RuntimeError(f"proof {name} uses a different policy digest")
    expected_production = name in _PRODUCTION_PROOFS
    if proof.get("production_claim") is not expected_production:
        raise RuntimeError(f"proof {name} has the wrong production ownership")
    producer_digest = proof.get("evidence_digest")
    if not isinstance(producer_digest, str) or len(producer_digest) != 64:
        raise RuntimeError(f"proof {name} has no producer evidence digest")
    workflow = proof["workflow"]
    assert isinstance(workflow, dict)
    return {
        "name": name,
        "proof_type": name,
        "status": "PASS",
        "profile": "community-local",
        "commit": proof["commit"],
        "policy_digest": policy_digest,
        "artifact_digest": artifact["artifact_digest"],
        "producer_artifact_name": artifact["name"],
        "producer_evidence_digest": producer_digest,
        "provenance": dict(workflow),
    }


def main() -> int:
    args = _args()
    repo_root = args.repo_root.resolve()
    commit = args.commit
    identity = _identity(commit)
    manifest = _load_manifest(args.producer_manifest.resolve(), commit)
    producers = _producer_files(args.producer_dir.resolve(), manifest, commit)
    required = set(COMMUNITY_LOCAL_REQUIRED_PROOFS)
    if set(producers) != required:
        missing = sorted(required - set(producers))
        unexpected = sorted(set(producers) - required)
        raise RuntimeError(
            "producer proof set is not exact: "
            f"missing={','.join(missing)} unexpected={','.join(unexpected)}"
        )
    policy = load_effective_policy(repo_root)
    proofs = [
        _local_proof(producers[name][0], producers[name][1], policy.digest)
        for name in COMMUNITY_LOCAL_REQUIRED_PROOFS
    ]
    composition = producers[PRODUCTION_COMPOSITION_PROOF][0]
    composition_digest = composition.get("production_composition_manifest_digest")
    if not isinstance(composition_digest, str) or len(composition_digest) != 64:
        raise RuntimeError("production composition producer has no manifest digest")
    payload: dict[str, Any] = {
        "schema": LOCAL_EVIDENCE_SCHEMA,
        "profile": "community-local",
        "commit": commit,
        "policy_digest": policy.digest,
        "security_facts_digest": _sha256(repo_root / "docs/security_facts.yaml"),
        "production_reachability_digest": _sha256(
            repo_root / "docs/generated/production-reachability.md"
        ),
        "production_composition_digest": composition_digest,
        "workflow": identity,
        "proofs": proofs,
        "profile_status": {
            "apple_developer_program": "NOT_APPLICABLE",
            "apple_team_id": "NOT_APPLICABLE",
            "signed_xpc": "NOT_APPLICABLE",
            "notarization": "NOT_APPLICABLE",
            "macos_signed_distribution": "OPTIONAL_PROFILE_NOT_ENABLED",
            "hostile_same_uid_isolation": "NOT_CLAIMED",
            "independent_review": "NOT_CLAIMED",
        },
        "residual_risks": [
            "hostile same-UID isolation is NOT_CLAIMED",
            "second-maintainer independent review is NOT_CLAIMED",
            "macOS Signed Distribution is OPTIONAL_PROFILE_NOT_ENABLED",
        ],
    }
    payload["evidence_digest"] = canonical_digest(payload)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        "aggregated exact producer proofs: "
        + ", ".join(
            f"{proof['name']} artifact={proof['producer_artifact_name']}"
            for proof in proofs
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
