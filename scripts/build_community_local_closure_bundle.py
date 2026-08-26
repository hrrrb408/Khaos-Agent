#!/usr/bin/env python3
"""Build an immutable, audit-only Community Local closure bundle.

The input is the output of the live exact-SHA release verifier. This command
does not issue or serialize ``VerifiedGitHubProvenance``; its output is a
release record for human and forensic review only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast


BUNDLE_SCHEMA = "khaos.community-local-closure-bundle.v1"
RELEASE_EVIDENCE_SCHEMA = "khaos.release-gate-evidence.v1"
PROFILE = "community-local"
REQUIRED_RUN_FIELDS = (
    "workflow",
    "workflow_name",
    "run_id",
    "run_attempt",
    "head_sha",
    "event",
    "head_branch",
    "status",
    "conclusion",
    "url",
    "evidence_digest",
)


def _canonical_digest(value: object) -> str:
    encoded = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _mapping(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{label} must be an object")
    return dict(cast(Mapping[str, Any], value))


def _run_identity(record: Mapping[str, Any], label: str, commit: str) -> dict[str, Any]:
    identity: dict[str, Any] = {}
    for field in REQUIRED_RUN_FIELDS:
        if field not in record:
            raise ValueError(f"{label} is missing {field}")
        identity[field] = record[field]
    if identity["head_sha"] != commit:
        raise ValueError(f"{label} is not bound to the exact commit")
    if (
        identity["run_attempt"] != 1
        or identity["event"] != "push"
        or identity["head_branch"] != "main"
        or identity["status"] != "completed"
        or identity["conclusion"] != "success"
    ):
        raise ValueError(f"{label} is not a successful original main-push run")
    return identity


def _producer_digests(record: Mapping[str, Any]) -> list[dict[str, Any]]:
    raw = record.get("producer_proofs")
    if not isinstance(raw, list) or not raw:
        raise ValueError("Community Local gate has no producer proof digests")
    output: list[dict[str, Any]] = []
    for item in raw:
        proof = _mapping(item, "producer proof")
        required = (
            "proof_type",
            "artifact_name",
            "artifact_id",
            "artifact_sha256",
            "producer_evidence_digest",
            "job_id",
            "job",
            "workflow",
            "runner_os",
            "policy_digest",
        )
        if any(field not in proof for field in required):
            raise ValueError("producer proof digest record is incomplete")
        output.append({field: proof[field] for field in required})
    return sorted(output, key=lambda item: str(item["proof_type"]))


def build_bundle(evidence: Mapping[str, Any]) -> dict[str, Any]:
    """Return a validated audit bundle from live release-gate evidence."""
    if evidence.get("schema") != RELEASE_EVIDENCE_SCHEMA:
        raise ValueError("unsupported release gate evidence schema")
    if evidence.get("profile") != PROFILE:
        raise ValueError("closure bundle requires the Community Local profile")
    commit = evidence.get("commit")
    if not isinstance(commit, str) or len(commit) != 40:
        raise ValueError("closure bundle commit is malformed")

    ancestry = _mapping(evidence.get("main_ancestry"), "main ancestry")
    if (
        ancestry.get("base") != commit
        or ancestry.get("head") != "main"
        or ancestry.get("behind_by") != 0
        or ancestry.get("status") not in {"ahead", "identical"}
    ):
        raise ValueError("closure bundle lacks protected main ancestry")
    gates = _mapping(evidence.get("gates"), "release gates")
    security = _mapping(gates.get("security_closure"), "Security Closure gate")
    product = _mapping(gates.get("product_integrity"), "Product Integrity gate")
    local = _mapping(gates.get("community_local"), "Community Local gate")
    security_identity = _run_identity(security, "Security Closure gate", commit)
    product_identity = _run_identity(product, "Product Integrity gate", commit)
    local_identity = _run_identity(local, "Community Local gate", commit)

    security_proof = _mapping(security.get("security_proof"), "Security Closure proof")
    local_proof = _mapping(local.get("local_proof"), "Community Local proof")
    policy_digest = security_proof.get("policy_digest")
    schema_digest = security_proof.get("schema_digest")
    if not isinstance(policy_digest, str) or not isinstance(schema_digest, str):
        raise ValueError("closure bundle lacks policy or schema digest")
    if local_proof.get("policy_digest") != policy_digest:
        raise ValueError("closure bundle policy digest is inconsistent")
    producer_digests = _producer_digests(local)
    if {item["policy_digest"] for item in producer_digests} != {policy_digest}:
        raise ValueError("producer policy digests are inconsistent")

    artifacts: list[dict[str, Any]] = []
    for gate_name, record in (
        ("security_closure", security),
        ("community_local", local),
    ):
        raw_artifacts = record.get("artifacts")
        if not isinstance(raw_artifacts, list):
            raise ValueError(f"{gate_name} has no artifact manifest")
        for item in raw_artifacts:
            artifact = _mapping(item, f"{gate_name} artifact")
            name = artifact.get("name")
            digest = artifact.get("digest")
            if isinstance(name, str) and isinstance(digest, str) and digest:
                artifacts.append(
                    {
                        "gate": gate_name,
                        "id": artifact.get("id"),
                        "name": name,
                        "digest": digest,
                        "expired": artifact.get("expired"),
                    }
                )

    local_evidence_digest = local_proof.get("local_evidence_digest")
    if not isinstance(local_evidence_digest, str) or not local_evidence_digest:
        raise ValueError("closure bundle lacks local evidence digest")
    residuals = local_proof.get("residual_risks", [])
    profile_status = local_proof.get("profile_status", {})
    if not isinstance(residuals, list) or not isinstance(profile_status, Mapping):
        raise ValueError("closure bundle accepted residuals are malformed")
    proof_digests = {
        item["proof_type"]: {
            "artifact_sha256": item["artifact_sha256"],
            "producer_evidence_digest": item["producer_evidence_digest"],
        }
        for item in producer_digests
    }
    evidence_digest = evidence.get("evidence_digest")
    if not isinstance(evidence_digest, str) or not evidence_digest:
        raise ValueError("closure bundle lacks release evidence digest")
    unsigned: dict[str, Any] = {
        "schema": BUNDLE_SCHEMA,
        "audit_only": True,
        "live_provenance_capability_issued": False,
        "machine_decision": {
            "status": "CLOSED",
            "profile": PROFILE,
            "source": "live_exact_sha_release_verifier",
            "saved_record_cannot_issue_capability": True,
        },
        "closure_report": {
            "status": "CLOSED",
            "profile": PROFILE,
            "commit": commit,
            "release_gate_evidence_digest": evidence_digest,
            "local_evidence_digest": local_evidence_digest,
            "accepted_residuals": list(residuals),
            "profile_status": dict(cast(Mapping[str, object], profile_status)),
        },
        "evidence_manifest": {
            "schema": RELEASE_EVIDENCE_SCHEMA,
            "evidence_digest": evidence_digest,
            "main_ancestry": ancestry,
        },
        "security_closure_run": security_identity,
        "product_integrity_run": product_identity,
        "community_local_run": local_identity,
        "producer_artifact_digests": sorted(
            artifacts, key=lambda item: (str(item["gate"]), str(item["name"]))
        ),
        "policy_digest": policy_digest,
        "schema_digest": schema_digest,
        "proof_digests": proof_digests,
        "exact_sha": commit,
        "profile": PROFILE,
    }
    bundle = dict(unsigned)
    bundle["bundle_digest"] = _canonical_digest(unsigned)
    return bundle


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--gate-evidence", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    try:
        raw = json.loads(args.gate_evidence.read_text(encoding="utf-8"))
        evidence = _mapping(raw, "release gate evidence")
        bundle = build_bundle(evidence)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(bundle, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise SystemExit(f"cannot build Community Local closure bundle: {exc}") from exc
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
