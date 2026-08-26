"""Audit-only Community Local closure bundle contracts."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location(
    "build_community_local_closure_bundle",
    ROOT / "scripts" / "build_community_local_closure_bundle.py",
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


COMMIT = "a" * 40
POLICY = "b" * 64
SCHEMA = "c" * 64


def _run(name: str) -> dict[str, object]:
    return {
        "workflow": f"{name}.yml",
        "workflow_name": name,
        "run_id": 10,
        "run_attempt": 1,
        "head_sha": COMMIT,
        "event": "push",
        "head_branch": "main",
        "status": "completed",
        "conclusion": "success",
        "url": f"https://example.invalid/{name}",
        "evidence_digest": "d" * 64,
        "artifacts": [
            {
                "id": 11,
                "name": f"{name}-evidence",
                "digest": "e" * 64,
                "expired": False,
            }
        ],
    }


def _evidence() -> dict[str, object]:
    security = _run("Security Closure Gate")
    security["security_proof"] = {
        "policy_digest": POLICY,
        "schema_digest": SCHEMA,
    }
    product = _run("Product Integrity Gate")
    local = _run("Community Local Security Closure")
    local["local_proof"] = {
        "local_evidence_digest": "f" * 64,
        "policy_digest": POLICY,
        "profile_status": {"macos_signed_distribution": "OPTIONAL_PROFILE_NOT_ENABLED"},
        "residual_risks": ["hostile_same_uid_isolation: NOT_CLAIMED"],
    }
    local["producer_proofs"] = [
        {
            "proof_type": "workspace_escape",
            "artifact_name": f"producer-{COMMIT}",
            "artifact_id": 12,
            "artifact_sha256": "1" * 64,
            "producer_evidence_digest": "2" * 64,
            "job_id": 13,
            "job": "community-local-producers",
            "workflow": "Security Closure Gate",
            "runner_os": "Linux",
            "policy_digest": POLICY,
        }
    ]
    return {
        "schema": "khaos.release-gate-evidence.v1",
        "profile": "community-local",
        "commit": COMMIT,
        "evidence_digest": "3" * 64,
        "main_ancestry": {
            "base": COMMIT,
            "head": "main",
            "behind_by": 0,
            "status": "identical",
        },
        "gates": {
            "security_closure": security,
            "product_integrity": product,
            "community_local": local,
        },
    }


def test_bundle_contains_required_audit_fields_without_capability() -> None:
    bundle = MODULE.build_bundle(_evidence())

    assert bundle["schema"] == "khaos.community-local-closure-bundle.v1"
    assert bundle["audit_only"] is True
    assert bundle["live_provenance_capability_issued"] is False
    assert bundle["machine_decision"]["status"] == "CLOSED"
    assert bundle["exact_sha"] == COMMIT
    assert bundle["policy_digest"] == POLICY
    assert bundle["schema_digest"] == SCHEMA
    assert bundle["proof_digests"]["workspace_escape"]["artifact_sha256"] == "1" * 64
    assert bundle["security_closure_run"]["run_id"] == 10
    assert bundle["product_integrity_run"]["run_id"] == 10
    assert bundle["closure_report"]["accepted_residuals"] == [
        "hostile_same_uid_isolation: NOT_CLAIMED"
    ]
    assert len(bundle["bundle_digest"]) == 64


def test_bundle_rejects_missing_producer_digests() -> None:
    evidence = _evidence()
    local = evidence["gates"]["community_local"]
    local["producer_proofs"] = []

    with pytest.raises(ValueError, match="producer proof digests"):
        MODULE.build_bundle(evidence)


def test_release_generator_publishes_bundle_as_an_audit_asset() -> None:
    generator = (ROOT / "scripts/generate_release_evidence.py").read_text(
        encoding="utf-8"
    )
    workflow = (ROOT / ".github/workflows/release-provenance.yml").read_text(
        encoding="utf-8"
    )

    assert "build_community_local_closure_bundle" in generator
    assert "community-local-closure-bundle-{args.commit}.json" in generator
    assert "gh release upload \"$RELEASE_TAG\" dist/*" in workflow
    assert "--clobber" not in workflow
