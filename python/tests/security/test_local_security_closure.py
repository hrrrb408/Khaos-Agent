"""Adversarial tests for the profile-aware local closure contract."""

from __future__ import annotations

import copy

import pytest

from khaos.security.local_closure import (
    COMMUNITY_LOCAL_REQUIRED_PROOFS,
    COMMUNITY_LOCAL_REQUIRED_WORKFLOW_GATES,
    ClosureEvidence,
    LocalClosureStatus,
    LocalEvidenceError,
    _VERIFIER_SEAL,
    canonical_digest,
    evaluate_local_security_closure,
    issue_verified_github_provenance,
)


COMMIT = "a" * 40
POLICY = "b" * 64


def _workflow() -> dict[str, object]:
    return {
        "repository": "hrrrb408/Khaos-Agent",
        "workflow": "Community Local Security Closure",
        "run_id": "9001",
        "run_attempt": 1,
        "event": "push",
        "ref": "refs/heads/main",
        "head_sha": COMMIT,
        "runner_os": "ubuntu-24.04",
    }


def _payload() -> dict[str, object]:
    proofs = [
        {
            "name": name,
            "status": "PASS",
            "profile": "community-local",
            "commit": COMMIT,
            "policy_digest": POLICY,
            "artifact_digest": canonical_digest({"proof": name}),
            "provenance": dict(_workflow(), job=name),
        }
        for name in COMMUNITY_LOCAL_REQUIRED_PROOFS
    ]
    payload: dict[str, object] = {
        "schema": "khaos.local-security-evidence.v1",
        "profile": "community-local",
        "commit": COMMIT,
        "policy_digest": POLICY,
        "security_facts_digest": "c" * 64,
        "production_reachability_digest": "d" * 64,
        "production_composition_digest": "e" * 64,
        "workflow": _workflow(),
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
        "residual_risks": ["same-UID code injection is not claimed"],
    }
    payload["evidence_digest"] = canonical_digest(payload)
    return payload


def test_valid_producer_evidence_stays_not_closed_without_live_github_capability() -> None:
    evidence = ClosureEvidence.from_payload(_payload())

    decision = evaluate_local_security_closure(
        evidence,
        expected_commit=COMMIT,
    )

    assert decision.status is LocalClosureStatus.NOT_CLOSED
    assert "exact GitHub provenance is not verified" in decision.missing_requirements
    assert decision.provenance is None


def test_exact_sha_and_live_github_capability_are_required_for_closed() -> None:
    evidence = ClosureEvidence.from_payload(_payload())
    provenance = issue_verified_github_provenance(
        live_verifier_receipt=_VERIFIER_SEAL,
        profile="community-local",
        repository="hrrrb408/Khaos-Agent",
        commit=COMMIT,
        event="push",
        branch="main",
        run_attempt=1,
        main_ancestry={
            "base": COMMIT,
            "head": "main",
            "status": "ahead",
            "ahead_by": 1,
            "behind_by": 0,
        },
        gate_evidence_digests={
            name: "f" * 64 for name in COMMUNITY_LOCAL_REQUIRED_WORKFLOW_GATES
        },
        release_evidence_digest="e" * 64,
        local_evidence_digest=evidence.evidence_digest,
    )

    decision = evaluate_local_security_closure(
        evidence,
        expected_commit=COMMIT,
        provenance=provenance,
    )

    assert decision.status is LocalClosureStatus.CLOSED
    assert decision.missing_requirements == ()
    assert decision.evidence_digest == evidence.evidence_digest
    assert decision.provenance is provenance


def test_boolean_or_local_json_cannot_mint_closure_capability() -> None:
    evidence = ClosureEvidence.from_payload(_payload())

    decision = evaluate_local_security_closure(
        evidence,
        expected_commit=COMMIT,
        provenance=True,
    )

    assert decision.status is LocalClosureStatus.NOT_CLOSED
    assert decision.provenance is None
    assert "GitHub provenance capability does not match evidence" in decision.rejected_evidence


def test_local_evidence_digest_must_match_the_live_artifact_binding() -> None:
    original = ClosureEvidence.from_payload(_payload())
    provenance = issue_verified_github_provenance(
        live_verifier_receipt=_VERIFIER_SEAL,
        profile="community-local",
        repository="hrrrb408/Khaos-Agent",
        commit=COMMIT,
        event="push",
        branch="main",
        run_attempt=1,
        main_ancestry={
            "base": COMMIT,
            "head": "main",
            "status": "ahead",
            "ahead_by": 1,
            "behind_by": 0,
        },
        gate_evidence_digests={
            name: "f" * 64 for name in COMMUNITY_LOCAL_REQUIRED_WORKFLOW_GATES
        },
        release_evidence_digest="e" * 64,
        local_evidence_digest=original.evidence_digest,
    )
    tampered = _payload()
    tampered["residual_risks"] = ["tampered producer payload"]
    tampered["evidence_digest"] = canonical_digest(
        {key: value for key, value in tampered.items() if key != "evidence_digest"}
    )
    decision = evaluate_local_security_closure(
        ClosureEvidence.from_payload(tampered),
        expected_commit=COMMIT,
        provenance=provenance,
    )

    assert decision.status is LocalClosureStatus.NOT_CLOSED
    assert decision.provenance is None


def test_manual_closure_status_is_rejected_as_untrusted_input() -> None:
    payload = _payload()
    payload["closure"] = {"status": "CLOSED"}

    with pytest.raises(LocalEvidenceError, match="unknown field|derived closure"):
        ClosureEvidence.from_payload(payload)


def test_tampered_proof_commit_is_rejected_even_with_a_rehashed_bundle() -> None:
    payload = _payload()
    proofs = copy.deepcopy(payload["proofs"])
    assert isinstance(proofs, list)
    proofs[0]["commit"] = "f" * 40
    payload["proofs"] = proofs
    unsigned = dict(payload)
    unsigned.pop("evidence_digest")
    payload["evidence_digest"] = canonical_digest(unsigned)

    with pytest.raises(LocalEvidenceError, match="different commit"):
        ClosureEvidence.from_payload(payload)


def test_community_profile_does_not_claim_same_uid_isolation_or_independent_review() -> None:
    payload = _payload()
    statuses = dict(payload["profile_status"])
    statuses["hostile_same_uid_isolation"] = "PASS"
    payload["profile_status"] = statuses
    payload["evidence_digest"] = canonical_digest(
        {key: value for key, value in payload.items() if key != "evidence_digest"}
    )
    with pytest.raises(LocalEvidenceError, match="hostile_same_uid_isolation"):
        ClosureEvidence.from_payload(payload)
