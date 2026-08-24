"""Profile-aware Community Local security-closure evidence.

This module is the decision boundary for the Community Local profile.  It
consumes producer-owned, commit-bound evidence; it never accepts a caller
supplied ``closed`` flag or a pre-computed closure status.  The older
``ClosureStatus`` enum in :mod:`authority_transport` remains the transport
status vocabulary and is intentionally not widened into a release decision.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any, cast


class LocalSecurityProfile(str, Enum):
    """Deployment profiles evaluated by the local closure contract."""

    COMMUNITY_LOCAL = "community-local"
    MACOS_SIGNED_DISTRIBUTION = "macos-signed-distribution"
    WINDOWS_NATIVE = "windows-native"


class LocalClosureStatus(str, Enum):
    """Machine-facing statuses for a profile closure decision."""

    CLOSED = "CLOSED"
    NOT_CLOSED = "NOT_CLOSED"
    BLOCKED_EXTERNAL = "BLOCKED_EXTERNAL"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    NOT_RUN = "NOT_RUN"
    OPTIONAL_PROFILE_NOT_ENABLED = "OPTIONAL_PROFILE_NOT_ENABLED"
    NOT_CLAIMED = "NOT_CLAIMED"
    REJECTED = "REJECTED"
    UNKNOWN = "UNKNOWN"


class LocalEvidenceError(ValueError):
    """Raised when closure evidence is malformed or not producer-bound."""


LOCAL_EVIDENCE_SCHEMA = "khaos.local-security-evidence.v1"
REPOSITORY = "hrrrb408/Khaos-Agent"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")

# These names are the evidence contract, not a list of booleans.  A proof is
# accepted only when its producer records the exact commit, profile, policy,
# GitHub run and artifact digest.
COMMUNITY_LOCAL_REQUIRED_PROOFS: tuple[str, ...] = (
    "community_authority",
    "platform_kernel",
    "production_reachability",
    "production_composition",
    "workspace_escape",
    "approval_replay",
    "approval_substitution",
    "process_tree_escape",
    "resource_owner_closure",
    "network_isolation",
)
COMMUNITY_LOCAL_REQUIRED_GATES: tuple[str, ...] = (
    "security_closure",
    "product_integrity",
)
COMMUNITY_LOCAL_REQUIRED_WORKFLOW_GATES: tuple[str, ...] = (
    *COMMUNITY_LOCAL_REQUIRED_GATES,
    "community_local",
)

PROFILE_REQUIRED_PROOFS: Mapping[LocalSecurityProfile, tuple[str, ...]] = {
    LocalSecurityProfile.COMMUNITY_LOCAL: COMMUNITY_LOCAL_REQUIRED_PROOFS,
    LocalSecurityProfile.MACOS_SIGNED_DISTRIBUTION: (
        "security_closure_gate",
        "product_integrity_gate",
        "macos_signed_authority",
        "notarization",
    ),
    LocalSecurityProfile.WINDOWS_NATIVE: (
        "security_closure_gate",
        "product_integrity_gate",
        "windows_native_authority",
    ),
}

_PROFILE_ALIASES = {
    "community": LocalSecurityProfile.COMMUNITY_LOCAL,
    "community-local": LocalSecurityProfile.COMMUNITY_LOCAL,
    "native-production": LocalSecurityProfile.MACOS_SIGNED_DISTRIBUTION,
    "macos-signed-distribution": LocalSecurityProfile.MACOS_SIGNED_DISTRIBUTION,
    "windows-native": LocalSecurityProfile.WINDOWS_NATIVE,
}

_EVIDENCE_KEYS = frozenset(
    {
        "schema",
        "profile",
        "commit",
        "policy_digest",
        "security_facts_digest",
        "production_reachability_digest",
        "production_composition_digest",
        "workflow",
        "proofs",
        "profile_status",
        "residual_risks",
        "evidence_digest",
    }
)
_WORKFLOW_KEYS = frozenset(
    {
        "repository",
        "workflow",
        "run_id",
        "run_attempt",
        "event",
        "ref",
        "head_sha",
        "runner_os",
        "job",
    }
)
_PROOF_KEYS = frozenset(
    {
        "name",
        "status",
        "profile",
        "commit",
        "policy_digest",
        "artifact_digest",
        "provenance",
    }
)
_PROFILE_STATUS_VALUES = {status.value for status in LocalClosureStatus}
_VERIFIER_SEAL = object()


def canonical_digest(value: object) -> str:
    """Hash canonical JSON without accepting NaN or non-JSON values."""
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise LocalEvidenceError("evidence is not canonical JSON") from exc
    return hashlib.sha256(encoded).hexdigest()


def normalize_profile(profile: LocalSecurityProfile | str) -> LocalSecurityProfile:
    """Resolve the public profile spelling and fail closed on unknown values."""
    if isinstance(profile, LocalSecurityProfile):
        return profile
    try:
        return _PROFILE_ALIASES[str(profile)]
    except KeyError as exc:
        raise LocalEvidenceError(f"unknown security profile: {profile!r}") from exc


def _require_keys(value: Mapping[str, Any], allowed: frozenset[str], label: str) -> None:
    unknown = set(value) - allowed
    if unknown:
        raise LocalEvidenceError(
            f"{label} contains unknown field(s): {', '.join(sorted(map(str, unknown)))}"
        )


def _require_digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not DIGEST_RE.fullmatch(value):
        raise LocalEvidenceError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _require_commit(value: object, label: str = "commit") -> str:
    if not isinstance(value, str) or not SHA_RE.fullmatch(value):
        raise LocalEvidenceError(f"{label} must be a full lowercase commit SHA")
    return value


def _require_nonempty_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise LocalEvidenceError(f"{label} must be a non-empty string")
    return value


def _parse_workflow(
    value: object, *, commit: str, require_job: bool = False
) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise LocalEvidenceError("workflow provenance must be an object")
    mapping = cast(Mapping[str, Any], value)
    _require_keys(mapping, _WORKFLOW_KEYS, "workflow provenance")
    if mapping.get("repository") != REPOSITORY:
        raise LocalEvidenceError("workflow provenance repository is not Khaos")
    if mapping.get("event") != "push" or mapping.get("ref") != "refs/heads/main":
        raise LocalEvidenceError("closure evidence must come from a main push")
    if mapping.get("head_sha") != commit:
        raise LocalEvidenceError("workflow provenance head SHA does not match evidence")
    if type(mapping.get("run_attempt")) is not int or mapping["run_attempt"] != 1:
        raise LocalEvidenceError("closure evidence requires the original run attempt")
    for field in ("workflow", "run_id", "runner_os"):
        _require_nonempty_string(mapping.get(field), f"workflow.{field}")
    if require_job:
        _require_nonempty_string(mapping.get("job"), "workflow.job")
    return dict(mapping)


def _parse_proof(
    value: object,
    *,
    profile: LocalSecurityProfile,
    commit: str,
    policy_digest: str,
) -> "LocalProof":
    if not isinstance(value, Mapping):
        raise LocalEvidenceError("each closure proof must be an object")
    mapping = cast(Mapping[str, Any], value)
    _require_keys(mapping, _PROOF_KEYS, "closure proof")
    name = _require_nonempty_string(mapping.get("name"), "proof.name")
    if mapping.get("status") != "PASS":
        raise LocalEvidenceError(f"proof {name!r} is not a producer PASS")
    if mapping.get("profile") != profile.value:
        raise LocalEvidenceError(f"proof {name!r} has a different profile")
    if mapping.get("commit") != commit:
        raise LocalEvidenceError(f"proof {name!r} has a different commit")
    if mapping.get("policy_digest") != policy_digest:
        raise LocalEvidenceError(f"proof {name!r} has a different policy digest")
    artifact_digest = _require_digest(
        mapping.get("artifact_digest"), f"proof {name}.artifact_digest"
    )
    provenance = _parse_workflow(
        mapping.get("provenance"), commit=commit, require_job=True
    )
    return LocalProof(
        name=name,
        status="PASS",
        profile=profile,
        commit=commit,
        policy_digest=policy_digest,
        artifact_digest=artifact_digest,
        provenance=provenance,
    )


@dataclass(frozen=True, slots=True)
class LocalProof:
    """One producer-owned proof attached to a closure evidence bundle."""

    name: str
    status: str
    profile: LocalSecurityProfile
    commit: str
    policy_digest: str
    artifact_digest: str
    provenance: Mapping[str, object]


@dataclass(frozen=True, slots=True)
class VerifiedGitHubProvenance:
    """Non-serializable capability issued only after live GitHub verification.

    A JSON document, a mock artifact, or a caller-supplied boolean cannot
    construct this capability.  The release verifier issues it only after it
    has checked the protected-main ancestry, exact push runs, gate artifacts,
    and their producer digests through the GitHub API.
    """

    profile: LocalSecurityProfile
    repository: str
    commit: str
    event: str
    branch: str
    run_attempt: int
    main_ancestry_digest: str
    gate_evidence_digests: Mapping[str, str]
    release_evidence_digest: str
    _issuer: object = field(repr=False, compare=False)
    local_evidence_digest: str = ""

    def __post_init__(self) -> None:
        if self._issuer is not _VERIFIER_SEAL:
            raise LocalEvidenceError(
                "GitHub provenance must be issued by the live release verifier"
            )
        _require_commit(self.commit, "GitHub provenance commit")
        if self.repository != REPOSITORY:
            raise LocalEvidenceError("GitHub provenance repository is not Khaos")
        if self.event != "push" or self.branch != "main":
            raise LocalEvidenceError("GitHub provenance is not a main push")
        if type(self.run_attempt) is not int or self.run_attempt != 1:
            raise LocalEvidenceError("GitHub provenance is not the original attempt")
        _require_digest(self.main_ancestry_digest, "main ancestry digest")
        _require_digest(self.release_evidence_digest, "release evidence digest")
        if self.profile is LocalSecurityProfile.COMMUNITY_LOCAL:
            _require_digest(self.local_evidence_digest, "local evidence digest")
        required = set(
            COMMUNITY_LOCAL_REQUIRED_WORKFLOW_GATES
            if self.profile is LocalSecurityProfile.COMMUNITY_LOCAL
            else PROFILE_REQUIRED_PROOFS[self.profile]
        )
        if set(self.gate_evidence_digests) != required:
            raise LocalEvidenceError("GitHub provenance gate set is not exact")
        for name, digest in self.gate_evidence_digests.items():
            if not name:
                raise LocalEvidenceError("GitHub provenance gate name is invalid")
            _require_digest(digest, f"GitHub provenance gate {name}")
        object.__setattr__(
            self,
            "gate_evidence_digests",
            MappingProxyType(dict(self.gate_evidence_digests)),
        )

    def matches(self, evidence: "ClosureEvidence") -> bool:
        """Return whether this live capability binds the supplied evidence."""
        return (
            self.profile is evidence.profile
            and self.commit == evidence.commit
            and evidence.workflow.get("repository") == REPOSITORY
            and evidence.workflow.get("event") == "push"
            and evidence.workflow.get("ref") == "refs/heads/main"
            and evidence.workflow.get("head_sha") == self.commit
            and evidence.workflow.get("run_attempt") == 1
            and (
                self.profile is not LocalSecurityProfile.COMMUNITY_LOCAL
                or self.local_evidence_digest == evidence.evidence_digest
            )
        )


def issue_verified_github_provenance(
    *,
    live_verifier_receipt: object,
    profile: LocalSecurityProfile | str,
    repository: str,
    commit: str,
    event: str,
    branch: str,
    run_attempt: int,
    main_ancestry: Mapping[str, object],
    gate_evidence_digests: Mapping[str, str],
    release_evidence_digest: str,
    local_evidence_digest: str = "",
) -> VerifiedGitHubProvenance:
    """Issue a typed capability to the live GitHub release verifier only."""
    if live_verifier_receipt is not _VERIFIER_SEAL:
        raise LocalEvidenceError(
            "GitHub provenance requires a receipt from the live release verifier"
        )
    resolved_profile = normalize_profile(profile)
    exact_commit = _require_commit(commit, "GitHub provenance commit")
    if (
        repository != REPOSITORY
        or event != "push"
        or branch != "main"
        or type(run_attempt) is not int
        or run_attempt != 1
    ):
        raise LocalEvidenceError("GitHub provenance identity is not exact")
    if not (
        main_ancestry.get("base") == exact_commit
        and main_ancestry.get("head") == "main"
        and main_ancestry.get("behind_by") == 0
        and main_ancestry.get("status") in {"ahead", "identical"}
    ):
        raise LocalEvidenceError("protected main ancestry is not exact")
    return VerifiedGitHubProvenance(
        profile=resolved_profile,
        repository=repository,
        commit=exact_commit,
        event=event,
        branch=branch,
        run_attempt=run_attempt,
        main_ancestry_digest=canonical_digest(dict(main_ancestry)),
        gate_evidence_digests=dict(gate_evidence_digests),
        release_evidence_digest=_require_digest(
            release_evidence_digest, "release evidence digest"
        ),
        local_evidence_digest=local_evidence_digest,
        _issuer=_VERIFIER_SEAL,
    )


@dataclass(frozen=True, slots=True)
class ClosureEvidence:
    """Validated, immutable input to the local closure evaluator."""

    profile: LocalSecurityProfile
    commit: str
    policy_digest: str
    security_facts_digest: str
    production_reachability_digest: str
    production_composition_digest: str
    workflow: Mapping[str, object]
    proofs: tuple[LocalProof, ...]
    profile_status: Mapping[str, str]
    residual_risks: tuple[str, ...]
    evidence_digest: str

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "ClosureEvidence":
        """Parse evidence and reject derived/manual closure state."""
        _require_keys(payload, _EVIDENCE_KEYS, "closure evidence")
        if payload.get("schema") != LOCAL_EVIDENCE_SCHEMA:
            raise LocalEvidenceError("unsupported local security evidence schema")
        if "closure" in payload or "status" in payload:
            raise LocalEvidenceError(
                "derived closure status is not accepted as evidence"
            )
        profile = normalize_profile(payload.get("profile", ""))
        commit = _require_commit(payload.get("commit"))
        policy_digest = _require_digest(payload.get("policy_digest"), "policy_digest")
        security_facts_digest = _require_digest(
            payload.get("security_facts_digest"), "security_facts_digest"
        )
        reachability_digest = _require_digest(
            payload.get("production_reachability_digest"),
            "production_reachability_digest",
        )
        composition_digest = _require_digest(
            payload.get("production_composition_digest"),
            "production_composition_digest",
        )
        workflow = _parse_workflow(payload.get("workflow"), commit=commit)
        raw_proofs = payload.get("proofs")
        if not isinstance(raw_proofs, Sequence) or isinstance(raw_proofs, (str, bytes)):
            raise LocalEvidenceError("proofs must be a JSON array")
        proof_values = cast(Sequence[Any], raw_proofs)
        proofs = tuple(
            _parse_proof(
                item,
                profile=profile,
                commit=commit,
                policy_digest=policy_digest,
            )
            for item in proof_values
        )
        if len({proof.name for proof in proofs}) != len(proofs):
            raise LocalEvidenceError("closure proof names must be unique")
        raw_status = payload.get("profile_status")
        if not isinstance(raw_status, Mapping):
            raise LocalEvidenceError("profile_status must be an object")
        status_values = cast(Mapping[object, object], raw_status)
        profile_status: dict[str, str] = {}
        for key, value in status_values.items():
            if not isinstance(key, str) or not isinstance(value, str):
                raise LocalEvidenceError("profile_status must map strings to strings")
            if value not in _PROFILE_STATUS_VALUES:
                raise LocalEvidenceError(
                    f"unknown profile status for {key!r}: {value!r}"
                )
            profile_status[key] = value
        raw_risks = payload.get("residual_risks", [])
        if not isinstance(raw_risks, Sequence) or isinstance(raw_risks, (str, bytes)):
            raise LocalEvidenceError("residual_risks must be a JSON array")
        risk_values = cast(Sequence[Any], raw_risks)
        residual_risks = tuple(
            _require_nonempty_string(item, "residual_risk") for item in risk_values
        )
        supplied_digest = payload.get("evidence_digest")
        if not isinstance(supplied_digest, str) or not DIGEST_RE.fullmatch(supplied_digest):
            raise LocalEvidenceError("evidence_digest must be a lowercase SHA-256 digest")
        unsigned = dict(payload)
        unsigned.pop("evidence_digest", None)
        if canonical_digest(unsigned) != supplied_digest:
            raise LocalEvidenceError("local security evidence digest mismatch")
        return cls(
            profile=profile,
            commit=commit,
            policy_digest=policy_digest,
            security_facts_digest=security_facts_digest,
            production_reachability_digest=reachability_digest,
            production_composition_digest=composition_digest,
            workflow=workflow,
            proofs=proofs,
            profile_status=profile_status,
            residual_risks=residual_risks,
            evidence_digest=supplied_digest,
        )


@dataclass(frozen=True, slots=True)
class ClosureDecision:
    """The only result that may be rendered as a closure report."""

    profile: LocalSecurityProfile
    commit: str
    status: LocalClosureStatus
    satisfied_requirements: tuple[str, ...]
    missing_requirements: tuple[str, ...]
    rejected_evidence: tuple[str, ...]
    residual_risks: tuple[str, ...]
    evidence_digest: str = ""
    provenance: VerifiedGitHubProvenance | None = None


def evaluate_local_security_closure(
    evidence: ClosureEvidence,
    *,
    expected_commit: str | None = None,
    provenance: VerifiedGitHubProvenance | None = None,
) -> ClosureDecision:
    """Evaluate one already-validated evidence bundle fail closed.

    ``provenance`` is a non-serializable capability issued by the live
    GitHub release verifier.  A local artifact can therefore describe
    successful tests without being able to produce ``CLOSED``.
    """
    requirements = PROFILE_REQUIRED_PROOFS[evidence.profile]
    proof_names = {proof.name for proof in evidence.proofs}
    missing = tuple(sorted(set(requirements) - proof_names))
    satisfied = tuple(sorted(set(requirements) & proof_names))
    rejected: list[str] = []
    if expected_commit is not None:
        try:
            expected = _require_commit(expected_commit, "expected_commit")
        except LocalEvidenceError as exc:
            rejected.append(str(exc))
        else:
            if evidence.commit != expected:
                rejected.append("evidence commit does not match the evaluated commit")
    if evidence.profile is LocalSecurityProfile.COMMUNITY_LOCAL:
        required_status = {
            "apple_developer_program": LocalClosureStatus.NOT_APPLICABLE.value,
            "apple_team_id": LocalClosureStatus.NOT_APPLICABLE.value,
            "signed_xpc": LocalClosureStatus.NOT_APPLICABLE.value,
            "notarization": LocalClosureStatus.NOT_APPLICABLE.value,
            "macos_signed_distribution": LocalClosureStatus.OPTIONAL_PROFILE_NOT_ENABLED.value,
            "hostile_same_uid_isolation": "NOT_CLAIMED",
            "independent_review": "NOT_CLAIMED",
        }
        for key, expected in required_status.items():
            if evidence.profile_status.get(key) != expected:
                rejected.append(f"profile_status.{key} must be {expected}")
    provenance_matches = isinstance(provenance, VerifiedGitHubProvenance) and provenance.matches(
        evidence
    )
    if provenance is not None and not provenance_matches:
        rejected.append("GitHub provenance capability does not match evidence")
    if missing or rejected or not provenance_matches:
        blockers = list(missing)
        if not provenance_matches:
            blockers.append("exact GitHub provenance is not verified")
        return ClosureDecision(
            profile=evidence.profile,
            commit=evidence.commit,
            status=LocalClosureStatus.NOT_CLOSED,
            satisfied_requirements=satisfied,
            missing_requirements=tuple(blockers),
            rejected_evidence=tuple(rejected),
            residual_risks=evidence.residual_risks,
            evidence_digest=evidence.evidence_digest,
            provenance=provenance if provenance_matches else None,
        )
    return ClosureDecision(
        profile=evidence.profile,
        commit=evidence.commit,
        status=LocalClosureStatus.CLOSED,
        satisfied_requirements=satisfied,
        missing_requirements=(),
        rejected_evidence=(),
        residual_risks=evidence.residual_risks,
        evidence_digest=evidence.evidence_digest,
        provenance=provenance,
    )


__all__ = [
    "ClosureDecision",
    "ClosureEvidence",
    "COMMUNITY_LOCAL_REQUIRED_PROOFS",
    "COMMUNITY_LOCAL_REQUIRED_GATES",
    "COMMUNITY_LOCAL_REQUIRED_WORKFLOW_GATES",
    "LOCAL_EVIDENCE_SCHEMA",
    "LocalClosureStatus",
    "LocalEvidenceError",
    "LocalProof",
    "LocalSecurityProfile",
    "PROFILE_REQUIRED_PROOFS",
    "REPOSITORY",
    "VerifiedGitHubProvenance",
    "canonical_digest",
    "evaluate_local_security_closure",
    "issue_verified_github_provenance",
    "normalize_profile",
]
