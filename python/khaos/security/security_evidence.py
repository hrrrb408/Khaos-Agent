"""Security evidence manifest schema and provenance verification.

M6.9 BATCH 5: a closure report may not be built from arbitrary local
files and CLI booleans.  Every security claim must be backed by an
evidence manifest describing a CI artifact that is cryptographically
bound to the exact release commit, the expected workflow, a successful
run conclusion, the correct runner platform, and the release policy
digest.  Verification fails closed on every mismatch, duplicate, or
missing required proof type.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

EXPECTED_REPOSITORY = "hrrrb408/Khaos-Agent"

# The workflow each proof type must come from.  A proof of the wrong type
# coming from an unrelated green workflow is not closure evidence.
EXPECTED_WORKFLOW_BY_PROOF_TYPE = {
    "linux-real-kernel": "Platform Sandbox Security",
    "macos-native-authority": "Native Authority Production E2E",
    "windows-native-authority": "Native Authority Production E2E",
    "security-closure-gate": "Security Closure Gate",
    "product-integrity-gate": "Product Integrity Gate",
    "resource-owner-proof": "Security Closure Gate",
    "exact-effect-proof": "Security Closure Gate",
}

REQUIRED_PROOF_TYPES = frozenset(EXPECTED_WORKFLOW_BY_PROOF_TYPE)

# The runner OS each native proof type must have been produced on: a
# macOS proof must not be silently satisfied by a Windows artifact or
# vice versa.
EXPECTED_RUNNER_OS = {
    "linux-real-kernel": "Linux",
    "macos-native-authority": "macOS",
    "windows-native-authority": "Windows",
    "security-closure-gate": "Linux",
    "product-integrity-gate": "Linux",
    "resource-owner-proof": "Linux",
    "exact-effect-proof": "Linux",
}

_MANIFEST_FIELDS = frozenset(
    {
        "schema_version",
        "repository",
        "commit_sha",
        "workflow_name",
        "workflow_run_id",
        "job_id",
        "runner_os",
        "runner_arch",
        "artifact_id",
        "artifact_name",
        "artifact_sha256",
        "proof_type",
        "proof_schema_version",
        "policy_digest",
        "generated_at",
        "producer_identity",
        "run_conclusion",
    }
)

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_HEX40 = re.compile(r"^[0-9a-f]{40}$")


class SecurityEvidenceError(ValueError):
    """An evidence manifest is malformed or fails provenance verification."""


@dataclass(frozen=True, slots=True)
class SecurityEvidenceManifest:
    """One CI-produced security proof artifact with full provenance."""

    schema_version: int
    repository: str
    commit_sha: str
    workflow_name: str
    workflow_run_id: str
    job_id: str
    runner_os: str
    runner_arch: str
    artifact_id: str
    artifact_name: str
    artifact_sha256: str
    proof_type: str
    proof_schema_version: int
    policy_digest: str
    generated_at: str
    producer_identity: str
    run_conclusion: str

    @classmethod
    def from_payload(cls, value: object) -> SecurityEvidenceManifest:
        if not isinstance(value, dict):
            raise SecurityEvidenceError("evidence manifest is not an object")
        if set(value) != _MANIFEST_FIELDS:
            missing = sorted(_MANIFEST_FIELDS - set(value))
            extra = sorted(set(value) - _MANIFEST_FIELDS)
            raise SecurityEvidenceError(
                f"evidence manifest fields mismatch (missing={missing}, extra={extra})"
            )
        try:
            manifest = cls(
                schema_version=int(value["schema_version"]),
                repository=str(value["repository"]),
                commit_sha=str(value["commit_sha"]),
                workflow_name=str(value["workflow_name"]),
                workflow_run_id=str(value["workflow_run_id"]),
                job_id=str(value["job_id"]),
                runner_os=str(value["runner_os"]),
                runner_arch=str(value["runner_arch"]),
                artifact_id=str(value["artifact_id"]),
                artifact_name=str(value["artifact_name"]),
                artifact_sha256=str(value["artifact_sha256"]),
                proof_type=str(value["proof_type"]),
                proof_schema_version=int(value["proof_schema_version"]),
                policy_digest=str(value["policy_digest"]),
                generated_at=str(value["generated_at"]),
                producer_identity=str(value["producer_identity"]),
                run_conclusion=str(value["run_conclusion"]),
            )
        except (TypeError, ValueError) as exc:
            raise SecurityEvidenceError("evidence manifest values are malformed") from exc
        if manifest.schema_version != 1 or manifest.proof_schema_version != 1:
            raise SecurityEvidenceError("evidence manifest schema version is unsupported")
        if not _HEX40.fullmatch(manifest.commit_sha):
            raise SecurityEvidenceError("evidence manifest commit SHA is malformed")
        if not _HEX64.fullmatch(manifest.artifact_sha256):
            raise SecurityEvidenceError("evidence manifest artifact digest is malformed")
        if not _HEX64.fullmatch(manifest.policy_digest):
            raise SecurityEvidenceError("evidence manifest policy digest is malformed")
        for name in (
            "workflow_run_id",
            "job_id",
            "artifact_id",
            "artifact_name",
            "generated_at",
            "producer_identity",
        ):
            if not getattr(manifest, name):
                raise SecurityEvidenceError(f"evidence manifest {name} is empty")
        return manifest

    def to_payload(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "repository": self.repository,
            "commit_sha": self.commit_sha,
            "workflow_name": self.workflow_name,
            "workflow_run_id": self.workflow_run_id,
            "job_id": self.job_id,
            "runner_os": self.runner_os,
            "runner_arch": self.runner_arch,
            "artifact_id": self.artifact_id,
            "artifact_name": self.artifact_name,
            "artifact_sha256": self.artifact_sha256,
            "proof_type": self.proof_type,
            "proof_schema_version": self.proof_schema_version,
            "policy_digest": self.policy_digest,
            "generated_at": self.generated_at,
            "producer_identity": self.producer_identity,
            "run_conclusion": self.run_conclusion,
        }


@dataclass(frozen=True, slots=True)
class EvidenceVerification:
    """Fail-closed verification result for one manifest set."""

    ok: bool
    errors: tuple[str, ...] = field(default_factory=tuple)
    proof_types: frozenset[str] = frozenset()

    @property
    def status(self) -> str:
        return "VERIFIED" if self.ok else "REJECTED"


def verify_evidence_manifests(
    manifests: list[SecurityEvidenceManifest],
    *,
    expected_commit: str,
    expected_policy_digest: str,
    expected_repository: str = EXPECTED_REPOSITORY,
    require_all_types: bool = True,
) -> EvidenceVerification:
    """Verify a set of evidence manifests against the release contract.

    Every check fails closed:
    - repository must be the expected repository;
    - commit_sha must be the exact release SHA;
    - run conclusion must be ``success`` (not cancelled/failure/skipped);
    - the workflow must be the one this proof type is produced by;
    - the runner OS must match the proof platform (macOS proof from a
      macOS runner, Windows proof from a Windows runner);
    - the policy digest must match the release policy digest;
    - no duplicate proof types (two macOS proofs cannot impersonate
      macOS + Windows);
    - when ``require_all_types`` is set, every required proof type must
      be present exactly once.
    """
    errors: list[str] = []
    seen_types: dict[str, str] = {}
    for manifest in manifests:
        label = f"{manifest.proof_type}:{manifest.artifact_id}"
        if manifest.repository != expected_repository:
            errors.append(f"{label}: repository is {manifest.repository!r}")
        if manifest.commit_sha != expected_commit:
            errors.append(f"{label}: commit does not match the release SHA")
        if manifest.run_conclusion != "success":
            errors.append(
                f"{label}: workflow run conclusion is {manifest.run_conclusion!r}"
            )
        expected_workflow = EXPECTED_WORKFLOW_BY_PROOF_TYPE.get(manifest.proof_type)
        if expected_workflow is None:
            errors.append(f"{label}: unknown proof type {manifest.proof_type!r}")
        elif manifest.workflow_name != expected_workflow:
            errors.append(
                f"{label}: proof must come from workflow {expected_workflow!r}, "
                f"got {manifest.workflow_name!r}"
            )
        expected_os = EXPECTED_RUNNER_OS.get(manifest.proof_type)
        if expected_os is not None and manifest.runner_os != expected_os:
            errors.append(
                f"{label}: proof platform requires runner OS {expected_os!r}, "
                f"got {manifest.runner_os!r}"
            )
        if manifest.policy_digest != expected_policy_digest:
            errors.append(f"{label}: policy digest does not match the release policy")
        if manifest.proof_type in seen_types:
            errors.append(
                f"{label}: duplicate proof type (already provided by artifact "
                f"{seen_types[manifest.proof_type]})"
            )
        else:
            seen_types[manifest.proof_type] = manifest.artifact_id
    if require_all_types:
        missing = sorted(REQUIRED_PROOF_TYPES - set(seen_types))
        if missing:
            errors.append(f"missing required evidence types: {', '.join(missing)}")
    return EvidenceVerification(
        ok=not errors,
        errors=tuple(errors),
        proof_types=frozenset(seen_types),
    )


def verify_artifact_digest(manifest: SecurityEvidenceManifest, path: Path) -> None:
    """Re-verify that a local artifact still matches its manifest digest."""
    if not path.is_file():
        raise SecurityEvidenceError(
            f"evidence artifact is missing on disk: {path}"
        )
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    if digest.hexdigest() != manifest.artifact_sha256:
        raise SecurityEvidenceError(
            f"evidence artifact digest does not match the manifest: {path}"
        )


def load_manifest_file(path: Path) -> SecurityEvidenceManifest:
    """Load one manifest JSON file, failing closed on malformed content."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SecurityEvidenceError(f"evidence manifest is unreadable: {path}") from exc
    return SecurityEvidenceManifest.from_payload(payload)


def build_verified_manifest(
    manifests: list[SecurityEvidenceManifest],
    *,
    verification: EvidenceVerification,
) -> dict[str, object]:
    """Serialize a verified manifest bundle for the closure builder.

    The bundle carries a digest over the verified manifest payloads so a
    consumer can detect post-verification tampering.
    """
    if not verification.ok:
        raise SecurityEvidenceError(
            "cannot bundle unverified evidence: " + "; ".join(verification.errors)
        )
    payloads = [manifest.to_payload() for manifest in manifests]
    bundle = {
        "schema_version": 1,
        "status": "VERIFIED",
        "manifests": payloads,
        "errors": [],
    }
    bundle["bundle_digest"] = hashlib.sha256(
        json.dumps(payloads, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return bundle


def load_verified_bundle(path: Path) -> dict[str, object]:
    """Load a verified manifest bundle and re-check its integrity."""
    try:
        bundle = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SecurityEvidenceError(f"verified bundle is unreadable: {path}") from exc
    if not isinstance(bundle, dict) or bundle.get("status") != "VERIFIED":
        raise SecurityEvidenceError("evidence bundle is not a verified bundle")
    payloads = bundle.get("manifests")
    if not isinstance(payloads, list) or not payloads:
        raise SecurityEvidenceError("verified bundle contains no manifests")
    expected_digest = bundle.get("bundle_digest")
    actual_digest = hashlib.sha256(
        json.dumps(payloads, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    if expected_digest != actual_digest:
        raise SecurityEvidenceError("verified bundle digest mismatch (tampered)")
    if bundle.get("errors") != []:
        raise SecurityEvidenceError("verified bundle carries verification errors")
    # Every embedded manifest must still be individually well-formed.
    for payload in payloads:
        SecurityEvidenceManifest.from_payload(payload)
    return bundle


__all__ = [
    "EXPECTED_REPOSITORY",
    "EXPECTED_WORKFLOW_BY_PROOF_TYPE",
    "REQUIRED_PROOF_TYPES",
    "EvidenceVerification",
    "SecurityEvidenceError",
    "SecurityEvidenceManifest",
    "build_verified_manifest",
    "load_manifest_file",
    "load_verified_bundle",
    "verify_artifact_digest",
    "verify_evidence_manifests",
]
