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
import io
import json
import re
import stat
import zipfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path

EXPECTED_REPOSITORY = "hrrrb408/Khaos-Agent"

# Artifact bytes are downloaded from an external API and are therefore
# bounded before ZIP parsing.  These limits are deliberately independent of
# the GitHub API's advertised artifact size: closure verification must remain
# safe even when a hostile or corrupted archive is supplied by a test double
# or a proxy.
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 128
MAX_ARCHIVE_FILE_BYTES = 8 * 1024 * 1024
MAX_ARCHIVE_TOTAL_UNCOMPRESSED_BYTES = 32 * 1024 * 1024

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
        "proof_manifest_sha256",
        "producer_job_name",
    }
)

_PROOF_MANIFEST_FIELDS = frozenset(
    {
        "schema_version",
        "proof_type",
        "github_sha",
        "github_run_id",
        "workflow_name",
        "job_name",
        "runner_os",
        "runner_arch",
        "platform",
        "policy_digest",
        "files",
    }
)

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_GENERIC_PROOF_OUTCOME_FIELDS = frozenset(
    {"ok", "outcome", "result", "status", "success", "tests", "checks"}
)
_NATIVE_IDENTITY_FIELDS = frozenset(
    {"peer_verified", "transport_verified", "protected_key_verified"}
)


class SecurityEvidenceError(ValueError):
    """An evidence manifest is malformed or fails provenance verification."""


def _json_object_without_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise SecurityEvidenceError(f"duplicate JSON key in proof manifest: {key}")
        value[key] = item
    return value


def _safe_archive_name(name: str) -> str:
    """Normalize one ZIP member name without permitting path traversal."""
    if not name or "\x00" in name or "\\" in name:
        raise SecurityEvidenceError("proof archive contains an unsafe member name")
    if name.startswith("/") or any(part in {"", ".", ".."} for part in name.split("/")):
        raise SecurityEvidenceError(f"proof archive contains an unsafe member path: {name!r}")
    return name


def _validate_bound_proof_record(
    record: object,
    *,
    name: str,
    expected_proof_type: str,
    expected_bindings: Mapping[str, object],
    expected_policy_digest: object,
) -> None:
    """Validate the producer result schema, not only its provenance labels."""
    if not isinstance(record, dict):
        raise SecurityEvidenceError(f"proof JSON is not an object: {name}")
    required = {
        "github_sha",
        "github_run_id",
        "proof_type",
        "policy_digest",
        "runner_os",
        "platform",
    }
    if not required.issubset(record):
        raise SecurityEvidenceError(
            f"proof file {name} is not semantically bound to the producer run"
        )
    for key, expected in expected_bindings.items():
        if key in record and str(record.get(key, "")) != str(expected):
            raise SecurityEvidenceError(
                f"proof file {name} has a mismatched {key} binding"
            )
    if record.get("policy_digest") != expected_policy_digest:
        raise SecurityEvidenceError(f"proof file {name} has a mismatched policy digest")

    if expected_proof_type in {
        "macos-native-authority",
        "windows-native-authority",
    }:
        if _NATIVE_IDENTITY_FIELDS.issubset(record):
            if not all(record[field] is True for field in _NATIVE_IDENTITY_FIELDS):
                raise SecurityEvidenceError(
                    f"proof file {name} contains a failed native identity postcondition"
                )
            return
        scenarios = record.get("scenarios")
        if not isinstance(scenarios, list) or not scenarios:
            raise SecurityEvidenceError(
                f"proof file {name} has no native result schema"
            )
        if not any(
            isinstance(item, dict) and item.get("outcome") == "SUCCESS"
            for item in scenarios
        ):
            raise SecurityEvidenceError(
                f"proof file {name} has no successful native transaction"
            )
        if not all(
            isinstance(item, dict)
            and (item.get("outcome") == "SUCCESS" or item.get("rejected") is True)
            for item in scenarios
        ):
            raise SecurityEvidenceError(
                f"proof file {name} contains an invalid native scenario result"
            )
        return

    if not any(field in record for field in _GENERIC_PROOF_OUTCOME_FIELDS):
        raise SecurityEvidenceError(f"proof file {name} has no result schema")


def parse_proof_archive(
    payload: bytes,
    *,
    expected_proof_type: str,
    expected_commit: str,
    expected_run_id: str,
    expected_workflow: str,
    expected_runner_os: str,
    expected_platform: str,
    expected_policy_digest: str | None = None,
    expected_job_name: str | None = None,
) -> tuple[dict[str, object], str]:
    """Verify the bounded semantic manifest inside one CI artifact.

    The archive may contain multiple proof JSON files.  ``proof-manifest.json``
    is the single producer-owned index: it binds the exact file set, each
    file digest, the GitHub run/workflow/job, the runner, the platform, and
    the effective policy.  The returned digest is over the proof-manifest
    bytes as stored in the artifact, so a live recheck can bind that
    declaration to the manifest that was fetched locally.
    """
    if not isinstance(payload, bytes):
        raise SecurityEvidenceError("proof artifact payload must be bytes")
    if len(payload) > MAX_ARTIFACT_BYTES:
        raise SecurityEvidenceError("proof artifact exceeds the download limit")
    try:
        archive = zipfile.ZipFile(io.BytesIO(payload))
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        raise SecurityEvidenceError("proof artifact is not a valid ZIP archive") from exc
    with archive:
        infos = archive.infolist()
        if not infos or len(infos) > MAX_ARCHIVE_ENTRIES:
            raise SecurityEvidenceError("proof archive entry count is outside the limit")
        members: dict[str, bytes] = {}
        total_uncompressed = 0
        for info in infos:
            name = _safe_archive_name(info.filename)
            if info.is_dir() or stat.S_ISLNK((info.external_attr >> 16) & 0xFFFF):
                raise SecurityEvidenceError("proof archive contains a directory or symlink")
            if info.flag_bits & 0x1:
                raise SecurityEvidenceError("encrypted proof archives are unsupported")
            if name in members:
                raise SecurityEvidenceError(f"proof archive contains duplicate member: {name}")
            if info.file_size < 0 or info.file_size > MAX_ARCHIVE_FILE_BYTES:
                raise SecurityEvidenceError(f"proof archive member exceeds the file limit: {name}")
            total_uncompressed += info.file_size
            if total_uncompressed > MAX_ARCHIVE_TOTAL_UNCOMPRESSED_BYTES:
                raise SecurityEvidenceError("proof archive exceeds the uncompressed limit")
            try:
                with archive.open(info, "r") as handle:
                    data = handle.read(MAX_ARCHIVE_FILE_BYTES + 1)
            except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
                raise SecurityEvidenceError(f"proof archive member cannot be read: {name}") from exc
            if len(data) != info.file_size or len(data) > MAX_ARCHIVE_FILE_BYTES:
                raise SecurityEvidenceError(f"proof archive member size is inconsistent: {name}")
            members[name] = data

        manifest_names = [
            name for name in members if name.rsplit("/", 1)[-1] == "proof-manifest.json"
        ]
        if len(manifest_names) != 1:
            raise SecurityEvidenceError("proof archive must contain exactly one proof-manifest.json")
        manifest_name = manifest_names[0]
        manifest_bytes = members[manifest_name]
        try:
            proof_manifest = json.loads(
                manifest_bytes.decode("utf-8-sig"),
                object_pairs_hook=_json_object_without_duplicate_keys,
            )
        except (UnicodeDecodeError, json.JSONDecodeError, SecurityEvidenceError) as exc:
            raise SecurityEvidenceError("proof-manifest.json is malformed") from exc
        if not isinstance(proof_manifest, dict):
            raise SecurityEvidenceError("proof-manifest.json is not an object")
        if set(proof_manifest) != _PROOF_MANIFEST_FIELDS:
            missing = sorted(_PROOF_MANIFEST_FIELDS - set(proof_manifest))
            extra = sorted(set(proof_manifest) - _PROOF_MANIFEST_FIELDS)
            raise SecurityEvidenceError(
                f"proof-manifest fields mismatch (missing={missing}, extra={extra})"
            )
        if proof_manifest.get("schema_version") != 1:
            raise SecurityEvidenceError("proof-manifest schema version is unsupported")
        expected_bindings = {
            "proof_type": expected_proof_type,
            "github_sha": expected_commit,
            "github_run_id": str(expected_run_id),
            "workflow_name": expected_workflow,
            "runner_os": expected_runner_os,
            "platform": expected_platform,
        }
        for key, expected in expected_bindings.items():
            if str(proof_manifest.get(key, "")) != str(expected):
                raise SecurityEvidenceError(
                    f"proof-manifest {key} does not match the expected binding"
                )
        if expected_policy_digest is not None and proof_manifest.get("policy_digest") != expected_policy_digest:
            raise SecurityEvidenceError("proof-manifest policy digest does not match")
        if expected_job_name is not None and proof_manifest.get("job_name") != expected_job_name:
            raise SecurityEvidenceError("proof-manifest job name does not match")
        for key in ("job_name", "runner_arch", "policy_digest"):
            value = proof_manifest.get(key)
            if not isinstance(value, str) or not value:
                raise SecurityEvidenceError(f"proof-manifest {key} is empty")
        files = proof_manifest.get("files")
        if not isinstance(files, dict) or not files:
            raise SecurityEvidenceError("proof-manifest files is empty or malformed")
        expected_files = set(members) - {manifest_name}
        if set(files) != expected_files:
            raise SecurityEvidenceError("proof-manifest file set does not match the archive")
        bound_records = 0
        for name in sorted(expected_files):
            digest = files.get(name)
            if not isinstance(digest, str) or not _HEX64.fullmatch(digest):
                raise SecurityEvidenceError(f"proof-manifest digest is malformed for {name}")
            if hashlib.sha256(members[name]).hexdigest() != digest:
                raise SecurityEvidenceError(f"proof file digest does not match for {name}")
            if name.lower().endswith(".json"):
                try:
                    record = json.loads(
                        members[name].decode("utf-8-sig"),
                        object_pairs_hook=_json_object_without_duplicate_keys,
                    )
                except (UnicodeDecodeError, json.JSONDecodeError, SecurityEvidenceError) as exc:
                    raise SecurityEvidenceError(f"proof JSON is malformed: {name}") from exc
                _validate_bound_proof_record(
                    record,
                    name=name,
                    expected_proof_type=expected_proof_type,
                    expected_bindings=expected_bindings,
                    expected_policy_digest=proof_manifest["policy_digest"],
                )
                bound_records += 1
        if bound_records == 0:
            raise SecurityEvidenceError("proof archive has no semantically bound proof JSON")
    return proof_manifest, hashlib.sha256(manifest_bytes).hexdigest()


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
    # These fields are populated by the bounded archive contract.  Empty
    # values remain readable for legacy local manifests, but the live
    # GitHub recheck rejects them because a raw artifact digest alone cannot
    # prove which job or proof files produced the artifact.
    proof_manifest_sha256: str = ""
    producer_job_name: str = ""

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
                proof_manifest_sha256=str(value["proof_manifest_sha256"]),
                producer_job_name=str(value["producer_job_name"]),
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
        if manifest.proof_manifest_sha256 and not _HEX64.fullmatch(
            manifest.proof_manifest_sha256
        ):
            raise SecurityEvidenceError(
                "evidence manifest proof-manifest digest is malformed"
            )
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
            "proof_manifest_sha256": self.proof_manifest_sha256,
            "producer_job_name": self.producer_job_name,
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

    These are all *local* consistency checks: they cannot tell a genuinely
    CI-produced manifest from a locally synthesized one whose strings look
    right.  Callers that decide closure must additionally pass the manifests
    through :func:`verify_manifests_against_github`.
    """
    errors: list[str] = []
    seen_types: dict[str, str] = {}
    seen_artifacts: set[str] = set()
    for manifest in manifests:
        label = f"{manifest.proof_type}:{manifest.artifact_id}"
        if manifest.artifact_id in seen_artifacts:
            errors.append(f"{label}: duplicate artifact id")
        else:
            seen_artifacts.add(manifest.artifact_id)
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


def verify_manifests_against_github(
    manifests: list[SecurityEvidenceManifest],
    *,
    fetch_json: Callable[[str], object],
    fetch_artifact: Callable[[str], bytes],
    expected_repository: str = EXPECTED_REPOSITORY,
) -> EvidenceVerification:
    """Re-resolve every manifest against the live GitHub Actions API.

    A locally VERIFIED bundle is attacker-controlled input until each
    manifest is re-queried at the trust root: the workflow run must exist
    with the claimed head SHA, workflow name, and ``success`` conclusion;
    the claimed job must exist in that run with a ``success`` conclusion;
    and the claimed artifact must exist and its downloaded bytes must hash
    to the manifest's ``artifact_sha256``.  A well-formed manifest naming a
    nonexistent run/job/artifact — the forgery that pure local verification
    accepts — fails closed here.

    ``fetch_json(path)`` must return parsed JSON for a GitHub API path
    (raising on any HTTP error); ``fetch_artifact(artifact_id)`` must
    return the raw artifact bytes (raising on any error).  Both are
    injected so tests can supply deterministic doubles.
    """
    errors: list[str] = []
    seen_types: dict[str, str] = {}
    seen_artifacts: set[str] = set()
    for manifest in manifests:
        label = f"{manifest.proof_type}:{manifest.artifact_id}"
        if manifest.artifact_id in seen_artifacts:
            errors.append(f"{label}: duplicate artifact id")
        else:
            seen_artifacts.add(manifest.artifact_id)
        if manifest.proof_type in seen_types:
            errors.append(
                f"{label}: duplicate proof type (already provided by artifact "
                f"{seen_types[manifest.proof_type]})"
            )
        else:
            seen_types[manifest.proof_type] = manifest.artifact_id
        expected_workflow = EXPECTED_WORKFLOW_BY_PROOF_TYPE.get(manifest.proof_type)
        expected_runner_os = EXPECTED_RUNNER_OS.get(manifest.proof_type)
        if manifest.repository != expected_repository:
            errors.append(f"{label}: repository is {manifest.repository!r}")
        if expected_workflow is None:
            errors.append(f"{label}: unknown proof type {manifest.proof_type!r}")
        elif manifest.workflow_name != expected_workflow:
            errors.append(
                f"{label}: proof must come from workflow {expected_workflow!r}, "
                f"got {manifest.workflow_name!r}"
            )
        if expected_runner_os is not None and manifest.runner_os != expected_runner_os:
            errors.append(
                f"{label}: proof platform requires runner OS {expected_runner_os!r}, "
                f"got {manifest.runner_os!r}"
            )
        if manifest.commit_sha != manifest.commit_sha.lower():
            errors.append(f"{label}: manifest commit SHA is not canonical lowercase")
        if manifest.run_conclusion != "success":
            errors.append(f"{label}: manifest run conclusion is not success")
        try:
            run = _require_mapping(
                fetch_json(f"repos/{expected_repository}/actions/runs/{manifest.workflow_run_id}"),
                label,
            )
            if run.get("head_sha") != manifest.commit_sha:
                errors.append(f"{label}: GitHub run head SHA does not match the manifest commit")
            if run.get("name") != manifest.workflow_name:
                errors.append(
                    f"{label}: GitHub run workflow is {run.get('name')!r}, "
                    f"manifest claims {manifest.workflow_name!r}"
                )
            if run.get("conclusion") != "success":
                errors.append(
                    f"{label}: GitHub run conclusion is {run.get('conclusion')!r}"
                )
            if run.get("status") != "completed":
                errors.append(
                    f"{label}: GitHub run status is {run.get('status')!r}, not completed"
                )
            if run.get("event") != "push":
                errors.append(
                    f"{label}: GitHub run event is {run.get('event')!r}, not push"
                )
            if run.get("head_branch") != "main":
                errors.append(
                    f"{label}: GitHub run head branch is {run.get('head_branch')!r}, not main"
                )
            try:
                run_attempt = int(run.get("run_attempt") or 0)
            except (TypeError, ValueError):
                run_attempt = 0
            if run_attempt != 1:
                errors.append(
                    f"{label}: GitHub run attempt is {run.get('run_attempt')!r}, not 1"
                )
        except Exception as exc:  # noqa: BLE001 - any lookup failure fails closed
            errors.append(f"{label}: GitHub run lookup failed ({exc})")
            continue
        try:
            jobs_payload = _require_mapping(
                fetch_json(
                    f"repos/{expected_repository}/actions/runs/{manifest.workflow_run_id}/jobs?per_page=100"
                ),
                label,
            )
            jobs = jobs_payload.get("jobs")
            if not isinstance(jobs, list):
                raise TypeError("jobs payload is malformed")
            if jobs_payload.get("total_count", len(jobs)) > 100:
                raise ValueError("run has more jobs than one page can prove")
            job_matches = [
                entry for entry in jobs
                if isinstance(entry, dict)
                and str(entry.get("id")) == str(manifest.job_id)
            ]
            if len(job_matches) != 1:
                errors.append(f"{label}: claimed job {manifest.job_id} does not exist in the GitHub run")
            else:
                job = job_matches[0]
                if job.get("status") != "completed":
                    errors.append(
                        f"{label}: GitHub job status is {job.get('status')!r}, not completed"
                    )
                if job.get("conclusion") != "success":
                    errors.append(
                        f"{label}: GitHub job conclusion is {job.get('conclusion')!r}"
                    )
                if not manifest.producer_job_name:
                    errors.append(f"{label}: manifest has no producer job name")
                elif job.get("name") != manifest.producer_job_name:
                    errors.append(
                        f"{label}: GitHub job name is {job.get('name')!r}, "
                        f"manifest claims {manifest.producer_job_name!r}"
                    )
                labels = job.get("labels")
                if not isinstance(labels, list):
                    errors.append(f"{label}: GitHub job runner labels are missing")
                else:
                    try:
                        runner_os = _runner_os_from_labels(labels)
                    except SecurityEvidenceError as exc:
                        errors.append(f"{label}: {exc}")
                    else:
                        if expected_runner_os and runner_os != expected_runner_os:
                            errors.append(
                                f"{label}: GitHub job runner OS is {runner_os!r}, "
                                f"expected {expected_runner_os!r}"
                            )
        except Exception as exc:  # noqa: BLE001 - any lookup failure fails closed
            errors.append(f"{label}: GitHub job lookup failed ({exc})")
        try:
            artifacts_payload = _require_mapping(
                fetch_json(
                    f"repos/{expected_repository}/actions/runs/{manifest.workflow_run_id}/artifacts?per_page=100"
                ),
                label,
            )
            artifacts = artifacts_payload.get("artifacts")
            if not isinstance(artifacts, list):
                raise TypeError("artifacts payload is malformed")
            if artifacts_payload.get("total_count", len(artifacts)) > 100:
                raise ValueError("run has more artifacts than one page can prove")
            artifact_matches = [
                entry for entry in artifacts
                if isinstance(entry, dict)
                and str(entry.get("id")) == str(manifest.artifact_id)
            ]
            if len(artifact_matches) != 1:
                raise ValueError(
                    f"artifact {manifest.artifact_id} does not exist uniquely in the GitHub run"
                )
            artifact = artifact_matches[0]
            if artifact.get("name") != manifest.artifact_name:
                raise ValueError("artifact name does not match the manifest")
            workflow_run = artifact.get("workflow_run")
            if not isinstance(workflow_run, dict) or str(workflow_run.get("id")) != str(manifest.workflow_run_id):
                raise ValueError("artifact workflow run does not match the manifest")
            if artifact.get("expired") is not False:
                raise ValueError("artifact has expired or is unverifiable")
            advertised_size = artifact.get("size_in_bytes")
            if advertised_size is not None and int(advertised_size) > MAX_ARTIFACT_BYTES:
                raise ValueError("artifact exceeds the download limit")
            api_digest = artifact.get("digest")
            if api_digest:
                normalized_api_digest = str(api_digest).removeprefix("sha256:")
                if normalized_api_digest != manifest.artifact_sha256:
                    raise ValueError("GitHub artifact digest does not match the manifest")
            payload = fetch_artifact(str(manifest.artifact_id))
            if not isinstance(payload, bytes):
                raise TypeError("downloaded artifact is not bytes")
            if len(payload) > MAX_ARTIFACT_BYTES:
                raise ValueError("downloaded artifact exceeds the download limit")
            digest = hashlib.sha256(payload).hexdigest()
            if digest != manifest.artifact_sha256:
                raise ValueError("downloaded artifact digest does not match the manifest")
            if not manifest.proof_manifest_sha256:
                raise ValueError("manifest has no proof-manifest digest")
            expected_platform = {
                "macos-native-authority": "darwin",
                "windows-native-authority": "win32",
                "linux-real-kernel": "linux",
                "security-closure-gate": "linux",
                "product-integrity-gate": "linux",
                "resource-owner-proof": "linux",
                "exact-effect-proof": "linux",
            }.get(manifest.proof_type)
            if expected_platform is None:
                raise ValueError("proof type has no platform contract")
            proof_manifest, proof_digest = parse_proof_archive(
                payload,
                expected_proof_type=manifest.proof_type,
                expected_commit=manifest.commit_sha,
                expected_run_id=manifest.workflow_run_id,
                expected_workflow=manifest.workflow_name,
                expected_runner_os=manifest.runner_os,
                expected_platform=expected_platform,
                expected_policy_digest=manifest.policy_digest,
                expected_job_name=manifest.producer_job_name,
            )
            if proof_digest != manifest.proof_manifest_sha256:
                raise ValueError("proof-manifest digest does not match the manifest")
            if proof_manifest.get("runner_arch") != manifest.runner_arch:
                raise ValueError("proof-manifest runner architecture does not match the manifest")
        except Exception as exc:  # noqa: BLE001 - any lookup failure fails closed
            errors.append(f"{label}: GitHub artifact verification failed ({exc})")
    return EvidenceVerification(
        ok=not errors,
        errors=tuple(errors),
        proof_types=frozenset(seen_types),
    )


def _require_mapping(value: object, label: str) -> dict:
    if not isinstance(value, dict):
        raise TypeError(f"{label}: API response is not an object")
    return value


def _runner_os_from_labels(labels: list[object]) -> str:
    normalized = [str(label) for label in labels]
    if any(label.startswith("macos-") for label in normalized):
        return "macOS"
    if any(label.startswith("windows-") for label in normalized):
        return "Windows"
    if any(label.startswith("ubuntu-") for label in normalized):
        return "Linux"
    raise SecurityEvidenceError("GitHub job has no recognized runner label")


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
    "MAX_ARCHIVE_ENTRIES",
    "MAX_ARCHIVE_FILE_BYTES",
    "MAX_ARCHIVE_TOTAL_UNCOMPRESSED_BYTES",
    "MAX_ARTIFACT_BYTES",
    "REQUIRED_PROOF_TYPES",
    "EvidenceVerification",
    "SecurityEvidenceError",
    "SecurityEvidenceManifest",
    "build_verified_manifest",
    "load_manifest_file",
    "load_verified_bundle",
    "parse_proof_archive",
    "verify_artifact_digest",
    "verify_evidence_manifests",
]
