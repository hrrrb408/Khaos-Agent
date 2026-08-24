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
import io
import json
import re
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from khaos.security.evidence_provenance import gh_api_bytes
from khaos.security.local_closure import (
    ClosureEvidence,
    LocalEvidenceError,
    VerifiedGitHubProvenance,
    _VERIFIER_SEAL,
    issue_verified_github_provenance,
)
from khaos.security.security_evidence import (
    MAX_ARTIFACT_BYTES,
    parse_proof_archive,
)

REQUIRED_GATES = {
    "security_closure": "security-closure-gate.yml",
    "product_integrity": "product-integrity-gate.yml",
    "native_authority": "native-authority-production-e2e.yml",
}
COMMUNITY_LOCAL_GATES = {
    "security_closure": "security-closure-gate.yml",
    "product_integrity": "product-integrity-gate.yml",
    "community_local": "community-local-closure.yml",
}
COMMUNITY_LOCAL_ARTIFACT = "local-security-evidence-{}"
SECURITY_EVIDENCE_TESTS = frozenset(
    {
        "workspace_escape",
        "approval_replay",
        "schema_injection",
        "browser_direct_ip",
        "browser_dns_rebinding",
        "helper_confused_deputy",
        "process_tree_escape",
        "resource_ownership_closure",
    }
)
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

_NATIVE_ARTIFACT_CONTRACTS = {
    "native-authority-macos-proof": {
        "proof_type": "macos-native-authority",
        "runner_os": "macOS",
        "platform": "darwin",
        "job_name": "macOS launchd/XPC authority",
    },
    "native-authority-windows-proof": {
        "proof_type": "windows-native-authority",
        "runner_os": "Windows",
        "platform": "win32",
        "job_name": "Windows Service-SID Named Pipe authority",
    },
}

# Windows remains the cross-platform native proof required for a native gate.
# macOS launchd/XPC is an optional deployment capability: community releases
# may omit it when the repository has no Team ID/signing material.  If the
# optional artifact is present, it is still verified with the exact same
# provenance rules.
_REQUIRED_NATIVE_ARTIFACTS = frozenset({"native-authority-windows-proof"})


def _canonical_digest(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _run_gh_api(repo: str, endpoint: str) -> dict[str, Any]:
    try:
        raw = gh_api_bytes(repo, endpoint)
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"GitHub API returned malformed JSON for {endpoint}") from exc
    if not isinstance(value, dict):
        raise TypeError(f"GitHub API returned a non-object for {endpoint}")
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
        and run.get("event") == "push"
        and run.get("head_branch") == "main"
        and run.get("status") == "completed"
        and run.get("conclusion") == "success"
        # A rerun can be green after an earlier attempt failed.  Release
        # provenance must bind the original exact-commit gate attempt unless
        # an explicit, separately reviewed exception is added to policy.
        and int(run.get("run_attempt") or 0) == 1
    ]
    if not candidates:
        raise RuntimeError(
            f"no successful completed attempt-1 {workflow} run exists for exact commit {commit}"
        )
    return max(candidates, key=_run_sort_key)


def _artifact_records(repo: str, run_id: int) -> list[dict[str, Any]]:
    payload = _run_gh_api(repo, f"actions/runs/{run_id}/artifacts?per_page=100")
    if int(payload.get("total_count", 0) or 0) > 100:
        raise RuntimeError("workflow run has more artifacts than one page can prove")
    raw_artifacts = payload.get("artifacts")
    if not isinstance(raw_artifacts, list):
        raise TypeError("workflow run artifact payload is malformed")
    records: list[dict[str, Any]] = []
    for artifact in raw_artifacts:
        if not isinstance(artifact, dict):
            continue
        records.append(
            {
                "id": artifact.get("id"),
                "name": artifact.get("name"),
                "size_in_bytes": artifact.get("size_in_bytes"),
                "expired": artifact.get("expired"),
                "digest": artifact.get("digest") or "",
                "workflow_run": artifact.get("workflow_run"),
            }
        )
    return sorted(records, key=lambda item: str(item.get("name") or ""))


def _reject_duplicate_json_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise RuntimeError(f"security evidence contains duplicate JSON key {key}")
        value[key] = item
    return value


def _verify_security_artifact(
    payload: bytes,
    *,
    commit: str,
) -> dict[str, Any]:
    """Verify the exact Security Closure manifest and commit attestation."""
    if len(payload) > MAX_ARTIFACT_BYTES:
        raise RuntimeError("security evidence artifact exceeds the download limit")
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            names = [name for name in archive.namelist() if not name.endswith("/")]
            expected_names = {"commit-attestation.txt", "security-evidence.json"}
            if len(names) != len(expected_names) or set(names) != expected_names:
                raise RuntimeError(
                    "security evidence artifact must contain only the manifest and commit attestation"
                )
            if archive.getinfo("commit-attestation.txt").file_size != len(commit) + 1:
                raise RuntimeError("security evidence commit attestation size is not exact")
            with archive.open("commit-attestation.txt", "r") as stream:
                attestation = stream.read(128)
            with archive.open("security-evidence.json", "r") as stream:
                manifest_bytes = stream.read(MAX_ARTIFACT_BYTES + 1)
        if attestation != f"{commit}\n".encode("ascii"):
            raise RuntimeError("security evidence commit attestation is not exact")
        if len(manifest_bytes) > MAX_ARTIFACT_BYTES:
            raise RuntimeError("security evidence manifest exceeds the download limit")
        manifest = json.loads(
            manifest_bytes.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_json_pairs,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, zipfile.BadZipFile) as exc:
        raise RuntimeError(f"security evidence artifact is invalid: {exc}") from exc
    if not isinstance(manifest, dict):
        raise RuntimeError("security evidence manifest is not an object")
    required_fields = {
        "commit",
        "production_mode",
        "python_uid",
        "python_cap_eff",
        "host_fallback",
        "browser_helper_authenticated",
        "policy_digest",
        "schema_digest",
        "launcher_digest",
        "helper_digest",
        "run_id",
        "job",
        "tests",
    }
    if set(manifest) != required_fields:
        raise RuntimeError("security evidence manifest fields are not exact")
    if (
        manifest.get("commit") != commit
        or manifest.get("production_mode") is not True
        or type(manifest.get("python_uid")) is not int
        or manifest.get("python_uid") == 0
        or manifest.get("host_fallback") is not False
        or manifest.get("browser_helper_authenticated") is not True
    ):
        raise RuntimeError("security evidence manifest is not fail-closed")
    try:
        if int(str(manifest.get("python_cap_eff")), 16) != 0:
            raise RuntimeError("security evidence CapEff is not zero")
    except (TypeError, ValueError) as exc:
        raise RuntimeError("security evidence CapEff is malformed") from exc
    for field_name in (
        "policy_digest",
        "schema_digest",
        "launcher_digest",
        "helper_digest",
    ):
        value = manifest.get(field_name)
        if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
            raise RuntimeError(f"security evidence {field_name} is not a SHA-256 digest")
    if not manifest.get("run_id") or not manifest.get("job"):
        raise RuntimeError("security evidence producer identity is incomplete")
    tests = manifest.get("tests")
    if not isinstance(tests, dict) or set(tests) != SECURITY_EVIDENCE_TESTS:
        raise RuntimeError("security evidence test set is not exact")
    for name, record in tests.items():
        if not isinstance(record, dict):
            raise RuntimeError(f"security evidence test {name} is malformed")
        if set(record) != {
            "commit",
            "run_id",
            "job",
            "test",
            "result",
            "environment",
            "digest",
        }:
            raise RuntimeError(f"security evidence test {name} fields are not exact")
        digest = record.get("digest")
        unsigned = dict(record)
        unsigned.pop("digest", None)
        if (
            record.get("commit") != commit
            or record.get("test") != name
            or record.get("result") != "blocked"
            or not record.get("run_id")
            or not record.get("job")
            or not isinstance(record.get("environment"), dict)
            or record["environment"].get("production_mode") is not True
            or not isinstance(digest, str)
            or not _SHA256_RE.fullmatch(digest)
            or _canonical_digest(unsigned) != digest
        ):
            raise RuntimeError(f"security evidence test {name} provenance is invalid")
    return {
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "commit_attestation_verified": True,
        "policy_digest": manifest["policy_digest"],
        "tests": sorted(tests),
    }


def _runner_os_from_labels(labels: object) -> str:
    if not isinstance(labels, list):
        raise TypeError("native producer job has no runner labels")
    normalized = [str(label) for label in labels]
    if any(label.startswith("macos-") for label in normalized):
        return "macOS"
    if any(label.startswith("windows-") for label in normalized):
        return "Windows"
    raise RuntimeError("native producer job runner platform is not macOS or Windows")


def _verify_native_artifacts(
    repo: str,
    *,
    run_id: int,
    commit: str,
    artifacts: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Verify native artifact bytes and producer-owned semantic proof data."""
    selected = [
        artifact
        for artifact in artifacts
        if str(artifact.get("name") or "") in _NATIVE_ARTIFACT_CONTRACTS
    ]
    selected_names = {str(artifact.get("name") or "") for artifact in selected}
    missing_required = _REQUIRED_NATIVE_ARTIFACTS - selected_names
    if missing_required:
        raise RuntimeError(
            "native gate is missing required artifact(s): "
            + ", ".join(sorted(missing_required))
        )
    artifact_ids = [str(artifact.get("id") or "") for artifact in selected]
    if not all(artifact_ids) or len(set(artifact_ids)) != len(artifact_ids):
        raise RuntimeError("native gate artifact ids are not unique")

    jobs_payload = _run_gh_api(repo, f"actions/runs/{run_id}/jobs?per_page=100")
    jobs = jobs_payload.get("jobs")
    if (
        not isinstance(jobs, list)
        or len(jobs) > 100
        or int(jobs_payload.get("total_count", len(jobs)) or 0) > 100
    ):
        raise RuntimeError("native gate jobs are missing or exceed the verification page")
    successful_jobs = [
        job
        for job in jobs
        if isinstance(job, dict)
        and job.get("status") == "completed"
        and job.get("conclusion") == "success"
    ]
    proofs: list[dict[str, Any]] = []
    for artifact in selected:
        name = str(artifact["name"])
        contract = _NATIVE_ARTIFACT_CONTRACTS[name]
        workflow_run = artifact.get("workflow_run")
        if not isinstance(workflow_run, dict) or str(workflow_run.get("id")) != str(run_id):
            raise RuntimeError(f"native artifact {name} is not bound to run {run_id}")
        if artifact.get("expired") is not False:
            raise RuntimeError(f"native artifact {name} is expired or unverifiable")
        size = artifact.get("size_in_bytes")
        if size is not None and int(size) > MAX_ARTIFACT_BYTES:
            raise RuntimeError(f"native artifact {name} exceeds the download limit")
        matching_jobs = [
            job
            for job in successful_jobs
            if job.get("name") == contract["job_name"]
            and _runner_os_from_labels(job.get("labels")) == contract["runner_os"]
        ]
        if len(matching_jobs) != 1:
            raise RuntimeError(f"native producer job for {name} is not unique")
        job = matching_jobs[0]
        payload = gh_api_bytes(
            repo,
            f"actions/artifacts/{artifact['id']}/zip",
            timeout_seconds=60.0,
            max_output_bytes=MAX_ARTIFACT_BYTES,
        )
        if len(payload) > MAX_ARTIFACT_BYTES:
            raise RuntimeError(f"native artifact {name} exceeds the download limit")
        digest = hashlib.sha256(payload).hexdigest()
        api_digest = str(artifact.get("digest") or "").removeprefix("sha256:")
        if api_digest and api_digest != digest:
            raise RuntimeError(f"native artifact {name} digest does not match GitHub metadata")
        proof_manifest, proof_digest = parse_proof_archive(
            payload,
            expected_proof_type=contract["proof_type"],
            expected_commit=commit,
            expected_run_id=str(run_id),
            expected_workflow="Native Authority Production E2E",
            expected_runner_os=contract["runner_os"],
            expected_platform=contract["platform"],
            expected_policy_digest=None,
            expected_job_name=contract["job_name"],
        )
        if not proof_manifest.get("policy_digest"):
            raise RuntimeError(f"native artifact {name} has no policy digest")
        proofs.append(
            {
                "artifact_id": artifact["id"],
                "artifact_name": name,
                "artifact_sha256": digest,
                "proof_manifest_sha256": proof_digest,
                "job_id": job.get("id"),
                "runner_os": contract["runner_os"],
                "runner_arch": proof_manifest["runner_arch"],
                "policy_digest": proof_manifest["policy_digest"],
            }
        )
    policy_digests = {str(proof["policy_digest"]) for proof in proofs}
    if len(policy_digests) != 1:
        raise RuntimeError("native artifacts do not share one effective policy digest")
    return proofs


def _verify_local_artifact(
    repo: str,
    *,
    run_id: int,
    commit: str,
    artifacts: list[dict[str, Any]],
) -> dict[str, Any]:
    """Verify the producer-owned Community Local JSON artifact in its zip."""
    expected_name = COMMUNITY_LOCAL_ARTIFACT.format(commit)
    matching = [artifact for artifact in artifacts if artifact.get("name") == expected_name]
    if len(matching) != 1:
        raise RuntimeError(f"local closure run {run_id} is missing exact artifact {expected_name}")
    artifact = matching[0]
    if artifact.get("expired") is not False:
        raise RuntimeError(f"local closure artifact {expected_name} is expired or unverifiable")
    artifact_id = artifact.get("id")
    if artifact_id is None or not str(artifact_id):
        raise RuntimeError(f"local closure artifact {expected_name} has no id")
    payload = gh_api_bytes(
        repo,
        f"actions/artifacts/{artifact_id}/zip",
        timeout_seconds=60.0,
        max_output_bytes=MAX_ARTIFACT_BYTES,
    )
    if len(payload) > MAX_ARTIFACT_BYTES:
        raise RuntimeError(f"local closure artifact {expected_name} exceeds the download limit")
    digest = hashlib.sha256(payload).hexdigest()
    api_digest = str(artifact.get("digest") or "").removeprefix("sha256:")
    if not api_digest or api_digest != digest:
        raise RuntimeError(f"local closure artifact {expected_name} digest does not match GitHub metadata")
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            names = [name for name in archive.namelist() if not name.endswith("/")]
            if names != ["local-security-evidence.json"]:
                raise RuntimeError("local closure artifact contains unexpected files")
            with archive.open(names[0], "r") as stream:
                raw = stream.read(MAX_ARTIFACT_BYTES + 1)
        if len(raw) > MAX_ARTIFACT_BYTES:
            raise RuntimeError("local closure evidence JSON exceeds the download limit")
        value = json.loads(raw.decode("utf-8"))
        evidence = ClosureEvidence.from_payload(value)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, zipfile.BadZipFile, LocalEvidenceError) as exc:
        raise RuntimeError(f"local closure artifact evidence is invalid: {exc}") from exc
    if evidence.commit != commit or evidence.profile.value != "community-local":
        raise RuntimeError("local closure artifact profile or commit is not exact")
    if str(evidence.workflow.get("run_id")) != str(run_id):
        raise RuntimeError("local closure evidence is not bound to its producer run")
    return {
        "artifact_id": artifact_id,
        "artifact_name": expected_name,
        "artifact_sha256": digest,
        "local_evidence_digest": evidence.evidence_digest,
        "policy_digest": evidence.policy_digest,
        "proof_names": [proof.name for proof in evidence.proofs],
    }


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
    artifacts = _artifact_records(repo, run_id)
    security_proof: dict[str, Any] | None = None
    if workflow == REQUIRED_GATES["security_closure"]:
        expected_name = f"security-evidence-{commit}"
        matching = [
            artifact for artifact in artifacts
            if artifact.get("name") == expected_name
        ]
        if len(matching) != 1:
            raise RuntimeError(
                f"security gate run {run_id} is missing exact artifact {expected_name}"
            )
        artifact = matching[0]
        if artifact.get("expired") is not False:
            raise RuntimeError(
                f"security evidence artifact {expected_name} is expired or unverifiable"
            )
        if not isinstance(artifact.get("digest"), str) or not artifact["digest"].strip():
            raise RuntimeError(
                f"security evidence artifact {expected_name} has no digest"
            )
        payload = gh_api_bytes(
            repo,
            f"actions/artifacts/{artifact['id']}/zip",
            timeout_seconds=60.0,
            max_output_bytes=MAX_ARTIFACT_BYTES,
        )
        artifact_digest = hashlib.sha256(payload).hexdigest()
        advertised_digest = str(artifact["digest"]).removeprefix("sha256:")
        if artifact_digest != advertised_digest:
            raise RuntimeError(
                f"security evidence artifact {expected_name} digest does not match GitHub metadata"
            )
        security_proof = _verify_security_artifact(payload, commit=commit)
    local_proof: dict[str, Any] | None = None
    if workflow == COMMUNITY_LOCAL_GATES["community_local"]:
        local_proof = _verify_local_artifact(
            repo,
            run_id=run_id,
            commit=commit,
            artifacts=artifacts,
        )
    if workflow == REQUIRED_GATES["native_authority"]:
        expected_names = set(_REQUIRED_NATIVE_ARTIFACTS)
        for expected_name in sorted(expected_names):
            matching = [
                artifact for artifact in artifacts
                if artifact.get("name") == expected_name
            ]
            if len(matching) != 1:
                raise RuntimeError(
                    f"native authority run {run_id} is missing exact artifact {expected_name}"
                )
            artifact = matching[0]
            if artifact.get("expired") is not False:
                raise RuntimeError(
                    f"native authority artifact {expected_name} is expired or unverifiable"
                )
            if not isinstance(artifact.get("digest"), str) or not artifact["digest"].strip():
                raise RuntimeError(
                    f"native authority artifact {expected_name} has no digest"
                )
        # A macOS native proof is optional for the community profile.  Do not
        # silently accept malformed optional metadata: when present it must
        # satisfy the same expiry/digest contract as the required artifact.
        optional_macos = [
            artifact
            for artifact in artifacts
            if artifact.get("name") == "native-authority-macos-proof"
        ]
        if len(optional_macos) > 1:
            raise RuntimeError(
                "native authority exposes duplicate macOS native artifacts"
            )
        if optional_macos:
            artifact = optional_macos[0]
            if (
                artifact.get("expired") is not False
                or not isinstance(artifact.get("digest"), str)
                or not artifact["digest"].strip()
            ):
                raise RuntimeError(
                    "native authority macOS artifact is expired or has no digest"
                )
        native_proofs = _verify_native_artifacts(
            repo,
            run_id=run_id,
            commit=commit,
            artifacts=artifacts,
        )
    else:
        native_proofs = []
    record = {
        "workflow": workflow,
        "run_id": run_id,
        "run_attempt": int(run["run_attempt"]),
        "head_sha": run.get("head_sha"),
        "event": run.get("event"),
        "head_branch": run.get("head_branch"),
        "status": run.get("status"),
        "conclusion": run.get("conclusion"),
        "url": run.get("html_url"),
        "created_at": run.get("created_at"),
        "updated_at": run.get("updated_at"),
        "artifacts": artifacts,
        "security_proof": security_proof or {},
        "native_proofs": native_proofs,
    }
    record["run_evidence_digest"] = _canonical_digest(record)
    record["evidence_digest"] = record["run_evidence_digest"]
    if local_proof is not None:
        record["local_proof"] = local_proof
        record["run_evidence_digest"] = _canonical_digest(record)
        record["evidence_digest"] = record["run_evidence_digest"]
    return record


def _verify_main_ancestry(repo: str, commit: str) -> dict[str, Any]:
    """Prove the release commit is an ancestor of protected ``main``."""
    payload = _run_gh_api(repo, f"compare/{commit}...main")
    try:
        behind_by = int(payload.get("behind_by"))
        ahead_by = int(payload.get("ahead_by"))
    except (TypeError, ValueError) as exc:
        raise RuntimeError("GitHub main ancestry comparison is incomplete") from exc
    # The comparison uses the release commit as BASE and main as HEAD.  A
    # valid release commit has no commits that are present only on the base;
    # identical is the zero/zero special case.
    if behind_by != 0 or str(payload.get("status")) not in {"ahead", "identical"}:
        raise RuntimeError(
            f"release commit {commit} is not in protected main ancestry"
        )
    return {
        "base": commit,
        "head": "main",
        "status": payload.get("status"),
        "ahead_by": ahead_by,
        "behind_by": behind_by,
        "url": payload.get("html_url"),
    }


def verify_release_gates(
    repo: str,
    commit: str,
    *,
    profile: str = "legacy-native",
) -> dict[str, Any]:
    """Return profile-aware evidence for every required aggregate gate."""
    main_ancestry = _verify_main_ancestry(repo, commit)
    if profile == "community-local":
        required_gates = COMMUNITY_LOCAL_GATES
    elif profile in {"legacy-native", "macos-signed-distribution", "windows-native"}:
        required_gates = REQUIRED_GATES
    else:
        raise ValueError(f"unknown release evidence profile: {profile}")
    gates = {
        name: _gate_record(repo, workflow, commit)
        for name, workflow in required_gates.items()
    }
    if profile == "community-local":
        security_proof = gates["security_closure"].get("security_proof")
        local_proof = gates["community_local"].get("local_proof")
        if not isinstance(security_proof, dict) or not security_proof.get(
            "commit_attestation_verified"
        ):
            raise RuntimeError("security gate commit attestation was not verified")
        if not isinstance(local_proof, dict) or security_proof.get(
            "policy_digest"
        ) != local_proof.get("policy_digest"):
            raise RuntimeError(
                "security and Community Local evidence use different policy digests"
            )
    evidence = {
        "schema": "khaos.release-gate-evidence.v1",
        "profile": profile,
        "commit": commit,
        "verified_at": datetime.now(UTC).isoformat(timespec="seconds").replace(
            "+00:00", "Z"
        ),
        "main_ancestry": main_ancestry,
        "gates": gates,
        "github_provenance": {
            "status": "VERIFIED",
            "repository": repo,
            "commit": commit,
            "event": "push",
            "branch": "main",
            "run_attempt": 1,
            "workflows": {
                name: record["run_id"] for name, record in sorted(gates.items())
            },
        },
    }
    evidence["evidence_digest"] = _canonical_digest(evidence)
    return evidence


def verify_release_gates_for_closure(
    repo: str,
    commit: str,
    *,
    profile: str = "community-local",
) -> VerifiedGitHubProvenance:
    """Verify GitHub live and issue the non-serializable closure capability.

    The JSON returned by :func:`verify_release_gates` remains useful as an
    audit record, but it is deliberately not accepted by the closure
    evaluator.  Only this live API verification path can issue the typed
    capability consumed by that evaluator.
    """
    evidence = verify_release_gates(repo, commit, profile=profile)
    gates = evidence.get("gates")
    provenance = evidence.get("github_provenance")
    if not isinstance(gates, dict) or not isinstance(provenance, dict):
        raise RuntimeError("release verification did not produce typed provenance inputs")
    gate_digests: dict[str, str] = {}
    for name, record in gates.items():
        if not isinstance(name, str) or not isinstance(record, dict):
            raise RuntimeError("release verification gate record is malformed")
        digest = record.get("evidence_digest")
        if not isinstance(digest, str):
            raise RuntimeError(f"release verification gate {name} has no evidence digest")
        gate_digests[name] = digest
    local_record = gates.get("community_local")
    if not isinstance(local_record, dict) or not isinstance(
        local_record.get("local_proof"), dict
    ):
        raise RuntimeError("release verification has no Community Local evidence binding")
    local_evidence_digest = local_record["local_proof"].get("local_evidence_digest")
    if not isinstance(local_evidence_digest, str):
        raise RuntimeError("release verification has no local evidence digest")
    return issue_verified_github_provenance(
        live_verifier_receipt=_VERIFIER_SEAL,
        profile=profile,
        repository=str(provenance.get("repository") or ""),
        commit=str(provenance.get("commit") or ""),
        event=str(provenance.get("event") or ""),
        branch=str(provenance.get("branch") or ""),
        run_attempt=provenance.get("run_attempt"),
        main_ancestry=evidence["main_ancestry"],
        gate_evidence_digests=gate_digests,
        release_evidence_digest=str(evidence.get("evidence_digest") or ""),
        local_evidence_digest=local_evidence_digest,
    )


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--profile", default="legacy-native")
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    evidence = verify_release_gates(args.repo, args.commit, profile=args.profile)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
