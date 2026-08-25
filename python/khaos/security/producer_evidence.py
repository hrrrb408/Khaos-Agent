"""Producer-owned evidence contracts for the Community Local profile.

The producer is the component that owns the resource or execution
environment.  This module only provides the bounded, typed serialization
shared by those producers and by the later evidence aggregator; it never
accepts a caller supplied PASS/production flag.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from khaos.security.effective_policy import load_effective_policy
from khaos.security.local_closure import (
    LocalEvidenceError,
    REPOSITORY,
    canonical_digest,
)

PRODUCER_EVIDENCE_SCHEMA = "khaos.local-security-producer-proof.v1"
PRODUCER_DIAGNOSTICS_SCHEMA = "khaos.local-security-producer-diagnostics.v1"
PRODUCTION_COMPOSITION_PROOF = "production_composition"
PROCESS_TREE_PROOF = "process_tree_escape"
RESOURCE_OWNER_PROOF = "resource_owner_closure"


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    """Hash one producer-owned regular file without following a symlink."""
    if not path.is_file() or path.is_symlink():
        raise LocalEvidenceError(f"producer file is not a regular non-symlink: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _require_sha(value: object, label: str) -> str:
    if not isinstance(value, str) or len(value) != 64:
        raise LocalEvidenceError(f"{label} must be a SHA-256 digest")
    try:
        int(value, 16)
    except ValueError as exc:
        raise LocalEvidenceError(f"{label} must be hexadecimal") from exc
    return value


def producer_identity(*, commit: str, require_main_push: bool = False) -> dict[str, object]:
    """Read and validate the immutable GitHub producer identity.

    The commit argument is checked against ``GITHUB_SHA`` and the checked-out
    repository.  ``require_main_push`` is used by the final exact-main
    producer path; PR runs may still emit diagnostics for the ordinary gate.
    """
    actual_commit = os.environ.get("GITHUB_SHA", "")
    if actual_commit != commit:
        raise LocalEvidenceError("producer commit does not match GITHUB_SHA")
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    event = os.environ.get("GITHUB_EVENT_NAME", "")
    ref = os.environ.get("GITHUB_REF", "")
    if repository != REPOSITORY:
        raise LocalEvidenceError("producer repository is not Khaos")
    if require_main_push and (event != "push" or ref != "refs/heads/main"):
        raise LocalEvidenceError("producer requires an exact main push")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    if not run_id.isdigit() or int(run_id) <= 0:
        raise LocalEvidenceError("producer GITHUB_RUN_ID is missing")
    attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "")
    if attempt != "1":
        raise LocalEvidenceError("producer evidence requires attempt 1")
    for field in ("GITHUB_WORKFLOW", "RUNNER_OS", "GITHUB_JOB"):
        if not os.environ.get(field, "").strip():
            raise LocalEvidenceError(f"producer {field} is missing")
    return {
        "repository": repository,
        "workflow": os.environ.get("GITHUB_WORKFLOW", ""),
        "run_id": run_id,
        "run_attempt": 1,
        "event": event,
        "ref": ref,
        "head_sha": commit,
        "runner_os": os.environ.get("RUNNER_OS", ""),
        "job": os.environ.get("GITHUB_JOB", ""),
    }


def _junit_counts(path: Path) -> dict[str, object]:
    if not path.is_file() or path.is_symlink():
        raise LocalEvidenceError(f"JUnit diagnostics file is unavailable: {path}")
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError) as exc:
        raise LocalEvidenceError(f"JUnit diagnostics are malformed: {path}") from exc
    suites = [root] if root.tag == "testsuite" else list(root.findall("testsuite"))
    if not suites:
        raise LocalEvidenceError("JUnit diagnostics contain no test suite")
    totals: dict[str, int] = {
        key: 0 for key in ("tests", "skipped", "failed", "errors")
    }
    skipped_reasons: list[str] = []
    failure_details: list[str] = []
    error_details: list[str] = []
    for suite in suites:
        for source, target in (
            ("tests", "tests"),
            ("skipped", "skipped"),
            ("failures", "failed"),
            ("errors", "errors"),
        ):
            try:
                totals[target] += int(
                    suite.attrib.get(source, "0")
                )
            except ValueError as exc:
                raise LocalEvidenceError("JUnit diagnostics contain non-integer counts") from exc
        for node in suite.iter():
            if node.tag == "skipped":
                reason = node.attrib.get("message") or node.attrib.get("type") or "unspecified"
                skipped_reasons.append(" ".join(reason.split())[:256])
            elif node.tag == "failure":
                detail = node.attrib.get("message") or (node.text or "failure")
                failure_details.append(" ".join(detail.split())[:256])
            elif node.tag == "error":
                detail = node.attrib.get("message") or (node.text or "error")
                error_details.append(" ".join(detail.split())[:256])
    result: dict[str, object] = dict(totals)
    result["passed"] = max(
        0,
        totals["tests"]
        - totals["skipped"]
        - totals["failed"]
        - totals["errors"],
    )
    result["skipped_reasons"] = skipped_reasons[:64]
    result["failure_details"] = failure_details[:64]
    result["error_details"] = error_details[:64]
    return result


def _digest_optional_file(path: Path | None) -> str:
    if path is None:
        return _sha256_bytes(b"")
    return sha256_file(path)


def diagnostics_from_junit(
    *,
    proof_name: str,
    junit: Path,
    returncode: int,
    stdout: Path | None = None,
    stderr: Path | None = None,
) -> dict[str, object]:
    """Build diagnostic counts from the producer's actual test result."""
    counts = _junit_counts(junit)
    payload: dict[str, object] = {
        "schema": PRODUCER_DIAGNOSTICS_SCHEMA,
        "proof_name": proof_name,
        "returncode": int(returncode),
        "test_count": counts["tests"],
        "passed": counts["passed"],
        "skipped": counts["skipped"],
        "failed": counts["failed"],
        "errors": counts["errors"],
        "skipped_reasons": counts["skipped_reasons"],
        "failure_details": counts["failure_details"],
        "error_details": counts["error_details"],
        "junit_digest": sha256_file(junit),
        "stdout_digest": _digest_optional_file(stdout),
        "stderr_digest": _digest_optional_file(stderr),
    }
    return payload


def _diagnostics_pass(diagnostics: dict[str, object]) -> bool:
    returncode = diagnostics.get("returncode")
    test_count = diagnostics.get("test_count")
    return (
        type(returncode) is int
        and returncode == 0
        and type(test_count) is int
        and test_count > 0
        and diagnostics.get("passed") == test_count
        and diagnostics.get("skipped") == 0
        and diagnostics.get("failed") == 0
        and diagnostics.get("errors") == 0
    )


def build_test_producer_proof(
    *,
    proof_name: str,
    commit: str,
    repo_root: Path,
    junit: Path,
    returncode: int,
    stdout: Path | None = None,
    stderr: Path | None = None,
) -> dict[str, object]:
    """Create a proof whose result is derived only from its JUnit output."""
    identity = producer_identity(commit=commit)
    policy = load_effective_policy(repo_root)
    diagnostics = diagnostics_from_junit(
        proof_name=proof_name,
        junit=junit,
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
    )
    unsigned: dict[str, object] = {
        "schema": PRODUCER_EVIDENCE_SCHEMA,
        "proof_type": proof_name,
        "commit": commit,
        "policy_digest": policy.digest,
        "profile": "community-local",
        "workflow": identity,
        "production_claim": False,
        "production_mode": False,
        "diagnostics": diagnostics,
        "result": "PASS" if _diagnostics_pass(diagnostics) else "FAIL",
    }
    unsigned["evidence_digest"] = canonical_digest(unsigned)
    return unsigned


def build_runtime_producer_proof(
    *,
    proof_type: str,
    commit: str,
    policy_digest: str,
    workflow: dict[str, object],
    diagnostics: dict[str, object],
    production_identity: dict[str, object],
) -> dict[str, object]:
    """Create a producer proof after a real production runtime oracle passed."""
    if proof_type not in {
        PRODUCTION_COMPOSITION_PROOF,
        PROCESS_TREE_PROOF,
        RESOURCE_OWNER_PROOF,
    }:
        raise LocalEvidenceError(f"unsupported production proof type: {proof_type}")
    _verify_live_production_authority_identity(production_identity)
    _require_sha(policy_digest, "policy_digest")
    required_identity = {
        "runtime_composition_digest",
        "production_composition_manifest_digest",
        "launcher_digest",
        "authority_proof_identity",
        "authority_proof_digest",
        "host_backend_absent",
        "dev_fallback_absent",
        "production_mode",
        "authority_profile",
    }
    if set(production_identity) != required_identity:
        raise LocalEvidenceError("production identity fields are not exact")
    digest_values = [
        production_identity[key]
        for key in (
            "runtime_composition_digest",
            "production_composition_manifest_digest",
            "launcher_digest",
            "authority_proof_digest",
        )
    ]
    if (
        production_identity["production_mode"] is not True
        or production_identity["authority_profile"] != "native-production"
        or production_identity["host_backend_absent"] is not True
        or production_identity["dev_fallback_absent"] is not True
        or not all(isinstance(value, str) and len(value) == 64 for value in digest_values)
    ):
        raise LocalEvidenceError("production identity did not prove the secure composition")
    if not _diagnostics_pass(diagnostics):
        result = "FAIL"
    else:
        result = "PASS"
    unsigned: dict[str, object] = {
        "schema": PRODUCER_EVIDENCE_SCHEMA,
        "proof_type": proof_type,
        "commit": commit,
        "policy_digest": policy_digest,
        "profile": "community-local",
        "workflow": workflow,
        "production_claim": True,
        **production_identity,
        "diagnostics": diagnostics,
        "result": result,
    }
    unsigned["evidence_digest"] = canonical_digest(unsigned)
    return unsigned


def validate_producer_proof(
    payload: object,
    *,
    expected_commit: str,
    expected_profile: str = "community-local",
) -> dict[str, object]:
    """Validate a producer file without deriving or accepting its result."""
    if not isinstance(payload, dict):
        raise LocalEvidenceError("producer proof must be an object")
    required = {
        "schema",
        "proof_type",
        "commit",
        "policy_digest",
        "profile",
        "workflow",
        "production_claim",
        "production_mode",
        "diagnostics",
        "result",
        "evidence_digest",
    }
    allowed = required | {
        "runtime_composition_digest",
        "production_composition_manifest_digest",
        "launcher_digest",
        "authority_profile",
        "authority_proof_identity",
        "authority_proof_digest",
        "host_backend_absent",
        "dev_fallback_absent",
    }
    if set(payload) - allowed or not required.issubset(payload):
        raise LocalEvidenceError("producer proof fields are not exact")
    if (
        payload["schema"] != PRODUCER_EVIDENCE_SCHEMA
        or payload["commit"] != expected_commit
        or payload["profile"] != expected_profile
        or payload["result"] not in {"PASS", "FAIL"}
    ):
        raise LocalEvidenceError("producer proof identity or result is invalid")
    if not isinstance(payload["proof_type"], str) or not payload["proof_type"]:
        raise LocalEvidenceError("producer proof_type is missing")
    if type(payload["production_claim"]) is not bool or type(
        payload["production_mode"]
    ) is not bool:
        raise LocalEvidenceError("producer production flags must be booleans")
    _require_sha(payload.get("policy_digest"), "producer policy_digest")
    workflow = payload["workflow"]
    if not isinstance(workflow, dict):
        raise LocalEvidenceError("producer workflow provenance is malformed")
    for key in ("repository", "workflow", "run_id", "runner_os", "job"):
        if not isinstance(workflow.get(key), str) or not workflow[key]:
            raise LocalEvidenceError(f"producer workflow.{key} is missing")
    if workflow.get("repository") != REPOSITORY:
        raise LocalEvidenceError("producer workflow repository is not Khaos")
    if workflow.get("run_attempt") != 1:
        raise LocalEvidenceError("producer workflow is not attempt 1")
    diagnostics = payload["diagnostics"]
    if not isinstance(diagnostics, dict) or diagnostics.get("schema") != PRODUCER_DIAGNOSTICS_SCHEMA:
        raise LocalEvidenceError("producer diagnostics are malformed")
    if not isinstance(diagnostics.get("proof_name"), str) or not diagnostics["proof_name"]:
        raise LocalEvidenceError("producer diagnostics.proof_name is missing")
    for key in (
        "returncode",
        "test_count",
        "passed",
        "skipped",
        "failed",
        "errors",
    ):
        if type(diagnostics.get(key)) is not int or diagnostics[key] < 0:
            raise LocalEvidenceError(f"producer diagnostics.{key} is invalid")
    for key in ("skipped_reasons", "failure_details", "error_details"):
        values = diagnostics.get(key)
        if not isinstance(values, list) or any(
            not isinstance(item, str) or not item for item in values
        ):
            raise LocalEvidenceError(f"producer diagnostics.{key} is invalid")
    for key in ("junit_digest", "stdout_digest", "stderr_digest"):
        _require_sha(diagnostics.get(key), f"producer diagnostics.{key}")
    if payload["production_claim"] is True:
        validate_production_identity(payload)
    elif payload["production_claim"] is not False or payload["production_mode"] is not False:
        raise LocalEvidenceError("non-production proof has an invalid production claim")
    unsigned = dict(payload)
    supplied = unsigned.pop("evidence_digest")
    if supplied != canonical_digest(unsigned):
        raise LocalEvidenceError("producer evidence digest mismatch")
    return dict(payload)


def validate_production_identity(payload: dict[str, object]) -> None:
    """Validate the non-forgeable production composition facts in a proof."""
    for key in (
        "runtime_composition_digest",
        "production_composition_manifest_digest",
        "launcher_digest",
        "authority_proof_digest",
    ):
        _require_sha(payload.get(key), f"producer {key}")
    authority_identity = payload.get("authority_proof_identity")
    if (
        payload.get("production_mode") is not True
        or payload.get("authority_profile") != "native-production"
        or payload.get("host_backend_absent") is not True
        or payload.get("dev_fallback_absent") is not True
        or not isinstance(authority_identity, dict)
        or set(authority_identity)
        != {"socket_path", "socket_owner_uid", "public_key_digest", "authority_profile"}
        or authority_identity.get("authority_profile") != "native-production"
        or type(authority_identity.get("socket_owner_uid")) is not int
        or not isinstance(authority_identity.get("socket_path"), str)
        or not authority_identity.get("socket_path")
        or not isinstance(authority_identity.get("public_key_digest"), str)
    ):
        raise LocalEvidenceError("production proof does not prove production composition")
    _require_sha(
        authority_identity["public_key_digest"],
        "producer authority public_key_digest",
    )
    if payload.get("authority_proof_digest") != canonical_digest(authority_identity):
        raise LocalEvidenceError("production authority proof digest does not bind its identity")


def _verify_live_production_authority_identity(
    production_identity: dict[str, object],
) -> None:
    """Bind production proof creation to the live Compose authority endpoint."""
    if (
        os.environ.get("KHAOS_DEV_MODE") != "0"
        or os.environ.get("KHAOS_AUTHORITY_PROFILE") != "native-production"
    ):
        raise LocalEvidenceError(
            "production proof creation requires the native-production environment"
        )
    socket_path = os.environ.get("KHAOS_AUTHORITYD_SOCKET", "")
    public_key_path = os.environ.get("KHAOS_AUTHORITYD_PUBLIC_KEY_PATH", "")
    authority_uid = os.environ.get("KHAOS_AUTHORITYD_UID", "")
    agent_uid = os.environ.get("KHAOS_AGENT_UID", "")
    if not socket_path or not public_key_path or not authority_uid.isdigit():
        raise LocalEvidenceError("production authority identity environment is incomplete")
    if agent_uid.isdigit() and os.getuid() != int(agent_uid):
        raise LocalEvidenceError("production proof creator is not the configured Agent UID")
    try:
        socket_info = Path(socket_path).lstat()
        key_path = Path(public_key_path)
        key_info = key_path.lstat()
    except OSError as exc:
        raise LocalEvidenceError("production authority endpoint is unavailable") from exc
    if (
        not stat.S_ISSOCK(socket_info.st_mode)
        or socket_info.st_uid != int(authority_uid)
        or socket_info.st_mode & 0o007
        or not stat.S_ISREG(key_info.st_mode)
        or key_path.is_symlink()
        or key_info.st_uid != int(authority_uid)
        or key_info.st_nlink != 1
        or key_info.st_mode & 0o022
    ):
        raise LocalEvidenceError("production authority endpoint identity is unsafe")
    authority_identity = production_identity.get("authority_proof_identity")
    if not isinstance(authority_identity, dict):
        raise LocalEvidenceError("production authority proof identity is missing")
    if (
        authority_identity.get("socket_path") != socket_path
        or authority_identity.get("socket_owner_uid") != int(authority_uid)
        or authority_identity.get("public_key_digest") != sha256_file(key_path)
        or authority_identity.get("authority_profile") != "native-production"
    ):
        raise LocalEvidenceError("production authority proof identity does not match the live endpoint")


def write_producer_proof(path: Path, payload: dict[str, object]) -> None:
    """Validate and write a producer proof atomically enough for CI use."""
    validate_producer_proof(payload, expected_commit=str(payload.get("commit") or ""))
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def git_head(repo_root: Path) -> str:
    """Return the checked-out commit used by producer diagnostics."""
    return subprocess.check_output(
        ["git", "-C", str(repo_root), "rev-parse", "HEAD"],
        text=True,
    ).strip()


__all__ = [
    "PROCESS_TREE_PROOF",
    "PRODUCTION_COMPOSITION_PROOF",
    "PRODUCER_DIAGNOSTICS_SCHEMA",
    "PRODUCER_EVIDENCE_SCHEMA",
    "RESOURCE_OWNER_PROOF",
    "build_runtime_producer_proof",
    "build_test_producer_proof",
    "diagnostics_from_junit",
    "git_head",
    "producer_identity",
    "sha256_file",
    "validate_producer_proof",
    "validate_production_identity",
    "write_producer_proof",
]
