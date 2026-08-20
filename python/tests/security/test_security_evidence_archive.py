"""Tests for the producer-owned semantic proof archive contract."""

from __future__ import annotations

import hashlib
import io
import json
import zipfile

import pytest
from khaos.security.security_evidence import (
    SecurityEvidenceError,
    parse_proof_archive,
)

COMMIT = "a" * 40
POLICY = "b" * 64


def _archive(*, member_name: str = "native-proof.json", record: object | None = None) -> bytes:
    record_value = record or {
        "github_sha": COMMIT,
        "github_run_id": "1234",
        "proof_type": "macos-native-authority",
        "policy_digest": POLICY,
        "runner_os": "macOS",
        "platform": "darwin",
        "peer_verified": True,
        "transport_verified": True,
        "protected_key_verified": True,
    }
    proof_bytes = json.dumps(record_value, sort_keys=True, separators=(",", ":")).encode()
    manifest = {
        "schema_version": 1,
        "proof_type": "macos-native-authority",
        "github_sha": COMMIT,
        "github_run_id": "1234",
        "workflow_name": "Native Authority Production E2E",
        "job_name": "macOS launchd/XPC authority",
        "runner_os": "macOS",
        "runner_arch": "arm64",
        "platform": "darwin",
        "policy_digest": POLICY,
        "files": {member_name: hashlib.sha256(proof_bytes).hexdigest()},
    }
    manifest_bytes = json.dumps(
        manifest, sort_keys=True, separators=(",", ":")
    ).encode()
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(member_name, proof_bytes)
        archive.writestr("proof-manifest.json", manifest_bytes)
    return output.getvalue()


def _parse(payload: bytes) -> tuple[dict[str, object], str]:
    return parse_proof_archive(
        payload,
        expected_proof_type="macos-native-authority",
        expected_commit=COMMIT,
        expected_run_id="1234",
        expected_workflow="Native Authority Production E2E",
        expected_runner_os="macOS",
        expected_platform="darwin",
        expected_policy_digest=POLICY,
        expected_job_name="macOS launchd/XPC authority",
    )


def test_parse_proof_archive_verifies_semantic_manifest_and_file_hashes() -> None:
    manifest, digest = _parse(_archive())
    assert manifest["proof_type"] == "macos-native-authority"
    assert len(digest) == 64


def test_parse_proof_archive_rejects_digest_tampering() -> None:
    payload = _archive()
    with zipfile.ZipFile(io.BytesIO(payload)) as source:
        entries = {info.filename: source.read(info.filename) for info in source.infolist()}
    manifest = json.loads(entries["proof-manifest.json"])
    manifest["files"]["native-proof.json"] = "0" * 64
    entries["proof-manifest.json"] = json.dumps(manifest).encode()
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        for name, value in entries.items():
            archive.writestr(name, value)
    with pytest.raises(SecurityEvidenceError, match="digest does not match"):
        _parse(output.getvalue())


def test_parse_proof_archive_rejects_unsafe_member_names() -> None:
    payload = _archive(member_name="../native-proof.json")
    with pytest.raises(SecurityEvidenceError, match="unsafe member path"):
        _parse(payload)


def test_parse_proof_archive_requires_semantically_bound_json() -> None:
    payload = _archive(record={"ok": True})
    with pytest.raises(SecurityEvidenceError, match="semantically bound"):
        _parse(payload)
