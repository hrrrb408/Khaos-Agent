#!/usr/bin/env python3
"""Run the Community Local adversarial matrix and emit producer evidence.

The script derives proof status from real subprocess results.  It does not
accept status/closed/boolean arguments and treats skipped tests as a failed
proof so an unavailable boundary cannot be promoted to PASS.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from khaos.security.effective_policy import load_effective_policy
from khaos.security.local_closure import (
    COMMUNITY_LOCAL_REQUIRED_PROOFS,
    LOCAL_EVIDENCE_SCHEMA,
    REPOSITORY,
    canonical_digest,
)


PROOF_TESTS: dict[str, tuple[str, ...]] = {
    "community_authority": (
        "python/tests/security/test_local_trust.py",
        "python/tests/security/test_authority_transport.py",
        "python/tests/security/test_authorityd_protocol.py",
        "python/tests/security/test_identity_isolation.py",
    ),
    "platform_kernel": (
        "python/tests/security/test_identity_isolation.py",
        "python/tests/security/test_kernel_helper_client_round11.py",
    ),
    "production_reachability": (
        "python/tests/security/test_production_reachability.py",
    ),
    "production_composition": (
        "python/tests/security/test_production_composition_manifest.py",
        "python/tests/security/test_production_composition_probe.py",
    ),
    "workspace_escape": (
        "python/tests/security/test_path_guard.py",
        "python/tests/coding/test_safe_workspace_fs.py",
        "python/tests/coding/test_workspace_boundary.py",
        "python/tests/coding/test_workspace_artifact_boundary.py",
    ),
    "approval_replay": (
        "python/tests/tools/test_authorization_contract.py",
        "python/tests/tools/test_approval_callback_boundary.py",
        "python/tests/agent/test_approval_broker.py",
        "python/tests/agent/test_operation_approval_ledger.py",
    ),
    "approval_substitution": (
        "python/tests/tools/test_authorization_contract.py",
        "python/tests/tools/test_approval_callback_boundary.py",
        "python/tests/tools/test_scheduler_boundaries.py",
        "python/tests/tools/test_execution_coordinator_boundary.py",
    ),
    "process_tree_escape": (
        "python/tests/coding/test_process_supervisor.py",
        "python/tests/coding/test_managed_process_lifecycle.py",
        "python/tests/coding/test_trusted_git_process_owner.py",
    ),
    "resource_owner_closure": (
        "python/tests/coding/test_resource_owner_protocol.py",
        "python/tests/coding/test_resource_owner_closure.py",
        "python/tests/coding/test_linux_resource_owner.py",
    ),
    "network_isolation": (
        "python/tests/security/test_network_guard.py",
        "python/tests/security/test_network_broker.py",
        "python/tests/tools/test_network_authority_integration.py",
        "python/tests/security/test_host_network_authority.py",
    ),
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    return parser.parse_args()


def _ci_identity(commit: str) -> dict[str, object]:
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
            "Community Local evidence must be produced by the exact main push: "
            + json.dumps(actual, sort_keys=True)
        )
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    if not run_id or not run_id.isdigit():
        raise RuntimeError("GITHUB_RUN_ID is required for producer evidence")
    run_attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "1")
    if run_attempt != "1":
        raise RuntimeError("Community Local evidence requires the original run attempt")
    return {
        "repository": REPOSITORY,
        "workflow": os.environ.get("GITHUB_WORKFLOW", "Community Local Security Closure"),
        "run_id": run_id,
        "run_attempt": 1,
        "event": "push",
        "ref": "refs/heads/main",
        "head_sha": commit,
        "runner_os": os.environ.get("RUNNER_OS", "unknown"),
    }


def _run_proof(repo_root: Path, name: str, tests: tuple[str, ...]) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix=f"khaos-{name}-") as temp_dir:
        junit = Path(temp_dir) / "results.xml"
        command = [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "--junitxml",
            str(junit),
            *tests,
        ]
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(repo_root / "python")
        completed = subprocess.run(
            command,
            cwd=repo_root,
            env=environment,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=900,
        )
        output = completed.stdout[-16000:]
        skipped = 0
        failed = 0
        errors = 0
        if junit.is_file():
            root = ET.parse(junit).getroot()
            suite = root if root.tag == "testsuite" else root.find("testsuite")
            if suite is not None:
                skipped = int(suite.attrib.get("skipped", "0"))
                failed = int(suite.attrib.get("failures", "0"))
                errors = int(suite.attrib.get("errors", "0"))
        status = "PASS" if completed.returncode == 0 and skipped == 0 else "FAIL"
        return {
            "name": name,
            "status": status,
            "tests": list(tests),
            "command": command,
            "returncode": completed.returncode,
            "skipped": skipped,
            "failures": failed,
            "errors": errors,
            "output_digest": hashlib.sha256(output.encode("utf-8")).hexdigest(),
            "artifact_digest": canonical_digest(
                {
                    "name": name,
                    "status": status,
                    "tests": list(tests),
                    "returncode": completed.returncode,
                    "skipped": skipped,
                    "failures": failed,
                    "errors": errors,
                    "output_digest": hashlib.sha256(output.encode("utf-8")).hexdigest(),
                }
            ),
        }


def main() -> int:
    args = _parse_args()
    repo_root = args.repo_root.resolve()
    output = args.output.resolve()
    identity = _ci_identity(args.commit)
    policy = load_effective_policy(repo_root)
    proofs: list[dict[str, object]] = []
    failed = False
    for name in COMMUNITY_LOCAL_REQUIRED_PROOFS:
        result = _run_proof(repo_root, name, PROOF_TESTS[name])
        failed = failed or result["status"] != "PASS"
        provenance = dict(identity)
        provenance["job"] = name
        proofs.append(
            {
                "name": name,
                "status": result["status"],
                "profile": "community-local",
                "commit": args.commit,
                "policy_digest": policy.digest,
                "artifact_digest": result["artifact_digest"],
                "provenance": provenance,
            }
        )
    payload: dict[str, Any] = {
        "schema": LOCAL_EVIDENCE_SCHEMA,
        "profile": "community-local",
        "commit": args.commit,
        "policy_digest": policy.digest,
        "security_facts_digest": _sha256(repo_root / "docs/security_facts.yaml"),
        "production_reachability_digest": _sha256(
            repo_root / "docs/generated/production-reachability.md"
        ),
        "production_composition_digest": _sha256(
            repo_root / "python/khaos/security/production_composition_manifest.py"
        ),
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
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
