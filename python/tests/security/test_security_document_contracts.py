"""Machine-readable security profile and closure-document contracts."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys

import yaml


ROOT = Path(__file__).resolve().parents[3]


def test_community_local_profile_contract_is_explicit_and_profile_aware() -> None:
    facts = yaml.safe_load((ROOT / "docs/security_facts.yaml").read_text(encoding="utf-8"))
    local = facts["local_security_closure"]

    assert local["scope"] == "community_local_profile_only"
    assert local["community_local_prerequisites"]["apple_developer_program"] == "not_required"
    assert local["community_local_prerequisites"]["apple_team_id"] == "not_required"
    assert local["community_local_prerequisites"]["signed_xpc"] == "not_required"
    assert local["community_local_prerequisites"]["notarization"] == "not_required"
    assert "apple_team_id" in local["community_local_prerequisites"]
    assert local["optional_profiles"]["macos_signed_distribution"] == (
        "OPTIONAL_PROFILE_NOT_ENABLED"
    )
    assert local["explicit_non_claims"] == {
        "hostile_same_uid_isolation": "NOT_CLAIMED",
        "second_maintainer_independent_review": "NOT_CLAIMED",
    }
    assert local["local_json_or_mock_artifact_can_close"] is False
    assert "exact_commit_sha" in local["mandatory_binding"]
    assert "producer_artifact_digest" in local["mandatory_binding"]
    assert "github_push_event" in local["mandatory_binding"]


def test_production_forbidden_fallback_contract_is_machine_readable() -> None:
    facts = yaml.safe_load((ROOT / "docs/security_facts.yaml").read_text(encoding="utf-8"))
    forbidden = set(facts["production_reachability"]["forbidden_modules"])

    assert "khaos.coding.execution.host" in forbidden
    assert "khaos.runtime.testing" in forbidden
    assert "khaos.security.mock_authority" in forbidden
    assert "khaos.coding.execution.testing_sandbox" in forbidden


def test_profile_document_records_nonclaims_and_no_apple_prerequisite() -> None:
    document = (ROOT / "docs/local-security-profile.md").read_text(encoding="utf-8")

    assert "hostile same-UID" in document
    assert "NOT_CLAIMED" in document
    assert "second-maintainer independent review" in document
    assert "Apple Developer Program membership" in document
    assert "OPTIONAL_PROFILE_NOT_ENABLED" in document
    assert "CLOSURE_PENDING_EXACT_SHA_CI_EVIDENCE" in document


def test_closure_report_generator_has_no_manual_status_switch() -> None:
    source = (ROOT / "scripts/build_local_security_closure_report.py").read_text(
        encoding="utf-8"
    )

    assert "--closed" not in source
    assert "--pass" not in source
    assert "--force" not in source
    assert "verify_release_gates_for_closure" in source
    assert "VerifiedGitHubProvenance" in source
    assert "--release-evidence" not in source
    assert "github_provenance_verified" not in source


def test_closure_report_rejects_wrong_head_without_error_path_crash() -> None:
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/build_local_security_closure_report.py"),
            "--repo-root",
            str(ROOT),
            "--profile",
            "community-local",
            "--commit",
            "0" * 40,
        ],
        env={**os.environ, "PYTHONPATH": str(ROOT / "python")},
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 1
    assert "Status: NOT_CLOSED" in result.stdout
    assert "TypeError" not in result.stdout
    assert "Traceback" not in result.stdout
