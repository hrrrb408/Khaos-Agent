#!/usr/bin/env python3
"""Validate cross-file security facts and the profile-facing contracts.

``docs/security_facts.yaml`` is the machine-facing source for security
claims.  This validator checks that its high-value sets still match the
runtime evaluator, type-check configuration, workflow names, and the
operator-facing documents.  It deliberately validates claims and boundaries;
it does not treat local execution as release or platform evidence.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))

from khaos.security.local_closure import (  # noqa: E402
    COMMUNITY_LOCAL_REQUIRED_GATES,
    COMMUNITY_LOCAL_REQUIRED_PROOFS,
)

FACTS_PATH = ROOT / "docs" / "security_facts.yaml"
TYPE_CONFIG_PATH = ROOT / "pyright-security.json"
TYPE_WORKFLOW_PATH = ROOT / ".github" / "workflows" / "type-check.yml"
TYPE_DOC_PATH = ROOT / "docs" / "type-check-rollout.md"
REQUIRED_STATUS_DOC_PATH = ROOT / "docs" / "required-status-checks.md"
LOCAL_PROFILE_DOC_PATH = ROOT / "docs" / "local-security-profile.md"
RELEASE_DOC_PATH = ROOT / "docs" / "security-release-governance.md"

ISSUE_STATUSES = {
    "COMPLETED",
    "PARTIALLY_COMPLETED",
    "RESIDUAL",
    "DEFERRED",
    "OUT_OF_PROFILE",
}


def _mapping(value: object, label: str, errors: list[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        errors.append(f"{label} must be a mapping")
        return {}
    return value


def _list(value: object, label: str, errors: list[str]) -> list[Any]:
    if not isinstance(value, list):
        errors.append(f"{label} must be a list")
        return []
    return value


def _check_paths(values: list[Any], label: str, errors: list[str]) -> None:
    for value in values:
        if not isinstance(value, str) or not value:
            errors.append(f"{label} contains a non-empty path requirement")
            continue
        if not (ROOT / value.rstrip("/")).exists():
            errors.append(f"{label} references a missing path: {value}")


def validate(root: Path = ROOT) -> list[str]:
    errors: list[str] = []
    try:
        facts = yaml.safe_load(FACTS_PATH.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        return [f"cannot load security facts: {exc}"]
    facts_map = _mapping(facts, "security facts", errors)

    profiles = _mapping(facts_map.get("deployment_profiles"), "deployment_profiles", errors)
    expected_profiles = {
        "community_local": "community-local",
        "macos_signed_distribution": "macos-signed-distribution",
        "windows_native": "windows-native",
    }
    for key, identifier in expected_profiles.items():
        if _mapping(profiles.get(key), f"deployment_profiles.{key}", errors).get(
            "identifier"
        ) != identifier:
            errors.append(f"deployment profile {key} has an incorrect identifier")
    if _mapping(profiles.get("macos_signed_distribution"), "signed profile", errors).get(
        "disabled_status"
    ) != "OPTIONAL_PROFILE_NOT_ENABLED":
        errors.append("signed macOS profile must use OPTIONAL_PROFILE_NOT_ENABLED")
    if _mapping(profiles.get("windows_native"), "Windows profile", errors).get(
        "status"
    ) != "native_or_fail_closed":
        errors.append("Windows profile must remain native_or_fail_closed")

    closure = _mapping(facts_map.get("local_security_closure"), "local_security_closure", errors)
    facts_proofs = _list(
        closure.get("mandatory_proofs"),
        "local_security_closure.mandatory_proofs",
        errors,
    )
    if tuple(facts_proofs) != COMMUNITY_LOCAL_REQUIRED_PROOFS:
        errors.append("machine proof names drift from local_closure.py")
    facts_gates = _list(
        closure.get("mandatory_gates"),
        "local_security_closure.mandatory_gates",
        errors,
    )
    if tuple(facts_gates) != COMMUNITY_LOCAL_REQUIRED_GATES:
        errors.append("machine closure gates drift from local_closure.py")

    required_gates = _mapping(facts_map.get("required_gates"), "required_gates", errors)
    merge_authority = _list(
        required_gates.get("merge_authority"),
        "required_gates.merge_authority",
        errors,
    )
    if tuple(merge_authority) != ("Security Closure Gate", "Product Integrity Gate"):
        errors.append("required merge authority must be the two aggregate gates")
    for key in (
        "security_closure_workflow",
        "product_integrity_workflow",
        "community_local_provenance_workflow",
        "release_verifier",
    ):
        value = required_gates.get(key)
        if not isinstance(value, str) or not (root / value).exists():
            errors.append(f"required_gates.{key} is not a live repository path")
    required_status_doc = REQUIRED_STATUS_DOC_PATH.read_text(encoding="utf-8")
    for gate in merge_authority:
        if f"`{gate}`" not in required_status_doc:
            errors.append(f"required-status-checks.md omits aggregate gate: {gate}")
    if required_gates.get("exact_push_event") != "push":
        errors.append("Community Local exact event must be push")
    if required_gates.get("exact_main_ref") != "refs/heads/main":
        errors.append("Community Local exact ref must be refs/heads/main")

    residuals = _list(facts_map.get("accepted_residuals"), "accepted_residuals", errors)
    residual_ids: set[str] = set()
    for item in residuals:
        mapping = _mapping(item, "accepted residual", errors)
        item_id = mapping.get("id")
        if not isinstance(item_id, str) or item_id in residual_ids:
            errors.append(f"accepted residual id is missing or duplicated: {item_id!r}")
        else:
            residual_ids.add(item_id)
        if mapping.get("status") not in {"NOT_CLAIMED", "RESIDUAL", "BLOCKED_EXTERNAL"}:
            errors.append(f"accepted residual {item_id!r} has an invalid status")
        source = mapping.get("source")
        if not isinstance(source, str) or not (root / source).exists():
            errors.append(f"accepted residual {item_id!r} has no live source")
    if {"hostile_same_uid_isolation", "second_maintainer_independent_review"} - residual_ids:
        errors.append("accepted residuals must preserve the two explicit NOT_CLAIMED boundaries")

    type_facts = _mapping(facts_map.get("type_check"), "type_check", errors)
    try:
        type_config = json.loads(TYPE_CONFIG_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        errors.append(f"cannot load strict Pyright config: {exc}")
        type_config = {}
    strict_files = _list(type_facts.get("strict_files"), "type_check.strict_files", errors)
    if type_config.get("typeCheckingMode") != type_facts.get("strict_mode"):
        errors.append("type-check facts and strict Pyright mode disagree")
    if type_config.get("include") != strict_files:
        errors.append("type-check facts and pyright-security.json strict files disagree")
    if type_facts.get("hard_gate") is not True:
        errors.append("type-check facts must mark the workflow as a hard gate")
    if type_facts.get("additional_coverage_mode") != "basic":
        errors.append("additional type-check coverage must remain explicitly basic")
    type_workflow = TYPE_WORKFLOW_PATH.read_text(encoding="utf-8")
    if "uv run pyright --project pyright-security.json" not in type_workflow:
        errors.append("type-check workflow does not execute the strict machine config")
    if "continue-on-error" in type_workflow:
        errors.append("type-check workflow contains a soft-fail setting")
    type_doc = TYPE_DOC_PATH.read_text(encoding="utf-8")
    for path in strict_files:
        if not isinstance(path, str) or f"`{path}`" not in type_doc:
            errors.append(f"type-check rollout omits strict file: {path}")

    issue = _mapping(facts_map.get("issue_169"), "issue_169", errors)
    if issue.get("tracker") != "#169":
        errors.append("Issue #169 tracker identity is missing")
    if issue.get("overall_status") not in ISSUE_STATUSES:
        errors.append("Issue #169 overall status is not a supported classification")
    if issue.get("do_not_close_from_local_evidence") is not True:
        errors.append("Issue #169 must not be closed from local evidence")
    vocabulary = set(_list(issue.get("classification_vocabulary"), "Issue #169 vocabulary", errors))
    if vocabulary != ISSUE_STATUSES:
        errors.append("Issue #169 classification vocabulary is incomplete or drifted")
    items = _mapping(issue.get("items"), "issue_169.items", errors)
    expected_items = {
        "typed_resource_narrowing",
        "grant_descendants",
        "immutable_scheduler_states",
        "native_authority",
        "delegation",
    }
    if set(items) != expected_items:
        errors.append("Issue #169 item set does not cover the five requested boundaries")
    for item_id, value in items.items():
        item = _mapping(value, f"issue_169.items.{item_id}", errors)
        if item.get("status") not in ISSUE_STATUSES:
            errors.append(f"Issue #169 item {item_id} has an invalid classification")
        _check_paths(_list(item.get("evidence"), f"Issue #169 {item_id} evidence", errors), item_id, errors)
    issue_doc = root / "docs" / "issue-169-status.md"
    if not issue_doc.is_file():
        errors.append("Issue #169 status document is missing")
    else:
        issue_text = issue_doc.read_text(encoding="utf-8")
        for status in ISSUE_STATUSES:
            if f"`{status}`" not in issue_text:
                errors.append(f"Issue #169 status document omits {status}")

    local_doc = LOCAL_PROFILE_DOC_PATH.read_text(encoding="utf-8")
    release_doc = RELEASE_DOC_PATH.read_text(encoding="utf-8")
    for marker in ("NOT_CLAIMED", "OPTIONAL_PROFILE_NOT_ENABLED", "CLOSED", "NOT_CLOSED"):
        if marker not in local_doc:
            errors.append(f"local security profile omits status boundary: {marker}")
    for marker in ("Security Closure Gate", "Product Integrity Gate", "exact-SHA"):
        if marker not in release_doc:
            errors.append(f"release governance omits machine boundary: {marker}")
    return errors


def main() -> int:
    errors = validate()
    if errors:
        print("SECURITY_FACTS_CONSISTENCY: FAIL")
        for error in errors:
            print(f"- {error}")
        return 1
    print("SECURITY_FACTS_CONSISTENCY: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
