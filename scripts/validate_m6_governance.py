#!/usr/bin/env python3
"""Validate the M6 release-governance preparation artifacts.

The hardened ruleset is deliberately a *template*.  This validator checks
that it is structurally ready for a second maintainer while refusing to
pretend that the current single-maintainer repository has already achieved
independent review.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "scripts" / "github-m6-hardened-ruleset.json"
CODEOWNERS = ROOT / ".github" / "CODEOWNERS"
GOVERNANCE = ROOT / "docs" / "security-release-governance.md"

REQUIRED_OWNERSHIP_MARKERS = (
    "/python/khaos/security/",
    "/python/khaos/permissions/",
    "/python/khaos/audit/",
    "/python/khaos/grpc_server.py",
    "/python/khaos/coding/execution/",
    "/go/internal/platform/",
    "/rust/khaos-core/src/bin/",
    "/packaging/macos/",
    "/packaging/windows/",
    "/Dockerfile",
    "/.github/workflows/",
)


def validate() -> list[str]:
    errors: list[str] = []
    try:
        template = json.loads(TEMPLATE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"cannot read hardened ruleset template: {exc}"]

    if template.get("enforcement") != "active":
        errors.append("hardened ruleset template must be active")
    if template.get("bypass_actors") != []:
        errors.append("hardened ruleset template must have no bypass actors")
    rules = template.get("rules", [])
    by_type = {rule.get("type"): rule for rule in rules if isinstance(rule, dict)}
    if "deletion" not in by_type or "non_fast_forward" not in by_type:
        errors.append("hardened template must protect deletion and non-fast-forward updates")
    pull_request = by_type.get("pull_request", {}).get("parameters", {})
    if pull_request.get("required_approving_review_count", 0) < 1:
        errors.append("hardened template must require an approving review")
    for field in ("require_code_owner_review", "require_last_push_approval"):
        if pull_request.get(field) is not True:
            errors.append(f"hardened template must enable {field}")
    if pull_request.get("required_review_thread_resolution") is not True:
        errors.append("hardened template must require resolved review threads")
    required_checks = {
        item.get("context")
        for item in by_type.get("required_status_checks", {})
        .get("parameters", {})
        .get("required_status_checks", [])
        if isinstance(item, dict)
    }
    if required_checks != {"Security Closure Gate", "Product Integrity Gate"}:
        errors.append("hardened template must require both aggregate gates")

    codeowners = CODEOWNERS.read_text(encoding="utf-8")
    for marker in REQUIRED_OWNERSHIP_MARKERS:
        if marker not in codeowners:
            errors.append(f"CODEOWNERS is missing security path: {marker}")
    governance = GOVERNANCE.read_text(encoding="utf-8")
    if "template" not in governance.lower() or "single-maintainer" not in governance:
        errors.append("governance document must distinguish the hardened template from current single-maintainer evidence")
    if "independent review achieved" in governance.lower():
        errors.append("governance document must not claim independent review is achieved")
    return errors


def main() -> int:
    errors = validate()
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print("M6 governance template and security CODEOWNERS are structurally valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
