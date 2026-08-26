#!/usr/bin/env python3
"""Validate the M6 release-governance preparation artifacts.

The hardened ruleset is deliberately a *template*.  This validator checks
that it is structurally ready for a second maintainer while refusing to
pretend that the current single-maintainer repository has already achieved
independent review.
"""

from __future__ import annotations

import fnmatch
import json
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "scripts" / "github-m6-hardened-ruleset.json"
CODEOWNERS = ROOT / ".github" / "CODEOWNERS"
GOVERNANCE = ROOT / "docs" / "security-release-governance.md"
FACTS = ROOT / "docs" / "security_facts.yaml"


def _normalise_path(value: object) -> str:
    """Return a repository-relative inventory path or raise ``ValueError``."""

    if not isinstance(value, str) or not value:
        raise ValueError("path must be a non-empty string")
    if "\\" in value or "\x00" in value:
        raise ValueError("path must use slash separators and contain no NUL")
    if value.startswith("/") or value.startswith("./"):
        raise ValueError("path must be repository-relative")
    components = value.split("/")
    if any(component in {"", ".", ".."} for component in components[:-1]):
        raise ValueError("path contains an empty or traversal component")
    if components[-1] in {"", ".", ".."}:
        if not value.endswith("/") or components[-1] != "":
            raise ValueError("path contains an invalid terminal component")
        components = components[:-1]
    result = "/".join(components)
    return f"{result}/" if value.endswith("/") else result


def load_security_critical_paths(root: Path = ROOT) -> tuple[str, ...]:
    """Load the canonical security-critical path inventory from security facts."""

    facts_path = root / "docs" / "security_facts.yaml"
    facts = yaml.safe_load(facts_path.read_text(encoding="utf-8"))
    if not isinstance(facts, dict):
        raise ValueError("security facts must be a mapping")
    governance = facts.get("governance")
    if not isinstance(governance, dict):
        raise ValueError("governance must be a mapping")
    raw_paths = governance.get("security_critical_paths")
    if not isinstance(raw_paths, list):
        raise ValueError("security_critical_paths must be a list")
    paths: list[str] = []
    for raw_path in raw_paths:
        paths.append(_normalise_path(raw_path))
    return tuple(paths)


def _parse_codeowners(text: str) -> tuple[tuple[str, tuple[str, ...]], ...]:
    entries: list[tuple[str, tuple[str, ...]]] = []
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        fields = line.split()
        if len(fields) < 2:
            raise ValueError(f"CODEOWNERS line {line_number} has no owner")
        entries.append((fields[0], tuple(fields[1:])))
    return tuple(entries)


def _codeowners_covers(pattern: str, path: str) -> bool:
    candidate = pattern.removeprefix("/")
    target = path.rstrip("/")
    if candidate.endswith("/"):
        directory = candidate.rstrip("/")
        return target == directory or target.startswith(f"{directory}/")
    if "/" not in candidate:
        return fnmatch.fnmatchcase(target.rsplit("/", 1)[-1], candidate)
    return fnmatch.fnmatchcase(target, candidate)


def security_critical_path_errors(
    paths: tuple[str, ...] | list[str],
    codeowners_text: str,
    *,
    root: Path = ROOT,
    require_exists: bool = True,
) -> list[str]:
    """Validate inventory uniqueness, liveness, and CODEOWNERS coverage."""

    errors: list[str] = []
    normalised: list[str] = []
    seen: set[str] = set()
    for raw_path in paths:
        try:
            path = _normalise_path(raw_path)
        except ValueError as exc:
            errors.append(f"invalid security-critical path {raw_path!r}: {exc}")
            continue
        if path in seen:
            errors.append(f"duplicate security-critical path: {path}")
        seen.add(path)
        normalised.append(path)
        if require_exists and not (root / path.rstrip("/")).exists():
            errors.append(f"security-critical path is missing: {path}")

    try:
        entries = _parse_codeowners(codeowners_text)
    except ValueError as exc:
        return [*errors, str(exc)]
    for path in normalised:
        if not any(owners and _codeowners_covers(pattern, path) for pattern, owners in entries):
            errors.append(f"security-critical path is not covered by CODEOWNERS: {path}")
    return errors


def validate_security_critical_paths(root: Path = ROOT) -> list[str]:
    """Validate the canonical inventory against live repository ownership."""

    try:
        paths = load_security_critical_paths(root)
        codeowners = (root / ".github" / "CODEOWNERS").read_text(encoding="utf-8")
    except (OSError, ValueError, yaml.YAMLError) as exc:
        return [f"cannot load security-critical path governance: {exc}"]
    return security_critical_path_errors(paths, codeowners, root=root)


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

    errors.extend(validate_security_critical_paths())
    try:
        facts = yaml.safe_load(FACTS.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        return [*errors, f"cannot read security facts: {exc}"]
    governance_facts = facts.get("governance", {}) if isinstance(facts, dict) else {}
    if governance_facts.get("critical_path_change_requires_manual_diff_review") is not True:
        errors.append("security facts must require manual diff review for critical paths")
    if governance_facts.get("autonomous_merge_allowed") is not False:
        errors.append("security facts must forbid autonomous merge")
    try:
        governance = GOVERNANCE.read_text(encoding="utf-8")
    except OSError as exc:
        return [*errors, f"cannot read governance document: {exc}"]
    if "template" not in governance.lower() or "single-maintainer" not in governance:
        errors.append("governance document must distinguish the hardened template from current single-maintainer evidence")
    if "manual maintainer diff review" not in governance.lower():
        errors.append("governance document must require manual maintainer diff review")
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
