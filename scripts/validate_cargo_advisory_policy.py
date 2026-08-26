#!/usr/bin/env python3
"""Validate Rust advisory suppressions against the locked dependency graph.

An advisory exception is a temporary, typed policy record. The validator
rejects an exception when the locked dependency has already reached the
declared fixed version, preventing a patched dependency plus stale ignore from
becoming a permanent scanner bypass.
"""

from __future__ import annotations

import re
import tomllib
from datetime import date
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
AUDIT_CONFIG = ROOT / "rust/khaos-core/audit.toml"
POLICY = ROOT / "rust/khaos-core/advisory-policy.toml"
CARGO_LOCK = ROOT / "rust/khaos-core/Cargo.lock"
WORKFLOW = ROOT / ".github/workflows/supply-chain-audit.yml"
ADVISORY_ID = re.compile(r"^RUSTSEC-[0-9]{4}-[0-9]{4}$")
REQUIRED_FIELDS = frozenset(
    {
        "id",
        "dependency",
        "current_version",
        "affected_range",
        "fixed_version",
        "reason",
        "owner",
        "removal_condition",
        "expires_on",
    }
)


def _version(value: object, label: str) -> tuple[int, ...]:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]+(?:\.[0-9]+){0,2}", value):
        raise ValueError(f"{label} must be a numeric semantic version")
    return tuple(int(part) for part in value.split("."))


def _locked_versions(path: Path) -> dict[str, str]:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    packages = data.get("package")
    if not isinstance(packages, list):
        raise ValueError("Cargo.lock has no package list")
    versions: dict[str, str] = {}
    for package in packages:
        if not isinstance(package, dict):
            continue
        name = package.get("name")
        version = package.get("version")
        if isinstance(name, str) and isinstance(version, str):
            versions[name] = version
    return versions


def validate_paths(
    *,
    audit_config: Path,
    policy_path: Path,
    cargo_lock: Path,
    workflow: Path,
    today: date | None = None,
) -> list[str]:
    errors: list[str] = []
    try:
        audit_data = tomllib.loads(audit_config.read_text(encoding="utf-8"))
        policy_data = tomllib.loads(policy_path.read_text(encoding="utf-8"))
        locked = _locked_versions(cargo_lock)
    except (OSError, tomllib.TOMLDecodeError, ValueError) as exc:
        return [f"input parsing failed: {exc}"]

    raw_advisories = audit_data.get("advisories")
    raw_ignored = raw_advisories.get("ignore", []) if isinstance(raw_advisories, dict) else []
    if not isinstance(raw_ignored, list) or not all(
        isinstance(item, str) for item in raw_ignored
    ):
        return ["audit.toml advisories.ignore must be a list of strings"]
    ignored = set(raw_ignored)
    raw_exceptions = policy_data.get("advisory_exceptions", [])
    if not isinstance(raw_exceptions, list):
        return ["advisory-policy.toml advisory_exceptions must be a list"]
    exceptions: dict[str, dict[str, Any]] = {}
    for item in raw_exceptions:
        if not isinstance(item, dict):
            errors.append("each advisory exception must be a table")
            continue
        missing = REQUIRED_FIELDS - set(item)
        if missing:
            errors.append(
                "advisory exception is missing: " + ", ".join(sorted(missing))
            )
            continue
        unknown = set(item) - REQUIRED_FIELDS
        if unknown:
            errors.append(
                "advisory exception has unknown fields: " + ", ".join(sorted(unknown))
            )
        advisory_id = item.get("id")
        if not isinstance(advisory_id, str) or not ADVISORY_ID.fullmatch(advisory_id):
            errors.append(f"invalid RustSec advisory id: {advisory_id!r}")
            continue
        if advisory_id in exceptions:
            errors.append(f"duplicate advisory exception: {advisory_id}")
        exceptions[advisory_id] = item
        for field in REQUIRED_FIELDS - {"id"}:
            if not isinstance(item.get(field), str) or not item[field].strip():
                errors.append(f"{advisory_id}: {field} must be non-empty text")
        dependency = item.get("dependency")
        current_version = item.get("current_version")
        fixed_version = item.get("fixed_version")
        if isinstance(dependency, str) and dependency not in locked:
            errors.append(f"{advisory_id}: dependency {dependency} is not in Cargo.lock")
        if isinstance(dependency, str) and isinstance(current_version, str):
            if locked.get(dependency) != current_version:
                errors.append(
                    f"{advisory_id}: current_version does not match Cargo.lock "
                    f"({locked.get(dependency)!r})"
                )
        try:
            locked_version = _version(
                locked.get(str(dependency), ""), f"{advisory_id} locked version"
            )
            fixed = _version(fixed_version, f"{advisory_id} fixed_version")
        except ValueError as exc:
            errors.append(str(exc))
        else:
            if locked_version >= fixed:
                errors.append(
                    f"{advisory_id}: locked dependency is outside the vulnerable range; "
                    f"remove the stale ignore (locked={locked.get(str(dependency))}, fixed={fixed_version})"
                )
        try:
            expires = date.fromisoformat(str(item.get("expires_on")))
        except ValueError:
            errors.append(f"{advisory_id}: expires_on must be YYYY-MM-DD")
        else:
            if expires <= (today or date.today()):
                errors.append(f"{advisory_id}: advisory exception is expired")

    if ignored != set(exceptions):
        errors.append(
            "audit.toml ignore ids must exactly match advisory-policy.toml: "
            f"audit={sorted(ignored)} policy={sorted(exceptions)}"
        )
    workflow_text = workflow.read_text(encoding="utf-8")
    flags = set(re.findall(r"--ignore\s+(RUSTSEC-[0-9]{4}-[0-9]{4})", workflow_text))
    if flags != ignored:
        errors.append(
            "workflow --ignore ids must exactly match audit.toml: "
            f"workflow={sorted(flags)} audit={sorted(ignored)}"
        )
    return errors


def validate() -> list[str]:
    return validate_paths(
        audit_config=AUDIT_CONFIG,
        policy_path=POLICY,
        cargo_lock=CARGO_LOCK,
        workflow=WORKFLOW,
    )


def main() -> int:
    errors = validate()
    if errors:
        for error in errors:
            print(f"CARGO_ADVISORY_POLICY: FAIL: {error}")
        return 1
    print("CARGO_ADVISORY_POLICY: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
