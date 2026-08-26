#!/usr/bin/env python3
"""Validate the repository's strict Pyright contract against its CI/docs.

The repository-wide Pyright configuration intentionally remains basic while
the trust-kernel set is migrated incrementally.  This validator prevents the
three authorities from drifting apart:

* ``pyright-security.json`` is the machine-readable strict source of truth;
* the reusable workflow must execute that exact config as a hard step; and
* the rollout document may describe only the files actually in that config.

The additional direct file list in the workflow is explicitly basic-mode
coverage until each file is promoted into the strict config.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT / "pyright-security.json"
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "type-check.yml"
DOC_PATH = ROOT / "docs" / "type-check-rollout.md"


def validate() -> tuple[str, ...]:
    findings: list[str] = []
    try:
        config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return (f"cannot load {CONFIG_PATH}: {exc}",)

    if config.get("typeCheckingMode") != "strict":
        findings.append("pyright-security.json must declare typeCheckingMode=strict")
    strict_files = config.get("include")
    if not isinstance(strict_files, list) or not strict_files:
        findings.append("pyright-security.json must contain a non-empty include list")
        strict_files = []
    if len(strict_files) != len(set(strict_files)):
        findings.append("pyright-security.json include list contains duplicates")

    for relative in strict_files:
        if not isinstance(relative, str):
            findings.append("pyright-security.json include entries must be strings")
            continue
        path = ROOT / relative
        if not path.is_file():
            findings.append(f"strict Pyright file does not exist: {relative}")
            continue
        source = path.read_text(encoding="utf-8")
        if re.search(r"#\s*type:\s*ignore(?:\s|$)", source):
            findings.append(f"bare type: ignore in strict Pyright file: {relative}")

    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
    if "uv run pyright --project pyright-security.json" not in workflow:
        findings.append("type-check workflow does not execute pyright-security.json")
    if "continue-on-error" in workflow:
        findings.append("type-check workflow must not use continue-on-error")
    if "additional direct file coverage remains basic-mode" not in workflow:
        findings.append(
            "workflow must label the non-project direct Pyright invocation as basic-mode"
        )

    document = DOC_PATH.read_text(encoding="utf-8")
    for relative in strict_files:
        if f"`{relative}`" not in document:
            findings.append(f"rollout document omits strict file: {relative}")
    return tuple(findings)


def main() -> int:
    findings = validate()
    if findings:
        print("TYPE_CHECK_CONTRACT: FAIL")
        for finding in findings:
            print(f"- {finding}")
        return 1
    print("TYPE_CHECK_CONTRACT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
