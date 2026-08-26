#!/usr/bin/env python3
"""Validate evidence retention classes against every upload-artifact step.

The classification lives in ``docs/security_facts.yaml`` so a new artifact
cannot silently become an unreviewed release or closure dependency. Saved
artifacts are audit evidence only; the live exact-SHA verifier remains the
authority for a closure decision.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import cast

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
FACTS = ROOT / "docs" / "security_facts.yaml"
VALID_CLASSES = frozenset({"diagnostic", "closure-critical", "release-critical"})


def _workflow_name(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def _walk_upload_steps(value: object, *, workflow: str) -> list[dict[str, object]]:
    found: list[dict[str, object]] = []
    if isinstance(value, Mapping):
        uses = value.get("uses")
        if isinstance(uses, str) and uses.startswith("actions/upload-artifact@"):
            with_value = value.get("with")
            if not isinstance(with_value, Mapping):
                raise ValueError(f"{workflow}: upload-artifact step has no with mapping")
            name = with_value.get("name")
            if not isinstance(name, str) or not name:
                raise ValueError(f"{workflow}: upload-artifact step has no literal name")
            found.append(
                {
                    "workflow": workflow,
                    "name": name,
                    "retention_days": with_value.get("retention-days"),
                }
            )
        for child in value.values():
            found.extend(_walk_upload_steps(child, workflow=workflow))
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for child in value:
            found.extend(_walk_upload_steps(child, workflow=workflow))
    return found


def _actual_uploads() -> list[dict[str, object]]:
    uploads: list[dict[str, object]] = []
    for path in sorted((*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml"))):
        parsed = yaml.safe_load(path.read_text(encoding="utf-8"))
        uploads.extend(_walk_upload_steps(parsed, workflow=_workflow_name(path)))
    return uploads


def _facts() -> tuple[int, list[dict[str, object]], dict[str, object]]:
    parsed = yaml.safe_load(FACTS.read_text(encoding="utf-8"))
    if not isinstance(parsed, Mapping):
        raise ValueError("security facts must be a mapping")
    raw = parsed.get("evidence_retention")
    if not isinstance(raw, Mapping):
        raise ValueError("security facts have no evidence_retention mapping")
    minimum = raw.get("critical_minimum_days")
    if isinstance(minimum, bool) or not isinstance(minimum, int):
        raise ValueError("critical_minimum_days must be an integer")
    raw_artifacts = raw.get("artifacts")
    if not isinstance(raw_artifacts, Sequence) or isinstance(
        raw_artifacts, (str, bytes, bytearray)
    ):
        raise ValueError("evidence_retention.artifacts must be a list")
    artifacts: list[dict[str, object]] = []
    for item in raw_artifacts:
        if not isinstance(item, Mapping):
            raise ValueError("each evidence retention entry must be a mapping")
        artifacts.append(dict(cast(Mapping[str, object], item)))
    release_assets = raw.get("release_asset_contract")
    if not isinstance(release_assets, Mapping):
        raise ValueError("evidence_retention has no release_asset_contract")
    return minimum, artifacts, dict(cast(Mapping[str, object], release_assets))


def validate() -> list[str]:
    errors: list[str] = []
    try:
        minimum, declared, release_assets = _facts()
        actual = _actual_uploads()
    except (OSError, ValueError, yaml.YAMLError) as exc:
        return [f"input parsing failed: {exc}"]

    if minimum < 90:
        errors.append("critical_minimum_days must be at least 90")

    declared_by_key: dict[tuple[str, str], dict[str, object]] = {}
    for item in declared:
        workflow = item.get("workflow")
        name = item.get("name")
        classification = item.get("class")
        if not isinstance(workflow, str) or not isinstance(name, str):
            errors.append(f"invalid evidence retention identity: {item!r}")
            continue
        key = (workflow, name)
        if key in declared_by_key:
            errors.append(f"duplicate evidence retention declaration: {workflow}:{name}")
        declared_by_key[key] = item
        if classification not in VALID_CLASSES:
            errors.append(f"invalid evidence retention class for {workflow}:{name}")

    actual_by_key: dict[tuple[str, str], dict[str, object]] = {}
    for item in actual:
        key = (str(item["workflow"]), str(item["name"]))
        if key in actual_by_key:
            errors.append(f"duplicate upload-artifact step: {key[0]}:{key[1]}")
        actual_by_key[key] = item

    for key in sorted(set(declared_by_key) - set(actual_by_key)):
        errors.append(f"stale evidence retention declaration: {key[0]}:{key[1]}")
    for key in sorted(set(actual_by_key) - set(declared_by_key)):
        errors.append(f"unclassified upload-artifact step: {key[0]}:{key[1]}")

    for key, declaration in declared_by_key.items():
        actual_item = actual_by_key.get(key)
        if actual_item is None or declaration.get("class") == "diagnostic":
            continue
        retention = actual_item.get("retention_days")
        if isinstance(retention, bool) or not isinstance(retention, int):
            errors.append(
                f"{key[0]}:{key[1]} must declare numeric retention-days >= {minimum}"
            )
        elif retention < minimum:
            errors.append(f"{key[0]}:{key[1]} retention-days {retention} < {minimum}")

    release_workflow = release_assets.get("workflow")
    upload_command = release_assets.get("upload_command")
    forbidden_flag = release_assets.get("replacement_flag_forbidden")
    if not isinstance(release_workflow, str) or not isinstance(upload_command, str):
        errors.append("release_asset_contract identity is incomplete")
    else:
        try:
            release_text = (ROOT / release_workflow).read_text(encoding="utf-8")
        except OSError as exc:
            errors.append(f"cannot read release workflow: {exc}")
        else:
            if upload_command not in release_text:
                errors.append("release workflow does not preserve immutable release upload")
            if isinstance(forbidden_flag, str) and forbidden_flag in release_text:
                errors.append("release workflow enables replacement of release assets")

    return errors


def main() -> int:
    errors = validate()
    if errors:
        for error in errors:
            print(f"EVIDENCE_RETENTION_CONTRACT: FAIL: {error}")
        return 1
    print("EVIDENCE_RETENTION_CONTRACT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
