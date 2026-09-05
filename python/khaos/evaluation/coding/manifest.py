"""Strict manifest loading for the M8.0 Coding evaluation pack."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from khaos.evaluation.coding.contracts import (
    CodingContractError,
    CodingResourceLimits,
    CodingScenario,
    CodingScenarioKind,
    CodingScenarioManifest,
    OracleSpec,
    oracle_from_payload,
)


_MANIFEST_FIELDS = frozenset({"schema_version", "manifest_id", "version", "scenarios", "digest"})
_SCENARIO_FIELDS = frozenset(
    {
        "scenario_id",
        "version",
        "kind",
        "repository_fixture",
        "user_prompt",
        "limits",
        "languages",
        "oracle",
        "difficulty",
        "expected_files",
        "forbidden_files",
        "base_revision",
        "max_changed_files",
        "max_diff_lines",
        "tags",
        "digest",
    }
)
_LIMIT_FIELDS = frozenset(
    {
        "timeout_seconds",
        "max_output_bytes",
        "max_diff_bytes",
        "max_changed_files",
        "max_source_files",
        "max_source_bytes",
        "max_tool_events",
        "max_model_turns",
        "max_tool_calls",
    }
)


def _load_mapping(path: Path) -> dict[str, Any]:
    """Load one bounded YAML/JSON object with duplicate-key rejection."""

    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise CodingContractError(f"cannot read manifest: {path}") from exc
    if len(raw) > 4 * 1024 * 1024:
        raise CodingContractError("manifest exceeds the 4 MiB bound")
    try:
        if path.suffix.lower() == ".json":
            value = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
        else:
            value = yaml.load(raw.decode("utf-8"), Loader=_StrictYamlLoader)
    except (OSError, UnicodeError, ValueError, yaml.YAMLError) as exc:
        raise CodingContractError(f"manifest is malformed: {path}") from exc
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise CodingContractError("manifest root must be a string-keyed object")
    return value


def _reject_duplicate_keys(pairs: list[tuple[object, object]]) -> dict[object, object]:
    result: dict[object, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate manifest key")
        result[key] = value
    return result


class _StrictYamlLoader(yaml.SafeLoader):
    """SafeLoader variant that rejects duplicate mapping keys."""


def _construct_mapping(loader: _StrictYamlLoader, node: yaml.MappingNode, deep: bool = False) -> dict[object, object]:
    mapping: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise yaml.YAMLError("duplicate manifest key")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_StrictYamlLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_mapping,
)


def _closed(value: dict[str, Any], allowed: frozenset[str], label: str) -> None:
    unknown = set(value) - allowed
    if unknown:
        raise CodingContractError(f"{label} contains unknown fields: {sorted(unknown)}")


def _strict_int(value: object, label: str) -> int:
    if type(value) is not int:
        raise CodingContractError(f"{label} must be an integer")
    return value


def _strict_string_sequence(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        raise CodingContractError(f"{label} must be a list of strings")
    if any(not isinstance(item, str) for item in value):
        raise CodingContractError(f"{label} must be a list of strings")
    return tuple(value)


def _limits(value: object) -> CodingResourceLimits:
    if value is None:
        return CodingResourceLimits()
    if not isinstance(value, dict):
        raise CodingContractError("scenario.limits must be an object")
    _closed(value, _LIMIT_FIELDS, "scenario.limits")
    return CodingResourceLimits(**value)


def _scenario(value: object, *, manifest_root: Path) -> CodingScenario:
    if not isinstance(value, dict):
        raise CodingContractError("manifest scenario must be an object")
    _closed(value, _SCENARIO_FIELDS, "scenario")
    required = {"scenario_id", "version", "kind", "repository_fixture", "user_prompt", "languages", "oracle"}
    missing = required - set(value)
    if missing:
        raise CodingContractError(f"scenario is missing fields: {sorted(missing)}")
    if not isinstance(value["repository_fixture"], str):
        raise CodingContractError("scenario.repository_fixture must be a string")
    fixture = Path(value["repository_fixture"])
    if fixture.is_absolute() or ".." in fixture.parts:
        raise CodingContractError("scenario.repository_fixture escapes manifest root")
    fixture_path = (manifest_root / fixture).resolve()
    if manifest_root.resolve() not in fixture_path.parents:
        raise CodingContractError("scenario.repository_fixture escapes manifest root")
    if not fixture_path.is_dir():
        raise CodingContractError(f"scenario fixture does not exist: {fixture}")
    return CodingScenario(
        scenario_id=value["scenario_id"],
        version=value["version"],
        kind=CodingScenarioKind(value["kind"]),
        repository_fixture=fixture.as_posix(),
        user_prompt=value["user_prompt"],
        limits=_limits(value.get("limits")),
        languages=_strict_string_sequence(value["languages"], "scenario.languages"),
        oracle=oracle_from_payload(value["oracle"]),
        difficulty=value.get("difficulty", "medium"),
        expected_files=_strict_string_sequence(value.get("expected_files", ()), "scenario.expected_files"),
        forbidden_files=_strict_string_sequence(value.get("forbidden_files", ()), "scenario.forbidden_files"),
        base_revision=value.get("base_revision"),
        max_changed_files=value.get("max_changed_files"),
        max_diff_lines=value.get("max_diff_lines"),
        tags=_strict_string_sequence(value.get("tags", ()), "scenario.tags"),
        digest=value.get("digest", ""),
    )


def load_manifest(path: Path) -> CodingScenarioManifest:
    """Load and validate a manifest from a file or a pack directory."""

    candidate = path.expanduser().absolute()
    if candidate.is_symlink():
        raise CodingContractError(f"manifest is not a regular file: {path}")
    if candidate.is_dir():
        for name in ("manifest.yaml", "manifest.yml", "manifest.json"):
            item = candidate / name
            if item.exists() and not item.is_symlink():
                candidate = item
                break
        else:
            raise CodingContractError(f"manifest not found in directory: {path}")
    if not candidate.is_file() or candidate.is_symlink():
        raise CodingContractError(f"manifest is not a regular file: {path}")
    candidate = candidate.resolve()
    value = _load_mapping(candidate)
    _closed(value, _MANIFEST_FIELDS, "manifest")
    required = {"manifest_id", "version", "scenarios"}
    missing = required - set(value)
    if missing:
        raise CodingContractError(f"manifest is missing fields: {sorted(missing)}")
    raw_scenarios = value["scenarios"]
    if not isinstance(raw_scenarios, list):
        raise CodingContractError("manifest.scenarios must be a list")
    scenarios = tuple(_scenario(item, manifest_root=candidate.parent) for item in raw_scenarios)
    scenarios = tuple(sorted(scenarios, key=lambda item: item.scenario_id))
    return CodingScenarioManifest(
        schema_version=_strict_int(value.get("schema_version", 1), "manifest.schema_version"),
        manifest_id=value["manifest_id"],
        version=_strict_int(value["version"], "manifest.version"),
        scenarios=scenarios,
        digest=value.get("digest", ""),
    )


def builtin_manifest_path() -> Path:
    """Return the checked-in M8.0 manifest path."""

    return Path(__file__).resolve().parent / "pack" / "manifest.yaml"


def load_builtin_manifest() -> CodingScenarioManifest:
    """Load the release-controlled built-in scenario pack."""

    return load_manifest(builtin_manifest_path())


def resolve_fixture_path(manifest_path: Path, scenario: CodingScenario) -> Path:
    """Resolve a scenario fixture without allowing path traversal."""

    root = manifest_path.expanduser().absolute()
    if root.is_symlink():
        raise CodingContractError("manifest path must not be a symlink")
    root = root.resolve()
    if root.is_file():
        root = root.parent
    lexical_path = root / scenario.repository_fixture
    path = lexical_path.resolve()
    if root not in path.parents or not path.is_dir() or lexical_path.is_symlink():
        raise CodingContractError("scenario fixture is outside its manifest root")
    return path


__all__ = [
    "builtin_manifest_path",
    "load_builtin_manifest",
    "load_manifest",
    "resolve_fixture_path",
]
