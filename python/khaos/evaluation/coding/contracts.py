"""Typed contracts for the M8.0 Coding capability evaluation plane.

The coding evaluator is deliberately a sibling of the M7.9 control-capability
evaluator.  These values describe an experiment and its evidence; they are not
permission, completion, verification, routing, or recovery authority.
"""

from __future__ import annotations

import hashlib
import math
import platform as platform_module
import re
import sys
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping, TypeAlias

from khaos.security.protocol_boundary import canonical_digest, canonical_json_bytes


class CodingContractError(ValueError):
    """A coding evaluation input violates its closed contract."""


class CodingScenarioKind(StrEnum):
    """Supported coding capability task families."""

    BUG_FIX = "BUG_FIX"
    FEATURE = "FEATURE"
    REFACTOR = "REFACTOR"
    MULTI_FILE = "MULTI_FILE"
    CROSS_LANGUAGE = "CROSS_LANGUAGE"
    CODE_REVIEW = "CODE_REVIEW"


class CodingVerdict(StrEnum):
    """Terminal verdicts emitted by the external evaluation plane."""

    PASS = "PASS"
    FAIL = "FAIL"
    TIMEOUT = "TIMEOUT"
    AGENT_ERROR = "AGENT_ERROR"
    ORACLE_ERROR = "ORACLE_ERROR"
    INVALID_FIXTURE = "INVALID_FIXTURE"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


class CodingFailureReason(StrEnum):
    """Structured agent/evaluator failure taxonomy for reports."""

    LOCALIZATION_FAILURE = "LOCALIZATION_FAILURE"
    EDIT_FAILURE = "EDIT_FAILURE"
    BUILD_FAILURE = "BUILD_FAILURE"
    TEST_FAILURE = "TEST_FAILURE"
    REGRESSION_FAILURE = "REGRESSION_FAILURE"
    TIMEOUT = "TIMEOUT"
    NO_PROGRESS = "NO_PROGRESS"
    WRONG_FILES_CHANGED = "WRONG_FILES_CHANGED"
    EXCESSIVE_DIFF = "EXCESSIVE_DIFF"
    REVIEW_MISSED_FINDING = "REVIEW_MISSED_FINDING"
    REVIEW_FALSE_POSITIVE = "REVIEW_FALSE_POSITIVE"
    AGENT_ERROR = "AGENT_ERROR"
    ORACLE_ERROR = "ORACLE_ERROR"
    INVALID_FIXTURE = "INVALID_FIXTURE"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


class OracleKind(StrEnum):
    """Typed external oracle variants."""

    COMMAND = "COMMAND"
    FILE_STATE = "FILE_STATE"
    DIFF = "DIFF"
    COMPOSITE = "COMPOSITE"
    REVIEW_FINDING = "REVIEW_FINDING"


class FindingMatchMode(StrEnum):
    """How a review finding is matched against agent findings."""

    ALL = "ALL"
    ANY = "ANY"


_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{1,95}$")
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_LANGUAGES = frozenset({"python", "go", "rust", "typescript", "javascript"})


def _require_id(value: object, label: str) -> str:
    if not isinstance(value, str) or _ID_PATTERN.fullmatch(value) is None:
        raise CodingContractError(f"{label} is not a valid bounded identifier")
    return value


def _require_text(value: object, label: str, *, max_bytes: int = 32 * 1024) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CodingContractError(f"{label} must be non-empty text")
    if len(value.encode("utf-8")) > max_bytes:
        raise CodingContractError(f"{label} exceeds its byte bound")
    return value


def _require_path(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise CodingContractError(f"{label} must be a relative path")
    path = Path(value)
    if path.is_absolute() or any(part == ".." for part in path.parts):
        raise CodingContractError(f"{label} must not escape its fixture root")
    if path == Path("."):
        raise CodingContractError(f"{label} must name a file or directory")
    return path.as_posix()


def _require_string_tuple(value: object, label: str, *, max_items: int = 256) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or len(value) > max_items:
        raise CodingContractError(f"{label} must be a bounded string list")
    result = tuple(_require_text(item, f"{label}[]", max_bytes=4096) for item in value)
    if len(set(result)) != len(result):
        raise CodingContractError(f"{label} must not contain duplicates")
    return result


def _require_path_tuple(value: object, label: str, *, max_items: int = 256) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or len(value) > max_items:
        raise CodingContractError(f"{label} must be a bounded path list")
    result = tuple(_require_path(item, f"{label}[]") for item in value)
    if len(set(result)) != len(result):
        raise CodingContractError(f"{label} must not contain duplicates")
    return result


def _mapping(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise CodingContractError(f"{label} must be an object")
    return MappingProxyType(dict(value))


def _bounded_float(value: object, label: str, default: float) -> float:
    candidate = default if value is None else value
    if isinstance(candidate, bool) or not isinstance(candidate, (int, float)):
        raise CodingContractError(f"{label} must be a finite number")
    number = float(candidate)
    if not math.isfinite(number):
        raise CodingContractError(f"{label} must be a finite number")
    return number


def _bounded_int(value: object, label: str, default: int) -> int:
    candidate = default if value is None else value
    if type(candidate) is not int:
        raise CodingContractError(f"{label} must be an integer")
    return candidate


def _bounded_bool(value: object, label: str, default: bool) -> bool:
    candidate = default if value is None else value
    if type(candidate) is not bool:
        raise CodingContractError(f"{label} must be boolean")
    return candidate


def _sequence(value: object, label: str) -> list[Any] | tuple[Any, ...]:
    if not isinstance(value, (list, tuple)):
        raise CodingContractError(f"{label} must be a list")
    return value


@dataclass(frozen=True, slots=True)
class CodingResourceLimits:
    """Independent bounds for agent and oracle work."""

    timeout_seconds: float = 120.0
    max_output_bytes: int = 64 * 1024
    max_diff_bytes: int = 4 * 1024 * 1024
    max_changed_files: int = 64
    max_source_files: int = 10
    max_source_bytes: int = 4 * 1024 * 1024
    max_tool_events: int = 2048
    max_model_turns: int = 128
    max_tool_calls: int = 512

    def __post_init__(self) -> None:
        if (
            type(self.timeout_seconds) not in {int, float}
            or not math.isfinite(float(self.timeout_seconds))
            or not 0 < self.timeout_seconds <= 3600
        ):
            raise CodingContractError("timeout_seconds is outside [0, 3600]")
        for name in (
            "max_output_bytes",
            "max_diff_bytes",
            "max_changed_files",
            "max_source_files",
            "max_source_bytes",
            "max_tool_events",
            "max_model_turns",
            "max_tool_calls",
        ):
            value = getattr(self, name)
            if type(value) is not int or value <= 0:
                raise CodingContractError(f"{name} must be a positive integer")

    def to_payload(self) -> dict[str, object]:
        return {
            "timeout_seconds": self.timeout_seconds,
            "max_output_bytes": self.max_output_bytes,
            "max_diff_bytes": self.max_diff_bytes,
            "max_changed_files": self.max_changed_files,
            "max_source_files": self.max_source_files,
            "max_source_bytes": self.max_source_bytes,
            "max_tool_events": self.max_tool_events,
            "max_model_turns": self.max_model_turns,
            "max_tool_calls": self.max_tool_calls,
        }


@dataclass(frozen=True, slots=True)
class CommandOracleSpec:
    """A manifest-owned argv command executed by a trusted adapter."""

    argv: tuple[str, ...]
    cwd: str = "."
    timeout_seconds: float = 120.0
    max_output_bytes: int = 64 * 1024
    expected_exit_code: int = 0
    hidden_files: tuple[str, ...] = ()
    environment: tuple[tuple[str, str], ...] = ()
    network: str = "none"

    kind: OracleKind = field(default=OracleKind.COMMAND, init=False)

    def __post_init__(self) -> None:
        if not self.argv or any(not isinstance(arg, str) or not arg for arg in self.argv):
            raise CodingContractError("command oracle argv must be non-empty strings")
        if len(self.argv) > 64 or any(len(arg.encode("utf-8")) > 4096 for arg in self.argv):
            raise CodingContractError("command oracle argv exceeds its bound")
        object.__setattr__(self, "cwd", _require_path(self.cwd, "oracle.cwd") if self.cwd != "." else ".")
        if type(self.timeout_seconds) not in {int, float} or not 0 < self.timeout_seconds <= 3600:
            raise CodingContractError("oracle timeout_seconds is outside bounds")
        if type(self.max_output_bytes) is not int or not 0 < self.max_output_bytes <= 16 * 1024 * 1024:
            raise CodingContractError("oracle max_output_bytes is outside bounds")
        if type(self.expected_exit_code) is not int or not 0 <= self.expected_exit_code <= 255:
            raise CodingContractError("oracle expected_exit_code is outside bounds")
        object.__setattr__(self, "hidden_files", _require_path_tuple(self.hidden_files, "oracle.hidden_files"))
        if self.network != "none":
            raise CodingContractError("coding evaluation oracle network must be none")
        if not isinstance(self.environment, (list, tuple)) or len(self.environment) > 32:
            raise CodingContractError("oracle environment is invalid")
        if any(
            not isinstance(item, (list, tuple))
            or len(item) != 2
            or not isinstance(item[0], str)
            or not item[0]
            or not isinstance(item[1], str)
            or len(item[0]) > 128
            or len(item[1].encode("utf-8")) > 4096
            for item in self.environment
        ):
            raise CodingContractError("oracle environment is invalid")
        environment = tuple((item[0], item[1]) for item in self.environment)
        if len({key for key, _ in environment}) != len(environment):
            raise CodingContractError("oracle environment contains duplicate keys")
        object.__setattr__(self, "environment", environment)

    def to_payload(self) -> dict[str, object]:
        return {
            "kind": self.kind.value,
            "argv": list(self.argv),
            "cwd": self.cwd,
            "timeout_seconds": self.timeout_seconds,
            "max_output_bytes": self.max_output_bytes,
            "expected_exit_code": self.expected_exit_code,
            "hidden_files": list(self.hidden_files),
            "environment": {key: value for key, value in self.environment},
            "network": self.network,
        }


@dataclass(frozen=True, slots=True)
class FileStateCheck:
    """One bounded, deterministic file-state assertion."""

    path: str
    exists: bool = True
    contains: tuple[str, ...] = ()
    not_contains: tuple[str, ...] = ()
    sha256: str | None = None
    json_equals: Mapping[str, object] | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "path", _require_path(self.path, "file_state.path"))
        if type(self.exists) is not bool:
            raise CodingContractError("file_state.exists must be boolean")
        object.__setattr__(self, "contains", _require_string_tuple(self.contains, "file_state.contains"))
        object.__setattr__(self, "not_contains", _require_string_tuple(self.not_contains, "file_state.not_contains"))
        if self.sha256 is not None and (
            not isinstance(self.sha256, str) or _SHA256_PATTERN.fullmatch(self.sha256) is None
        ):
            raise CodingContractError("file_state.sha256 must be a lowercase SHA-256")
        if self.json_equals is not None:
            object.__setattr__(self, "json_equals", MappingProxyType(dict(_mapping(self.json_equals, "file_state.json_equals"))))

    def to_payload(self) -> dict[str, object]:
        return {
            "path": self.path,
            "exists": self.exists,
            "contains": list(self.contains),
            "not_contains": list(self.not_contains),
            "sha256": self.sha256,
            "json_equals": dict(self.json_equals) if self.json_equals is not None else None,
        }


@dataclass(frozen=True, slots=True)
class FileStateOracleSpec:
    """External assertions over the final evaluated workspace."""

    checks: tuple[FileStateCheck, ...]
    kind: OracleKind = field(default=OracleKind.FILE_STATE, init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.checks, (list, tuple)) or not self.checks or len(self.checks) > 256:
            raise CodingContractError("file-state oracle requires bounded checks")
        if any(not isinstance(check, FileStateCheck) for check in self.checks):
            raise CodingContractError("file-state oracle contains an invalid check")
        object.__setattr__(self, "checks", tuple(self.checks))

    def to_payload(self) -> dict[str, object]:
        return {"kind": self.kind.value, "checks": [check.to_payload() for check in self.checks]}


@dataclass(frozen=True, slots=True)
class DiffOracleSpec:
    """Deterministic constraints over the agent's source diff."""

    required_changed_files: tuple[str, ...] = ()
    forbidden_changed_files: tuple[str, ...] = ()
    min_changed_files: int = 0
    max_changed_files: int = 64
    max_insertions: int = 10_000
    max_deletions: int = 10_000
    max_diff_lines: int | None = None
    allow_binary: bool = False
    kind: OracleKind = field(default=OracleKind.DIFF, init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "required_changed_files", _require_path_tuple(self.required_changed_files, "diff.required_changed_files"))
        object.__setattr__(self, "forbidden_changed_files", _require_path_tuple(self.forbidden_changed_files, "diff.forbidden_changed_files"))
        if (
            type(self.min_changed_files) is not int
            or type(self.max_changed_files) is not int
            or type(self.max_insertions) is not int
            or type(self.max_deletions) is not int
            or self.max_insertions > 1_000_000
            or self.max_deletions > 1_000_000
            or self.max_insertions < 0
            or self.max_deletions < 0
            or (
                self.max_diff_lines is not None
                and (
                    type(self.max_diff_lines) is not int
                    or self.max_diff_lines < 0
                    or self.max_diff_lines > 1_000_000
                )
            )
            or type(self.allow_binary) is not bool
        ):
            raise CodingContractError("diff limits are invalid")
        if not 0 <= self.min_changed_files <= self.max_changed_files <= 10_000:
            raise CodingContractError("diff file count bounds are invalid")

    def to_payload(self) -> dict[str, object]:
        return {
            "kind": self.kind.value,
            "required_changed_files": list(self.required_changed_files),
            "forbidden_changed_files": list(self.forbidden_changed_files),
            "min_changed_files": self.min_changed_files,
            "max_changed_files": self.max_changed_files,
            "max_insertions": self.max_insertions,
            "max_deletions": self.max_deletions,
            "max_diff_lines": self.max_diff_lines,
            "allow_binary": self.allow_binary,
        }


@dataclass(frozen=True, slots=True)
class ReviewFindingExpectation:
    """One ground-truth code-review finding."""

    finding_id: str
    category: str
    file: str
    concepts: tuple[str, ...]
    severity: str = "medium"
    line: int | None = None
    line_tolerance: int = 3
    line_start: int | None = None
    line_end: int | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "finding_id", _require_id(self.finding_id, "finding_id"))
        object.__setattr__(self, "category", _require_text(self.category, "finding.category", max_bytes=256))
        object.__setattr__(self, "file", _require_path(self.file, "finding.file"))
        object.__setattr__(self, "concepts", _require_string_tuple(self.concepts, "finding.concepts", max_items=32))
        if self.severity not in {"low", "medium", "high", "critical"}:
            raise CodingContractError("finding severity is invalid")
        if self.line is not None and (type(self.line) is not int or self.line <= 0):
            raise CodingContractError("finding line must be positive")
        if type(self.line_tolerance) is not int or not 0 <= self.line_tolerance <= 20:
            raise CodingContractError("finding line_tolerance is invalid")
        for name in ("line_start", "line_end"):
            value = getattr(self, name)
            if value is not None and (type(value) is not int or value <= 0):
                raise CodingContractError(f"finding {name} must be positive")
        if self.line is not None:
            if self.line_start is not None and self.line_start != self.line:
                raise CodingContractError("finding line and line_start disagree")
            if self.line_end is not None and self.line_end != self.line:
                raise CodingContractError("finding line and line_end disagree")
            object.__setattr__(self, "line_start", self.line)
            object.__setattr__(self, "line_end", self.line)
        elif (self.line_start is None) != (self.line_end is None):
            raise CodingContractError("finding line range must have both endpoints")
        elif (
            self.line_start is not None
            and self.line_end is not None
            and self.line_start > self.line_end
        ):
            raise CodingContractError("finding line range is inverted")

    def to_payload(self) -> dict[str, object]:
        return {
            "finding_id": self.finding_id,
            "category": self.category,
            "file": self.file,
            "concepts": list(self.concepts),
            "severity": self.severity,
            "line": self.line,
            "line_tolerance": self.line_tolerance,
            "line_start": self.line_start,
            "line_end": self.line_end,
        }


@dataclass(frozen=True, slots=True)
class ReviewOracleSpec:
    """Ground-truth matching rules for a read-only code-review task."""

    required_findings: tuple[ReviewFindingExpectation, ...]
    allow_extra_findings: bool = True
    match_mode: FindingMatchMode = FindingMatchMode.ALL
    kind: OracleKind = field(default=OracleKind.REVIEW_FINDING, init=False)

    def __post_init__(self) -> None:
        if (
            not isinstance(self.required_findings, (list, tuple))
            or not self.required_findings
            or len(self.required_findings) > 128
        ):
            raise CodingContractError("review oracle requires bounded findings")
        if any(not isinstance(finding, ReviewFindingExpectation) for finding in self.required_findings):
            raise CodingContractError("review oracle contains an invalid finding")
        if type(self.allow_extra_findings) is not bool:
            raise CodingContractError("review allow_extra_findings must be boolean")
        try:
            match_mode = FindingMatchMode(self.match_mode)
        except (TypeError, ValueError) as exc:
            raise CodingContractError("review match_mode is invalid") from exc
        object.__setattr__(self, "required_findings", tuple(self.required_findings))
        object.__setattr__(self, "match_mode", match_mode)

    def to_payload(self) -> dict[str, object]:
        return {
            "kind": self.kind.value,
            "required_findings": [finding.to_payload() for finding in self.required_findings],
            "allow_extra_findings": self.allow_extra_findings,
            "match_mode": self.match_mode.value,
        }


OracleLeafSpec: TypeAlias = CommandOracleSpec | FileStateOracleSpec | DiffOracleSpec | ReviewOracleSpec


@dataclass(frozen=True, slots=True)
class CompositeOracleSpec:
    """AND-composition of typed child oracles."""

    children: tuple[OracleLeafSpec | CompositeOracleSpec, ...]
    kind: OracleKind = field(default=OracleKind.COMPOSITE, init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.children, (list, tuple)) or not self.children or len(self.children) > 16:
            raise CodingContractError("composite oracle requires bounded children")
        if any(not isinstance(child, (CommandOracleSpec, FileStateOracleSpec, DiffOracleSpec, ReviewOracleSpec, CompositeOracleSpec)) for child in self.children):
            raise CodingContractError("composite oracle contains an invalid child")
        object.__setattr__(self, "children", tuple(self.children))

    def to_payload(self) -> dict[str, object]:
        return {"kind": self.kind.value, "children": [child.to_payload() for child in self.children]}


OracleSpec: TypeAlias = OracleLeafSpec | CompositeOracleSpec


def oracle_from_payload(value: object) -> OracleSpec:
    data = _mapping(value, "scenario.oracle")
    kind_value = data.get("kind")
    try:
        kind = OracleKind(kind_value)
    except (TypeError, ValueError) as exc:
        raise CodingContractError("scenario.oracle.kind is invalid") from exc
    allowed: dict[OracleKind, frozenset[str]] = {
        OracleKind.COMMAND: frozenset({"kind", "argv", "cwd", "timeout_seconds", "max_output_bytes", "expected_exit_code", "hidden_files", "environment", "network"}),
        OracleKind.FILE_STATE: frozenset({"kind", "checks"}),
        OracleKind.DIFF: frozenset({"kind", "required_changed_files", "forbidden_changed_files", "min_changed_files", "max_changed_files", "max_insertions", "max_deletions", "max_diff_lines", "allow_binary"}),
        OracleKind.REVIEW_FINDING: frozenset({"kind", "required_findings", "allow_extra_findings", "match_mode"}),
        OracleKind.COMPOSITE: frozenset({"kind", "children"}),
    }
    if set(data) - allowed[kind]:
        raise CodingContractError("scenario.oracle contains unknown fields")
    if kind is OracleKind.COMMAND:
        environment = data.get("environment", {})
        if not isinstance(environment, dict):
            raise CodingContractError("oracle.environment must be an object")
        if any(not isinstance(key, str) or not isinstance(val, str) for key, val in environment.items()):
            raise CodingContractError("oracle.environment keys and values must be strings")
        cwd = data.get("cwd", ".")
        network = data.get("network", "none")
        if not isinstance(cwd, str) or not isinstance(network, str):
            raise CodingContractError("oracle cwd and network must be strings")
        return CommandOracleSpec(
            argv=tuple(_sequence(data.get("argv", ()), "oracle.argv")),
            cwd=cwd,
            timeout_seconds=_bounded_float(data.get("timeout_seconds"), "oracle.timeout_seconds", 120.0),
            max_output_bytes=_bounded_int(data.get("max_output_bytes"), "oracle.max_output_bytes", 64 * 1024),
            expected_exit_code=_bounded_int(data.get("expected_exit_code"), "oracle.expected_exit_code", 0),
            hidden_files=tuple(_sequence(data.get("hidden_files", ()), "oracle.hidden_files")),
            environment=tuple(sorted(environment.items())),
            network=network,
        )
    if kind is OracleKind.FILE_STATE:
        raw_checks = data.get("checks")
        if not isinstance(raw_checks, list):
            raise CodingContractError("file-state oracle checks must be a list")
        checks: list[FileStateCheck] = []
        for raw in raw_checks:
            item = _mapping(raw, "file_state.check")
            if set(item) - {"path", "exists", "contains", "not_contains", "sha256", "json_equals"}:
                raise CodingContractError("file-state check contains unknown fields")
            checks.append(FileStateCheck(**dict(item)))
        return FileStateOracleSpec(tuple(checks))
    if kind is OracleKind.DIFF:
        return DiffOracleSpec(
            required_changed_files=tuple(_sequence(data.get("required_changed_files", ()), "diff.required_changed_files")),
            forbidden_changed_files=tuple(_sequence(data.get("forbidden_changed_files", ()), "diff.forbidden_changed_files")),
            min_changed_files=_bounded_int(data.get("min_changed_files"), "diff.min_changed_files", 0),
            max_changed_files=_bounded_int(data.get("max_changed_files"), "diff.max_changed_files", 64),
            max_insertions=_bounded_int(data.get("max_insertions"), "diff.max_insertions", 10_000),
            max_deletions=_bounded_int(data.get("max_deletions"), "diff.max_deletions", 10_000),
            max_diff_lines=(
                _bounded_int(data.get("max_diff_lines"), "diff.max_diff_lines", 0)
                if "max_diff_lines" in data and data.get("max_diff_lines") is not None
                else None
            ),
            allow_binary=_bounded_bool(data.get("allow_binary"), "diff.allow_binary", False),
        )
    if kind is OracleKind.REVIEW_FINDING:
        raw_findings = data.get("required_findings")
        if not isinstance(raw_findings, list):
            raise CodingContractError("review required_findings must be a list")
        findings: list[ReviewFindingExpectation] = []
        for raw in raw_findings:
            item = _mapping(raw, "review.finding")
            if set(item) - {"finding_id", "category", "file", "concepts", "severity", "line", "line_tolerance", "line_start", "line_end"}:
                raise CodingContractError("review finding contains unknown fields")
            findings.append(ReviewFindingExpectation(**dict(item)))
        return ReviewOracleSpec(
            required_findings=tuple(findings),
            allow_extra_findings=_bounded_bool(data.get("allow_extra_findings"), "review.allow_extra_findings", True),
            match_mode=FindingMatchMode(data.get("match_mode", FindingMatchMode.ALL.value)),
        )
    raw_children = data.get("children")
    if not isinstance(raw_children, list):
        raise CodingContractError("composite oracle children must be a list")
    return CompositeOracleSpec(tuple(oracle_from_payload(child) for child in raw_children))


@dataclass(frozen=True, slots=True)
class CodingScenario:
    """One immutable, digest-bound coding evaluation scenario."""

    scenario_id: str
    version: int
    kind: CodingScenarioKind
    repository_fixture: str
    user_prompt: str
    limits: CodingResourceLimits
    languages: tuple[str, ...]
    oracle: OracleSpec
    difficulty: str = "medium"
    expected_files: tuple[str, ...] = ()
    forbidden_files: tuple[str, ...] = ()
    base_revision: str | None = None
    max_changed_files: int | None = None
    max_diff_lines: int | None = None
    tags: tuple[str, ...] = ()
    digest: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "scenario_id", _require_id(self.scenario_id, "scenario_id"))
        if type(self.version) is not int or self.version <= 0:
            raise CodingContractError("scenario.version must be positive")
        try:
            kind = CodingScenarioKind(self.kind)
        except (TypeError, ValueError) as exc:
            raise CodingContractError("scenario.kind is invalid") from exc
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "repository_fixture", _require_path(self.repository_fixture, "repository_fixture"))
        object.__setattr__(self, "user_prompt", _require_text(self.user_prompt, "user_prompt", max_bytes=64 * 1024))
        languages = _require_string_tuple(self.languages, "languages", max_items=8)
        if not languages or any(language not in _LANGUAGES for language in languages):
            raise CodingContractError("scenario.languages contains an unsupported language")
        object.__setattr__(self, "languages", languages)
        if not isinstance(self.difficulty, str) or self.difficulty not in {"easy", "medium", "hard"}:
            raise CodingContractError("scenario.difficulty is invalid")
        if not isinstance(self.limits, CodingResourceLimits):
            raise CodingContractError("scenario.limits is invalid")
        if not isinstance(self.oracle, (CommandOracleSpec, FileStateOracleSpec, DiffOracleSpec, ReviewOracleSpec, CompositeOracleSpec)):
            raise CodingContractError("scenario.oracle is invalid")
        if self.base_revision is not None:
            _require_text(self.base_revision, "base_revision", max_bytes=256)
        for name in ("max_changed_files", "max_diff_lines"):
            value = getattr(self, name)
            if value is not None and (type(value) is not int or value < 0):
                raise CodingContractError(f"scenario.{name} must be a non-negative integer")
        object.__setattr__(self, "expected_files", _require_path_tuple(self.expected_files, "expected_files"))
        object.__setattr__(self, "forbidden_files", _require_path_tuple(self.forbidden_files, "forbidden_files"))
        object.__setattr__(self, "tags", _require_string_tuple(self.tags, "tags", max_items=32))
        if set(self.expected_files) & set(self.forbidden_files):
            raise CodingContractError("expected_files and forbidden_files overlap")
        if not isinstance(self.digest, str):
            raise CodingContractError("scenario digest must be a string")
        expected_digest = canonical_digest(self._payload_without_digest())
        if self.digest and (not _SHA256_PATTERN.fullmatch(self.digest) or self.digest != expected_digest):
            raise CodingContractError("scenario digest does not match its canonical payload")
        object.__setattr__(self, "digest", expected_digest)

    def _payload_without_digest(self) -> dict[str, object]:
        return {
            "scenario_id": self.scenario_id,
            "version": self.version,
            "kind": self.kind.value,
            "repository_fixture": self.repository_fixture,
            "user_prompt": self.user_prompt,
            "limits": self.limits.to_payload(),
            "languages": list(self.languages),
            "oracle": self.oracle.to_payload(),
            "difficulty": self.difficulty,
            "expected_files": list(self.expected_files),
            "forbidden_files": list(self.forbidden_files),
            "base_revision": self.base_revision,
            "max_changed_files": self.max_changed_files,
            "max_diff_lines": self.max_diff_lines,
            "tags": list(self.tags),
        }

    def to_payload(self) -> dict[str, object]:
        return {**self._payload_without_digest(), "digest": self.digest}


@dataclass(frozen=True, slots=True)
class CodingScenarioManifest:
    """Closed, digest-bound collection of scenarios."""

    manifest_id: str
    version: int
    scenarios: tuple[CodingScenario, ...]
    digest: str = ""
    schema_version: int = 1

    def __post_init__(self) -> None:
        object.__setattr__(self, "manifest_id", _require_id(self.manifest_id, "manifest_id"))
        if (
            type(self.version) is not int
            or self.version <= 0
            or type(self.schema_version) is not int
            or self.schema_version != 1
        ):
            raise CodingContractError("manifest version is unsupported")
        if not isinstance(self.scenarios, (list, tuple)) or not self.scenarios or len(self.scenarios) > 10_000:
            raise CodingContractError("manifest must contain bounded scenarios")
        if any(not isinstance(scenario, CodingScenario) for scenario in self.scenarios):
            raise CodingContractError("manifest contains an invalid scenario")
        object.__setattr__(self, "scenarios", tuple(self.scenarios))
        ids = [scenario.scenario_id for scenario in self.scenarios]
        if len(set(ids)) != len(ids) or ids != sorted(ids):
            raise CodingContractError("manifest scenario ids must be unique and sorted")
        if not isinstance(self.digest, str):
            raise CodingContractError("manifest digest must be a string")
        expected_digest = canonical_digest(self._payload_without_digest())
        if self.digest and (not _SHA256_PATTERN.fullmatch(self.digest) or self.digest != expected_digest):
            raise CodingContractError("manifest digest does not match its canonical payload")
        object.__setattr__(self, "digest", expected_digest)

    def _payload_without_digest(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "manifest_id": self.manifest_id,
            "version": self.version,
            "scenarios": [scenario.to_payload() for scenario in self.scenarios],
        }

    def to_payload(self) -> dict[str, object]:
        return {**self._payload_without_digest(), "digest": self.digest}

    def get(self, scenario_id: str) -> CodingScenario:
        for scenario in self.scenarios:
            if scenario.scenario_id == scenario_id:
                return scenario
        raise KeyError(scenario_id)

    def select(self, *, tag: str | None = None, scenario_id: str | None = None) -> tuple[CodingScenario, ...]:
        if scenario_id is not None:
            return (self.get(scenario_id),)
        if tag is None:
            return self.scenarios
        return tuple(scenario for scenario in self.scenarios if tag in scenario.tags)


@dataclass(frozen=True, slots=True)
class CodingRunIdentity:
    """Immutable provenance binding for one evaluation run."""

    run_id: str
    scenario_id: str
    scenario_version: int
    scenario_digest: str
    oracle_spec_digest: str
    fixture_digest: str
    source_sha: str
    model: str
    provider: str
    config_digest: str
    runtime_profile: str
    runtime_id: str
    agent_version: str = "khaos"
    model_config_digest: str = ""
    reasoning_effort: str | None = None
    os_name: str = ""
    platform: str = ""
    python_version: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "run_id", _require_id(self.run_id, "run_id"))
        object.__setattr__(self, "scenario_id", _require_id(self.scenario_id, "scenario_id"))
        for name in ("scenario_digest", "oracle_spec_digest", "fixture_digest", "config_digest"):
            value = getattr(self, name)
            if not isinstance(value, str) or _SHA256_PATTERN.fullmatch(value) is None:
                raise CodingContractError(f"{name} must be a lowercase SHA-256")
        if not isinstance(self.model_config_digest, str):
            raise CodingContractError("model_config_digest must be a string")
        model_config_digest = self.model_config_digest or self.config_digest
        if _SHA256_PATTERN.fullmatch(model_config_digest) is None:
            raise CodingContractError("model_config_digest must be a lowercase SHA-256")
        object.__setattr__(self, "model_config_digest", model_config_digest)
        if self.reasoning_effort is not None:
            _require_text(self.reasoning_effort, "reasoning_effort", max_bytes=128)
        for name in ("os_name", "platform", "python_version"):
            value = getattr(self, name)
            if not isinstance(value, str):
                raise CodingContractError(f"{name} must be a string")
        object.__setattr__(self, "os_name", self.os_name or platform_module.system() or "unknown")
        object.__setattr__(self, "platform", self.platform or sys.platform or "unknown")
        object.__setattr__(self, "python_version", self.python_version or platform_module.python_version() or "unknown")
        if not isinstance(self.source_sha, str) or not self.source_sha:
            raise CodingContractError("source_sha must be present even when unknown")
        for name in ("model", "provider", "runtime_profile", "runtime_id", "agent_version"):
            _require_text(getattr(self, name), name, max_bytes=1024)
        if type(self.scenario_version) is not int or self.scenario_version <= 0:
            raise CodingContractError("scenario_version must be positive")

    def to_payload(self) -> dict[str, object]:
        return {
            "run_id": self.run_id,
            "scenario_id": self.scenario_id,
            "scenario_version": self.scenario_version,
            "scenario_digest": self.scenario_digest,
            "oracle_spec_digest": self.oracle_spec_digest,
            "fixture_digest": self.fixture_digest,
            "source_sha": self.source_sha,
            "model": self.model,
            "provider": self.provider,
            "config_digest": self.config_digest,
            "runtime_profile": self.runtime_profile,
            "runtime_id": self.runtime_id,
            "agent_version": self.agent_version,
            "model_config_digest": self.model_config_digest,
            "reasoning_effort": self.reasoning_effort,
            "os_name": self.os_name,
            "platform": self.platform,
            "python_version": self.python_version,
        }


def digest_payload(payload: object) -> str:
    """Expose the same canonical digest primitive to report/ledger code."""

    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


__all__ = [
    "CodingContractError",
    "CodingFailureReason",
    "CodingResourceLimits",
    "CodingRunIdentity",
    "CodingScenario",
    "CodingScenarioKind",
    "CodingScenarioManifest",
    "CodingVerdict",
    "CommandOracleSpec",
    "CompositeOracleSpec",
    "DiffOracleSpec",
    "FileStateCheck",
    "FileStateOracleSpec",
    "FindingMatchMode",
    "OracleKind",
    "OracleSpec",
    "ReviewFindingExpectation",
    "ReviewOracleSpec",
    "digest_payload",
    "oracle_from_payload",
]
