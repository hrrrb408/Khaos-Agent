"""Immutable contracts for the M8.3 autonomous verification planner.

The contracts in this module deliberately contain selection metadata and
bounded evidence only.  They do not contain a shell command, a permission,
an approval, a completion token, or repository content.  ``ExecutionService``
and the existing trusted-verification authority remain the owners of those
boundaries.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from enum import Enum, IntEnum
from pathlib import PurePosixPath

from khaos.security.protocol_boundary import canonical_digest

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_CONTROL_TOKENS = (";", "&&", "||", "|", ">", "<", "`", "$(")
_FORBIDDEN_LAUNCHERS = frozenset(
    {
        "sh",
        "bash",
        "zsh",
        "fish",
        "cmd",
        "cmd.exe",
        "powershell",
        "powershell.exe",
        "pwsh",
        "pwsh.exe",
    }
)
_AUTO_FIX_TOKENS = frozenset(
    {"--fix", "--fix-only", "--unsafe-fixes", "--write", "--write-changes", "fix"}
)
_MAX_ID = 512
_MAX_REASON = 512
_MAX_PATH = 1024
_MAX_ARGV = 64
_MAX_ARGV_BYTES = 8192
_MAX_DIAGNOSTICS = 64


class VerificationContractError(ValueError):
    """Raised when an M8.3 verification contract is malformed."""


class VerificationStage(IntEnum):
    """Ordered verification stages from cheapest to broadest."""

    STRUCTURAL = 0
    STATIC = 1
    TYPECHECK = 2
    TARGETED = 3
    MODULE = 4
    INTEGRATION = 5
    REGRESSION = 6


class VerificationCheckKind(str, Enum):
    """Closed set of checks the planner may select."""

    PARSE = "parse"
    FORMAT = "format"
    LINT = "lint"
    TYPECHECK = "typecheck"
    TARGETED_TEST = "targeted_test"
    PACKAGE_TEST = "package_test"
    INTEGRATION_TEST = "integration_test"
    BUILD = "build"
    REGRESSION = "regression"
    CUSTOM_PROJECT_CHECK = "custom_project_check"
    # Reserved extension points.  M8.3 never schedules these kinds; a later
    # browser/UI harness must introduce its own explicit authority path.
    BROWSER = "browser"
    UI = "ui"


class VerificationCheckStatus(str, Enum):
    """Outcome of one bounded execution."""

    PASSED = "passed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"
    STALE = "stale"
    INFRASTRUCTURE_ERROR = "infrastructure_error"
    UNKNOWN = "unknown"


# ``VerificationEvidence`` uses the per-check vocabulary while callers that
# aggregate a run use ``VerificationRunStatus`` below.  Keep the concise
# contract name available for integrations following the M8.3 terminology.
VerificationStatus = VerificationCheckStatus


class VerificationRunStatus(str, Enum):
    """Aggregate outcome of one planner/executor attempt."""

    PLANNED = "planned"
    RUNNING = "running"
    PASSED = "passed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"
    STALE = "stale"
    INFRASTRUCTURE_ERROR = "infrastructure_error"
    UNKNOWN = "unknown"


class VerificationRisk(str, Enum):
    """Conservative risk bucket used to widen check selection."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class VerificationCost(str, Enum):
    """Planner estimate used only for deterministic ordering."""

    CHEAP = "cheap"
    NORMAL = "normal"
    EXPENSIVE = "expensive"


class DiagnosticCategory(str, Enum):
    """Conservative diagnostic categories."""

    SYNTAX = "syntax"
    FORMAT = "format"
    LINT = "lint"
    TYPE = "type"
    TEST = "test"
    BUILD = "build"
    TIMEOUT = "timeout"
    INFRASTRUCTURE = "infrastructure"
    UNSTRUCTURED = "unstructured"


class DiagnosticSeverity(str, Enum):
    """Diagnostic severity parsed from an untrusted execution stream."""

    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


def _text(value: object, *, label: str, allow_empty: bool = False, limit: int = _MAX_ID) -> str:
    if type(value) is not str or (not allow_empty and not value):
        raise VerificationContractError(f"{label} must be a string")
    if len(value) > limit:
        raise VerificationContractError(f"{label} exceeds its bound")
    if "\x00" in value:
        raise VerificationContractError(f"{label} contains a NUL byte")
    return value


def _digest(value: object, *, label: str, allow_empty: bool = False) -> str:
    if allow_empty and value == "":
        return ""
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise VerificationContractError(f"{label} must be a SHA-256 digest")
    return value


def _path(value: object, *, label: str, allow_dot: bool = False) -> str:
    text = _text(value, label=label, limit=_MAX_PATH)
    normalized = text.replace("\\", "/")
    if normalized in {".", "./"}:
        if allow_dot:
            return "."
        raise VerificationContractError(f"{label} must not be the workspace root")
    if normalized.startswith("/") or (len(normalized) >= 2 and normalized[1] == ":"):
        raise VerificationContractError(f"{label} must be workspace-relative")
    candidate = PurePosixPath(normalized)
    if not candidate.parts:
        raise VerificationContractError(f"{label} must not be empty")
    if any(part in {"", ".."} for part in candidate.parts):
        raise VerificationContractError(f"{label} contains traversal")
    if not allow_dot and candidate.as_posix() == ".":
        raise VerificationContractError(f"{label} must not be the workspace root")
    if any(part.casefold() in {".git", ".agents", ".codex", ".khaos"} for part in candidate.parts):
        raise VerificationContractError(f"{label} reaches protected metadata")
    return candidate.as_posix()


def _string_tuple(value: object, *, label: str, path_values: bool = False) -> tuple[str, ...]:
    if type(value) is not tuple:
        raise VerificationContractError(f"{label} must be a tuple")
    normalized = tuple(
        (_path(item, label=label, allow_dot=True) if path_values else _text(item, label=label))
        for item in value
    )
    if len(normalized) != len(set(normalized)):
        raise VerificationContractError(f"{label} contains duplicates")
    return tuple(sorted(normalized))


def _argv(value: object) -> tuple[str, ...]:
    if type(value) is not tuple or not value or len(value) > _MAX_ARGV:
        raise VerificationContractError("argv must be a non-empty immutable tuple")
    result: list[str] = []
    total = 0
    for index, token in enumerate(value):
        item = _text(token, label="argv", limit=1024)
        if any(control in item for control in _CONTROL_TOKENS):
            raise VerificationContractError("argv contains shell control syntax")
        if item.startswith("/") or (len(item) >= 2 and item[1] == ":"):
            raise VerificationContractError("argv must not contain absolute paths")
        if index == 0 and PurePosixPath(item).name.casefold() in _FORBIDDEN_LAUNCHERS:
            raise VerificationContractError("shell launchers are not verification commands")
        if item in {"-c", "--command", "--eval", "-e", "--shell"}:
            raise VerificationContractError("inline or shell evaluation is not allowed")
        if item.casefold() in _AUTO_FIX_TOKENS:
            raise VerificationContractError("automatic-fix commands are not verification commands")
        result.append(item)
        total += len(item.encode("utf-8")) + 1
    if total > _MAX_ARGV_BYTES:
        raise VerificationContractError("argv exceeds its byte bound")
    return tuple(result)


@dataclass(frozen=True, slots=True)
class VerificationReason:
    """A bounded, deterministic reason for selecting or widening a check."""

    code: str
    message: str
    paths: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _text(self.code, label="reason code", limit=128)
        _text(self.message, label="reason message", limit=_MAX_REASON)
        object.__setattr__(self, "paths", _string_tuple(self.paths, label="reason paths", path_values=True))

    def to_payload(self) -> dict[str, object]:
        return {"code": self.code, "message": self.message, "paths": self.paths}


@dataclass(frozen=True, slots=True)
class VerificationDiagnostic:
    """One parsed diagnostic; all text is untrusted observation data."""

    category: DiagnosticCategory
    severity: DiagnosticSeverity
    message: str
    path: str | None = None
    line: int | None = None
    column: int | None = None
    source: str = "execution"
    related_paths: tuple[str, ...] = ()
    # These fields keep repair localization explicit without trusting the
    # diagnostic text.  ``check_id`` is empty only for run-level synthetic
    # diagnostics (for example a stale-plan observation).
    symbol: str | None = None
    check_id: str = ""
    related_changed_paths: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        category = self.category
        severity = self.severity
        if isinstance(category, str):
            category = DiagnosticCategory(category)
            object.__setattr__(self, "category", category)
        if isinstance(severity, str):
            severity = DiagnosticSeverity(severity)
            object.__setattr__(self, "severity", severity)
        if type(category) is not DiagnosticCategory or type(severity) is not DiagnosticSeverity:
            raise VerificationContractError("diagnostic enum is invalid")
        _text(self.message, label="diagnostic message", limit=2048)
        if self.path is not None:
            object.__setattr__(self, "path", _path(self.path, label="diagnostic path"))
        for label, value in (("line", self.line), ("column", self.column)):
            if value is not None and (type(value) is not int or value <= 0):
                raise VerificationContractError(f"{label} must be a positive integer")
        _text(self.source, label="diagnostic source", limit=128)
        if self.symbol is not None:
            _text(self.symbol, label="diagnostic symbol", limit=_MAX_ID)
        _text(self.check_id, label="diagnostic check_id", allow_empty=True, limit=_MAX_ID)
        object.__setattr__(
            self,
            "related_paths",
            _string_tuple(self.related_paths, label="diagnostic related paths", path_values=True),
        )
        object.__setattr__(
            self,
            "related_changed_paths",
            _string_tuple(
                self.related_changed_paths,
                label="diagnostic related changed paths",
                path_values=True,
            ),
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "category": self.category.value,
            "severity": self.severity.value,
            "message": self.message,
            "path": self.path,
            "line": self.line,
            "column": self.column,
            "source": self.source,
            "related_paths": self.related_paths,
            "symbol": self.symbol,
            "check_id": self.check_id,
            "related_changed_paths": self.related_changed_paths,
        }


@dataclass(frozen=True, slots=True)
class VerificationCheck:
    """One planner-selected structured command."""

    check_id: str
    kind: VerificationCheckKind
    stage: VerificationStage
    argv: tuple[str, ...]
    cwd: str
    command_id: str
    profile_digest: str
    source: str
    timeout_seconds: float = 120.0
    output_limit_bytes: int = 65_536
    expected_exit_codes: tuple[int, ...] = (0,)
    required: bool = True
    target_paths: tuple[str, ...] = ()
    target_symbols: tuple[str, ...] = ()
    reason_codes: tuple[str, ...] = ()
    cost: VerificationCost = VerificationCost.NORMAL

    def __post_init__(self) -> None:
        _text(self.check_id, label="check_id")
        kind = self.kind
        if isinstance(kind, str):
            kind = VerificationCheckKind(kind)
            object.__setattr__(self, "kind", kind)
        if type(kind) is not VerificationCheckKind:
            raise VerificationContractError("check kind is invalid")
        stage = self.stage
        if isinstance(stage, int) and not isinstance(stage, bool):
            stage = VerificationStage(stage)
            object.__setattr__(self, "stage", stage)
        if type(stage) is not VerificationStage:
            raise VerificationContractError("verification stage is invalid")
        object.__setattr__(self, "argv", _argv(self.argv))
        object.__setattr__(self, "cwd", _path(self.cwd, label="cwd", allow_dot=True))
        _text(self.command_id, label="command_id")
        object.__setattr__(self, "profile_digest", _digest(self.profile_digest, label="profile_digest"))
        _text(self.source, label="source")
        if (
            type(self.timeout_seconds) not in (int, float)
            or not math.isfinite(float(self.timeout_seconds))
            or self.timeout_seconds <= 0
        ):
            raise VerificationContractError("timeout_seconds must be finite and positive")
        if type(self.output_limit_bytes) is not int or self.output_limit_bytes <= 0:
            raise VerificationContractError("output_limit_bytes must be positive")
        if type(self.expected_exit_codes) is not tuple or not self.expected_exit_codes:
            raise VerificationContractError("expected_exit_codes must be a tuple")
        if any(type(code) is not int for code in self.expected_exit_codes):
            raise VerificationContractError("expected exit codes must be integers")
        if type(self.required) is not bool:
            raise VerificationContractError("required must be a bool")
        object.__setattr__(self, "target_paths", _string_tuple(self.target_paths, label="target paths", path_values=True))
        object.__setattr__(self, "target_symbols", _string_tuple(self.target_symbols, label="target symbols"))
        object.__setattr__(self, "reason_codes", _string_tuple(self.reason_codes, label="reason codes"))
        cost = self.cost
        if isinstance(cost, str):
            cost = VerificationCost(cost)
            object.__setattr__(self, "cost", cost)
        if type(cost) is not VerificationCost:
            raise VerificationContractError("verification cost is invalid")

    @property
    def command_digest(self) -> str:
        """Return the digest of the exact structured command semantics."""
        return canonical_digest(
            {
                "check_id": self.check_id,
                "kind": self.kind.value,
                "stage": int(self.stage),
                "argv": self.argv,
                "cwd": self.cwd,
                "command_id": self.command_id,
                "profile_digest": self.profile_digest,
                "source": self.source,
                "timeout_seconds": self.timeout_seconds,
                "output_limit_bytes": self.output_limit_bytes,
                "expected_exit_codes": self.expected_exit_codes,
                "required": self.required,
                "target_paths": self.target_paths,
                "target_symbols": self.target_symbols,
            }
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "check_id": self.check_id,
            "kind": self.kind.value,
            "stage": int(self.stage),
            "argv": self.argv,
            "cwd": self.cwd,
            "command_id": self.command_id,
            "profile_digest": self.profile_digest,
            "source": self.source,
            "timeout_seconds": self.timeout_seconds,
            "output_limit_bytes": self.output_limit_bytes,
            "expected_exit_codes": self.expected_exit_codes,
            "required": self.required,
            "target_paths": self.target_paths,
            "target_symbols": self.target_symbols,
            "reason_codes": self.reason_codes,
            "cost": self.cost.value,
            "command_digest": self.command_digest,
        }


@dataclass(frozen=True, slots=True)
class VerificationPlan:
    """Generation-bound immutable plan produced by the autonomous planner."""

    plan_id: str
    workspace_id: str
    workspace_generation: int
    repository_generation: int
    impact_digest: str
    profile_id: str
    profile_digest: str
    checks: tuple[VerificationCheck, ...]
    risk: VerificationRisk
    reasons: tuple[VerificationReason, ...] = ()
    edit_transaction_id: str | None = None
    edit_transaction_digest: str | None = None
    max_checks: int = 16
    max_total_seconds: float = 600.0
    max_output_bytes: int = 65_536
    planner_version: str = "m8.3-v1"
    plan_digest: str = ""

    def __post_init__(self) -> None:
        _text(self.plan_id, label="plan_id")
        _text(self.workspace_id, label="workspace_id")
        for label, value in (("workspace_generation", self.workspace_generation), ("repository_generation", self.repository_generation)):
            if type(value) is not int or value < 0:
                raise VerificationContractError(f"{label} must be a non-negative integer")
        object.__setattr__(self, "impact_digest", _digest(self.impact_digest, label="impact_digest"))
        _text(self.profile_id, label="profile_id")
        object.__setattr__(self, "profile_digest", _digest(self.profile_digest, label="profile_digest"))
        if type(self.max_checks) is not int or self.max_checks <= 0:
            raise VerificationContractError("max_checks must be positive")
        if type(self.checks) is not tuple or len(self.checks) > self.max_checks:
            raise VerificationContractError("checks exceed the plan bound")
        if any(type(check) is not VerificationCheck for check in self.checks):
            raise VerificationContractError("checks must contain VerificationCheck values")
        if len({check.check_id for check in self.checks}) != len(self.checks):
            raise VerificationContractError("check IDs must be unique")
        stages = [int(check.stage) for check in self.checks]
        if stages != sorted(stages):
            raise VerificationContractError("checks must be ordered by verification stage")
        if (
            type(self.max_total_seconds) not in (int, float)
            or not math.isfinite(float(self.max_total_seconds))
            or self.max_total_seconds <= 0
        ):
            raise VerificationContractError("max_total_seconds must be finite and positive")
        if sum(check.timeout_seconds for check in self.checks) > self.max_total_seconds:
            raise VerificationContractError("check timeouts exceed the plan budget")
        if type(self.max_output_bytes) is not int or self.max_output_bytes <= 0:
            raise VerificationContractError("max_output_bytes must be positive")
        if self.edit_transaction_id is not None:
            _text(self.edit_transaction_id, label="edit_transaction_id")
        if self.edit_transaction_digest is not None:
            object.__setattr__(
                self,
                "edit_transaction_digest",
                _digest(self.edit_transaction_digest, label="edit_transaction_digest"),
            )
        risk = self.risk
        if isinstance(risk, str):
            risk = VerificationRisk(risk)
            object.__setattr__(self, "risk", risk)
        if type(risk) is not VerificationRisk:
            raise VerificationContractError("verification risk is invalid")
        if type(self.reasons) is not tuple or any(type(item) is not VerificationReason for item in self.reasons):
            raise VerificationContractError("reasons must contain VerificationReason values")
        _text(self.planner_version, label="planner_version", limit=128)
        computed = self._computed_digest()
        if self.plan_digest:
            object.__setattr__(self, "plan_digest", _digest(self.plan_digest, label="plan_digest"))
            if self.plan_digest != computed:
                raise VerificationContractError("plan_digest does not match plan semantics")
        else:
            object.__setattr__(self, "plan_digest", computed)

    def _payload_without_digest(self) -> dict[str, object]:
        return {
            "plan_id": self.plan_id,
            "workspace_id": self.workspace_id,
            "workspace_generation": self.workspace_generation,
            "repository_generation": self.repository_generation,
            "impact_digest": self.impact_digest,
            "profile_id": self.profile_id,
            "profile_digest": self.profile_digest,
            "checks": tuple(check.to_payload() for check in self.checks),
            "risk": self.risk.value,
            "reasons": tuple(reason.to_payload() for reason in self.reasons),
            "edit_transaction_id": self.edit_transaction_id,
            "edit_transaction_digest": self.edit_transaction_digest,
            "max_checks": self.max_checks,
            "max_total_seconds": self.max_total_seconds,
            "max_output_bytes": self.max_output_bytes,
            "planner_version": self.planner_version,
        }

    def _computed_digest(self) -> str:
        return canonical_digest(self._payload_without_digest())

    def is_valid(self) -> bool:
        """Return whether the stored digest still covers the plan."""
        return self.plan_digest == self._computed_digest()

    @property
    def required_checks(self) -> tuple[VerificationCheck, ...]:
        """Return required checks in the immutable planner order."""
        return tuple(check for check in self.checks if check.required)

    @property
    def rationale(self) -> tuple[VerificationReason, ...]:
        """Compatibility vocabulary for callers that call reasons rationale."""
        return self.reasons

    def to_payload(self) -> dict[str, object]:
        payload = self._payload_without_digest()
        payload["plan_digest"] = self.plan_digest
        return payload


__all__ = [
    "DiagnosticCategory",
    "DiagnosticSeverity",
    "VerificationCheck",
    "VerificationCheckKind",
    "VerificationCheckStatus",
    "VerificationContractError",
    "VerificationCost",
    "VerificationDiagnostic",
    "VerificationPlan",
    "VerificationReason",
    "VerificationRisk",
    "VerificationRunStatus",
    "VerificationStage",
    "VerificationStatus",
]
