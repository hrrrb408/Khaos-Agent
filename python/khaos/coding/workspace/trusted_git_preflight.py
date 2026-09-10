"""Operational preflight and diagnostics for the pinned Trusted Git binary."""

from __future__ import annotations

import asyncio
import os
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from khaos.coding.execution.environment import scrub_spawn_environment
from khaos.coding.workspace.git_process import TrustedGitError, TrustedGitProcessOwner
from khaos.coding.workspace.trusted_git_locator import (
    PlatformTrustedGitLocator,
    TrustedGitLocator,
    trusted_git_exec_path,
    trusted_git_path_environment,
)
from khaos.coding.workspace.trusted_git_policy import (
    TrustedGitExecutableIdentity,
    TrustedGitExecutablePolicy,
    TrustedGitExecutablePolicyError,
)

_PREFLIGHT_TIMEOUT_SECONDS = 5.0
_PREFLIGHT_OUTPUT_BYTES = 64 * 1024
_PREFLIGHT_DIAGNOSTIC_BYTES = 4 * 1024
_APPLE_BLOCKED_MARKERS = (
    "xcodebuild",
    "developer tools",
    "apple sdk",
    "xcode",
)


class TrustedGitAvailability(str, Enum):
    """Machine-readable status for candidate selection and invocation."""

    AVAILABLE = "available"
    MISSING = "missing"
    CANDIDATE_NOT_FOUND = "missing"  # noqa: PIE796 - compatibility alias
    TRUST_REJECTED = "trust_rejected"
    TRUST_POLICY_REJECTED = "trust_rejected"  # noqa: PIE796 - compatibility alias
    IDENTITY_DRIFT = "identity_drift"
    INVOCATION_BLOCKED = "invocation_blocked"
    INVOCATION_FAILED = "invocation_failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"


@dataclass(frozen=True, slots=True)
class TrustedGitPreflightResult:
    """Bounded result from one absolute-path ``git --version`` invocation."""

    status: TrustedGitAvailability
    candidate: Path
    identity: TrustedGitExecutableIdentity | None = None
    returncode: int | None = None
    stdout: str = ""
    stderr: str = ""
    diagnostic: str = ""

    @property
    def classification(self) -> str:
        """Return the external diagnostic class used by tests and CLI."""
        if self.status is TrustedGitAvailability.INVOCATION_BLOCKED:
            return "ENVIRONMENT_BLOCKED"
        return self.status.value.upper()

    @property
    def environment_blocked(self) -> bool:
        """Whether this is a known host toolchain blocker, not Git failure."""
        return self.status is TrustedGitAvailability.INVOCATION_BLOCKED

    def as_dict(self) -> dict[str, object]:
        """Return bounded JSON-safe diagnostics without ambient environment."""
        identity = self.identity
        return {
            "status": self.status.value,
            "classification": self.classification,
            "candidate": str(self.candidate),
            "canonical_path": str(identity.path) if identity is not None else None,
            "identity": list(identity.file_identity) if identity is not None else None,
            "digest": identity.sha256 if identity is not None else None,
            "returncode": self.returncode,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "diagnostic": self.diagnostic,
        }


@dataclass(frozen=True, slots=True)
class TrustedGitCandidateDiagnostic:
    """Doctor record for one locator candidate."""

    candidate: Path
    policy: dict[str, object]
    preflight: TrustedGitPreflightResult | None

    def as_dict(self) -> dict[str, object]:
        """Return the candidate record in a JSON-safe form."""
        value = dict(self.policy)
        value["preflight"] = self.preflight.as_dict() if self.preflight else None
        return value


@dataclass(frozen=True, slots=True)
class TrustedGitDiagnosticReport:
    """Complete bounded report used by ``khaos doctor trusted-git``."""

    status: TrustedGitAvailability
    selected: TrustedGitPreflightResult | None
    candidates: tuple[TrustedGitCandidateDiagnostic, ...]

    @property
    def classification(self) -> str:
        """Return the report-level diagnostic classification."""
        if self.selected is not None:
            return self.selected.classification
        for candidate in self.candidates:
            if candidate.preflight is not None:
                return candidate.preflight.classification
        return self.status.value.upper()

    def as_dict(self) -> dict[str, object]:
        """Return bounded machine-readable doctor output."""
        return {
            "status": self.status.value,
            "classification": self.classification,
            "selected": self.selected.as_dict() if self.selected else None,
            "candidates": [candidate.as_dict() for candidate in self.candidates],
        }


def build_trusted_git_environment(
    executable: Path,
    *,
    home: Path,
) -> dict[str, str]:
    """Build the same scrubbed, pinned environment used by Git operations."""
    environment = {
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": os.devnull,
        "SSH_ASKPASS": os.devnull,
        "GIT_PAGER": "cat",
        "PAGER": "cat",
        "GIT_EDITOR": ":",
        "GIT_SEQUENCE_EDITOR": ":",
        "GIT_OPTIONAL_LOCKS": "0",
        "PATH": trusted_git_path_environment(),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "HOME": str(home),
    }
    exec_path = trusted_git_exec_path(executable)
    if exec_path is not None:
        environment["GIT_EXEC_PATH"] = str(exec_path)
    return scrub_spawn_environment(
        environment,
        preserve={
            "GIT_CONFIG_GLOBAL",
            "GIT_CONFIG_SYSTEM",
            "GIT_TERMINAL_PROMPT",
            "GIT_ASKPASS",
            "SSH_ASKPASS",
            "GIT_PAGER",
            "PAGER",
            "GIT_EXEC_PATH",
        },
    )


def classify_invocation_failure(
    *,
    returncode: int | None,
    stderr: str,
    platform: str | None = None,
) -> TrustedGitAvailability:
    """Conservatively classify a non-zero Git preflight result."""
    current_platform = sys.platform if platform is None else platform
    lowered = stderr.casefold()
    if (
        current_platform == "darwin"
        and returncode == 69
        and any(marker in lowered for marker in _APPLE_BLOCKED_MARKERS)
    ):
        return TrustedGitAvailability.INVOCATION_BLOCKED
    return TrustedGitAvailability.INVOCATION_FAILED


def _bounded_text(value: bytes, *, limit: int = _PREFLIGHT_DIAGNOSTIC_BYTES) -> str:
    return value[:limit].decode("utf-8", errors="replace").strip()


def _diagnostic(status: TrustedGitAvailability, *, stderr: str, returncode: int | None) -> str:
    if status is TrustedGitAvailability.INVOCATION_BLOCKED:
        return "host developer toolchain refused Trusted Git invocation"
    if stderr:
        return stderr
    if returncode is None:
        return status.value.replace("_", " ")
    return f"git --version returned exit code {returncode}"


async def run_trusted_git_preflight(
    identity: TrustedGitExecutableIdentity,
    owner: TrustedGitProcessOwner,
    *,
    cwd: Path,
    environment: Mapping[str, str] | None = None,
    timeout_seconds: float = _PREFLIGHT_TIMEOUT_SECONDS,
) -> TrustedGitPreflightResult:
    """Run the bounded no-repository preflight through one process owner."""
    if timeout_seconds <= 0:
        raise ValueError("Trusted Git preflight timeout must be positive")
    selected_environment = dict(
        environment
        or build_trusted_git_environment(identity.path, home=cwd)
    )
    try:
        stdout, stderr, returncode = await asyncio.wait_for(
            owner.communicate_bounded_after_spawn(
                str(identity.path),
                "--version",
                cwd=str(cwd),
                env=selected_environment,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                max_stdout_bytes=_PREFLIGHT_OUTPUT_BYTES,
                max_stderr_bytes=_PREFLIGHT_OUTPUT_BYTES,
            ),
            timeout=timeout_seconds,
        )
    except TimeoutError:
        return TrustedGitPreflightResult(
            TrustedGitAvailability.TIMEOUT,
            identity.path,
            identity,
            returncode=getattr(owner.process, "returncode", None),
            diagnostic="trusted Git preflight exceeded its bounded timeout",
        )
    except asyncio.CancelledError:
        raise
    except (OSError, TrustedGitError) as exc:
        return TrustedGitPreflightResult(
            TrustedGitAvailability.INVOCATION_FAILED,
            identity.path,
            identity,
            returncode=getattr(owner.process, "returncode", None),
            diagnostic=str(exc) or "trusted Git preflight could not start",
        )

    stdout_text = _bounded_text(stdout)
    stderr_text = _bounded_text(stderr)
    if returncode == 0:
        return TrustedGitPreflightResult(
            TrustedGitAvailability.AVAILABLE,
            identity.path,
            identity,
            returncode=returncode,
            stdout=stdout_text,
            stderr=stderr_text,
            diagnostic="git --version completed successfully",
        )
    status = classify_invocation_failure(
        returncode=returncode,
        stderr=stderr_text,
    )
    return TrustedGitPreflightResult(
        status,
        identity.path,
        identity,
        returncode=returncode,
        stdout=stdout_text,
        stderr=stderr_text,
        diagnostic=_diagnostic(status, stderr=stderr_text, returncode=returncode),
    )


async def diagnose_trusted_git(
    *,
    locator: TrustedGitLocator | None = None,
    policy: TrustedGitExecutablePolicy | None = None,
    cwd: Path | None = None,
) -> TrustedGitDiagnosticReport:
    """Inspect every static candidate and run bounded preflight as needed."""
    selected_locator = locator or PlatformTrustedGitLocator()
    selected_policy = policy or TrustedGitExecutablePolicy()
    preflight_cwd = cwd or (Path("C:/") if os.name == "nt" else Path("/"))
    records: list[TrustedGitCandidateDiagnostic] = []
    selected: TrustedGitPreflightResult | None = None
    allow_static_fallback = True
    for candidate in selected_locator.candidates():
        policy_record = selected_policy.inspect(candidate)
        if policy_record.get("status") != "policy_validated" or not allow_static_fallback:
            records.append(TrustedGitCandidateDiagnostic(candidate, policy_record, None))
            continue
        try:
            identity = selected_policy.validate(candidate)
        except TrustedGitExecutablePolicyError as exc:
            policy_record["status"] = "trust_rejected"
            policy_record["diagnostic"] = str(exc)
            records.append(TrustedGitCandidateDiagnostic(candidate, policy_record, None))
            continue
        owner = TrustedGitProcessOwner("git.doctor-preflight")
        result = await run_trusted_git_preflight(
            identity,
            owner,
            cwd=preflight_cwd,
            environment=build_trusted_git_environment(identity.path, home=preflight_cwd),
        )
        try:
            await owner.close()
        except TrustedGitError as exc:
            result = TrustedGitPreflightResult(
                TrustedGitAvailability.INVOCATION_FAILED,
                identity.path,
                identity,
                returncode=result.returncode,
                stdout=result.stdout,
                stderr=result.stderr,
                diagnostic=f"{result.diagnostic}; process terminal proof failed: {exc}",
            )
        records.append(TrustedGitCandidateDiagnostic(candidate, policy_record, result))
        if selected is None and result.status is TrustedGitAvailability.AVAILABLE:
            selected = result
            break
        if result.status is not TrustedGitAvailability.INVOCATION_BLOCKED:
            allow_static_fallback = False
    if selected is not None:
        return TrustedGitDiagnosticReport(
            TrustedGitAvailability.AVAILABLE,
            selected,
            tuple(records),
        )
    statuses = [
        record.preflight.status
        for record in records
        if record.preflight is not None
    ]
    if statuses:
        status = (
            TrustedGitAvailability.INVOCATION_BLOCKED
            if TrustedGitAvailability.INVOCATION_BLOCKED in statuses
            else statuses[-1]
        )
    elif records:
        categories = {record.policy.get("category") for record in records}
        status = (
            TrustedGitAvailability.TRUST_REJECTED
            if any(category != "candidate_not_found" for category in categories)
            else TrustedGitAvailability.MISSING
        )
    else:
        status = TrustedGitAvailability.MISSING
    return TrustedGitDiagnosticReport(status, None, tuple(records))


def format_preflight_error(result: TrustedGitPreflightResult) -> str:
    """Render one actionable, non-secret runtime diagnostic."""
    candidate = result.identity.path if result.identity is not None else result.candidate
    exit_code = "unknown" if result.returncode is None else str(result.returncode)
    if result.environment_blocked:
        prefix = "trusted Git control-plane dependency is blocked by the host environment"
        diagnostic = (
            "host developer toolchain refused Trusted Git invocation; "
            "inspect `khaos doctor trusted-git` for bounded host diagnostics"
        )
    elif result.status is TrustedGitAvailability.TRUST_REJECTED:
        prefix = "trusted Git executable was rejected by the trust policy"
        diagnostic = result.diagnostic or "none"
    else:
        prefix = "trusted Git control-plane invocation failed"
        diagnostic = result.diagnostic or "none"
    return (
        f"{prefix}; candidate={candidate}; classification={result.classification}; "
        f"exit_code={exit_code}; diagnostic={diagnostic}"
    )


__all__ = [
    "TrustedGitAvailability",
    "TrustedGitCandidateDiagnostic",
    "TrustedGitDiagnosticReport",
    "TrustedGitPreflightResult",
    "build_trusted_git_environment",
    "classify_invocation_failure",
    "diagnose_trusted_git",
    "format_preflight_error",
    "run_trusted_git_preflight",
]
