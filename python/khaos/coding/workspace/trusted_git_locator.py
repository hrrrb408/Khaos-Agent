"""Platform-owned location policy for the Trusted Git executable.

This module answers only *where the platform permits Khaos to look*.  It does
not decide whether a candidate is safe.  Candidate validation, identity
pinning, and digest checks belong to :mod:`trusted_git_policy`.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

_MACOS_SYSTEM_GIT = Path("/usr/bin/git")
_MACOS_COMMAND_LINE_TOOLS_GIT = Path(
    "/Library/Developer/CommandLineTools/usr/bin/git"
)
_LINUX_SYSTEM_GIT = Path("/usr/bin/git")
_WINDOWS_GIT = Path("C:/Program Files/Git/cmd/git.exe")
_MACOS_COMMAND_LINE_TOOLS_EXEC_PATH = Path(
    "/Library/Developer/CommandLineTools/usr/libexec/git-core"
)

_POSIX_TRUSTED_GIT_PATH = "/usr/bin:/bin"
_WINDOWS_TRUSTED_GIT_PATH = r"C:\Windows\System32;C:\Program Files\Git\cmd"


@runtime_checkable
class TrustedGitLocator(Protocol):
    """Provide platform-approved candidate paths in deterministic order."""

    def candidates(self) -> tuple[Path, ...]:
        """Return candidate paths without consulting caller-controlled PATH."""
        ...


@dataclass(frozen=True, slots=True)
class PlatformTrustedGitLocator:
    """Locate the small, statically-reviewed platform candidate set.

    macOS includes the system shim first and the separately installed Command
    Line Tools binary second.  The latter is intentionally not Homebrew or a
    user-installed executable; both paths are subsequently subjected to the
    same root-owner, parent-chain, identity, and digest policy.
    """

    def candidates(self) -> tuple[Path, ...]:
        """Return candidates ordered by the platform's fixed priority."""
        if os.name == "nt":
            return (_WINDOWS_GIT,)
        if sys.platform == "darwin":
            return (_MACOS_SYSTEM_GIT, _MACOS_COMMAND_LINE_TOOLS_GIT)
        return (_LINUX_SYSTEM_GIT,)


@dataclass(frozen=True, slots=True)
class StaticTrustedGitLocator:
    """Small deterministic locator used by policy/preflight contract tests."""

    paths: tuple[Path, ...]

    def candidates(self) -> tuple[Path, ...]:
        """Return the injected paths exactly in their declared order."""
        return self.paths


def trusted_git_path_environment() -> str:
    """Return the scrubbed PATH supplied to a Trusted Git child.

    This is an execution environment constant, not a lookup source.  The
    child is always started with an absolute executable path.
    """
    return _WINDOWS_TRUSTED_GIT_PATH if os.name == "nt" else _POSIX_TRUSTED_GIT_PATH


def trusted_git_exec_path(executable: Path) -> Path | None:
    """Return a statically-known Git helper directory for one candidate.

    Apple Command Line Tools Git is paired with this exact root-owned helper
    directory.  Other platforms retain Git's built-in executable discovery;
    no caller-provided ``GIT_EXEC_PATH`` is ever accepted.
    """
    if sys.platform == "darwin":
        try:
            canonical = executable.resolve(strict=False)
        except OSError:
            canonical = executable.absolute()
        if canonical == _MACOS_COMMAND_LINE_TOOLS_GIT:
            return _MACOS_COMMAND_LINE_TOOLS_EXEC_PATH
    return None


__all__ = [
    "PlatformTrustedGitLocator",
    "StaticTrustedGitLocator",
    "TrustedGitLocator",
    "trusted_git_exec_path",
    "trusted_git_path_environment",
]
