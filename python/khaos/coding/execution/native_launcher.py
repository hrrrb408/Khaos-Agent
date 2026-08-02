"""Build the process boundary used for host execution.

The Python event loop must not install a ``preexec_fn``.  A pre-exec callback
runs in the forked child while the interpreter is still alive and can deadlock
or leave security setup partially applied.  Production images therefore use
the root-owned Rust launcher.  An explicitly enabled development mode may use
the equivalent standalone Python launcher so unit tests remain runnable on a
checkout that has not built Rust yet; that process still performs all checks
before ``exec`` and is never selected by the production images.
"""

from __future__ import annotations

import os
import stat
import sys
from dataclasses import dataclass
from pathlib import Path

from khaos.coding.execution.binding import ExecutionDirectoryBinding
from khaos.coding.execution.models import ResourceBudget


@dataclass(frozen=True)
class ProcessLaunch:
    """Complete subprocess launch parameters after authority compilation."""

    argv: tuple[str, ...]
    cwd: str | None
    pass_fds: tuple[int, ...]
    start_new_session: bool


def build_process_launch(
    command: tuple[str, ...] | list[str],
    *,
    cwd: Path,
    directory_binding: ExecutionDirectoryBinding | None,
    budget: ResourceBudget | None,
    enforce_resource_limits: bool,
) -> ProcessLaunch:
    """Compile a safe launch into either the native or explicit dev boundary.

    The returned launch never contains ``preexec_fn``.  A native boundary is
    mandatory whenever a pinned directory or host rlimits are required.  On
    Windows those guarantees are unavailable and the caller fails closed.
    """
    command_tuple = tuple(str(value) for value in command)
    if not command_tuple:
        raise ValueError("execution command cannot be empty")
    needs_boundary = directory_binding is not None or (
        enforce_resource_limits and budget is not None
    )
    if not needs_boundary:
        return ProcessLaunch(
            argv=command_tuple,
            cwd=str(cwd),
            pass_fds=(),
            start_new_session=True,
        )
    if os.name != "posix":
        raise PermissionError(
            "host execution resource and directory guarantees are unsupported on this platform"
        )
    launcher = _find_launcher()
    development = launcher is None and os.environ.get("KHAOS_DEV_MODE") == "1"
    if launcher is None and not development:
        raise PermissionError(
            "native execution launcher is required; build khaos-exec-launcher "
            "or set KHAOS_DEV_MODE=1 for an explicit development fallback"
        )
    args = [launcher] if launcher is not None else [sys.executable, "-m", "khaos.coding.execution.native_launcher_runtime"]
    args.append("--new-session")
    if directory_binding is not None:
        args.extend(
            (
                "--root-fd",
                str(directory_binding.root_fd),
                "--root-device",
                str(directory_binding.root_identity[0]),
                "--root-inode",
                str(directory_binding.root_identity[1]),
                "--cwd-fd",
                str(directory_binding.cwd_fd),
                "--cwd-device",
                str(directory_binding.cwd_identity[0]),
                "--cwd-inode",
                str(directory_binding.cwd_identity[1]),
            )
        )
    if enforce_resource_limits and budget is not None:
        args.extend(
            (
                "--rlimit-fsize",
                str(_positive_limit(budget.file_bytes, "file_bytes")),
                "--rlimit-nofile",
                str(_positive_limit(budget.open_files, "open_files")),
                "--rlimit-cpu",
                str(max(1, int(budget.cpu_time_seconds + 0.999999))),
            )
        )
        if sys.platform != "darwin":
            args.extend(
                (
                    "--rlimit-as",
                    str(_positive_limit(budget.memory_bytes, "memory_bytes")),
                )
            )
    args.extend(("--", *command_tuple))
    return ProcessLaunch(
        argv=tuple(args),
        cwd=(None if directory_binding is not None else str(cwd)),
        pass_fds=(directory_binding.pass_fds if directory_binding is not None else ()),
        start_new_session=False,
    )


def _positive_limit(value: int, label: str) -> int:
    normalized = int(value)
    if normalized <= 0:
        raise ValueError(f"{label} must be positive")
    return normalized


def _find_launcher() -> str | None:
    """Return a trusted launcher, or the explicit development wrapper."""
    configured = os.environ.get("KHAOS_EXEC_LAUNCHER", "").strip()
    candidates = [Path(configured)] if configured else []
    candidates.extend(
        (
            Path("/usr/local/bin/khaos-exec-launcher"),
            Path(__file__).resolve().parents[4]
            / "rust"
            / "khaos-core"
            / "target"
            / "release"
            / "khaos-exec-launcher",
            Path(__file__).resolve().parents[4]
            / "rust"
            / "khaos-core"
            / "target"
            / "debug"
            / "khaos-exec-launcher",
        )
    )
    for candidate in candidates:
        if _is_secure_executable(candidate):
            return str(candidate)
    return None


def _is_secure_executable(path: Path) -> bool:
    """Reject symlinks and writable binary/parent paths in production."""
    try:
        info = path.lstat()
    except OSError:
        return False
    if not stat.S_ISREG(info.st_mode) or not (info.st_mode & 0o111):
        return False
    if info.st_mode & 0o022:
        return False
    if info.st_uid not in {0, os.geteuid()}:
        return False
    current = path.parent
    for _ in range(32):
        try:
            directory = current.lstat()
        except OSError:
            return False
        if not stat.S_ISDIR(directory.st_mode) or directory.st_mode & 0o022:
            return False
        if current.parent == current:
            break
        current = current.parent
    return True
