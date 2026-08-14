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
from khaos.coding.execution.identity import (
    ExecutableAuthority,
    open_executable_authority,
)
from khaos.coding.execution.models import ResourceBudget
from khaos.coding.execution.receipt_binding import execution_binding_digest
from khaos.security.authority_broker import EffectCapability
from khaos.security.authorityd_protocol import (
    AuthorityReceiptFDs,
    SignedAuthorizationReceipt,
    open_authority_receipt_fds,
)


@dataclass(frozen=True)
class ProcessLaunch:
    """Complete subprocess launch parameters after authority compilation."""

    argv: tuple[str, ...]
    cwd: str | None
    pass_fds: tuple[int, ...]
    start_new_session: bool
    executable_authority: ExecutableAuthority | None = None
    authority_receipt_handles: AuthorityReceiptFDs | None = None
    authority_capability: EffectCapability | None = None

    def close_owned_fds(self) -> None:
        """Close parent-side executable authority descriptors after spawn."""
        if self.executable_authority is not None:
            self.executable_authority.close()
        if self.authority_receipt_handles is not None:
            self.authority_receipt_handles.close()


def build_process_launch(
    command: tuple[str, ...] | list[str],
    *,
    cwd: Path,
    directory_binding: ExecutionDirectoryBinding | None,
    budget: ResourceBudget | None,
    enforce_resource_limits: bool,
    preserve_directory_fds: bool = False,
    environment: dict[str, str] | None = None,
    expected_identity: str | None = None,
    executable_authority: ExecutableAuthority | None = None,
    authority_receipt_fd: int | None = None,
    authority_public_key_fd: int | None = None,
    require_authority_receipt: bool | None = None,
    authority_receipt: SignedAuthorizationReceipt | None = None,
    authority_public_key_path: Path | None = None,
    authority_capability: EffectCapability | None = None,
) -> ProcessLaunch:
    """Compile a safe launch into either the native or explicit dev boundary.

    The returned launch never contains ``preexec_fn``.  A native boundary is
    mandatory whenever a pinned directory or host rlimits are required.  On
    Windows those guarantees are unavailable and the caller fails closed.
    """
    command_tuple = tuple(str(value) for value in command)
    if not command_tuple:
        raise ValueError("execution command cannot be empty")
    if preserve_directory_fds and directory_binding is None:
        raise ValueError(
            "preserving directory descriptors requires a directory binding"
        )
    if (authority_receipt_fd is None) != (authority_public_key_fd is None):
        raise ValueError("signed authority receipt requires both descriptors")
    if authority_capability is not None:
        if authority_receipt is not None:
            raise ValueError("authority capability and receipt cannot both be supplied")
        authority_receipt = authority_capability.receipt
    require_receipt = (
        os.environ.get("KHAOS_DEV_MODE") != "1"
        if require_authority_receipt is None
        else require_authority_receipt
    )
    if not require_receipt and os.environ.get("KHAOS_DEV_MODE") != "1":
        raise PermissionError(
            "production native execution cannot disable authority receipts"
        )
    if authority_receipt_fd is not None:
        require_receipt = True
    receipt_handles: AuthorityReceiptFDs | None = None
    if authority_receipt is not None:
        if authority_receipt_fd is not None or authority_public_key_fd is not None:
            raise ValueError(
                "signed authority receipt cannot mix object and descriptor inputs"
            )
        if authority_public_key_path is None:
            raise PermissionError("authority public-key trust anchor is required")
        receipt_handles = open_authority_receipt_fds(
            authority_receipt, authority_public_key_path
        )
        authority_receipt_fd, authority_public_key_fd = receipt_handles.pass_fds
        require_receipt = True
    if os.name != "posix":
        raise PermissionError(
            "host execution resource and directory guarantees are unsupported on this platform"
        )
    owned_authority = executable_authority
    try:
        if owned_authority is None:
            owned_authority = open_executable_authority(
                command_tuple,
                environment,
                expected_identity=expected_identity,
            )
    except BaseException:
        if receipt_handles is not None:
            receipt_handles.close()
        raise
    launcher = _find_launcher()
    development = launcher is None and os.environ.get("KHAOS_DEV_MODE") == "1"
    if launcher is None and not development:
        owned_authority.close()
        if receipt_handles is not None:
            receipt_handles.close()
        raise PermissionError(
            "native execution launcher is required; build khaos-exec-launcher "
            "or set KHAOS_DEV_MODE=1 for an explicit development fallback"
        )
    if require_receipt and (
        authority_receipt is None
        and (authority_receipt_fd is None or authority_public_key_fd is None)
    ):
        owned_authority.close()
        if receipt_handles is not None:
            receipt_handles.close()
        raise PermissionError(
            "production native execution requires a signed authority receipt"
        )
    if authority_receipt is not None:
        expected_resource_digest = execution_binding_digest(
            command_tuple,
            directory_binding=directory_binding,
            budget=budget,
            enforce_resource_limits=enforce_resource_limits,
            preserve_directory_fds=preserve_directory_fds,
            environment=environment or {},
            executable_authority=owned_authority,
        )
        if authority_receipt.operation != "exec.host":
            owned_authority.close()
            if receipt_handles is not None:
                receipt_handles.close()
            raise PermissionError("native execution receipt operation is not exec.host")
        if authority_receipt.resource_digest != expected_resource_digest:
            owned_authority.close()
            if receipt_handles is not None:
                receipt_handles.close()
            raise PermissionError(
                "native execution receipt is not bound to the exact launch"
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
        if preserve_directory_fds:
            args.append("--preserve-directory-fds")
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
    args.extend(
        (
            "--exec-fd",
            str(owned_authority.executable_fd),
            "--exec-digest",
            owned_authority.executable_digest,
        )
    )
    if owned_authority.interpreter_fd is not None:
        assert owned_authority.interpreter_digest is not None
        args.extend(
            (
                "--interpreter-fd",
                str(owned_authority.interpreter_fd),
                "--interpreter-digest",
                owned_authority.interpreter_digest,
            )
        )
        if owned_authority.interpreter_argv0 is not None:
            args.extend(("--interpreter-argv0", owned_authority.interpreter_argv0))
        for interpreter_arg in owned_authority.interpreter_args:
            args.extend(("--interpreter-arg", interpreter_arg))
    if require_receipt:
        assert authority_receipt_fd is not None
        assert authority_public_key_fd is not None
        args.extend(
            (
                "--require-authority-receipt",
                "--authority-receipt-fd",
                str(authority_receipt_fd),
                "--authority-public-key-fd",
                str(authority_public_key_fd),
            )
        )
    args.extend(("--", *command_tuple))
    receipt_fds = (
        (authority_receipt_fd, authority_public_key_fd)
        if authority_receipt_fd is not None and authority_public_key_fd is not None
        else ()
    )
    return ProcessLaunch(
        argv=tuple(args),
        cwd=(None if directory_binding is not None else str(cwd)),
        pass_fds=(
            (directory_binding.pass_fds if directory_binding is not None else ())
            + owned_authority.pass_fds
            + receipt_fds
        ),
        start_new_session=False,
        executable_authority=owned_authority,
        authority_receipt_handles=receipt_handles,
        authority_capability=authority_capability,
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
    """Reject symlinks and group/world-writable binary/parent paths.

    The loader accepts a root-owned or current-EUID-owned executable so local
    development builds remain usable; production packaging must additionally
    provide a root-owned, read-only launcher (or an equivalent digest gate).
    Owner-writable files are therefore not treated as production trust proof.
    """
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
