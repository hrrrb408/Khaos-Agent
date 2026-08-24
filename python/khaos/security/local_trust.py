"""The filesystem root for the Community Local authority profile.

The Community profile does not have an Apple signing identity, but it still
has a Khaos-owned local trust root.  This module owns only the filesystem
part of that root: the current user's ``~/.khaos`` directory and the private
``authorityd`` descendant.  Peer credentials, Runtime Authority, Ed25519
receipts, policy/catalog binding, approval, verification, and audit remain
owned by their existing Trust-Kernel modules.

Model-controlled project paths are never accepted for Community authority
state.  Every configured socket, key, catalog, public key, and local audit
path must be an owner-held, no-symlink descendant of the private authority
directory.  The helper is intentionally small and synchronous because it is
an admission check at a process/descriptor boundary.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path


class LocalTrustRootError(PermissionError):
    """The Community authority filesystem trust root is unsafe."""


def _require_posix() -> None:
    if os.name != "posix":
        raise LocalTrustRootError(
            "Community Local Trust Root requires POSIX owner metadata and AF_UNIX"
        )


def local_authority_root() -> Path:
    """Return the default owner-only directory for Community authority state."""

    _require_posix()
    import pwd

    try:
        home = Path(pwd.getpwuid(os.getuid()).pw_dir)
    except (KeyError, OSError) as exc:
        raise LocalTrustRootError(
            "the current user's system home directory is unavailable"
        ) from exc
    return home / ".khaos" / "authorityd"


def _check_directory(path: Path, *, label: str, require_private: bool) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise LocalTrustRootError(f"cannot stat trusted {label}: {path}") from exc
    if stat.S_ISLNK(info.st_mode):
        raise LocalTrustRootError(f"trusted {label} must not be a symlink: {path}")
    if not stat.S_ISDIR(info.st_mode):
        raise LocalTrustRootError(f"trusted {label} is not a directory: {path}")
    if info.st_uid != os.getuid():
        raise LocalTrustRootError(
            f"trusted {label} is not owned by the current user: {path}"
        )
    mode = stat.S_IMODE(info.st_mode)
    if mode & 0o022:
        raise LocalTrustRootError(
            f"trusted {label} is group/world writable: {path}"
        )
    if require_private and mode & 0o700 != 0o700:
        raise LocalTrustRootError(
            f"trusted {label} must be owner-readable, writable, and searchable: {path}"
        )


def _ensure_directory(path: Path, *, label: str, require_private: bool) -> None:
    try:
        path.mkdir(mode=0o700, exist_ok=True)
    except OSError as exc:
        raise LocalTrustRootError(f"cannot create trusted {label}: {path}") from exc
    _check_directory(path, label=label, require_private=require_private)


def ensure_local_authority_root(root: Path | None = None) -> Path:
    """Create and validate the Community authority directory chain.

    ``root`` is injectable for isolated tests.  Production callers use the
    fixed ``~/.khaos/authorityd`` location and therefore cannot let a project
    repository choose the authority state directory.
    """

    _require_posix()
    selected = (root or local_authority_root()).expanduser()
    if not selected.is_absolute():
        raise LocalTrustRootError("Community authority root must be absolute")
    selected = Path(os.path.normpath(str(selected)))
    if selected.name != "authorityd" or selected.parent.name != ".khaos":
        raise LocalTrustRootError(
            "Community authority root must be the authorityd directory under .khaos"
        )
    home = selected.parent.parent
    _check_directory(home, label="home directory", require_private=False)
    khaos_dir = selected.parent
    _ensure_directory(khaos_dir, label=".khaos directory", require_private=False)
    _ensure_directory(selected, label="authority directory", require_private=True)
    return selected


def _ensure_parent_chain(path: Path, root: Path) -> None:
    relative_parent = path.parent.relative_to(root)
    current = root
    for component in relative_parent.parts:
        current /= component
        _ensure_directory(
            current,
            label="authority path parent",
            require_private=True,
        )


def validate_trusted_local_path(
    path: Path,
    *,
    kind: str,
    root: Path | None = None,
    allow_missing: bool = False,
) -> Path:
    """Validate one Community authority path beneath the trusted root.

    ``kind`` is ``socket`` or ``file``.  Missing final paths are allowed only
    when the caller is about to create them with an exclusive/no-follow open.
    Existing final paths must be single-link objects owned by the current
    user, without group/other write permission.
    """

    if kind not in {"socket", "file"}:
        raise ValueError("unknown Community authority path kind")
    selected_root = ensure_local_authority_root(root)
    candidate = path.expanduser()
    if not candidate.is_absolute():
        raise LocalTrustRootError("Community authority paths must be absolute")
    candidate = Path(os.path.normpath(str(candidate)))
    try:
        candidate.relative_to(selected_root)
    except ValueError as exc:
        raise LocalTrustRootError(
            f"Community authority {kind} must stay under the trusted authority directory"
        ) from exc
    if candidate == selected_root:
        raise LocalTrustRootError("Community authority path cannot be the root directory")
    _ensure_parent_chain(candidate, selected_root)
    try:
        info = candidate.lstat()
    except FileNotFoundError:
        if allow_missing:
            return candidate
        raise LocalTrustRootError(
            f"trusted Community authority {kind} is unavailable: {candidate}"
        )
    except OSError as exc:
        raise LocalTrustRootError(
            f"cannot stat trusted Community authority {kind}: {candidate}"
        ) from exc
    if stat.S_ISLNK(info.st_mode):
        raise LocalTrustRootError(
            f"trusted Community authority {kind} must not be a symlink: {candidate}"
        )
    expected_type = stat.S_ISSOCK if kind == "socket" else stat.S_ISREG
    if not expected_type(info.st_mode) or info.st_nlink != 1:
        raise LocalTrustRootError(
            f"trusted Community authority {kind} has an invalid file type: {candidate}"
        )
    if info.st_uid != os.getuid():
        raise LocalTrustRootError(
            f"trusted Community authority {kind} is not owner-held: {candidate}"
        )
    mode = stat.S_IMODE(info.st_mode)
    if kind == "socket" and mode != 0o600:
        raise LocalTrustRootError(
            f"Community authority socket must be exactly 0600: {candidate}"
        )
    if mode & 0o022:
        raise LocalTrustRootError(
            f"trusted Community authority {kind} is writable outside the owner: {candidate}"
        )
    return candidate


__all__ = [
    "LocalTrustRootError",
    "ensure_local_authority_root",
    "local_authority_root",
    "validate_trusted_local_path",
]
