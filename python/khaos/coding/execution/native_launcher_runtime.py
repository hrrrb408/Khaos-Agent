"""Explicit-development process boundary matching the Rust launcher."""

from __future__ import annotations

import os
import resource
import sys


def main(argv: list[str]) -> int:
    options, command = _parse(argv)
    if options.get("new_session"):
        os.setsid()
    for prefix in ("root", "cwd"):
        fd = options.get(f"{prefix}_fd")
        if fd is None:
            continue
        _verify_fd(
            int(fd),
            int(options[f"{prefix}_device"]),
            int(options[f"{prefix}_inode"]),
            prefix,
        )
    if "cwd_fd" in options:
        os.fchdir(int(options["cwd_fd"]))
    preserve_directory_fds = bool(options.get("preserve_directory_fds"))
    if preserve_directory_fds and (
        options.get("root_fd") is None or options.get("cwd_fd") is None
    ):
        raise ValueError(
            "preserving directory descriptors requires root and cwd bindings"
        )
    preserved = tuple(
        dict.fromkeys(
            int(options[key])
            for key in ("root_fd", "cwd_fd")
            if options.get(key) is not None
        )
    ) if preserve_directory_fds else ()
    # Directory descriptors are authority capabilities, not child-process
    # resources.  The explicit-development launcher mirrors the Rust
    # launcher's stdio-only inheritance policy before exec.  Bubblewrap is
    # the one explicit protocol exception: it resolves a validated workspace
    # source through /proc/self/fd before constructing its mount namespace.
    _close_inherited_fds(preserved)
    _set_limit("RLIMIT_FSIZE", options)
    _set_limit("RLIMIT_NOFILE", options)
    _set_limit("RLIMIT_CPU", options)
    _set_limit("RLIMIT_AS", options)
    os.execvpe(command[0], command, os.environ)
    return 126


def _parse(argv: list[str]) -> tuple[dict[str, int | bool], list[str]]:
    options: dict[str, int | bool] = {}
    index = 0
    while index < len(argv):
        value = argv[index]
        if value == "--":
            command = argv[index + 1 :]
            if not command:
                raise ValueError("command required")
            return options, command
        if value == "--new-session":
            if options.get("new_session"):
                raise ValueError("duplicate --new-session")
            options["new_session"] = True
            index += 1
            continue
        if value == "--preserve-directory-fds":
            if options.get("preserve_directory_fds"):
                raise ValueError("duplicate --preserve-directory-fds")
            options["preserve_directory_fds"] = True
            index += 1
            continue
        if not value.startswith("--") or index + 1 >= len(argv):
            raise ValueError(f"invalid launcher option: {value}")
        key = value[2:].replace("-", "_")
        if key not in {
            "root_fd",
            "root_device",
            "root_inode",
            "cwd_fd",
            "cwd_device",
            "cwd_inode",
            "rlimit_fsize",
            "rlimit_nofile",
            "rlimit_cpu",
            "rlimit_as",
        }:
            raise ValueError(f"unknown launcher option: {value}")
        if key in options:
            raise ValueError(f"duplicate launcher option: {value}")
        parsed = int(argv[index + 1], 10)
        if parsed < 0:
            raise ValueError(f"negative launcher option: {value}")
        options[key] = parsed
        index += 2
    raise ValueError("launcher command separator is required")


def _verify_fd(fd: int, device: int, inode: int, label: str) -> None:
    info = os.fstat(fd)
    if not _same_identity(info, device, inode):
        raise PermissionError(f"{label} directory identity changed before exec")


def _same_identity(info, device: int, inode: int) -> bool:
    return int(info.st_dev) == device and int(info.st_ino) == inode


def _set_limit(name: str, options: dict[str, int | bool]) -> None:
    key = name.lower()
    if key not in options or not hasattr(resource, name):
        return
    resource_id = getattr(resource, name)
    requested = int(options[key])
    _soft, hard = resource.getrlimit(resource_id)
    effective = requested if hard == resource.RLIM_INFINITY else min(requested, hard)
    resource.setrlimit(resource_id, (effective, effective))


def _close_inherited_fds(preserved: tuple[int, ...] = ()) -> None:
    """Close inherited descriptors except stdio and explicit protocol FDs."""
    preserved_fds = set(preserved)
    try:
        maximum = int(os.sysconf("SC_OPEN_MAX"))
    except (AttributeError, OSError, ValueError):
        maximum = 1024
    for fd in range(3, max(3, maximum)):
        if fd in preserved_fds:
            continue
        try:
            os.close(fd)
        except OSError:
            continue


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (OSError, PermissionError, ValueError) as exc:
        print(f"khaos-exec-launcher: {exc}", file=sys.stderr)
        raise SystemExit(126) from exc
