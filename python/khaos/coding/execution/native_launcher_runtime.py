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


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (OSError, PermissionError, ValueError) as exc:
        print(f"khaos-exec-launcher: {exc}", file=sys.stderr)
        raise SystemExit(126) from exc
