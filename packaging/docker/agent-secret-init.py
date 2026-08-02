"""Materialize the Docker secret for the non-root Agent container."""

from __future__ import annotations

import os
import pwd
import stat
import tempfile
from pathlib import Path


CAPABILITY_SOURCE_ENV = "KHAOS_PYTHON_CAPABILITY_FILE"
STAGED_CAPABILITY = Path("/var/lib/khaos/rpc-capability")
MAX_CAPABILITY_BYTES = 4096


def _same_file(left: os.stat_result, right: os.stat_result) -> bool:
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def _read_capability_source() -> bytes:
    source_value = os.environ.get(CAPABILITY_SOURCE_ENV, "").strip()
    if not source_value:
        raise RuntimeError("KHAOS_PYTHON_CAPABILITY_FILE is required")
    source = Path(source_value).expanduser()
    if not source.is_absolute():
        raise RuntimeError("RPC capability source path must be absolute")

    entry = source.lstat()
    if stat.S_ISLNK(entry.st_mode) or not stat.S_ISREG(entry.st_mode):
        raise RuntimeError("RPC capability source must be a regular non-symlink file")
    if stat.S_IMODE(entry.st_mode) & 0o022:
        raise RuntimeError("RPC capability source must not be group/other writable")

    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        opened = os.fstat(fd)
        if not _same_file(entry, opened):
            raise RuntimeError("RPC capability source identity changed")
        content = os.read(fd, MAX_CAPABILITY_BYTES + 1)
    finally:
        os.close(fd)

    final = source.lstat()
    if not _same_file(entry, final):
        raise RuntimeError("RPC capability source identity changed")
    if len(content) > MAX_CAPABILITY_BYTES:
        raise RuntimeError("RPC capability source is too large")
    if len(content.decode("utf-8").strip()) < 32:
        raise RuntimeError("RPC capability must contain at least 32 characters")
    return content


def _stage_capability(content: bytes, service_uid: int, service_gid: int) -> None:
    parent = STAGED_CAPABILITY.parent
    parent_entry = parent.lstat()
    if stat.S_ISLNK(parent_entry.st_mode) or not stat.S_ISDIR(parent_entry.st_mode):
        raise RuntimeError("RPC capability staging directory is unsafe")

    fd, temporary_name = tempfile.mkstemp(
        prefix=".rpc-capability.",
        dir=parent,
    )
    replaced = False
    try:
        os.fchown(fd, service_uid, service_gid)
        os.fchmod(fd, 0o400)
        written = 0
        while written < len(content):
            written += os.write(fd, content[written:])
        os.fsync(fd)
        os.replace(temporary_name, STAGED_CAPABILITY)
        replaced = True
    finally:
        os.close(fd)
        if not replaced:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass

    directory_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def main() -> None:
    if os.getuid() != 0:
        raise RuntimeError("Agent secret init must run as root")
    service = pwd.getpwnam("khaos")
    _stage_capability(_read_capability_source(), service.pw_uid, service.pw_gid)


if __name__ == "__main__":
    main()
