"""Stable executable identities for approval and pre-exec verification."""

from __future__ import annotations

import errno
import hashlib
import json
import os
import shutil
import shlex
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path


def executable_identity(
    argv: tuple[str, ...], environment: Mapping[str, str] | None = None
) -> str:
    """Return a non-secret identity for ``argv[0]``.

    The identity includes the resolved path, device/inode and file digest.  A
    missing executable still receives a deterministic unresolved identity so
    request construction remains usable for tests; the eventual spawn will
    fail, while an existing executable replaced between approval and spawn
    produces a different identity and is rejected.
    """
    if not argv or not isinstance(argv[0], str) or not argv[0]:
        return _digest({"argv0": ""})
    raw = argv[0]
    search_path = _search_path(environment)
    candidate = _resolve_argv0(raw, search_path)
    try:
        resolved = candidate.resolve(strict=True)
        file_payload = _file_identity_payload(resolved, search_path, seen=set())
        return _digest(
            {
                "argv0": raw,
                **file_payload,
            }
        )
    except (OSError, ValueError):
        return _digest({"argv0": raw, "resolved_path": "unresolved"})


@dataclass
class ExecutableAuthority:
    """Descriptor authority retained through the final native exec.

    The descriptor is opened with ``O_NOFOLLOW`` and its digest/device/inode
    are checked before it crosses the subprocess boundary.  The native
    launcher checks the same descriptor again immediately before exec, so a
    pathname replacement cannot redirect the approved command.
    """

    executable_fd: int
    executable_digest: str
    interpreter_fd: int | None = None
    interpreter_digest: str | None = None
    interpreter_args: tuple[str, ...] = ()
    interpreter_argv0: str | None = None

    @property
    def pass_fds(self) -> tuple[int, ...]:
        return tuple(
            dict.fromkeys(
                fd for fd in (self.executable_fd, self.interpreter_fd)
                if fd is not None
            )
        )

    def close(self) -> None:
        for fd in self.pass_fds:
            try:
                os.close(fd)
            except OSError:
                pass


def open_executable_authority(
    argv: tuple[str, ...],
    environment: Mapping[str, str] | None = None,
    *,
    expected_identity: str | None = None,
) -> ExecutableAuthority:
    """Open the approved executable object without following a final symlink.

    ``expected_identity`` is checked both before and after opening.  The
    second check closes the race where the approved pathname is replaced
    between the supervisor's last pathname observation and ``open(2)``.
    The descriptor itself is then the object authority passed to the native
    launcher; a later replacement cannot change it.
    """
    if os.name != "posix":
        raise PermissionError("descriptor-bound executable authority requires POSIX")
    expected = expected_identity or executable_identity(argv, environment)
    if executable_identity(argv, environment) != expected:
        raise PermissionError("executable identity changed before authority open")
    resolved = resolved_executable(argv, environment)
    if resolved is None:
        raise FileNotFoundError(
            errno.ENOENT,
            "approved executable could not be resolved",
            argv[0],
        )
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        executable_fd = os.open(resolved, flags)
    except OSError as exc:
        raise PermissionError(
            f"approved executable could not be opened without following symlinks: {resolved}"
        ) from exc
    interpreter_fd: int | None = None
    try:
        executable_info = os.fstat(executable_fd)
        if not stat.S_ISREG(executable_info.st_mode) or not executable_info.st_mode & 0o111:
            raise PermissionError("approved executable descriptor is not executable")
        resolved_info = os.stat(resolved, follow_symlinks=False)
        if (
            int(executable_info.st_dev), int(executable_info.st_ino)
        ) != (int(resolved_info.st_dev), int(resolved_info.st_ino)):
            raise PermissionError("approved executable object changed during authority open")
        executable_digest = _sha256_fd(executable_fd)
        path_payload = _file_identity_payload(resolved, _search_path(environment), seen=set())
        if executable_digest != path_payload.get("file_digest"):
            raise PermissionError("approved executable content changed during authority open")
        if executable_identity(argv, environment) != expected:
            raise PermissionError("executable identity changed after authority open")

        interpreter_digest: str | None = None
        interpreter_args: tuple[str, ...] = ()
        interpreter_argv0: str | None = None
        interpreter = _shebang_interpreter_from_fd(
            executable_fd, _search_path(environment)
        )
        if interpreter is not None:
            interpreter_path, interpreter_args = interpreter
            interpreter_argv0 = str(interpreter_path)
            interpreter_fd = os.open(interpreter_path, flags)
            interpreter_info = os.fstat(interpreter_fd)
            if not stat.S_ISREG(interpreter_info.st_mode) or not interpreter_info.st_mode & 0o111:
                raise PermissionError("approved interpreter descriptor is not executable")
            interpreter_path_info = os.stat(
                interpreter_path, follow_symlinks=False
            )
            if (
                int(interpreter_info.st_dev), int(interpreter_info.st_ino)
            ) != (
                int(interpreter_path_info.st_dev), int(interpreter_path_info.st_ino)
            ):
                raise PermissionError("approved interpreter object changed during authority open")
            interpreter_digest = _sha256_fd(interpreter_fd)
            interpreter_payload = _file_identity_payload(
                interpreter_path, _search_path(environment), seen=set()
            )
            if interpreter_digest != interpreter_payload.get("file_digest"):
                raise PermissionError("approved interpreter changed during authority open")
            if executable_identity(argv, environment) != expected:
                raise PermissionError("executable interpreter identity changed after authority open")
        return ExecutableAuthority(
            executable_fd=executable_fd,
            executable_digest=executable_digest,
            interpreter_fd=interpreter_fd,
            interpreter_digest=interpreter_digest,
            interpreter_args=interpreter_args,
            interpreter_argv0=interpreter_argv0,
        )
    except BaseException:
        if interpreter_fd is not None:
            try:
                os.close(interpreter_fd)
            except OSError:
                pass
        try:
            os.close(executable_fd)
        except OSError:
            pass
        raise


def container_command_identity(
    image_reference_or_digest: str,
    argv: tuple[str, ...],
    *,
    command_digest: str | None = None,
) -> str:
    """Bind a container command to its image, never to a host executable.

    The Docker daemon resolves ``argv[0]`` inside the pinned image.  A host
    ``executable_identity`` would therefore describe the wrong object and
    could make an approval appear to verify the payload when it only verified
    the local machine's PATH.  The authority instead binds the image digest
    and canonical command digest.
    """
    image_digest = image_reference_or_digest.rsplit("@sha256:", 1)[-1]
    normalized_command_digest = command_digest or _digest(list(argv))
    return _digest(
        {
            "kind": "container-command-v1",
            "image_digest": image_digest,
            "command_digest": normalized_command_digest,
        }
    )


def _sha256_fd(fd: int) -> str:
    digest = hashlib.sha256()
    offset = 0
    while True:
        chunk = os.pread(fd, 1024 * 1024, offset)
        if not chunk:
            break
        digest.update(chunk)
        offset += len(chunk)
    return digest.hexdigest()


def _shebang_interpreter_from_fd(
    fd: int, search_path: str
) -> tuple[Path, tuple[str, ...]] | None:
    try:
        payload = os.pread(fd, 4096, 0).decode("utf-8", errors="strict")
        first_line = payload.splitlines()[0]
    except (OSError, UnicodeError, IndexError):
        return None
    if not first_line.startswith("#!"):
        return None
    try:
        parts = tuple(shlex.split(first_line[2:].strip()))
    except ValueError as exc:
        raise PermissionError("approved executable has an invalid shebang") from exc
    if not parts:
        raise PermissionError("approved executable has an empty shebang")
    interpreter = parts[0]
    args = list(parts[1:])
    if interpreter == "/usr/bin/env":
        while args and args[0].startswith("-"):
            args.pop(0)
        if not args:
            raise PermissionError("approved env shebang has no interpreter")
        interpreter = args.pop(0)
    path = _resolve_argv0(interpreter, search_path).resolve(strict=True)
    return path, tuple(args)


def _digest(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def resolved_executable(
    argv: tuple[str, ...], environment: Mapping[str, str] | None = None
) -> Path | None:
    """Resolve ``argv[0]`` with the exact PATH visible to the child."""
    if not argv or not isinstance(argv[0], str) or not argv[0]:
        return None
    try:
        resolved = _resolve_argv0(argv[0], _search_path(environment)).resolve(strict=True)
        metadata = resolved.stat()
        if not stat.S_ISREG(metadata.st_mode):
            return None
        return resolved
    except (OSError, ValueError):
        return None


def _search_path(environment: Mapping[str, str] | None) -> str:
    if environment is not None and "PATH" in environment:
        return str(environment["PATH"])
    return os.environ.get("PATH", os.defpath)


def _resolve_argv0(raw: str, search_path: str) -> Path:
    candidate = Path(raw)
    if candidate.is_absolute():
        return candidate
    resolved_name = shutil.which(raw, path=search_path)
    return Path(resolved_name) if resolved_name else candidate


def _file_identity_payload(
    resolved: Path, search_path: str, *, seen: set[Path]
) -> dict[str, object]:
    if resolved in seen:
        raise OSError("executable interpreter cycle")
    seen.add(resolved)
    metadata = resolved.stat()
    if not stat.S_ISREG(metadata.st_mode):
        raise OSError("executable is not a regular file")
    digest = hashlib.sha256()
    with resolved.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    payload: dict[str, object] = {
        "resolved_path": str(resolved),
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "file_digest": digest.hexdigest(),
    }
    interpreter = _shebang_interpreter(resolved, search_path)
    if interpreter is not None:
        interpreter_path, interpreter_args = interpreter
        payload["shebang"] = (str(interpreter_path), interpreter_args)
        payload["interpreter"] = _file_identity_payload(
            interpreter_path, search_path, seen=seen.copy()
        )
    return payload


def _shebang_interpreter(
    path: Path, search_path: str
) -> tuple[Path, tuple[str, ...]] | None:
    try:
        with path.open("rb") as stream:
            first_line = stream.readline(4096).decode("utf-8", errors="strict")
    except (OSError, UnicodeError):
        return None
    if not first_line.startswith("#!"):
        return None
    try:
        parts = tuple(shlex.split(first_line[2:].strip()))
    except ValueError:
        raise OSError("invalid executable shebang")
    if not parts:
        raise OSError("empty executable shebang")
    interpreter = parts[0]
    args = parts[1:]
    if interpreter == "/usr/bin/env":
        if not args:
            raise OSError("env shebang has no interpreter")
        while args and args[0].startswith("-"):
            args = args[1:]
        if not args:
            raise OSError("env shebang has no interpreter")
        interpreter = args[0]
        args = args[1:]
    resolved = _resolve_argv0(interpreter, search_path).resolve(strict=True)
    return resolved, tuple(args)
