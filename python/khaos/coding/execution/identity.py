"""Stable executable identities for approval and pre-exec verification."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import shlex
import stat
from collections.abc import Mapping
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
