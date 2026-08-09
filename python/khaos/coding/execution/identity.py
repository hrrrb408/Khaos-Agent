"""Stable executable identities for approval and pre-exec verification."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
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
    search_path = (environment or {}).get("PATH") or os.environ.get("PATH", "")
    candidate = Path(raw)
    if not candidate.is_absolute():
        resolved_name = shutil.which(raw, path=search_path)
        candidate = Path(resolved_name) if resolved_name else candidate
    try:
        resolved = candidate.resolve(strict=True)
        metadata = resolved.stat()
        if not stat.S_ISREG(metadata.st_mode):
            raise OSError("executable is not a regular file")
        digest = hashlib.sha256()
        with resolved.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return _digest(
            {
                "argv0": raw,
                "resolved_path": str(resolved),
                "device": metadata.st_dev,
                "inode": metadata.st_ino,
                "file_digest": digest.hexdigest(),
            }
        )
    except (OSError, ValueError):
        return _digest({"argv0": raw, "resolved_path": "unresolved"})


def _digest(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
