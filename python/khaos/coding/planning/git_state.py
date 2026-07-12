"""Fixed, read-only Git/worktree state inspection without shell commands."""
from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class WorkspaceFileState:
    relative_path: str
    file_type: str
    content_hash: str
    mode: int
    symlink_target_digest: str = ""
    identity_digest: str = ""

    @property
    def state_digest(self) -> str:
        payload = (
            f"{self.relative_path}|{self.file_type}|{self.content_hash}|"
            f"{self.mode}|{self.symlink_target_digest}|{self.identity_digest}"
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class GitStateSnapshot:
    head_commit: str
    index_digest: str
    file_hashes: tuple[tuple[str, str], ...]
    worktree_admin_identity: str
    repository_generation: int
    file_states: tuple[WorkspaceFileState, ...] = ()


class GitStateInspector:
    """Server-defined, argument-free Git metadata reader for one workspace."""

    def snapshot(self, workspace: Any, *, repository_generation: int) -> GitStateSnapshot:
        root = workspace.worktree_path.resolve(strict=True)
        marker = root / ".git"
        marker_bytes = marker.read_bytes() if marker.is_file() else b""
        git_dir = self._git_dir(root, marker_bytes)
        head = self._read_head(git_dir) if git_dir is not None else workspace.base_sha
        index_digest = self._hash_file(git_dir / "index") if git_dir and (git_dir / "index").is_file() else ""
        admin_parts = [hashlib.sha256(marker_bytes).hexdigest()]
        if git_dir is not None and git_dir.exists():
            info = git_dir.stat()
            admin_parts.extend((str(info.st_dev), str(info.st_ino), str(git_dir)))
        files: list[tuple[str, str]] = []
        states: list[WorkspaceFileState] = []
        for path in sorted(root.rglob("*")):
            relative = path.relative_to(root).as_posix()
            if relative == ".git" or relative.startswith(".git/"):
                continue
            if path.is_symlink():
                target_digest = hashlib.sha256(os.readlink(path).encode("utf-8")).hexdigest()
                digest = f"symlink:{target_digest}"
                files.append((relative, digest))
                states.append(WorkspaceFileState(
                    relative, "symlink", "", stat.S_IMODE(path.lstat().st_mode),
                    target_digest,
                    hashlib.sha256(
                        f"{path.lstat().st_dev}:{path.lstat().st_ino}".encode()
                    ).hexdigest(),
                ))
            elif path.is_file():
                digest = self._hash_file(path)
                files.append((relative, digest))
                states.append(WorkspaceFileState(
                    relative, "regular", digest,
                    stat.S_IMODE(path.stat().st_mode),
                    identity_digest=hashlib.sha256(
                        f"{path.stat().st_dev}:{path.stat().st_ino}".encode()
                    ).hexdigest(),
                ))
        return GitStateSnapshot(
            head, index_digest, tuple(files),
            hashlib.sha256("|".join(admin_parts).encode("utf-8")).hexdigest(),
            int(repository_generation), tuple(states),
        )

    @staticmethod
    def _git_dir(root: Path, marker_bytes: bytes) -> Path | None:
        try:
            text = marker_bytes.decode("utf-8").strip()
        except UnicodeDecodeError:
            return None
        if not text.startswith("gitdir: "):
            directory = root / ".git"
            return directory if directory.is_dir() else None
        raw = Path(text[8:])
        candidate = raw if raw.is_absolute() else root / raw
        try:
            return candidate.resolve(strict=True)
        except FileNotFoundError:
            return None

    def _read_head(self, git_dir: Path) -> str:
        head_file = git_dir / "HEAD"
        if not head_file.is_file():
            return ""
        value = head_file.read_text(encoding="utf-8").strip()
        if not value.startswith("ref: "):
            return value
        ref = value[5:]
        for base in (git_dir, self._common_dir(git_dir)):
            candidate = base / ref
            if candidate.is_file():
                return candidate.read_text(encoding="utf-8").strip()
        packed = self._common_dir(git_dir) / "packed-refs"
        if packed.is_file():
            for line in packed.read_text(encoding="utf-8").splitlines():
                if line and not line.startswith(("#", "^")):
                    sha, name = line.split(" ", 1)
                    if name == ref:
                        return sha
        return ""

    @staticmethod
    def _common_dir(git_dir: Path) -> Path:
        marker = git_dir / "commondir"
        if marker.is_file():
            raw = Path(marker.read_text(encoding="utf-8").strip())
            return (git_dir / raw).resolve()
        return git_dir

    @staticmethod
    def _hash_file(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
