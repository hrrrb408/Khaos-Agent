"""Server-owned trusted verification command and disposable workspace policy."""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Iterable

from khaos.coding.planning.contracts import VerificationCatalogEntry, VerificationRequirement
from khaos.coding.planning.verification_execution_models import TrustedVerificationCommand


_SHELL_LAUNCHERS = {
    "sh", "bash", "dash", "zsh", "cmd", "cmd.exe", "powershell",
    "powershell.exe", "pwsh", "eval", "xargs", "env",
}
_CONTROL = re.compile(r"[\x00\n\r]|&&|\|\||[;|`]|\$\(")


@dataclass(frozen=True)
class TrustedToolchain:
    executable_id: str
    language: str
    absolute_path: str
    version: str
    image_digest: str
    binary_digest: str = ""


@dataclass(frozen=True)
class SandboxProfile:
    profile_id: str
    image_digest: str
    network_enabled: bool = False
    read_only_root: bool = True
    run_as_user: str = "65532:65532"
    memory_bytes: int = 512 * 1024 * 1024
    cpu_count: float = 1.0
    pids_limit: int = 128
    file_size_bytes: int = 64 * 1024 * 1024
    open_files: int = 256

    @property
    def digest(self) -> str:
        payload = {
            "profile_id": self.profile_id, "image_digest": self.image_digest,
            "network_enabled": self.network_enabled,
            "read_only_root": self.read_only_root, "run_as_user": self.run_as_user,
            "memory_bytes": self.memory_bytes, "cpu_count": self.cpu_count,
            "pids_limit": self.pids_limit, "file_size_bytes": self.file_size_bytes,
            "open_files": self.open_files,
        }
        return hashlib.sha256(json.dumps(
            payload, sort_keys=True, separators=(",", ":"),
        ).encode()).hexdigest()


class TrustedCommandFactory:
    """Rebuild commands from catalog evidence; caller command fields are absent."""

    def __init__(
        self,
        toolchains: tuple[TrustedToolchain, ...],
        profiles: tuple[SandboxProfile, ...],
        *,
        default_timeout_ms: int = 120_000,
        output_limit_bytes: int = 2 * 1024 * 1024,
    ) -> None:
        self._tools = {(tool.language, tool.executable_id): tool for tool in toolchains}
        self._profiles = {profile.profile_id: profile for profile in profiles}
        self._timeout = default_timeout_ms
        self._output_limit = output_limit_bytes

    def build(
        self,
        requirements: tuple[VerificationRequirement, ...],
        entries: tuple[VerificationCatalogEntry, ...],
        *,
        profile_id: str,
    ) -> tuple[TrustedVerificationCommand, ...]:
        profile = self._profiles.get(profile_id)
        if profile is None or profile.network_enabled or not profile.read_only_root:
            raise PermissionError("trusted verification requires an offline read-only profile")
        entry_map = {
            (entry.verification_type, entry.language, entry.argv): entry
            for entry in entries
        }
        commands: list[TrustedVerificationCommand] = []
        for ordinal, requirement in enumerate(requirements):
            if requirement.command is None:
                if requirement.required:
                    raise PermissionError("required verification has no trusted command")
                continue
            entry = entry_map.get((
                requirement.verification_type, requirement.scope, requirement.command,
            ))
            if entry is None:
                raise PermissionError("verification requirement is absent from trusted catalog")
            argv = tuple(entry.argv)
            self._validate_argv(argv)
            executable_id = argv[0]
            tool = self._tools.get((entry.language, executable_id))
            if tool is None or tool.image_digest != profile.image_digest:
                raise PermissionError("trusted toolchain is unavailable for sandbox image")
            command = TrustedVerificationCommand(
                command_id=f"verify-{ordinal + 1}-{hashlib.sha256('|'.join(argv).encode()).hexdigest()[:12]}",
                requirement_id=f"requirement-{ordinal + 1}",
                kind=entry.verification_type,
                language=entry.language,
                executable_id=tool.executable_id,
                argv=(tool.absolute_path, *argv[1:]),
                cwd=".", config_path=entry.config_path,
                config_hash=entry.config_hash,
                toolchain_id=f"{tool.language}:{tool.executable_id}",
                toolchain_version=tool.version,
                sandbox_profile_id=profile.profile_id,
                timeout_ms=self._timeout,
                output_limit_bytes=self._output_limit,
                expected_exit_codes=(0,), executes_project_code=True,
                metadata={"required": requirement.required},
            ).normalized()
            commands.append(command)
        return tuple(commands)

    @staticmethod
    def _validate_argv(argv: tuple[str, ...]) -> None:
        if not argv or any(not isinstance(part, str) or _CONTROL.search(part) for part in argv):
            raise PermissionError("invalid trusted verification argv")
        launcher = PurePosixPath(argv[0].replace("\\", "/")).name.casefold()
        if launcher in _SHELL_LAUNCHERS:
            raise PermissionError("shell and command launchers are forbidden")
        if launcher in {"npm", "pnpm", "yarn"}:
            if len(argv) < 3 or argv[1] not in {"run", "test"}:
                raise PermissionError("package manager verification must use a catalog script")
        if argv[0].startswith(("./", "../", "/")):
            raise PermissionError("catalog executable must be a logical toolchain id")


@dataclass(frozen=True)
class ManifestEntry:
    path: str
    content_hash: str
    mode: int


@dataclass(frozen=True)
class DisposableVerificationWorkspace:
    instance_id: str
    root: Path
    manifest: tuple[ManifestEntry, ...]
    manifest_digest: str


class VerificationWorkspaceFactory:
    """Copies a canonical workspace without Git metadata, symlinks or hardlinks."""

    def __init__(self, root: Path) -> None:
        self._root = root.resolve()

    def create(
        self,
        source: Path,
        *,
        forbidden_roots: Iterable[Path],
    ) -> DisposableVerificationWorkspace:
        source = source.resolve(strict=True)
        forbidden = tuple(path.resolve() for path in forbidden_roots)
        if any(self._root == path or self._root in path.parents or path in self._root.parents for path in forbidden):
            raise PermissionError("verification root overlaps a protected root")
        self._root.mkdir(mode=0o700, parents=True, exist_ok=True)
        instance_id = f"verify_{secrets.token_hex(16)}"
        destination = self._root / instance_id
        destination.mkdir(mode=0o700)
        entries: list[ManifestEntry] = []
        try:
            for item in sorted(source.rglob("*")):
                relative = item.relative_to(source)
                if relative.parts and relative.parts[0] == ".git":
                    continue
                if item.is_symlink():
                    raise PermissionError("verification workspace does not copy symlinks")
                target = destination / relative
                if item.is_dir():
                    target.mkdir(mode=0o700, parents=True, exist_ok=True)
                    continue
                info = item.stat(follow_symlinks=False)
                if not stat.S_ISREG(info.st_mode):
                    raise PermissionError("verification workspace accepts regular files only")
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                with item.open("rb") as reader, target.open("xb") as writer:
                    shutil.copyfileobj(reader, writer, 1024 * 1024)
                    writer.flush()
                    os.fsync(writer.fileno())
                os.chmod(target, stat.S_IMODE(info.st_mode) & 0o777)
                copied = target.stat(follow_symlinks=False)
                if copied.st_ino == info.st_ino and copied.st_dev == info.st_dev:
                    raise PermissionError("hard-linked verification copy is forbidden")
                source_hash = self._hash(item)
                if self._hash(target) != source_hash:
                    raise RuntimeError("verification workspace copy hash mismatch")
                entries.append(ManifestEntry(relative.as_posix(), source_hash, stat.S_IMODE(info.st_mode)))
            payload = [entry.__dict__ for entry in entries]
            manifest_digest = hashlib.sha256(json.dumps(
                payload, sort_keys=True, separators=(",", ":"),
            ).encode()).hexdigest()
            return DisposableVerificationWorkspace(
                instance_id, destination, tuple(entries), manifest_digest,
            )
        except Exception:
            shutil.rmtree(destination, ignore_errors=True)
            raise

    @staticmethod
    def destroy(workspace: DisposableVerificationWorkspace) -> None:
        shutil.rmtree(workspace.root)

    @staticmethod
    def _hash(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
