# KHAOS-PRIVILEGED-SPAWN owner=FixtureManager threat-model=private-fixture-git boundary=coding-evaluation-fixture
"""Immutable fixture materialization and oracle-only workspace isolation."""

from __future__ import annotations

import asyncio
import hashlib
import os
import shutil
import stat
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from khaos.evaluation.coding.contracts import CodingContractError, CodingScenario
from khaos.evaluation.coding.manifest import resolve_fixture_path
from khaos.security.protocol_boundary import canonical_json_bytes


class FixtureError(RuntimeError):
    """Fixture materialization or mutation detection failed closed."""


MAX_FIXTURE_FILES = 256
MAX_FIXTURE_BYTES = 16 * 1024 * 1024
_PRIVATE_PREFIX = ".khaos-m8-"
_GENERATED_DIRECTORIES = frozenset(
    {"__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".tox"}
)
_GENERATED_SUFFIXES = frozenset({".pyc", ".pyo"})


@dataclass(frozen=True, slots=True)
class OracleWorkspace:
    """Oracle-owned copy containing hidden material never present in agent root."""

    root: Path
    hidden_root: Path
    _cleanup_root: Path = field(repr=False)

    async def cleanup(self) -> None:
        """Remove the exact private oracle directory."""

        await asyncio.to_thread(_remove_private_tree, self._cleanup_root)


@dataclass(slots=True)
class MaterializedFixture:
    """One run's public fixture and immutable source evidence."""

    scenario: CodingScenario
    agent_root: Path
    fixture_root: Path
    fixture_digest: str
    source_digest: str
    source_sha: str
    base_revision: str
    _hidden_source: Path = field(repr=False)
    _private_root: Path = field(repr=False)
    _initial_agent_digest: str = field(repr=False)
    _cleaned: bool = field(default=False, init=False, repr=False)

    def assert_source_unchanged(self) -> None:
        """Reject mutation of the fixture baseline outside agent effects."""

        if self._cleaned:
            raise FixtureError("fixture has already been cleaned")
        source = self.fixture_root / "repo"
        if not source.is_dir():
            source = self.fixture_root
        current = digest_tree(source, include_git=False)
        current_fixture_digest = digest_fixture(
            source,
            self._hidden_source,
            self.scenario.limits.max_source_files,
            self.scenario.limits.max_source_bytes,
        )
        if current != self._initial_agent_digest or current_fixture_digest != self.fixture_digest:
            raise FixtureError(
                "fixture baseline changed before the evaluated agent completed"
            )

    def digest_evaluated_tree(self, root: Path) -> str:
        """Return a bounded digest of the evaluated source tree."""

        self._require_descendant_or_agent(root)
        return digest_tree(root, include_git=False)

    async def create_oracle_workspace(self, evaluated_root: Path) -> OracleWorkspace:
        """Copy evaluated files and inject hidden files only into an oracle root."""

        if self._cleaned:
            raise FixtureError("fixture has already been cleaned")
        self._require_descendant_or_agent(evaluated_root)
        parent = self._private_root / "oracle"
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        root = Path(tempfile.mkdtemp(prefix="run-", dir=parent))
        hidden = root / ".oracle-hidden"
        try:
            await asyncio.to_thread(_copy_tree, evaluated_root, root, MAX_FIXTURE_FILES, MAX_FIXTURE_BYTES, False)
            await asyncio.to_thread(_copy_tree, self._hidden_source, hidden, MAX_FIXTURE_FILES, MAX_FIXTURE_BYTES, False)
        except BaseException:
            await asyncio.to_thread(_remove_private_tree, root)
            raise
        return OracleWorkspace(root=root, hidden_root=hidden, _cleanup_root=root)

    async def cleanup(self) -> None:
        """Clean the exact run root after all owned resources are closed."""

        if self._cleaned:
            return
        await asyncio.to_thread(_remove_private_tree, self._private_root)
        self._cleaned = True

    def _require_descendant_or_agent(self, root: Path) -> None:
        lexical_candidate = root.expanduser().absolute()
        if lexical_candidate.is_symlink():
            raise FixtureError("evaluated workspace must not be a symlink")
        candidate = lexical_candidate.resolve()
        agent = self.agent_root.expanduser().resolve()
        private = self._private_root.expanduser().resolve()
        oracle_root = (private / "oracle").resolve()
        if candidate == oracle_root or oracle_root in candidate.parents:
            raise FixtureError("oracle-owned workspace cannot be evaluated as agent output")
        if candidate != agent and agent not in candidate.parents and private not in candidate.parents:
            raise FixtureError("evaluated workspace is outside the fixture root")
        if lexical_candidate.is_symlink() or not lexical_candidate.is_dir():
            raise FixtureError("evaluated workspace is not a regular directory")


class FixtureManager:
    """Materialize trusted pack bytes into a fresh private run directory."""

    def __init__(self, manifest_path: Path, *, private_root: Path | None = None) -> None:
        self.manifest_path = manifest_path.expanduser().absolute()
        if self.manifest_path.is_symlink():
            raise FixtureError("fixture manifest must not be a symlink")
        self.manifest_path = self.manifest_path.resolve()
        self.private_root = (private_root or Path(tempfile.gettempdir()) / "khaos-m8-evaluations").expanduser().absolute()
        self.private_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.private_root.is_symlink() or not self.private_root.is_dir():
            raise FixtureError("fixture private root is not a directory")

    async def materialize(self, scenario: CodingScenario) -> MaterializedFixture:
        """Create a Git-backed public agent fixture and preserve hidden bytes."""

        fixture = resolve_fixture_path(self.manifest_path, scenario)
        source = fixture / "repo"
        hidden = fixture / "hidden"
        if not source.is_dir():
            source = fixture
        if not hidden.is_dir():
            raise FixtureError(f"fixture hidden oracle directory is missing: {hidden}")
        run_root = Path(tempfile.mkdtemp(prefix=_PRIVATE_PREFIX, dir=self.private_root))
        agent_root = run_root / "agent-source"
        try:
            await asyncio.to_thread(_copy_tree, source, agent_root, scenario.limits.max_source_files, scenario.limits.max_source_bytes, True)
            source_digest = digest_tree(agent_root, include_git=False)
            fixture_digest = digest_fixture(source, hidden, scenario.limits.max_source_files, scenario.limits.max_source_bytes)
            await _initialize_git(agent_root)
            source_sha = await _git_output(agent_root, "rev-parse", "HEAD")
            return MaterializedFixture(
                scenario=scenario,
                agent_root=agent_root,
                fixture_root=fixture,
                fixture_digest=fixture_digest,
                source_digest=source_digest,
                source_sha=source_sha,
                base_revision=source_sha,
                _hidden_source=hidden,
                _private_root=run_root,
                _initial_agent_digest=source_digest,
            )
        except BaseException:
            await asyncio.to_thread(_remove_private_tree, run_root)
            raise


def digest_fixture(source: Path, hidden: Path, max_files: int, max_bytes: int) -> str:
    """Digest public and hidden fixture bytes with explicit namespace labels."""

    payload = {
        "public": digest_tree(source, include_git=False, max_files=max_files, max_bytes=max_bytes),
        "hidden": digest_tree(hidden, include_git=False, max_files=max_files, max_bytes=max_bytes),
    }
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def digest_tree(
    root: Path,
    *,
    include_git: bool = False,
    max_files: int = MAX_FIXTURE_FILES,
    max_bytes: int = MAX_FIXTURE_BYTES,
) -> str:
    """Hash regular files in lexical path order under a bounded directory."""

    records: list[tuple[str, bytes]] = []
    total = 0
    for path in _walk_regular_files(root, include_git=include_git):
        relative = path.relative_to(root).as_posix()
        data = path.read_bytes()
        total += len(data)
        if len(records) >= max_files or total > max_bytes:
            raise FixtureError("fixture exceeds file or byte bounds")
        records.append((relative, data))
    hasher = hashlib.sha256()
    for relative, data in records:
        encoded = relative.encode("utf-8")
        hasher.update(len(encoded).to_bytes(4, "big"))
        hasher.update(encoded)
        hasher.update(len(data).to_bytes(8, "big"))
        hasher.update(data)
    return hasher.hexdigest()


def _walk_regular_files(root: Path, *, include_git: bool) -> Iterable[Path]:
    root = root.expanduser().absolute()
    if root.is_symlink() or not root.is_dir():
        raise FixtureError(f"fixture root is not a regular directory: {root}")
    paths: list[Path] = []
    for current, directories, files in os.walk(root, followlinks=False):
        current_path = Path(current)
        directories[:] = sorted(directories)
        files = sorted(files)
        for directory in tuple(directories):
            candidate = current_path / directory
            if candidate.is_symlink():
                raise FixtureError("fixture contains a symlink directory")
            if directory in _GENERATED_DIRECTORIES or (
                not include_git and directory in {".git", ".khaos"}
            ):
                directories.remove(directory)
        for name in files:
            candidate = current_path / name
            info = candidate.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                raise FixtureError("fixture contains a symlink or special file")
            if name in {".git", ".khaos"}:
                # Worktrees use a regular ``.git`` pointer file; keep Git
                # control metadata outside fixture/source digests.  Validate
                # its file type before ignoring it so an agent cannot replace
                # the pointer with a symlink and evade the no-symlink rule.
                continue
            if candidate.suffix in _GENERATED_SUFFIXES:
                continue
            paths.append(candidate)
    return tuple(sorted(paths, key=lambda path: path.relative_to(root).as_posix()))


def _copy_tree(source: Path, destination: Path, max_files: int, max_bytes: int, include_git: bool) -> None:
    if destination.exists():
        if destination.is_symlink() or not destination.is_dir() or any(destination.iterdir()):
            raise FixtureError("fixture copy destination is not an empty directory")
    else:
        destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    copied = 0
    total = 0
    for path in _walk_regular_files(source, include_git=include_git):
        relative = path.relative_to(source)
        target = destination / relative
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        data = path.read_bytes()
        copied += 1
        total += len(data)
        if copied > max_files or total > max_bytes:
            raise FixtureError("fixture exceeds file or byte bounds")
        descriptor = os.open(
            target,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0),
            0o600,
        )
        try:
            os.write(descriptor, data)
        finally:
            os.close(descriptor)


async def _initialize_git(root: Path) -> None:
    """Create a deterministic local baseline using fixed, non-shell argv."""

    commands = (
        ("init", "--quiet", "--initial-branch=main"),
        ("config", "user.name", "Khaos Evaluation"),
        ("config", "user.email", "evaluation@khaos.invalid"),
        ("add", "--all"),
        ("commit", "--quiet", "--no-gpg-sign", "-m", "fixture baseline"),
    )
    for command in commands:
        await _git_output(root, *command)


async def _git_output(root: Path, *arguments: str) -> str:
    try:
        process = await asyncio.create_subprocess_exec(
            "git",
            *arguments,
            cwd=str(root),
            env={
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_TERMINAL_PROMPT": "0",
                "LC_ALL": "C",
                "GIT_AUTHOR_DATE": "2000-01-01T00:00:00Z",
                "GIT_COMMITTER_DATE": "2000-01-01T00:00:00Z",
            },
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except OSError as exc:
        raise FixtureError("git is unavailable for fixture setup") from exc
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=30.0)
    except asyncio.TimeoutError as exc:
        process.kill()
        await process.communicate()
        raise FixtureError("fixture git setup timed out") from exc
    if process.returncode != 0:
        raise FixtureError("fixture git setup failed")
    if len(stdout) > 64 * 1024 or len(stderr) > 64 * 1024:
        raise FixtureError("fixture git setup output exceeded its bound")
    return stdout.decode("utf-8", errors="strict").strip()


def _remove_private_tree(root: Path) -> None:
    candidate = root.expanduser().absolute()
    if candidate.name and not candidate.name.startswith((_PRIVATE_PREFIX, "run-")):
        raise FixtureError("refusing to remove a non-evaluation directory")
    if candidate.is_symlink() or not candidate.exists():
        return
    if not candidate.is_dir():
        raise FixtureError("private evaluation root is not a directory")
    # Git object files are read-only on Windows.  Cleanup is restricted to the
    # exact private run root above, so clearing that file attribute and retrying
    # the same removal operation is safe and keeps fixture cleanup reliable
    # across platforms.  The callback re-raises any failure it cannot repair.
    shutil.rmtree(candidate, onerror=_retry_readonly_removal)


def _retry_readonly_removal(function, path: str, _exc_info) -> None:
    """Clear a Windows read-only bit and retry one rmtree operation."""

    candidate = Path(path)
    try:
        info = candidate.lstat()
    except FileNotFoundError:
        return
    if not stat.S_ISLNK(info.st_mode):
        os.chmod(candidate, info.st_mode | stat.S_IWRITE)
    function(path)


__all__ = [
    "FixtureError",
    "FixtureManager",
    "MaterializedFixture",
    "OracleWorkspace",
    "digest_fixture",
    "digest_tree",
]
