"""Fail-closed Git runner for host-side workspace control-plane effects.

Repository-local Git configuration is untrusted input.  This runner pins the
Git executable, scrubs ambient configuration, disables extension points that
can spawn programs, and refuses the checkout path entirely.  Worktree
creation therefore uses ``--no-checkout``; tracked content is materialized
from raw tree/blob objects with a no-follow, traversal-checked extractor.
"""

# KHAOS-PRIVILEGED-SPAWN owner=TrustedGitRunner threat-model=untrusted-repository-config boundary=workspace-control-plane

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import signal
import stat
import subprocess
import threading
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field, replace
from functools import wraps
from pathlib import Path, PurePosixPath
from typing import Any, TypeVar

from khaos.coding.execution.environment import scrub_spawn_environment
from khaos.coding.workspace.git_process import (
    TrustedGitError,
    TrustedGitProcessOwner,
    TrustedGitProcessState,
)
from khaos.security.authority import AuthorityEnvelope
from khaos.security.authority_broker import (
    AuthorityBroker,
    AuthorityBrokerError,
    EffectCapability,
)
from khaos.security.resource_scope import (
    GitRefScope,
    ResourceScopeError,
    TypedResourcePartialOrder,
)

FileIdentity = tuple[int, int, int, int]
_PROTECTED_GIT_NAME = ".git"
_MAX_GIT_ERROR_BYTES = 64 * 1024
_MAX_GIT_SYNC_SECONDS = 120.0
_MAX_GIT_CHUNK_BYTES = 1024 * 1024
_MAX_GIT_EFFECT_FILE_BYTES = 256 * 1024 * 1024
_TRUSTED_GIT_PATH = (
    r"C:\Windows\System32;C:\Program Files\Git\cmd"
    if os.name == "nt"
    else "/usr/bin:/bin"
)
_ALLOWED_COMMANDS = frozenset(
    {
        "apply",
        "cat-file",
        "commit-tree",
        "diff",
        "diff-files",
        "diff-index",
        "diff-tree",
        "hash-object",
        "ls-files",
        "ls-tree",
        "read-tree",
        "rev-parse",
        "update-index",
        "update-ref",
        "worktree",
        "write-tree",
    }
)
_ALLOWED_WORKTREE_COMMANDS = frozenset({"add", "move", "remove"})
_DIFF_COMMANDS = frozenset({"diff", "diff-files", "diff-index", "diff-tree"})
_EXACT_EFFECT_COMMANDS = frozenset(
    {"apply", "commit-tree", "read-tree", "update-index", "update-ref", "worktree", "write-tree"}
)
logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class WorkspaceBootstrapLimits:
    """Independent resource limits for untrusted Git tree materialization.

    These limits are deliberately separate from the post-bootstrap workspace
    growth budget.  A tracked repository must not become the storage baseline
    merely because it was materialized before the baseline was captured.
    """

    max_materialized_bytes: int = 512 * 1024 * 1024
    max_single_blob_bytes: int = 128 * 1024 * 1024
    max_tree_entries: int = 100_000
    max_path_depth: int = 64
    max_symlinks: int = 1_024
    max_tree_listing_bytes: int = 64 * 1024 * 1024
    max_duration_seconds: float = 120.0

    def __post_init__(self) -> None:
        if (
            self.max_materialized_bytes <= 0
            or self.max_single_blob_bytes <= 0
            or self.max_tree_entries <= 0
            or self.max_path_depth <= 0
            or self.max_symlinks < 0
            or self.max_tree_listing_bytes <= 0
            or self.max_duration_seconds <= 0
        ):
            raise ValueError("workspace bootstrap limits must be positive")
        if self.max_single_blob_bytes > self.max_materialized_bytes:
            raise ValueError("single blob limit cannot exceed materialized byte limit")


@dataclass(frozen=True)
class GitStreamResult:
    """Bounded digest/preview metadata for a streamed Git stdout."""

    byte_length: int
    sha256: str
    preview: str


@dataclass(frozen=True, slots=True)
class GitEffect:
    """A fixed Git state transition with its expected old/new values.

    Callers do not pass arbitrary argv for state-changing Git commands.  They
    construct one of the factories below, and the runner checks the exact
    tuple again immediately before spawn.  The typed resource catalog binds
    the effect to the repository, ref/namespace, and approved Git action;
    the effect itself binds the concrete CAS old/new OIDs and path arguments.
    """

    kind: str
    args: tuple[str, ...]
    repository_id: str
    ref_name: str | None = None
    expected_old_oid: str | None = None
    new_oid: str | None = None
    stdin_sha256: str | None = None
    required_operation: str | None = None
    worktree_paths: tuple[str, ...] = ()
    patch_sha256: str | None = None
    patch_length: int | None = None

    def __post_init__(self) -> None:
        if self.kind not in _EXACT_EFFECT_COMMANDS:
            raise ValueError("unsupported Git effect kind")
        if not self.args or any(
            not isinstance(value, str) or not value or "\x00" in value
            for value in self.args
        ):
            raise ValueError("Git effect argv is invalid")
        repository = Path(self.repository_id)
        if not repository.is_absolute() or repository != repository.resolve():
            raise ValueError("Git effect repository_id must be canonical and absolute")
        if self.ref_name is not None and (
            not self.ref_name.startswith("refs/")
            or any(character in self.ref_name for character in "*?[]\x00")
        ):
            raise ValueError("Git effect ref_name is invalid")
        if self.required_operation is not None and (
            not self.required_operation or "." in self.required_operation
        ):
            raise ValueError("Git effect operation must be an action name")
        if self.stdin_sha256 is not None and (
            len(self.stdin_sha256) != 64
            or any(character not in "0123456789abcdef" for character in self.stdin_sha256)
        ):
            raise ValueError("Git effect stdin digest is invalid")
        if isinstance(self.worktree_paths, str):
            raise TypeError("Git effect worktree paths must be a tuple")
        canonical_worktree_paths = tuple(
            _canonical_git_effect_path(value, field="worktree path")
            for value in self.worktree_paths
        )
        object.__setattr__(self, "worktree_paths", canonical_worktree_paths)
        if (self.patch_sha256 is None) != (self.patch_length is None):
            raise ValueError("Git effect patch digest and length must be paired")
        if self.patch_sha256 is not None and (
            len(self.patch_sha256) != 64
            or any(character not in "0123456789abcdef" for character in self.patch_sha256)
        ):
            raise ValueError("Git effect patch digest is invalid")
        if self.patch_length is not None and (
            type(self.patch_length) is not int
            or self.patch_length < 0
            or self.patch_length > _MAX_GIT_EFFECT_FILE_BYTES
        ):
            raise ValueError("Git effect patch length is invalid")
        if self.kind != "apply" and (
            self.patch_sha256 is not None or self.patch_length is not None
        ):
            raise ValueError("patch binding is only valid for Git apply effects")

    def with_prefix(self, prefix: tuple[str, ...]) -> GitEffect:
        """Bind the fixed repository/worktree options without changing the effect."""
        if self.args[: len(prefix)] == prefix:
            return self
        return replace(self, args=(*prefix, *self.args))

    @classmethod
    def update_ref(
        cls,
        *,
        repository_id: str,
        ref_name: str,
        new_oid: str | None,
        expected_old_oid: str,
        delete: bool = False,
        prefix: tuple[str, ...] = (),
        required_operation: str = "workspace",
    ) -> GitEffect:
        """Create an exact CAS update-ref or delete-ref effect."""
        _validate_git_effect_ref(ref_name)
        _validate_git_effect_oid(expected_old_oid, allow_zero=True)
        if delete:
            if new_oid is not None:
                raise ValueError("delete Git effect cannot carry a new OID")
            args = (*prefix, "update-ref", "-d", ref_name, expected_old_oid)
        else:
            if new_oid is None:
                raise ValueError("update Git effect requires a new OID")
            _validate_git_effect_oid(new_oid)
            args = (*prefix, "update-ref", ref_name, new_oid, expected_old_oid)
        return cls(
            kind="update-ref",
            args=tuple(args),
            repository_id=repository_id,
            ref_name=ref_name,
            expected_old_oid=expected_old_oid,
            new_oid=new_oid,
            required_operation=required_operation,
        )

    @classmethod
    def worktree_add(
        cls,
        *,
        repository_id: str,
        branch: str,
        path: str,
        base_oid: str,
        prefix: tuple[str, ...] = (),
        required_operation: str = "workspace",
    ) -> GitEffect:
        """Create the exact no-checkout task worktree effect."""
        if not branch or branch.startswith("/") or ".." in branch:
            raise ValueError("Git worktree branch is invalid")
        _validate_git_effect_oid(base_oid)
        _validate_git_effect_path(path)
        return cls(
            kind="worktree",
            args=(*prefix, "worktree", "add", "--no-checkout", "-b", branch, path, base_oid),
            repository_id=repository_id,
            ref_name=f"refs/heads/{branch}",
            expected_old_oid="0" * len(base_oid),
            new_oid=base_oid,
            required_operation=required_operation,
            worktree_paths=(path,),
        )

    @classmethod
    def worktree_move(
        cls,
        *,
        repository_id: str,
        source: str,
        destination: str,
        prefix: tuple[str, ...] = (),
        required_operation: str = "workspace",
    ) -> GitEffect:
        _validate_git_effect_path(source)
        _validate_git_effect_path(destination)
        return cls(
            kind="worktree",
            args=(*prefix, "worktree", "move", source, destination),
            repository_id=repository_id,
            required_operation=required_operation,
            worktree_paths=(source, destination),
        )

    @classmethod
    def worktree_remove(
        cls,
        *,
        repository_id: str,
        path: str,
        force: bool = False,
        prefix: tuple[str, ...] = (),
        required_operation: str = "cleanup",
    ) -> GitEffect:
        _validate_git_effect_path(path)
        force_args = ("--force",) if force else ()
        return cls(
            kind="worktree",
            args=(*prefix, "worktree", "remove", *force_args, path),
            repository_id=repository_id,
            required_operation=required_operation,
            worktree_paths=(path,),
        )

    @classmethod
    def read_tree(
        cls,
        *,
        repository_id: str,
        treeish: str,
        prefix: tuple[str, ...] = (),
        required_operation: str = "index",
    ) -> GitEffect:
        _validate_git_effect_oid(treeish)
        return cls(
            kind="read-tree",
            args=(*prefix, "read-tree", treeish),
            repository_id=repository_id,
            required_operation=required_operation,
        )

    @classmethod
    def update_index_remove(
        cls,
        *,
        repository_id: str,
        path: str,
        prefix: tuple[str, ...] = (),
        required_operation: str = "index",
    ) -> GitEffect:
        _validate_git_effect_relative_path(path)
        return cls(
            kind="update-index",
            args=(*prefix, "update-index", "--remove", "--", path),
            repository_id=repository_id,
            required_operation=required_operation,
        )

    @classmethod
    def update_index_cacheinfo(
        cls,
        *,
        repository_id: str,
        mode: str,
        object_id: str,
        path: str,
        prefix: tuple[str, ...] = (),
        required_operation: str = "index",
    ) -> GitEffect:
        if mode not in {"100644", "100755", "120000", "160000"}:
            raise ValueError("Git index mode is invalid")
        _validate_git_effect_oid(object_id)
        _validate_git_effect_relative_path(path)
        return cls(
            kind="update-index",
            args=(*prefix, "update-index", "--add", "--cacheinfo", f"{mode},{object_id},{path}"),
            repository_id=repository_id,
            required_operation=required_operation,
        )

    @classmethod
    def write_tree(
        cls,
        *,
        repository_id: str,
        prefix: tuple[str, ...] = (),
        required_operation: str = "workspace",
    ) -> GitEffect:
        return cls(
            kind="write-tree",
            args=(*prefix, "write-tree"),
            repository_id=repository_id,
            required_operation=required_operation,
        )

    @classmethod
    def commit_tree(
        cls,
        *,
        repository_id: str,
        tree_oid: str,
        parent_oid: str,
        stdin_sha256: str,
        prefix: tuple[str, ...] = (),
        required_operation: str = "workspace",
    ) -> GitEffect:
        _validate_git_effect_oid(tree_oid)
        _validate_git_effect_oid(parent_oid)
        return cls(
            kind="commit-tree",
            args=(*prefix, "commit-tree", tree_oid, "-p", parent_oid),
            repository_id=repository_id,
            stdin_sha256=stdin_sha256,
            required_operation=required_operation,
        )

    @classmethod
    def apply_index(
        cls,
        *,
        repository_id: str,
        stdin_sha256: str,
        prefix: tuple[str, ...] = (),
        extra_args: tuple[str, ...] = (),
        required_operation: str = "apply",
    ) -> GitEffect:
        args = (*prefix, "apply", "--index", *extra_args)
        return cls(
            kind="apply",
            args=tuple(args),
            repository_id=repository_id,
            stdin_sha256=stdin_sha256,
            required_operation=required_operation,
        )

    @classmethod
    def apply_index_file(
        cls,
        *,
        repository_id: str,
        patch_path: str,
        patch_sha256: str,
        patch_length: int,
        prefix: tuple[str, ...] = (),
        required_operation: str = "apply",
    ) -> GitEffect:
        """Create an exact ``apply --index`` effect for one patch path."""
        _validate_git_effect_path(patch_path)
        return cls(
            kind="apply",
            args=(*prefix, "apply", "--index", patch_path),
            repository_id=repository_id,
            required_operation=required_operation,
            patch_sha256=patch_sha256,
            patch_length=patch_length,
        )


def _validate_git_effect_ref(ref_name: str) -> None:
    if (
        not ref_name.startswith("refs/")
        or any(character in ref_name for character in "*?[]\x00")
        or ref_name.endswith("/")
        or ".." in ref_name
    ):
        raise ValueError("Git effect ref is invalid")


def _validate_git_effect_oid(value: str, *, allow_zero: bool = False) -> None:
    if len(value) not in {40, 64} or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise ValueError("Git effect object id is invalid")
    if not allow_zero and set(value) == {"0"}:
        raise ValueError("Git effect new object id cannot be all zero")


def _validate_git_effect_path(value: str) -> None:
    _canonical_git_effect_path(value)


def _canonical_git_effect_path(value: str, *, field: str = "Git effect path") -> str:
    path = Path(value)
    if not path.is_absolute() or path != path.resolve():
        raise ValueError(f"{field} must be canonical and absolute")
    return str(path)


def _validate_git_effect_relative_path(value: str) -> None:
    if (
        not value
        or "\x00" in value
        or Path(value).is_absolute()
        or any(part in {"", ".", ".."} for part in value.replace("\\", "/").split("/"))
    ):
        raise ValueError("Git effect relative path is invalid")


def _git_command_index(args: tuple[str, ...]) -> int | None:
    return next(
        (
            index
            for index, arg in enumerate(args)
            if not arg.startswith("-")
            and not arg.startswith("--git-dir=")
            and not arg.startswith("--work-tree=")
        ),
        None,
    )


def _git_command(args: tuple[str, ...]) -> str | None:
    index = _git_command_index(args)
    return args[index] if index is not None else None



def _identity(info: os.stat_result) -> FileIdentity:
    return (int(info.st_dev), int(info.st_ino), int(info.st_uid), int(info.st_mode))


def _verify_same_file_snapshot(
    current: os.stat_result, expected: os.stat_result
) -> None:
    """Reject descriptor content drift that a pathname check cannot see."""
    if (
        current.st_dev,
        current.st_ino,
        current.st_mode,
        current.st_nlink,
        current.st_size,
        current.st_mtime_ns,
        current.st_ctime_ns,
    ) != (
        expected.st_dev,
        expected.st_ino,
        expected.st_mode,
        expected.st_nlink,
        expected.st_size,
        expected.st_mtime_ns,
        expected.st_ctime_ns,
    ):
        raise TrustedGitError("Git hash input changed while being consumed")


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise TrustedGitError(f"Git executable is unavailable: {path}") from exc
    try:
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
    finally:
        os.close(descriptor)
    return digest.hexdigest()


def resolve_trusted_git() -> tuple[Path, FileIdentity, str]:
    """Resolve and fingerprint the platform Git without consulting ``PATH``."""
    system_git = (
        Path("C:/Program Files/Git/cmd/git.exe")
        if os.name == "nt"
        else Path("/usr/bin/git")
    )
    try:
        executable = system_git.resolve(strict=True)
        info = executable.stat()
    except OSError as exc:
        raise TrustedGitError("trusted system Git executable is unavailable") from exc
    if (
        not executable.is_absolute()
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or info.st_mode & 0o022
    ):
        raise TrustedGitError(
            "Git executable must be absolute, root-owned, regular, and immutable"
        )
    for parent in executable.parents:
        try:
            parent_info = parent.stat()
        except OSError as exc:
            raise TrustedGitError("Git executable parent chain is unavailable") from exc
        if parent_info.st_uid != 0 or parent_info.st_mode & 0o022:
            raise TrustedGitError("Git executable parent chain is not trusted")
    return executable, _identity(info), _file_digest(executable)


def _verify_identity(
    path: Path,
    expected: FileIdentity,
    *,
    require_root_owner: bool,
    label: str,
    expected_digest: str | None = None,
) -> None:
    """Open an authority object with no-follow and compare its live identity."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        try:
            current = os.fstat(descriptor)
            if expected_digest is not None:
                digest = hashlib.sha256()
                while chunk := os.read(descriptor, 1024 * 1024):
                    digest.update(chunk)
                if digest.hexdigest() != expected_digest:
                    raise TrustedGitError(f"{label} content digest drifted")
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise TrustedGitError(f"{label} is unavailable") from exc
    if _identity(current) != expected:
        raise TrustedGitError(f"{label} identity drifted")
    required_uid = 0 if require_root_owner else os.getuid()
    if current.st_uid != required_uid or current.st_mode & 0o022:
        raise TrustedGitError(f"{label} trust policy failed")


AuthorityInput = EffectCapability | AuthorityEnvelope
_AsyncMethod = TypeVar("_AsyncMethod", bound=Callable[..., Awaitable[Any]])
_SyncMethod = TypeVar("_SyncMethod", bound=Callable[..., Any])


def _effect_result_digest(capability: EffectCapability, result: str) -> str:
    return hashlib.sha256(f"{capability.digest}:{result}".encode("ascii")).hexdigest()


def _finalize_effect(
    runner: Any, capability: EffectCapability, *, result: str
) -> None:
    broker = runner.authority_broker
    if broker is None:
        raise TrustedGitError("TrustedGitRunner has no authority broker")
    complete = getattr(broker, "complete", None)
    if not callable(complete):
        broker.revoke(capability)
        return
    try:
        complete(
            capability,
            result=result,
            result_digest=_effect_result_digest(capability, result),
        )
    except AuthorityBrokerError as exc:
        # A result append can fail after the effect has run. Keep the exact
        # claimed handle for close-time reconciliation and try the conservative
        # terminal state immediately. The runner stays quarantined even if the
        # retry succeeds, because another host effect must not follow ambiguity.
        runner._authority_quarantined = True
        pending = runner._authority_pending_effects
        if len(pending) >= 64 and capability.nonce not in pending:
            raise TrustedGitError(
                "Git effect result could not be committed and quarantine quota is exhausted"
            ) from exc
        pending[capability.nonce] = capability
        if result != "unknown":
            try:
                complete(
                    capability,
                    result="unknown",
                    result_digest=_effect_result_digest(capability, "unknown"),
                )
            except AuthorityBrokerError:
                logger.exception(
                    "Git effect remains uncommitted after unknown reconciliation",
                )
            else:
                pending.pop(capability.nonce, None)
        raise TrustedGitError(
            f"Git effect result could not be committed as {result}; runner quarantined"
        ) from exc
    else:
        runner._authority_pending_effects.pop(capability.nonce, None)


def _claim_effect(runner: Any, capability: EffectCapability) -> None:
    broker = runner.authority_broker
    if broker is None:
        raise TrustedGitError("TrustedGitRunner has no authority broker")
    claim = getattr(broker, "claim", None)
    if callable(claim):
        claim(capability)


def _revoke_effect(runner: Any, capability: EffectCapability) -> None:
    broker = runner.authority_broker
    if broker is None:
        return
    try:
        broker.revoke(capability)
    except AuthorityBrokerError:
        runner._authority_quarantined = True
        pending = runner._authority_pending_effects
        if len(pending) < 64 or capability.nonce in pending:
            pending[capability.nonce] = capability
        complete = getattr(broker, "complete", None)
        if callable(complete):
            try:
                complete(
                    capability,
                    result="unknown",
                    result_digest=_effect_result_digest(capability, "unknown"),
                )
            except AuthorityBrokerError:
                logger.exception(
                    "Git effect receipt could not be revoked or reconciled",
                )
            else:
                pending.pop(capability.nonce, None)
        else:
            logger.exception("Git effect receipt could not be revoked")


def _authorize_async(method: _AsyncMethod) -> _AsyncMethod:
    @wraps(method)
    async def wrapped(self: Any, *args: Any, **kwargs: Any) -> Any:
        # ``status`` is a composite read-only query; its nested direct Git
        # effects obtain and finish their own receipts.
        if len(args) > 1 and args[1] == "status":
            return await method(self, *args, **kwargs)
        authority = kwargs.get("authority")
        if self._authority_quarantined:
            raise TrustedGitError(
                "TrustedGitRunner is quarantined because an authority result is unresolved"
            )
        capability = self._authority_or_fail(authority)
        try:
            _claim_effect(self, capability)
        except BaseException:
            _revoke_effect(self, capability)
            raise
        try:
            result = await method(self, *args, **{**kwargs, "authority": capability})
        except asyncio.CancelledError:
            try:
                _finalize_effect(self, capability, result="unknown")
            except TrustedGitError:
                pass
            raise
        except BaseException:
            try:
                _finalize_effect(self, capability, result="failed")
            except TrustedGitError:
                pass
            raise
        _finalize_effect(self, capability, result="success")
        return result

    return wrapped  # type: ignore[return-value]


def _authorize_sync(method: _SyncMethod) -> _SyncMethod:
    @wraps(method)
    def wrapped(self: Any, *args: Any, **kwargs: Any) -> Any:
        if len(args) > 1 and args[1] == "status":
            return method(self, *args, **kwargs)
        authority = kwargs.get("authority")
        if self._authority_quarantined:
            raise TrustedGitError(
                "TrustedGitRunner is quarantined because an authority result is unresolved"
            )
        capability = self._authority_or_fail(authority)
        try:
            _claim_effect(self, capability)
        except BaseException:
            _revoke_effect(self, capability)
            raise
        try:
            result = method(self, *args, **{**kwargs, "authority": capability})
        except BaseException:
            try:
                _finalize_effect(self, capability, result="failed")
            except TrustedGitError:
                pass
            raise
        _finalize_effect(self, capability, result="success")
        return result

    return wrapped  # type: ignore[return-value]


@dataclass
class TrustedGitRunner:
    """Run bounded Git operations under a broker-issued capability."""

    executable: Path
    git_identity: FileIdentity
    git_digest: str
    authority_root: Path
    authority_root_identity: FileIdentity
    authority_broker: AuthorityBroker | None = None
    resource_order: TypedResourcePartialOrder | None = None
    _owners: dict[str, TrustedGitProcessOwner] = field(default_factory=dict, init=False, repr=False)
    _authority_pending_effects: dict[str, EffectCapability] = field(
        default_factory=dict, init=False, repr=False
    )
    _authority_quarantined: bool = field(default=False, init=False, repr=False)

    @classmethod
    def for_authority_root(
        cls,
        root: Path,
        root_identity: FileIdentity,
        *,
        authority_broker: AuthorityBroker | None = None,
        resource_order: TypedResourcePartialOrder | None = None,
    ) -> TrustedGitRunner:
        executable, identity, digest = resolve_trusted_git()
        return cls(
            executable,
            identity,
            digest,
            root,
            root_identity,
            authority_broker or AuthorityBroker.default(),
            resource_order,
        )

    def _new_owner(self, label: str) -> TrustedGitProcessOwner:
        """Register a Git process owner before the native spawn begins."""
        owner = TrustedGitProcessOwner(label)
        self._owners[f"{label}:{id(owner)}"] = owner
        return owner

    def _release_owner(self, owner: TrustedGitProcessOwner) -> None:
        """Release only after the owner has an independently proven terminal state."""
        if not owner.terminal_postcondition:
            return
        for key, current in tuple(self._owners.items()):
            if current is owner:
                self._owners.pop(key, None)
                return

    def owned_resources(self) -> tuple[str, ...]:
        """Return the parent-owned Git process/reaper inventory."""
        resources: list[str] = []
        for key, owner in self._owners.items():
            resources.append(key)
            if owner._late_spawn_task is not None and not owner._late_spawn_task.done():
                resources.append(f"{key}:late-spawn")
        if self._authority_pending_effects:
            resources.append(f"authority-results:{len(self._authority_pending_effects)}")
        return tuple(sorted(resources))

    @property
    def is_quarantined(self) -> bool:
        return self._authority_quarantined or any(
            owner.state is TrustedGitProcessState.QUARANTINED
            for owner in self._owners.values()
        )

    def terminal_postcondition(self) -> bool:
        return not self._owners and not self._authority_pending_effects

    async def close(self) -> None:
        """Retry every retained owner and never manufacture an empty registry."""
        errors: list[BaseException] = []
        for key, owner in tuple(self._owners.items()):
            try:
                await asyncio.shield(owner.close())
            except BaseException as exc:  # noqa: BLE001 - retain owner
                errors.append(exc)
                continue
            self._release_owner(owner)
        broker = self.authority_broker
        complete = getattr(broker, "complete", None) if broker is not None else None
        if callable(complete):
            for nonce, capability in tuple(self._authority_pending_effects.items()):
                try:
                    complete(
                        capability,
                        result="unknown",
                        result_digest=_effect_result_digest(capability, "unknown"),
                    )
                except AuthorityBrokerError as exc:
                    errors.append(exc)
                else:
                    self._authority_pending_effects.pop(nonce, None)
        if errors or self._owners or self._authority_pending_effects:
            raise TrustedGitError(
                "TrustedGitRunner close retained owned resources: "
                + "; ".join(
                    type(error).__name__ for error in errors
                )
            ) from (errors[0] if errors else None)

    def _verify(self) -> None:
        _verify_identity(
            self.executable,
            self.git_identity,
            require_root_owner=True,
            label="Git executable",
            expected_digest=self.git_digest,
        )
        _verify_identity(
            self.authority_root,
            self.authority_root_identity,
            require_root_owner=False,
            label="workspace authority root",
        )

    @staticmethod
    def _validate_args(args: tuple[str, ...]) -> tuple[str, ...]:
        """Allow only audited plumbing operations and safe diff modes."""
        if any(
            arg in {"-c", "--config-env"}
            or arg.startswith(("--config=", "--config-env="))
            for arg in args
        ):
            raise TrustedGitError("TrustedGitRunner rejects caller Git configuration switches")
        values = list(args)
        for arg in values:
            if (
                arg in {"--ext-diff", "--textconv", "--paginate", "--exec-path"}
                or arg.startswith(
                    (
                        "--upload-pack",
                        "--receive-pack",
                        "--ssh-command",
                        "--exec-path=",
                        "--output=",
                    )
                )
            ):
                raise TrustedGitError("TrustedGitRunner rejects Git extension or output switches")
        command_index = next(
            (
                index
                for index, arg in enumerate(values)
                if not arg.startswith("-")
                and not arg.startswith("--git-dir=")
                and not arg.startswith("--work-tree=")
            ),
            None,
        )
        if command_index is None or values[command_index] not in _ALLOWED_COMMANDS:
            raise TrustedGitError("TrustedGitRunner operation is outside the audited allowlist")
        command = values[command_index]
        if command == "worktree" and (
            len(values) <= command_index + 1
            or values[command_index + 1] not in _ALLOWED_WORKTREE_COMMANDS
        ):
            raise TrustedGitError("TrustedGitRunner worktree operation is not allowed")
        if command == "worktree" and "--checkout" in values:
            raise TrustedGitError("TrustedGitRunner refuses checkout-enabled worktrees")
        if command == "read-tree" and ("-u" in values or "--update-worktree" in values):
            raise TrustedGitError("TrustedGitRunner refuses checkout-enabled read-tree")
        if command == "hash-object" and "--no-filters" not in values:
            raise TrustedGitError("TrustedGitRunner hash-object requires --no-filters")
        if values[:2] == ["worktree", "add"] and "--no-checkout" not in values:
            values.insert(2, "--no-checkout")
        if command in _DIFF_COMMANDS:
            insertion = command_index + 1
            for flag in ("--no-ext-diff", "--no-textconv"):
                if flag not in values:
                    values.insert(insertion, flag)
                    insertion += 1
        return tuple(values)

    def _environment(self, *, index_file: Path | None = None) -> dict[str, str]:
        # These values are pinned and preserved explicitly.  The runner does
        # not inherit PATH, credentials, proxy variables, Git aliases, or
        # caller-provided GIT_CONFIG_* injection variables.
        environment = {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ASKPASS": os.devnull,
            "SSH_ASKPASS": os.devnull,
            "GIT_PAGER": "cat",
            "PAGER": "cat",
            "GIT_EDITOR": ":",
            "GIT_SEQUENCE_EDITOR": ":",
            "GIT_OPTIONAL_LOCKS": "0",
            "PATH": _TRUSTED_GIT_PATH,
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "HOME": str(self.authority_root),
        }
        if index_file is not None:
            environment["GIT_INDEX_FILE"] = str(index_file)
        return scrub_spawn_environment(
            environment,
            preserve={
                "GIT_CONFIG_GLOBAL",
                "GIT_CONFIG_SYSTEM",
                "GIT_TERMINAL_PROMPT",
                "GIT_ASKPASS",
                "SSH_ASKPASS",
                # These are THIS runner's own pinned plumbing values, not
                # inherited caller state: index-scoped plumbing and the
                # pinned pagers are authority-chosen and must survive the
                # scrub that strips the same names from untrusted spawns.
                "GIT_INDEX_FILE",
                "GIT_PAGER",
                "PAGER",
                "GIT_OBJECT_DIRECTORY",
                "GIT_ALTERNATE_OBJECT_DIRECTORIES",
            },
        )

    def _argv(self, args: tuple[str, ...]) -> tuple[str, ...]:
        # Command-line configuration has higher precedence than repository
        # local config.  The checkout itself is separately forbidden by
        # --no-checkout; this closes hooks, fsmonitor and untracked-cache
        # process-extension surfaces for status/worktree/admin operations.
        safe_config = (
            "-c",
            f"core.hooksPath={os.devnull}",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.untrackedCache=false",
            "-c",
            "commit.gpgSign=false",
        )
        return ("--no-optional-locks", *safe_config, *self._validate_args(args))

    def _authority_or_fail(
        self, authority: AuthorityInput | None
    ) -> EffectCapability:
        if isinstance(authority, AuthorityEnvelope):
            operation = authority.operation_class
            capability = self._issue_from_grant(authority)
        elif isinstance(authority, EffectCapability):
            operation = authority.authority.operation_class
            capability = authority
        else:
            raise TrustedGitError(
                "TrustedGitRunner requires a broker-issued authority grant or effect capability"
            )
        if not operation.startswith("git."):
            raise TrustedGitError("Git operation authority class is invalid")
        broker = self.authority_broker
        if broker is None:
            raise TrustedGitError("TrustedGitRunner has no authority broker")
        try:
            if capability.expires_at <= time.time():
                capability = self._issue_from_grant(
                    capability.authority,
                )
            broker.validate(
                capability,
                expected_operation=capability.authority.operation_class,
                expected_resource_digest=capability.resource_digest,
            )
        except AuthorityBrokerError as exc:
            raise TrustedGitError(f"Git effect capability rejected: {exc}") from exc
        return capability

    def _issue_from_grant(self, authority: AuthorityEnvelope) -> EffectCapability:
        broker = self.authority_broker
        if broker is None:
            raise TrustedGitError("TrustedGitRunner has no authority broker")
        try:
            return broker.issue(
                authority,
                allowed_operation=authority.operation_class,
                resource_digest=authority.resource_digest,
            )
        except AuthorityBrokerError as exc:
            raise TrustedGitError(f"Git authority grant could not issue an effect: {exc}") from exc

    def _validate_effect_binding(
        self,
        repository: Path,
        args: tuple[str, ...],
        effect: GitEffect,
        capability: EffectCapability,
    ) -> None:
        """Bind typed scope, repository identity, and exact Git argv."""
        if args != effect.args:
            raise TrustedGitError(
                "Git effect argv changed after its exact authorization was built"
            )
        if _git_command(args) != effect.kind:
            raise TrustedGitError("Git effect command does not match its authority")
        command_index = _git_command_index(args)
        if command_index is None:
            raise TrustedGitError("Git effect command is missing")
        command_args = args[command_index:]
        if effect.kind == "update-ref":
            if effect.ref_name is None or effect.expected_old_oid is None:
                raise TrustedGitError("Git update-ref effect is incomplete")
            if effect.new_oid is None:
                expected = (
                    "update-ref",
                    "-d",
                    effect.ref_name,
                    effect.expected_old_oid,
                )
            else:
                expected = (
                    "update-ref",
                    effect.ref_name,
                    effect.new_oid,
                    effect.expected_old_oid,
                )
            if command_args != expected:
                raise TrustedGitError(
                    "Git update-ref effect does not bind its expected old/new OIDs"
                )
        elif effect.kind == "worktree":
            if len(command_args) < 2 or command_args[1] not in _ALLOWED_WORKTREE_COMMANDS:
                raise TrustedGitError("Git worktree effect shape is invalid")
            if command_args[1] == "add":
                if (
                    len(command_args) != 7
                    or command_args[2] != "--no-checkout"
                    or command_args[3] != "-b"
                    or effect.worktree_paths != (command_args[5],)
                ):
                    raise TrustedGitError("Git worktree add effect shape is invalid")
            elif command_args[1] == "move":
                if (
                    len(command_args) != 4
                    or effect.worktree_paths != (command_args[2], command_args[3])
                ):
                    raise TrustedGitError("Git worktree move effect shape is invalid")
            elif command_args[1] == "remove":
                if len(command_args) == 3:
                    paths = (command_args[2],)
                elif len(command_args) == 4 and command_args[2] == "--force":
                    paths = (command_args[3],)
                else:
                    raise TrustedGitError("Git worktree remove effect shape is invalid")
                if effect.worktree_paths != paths:
                    raise TrustedGitError("Git worktree remove path binding is invalid")
            self._validate_worktree_paths(effect.worktree_paths)
        elif effect.kind == "update-index":
            if command_args[1:3] == ("--remove", "--"):
                if len(command_args) != 4:
                    raise TrustedGitError("Git update-index remove effect shape is invalid")
            elif command_args[1:3] == ("--add", "--cacheinfo"):
                if len(command_args) != 4:
                    raise TrustedGitError(
                        "Git update-index cacheinfo effect shape is invalid"
                    )
            else:
                raise TrustedGitError("Git update-index effect is not exact")
        elif effect.kind == "read-tree":
            if len(command_args) != 2:
                raise TrustedGitError("Git read-tree effect shape is invalid")
        elif effect.kind == "apply":
            if effect.stdin_sha256 is None:
                if (
                    len(command_args) != 3
                    or command_args[1] != "--index"
                    or effect.patch_sha256 is None
                    or effect.patch_length is None
                ):
                    raise TrustedGitError("Git apply effect shape is invalid")
                try:
                    _validate_git_effect_path(command_args[2])
                except ValueError as exc:
                    raise TrustedGitError("Git apply patch path is invalid") from exc
                self._validate_private_effect_path(command_args[2])
            elif "--index" not in command_args:
                raise TrustedGitError("Git apply effect must bind --index")
        elif effect.kind == "write-tree":
            if len(command_args) != 1:
                raise TrustedGitError("Git write-tree effect shape is invalid")
        elif effect.kind == "commit-tree":
            if len(command_args) != 4 or command_args[2] != "-p":
                raise TrustedGitError("Git commit-tree effect shape is invalid")
            if effect.stdin_sha256 is None:
                raise TrustedGitError("Git commit-tree effect must bind stdin")

        canonical_repository = Path(effect.repository_id)
        current_repository = repository.expanduser().resolve()
        git_dir_value = next(
            (arg[len("--git-dir="):] for arg in args if arg.startswith("--git-dir=")),
            None,
        )
        if git_dir_value is None:
            if current_repository != canonical_repository:
                raise TrustedGitError(
                    "Git effect repository does not match the process working directory"
                )
        else:
            git_dir = Path(git_dir_value).expanduser()
            if not git_dir.is_absolute() or git_dir.resolve() != git_dir:
                raise TrustedGitError("Git effect git-dir is not canonical")
            repository_git = canonical_repository / ".git"
            try:
                git_dir.relative_to(repository_git)
            except ValueError as exc:
                raise TrustedGitError(
                    "Git effect git-dir is outside the authorized repository"
                ) from exc
            work_tree_value = next(
                (
                    arg[len("--work-tree=") :]
                    for arg in args
                    if arg.startswith("--work-tree=")
                ),
                None,
            )
            if work_tree_value is not None and (
                not Path(work_tree_value).is_absolute()
                or Path(work_tree_value).resolve() != current_repository
            ):
                raise TrustedGitError("Git effect work-tree does not match its cwd")

        capability_action = capability.authority.operation_class.rsplit(".", 1)[-1]
        if effect.required_operation is not None and capability_action != effect.required_operation:
            raise TrustedGitError(
                "Git effect operation does not match its exact authority class"
            )
        resource_order = self.resource_order
        if resource_order is None:
            return
        try:
            scope = resource_order.resolve(capability.resource_digest)
        except ResourceScopeError as exc:
            raise TrustedGitError(
                "Git effect capability is not a typed catalog scope"
            ) from exc
        if not isinstance(scope, GitRefScope):
            raise TrustedGitError("Git effect capability is not a Git scope")
        if scope.repository != effect.repository_id:
            raise TrustedGitError("Git effect repository is outside its typed scope")
        action = effect.required_operation or effect.kind
        if action not in scope.operations:
            raise TrustedGitError("Git effect action is outside its typed scope")
        if effect.ref_name is not None and not scope.allows_ref(effect.ref_name):
            raise TrustedGitError("Git effect ref is outside its typed scope")
        if effect.kind == "worktree" and scope.worktree_root is not None and not all(
            scope.allows_worktree_path(path) for path in effect.worktree_paths
        ):
            raise TrustedGitError("Git worktree path is outside its typed worktree scope")

    def _validate_worktree_paths(self, paths: tuple[str, ...]) -> None:
        """Require every Git worktree target to be a strict private-root child."""
        if not paths:
            raise TrustedGitError("Git worktree effect has no bound path")
        root = self.authority_root.expanduser().resolve()
        for value in paths:
            candidate = Path(value).expanduser().resolve()
            if candidate == root:
                raise TrustedGitError("Git worktree effect cannot target the authority root")
            try:
                candidate.relative_to(root)
            except ValueError as exc:
                raise TrustedGitError(
                    "Git worktree effect path is outside the authority root"
                ) from exc
            if candidate != Path(value):
                raise TrustedGitError(
                    "Git worktree effect path is not a canonical private path"
                )

    def _validate_private_effect_path(self, value: str) -> None:
        """Keep Git file-backed effects inside the private authority root."""
        candidate = Path(value).expanduser().resolve()
        root = self.authority_root.expanduser().resolve()
        if candidate == root:
            raise TrustedGitError("Git file effect cannot target the authority root")
        try:
            candidate.relative_to(root)
        except ValueError as exc:
            raise TrustedGitError(
                "Git file effect path is outside the authority root"
            ) from exc
        if candidate != Path(value):
            raise TrustedGitError("Git file effect path is not canonical")

    @staticmethod
    def _verify_patch_file(effect: GitEffect) -> None:
        """Recheck the exclusive patch artifact immediately before spawn."""
        if effect.kind != "apply" or effect.stdin_sha256 is not None:
            return
        if effect.patch_sha256 is None or effect.patch_length is None:
            raise TrustedGitError("Git apply effect is missing patch content binding")
        command_index = _git_command_index(effect.args)
        if command_index is None or len(effect.args) <= command_index + 2:
            raise TrustedGitError("Git apply patch path is missing")
        path = Path(effect.args[command_index + 2])
        descriptor = -1
        digest = hashlib.sha256()
        total = 0
        try:
            descriptor = os.open(
                path,
                os.O_RDONLY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
            )
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise TrustedGitError("Git apply patch is not a single-link regular file")
            while chunk := os.read(descriptor, _MAX_GIT_CHUNK_BYTES):
                total += len(chunk)
                if total > _MAX_GIT_EFFECT_FILE_BYTES:
                    raise TrustedGitError("Git apply patch exceeds its configured bound")
                digest.update(chunk)
        except OSError as exc:
            raise TrustedGitError("Git apply patch cannot be verified") from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        if total != effect.patch_length or digest.hexdigest() != effect.patch_sha256:
            raise TrustedGitError("Git apply patch digest or length does not match authorization")

    async def run_effect(
        self,
        repository: Path,
        effect: GitEffect,
        *,
        authority: AuthorityInput,
        preserve_output: bool = False,
        index_file: Path | None = None,
    ) -> str:
        """Execute one exact state-changing effect through the normal receipt gate."""
        return await self.run(
            repository,
            *effect.args,
            authority=authority,
            preserve_output=preserve_output,
            index_file=index_file,
            effect=effect,
        )

    async def run_effect_with_input(
        self,
        repository: Path,
        effect: GitEffect,
        *,
        input_bytes: bytes,
        authority: AuthorityInput,
        max_input_bytes: int = 64 * 1024,
        max_output_bytes: int = 64 * 1024,
        index_file: Path | None = None,
    ) -> str:
        """Execute an exact stdin-bound effect with a digest-bound payload."""
        if effect.stdin_sha256 is None or hashlib.sha256(input_bytes).hexdigest() != effect.stdin_sha256:
            raise TrustedGitError("Git effect stdin does not match its authorization")
        return await self.run_with_input(
            repository,
            *effect.args,
            input_bytes=input_bytes,
            authority=authority,
            max_input_bytes=max_input_bytes,
            max_output_bytes=max_output_bytes,
            index_file=index_file,
            effect=effect,
        )

    @_authorize_async
    async def run(
        self,
        repository: Path,
        *args: str,
        authority: EffectCapability,
        preserve_output: bool = False,
        max_output_bytes: int = 64 * 1024,
        index_file: Path | None = None,
        effect: GitEffect | None = None,
    ) -> str:
        """Run one text-producing Git command with fail-closed authority."""
        if args and args[0] == "status":
            dirty = await self.is_dirty(repository, authority=authority)
            return "dirty" if dirty else ""
        self._verify()
        capability = self._authority_or_fail(authority)
        command = _git_command(tuple(args))
        if command in _EXACT_EFFECT_COMMANDS:
            if effect is None:
                raise TrustedGitError(
                    "state-changing Git commands require a structured exact effect"
                )
            self._validate_effect_binding(repository, tuple(args), effect, capability)
            self._verify_patch_file(effect)
        elif effect is not None:
            raise TrustedGitError("a Git effect cannot authorize a read-only command")
        owner = self._new_owner("git.run")
        try:
            stdout, stderr, _ = await owner.communicate_bounded_after_spawn(
                str(self.executable),
                *self._argv(tuple(args)),
                max_stdout_bytes=max_output_bytes,
                cwd=str(repository),
                env=self._environment(index_file=index_file),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except OSError as exc:
            raise TrustedGitError("trusted Git process could not start") from exc
        finally:
            self._release_owner(owner)
        if owner.process is None or owner.process.returncode != 0:
            message = stderr.decode("utf-8", errors="replace").strip()
            raise TrustedGitError(message or "trusted Git command failed")
        output = stdout.decode("utf-8", errors="replace")
        return output if preserve_output else output.strip()

    @_authorize_async
    async def run_bytes(
        self,
        repository: Path,
        *args: str,
        authority: EffectCapability,
        max_output_bytes: int = 64 * 1024,
        index_file: Path | None = None,
    ) -> bytes:
        """Run one binary-producing Git command with the same authority gate."""
        self._verify()
        self._authority_or_fail(authority)
        if _git_command(tuple(args)) in _EXACT_EFFECT_COMMANDS:
            raise TrustedGitError(
                "state-changing Git commands require a structured exact effect"
            )
        owner = self._new_owner("git.run-bytes")
        try:
            stdout, stderr, _ = await owner.communicate_bounded_after_spawn(
                str(self.executable),
                *self._argv(tuple(args)),
                max_stdout_bytes=max_output_bytes,
                cwd=str(repository),
                env=self._environment(index_file=index_file),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except OSError as exc:
            raise TrustedGitError("trusted Git process could not start") from exc
        finally:
            self._release_owner(owner)
        if owner.process is None or owner.process.returncode != 0:
            message = stderr.decode("utf-8", errors="replace").strip()
            raise TrustedGitError(message or "trusted Git command failed")
        return stdout

    @_authorize_async
    async def run_with_input(
        self,
        repository: Path,
        *args: str,
        input_bytes: bytes,
        authority: EffectCapability,
        max_input_bytes: int = 64 * 1024,
        max_output_bytes: int = 64 * 1024,
        index_file: Path | None = None,
        effect: GitEffect | None = None,
    ) -> str:
        """Run a plumbing command with bounded, caller-owned stdin only."""
        if len(input_bytes) > max_input_bytes:
            raise TrustedGitError("trusted Git input exceeds the configured bound")
        self._verify()
        capability = self._authority_or_fail(authority)
        command = _git_command(tuple(args))
        if command in _EXACT_EFFECT_COMMANDS:
            if effect is None:
                raise TrustedGitError(
                    "state-changing Git commands require a structured exact effect"
                )
            self._validate_effect_binding(repository, tuple(args), effect, capability)
            if effect.stdin_sha256 is None or hashlib.sha256(input_bytes).hexdigest() != effect.stdin_sha256:
                raise TrustedGitError("Git effect stdin does not match its authorization")
        elif effect is not None:
            raise TrustedGitError("a Git effect cannot authorize a read-only command")
        owner = self._new_owner("git.run-with-input")
        try:
            stdout, stderr, _ = await owner.communicate_bounded_after_spawn(
                str(self.executable),
                *self._argv(tuple(args)),
                input_bytes=input_bytes,
                max_stdout_bytes=max_output_bytes,
                max_stderr_bytes=_MAX_GIT_ERROR_BYTES,
                cwd=str(repository),
                env=self._environment(index_file=index_file),
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except OSError as exc:
            raise TrustedGitError("trusted Git process could not start") from exc
        finally:
            self._release_owner(owner)
        if owner.process is None or owner.process.returncode != 0:
            message = stderr.decode("utf-8", errors="replace").strip()
            raise TrustedGitError(message or "trusted Git command failed")
        return stdout.decode("utf-8", errors="replace").strip()

    @_authorize_async
    async def hash_fd(
        self,
        repository: Path,
        descriptor: int,
        expected: os.stat_result,
        *,
        authority: EffectCapability,
        max_bytes: int,
        index_file: Path | None = None,
    ) -> str:
        """Hash a pinned regular-file descriptor without handing Git a path.

        ``git hash-object <pathname>`` is deliberately not used for mutable
        workspace entries.  The descriptor is opened by ``SafeWorkspaceFS``
        with no-follow parent traversal, streamed in bounded chunks, and
        revalidated after the stream.  A replacement of the leaf or a parent
        directory therefore cannot turn Git into a host-file confused deputy.
        """
        if max_bytes <= 0:
            raise ValueError("max_bytes must be positive")
        if not stat.S_ISREG(expected.st_mode) or expected.st_nlink != 1:
            raise TrustedGitError("Git hash input is not a single-link regular file")
        self._verify()
        self._authority_or_fail(authority)
        try:
            opened = os.fstat(descriptor)
            _verify_same_file_snapshot(opened, expected)
            os.lseek(descriptor, 0, os.SEEK_SET)
        except OSError as exc:
            raise TrustedGitError("Git hash input descriptor is unavailable") from exc

        owner = self._new_owner("git.hash-fd")
        stderr_task: asyncio.Task[tuple[bytes, bool]] | None = None
        stdout_task: asyncio.Task[tuple[bytes, bool]] | None = None
        try:
            process = await owner.spawn(
                str(self.executable),
                *self._argv(("hash-object", "--stdin", "--no-filters", "-w")),
                cwd=str(repository),
                env=self._environment(index_file=index_file),
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            if process.stdin is None or process.stdout is None or process.stderr is None:
                raise TrustedGitError("trusted Git hash process has unusable pipes")
            stdout_task = asyncio.create_task(
                _drain_stream_limited(process.stdout, 4096)
            )
            stderr_task = asyncio.create_task(
                _drain_stream_limited(process.stderr, _MAX_GIT_ERROR_BYTES)
            )
            total = 0
            while True:
                chunk = await asyncio.to_thread(os.read, descriptor, _MAX_GIT_CHUNK_BYTES)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise TrustedGitError("Git hash input exceeds its configured bound")
                process.stdin.write(chunk)
                await process.stdin.drain()
            process.stdin.close()
            await process.stdin.wait_closed()
            stdout, stdout_overflow = await stdout_task
            stdout_task = None
            stderr, stderr_overflow = await stderr_task
            stderr_task = None
            await owner.wait()
            if stdout_overflow or stderr_overflow:
                raise TrustedGitError("trusted Git hash output exceeds its bound")
            if process.returncode != 0:
                message = stderr.decode("utf-8", errors="replace").strip()
                raise TrustedGitError(message or "trusted Git hash command failed")
            try:
                final = os.fstat(descriptor)
                _verify_same_file_snapshot(final, expected)
            except OSError as exc:
                raise TrustedGitError("Git hash input changed during hashing") from exc
            object_id = stdout.decode("ascii", errors="strict").strip()
            if not object_id or len(object_id) not in {40, 64}:
                raise TrustedGitError("Git hash command returned an invalid object id")
            return object_id
        except asyncio.CancelledError:
            await asyncio.shield(owner.abort(cancelled=True))
            raise
        except (OSError, UnicodeError, TrustedGitError) as exc:
            if not owner.terminal:
                await asyncio.shield(owner.abort(cancelled=False))
            self._release_owner(owner)
            if isinstance(exc, TrustedGitError):
                raise
            raise TrustedGitError("trusted Git hash input failed") from exc
        finally:
            for task in (stdout_task, stderr_task):
                if task is not None:
                    task.cancel()
                    try:
                        await task
                    except asyncio.CancelledError:
                        pass
            if not owner.terminal:
                await asyncio.shield(owner.abort(cancelled=False))
            self._release_owner(owner)

    @_authorize_async
    async def stream_to_file(
        self,
        repository: Path,
        *args: str,
        destination: Path,
        authority: EffectCapability,
        max_bytes: int,
        preview_bytes: int = 64 * 1024,
        index_file: Path | None = None,
    ) -> GitStreamResult:
        """Stream Git stdout into an exclusive artifact with hard bounds."""
        if max_bytes <= 0 or preview_bytes <= 0 or preview_bytes > max_bytes:
            raise ValueError("invalid Git stream limits")
        self._verify()
        self._authority_or_fail(authority)
        process: asyncio.subprocess.Process | None = None
        owner = self._new_owner("git.stream-to-file")
        stderr_task: asyncio.Task[bytes] | None = None
        descriptor: int | None = None
        completed = False
        try:
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            descriptor = os.open(
                destination,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            process = await owner.spawn(
                str(self.executable),
                *self._argv(tuple(args)),
                cwd=str(repository),
                env=self._environment(index_file=index_file),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            if process.stdout is None or process.stderr is None:
                raise TrustedGitError("trusted Git process has no usable output pipes")
            stderr_task = asyncio.create_task(
                _drain_stream_limited(process.stderr, _MAX_GIT_ERROR_BYTES)
            )
            digest = hashlib.sha256()
            preview = bytearray()
            byte_length = 0
            while chunk := await process.stdout.read(_MAX_GIT_CHUNK_BYTES):
                byte_length += len(chunk)
                if byte_length > max_bytes:
                    raise TrustedGitError("trusted Git artifact exceeds the configured bound")
                offset = 0
                while offset < len(chunk):
                    offset += os.write(descriptor, chunk[offset:])
                digest.update(chunk)
                if len(preview) < preview_bytes:
                    preview.extend(chunk[: preview_bytes - len(preview)])
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = None
            stderr, stderr_overflow = await stderr_task
            stderr_task = None
            await owner.wait()
            if stderr_overflow:
                raise TrustedGitError(
                    "trusted Git diagnostic output exceeds its bound"
                )
            if process.returncode != 0:
                message = stderr.decode("utf-8", errors="replace").strip()
                raise TrustedGitError(message or "trusted Git command failed")
            completed = True
            return GitStreamResult(
                byte_length=byte_length,
                sha256=digest.hexdigest(),
                preview=preview.decode("utf-8", errors="replace"),
            )
        except asyncio.CancelledError:
            await asyncio.shield(owner.abort(cancelled=True))
            raise
        except TrustedGitError:
            if not owner.terminal:
                await asyncio.shield(owner.abort(cancelled=False))
            raise
        except OSError as exc:
            if not owner.terminal:
                await asyncio.shield(owner.abort(cancelled=False))
            raise TrustedGitError("trusted Git artifact stream failed") from exc
        finally:
            if stderr_task is not None:
                stderr_task.cancel()
                try:
                    await stderr_task
                except asyncio.CancelledError:
                    pass
            if not completed and not owner.terminal:
                await asyncio.shield(owner.abort(cancelled=False))
            if descriptor is not None:
                os.close(descriptor)
            if not completed:
                destination.unlink(missing_ok=True)
            self._release_owner(owner)

    @_authorize_async
    async def run_bytes_limited(
        self,
        repository: Path,
        *args: str,
        authority: EffectCapability,
        max_bytes: int,
        index_file: Path | None = None,
    ) -> bytes:
        """Run a binary Git operation with a hard stdout bound."""
        if max_bytes <= 0:
            raise ValueError("max_bytes must be positive")
        self._verify()
        self._authority_or_fail(authority)
        if _git_command(tuple(args)) in _EXACT_EFFECT_COMMANDS:
            raise TrustedGitError(
                "state-changing Git commands require a structured exact effect"
            )
        process: asyncio.subprocess.Process | None = None
        owner = self._new_owner("git.run-bytes-limited")
        stderr_task: asyncio.Task[bytes] | None = None
        try:
            process = await owner.spawn(
                str(self.executable),
                *self._argv(tuple(args)),
                cwd=str(repository),
                env=self._environment(index_file=index_file),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            if process.stdout is None or process.stderr is None:
                raise TrustedGitError("trusted Git process has no usable output pipes")
            stderr_task = asyncio.create_task(
                _drain_stream_limited(process.stderr, _MAX_GIT_ERROR_BYTES)
            )
            output = bytearray()
            while chunk := await process.stdout.read(
                min(_MAX_GIT_CHUNK_BYTES, max_bytes + 1 - len(output))
            ):
                output.extend(chunk)
                if len(output) > max_bytes:
                    raise TrustedGitError("trusted Git output exceeds the configured bound")
            stderr, stderr_overflow = await stderr_task
            stderr_task = None
            await owner.wait()
            if stderr_overflow:
                raise TrustedGitError(
                    "trusted Git diagnostic output exceeds its bound"
                )
            if process.returncode != 0:
                message = stderr.decode("utf-8", errors="replace").strip()
                raise TrustedGitError(message or "trusted Git command failed")
            return bytes(output)
        except asyncio.CancelledError:
            await asyncio.shield(owner.abort(cancelled=True))
            raise
        except TrustedGitError:
            if not owner.terminal:
                await asyncio.shield(owner.abort(cancelled=False))
            self._release_owner(owner)
            raise
        except (OSError, asyncio.IncompleteReadError) as exc:
            if not owner.terminal:
                await asyncio.shield(owner.abort(cancelled=False))
            raise TrustedGitError("trusted Git process could not be read") from exc
        finally:
            if stderr_task is not None:
                stderr_task.cancel()
                try:
                    await stderr_task
                except asyncio.CancelledError:
                    pass
            if not owner.terminal:
                await asyncio.shield(owner.abort(cancelled=False))
            self._release_owner(owner)

    async def materialize_tree(
        self,
        repository: Path,
        treeish: str,
        worktree: Path,
        *,
        authority: EffectCapability,
        limits: WorkspaceBootstrapLimits | None = None,
    ) -> None:
        """Materialize a commit's blobs without checkout filters or archives.

        ``git archive`` consults tracked ``.gitattributes`` and can therefore
        activate a repository-local filter process.  The trusted path only
        asks Git for tree metadata and raw blob bytes, then validates every
        pathname and symlink before creating the worktree entry itself.
        """
        bootstrap_limits = limits or WorkspaceBootstrapLimits()
        try:
            async with asyncio.timeout(bootstrap_limits.max_duration_seconds):
                object_id_length = await self._object_id_length(
                    repository, authority=authority
                )
                listing = await self.run_bytes_limited(
                    repository,
                    "ls-tree",
                    "-r",
                    "-z",
                    "--full-tree",
                    treeish,
                    authority=authority.derive(operation_class="git.tree"),
                    max_bytes=bootstrap_limits.max_tree_listing_bytes,
                )
                entries = _parse_tree_listing(
                    listing,
                    object_id_length=object_id_length,
                    max_entries=bootstrap_limits.max_tree_entries,
                )
                await self._materialize_blobs(
                    repository,
                    entries,
                    worktree,
                    authority=authority.derive(operation_class="git.blob"),
                    limits=bootstrap_limits,
                    object_id_length=object_id_length,
                )
        except TimeoutError as exc:
            raise TrustedGitError("Git workspace bootstrap exceeded its time limit") from exc

    @_authorize_async
    async def _materialize_blobs(
        self,
        repository: Path,
        entries: list[tuple[str, str, str]],
        worktree: Path,
        *,
        authority: EffectCapability,
        limits: WorkspaceBootstrapLimits,
        object_id_length: int,
    ) -> None:
        self._verify()
        self._authority_or_fail(authority)
        process: asyncio.subprocess.Process | None = None
        owner = self._new_owner("git.materialize-blobs")
        try:
            process = await owner.spawn(
                str(self.executable),
                *self._argv(("cat-file", "--batch")),
                cwd=str(repository),
                env=self._environment(),
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            if process.stdin is None or process.stdout is None:
                raise TrustedGitError("trusted Git blob process has no usable pipes")
            seen: set[str] = set()
            materialized_bytes = 0
            symlink_count = 0
            for mode, object_id, path in entries:
                if len(seen) >= limits.max_tree_entries:
                    raise TrustedGitError("Git tree exceeds the entry limit")
                if path in seen:
                    raise TrustedGitError(f"Git tree contains duplicate path: {path}")
                seen.add(path)
                parts = _safe_member_parts(path)
                if len(parts) > limits.max_path_depth:
                    raise TrustedGitError("Git tree path exceeds the depth limit")
                process.stdin.write(f"{object_id}\n".encode("ascii"))
                await process.stdin.drain()
                header = await process.stdout.readline()
                fields = header.rstrip(b"\n").split()
                if len(fields) != 3 or fields[0].decode("ascii", errors="replace") != object_id:
                    raise TrustedGitError("Git blob response did not match requested object")
                if fields[1] != b"blob":
                    raise TrustedGitError(f"Git tree entry is not a blob: {path}")
                try:
                    size = int(fields[2])
                except ValueError as exc:
                    raise TrustedGitError("Git blob response has an invalid size") from exc
                if size < 0 or size > limits.max_single_blob_bytes:
                    raise TrustedGitError("Git blob exceeds the single-blob limit")
                materialized_bytes += size
                if materialized_bytes > limits.max_materialized_bytes:
                    raise TrustedGitError("Git tree exceeds the materialized-byte limit")
                parent = _ensure_directory(worktree, parts[:-1])
                target = parent / parts[-1]
                if target.exists() or target.is_symlink():
                    raise TrustedGitError(
                        f"Git tree would overwrite an existing worktree entry: {path}"
                    )
                if mode == "120000":
                    symlink_count += 1
                    if symlink_count > limits.max_symlinks or size > 4096:
                        raise TrustedGitError("Git symlink target is unreasonably large")
                    link_target = await process.stdout.readexactly(size)
                    await _read_blob_separator(process.stdout)
                    _verify_blob_digest(object_id, link_target)
                    os.symlink(_safe_symlink_target(parts, link_target), target)
                    continue
                if mode not in {"100644", "100755"}:
                    raise TrustedGitError(f"Git tree entry has an unsupported mode: {path}")
                descriptor = os.open(
                    target,
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_NOFOLLOW", 0),
                    0o755 if mode == "100755" else 0o644,
                )
                try:
                    remaining = size
                    digest = _blob_hasher(object_id, size)
                    with os.fdopen(descriptor, "wb") as output:
                        while remaining:
                            chunk = await process.stdout.read(min(_MAX_GIT_CHUNK_BYTES, remaining))
                            if not chunk:
                                raise TrustedGitError("Git blob ended before its declared size")
                            output.write(chunk)
                            digest.update(chunk)
                            remaining -= len(chunk)
                        output.flush()
                        os.fsync(output.fileno())
                except Exception:
                    target.unlink(missing_ok=True)
                    raise
                await _read_blob_separator(process.stdout)
                if digest.hexdigest() != object_id:
                    target.unlink(missing_ok=True)
                    raise TrustedGitError("Git blob content hash did not match its object id")
            if process.stdin is not None:
                process.stdin.close()
                await process.stdin.wait_closed()
            if await process.stdout.read(1):
                raise TrustedGitError("Git blob process returned unexpected trailing data")
            stderr, stderr_overflow = (
                await _drain_stream_limited(process.stderr, _MAX_GIT_ERROR_BYTES)
                if process.stderr is not None
                else (b"", False)
            )
            await owner.wait()
            if stderr_overflow:
                raise TrustedGitError(
                    "trusted Git diagnostic output exceeds its bound"
                )
            if process.returncode != 0:
                message = stderr.decode("utf-8", errors="replace").strip()
                raise TrustedGitError(message or "trusted Git blob process failed")
        except asyncio.CancelledError:
            await asyncio.shield(owner.abort(cancelled=True))
            raise
        except TrustedGitError:
            if not owner.terminal:
                await asyncio.shield(owner.abort(cancelled=False))
            raise
        except (OSError, asyncio.IncompleteReadError, ValueError) as exc:
            if not owner.terminal:
                await asyncio.shield(owner.abort(cancelled=False))
            raise TrustedGitError("trusted Git blob materialization failed") from exc
        finally:
            if not owner.terminal:
                await asyncio.shield(owner.abort(cancelled=False))
            self._release_owner(owner)

    async def _object_id_length(
        self, repository: Path, *, authority: EffectCapability
    ) -> int:
        object_format = await self.run(
            repository,
            "rev-parse",
            "--show-object-format",
            authority=authority.derive(operation_class="git.object-format"),
        )
        return _object_id_length(object_format)

    async def is_dirty(
        self,
        repository: Path,
        *,
        authority: EffectCapability,
    ) -> bool:
        """Detect changes without invoking status/filter extensions."""
        object_id_length = await self._object_id_length(repository, authority=authority)
        staged = await self.run(
            repository,
            "diff-index",
            "--cached",
            "--no-ext-diff",
            "--no-textconv",
            "--name-only",
            "HEAD",
            authority=authority.derive(operation_class="git.status"),
        )
        if staged:
            return True
        untracked = await self.run(
            repository,
            "ls-files",
            "--others",
            "--exclude-standard",
            authority=authority.derive(operation_class="git.status"),
        )
        if untracked:
            return True
        listing = await self.run_bytes(
            repository,
            "ls-files",
            "--stage",
            "-z",
            authority=authority.derive(operation_class="git.status"),
        )
        return not _working_tree_matches_index(listing, repository, object_id_length)

    @_authorize_sync
    def run_sync(
        self,
        repository: Path,
        *args: str,
        authority: EffectCapability,
    ) -> str:
        """Synchronous variant used only by startup/recovery discovery."""
        if args and args[0] == "status":
            return "dirty" if self.is_dirty_sync(repository, authority=authority) else ""
        self._verify()
        self._authority_or_fail(authority)
        if _git_command(tuple(args)) in _EXACT_EFFECT_COMMANDS:
            raise TrustedGitError(
                "state-changing Git commands require a structured exact effect"
            )
        try:
            stdout, stderr, returncode = _run_sync_bounded(
                [str(self.executable), *self._argv(tuple(args))],
                cwd=repository,
                env=self._environment(),
            )
        except OSError as exc:
            raise TrustedGitError("trusted Git process could not start") from exc
        if returncode != 0:
            message = stderr.decode("utf-8", errors="replace").strip()
            raise TrustedGitError(message or "trusted Git command failed")
        return stdout.decode("utf-8", errors="replace").strip()

    def is_dirty_sync(
        self,
        repository: Path,
        *,
        authority: EffectCapability,
    ) -> bool:
        """Synchronous filter-free dirty-state check for recovery."""
        object_id_length = self._object_id_length_sync(repository, authority=authority)
        staged = self.run_sync(
            repository,
            "diff-index",
            "--cached",
            "--no-ext-diff",
            "--no-textconv",
            "--name-only",
            "HEAD",
            authority=authority.derive(operation_class="git.status"),
        )
        if staged:
            return True
        untracked = self.run_sync(
            repository,
            "ls-files",
            "--others",
            "--exclude-standard",
            authority=authority.derive(operation_class="git.status"),
        )
        if untracked:
            return True
        listing = self.run_sync_bytes(
            repository,
            "ls-files",
            "--stage",
            "-z",
            authority=authority.derive(operation_class="git.status"),
        )
        return not _working_tree_matches_index(listing, repository, object_id_length)

    def _object_id_length_sync(
        self, repository: Path, *, authority: EffectCapability
    ) -> int:
        object_format = self.run_sync(
            repository,
            "rev-parse",
            "--show-object-format",
            authority=authority.derive(operation_class="git.object-format"),
        )
        return _object_id_length(object_format)

    @_authorize_sync
    def run_sync_bytes(
        self,
        repository: Path,
        *args: str,
        authority: EffectCapability,
    ) -> bytes:
        """Synchronous binary variant used by recovery dirty checks."""
        self._verify()
        self._authority_or_fail(authority)
        if _git_command(tuple(args)) in _EXACT_EFFECT_COMMANDS:
            raise TrustedGitError(
                "state-changing Git commands require a structured exact effect"
            )
        try:
            stdout, stderr, returncode = _run_sync_bounded(
                [str(self.executable), *self._argv(tuple(args))],
                cwd=repository,
                env=self._environment(),
            )
        except OSError as exc:
            raise TrustedGitError("trusted Git process could not start") from exc
        if returncode != 0:
            message = stderr.decode("utf-8", errors="replace").strip()
            raise TrustedGitError(message or "trusted Git command failed")
        return stdout


def _run_sync_bounded(
    argv: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    max_stdout_bytes: int = 64 * 1024,
    max_stderr_bytes: int = _MAX_GIT_ERROR_BYTES,
    timeout_seconds: float = _MAX_GIT_SYNC_SECONDS,
) -> tuple[bytes, bytes, int]:
    """Run one synchronous Git command with bounded pipes and terminal proof.

    Recovery code cannot use the async process owner, but it must retain the
    same safety properties: both pipes are drained concurrently, output and
    lifetime are bounded before returning, and a failed bound terminates the
    complete POSIX process group before the result is published.
    """
    if (
        not argv
        or max_stdout_bytes <= 0
        or max_stderr_bytes <= 0
        or timeout_seconds <= 0
    ):
        raise ValueError("invalid synchronous Git process limits")
    popen_kwargs: dict[str, object] = {
        "cwd": cwd,
        "env": env,
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
    }
    if os.name == "nt":
        popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        popen_kwargs["start_new_session"] = True
    process = subprocess.Popen(argv, **popen_kwargs)
    assert process.stdout is not None
    assert process.stderr is not None
    streams = ((process.stdout, max_stdout_bytes), (process.stderr, max_stderr_bytes))
    outputs = [bytearray(), bytearray()]
    failures: list[str] = []
    failure_lock = threading.Lock()
    stop_readers = threading.Event()

    def read_stream(index: int, stream: Any, limit: int) -> None:
        try:
            while not stop_readers.is_set():
                remaining = max(limit + 1 - len(outputs[index]), 1)
                chunk = stream.read(min(_MAX_GIT_CHUNK_BYTES, remaining))
                if not chunk:
                    return
                outputs[index].extend(chunk)
                if len(outputs[index]) > limit:
                    with failure_lock:
                        failures.append(
                            "trusted Git "
                            f"{'stdout' if index == 0 else 'stderr'} output exceeds its bound"
                        )
                    stop_readers.set()
                    return
        except (OSError, ValueError) as exc:
            with failure_lock:
                failures.append(f"trusted Git output reader failed: {exc}")
            stop_readers.set()

    readers = [
        threading.Thread(
            target=read_stream,
            args=(index, stream, limit),
            name=f"khaos-git-sync-reader-{index}",
            daemon=True,
        )
        for index, (stream, limit) in enumerate(streams)
    ]
    for reader in readers:
        reader.start()

    def terminate(force: bool) -> None:
        if process.poll() is not None:
            return
        if os.name != "nt":
            signum = signal.SIGKILL if force else signal.SIGTERM
            try:
                os.killpg(process.pid, signum)
                return
            except ProcessLookupError:
                return
            except OSError:
                if not force:
                    return
        if force:
            process.kill()
        else:
            process.terminate()

    deadline = time.monotonic() + timeout_seconds
    timed_out = False
    while process.poll() is None:
        with failure_lock:
            failed = bool(failures)
        if stop_readers.is_set() or failed:
            terminate(force=False)
            break
        if time.monotonic() >= deadline:
            timed_out = True
            stop_readers.set()
            terminate(force=False)
            break
        time.sleep(0.005)

    try:
        process.wait(timeout=1.0)
    except subprocess.TimeoutExpired:
        stop_readers.set()
        terminate(force=True)
        try:
            process.wait(timeout=1.0)
        except subprocess.TimeoutExpired as exc:
            raise TrustedGitError(
                "trusted Git synchronous process terminal state could not be proved"
            ) from exc
    finally:
        for reader in readers:
            reader.join(timeout=1.0)
        if any(reader.is_alive() for reader in readers):
            stop_readers.set()
        for stream, _limit in streams:
            try:
                stream.close()
            except OSError:
                pass
        for reader in readers:
            if reader.is_alive():
                reader.join(timeout=1.0)

    if any(reader.is_alive() for reader in readers):
        raise TrustedGitError("trusted Git output readers did not terminate")
    with failure_lock:
        failure = failures[0] if failures else ""
    if timed_out:
        raise TrustedGitError("trusted Git synchronous command exceeded its time limit")
    if failure:
        raise TrustedGitError(failure)
    return bytes(outputs[0]), bytes(outputs[1]), int(process.returncode)


def _safe_member_parts(name: str) -> tuple[str, ...]:
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise TrustedGitError(f"Git archive contains an unsafe path: {name!r}")
    if _PROTECTED_GIT_NAME in {part.casefold() for part in path.parts}:
        raise TrustedGitError("Git archive attempted to materialize .git metadata")
    return tuple(path.parts)


def _ensure_directory(root: Path, parts: tuple[str, ...]) -> Path:
    current = root
    for part in parts:
        current /= part
        try:
            info = current.lstat()
        except FileNotFoundError:
            current.mkdir(mode=0o700)
            info = current.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise TrustedGitError("Git archive parent traverses a non-directory")
    return current


def _parse_tree_listing(
    listing: bytes,
    *,
    object_id_length: int = 40,
    max_entries: int | None = None,
) -> list[tuple[str, str, str]]:
    """Parse NUL-delimited ``ls-tree`` records without pathname quoting."""
    entries: list[tuple[str, str, str]] = []
    for record in listing.split(b"\0"):
        if not record:
            continue
        metadata, separator, raw_path = record.partition(b"\t")
        fields = metadata.split()
        if not separator or len(fields) != 3:
            raise TrustedGitError("Git tree listing has an invalid record")
        try:
            mode = fields[0].decode("ascii")
            object_type = fields[1].decode("ascii")
            object_id = fields[2].decode("ascii")
            path = os.fsdecode(raw_path)
        except UnicodeDecodeError as exc:
            raise TrustedGitError("Git tree listing is not valid text metadata") from exc
        if mode == "160000":
            raise TrustedGitError(
                "Git submodules/gitlinks are unsupported by Khaos sandboxed workspace bootstrap"
            )
        if object_type != "blob" or len(object_id) != object_id_length:
            raise TrustedGitError("Git tree contains an unsupported object")
        if any(character not in "0123456789abcdef" for character in object_id):
            raise TrustedGitError("Git tree contains an invalid object id")
        if mode not in {"100644", "100755", "120000"}:
            raise TrustedGitError(f"Git tree contains an unsupported mode: {path}")
        entries.append((mode, object_id, path))
        if max_entries is not None and len(entries) > max_entries:
            raise TrustedGitError("Git tree exceeds the entry limit")
    return entries


def _parse_index_listing(
    listing: bytes, *, object_id_length: int | None = None
) -> list[tuple[str, str, str]]:
    """Parse NUL-delimited ``ls-files --stage`` records."""
    entries: list[tuple[str, str, str]] = []
    for record in listing.split(b"\0"):
        if not record:
            continue
        metadata, separator, raw_path = record.partition(b"\t")
        fields = metadata.split()
        if not separator or len(fields) != 3:
            raise TrustedGitError("Git index listing has an invalid record")
        try:
            mode = fields[0].decode("ascii")
            object_id = fields[1].decode("ascii")
            stage = fields[2].decode("ascii")
            path = os.fsdecode(raw_path)
        except UnicodeDecodeError as exc:
            raise TrustedGitError("Git index listing is not valid metadata") from exc
        if stage != "0" or (
            len(object_id) not in {40, 64}
            if object_id_length is None
            else len(object_id) != object_id_length
        ):
            raise TrustedGitError("Git index contains a conflicted or invalid entry")
        if any(character not in "0123456789abcdef" for character in object_id):
            raise TrustedGitError("Git index contains an invalid object id")
        if mode == "160000":
            raise TrustedGitError(
                "Git submodules/gitlinks are unsupported by Khaos sandboxed workspace bootstrap"
            )
        if mode not in {"100644", "100755", "120000"}:
            raise TrustedGitError(f"Git index contains an unsupported mode: {path}")
        entries.append((mode, object_id, path))
    return entries


def _blob_hasher(object_id: str, size: int) -> hashlib._Hash:
    algorithm = "sha256" if len(object_id) == 64 else "sha1"
    digest = hashlib.new(algorithm)
    digest.update(f"blob {size}\0".encode("ascii"))
    return digest


def _working_tree_matches_index(
    listing: bytes, repository: Path, object_id_length: int | None = None
) -> bool:
    """Compare raw worktree bytes to the index without clean/smudge filters."""
    for mode, object_id, path in _parse_index_listing(
        listing, object_id_length=object_id_length
    ):
        parts = _safe_member_parts(path)
        target = repository.joinpath(*parts)
        try:
            info = target.lstat()
        except FileNotFoundError:
            return False
        if mode == "120000":
            if not stat.S_ISLNK(info.st_mode):
                return False
            content = os.fsencode(os.readlink(target))
            digest = _blob_hasher(object_id, len(content))
            digest.update(content)
        else:
            if not stat.S_ISREG(info.st_mode):
                return False
            executable = bool(info.st_mode & 0o111)
            if executable != (mode == "100755"):
                return False
            digest = _blob_hasher(object_id, int(info.st_size))
            descriptor = os.open(
                target,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            )
            try:
                while chunk := os.read(descriptor, 1024 * 1024):
                    digest.update(chunk)
            finally:
                os.close(descriptor)
        if digest.hexdigest() != object_id:
            return False
    return True


async def _read_blob_separator(stdout: asyncio.StreamReader) -> None:
    separator = await stdout.readexactly(1)
    if separator != b"\n":
        raise TrustedGitError("Git blob response is missing its separator")


async def _drain_stream_limited(
    stream: asyncio.StreamReader, max_bytes: int
) -> tuple[bytes, bool]:
    """Drain diagnostics without allowing output or pipe backpressure to grow."""
    output = bytearray()
    overflow = False
    while chunk := await stream.read(_MAX_GIT_CHUNK_BYTES):
        remaining = max_bytes - len(output)
        if remaining > 0:
            output.extend(chunk[:remaining])
        if len(chunk) > max(remaining, 0):
            overflow = True
        # Once the preview is full, continue reading and discard diagnostics
        # so the child cannot block on a full stderr pipe.
    return bytes(output), overflow


def _object_id_length(object_format: str) -> int:
    if object_format == "sha1":
        return 40
    if object_format == "sha256":
        return 64
    raise TrustedGitError(f"unsupported Git object format: {object_format}")


def _verify_blob_digest(object_id: str, content: bytes) -> None:
    digest = _blob_hasher(object_id, len(content))
    digest.update(content)
    if digest.hexdigest() != object_id:
        raise TrustedGitError("Git blob content hash did not match its object id")


def _safe_symlink_target(parts: tuple[str, ...], raw_target: bytes) -> str:
    """Reject symlinks that escape the disposable worktree or target metadata."""
    if b"\0" in raw_target:
        raise TrustedGitError("Git symlink target contains NUL")
    target = os.fsdecode(raw_target)
    path = PurePosixPath(target)
    if path.is_absolute():
        raise TrustedGitError("Git symlink target is absolute")
    resolved = list(parts[:-1])
    for part in path.parts:
        if part in {"", "."}:
            continue
        if part == "..":
            if not resolved:
                raise TrustedGitError("Git symlink target escapes the worktree")
            resolved.pop()
            continue
        resolved.append(part)
    if _PROTECTED_GIT_NAME in {part.casefold() for part in resolved}:
        raise TrustedGitError("Git symlink target reaches protected metadata")
    return target


__all__ = [
    "FileIdentity",
    "GitEffect",
    "GitStreamResult",
    "TrustedGitError",
    "TrustedGitRunner",
    "WorkspaceBootstrapLimits",
    "resolve_trusted_git",
]
