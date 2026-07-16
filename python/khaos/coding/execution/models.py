"""Execution request/result models and safe defaults."""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class NetworkPolicy(str, Enum):
    NONE = "none"
    LOOPBACK_ONLY = "loopback-only"
    UNRESTRICTED_WITH_APPROVAL = "unrestricted-with-approval"


class FileSystemAccess(str, Enum):
    """Filesystem authority requested for one execution."""

    READ_ONLY = "read-only"
    WORKSPACE_WRITE = "workspace-write"


@dataclass(frozen=True)
class ResourceBudget:
    timeout_seconds: float = 120.0
    output_bytes: int = 65536
    pids: int = 256
    # CPU shares/cores are enforced only by backends with a native quota
    # controller (currently Docker). Host backends use cpu_time_seconds.
    cpu_count: float = 1.0
    cpu_time_seconds: float = 120.0
    memory_bytes: int = 512 * 1024 * 1024
    tmpfs_bytes: int = 256 * 1024 * 1024
    filesystem_entries: int = 100_000
    file_bytes: int = 64 * 1024 * 1024
    open_files: int = 256


@dataclass(frozen=True)
class PermissionProfile:
    """Versioned, immutable execution authority.

    The profile is the sole security authority consumed by execution
    backends.  Legacy ``ExecutionRequest`` fields remain as a compatibility
    projection during migration, but are normalized from this object before
    execution and cannot override it.
    """

    schema_version: int = 1
    filesystem: FileSystemAccess = FileSystemAccess.READ_ONLY
    network: NetworkPolicy = NetworkPolicy.NONE
    workspace_roots: tuple[Path, ...] = ()
    writable_roots: tuple[Path, ...] = ()
    unreadable_roots: tuple[Path, ...] = field(
        default_factory=lambda: _default_unreadable_roots()
    )
    environment_keys: frozenset[str] = frozenset(
        {"PATH", "LANG", "LC_ALL", "TMPDIR"}
    )
    resources: ResourceBudget = field(default_factory=ResourceBudget)

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise ValueError(
                f"unsupported permission profile schema version: {self.schema_version}"
            )
        filesystem = FileSystemAccess(self.filesystem)
        network = NetworkPolicy(self.network)
        workspace_roots = _canonical_roots(self.workspace_roots)
        writable_roots = _canonical_roots(self.writable_roots)
        # Restricted callers may add deny-read roots but cannot remove the
        # platform minimum. This prevents a forged profile from re-exposing
        # host credential stores.
        unreadable_roots = _canonical_roots(
            (*_default_unreadable_roots(), *self.unreadable_roots)
        )
        if filesystem is FileSystemAccess.READ_ONLY and writable_roots:
            raise ValueError("read-only permission profile cannot contain writable roots")
        if any(root not in workspace_roots for root in writable_roots):
            raise ValueError("writable roots must be contained in workspace roots")
        if any(not isinstance(key, str) or not key for key in self.environment_keys):
            raise ValueError("permission profile environment keys must be non-empty strings")
        _validate_resource_budget(self.resources)
        object.__setattr__(self, "filesystem", filesystem)
        object.__setattr__(self, "network", network)
        object.__setattr__(self, "workspace_roots", workspace_roots)
        object.__setattr__(self, "writable_roots", writable_roots)
        object.__setattr__(self, "unreadable_roots", unreadable_roots)
        object.__setattr__(self, "environment_keys", frozenset(self.environment_keys))

    @classmethod
    def from_legacy(
        cls,
        *,
        access_mode: str,
        network_policy: NetworkPolicy,
        roots: tuple[Path, ...],
        environment_keys: frozenset[str],
        resources: ResourceBudget,
    ) -> "PermissionProfile":
        filesystem = FileSystemAccess(access_mode)
        canonical_roots = _canonical_roots(roots)
        return cls(
            filesystem=filesystem,
            network=NetworkPolicy(network_policy),
            workspace_roots=canonical_roots,
            writable_roots=(
                canonical_roots
                if filesystem is FileSystemAccess.WORKSPACE_WRITE
                else ()
            ),
            unreadable_roots=_default_unreadable_roots(),
            environment_keys=environment_keys,
            resources=resources,
        )

    def bind_workspace(self, root: Path) -> "PermissionProfile":
        """Return a profile bound to exactly one canonical TaskWorkspace."""
        canonical = root.expanduser().resolve()
        return PermissionProfile(
            schema_version=self.schema_version,
            filesystem=self.filesystem,
            network=self.network,
            workspace_roots=(canonical,),
            writable_roots=(
                (canonical,)
                if self.filesystem is FileSystemAccess.WORKSPACE_WRITE
                else ()
            ),
            unreadable_roots=self.unreadable_roots,
            environment_keys=self.environment_keys,
            resources=self.resources,
        )

    def validate_resolved(self) -> None:
        """Fail unless the profile is bound and internally enforceable."""
        if len(self.workspace_roots) != 1:
            raise PermissionError("permission profile must bind exactly one workspace root")
        workspace_root = self.workspace_roots[0]
        if any(
            workspace_root == denied or denied in workspace_root.parents
            for denied in self.unreadable_roots
        ):
            raise PermissionError("workspace root is inside a protected unreadable root")
        if self.filesystem is FileSystemAccess.WORKSPACE_WRITE:
            if self.writable_roots != self.workspace_roots:
                raise PermissionError(
                    "workspace-write profile must bind exactly the active workspace"
                )
        elif self.writable_roots:
            raise PermissionError("read-only profile cannot contain writable roots")

    def digest(self) -> str:
        """Return a stable digest suitable for approval and audit binding."""
        payload = {
            "schema_version": self.schema_version,
            "filesystem": self.filesystem.value,
            "network": self.network.value,
            "workspace_roots": [str(path) for path in self.workspace_roots],
            "writable_roots": [str(path) for path in self.writable_roots],
            "unreadable_roots": [str(path) for path in self.unreadable_roots],
            "environment_keys": sorted(self.environment_keys),
            "resources": {
                "timeout_seconds": self.resources.timeout_seconds,
                "output_bytes": self.resources.output_bytes,
                "pids": self.resources.pids,
                "cpu_count": self.resources.cpu_count,
                "cpu_time_seconds": self.resources.cpu_time_seconds,
                "memory_bytes": self.resources.memory_bytes,
                "tmpfs_bytes": self.resources.tmpfs_bytes,
                "filesystem_entries": self.resources.filesystem_entries,
                "file_bytes": self.resources.file_bytes,
                "open_files": self.resources.open_files,
            },
        }
        encoded = json.dumps(
            payload, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class ExecutionRequest:
    argv: tuple[str, ...]
    cwd: Path
    writable_roots: tuple[Path, ...] = ()
    environment: dict[str, str] = field(default_factory=dict)
    allowed_environment_keys: frozenset[str] = frozenset({"PATH", "LANG", "LC_ALL", "TMPDIR"})
    network_policy: NetworkPolicy = NetworkPolicy.NONE
    budget: ResourceBudget = field(default_factory=ResourceBudget)
    task_id: str | None = None
    workspace_id: str | None = None
    access_mode: str = "read-only"
    backend_hint: str = "default"
    correlation_id: str | None = None
    permission_profile: PermissionProfile | None = None

    def __post_init__(self) -> None:
        profile = self.permission_profile or PermissionProfile.from_legacy(
            access_mode=self.access_mode,
            network_policy=self.network_policy,
            roots=self.writable_roots,
            environment_keys=self.allowed_environment_keys,
            resources=self.budget,
        )
        # Compatibility fields are a projection of the profile.  Explicit
        # profiles always win over conflicting legacy values.
        object.__setattr__(self, "permission_profile", profile)
        object.__setattr__(self, "access_mode", profile.filesystem.value)
        object.__setattr__(self, "network_policy", profile.network)
        object.__setattr__(self, "writable_roots", profile.writable_roots)
        object.__setattr__(self, "allowed_environment_keys", profile.environment_keys)
        object.__setattr__(self, "budget", profile.resources)
        object.__setattr__(
            self,
            "correlation_id",
            self.correlation_id or uuid.uuid4().hex[:12],
        )


@dataclass(frozen=True)
class ResolvedExecutionContext:
    task_id: str
    workspace_id: str
    workspace_state: str
    repository_root: Path
    worktree_path: Path
    cwd: Path
    writable_roots: tuple[Path, ...]
    access_mode: str
    network_policy: NetworkPolicy
    budget: ResourceBudget
    environment: dict[str, str]
    allowed_environment_keys: frozenset[str]
    argv: tuple[str, ...]
    correlation_id: str
    permission_profile: PermissionProfile | None = None

    def __post_init__(self) -> None:
        profile = self.permission_profile or PermissionProfile.from_legacy(
            access_mode=self.access_mode,
            network_policy=self.network_policy,
            roots=self.writable_roots,
            environment_keys=self.allowed_environment_keys,
            resources=self.budget,
        ).bind_workspace(self.worktree_path)
        object.__setattr__(self, "permission_profile", profile)


@dataclass(frozen=True)
class ExecutionResult:
    execution_id: str
    status: str
    return_code: int | None
    stdout: str
    stderr: str
    duration_ms: int
    diagnostics: dict[str, object] = field(default_factory=dict)


def _canonical_roots(roots: tuple[Path, ...]) -> tuple[Path, ...]:
    canonical: list[Path] = []
    for root in roots:
        resolved = Path(root).expanduser().resolve()
        if resolved not in canonical:
            canonical.append(resolved)
    return tuple(canonical)


def _default_unreadable_roots() -> tuple[Path, ...]:
    """Host credential locations hidden from restricted Agent execution."""
    home = Path.home().expanduser().resolve()
    return (
        home / ".ssh",
        home / ".gnupg",
        home / ".aws",
        home / ".kube",
        home / ".config" / "gcloud",
        home / "Library" / "Keychains",
    )


def _validate_resource_budget(budget: ResourceBudget) -> None:
    if budget.timeout_seconds <= 0:
        raise ValueError("resource timeout must be positive")
    if budget.output_bytes <= 0:
        raise ValueError("resource output limit must be positive")
    if budget.pids <= 0 or budget.cpu_count <= 0 or budget.cpu_time_seconds <= 0:
        raise ValueError("resource process and CPU limits must be positive")
    if (
        budget.memory_bytes <= 0
        or budget.tmpfs_bytes <= 0
        or budget.filesystem_entries <= 0
    ):
        raise ValueError("resource memory limits must be positive")
    if budget.file_bytes <= 0 or budget.open_files <= 0:
        raise ValueError("resource file and open-file limits must be positive")
