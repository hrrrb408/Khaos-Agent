"""Execution request/result models and safe defaults."""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING

from khaos.coding.execution.capability import SandboxDecision
from khaos.coding.execution.identity import executable_identity
from khaos.coding.workspace.storage import (
    DEFAULT_WORKSPACE_BYTES,
    DEFAULT_WORKSPACE_ENTRIES,
    WorkspaceStorageSnapshot,
)
from khaos.security.network_broker import NetworkLease

if TYPE_CHECKING:
    from khaos.coding.execution.authority import ExecutionAuthority


class NetworkPolicy(str, Enum):
    NONE = "none"
    LOOPBACK_ONLY = "loopback-only"
    BROKERED = "brokered"
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
    workspace_bytes: int = DEFAULT_WORKSPACE_BYTES
    workspace_entries: int = DEFAULT_WORKSPACE_ENTRIES
    file_bytes: int = 64 * 1024 * 1024
    open_files: int = 256

    def digest(self) -> str:
        """Return the immutable resource authority digest."""
        return _canonical_digest(
            {
                "timeout_seconds": self.timeout_seconds,
                "output_bytes": self.output_bytes,
                "pids": self.pids,
                "cpu_count": self.cpu_count,
                "cpu_time_seconds": self.cpu_time_seconds,
                "memory_bytes": self.memory_bytes,
                "tmpfs_bytes": self.tmpfs_bytes,
                "filesystem_entries": self.filesystem_entries,
                "workspace_bytes": self.workspace_bytes,
                "workspace_entries": self.workspace_entries,
                "file_bytes": self.file_bytes,
                "open_files": self.open_files,
            }
        )


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
    network_broker: NetworkLease | None = None
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
        if network is NetworkPolicy.BROKERED and self.network_broker is None:
            raise ValueError("brokered network profile requires a NetworkLease")
        if network is not NetworkPolicy.BROKERED and self.network_broker is not None:
            raise ValueError("NetworkLease is only valid for a brokered profile")
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
        network_broker: NetworkLease | None = None,
        roots: tuple[Path, ...],
        environment_keys: frozenset[str],
        resources: ResourceBudget,
    ) -> PermissionProfile:
        filesystem = FileSystemAccess(access_mode)
        canonical_roots = _canonical_roots(roots)
        return cls(
            filesystem=filesystem,
            network=NetworkPolicy(network_policy),
            network_broker=network_broker,
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

    def bind_workspace(self, root: Path) -> PermissionProfile:
        """Return a profile bound to exactly one canonical TaskWorkspace."""
        canonical = root.expanduser().resolve()
        return PermissionProfile(
            schema_version=self.schema_version,
            filesystem=self.filesystem,
            network=self.network,
            network_broker=self.network_broker,
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
            "network_broker": (
                self.network_broker.identity_digest
                if self.network_broker is not None
                else None
            ),
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
                "workspace_bytes": self.resources.workspace_bytes,
                "workspace_entries": self.resources.workspace_entries,
                "file_bytes": self.resources.file_bytes,
                "open_files": self.resources.open_files,
            },
        }
        encoded = json.dumps(
            payload, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class ResolvedSpawnPlan:
    """Immutable plan consumed by approval and the final spawn boundary.

    The plan deliberately contains the final, non-secret environment values
    used for executable resolution.  Backends may add an implementation
    wrapper (for example a native launcher or ``docker run``), but they must
    retain this plan as the authority for the model-controlled command,
    workspace identities, sandbox decision and resource budget.
    """

    principal_id: str
    project_id: str
    session_id: str
    task_id: str
    turn_id: str
    step_id: str
    workspace_generation: int
    workspace_root_device: int | None
    workspace_root_inode: int | None
    workspace_cwd_device: int | None
    workspace_cwd_inode: int | None
    permission_profile_digest: str
    sandbox_decision_digest: str
    network_authority: str
    environment: tuple[tuple[str, str], ...]
    executable_identity: str
    argv: tuple[str, ...]
    budget_digest: str
    plan_digest: str = ""
    principal_kind: str = ""
    parent_principal_id: str = ""
    delegation_digest: str = ""
    source_transport: str = ""

    def __post_init__(self) -> None:
        required = (
            self.principal_id,
            self.project_id,
            self.session_id,
            self.task_id,
            self.turn_id,
            self.step_id,
            self.permission_profile_digest,
            self.sandbox_decision_digest,
            self.network_authority,
            self.executable_identity,
            self.budget_digest,
        )
        if any(not isinstance(value, str) or not value for value in required):
            raise ValueError("resolved spawn plan identity fields must not be empty")
        if self.workspace_generation < 0:
            raise ValueError("resolved spawn plan workspace generation must be non-negative")
        typed = (self.principal_kind, self.parent_principal_id, self.delegation_digest)
        if any(typed) and not all(typed):
            raise ValueError("resolved spawn plan typed principal binding is incomplete")
        if self.principal_kind and self.principal_kind not in {
            "human", "gateway", "channel", "automation", "subagent", "browser"
        }:
            raise ValueError("resolved spawn plan principal kind is invalid")
        if self.delegation_digest and (
            len(self.delegation_digest) != 64
            or any(c not in "0123456789abcdef" for c in self.delegation_digest)
        ):
            raise ValueError("resolved spawn plan delegation digest is invalid")
        if not self.argv or any(not isinstance(value, str) or not value for value in self.argv):
            raise ValueError("resolved spawn plan argv must contain non-empty strings")
        normalized_environment = tuple(
            (str(key), str(value)) for key, value in self.environment
        )
        if tuple(sorted(normalized_environment)) != normalized_environment:
            raise ValueError("resolved spawn plan environment must be sorted")
        if len({key for key, _ in normalized_environment}) != len(normalized_environment):
            raise ValueError("resolved spawn plan environment keys must be unique")
        object.__setattr__(self, "environment", normalized_environment)
        calculated = _canonical_digest(self._payload())
        if self.plan_digest and self.plan_digest != calculated:
            raise ValueError("resolved spawn plan digest does not match its contents")
        object.__setattr__(self, "plan_digest", calculated)

    def _payload(self) -> dict[str, object]:
        return {
            "principal_id": self.principal_id,
            "project_id": self.project_id,
            "session_id": self.session_id,
            "task_id": self.task_id,
            "turn_id": self.turn_id,
            "step_id": self.step_id,
            "workspace_generation": self.workspace_generation,
            "workspace_root_device": self.workspace_root_device,
            "workspace_root_inode": self.workspace_root_inode,
            "workspace_cwd_device": self.workspace_cwd_device,
            "workspace_cwd_inode": self.workspace_cwd_inode,
            "permission_profile_digest": self.permission_profile_digest,
            "sandbox_decision_digest": self.sandbox_decision_digest,
            "network_authority": self.network_authority,
            "environment": self.environment,
            "executable_identity": self.executable_identity,
            "argv": self.argv,
            "budget_digest": self.budget_digest,
            "principal_kind": self.principal_kind,
            "parent_principal_id": self.parent_principal_id,
            "delegation_digest": self.delegation_digest,
        }

    def digest(self) -> str:
        """Return the canonical authority digest for this plan."""
        return self.plan_digest

    def is_valid(self) -> bool:
        """Return whether the stored digest still covers every field."""
        return self.plan_digest == _canonical_digest(self._payload())


@dataclass(frozen=True)
class ExecutionRequest:
    argv: tuple[str, ...]
    cwd: Path
    writable_roots: tuple[Path, ...] = ()
    environment: dict[str, str] = field(default_factory=dict)
    allowed_environment_keys: frozenset[str] = frozenset({"PATH", "LANG", "LC_ALL", "TMPDIR"})
    network_policy: NetworkPolicy = NetworkPolicy.NONE
    network_broker: NetworkLease | None = None
    budget: ResourceBudget = field(default_factory=ResourceBudget)
    task_id: str | None = None
    workspace_id: str | None = None
    access_mode: str = "read-only"
    backend_hint: str = "default"
    correlation_id: str | None = None
    permission_profile: PermissionProfile | None = None
    workspace_baseline: WorkspaceStorageSnapshot | None = None
    # Final pre-exec identity binding for production TaskWorkspace launches.
    # The supervisor checks these again in the forked child so a path swap
    # after the async workspace check fails closed.
    workspace_root_identity: tuple[int, int] | None = None
    workspace_cwd_identity: tuple[int, int] | None = None
    executable_identity: str = ""
    sandbox_decision: SandboxDecision | None = None
    spawn_plan: ResolvedSpawnPlan | None = None
    execution_authority: ExecutionAuthority | None = None

    def __post_init__(self) -> None:
        profile = self.permission_profile or PermissionProfile.from_legacy(
            access_mode=self.access_mode,
            network_policy=self.network_policy,
            network_broker=self.network_broker,
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
        if not self.executable_identity:
            object.__setattr__(
                self,
                "executable_identity",
                executable_identity(self.argv, self.environment),
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
    workspace_baseline: WorkspaceStorageSnapshot | None = None
    workspace_root_identity: tuple[int, int] | None = None
    workspace_cwd_identity: tuple[int, int] | None = None
    executable_identity: str = ""
    sandbox_decision: SandboxDecision | None = None
    spawn_plan: ResolvedSpawnPlan | None = None
    workspace_generation: int = 0
    execution_authority: ExecutionAuthority | None = None

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
        or budget.workspace_bytes <= 0
        or budget.workspace_entries <= 0
    ):
        raise ValueError("resource memory limits must be positive")
    if budget.file_bytes <= 0 or budget.open_files <= 0:
        raise ValueError("resource file and open-file limits must be positive")


def _canonical_digest(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
