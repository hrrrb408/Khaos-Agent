"""Execution request/result models and safe defaults."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class NetworkPolicy(str, Enum):
    NONE = "none"
    LOOPBACK_ONLY = "loopback-only"
    UNRESTRICTED_WITH_APPROVAL = "unrestricted-with-approval"


@dataclass(frozen=True)
class ResourceBudget:
    timeout_seconds: float = 120.0
    output_bytes: int = 65536
    pids: int = 256
    cpu_count: float = 1.0
    memory_bytes: int = 512 * 1024 * 1024
    tmpfs_bytes: int = 256 * 1024 * 1024


@dataclass(frozen=True)
class ExecutionRequest:
    argv: tuple[str, ...]
    cwd: Path
    writable_roots: tuple[Path, ...] = ()
    environment: dict[str, str] = field(default_factory=dict)
    allowed_environment_keys: frozenset[str] = frozenset({"PATH", "HOME", "LANG", "LC_ALL", "TMPDIR"})
    network_policy: NetworkPolicy = NetworkPolicy.NONE
    budget: ResourceBudget = field(default_factory=ResourceBudget)
    task_id: str | None = None
    workspace_id: str | None = None
    access_mode: str = "read-only"
    backend_hint: str = "default"
    correlation_id: str | None = None


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


@dataclass(frozen=True)
class ExecutionResult:
    execution_id: str
    status: str
    return_code: int | None
    stdout: str
    stderr: str
    duration_ms: int
    diagnostics: dict[str, object] = field(default_factory=dict)
