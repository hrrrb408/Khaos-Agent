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


@dataclass(frozen=True)
class ExecutionRequest:
    argv: tuple[str, ...]
    cwd: Path
    writable_roots: tuple[Path, ...] = ()
    environment: dict[str, str] = field(default_factory=dict)
    allowed_environment_keys: frozenset[str] = frozenset({"PATH", "HOME", "LANG", "LC_ALL", "TMPDIR"})
    network_policy: NetworkPolicy = NetworkPolicy.NONE
    budget: ResourceBudget = field(default_factory=ResourceBudget)


@dataclass(frozen=True)
class ExecutionResult:
    execution_id: str
    status: str
    return_code: int | None
    stdout: str
    stderr: str
    duration_ms: int
    diagnostics: dict[str, object] = field(default_factory=dict)
