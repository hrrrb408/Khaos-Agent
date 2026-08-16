"""Typed resource scopes and their fail-closed partial order.

The authority daemon signs opaque resource digests.  That keeps the native
receipt protocol small, but an opaque digest alone cannot prove that a child
resource is contained by its parent.  This module is the semantic layer for
that decision: callers construct a typed scope, register its canonical digest
in the effective policy snapshot, and ask :class:`TypedResourcePartialOrder`
whether a requested transition is a subset.

The model is deliberately conservative.  Paths, hosts, refs, commands, and
credential names are concrete values; wildcard syntax is rejected.  Missing
catalog entries, mismatched digests, cross-kind comparisons, and malformed
values all fail closed.  The catalog is immutable after construction so a
policy decision cannot change underneath a signed receipt.
"""

from __future__ import annotations

import hashlib
import json
import posixpath
from abc import ABC, abstractmethod
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Final

from khaos.coding.planning.security_identities import CanonicalWorkspaceId


class ResourceScopeError(ValueError):
    """Raised when a typed resource scope cannot be trusted."""


class ResourceScopeKind(str, Enum):
    """Supported semantic resource families."""

    FILESYSTEM = "filesystem"
    NETWORK = "network"
    GIT_REF = "git-ref"
    EXECUTION = "execution"
    CREDENTIAL = "credential"


_SCHEMA_VERSION: Final = 1
_HEX_DIGITS: Final = frozenset("0123456789abcdef")
_WILDCARD_CHARS: Final = frozenset("*?[]")


def _require_text(field: str, value: object) -> str:
    if type(value) is not str or not value or "\x00" in value:
        raise ResourceScopeError(f"{field} must be a non-empty string")
    if len(value) > 4096:
        raise ResourceScopeError(f"{field} is too long")
    return value


def _require_concrete(field: str, value: object) -> str:
    text = _require_text(field, value)
    if any(char in text for char in _WILDCARD_CHARS):
        raise ResourceScopeError(f"{field} must not contain wildcard syntax")
    return text


def _require_tokens(field: str, values: Iterable[str]) -> frozenset[str]:
    if isinstance(values, (str, bytes)):
        raise ResourceScopeError(f"{field} must be a collection of concrete values")
    normalized: set[str] = set()
    for value in values:
        normalized.add(_require_concrete(field, value))
    if not normalized:
        raise ResourceScopeError(f"{field} must not be empty")
    return frozenset(normalized)


def _canonical_path(field: str, value: object) -> str:
    raw = _require_concrete(field, value)
    if not raw.startswith("/"):
        raise ResourceScopeError(f"{field} must be absolute")
    raw_parts = tuple(part for part in raw.split("/") if part)
    if ".." in raw_parts:
        raise ResourceScopeError(f"{field} must not contain parent traversal")
    normalized = posixpath.normpath(raw)
    if normalized == "." or not normalized.startswith("/"):
        raise ResourceScopeError(f"{field} is not canonical")
    return normalized


def _path_contains(parent: str, child: str) -> bool:
    if parent == "/":
        return child.startswith("/")
    return child == parent or child.startswith(parent.rstrip("/") + "/")


def _canonical_scheme_set(field: str, values: Iterable[str]) -> frozenset[str]:
    result = _require_tokens(field, values)
    return frozenset(value.lower() for value in result)


def _canonical_host_set(field: str, values: Iterable[str]) -> frozenset[str]:
    hosts: set[str] = set()
    for value in values:
        host = _require_concrete(field, value).rstrip(".").lower()
        if not host:
            raise ResourceScopeError(f"{field} contains an empty host")
        try:
            hosts.add(host.encode("idna").decode("ascii"))
        except UnicodeError as exc:
            raise ResourceScopeError(f"{field} contains an invalid host") from exc
    if not hosts:
        raise ResourceScopeError(f"{field} must not be empty")
    return frozenset(hosts)


def _require_kind(value: ResourceScopeKind, expected: ResourceScopeKind) -> None:
    if value is not expected:
        raise ResourceScopeError(f"scope kind must be {expected.value}")


class ResourceScope(ABC):
    """Base contract implemented by every semantic resource scope."""

    kind: ResourceScopeKind

    @abstractmethod
    def contains(self, child: ResourceScope) -> bool:
        """Return whether ``child`` is no broader than this scope."""

    @abstractmethod
    def canonical(self) -> dict[str, object]:
        """Return the canonical, JSON-safe scope body."""

    def digest(self) -> str:
        """Return the stable SHA-256 digest used by the policy catalog."""
        payload = {
            "schema_version": _SCHEMA_VERSION,
            "kind": self.kind.value,
            "scope": self.canonical(),
        }
        encoded = json.dumps(
            payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class FilesystemScope(ResourceScope):
    """Workspace-relative filesystem capability."""

    workspace_id: CanonicalWorkspaceId
    root: str
    operations: frozenset[str]
    kind: ResourceScopeKind = ResourceScopeKind.FILESYSTEM

    def __post_init__(self) -> None:
        _require_kind(self.kind, ResourceScopeKind.FILESYSTEM)
        object.__setattr__(self, "workspace_id", CanonicalWorkspaceId(
            _require_text("workspace_id", self.workspace_id)
        ))
        object.__setattr__(self, "root", _canonical_path("root", self.root))
        object.__setattr__(self, "operations", _require_tokens("operations", self.operations))

    def contains(self, child: ResourceScope) -> bool:
        return (
            isinstance(child, FilesystemScope)
            and self.workspace_id == child.workspace_id
            and _path_contains(self.root, child.root)
            and self.operations.issuperset(child.operations)
        )

    def canonical(self) -> dict[str, object]:
        return {
            "workspace_id": str(self.workspace_id),
            "root": self.root,
            "operations": sorted(self.operations),
        }


@dataclass(frozen=True, slots=True)
class NetworkScope(ResourceScope):
    """Concrete network origins, ports, and URL path prefixes."""

    schemes: frozenset[str]
    hosts: frozenset[str]
    ports: frozenset[int]
    path_prefixes: frozenset[str]
    operations: frozenset[str]
    kind: ResourceScopeKind = ResourceScopeKind.NETWORK

    def __post_init__(self) -> None:
        _require_kind(self.kind, ResourceScopeKind.NETWORK)
        object.__setattr__(self, "schemes", _canonical_scheme_set("schemes", self.schemes))
        object.__setattr__(self, "hosts", _canonical_host_set("hosts", self.hosts))
        if not self.ports or any(
            type(port) is not int or not 1 <= port <= 65535 for port in self.ports
        ):
            raise ResourceScopeError("ports must contain explicit values from 1 to 65535")
        object.__setattr__(self, "ports", frozenset(self.ports))
        prefixes = frozenset(
            _canonical_path("path_prefix", prefix) for prefix in self.path_prefixes
        )
        if not prefixes:
            raise ResourceScopeError("path_prefixes must not be empty")
        object.__setattr__(self, "path_prefixes", prefixes)
        object.__setattr__(self, "operations", _require_tokens("operations", self.operations))

    def contains(self, child: ResourceScope) -> bool:
        if not isinstance(child, NetworkScope):
            return False
        return (
            self.schemes.issuperset(child.schemes)
            and self.hosts.issuperset(child.hosts)
            and self.ports.issuperset(child.ports)
            and self.operations.issuperset(child.operations)
            and all(
                any(_path_contains(parent, requested) for parent in self.path_prefixes)
                for requested in child.path_prefixes
            )
        )

    def canonical(self) -> dict[str, object]:
        return {
            "schemes": sorted(self.schemes),
            "hosts": sorted(self.hosts),
            "ports": sorted(self.ports),
            "path_prefixes": sorted(self.path_prefixes),
            "operations": sorted(self.operations),
        }


@dataclass(frozen=True, slots=True)
class GitRefScope(ResourceScope):
    """Repository/ref capability with exact refs and operations."""

    repository: str
    refs: frozenset[str]
    operations: frozenset[str]
    kind: ResourceScopeKind = ResourceScopeKind.GIT_REF

    def __post_init__(self) -> None:
        _require_kind(self.kind, ResourceScopeKind.GIT_REF)
        object.__setattr__(self, "repository", _require_concrete("repository", self.repository))
        object.__setattr__(self, "refs", _require_tokens("refs", self.refs))
        object.__setattr__(self, "operations", _require_tokens("operations", self.operations))

    def contains(self, child: ResourceScope) -> bool:
        return (
            isinstance(child, GitRefScope)
            and self.repository == child.repository
            and self.refs.issuperset(child.refs)
            and self.operations.issuperset(child.operations)
        )

    def canonical(self) -> dict[str, object]:
        return {
            "repository": self.repository,
            "refs": sorted(self.refs),
            "operations": sorted(self.operations),
        }


@dataclass(frozen=True, slots=True)
class ExecutionScope(ResourceScope):
    """Workspace-bound executable and argument-prefix capability."""

    workspace_id: CanonicalWorkspaceId
    executable: str
    argv_prefix: tuple[str, ...]
    cwd: str
    operations: frozenset[str]
    argv_exact: bool = False
    kind: ResourceScopeKind = ResourceScopeKind.EXECUTION

    def __post_init__(self) -> None:
        _require_kind(self.kind, ResourceScopeKind.EXECUTION)
        object.__setattr__(self, "workspace_id", CanonicalWorkspaceId(
            _require_text("workspace_id", self.workspace_id)
        ))
        object.__setattr__(self, "executable", _require_concrete("executable", self.executable))
        if isinstance(self.argv_prefix, str):
            raise ResourceScopeError("argv_prefix must be a tuple of concrete arguments")
        argv = tuple(_require_concrete("argv_prefix", value) for value in self.argv_prefix)
        object.__setattr__(self, "argv_prefix", argv)
        object.__setattr__(self, "cwd", _canonical_path("cwd", self.cwd))
        object.__setattr__(self, "operations", _require_tokens("operations", self.operations))
        if type(self.argv_exact) is not bool:
            raise ResourceScopeError("argv_exact must be boolean")

    def contains(self, child: ResourceScope) -> bool:
        if not isinstance(child, ExecutionScope):
            return False
        if (
            self.workspace_id != child.workspace_id
            or self.executable != child.executable
            or self.cwd != child.cwd
            or not self.operations.issuperset(child.operations)
        ):
            return False
        if self.argv_exact:
            return child.argv_exact and self.argv_prefix == child.argv_prefix
        if child.argv_exact:
            return child.argv_prefix[: len(self.argv_prefix)] == self.argv_prefix
        return child.argv_prefix[: len(self.argv_prefix)] == self.argv_prefix

    def canonical(self) -> dict[str, object]:
        return {
            "workspace_id": str(self.workspace_id),
            "executable": self.executable,
            "argv_prefix": list(self.argv_prefix),
            "argv_exact": self.argv_exact,
            "cwd": self.cwd,
            "operations": sorted(self.operations),
        }


@dataclass(frozen=True, slots=True)
class CredentialScope(ResourceScope):
    """Named credential capability; values are never included in the scope."""

    provider: str
    names: frozenset[str]
    operations: frozenset[str]
    kind: ResourceScopeKind = ResourceScopeKind.CREDENTIAL

    def __post_init__(self) -> None:
        _require_kind(self.kind, ResourceScopeKind.CREDENTIAL)
        object.__setattr__(self, "provider", _require_concrete("provider", self.provider))
        object.__setattr__(self, "names", _require_tokens("names", self.names))
        object.__setattr__(self, "operations", _require_tokens("operations", self.operations))

    def contains(self, child: ResourceScope) -> bool:
        return (
            isinstance(child, CredentialScope)
            and self.provider == child.provider
            and self.names.issuperset(child.names)
            and self.operations.issuperset(child.operations)
        )

    def canonical(self) -> dict[str, object]:
        return {
            "provider": self.provider,
            "names": sorted(self.names),
            "operations": sorted(self.operations),
        }


class TypedResourcePartialOrder:
    """Immutable semantic subset checker for authority resource digests."""

    def __init__(self, scopes: Mapping[str, ResourceScope]) -> None:
        validated: dict[str, ResourceScope] = {}
        for digest, scope in scopes.items():
            if type(digest) is not str or len(digest) != 64:
                raise ResourceScopeError("resource catalog digest is invalid")
            if any(char not in _HEX_DIGITS for char in digest.lower()):
                raise ResourceScopeError("resource catalog digest is not hexadecimal")
            if not isinstance(scope, ResourceScope):
                raise ResourceScopeError("resource catalog contains an invalid scope")
            canonical_digest = scope.digest()
            if digest.lower() != canonical_digest:
                raise ResourceScopeError("resource catalog digest does not match scope")
            validated[digest.lower()] = scope
        self._scopes: Mapping[str, ResourceScope] = MappingProxyType(validated)

    @property
    def scopes(self) -> Mapping[str, ResourceScope]:
        """Return the read-only policy snapshot."""
        return self._scopes

    def resolve(self, digest: str) -> ResourceScope:
        """Resolve a digest or reject an unknown semantic resource."""
        if type(digest) is not str:
            raise ResourceScopeError("resource digest is invalid")
        try:
            return self._scopes[digest.lower()]
        except KeyError as exc:
            raise ResourceScopeError("resource digest is not in the typed catalog") from exc

    def contains(self, parent_digest: str, child_digest: str) -> bool:
        """Return false for every malformed or unknown comparison."""
        try:
            parent = self.resolve(parent_digest)
            child = self.resolve(child_digest)
        except ResourceScopeError:
            return False
        return parent.contains(child)

    def require_subset(self, parent_digest: str, child_digest: str) -> None:
        """Require a known, same-kind child scope contained by its parent."""
        parent = self.resolve(parent_digest)
        child = self.resolve(child_digest)
        if not parent.contains(child):
            raise ResourceScopeError("requested resource is not a typed subset")

    def require_transition(
        self,
        *,
        parent_digest: str,
        requested_scope: str,
        source_operation: str,
        target_operation: str,
    ) -> None:
        """Validate one same-family operation/resource transition."""
        source_family = _operation_family(source_operation)
        target_family = _operation_family(target_operation)
        if source_family != target_family:
            raise ResourceScopeError("typed resource transition crosses operation families")
        self.require_subset(parent_digest, requested_scope)


def _operation_family(operation: str) -> str:
    if type(operation) is not str or "." not in operation:
        raise ResourceScopeError("operation must contain a family separator")
    family, action = operation.split(".", 1)
    if not family or not action:
        raise ResourceScopeError("operation family is invalid")
    return family


__all__ = [
    "CredentialScope",
    "ExecutionScope",
    "FilesystemScope",
    "GitRefScope",
    "NetworkScope",
    "ResourceScope",
    "ResourceScopeError",
    "ResourceScopeKind",
    "TypedResourcePartialOrder",
]
