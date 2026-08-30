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

import errno
import os
import posixpath
import stat
from abc import ABC, abstractmethod
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import Final, cast

from khaos.coding.planning.security_identities import CanonicalWorkspaceId
from khaos.security.protocol_boundary import canonical_digest, strict_json_loads
from khaos.security.windows_trust import (
    WindowsTrustError,
    validate_windows_trusted_descriptor,
    validate_windows_trusted_path,
)


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
MAX_TYPED_RESOURCE_CATALOG_BYTES: Final = 4 * 1024 * 1024
_HEX_DIGITS: Final = frozenset("0123456789abcdef")
_WILDCARD_CHARS: Final = frozenset("*?[]")
_O_BINARY: Final = getattr(os, "O_BINARY", 0)
GIT_WORKTREE_AUTHORITY_ROOT_ENV: Final = "KHAOS_WORKTREE_AUTHORITY_ROOT"
GIT_SCOPE_OPERATIONS: Final = frozenset(
    {
        "apply",
        "blob",
        "bootstrap",
        "cleanup",
        "cleanup-ref",
        "host",
        "index",
        "materialize",
        "object-format",
        "recovery",
        "status",
        "tree",
        "workspace",
    }
)


def configured_git_worktree_authority_root() -> Path | None:
    """Return the host-reviewed private Git worktree root, when configured.

    The value is an explicit deployment input shared by the effective-policy
    compiler and ``WorkspaceManager``. If it is absent, TrustedGitRunner's
    own private authority root remains the final local TCB and the generated
    typed Git scope intentionally has no pathname claim.
    """
    raw = os.environ.get(GIT_WORKTREE_AUTHORITY_ROOT_ENV, "").strip()
    if not raw:
        return None
    candidate = Path(raw).expanduser()
    if not candidate.is_absolute():
        raise ResourceScopeError(
            f"{GIT_WORKTREE_AUTHORITY_ROOT_ENV} must be an absolute path"
        )
    return candidate.resolve()


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


def _require_actions(field: str, values: Iterable[str]) -> frozenset[str]:
    """Validate operation actions stored inside a typed resource scope."""
    actions = _require_tokens(field, values)
    if any("." in action for action in actions):
        raise ResourceScopeError(
            f"{field} must contain action names, not family-qualified operations"
        )
    return actions


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


def _canonical_filesystem_path(field: str, value: object) -> str:
    """Canonicalize an absolute host filesystem path on POSIX or Windows."""
    raw = _require_concrete(field, value)
    if not os.path.isabs(raw):
        raise ResourceScopeError(f"{field} must be absolute")
    path_parts = raw.replace("\\", "/").split("/")
    if ".." in path_parts:
        raise ResourceScopeError(f"{field} must not contain parent traversal")
    normalized = os.path.normpath(raw).replace("\\", "/")
    windows_drive_absolute = (
        len(normalized) >= 3
        and normalized[1] == ":"
        and normalized[2] == "/"
        and normalized[0].isalpha()
    )
    if normalized == "." or not normalized.startswith("/") and not windows_drive_absolute:
        raise ResourceScopeError(f"{field} is not canonical")
    return normalized


def _path_contains(parent: str, child: str) -> bool:
    if parent == "/":
        return child.startswith("/")
    parent_key = parent.casefold() if os.name == "nt" else parent
    child_key = child.casefold() if os.name == "nt" else child
    return child_key == parent_key or child_key.startswith(parent_key.rstrip("/") + "/")


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
        return canonical_digest(payload)

    def manifest(self) -> dict[str, object]:
        """Return the canonical, JSON-safe catalog entry for this scope."""
        return {
            "kind": self.kind.value,
            "scope": self.canonical(),
        }


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
        object.__setattr__(self, "root", _canonical_filesystem_path("root", self.root))
        object.__setattr__(self, "operations", _require_actions("operations", self.operations))

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
    blocked_hosts: frozenset[str] = frozenset()
    kind: ResourceScopeKind = ResourceScopeKind.NETWORK

    def __post_init__(self) -> None:
        _require_kind(self.kind, ResourceScopeKind.NETWORK)
        object.__setattr__(self, "schemes", _canonical_scheme_set("schemes", self.schemes))
        object.__setattr__(self, "hosts", _canonical_host_set("hosts", self.hosts))
        object.__setattr__(
            self,
            "blocked_hosts",
            _canonical_host_set("blocked_hosts", self.blocked_hosts)
            if self.blocked_hosts
            else frozenset(),
        )
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
        object.__setattr__(self, "operations", _require_actions("operations", self.operations))

    def contains(self, child: ResourceScope) -> bool:
        if not isinstance(child, NetworkScope):
            return False
        return (
            self.schemes.issuperset(child.schemes)
            and self.hosts.issuperset(child.hosts)
            and self.ports.issuperset(child.ports)
            and self.operations.issuperset(child.operations)
            and self.blocked_hosts.issubset(child.blocked_hosts)
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
            "blocked_hosts": sorted(self.blocked_hosts),
        }


@dataclass(frozen=True, slots=True)
class GitRefScope(ResourceScope):
    """Repository/ref capability with exact refs and approved namespaces.

    ``refs`` remains exact.  ``ref_namespaces`` is the only supported dynamic
    form and is prefix-based, so a workspace task ref can be authorized as
    ``refs/heads/khaos/task/<task-id>`` without introducing wildcard syntax
    into the catalog or confusing a ref name with an argv pattern.
    """

    repository: str
    refs: frozenset[str]
    operations: frozenset[str]
    ref_namespaces: frozenset[str] = frozenset()
    # A Git ref capability is not sufficient to authorize a host worktree
    # pathname.  Production callers may bind the worktree effects to this
    # independent private root; read/ref-only catalog entries can leave it
    # unset, but a runner must reject worktree effects without the binding.
    worktree_root: str | None = None
    kind: ResourceScopeKind = ResourceScopeKind.GIT_REF

    def __post_init__(self) -> None:
        _require_kind(self.kind, ResourceScopeKind.GIT_REF)
        object.__setattr__(self, "repository", _require_concrete("repository", self.repository))
        refs = frozenset(_require_concrete("refs", ref) for ref in self.refs)
        namespaces = frozenset(
            _require_concrete("ref_namespaces", namespace)
            for namespace in self.ref_namespaces
        )
        if not refs and not namespaces:
            raise ResourceScopeError("refs or ref_namespaces must not be empty")
        if any(
            not namespace.startswith("refs/") or not namespace.endswith("/")
            for namespace in namespaces
        ):
            raise ResourceScopeError(
                "ref_namespaces must be slash-terminated refs namespaces"
            )
        object.__setattr__(self, "refs", refs)
        object.__setattr__(self, "ref_namespaces", namespaces)
        if self.worktree_root is not None:
            object.__setattr__(
                self,
                "worktree_root",
                _canonical_filesystem_path("worktree_root", self.worktree_root),
            )
        object.__setattr__(self, "operations", _require_actions("operations", self.operations))

    def _contains_ref(self, ref: str) -> bool:
        return ref in self.refs or any(ref.startswith(namespace) for namespace in self.ref_namespaces)

    def _contains_namespace(self, namespace: str) -> bool:
        return any(namespace.startswith(parent) for parent in self.ref_namespaces)

    def allows_ref(self, ref: str) -> bool:
        """Return whether one concrete ref is covered by this scope."""
        return self._contains_ref(_require_concrete("ref", ref))

    def allows_worktree_path(self, path: str) -> bool:
        """Return whether a worktree path is a strict child of its root.

        The root itself is intentionally not an allowed Git worktree target:
        worktree effects must create, move, or remove a child allocation and
        never operate on the authority root directory.
        """
        if self.worktree_root is None:
            return False
        candidate = _canonical_filesystem_path("worktree_path", path)
        return candidate != self.worktree_root and _path_contains(
            self.worktree_root, candidate
        )

    def contains(self, child: ResourceScope) -> bool:
        if not isinstance(child, GitRefScope) or self.repository != child.repository:
            return False
        if not (
            all(self._contains_ref(ref) for ref in child.refs)
            and all(self._contains_namespace(namespace) for namespace in child.ref_namespaces)
            and self.operations.issuperset(child.operations)
        ):
            return False
        if self.worktree_root is None:
            return child.worktree_root is None
        if child.worktree_root is None:
            return False
        return _path_contains(self.worktree_root, child.worktree_root)

    def canonical(self) -> dict[str, object]:
        return {
            "repository": self.repository,
            "refs": sorted(self.refs),
            "ref_namespaces": sorted(self.ref_namespaces),
            "operations": sorted(self.operations),
            "worktree_root": self.worktree_root,
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
        object.__setattr__(self, "operations", _require_actions("operations", self.operations))
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
        object.__setattr__(self, "operations", _require_actions("operations", self.operations))

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

    _CATALOG_SCHEMA_VERSION: Final = 1

    def __init__(
        self,
        scopes: Mapping[str, ResourceScope],
        *,
        policy_digest: str | None = None,
    ) -> None:
        if policy_digest is not None:
            _require_text("policy_digest", policy_digest)
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
        self._policy_digest = policy_digest
        self._catalog_digest = _catalog_digest(
            validated, policy_digest=policy_digest
        )

    @property
    def policy_digest(self) -> str | None:
        """Return the effective-policy digest this catalog is bound to."""
        return self._policy_digest

    @property
    def catalog_digest(self) -> str:
        """Return the stable digest of the immutable catalog snapshot."""
        return self._catalog_digest

    @property
    def catalog_semantic_digest(self) -> str:
        """Return the digest independently recomputed from catalog semantics."""
        return self._catalog_digest

    @property
    def scopes(self) -> Mapping[str, ResourceScope]:
        """Return the read-only policy snapshot."""
        return self._scopes

    def manifest(self) -> dict[str, object]:
        """Return a canonical manifest suitable for host-reviewed storage."""
        entries = [
            {
                "digest": digest,
                **scope.manifest(),
            }
            for digest, scope in sorted(self._scopes.items())
        ]
        return {
            "schema_version": self._CATALOG_SCHEMA_VERSION,
            "policy_digest": self._policy_digest,
            "catalog_digest": self._catalog_digest,
            "scopes": entries,
        }

    @classmethod
    def from_manifest(
        cls,
        value: object,
        *,
        expected_policy_digest: str | None = None,
    ) -> TypedResourcePartialOrder:
        """Load and verify a host-reviewed JSON catalog manifest."""
        if not isinstance(value, Mapping):
            raise ResourceScopeError("resource catalog manifest is not a mapping")
        _reject_unknown_fields(
            value,
            {
                "schema_version",
                "policy_digest",
                "catalog_digest",
                "scopes",
            },
            "resource catalog manifest",
        )
        if value.get("schema_version") != cls._CATALOG_SCHEMA_VERSION:
            raise ResourceScopeError("unsupported resource catalog schema")
        policy_digest = value.get("policy_digest")
        if policy_digest is not None and not isinstance(policy_digest, str):
            raise ResourceScopeError("resource catalog policy digest is invalid")
        if (
            expected_policy_digest is not None
            and policy_digest != expected_policy_digest
        ):
            raise ResourceScopeError(
                "resource catalog is not bound to the effective policy"
            )
        entries = value.get("scopes")
        if not isinstance(entries, list):
            raise ResourceScopeError("resource catalog scopes must be a list")
        scopes: dict[str, ResourceScope] = {}
        for entry in entries:
            if not isinstance(entry, Mapping):
                raise ResourceScopeError("resource catalog entry is invalid")
            digest = entry.get("digest")
            kind = entry.get("kind")
            body = entry.get("scope")
            if not isinstance(digest, str) or not isinstance(kind, str):
                raise ResourceScopeError("resource catalog entry identity is invalid")
            if digest != digest.lower() or len(digest) != 64 or any(
                char not in _HEX_DIGITS for char in digest
            ):
                raise ResourceScopeError("resource catalog entry digest is invalid")
            if digest in scopes:
                raise ResourceScopeError("resource catalog contains a duplicate digest")
            scope = _scope_from_manifest(kind, body)
            scopes[digest] = scope
        order = cls(scopes, policy_digest=policy_digest)
        catalog_digest = value.get("catalog_digest")
        if catalog_digest != order.catalog_digest:
            raise ResourceScopeError("resource catalog digest does not match manifest")
        return order

    @classmethod
    def from_json_file(
        cls,
        path: Path,
        *,
        expected_policy_digest: str | None = None,
        require_windows_acl: bool = False,
    ) -> TypedResourcePartialOrder:
        """Load a catalog from a JSON file and fail closed on any mismatch."""
        descriptor = _open_trusted_catalog(
            path, require_windows_acl=require_windows_acl
        )
        try:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_size < 0
                or info.st_size > MAX_TYPED_RESOURCE_CATALOG_BYTES
            ):
                raise ResourceScopeError("resource catalog must be a regular file")
            raw = _read_catalog_descriptor(
                descriptor, maximum=MAX_TYPED_RESOURCE_CATALOG_BYTES
            )
            after = os.fstat(descriptor)
            if (
                after.st_dev != info.st_dev
                or after.st_ino != info.st_ino
                or after.st_nlink != info.st_nlink
                or after.st_size != info.st_size
                or after.st_mtime_ns != info.st_mtime_ns
                or after.st_ctime_ns != info.st_ctime_ns
            ):
                raise ResourceScopeError(
                    "resource catalog changed while it was being read"
                )
        except ResourceScopeError:
            raise
        except OSError as exc:
            raise ResourceScopeError("resource catalog cannot be read") from exc
        finally:
            os.close(descriptor)
        try:
            payload = strict_json_loads(
                raw, max_bytes=MAX_TYPED_RESOURCE_CATALOG_BYTES
            )
        except ValueError as exc:
            raise ResourceScopeError("resource catalog contains malformed JSON") from exc
        return cls.from_manifest(
            payload,
            expected_policy_digest=expected_policy_digest,
        )

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

    def require_scope(self, scope: ResourceScope) -> str:
        """Require an exact scope entry and return its canonical digest."""
        if not isinstance(scope, ResourceScope):
            raise ResourceScopeError("resource scope is invalid")
        digest = scope.digest()
        registered = self.resolve(digest)
        if registered != scope:
            raise ResourceScopeError("resource scope does not match catalog entry")
        return digest

    def require_operation(self, resource_digest: str, operation: str) -> None:
        """Require that an exact action is allowed by a typed scope."""
        scope = self.resolve(resource_digest)
        family, action = _operation_parts(operation)
        if family != _scope_family(scope):
            raise ResourceScopeError(
                "operation family does not match typed resource kind"
            )
        operations = getattr(scope, "operations", None)
        if not isinstance(operations, frozenset) or action not in operations:
            raise ResourceScopeError(
                "operation action is not allowed by the typed resource scope"
            )

    def require_transition(
        self,
        *,
        parent_digest: str,
        requested_scope: str,
        source_operation: str,
        target_operation: str,
    ) -> None:
        """Validate one same-family operation/resource transition."""
        source_family, _source_action = _operation_parts(source_operation)
        target_family, _target_action = _operation_parts(target_operation)
        if source_family != target_family:
            raise ResourceScopeError("typed resource transition crosses operation families")
        self.require_operation(parent_digest, source_operation)
        self.require_subset(parent_digest, requested_scope)
        self.require_operation(requested_scope, target_operation)


def _operation_parts(operation: str) -> tuple[str, str]:
    if type(operation) is not str or "." not in operation:
        raise ResourceScopeError("operation must contain a family separator")
    family, action = operation.split(".", 1)
    if not family or not action:
        raise ResourceScopeError("operation family is invalid")
    return family, action


def _scope_family(scope: ResourceScope) -> str:
    families = {
        ResourceScopeKind.FILESYSTEM: "workspace",
        ResourceScopeKind.NETWORK: "network",
        ResourceScopeKind.GIT_REF: "git",
        ResourceScopeKind.EXECUTION: "exec",
        ResourceScopeKind.CREDENTIAL: "credential",
    }
    try:
        return families[scope.kind]
    except KeyError as exc:
        raise ResourceScopeError("resource kind has no operation family") from exc


def _scope_from_manifest(kind: str, body: object) -> ResourceScope:
    if not isinstance(body, Mapping):
        raise ResourceScopeError("resource catalog scope body is invalid")
    try:
        scope_kind = ResourceScopeKind(kind)
    except ValueError as exc:
        raise ResourceScopeError("resource catalog scope kind is invalid") from exc
    try:
        if scope_kind is ResourceScopeKind.FILESYSTEM:
            _reject_unknown_fields(
                body,
                {"workspace_id", "root", "operations"},
                "filesystem scope",
            )
            return FilesystemScope(
                workspace_id=cast(CanonicalWorkspaceId, body["workspace_id"]),
                root=cast(str, body["root"]),
                operations=frozenset(_manifest_text_list(body, "operations")),
            )
        if scope_kind is ResourceScopeKind.NETWORK:
            _reject_unknown_fields(
                body,
                {
                    "schemes",
                    "hosts",
                    "ports",
                    "path_prefixes",
                    "operations",
                    "blocked_hosts",
                },
                "network scope",
            )
            return NetworkScope(
                schemes=frozenset(_manifest_text_list(body, "schemes")),
                hosts=frozenset(_manifest_text_list(body, "hosts")),
                ports=frozenset(_manifest_int_list(body, "ports")),
                path_prefixes=frozenset(
                    _manifest_text_list(body, "path_prefixes")
                ),
                operations=frozenset(_manifest_text_list(body, "operations")),
                blocked_hosts=frozenset(
                    _manifest_text_list(body, "blocked_hosts")
                ),
            )
        if scope_kind is ResourceScopeKind.GIT_REF:
            _reject_unknown_fields(
                body,
                {
                    "repository",
                    "refs",
                    "ref_namespaces",
                    "operations",
                    "worktree_root",
                },
                "git-ref scope",
            )
            return GitRefScope(
                repository=cast(str, body["repository"]),
                refs=frozenset(_manifest_text_list(body, "refs")),
                operations=frozenset(_manifest_text_list(body, "operations")),
                ref_namespaces=frozenset(
                    _manifest_text_list(body, "ref_namespaces")
                )
                if "ref_namespaces" in body
                else frozenset(),
                worktree_root=cast(str, body["worktree_root"])
                if "worktree_root" in body and body["worktree_root"] is not None
                else None,
            )
        if scope_kind is ResourceScopeKind.EXECUTION:
            _reject_unknown_fields(
                body,
                {
                    "workspace_id",
                    "executable",
                    "argv_prefix",
                    "argv_exact",
                    "cwd",
                    "operations",
                },
                "execution scope",
            )
            argv_exact = body["argv_exact"]
            if type(argv_exact) is not bool:
                raise ResourceScopeError("resource catalog argv_exact is invalid")
            return ExecutionScope(
                workspace_id=cast(CanonicalWorkspaceId, body["workspace_id"]),
                executable=cast(str, body["executable"]),
                argv_prefix=tuple(_manifest_text_list(body, "argv_prefix")),
                argv_exact=argv_exact,
                cwd=cast(str, body["cwd"]),
                operations=frozenset(_manifest_text_list(body, "operations")),
            )
        _reject_unknown_fields(
            body,
            {"provider", "names", "operations"},
            "credential scope",
        )
        return CredentialScope(
            provider=cast(str, body["provider"]),
            names=frozenset(_manifest_text_list(body, "names")),
            operations=frozenset(_manifest_text_list(body, "operations")),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ResourceScopeError("resource catalog scope body is malformed") from exc


def _manifest_list(body: Mapping[str, object], field: str) -> list[object]:
    value = body.get(field)
    if not isinstance(value, list):
        raise ResourceScopeError(f"resource catalog {field} must be a list")
    return value


def _manifest_text_list(body: Mapping[str, object], field: str) -> list[str]:
    values = _manifest_list(body, field)
    if any(type(value) is not str for value in values):
        raise ResourceScopeError(f"resource catalog {field} must contain text")
    return cast(list[str], values)


def _manifest_int_list(body: Mapping[str, object], field: str) -> list[int]:
    values = _manifest_list(body, field)
    if any(type(value) is not int for value in values):
        raise ResourceScopeError(f"resource catalog {field} must contain integers")
    return cast(list[int], values)


def _reject_unknown_fields(
    value: Mapping[object, object], allowed: set[str], label: str
) -> None:
    if any(type(key) is not str for key in value):
        raise ResourceScopeError(f"{label} contains a non-text field")
    unknown = set(value) - allowed
    if unknown:
        raise ResourceScopeError(f"{label} contains unknown fields")


def _catalog_digest(
    scopes: Mapping[str, ResourceScope], *, policy_digest: str | None
) -> str:
    payload = {
        "schema_version": TypedResourcePartialOrder._CATALOG_SCHEMA_VERSION,
        "policy_digest": policy_digest,
        "scopes": [
            {
                "digest": digest,
                **scope.manifest(),
            }
            for digest, scope in sorted(scopes.items())
        ],
    }
    return canonical_digest(payload)


def _trusted_catalog_path(path: Path) -> Path:
    """Validate catalog path syntax without resolving it through a workspace.

    The actual loader uses :func:`_open_trusted_catalog`, which walks the
    parent chain with directory descriptors.  This small helper remains the
    single lexical path gate for callers that need to validate a path before
    opening it.
    """
    candidate = Path(path).expanduser()
    if not candidate.is_absolute():
        raise ResourceScopeError("resource catalog path must be absolute")
    if any(part == ".." for part in candidate.parts):
        raise ResourceScopeError("resource catalog path contains parent traversal")
    return candidate


def _trusted_owner_directory(info: os.stat_result) -> bool:
    """Return whether one opened catalog parent has an allowed owner/mode."""
    if os.name == "nt":
        # Windows production uses ``windows_trust``.  POSIX mode bits are not
        # an equivalent ACL and must never silently admit a catalog here.
        return False
    allowed_uids = {0, os.getuid()}
    sticky_system_directory = (
        stat.S_ISDIR(info.st_mode)
        and info.st_uid == 0
        and bool(info.st_mode & 0o1000)
    )
    return (
        info.st_uid in allowed_uids and not info.st_mode & 0o022
    ) or sticky_system_directory


def _open_trusted_catalog(path: Path, *, require_windows_acl: bool = False) -> int:
    """Open a catalog through a no-follow, descriptor-relative path walk."""
    candidate = _trusted_catalog_path(path)
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    close_on_exec = getattr(os, "O_CLOEXEC", 0)
    if os.name == "nt":
        try:
            if require_windows_acl:
                validate_windows_trusted_path(candidate, kind="catalog")
            descriptor = os.open(
                str(candidate), os.O_RDONLY | no_follow | close_on_exec | _O_BINARY
            )
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                os.close(descriptor)
                raise ResourceScopeError(
                    "resource catalog must be a single-link regular file"
                )
            if require_windows_acl:
                validate_windows_trusted_descriptor(
                    descriptor, path=candidate, kind="catalog"
                )
            return descriptor
        except WindowsTrustError as exc:
            raise ResourceScopeError(str(exc)) from exc
        except ResourceScopeError:
            raise
        except OSError as exc:
            raise ResourceScopeError("resource catalog cannot be opened") from exc

    directory_flag = getattr(os, "O_DIRECTORY", 0)
    directory_descriptors: list[int] = []
    try:
        root_descriptor = os.open(
            str(candidate.anchor),
            os.O_RDONLY | directory_flag | no_follow | close_on_exec,
        )
        directory_descriptors.append(root_descriptor)
        current_descriptor = root_descriptor
        for part in candidate.parts[1:-1]:
            try:
                next_descriptor = os.open(
                    part,
                    os.O_RDONLY | directory_flag | no_follow | close_on_exec,
                    dir_fd=current_descriptor,
                )
            except OSError as exc:
                if getattr(exc, "errno", None) in {errno.ELOOP, errno.ENOTDIR}:
                    try:
                        parent_info = os.stat(
                            part,
                            dir_fd=current_descriptor,
                            follow_symlinks=False,
                        )
                    except OSError:
                        parent_info = None
                    if parent_info is not None and stat.S_ISLNK(
                        parent_info.st_mode
                    ):
                        raise ResourceScopeError(
                            "resource catalog path contains a symlink"
                        ) from exc
                if getattr(exc, "errno", None) == errno.ELOOP:
                    raise ResourceScopeError(
                        "resource catalog path contains a symlink"
                    ) from exc
                raise ResourceScopeError("resource catalog path is unavailable") from exc
            info = os.fstat(next_descriptor)
            if not stat.S_ISDIR(info.st_mode):
                os.close(next_descriptor)
                raise ResourceScopeError("resource catalog parent is not a directory")
            if not _trusted_owner_directory(info):
                os.close(next_descriptor)
                raise ResourceScopeError(
                    "resource catalog path is not owned by a trusted non-writable identity"
                )
            directory_descriptors.append(next_descriptor)
            current_descriptor = next_descriptor

        try:
            descriptor = os.open(
                candidate.parts[-1],
                os.O_RDONLY | no_follow | close_on_exec | _O_BINARY,
                dir_fd=current_descriptor,
            )
        except OSError as exc:
            if getattr(exc, "errno", None) == errno.ELOOP:
                raise ResourceScopeError(
                    "resource catalog path contains a symlink"
                ) from exc
            raise ResourceScopeError("resource catalog cannot be opened") from exc
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            os.close(descriptor)
            raise ResourceScopeError(
                "resource catalog must be a single-link regular file"
            )
        if not _trusted_owner_directory(info):
            os.close(descriptor)
            raise ResourceScopeError(
                "resource catalog is not owned by a trusted non-writable identity"
            )
        return descriptor
    finally:
        for descriptor in reversed(directory_descriptors):
            os.close(descriptor)


def _read_catalog_descriptor(descriptor: int, *, maximum: int) -> bytes:
    """Read one opened catalog descriptor with a hard byte limit."""
    chunks: list[bytes] = []
    total = 0
    while total <= maximum:
        chunk = os.read(descriptor, min(64 * 1024, maximum + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > maximum:
            raise ResourceScopeError("resource catalog exceeds its size bound")
    return b"".join(chunks)


def compile_typed_resource_catalog(
    workspace_root: Path,
    *,
    policy_digest: str,
    filesystem_roots: Iterable[Path],
    filesystem_operations: Iterable[str],
    network_allowed_domains: frozenset[str] | None,
    network_blocked_domains: Iterable[str],
    git_worktree_root: Path | None = None,
) -> TypedResourcePartialOrder:
    """Compile the immutable baseline catalog from one effective policy.

    The same deterministic compiler is used by the runtime and the
    deployment-time catalog generator.  Dynamic authority owners must still
    resolve their concrete scope through this catalog; no owner may silently
    substitute an opaque hash when the production catalog is present.
    """
    root = workspace_root.expanduser().resolve()
    workspace_id = CanonicalWorkspaceId(str(root))
    scopes: dict[str, ResourceScope] = {}
    operations = frozenset(filesystem_operations)
    for filesystem_root in filesystem_roots:
        candidate = Path(filesystem_root).expanduser().resolve()
        try:
            candidate.relative_to(root)
        except ValueError:
            raise ResourceScopeError(
                "filesystem resource catalog root escapes the workspace"
            )
        scope = FilesystemScope(
            workspace_id=workspace_id,
            root=str(candidate),
            operations=operations,
        )
        scopes[scope.digest()] = scope

    if (root / ".git").exists():
        git_scope = GitRefScope(
            repository=str(root),
            refs=frozenset({"HEAD"}),
            ref_namespaces=frozenset({"refs/heads/khaos/task/"}),
            operations=GIT_SCOPE_OPERATIONS,
            worktree_root=(
                str(git_worktree_root.expanduser().resolve())
                if git_worktree_root is not None
                else None
            ),
        )
        scopes[git_scope.digest()] = git_scope

    if network_allowed_domains is not None and network_allowed_domains:
        network_scope = NetworkScope(
            schemes=frozenset({"http", "https"}),
            hosts=network_allowed_domains,
            ports=frozenset({80, 443}),
            path_prefixes=frozenset({"/"}),
            operations=frozenset({"connect"}),
            blocked_hosts=frozenset(network_blocked_domains),
        )
        scopes[network_scope.digest()] = network_scope

    return TypedResourcePartialOrder(scopes, policy_digest=policy_digest)


__all__ = [
    "GIT_SCOPE_OPERATIONS",
    "GIT_WORKTREE_AUTHORITY_ROOT_ENV",
    "CredentialScope",
    "ExecutionScope",
    "FilesystemScope",
    "GitRefScope",
    "NetworkScope",
    "ResourceScope",
    "ResourceScopeError",
    "ResourceScopeKind",
    "TypedResourcePartialOrder",
    "compile_typed_resource_catalog",
    "configured_git_worktree_authority_root",
]
