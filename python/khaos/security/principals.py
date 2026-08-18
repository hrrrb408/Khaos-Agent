"""Typed principals and narrow-only delegation records.

The old runtime identity was a string that carried no information about the
entry point which created it.  This module keeps the public identity stable
while making the security-relevant principal kind and delegation scope
explicit.  It is deliberately independent from transport code: callers hand
the authority an immutable scope, and the authority decides whether that
scope may be issued or consumed.

Delegation is a strict subset operation.  A child cannot change its project,
session, runtime, task, workspace, policy digest, expiry, operation family,
or resource set.  A consumed nonce is terminal and cannot be replayed by a
different principal, channel, cron task, or subagent.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import threading
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import Enum


class PrincipalKind(str, Enum):
    """Security domain of an authenticated entry point."""

    HUMAN = "human"
    GATEWAY = "gateway"
    CHANNEL = "channel"
    AUTOMATION = "automation"
    SUBAGENT = "subagent"
    BROWSER = "browser"


class PrincipalDelegationError(PermissionError):
    """A typed principal or delegation proof is invalid."""


_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,255}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_TRANSPORT_KINDS = {
    "cli": PrincipalKind.HUMAN,
    "tui": PrincipalKind.HUMAN,
    "test": PrincipalKind.HUMAN,
    "rpc": PrincipalKind.GATEWAY,
    "websocket": PrincipalKind.GATEWAY,
    "webhook": PrincipalKind.CHANNEL,
    "cron": PrincipalKind.AUTOMATION,
    "subagent": PrincipalKind.SUBAGENT,
    "browser": PrincipalKind.BROWSER,
}


@dataclass(frozen=True, slots=True)
class Principal:
    """Immutable principal identity used by request and authority bindings."""

    principal_id: str
    kind: PrincipalKind

    def __post_init__(self) -> None:
        if not isinstance(self.kind, PrincipalKind):
            object.__setattr__(self, "kind", PrincipalKind(str(self.kind)))
        if (
            not isinstance(self.principal_id, str)
            or _IDENTIFIER.fullmatch(self.principal_id) is None
        ):
            raise PrincipalDelegationError("principal_id is malformed")

    @property
    def identity(self) -> str:
        """Return the typed wire identity without changing the stable ID."""
        return f"{self.kind.value}:{self.principal_id}"

    def canonical(self) -> dict[str, str]:
        return {"kind": self.kind.value, "principal_id": self.principal_id}

    @property
    def digest(self) -> str:
        return _digest(self.canonical())


class HumanPrincipal(Principal):
    """Interactive human or local CLI principal."""

    def __init__(self, principal_id: str) -> None:
        super().__init__(principal_id, PrincipalKind.HUMAN)


class GatewayPrincipal(Principal):
    """Authenticated Gateway/API transport principal."""

    def __init__(self, principal_id: str) -> None:
        super().__init__(principal_id, PrincipalKind.GATEWAY)


class ChannelPrincipal(Principal):
    """Inbound webhook/platform sender principal."""

    def __init__(self, principal_id: str) -> None:
        super().__init__(principal_id, PrincipalKind.CHANNEL)


class AutomationPrincipal(Principal):
    """Scheduled/cron automation principal."""

    def __init__(self, principal_id: str) -> None:
        super().__init__(principal_id, PrincipalKind.AUTOMATION)


class SubagentPrincipal(Principal):
    """Child agent principal with explicitly delegated authority."""

    def __init__(self, principal_id: str) -> None:
        super().__init__(principal_id, PrincipalKind.SUBAGENT)


class BrowserPrincipal(Principal):
    """Browser/kernel helper principal."""

    def __init__(self, principal_id: str) -> None:
        super().__init__(principal_id, PrincipalKind.BROWSER)


def principal_for_transport(
    principal_id: str, source_transport: str
) -> Principal:
    """Construct a typed principal from an authenticated transport.

    Unknown transports are rejected rather than silently treated as a human
    or API-key principal.  ``test`` and ``tui`` are explicit non-production
    transport names retained for isolated local fixtures.
    """

    try:
        kind = _TRANSPORT_KINDS[source_transport]
    except KeyError as exc:
        raise PrincipalDelegationError(
            f"unrecognized principal transport: {source_transport}"
        ) from exc
    return principal_from_kind(principal_id, kind)


def principal_from_kind(principal_id: str, kind: PrincipalKind | str) -> Principal:
    """Construct the concrete principal class for a validated kind."""

    normalized = PrincipalKind(kind)
    classes = {
        PrincipalKind.HUMAN: HumanPrincipal,
        PrincipalKind.GATEWAY: GatewayPrincipal,
        PrincipalKind.CHANNEL: ChannelPrincipal,
        PrincipalKind.AUTOMATION: AutomationPrincipal,
        PrincipalKind.SUBAGENT: SubagentPrincipal,
        PrincipalKind.BROWSER: BrowserPrincipal,
    }
    return classes[normalized](principal_id)


@dataclass(frozen=True, slots=True)
class DelegationScope:
    """Exact context and bounded effect scope carried by one delegation."""

    subject: Principal
    parent_principal: Principal
    project_id: str
    session_id: str
    runtime_id: str
    task_id: str
    workspace_id: str
    operation_family: str
    resource_scope: frozenset[str] = field(default_factory=frozenset)
    policy_digest: str = ""
    expires_at: float = 0.0
    nonce: str = ""
    issued_at: float = 0.0

    def __post_init__(self) -> None:
        for name in (
            "project_id",
            "session_id",
            "runtime_id",
            "task_id",
            "workspace_id",
            "operation_family",
        ):
            value = getattr(self, name)
            if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
                raise PrincipalDelegationError(f"delegation {name} is malformed")
        if not _DIGEST.fullmatch(self.policy_digest):
            raise PrincipalDelegationError("delegation policy_digest is malformed")
        if not self.nonce or len(self.nonce) > 128 or "\x00" in self.nonce:
            raise PrincipalDelegationError("delegation nonce is malformed")
        if self.expires_at <= 0 or self.issued_at < 0 or self.expires_at <= self.issued_at:
            raise PrincipalDelegationError("delegation expiry is invalid")
        if not self.resource_scope:
            raise PrincipalDelegationError("delegation resource scope is empty")
        normalized_scope = frozenset(self.resource_scope)
        if any(
            not isinstance(resource, str)
            or not resource
            or len(resource) > 512
            or "\x00" in resource
            for resource in normalized_scope
        ):
            raise PrincipalDelegationError("delegation resource scope is malformed")
        object.__setattr__(self, "resource_scope", normalized_scope)

    @classmethod
    def root(
        cls,
        principal: Principal,
        *,
        project_id: str,
        session_id: str,
        runtime_id: str,
        task_id: str,
        workspace_id: str,
        operation_family: str,
        resource_scope: Iterable[str],
        policy_digest: str,
        expires_at: float,
        issued_at: float | None = None,
        nonce: str | None = None,
    ) -> DelegationScope:
        """Create an explicit human-owned root scope.

        Root scope creation is only an input to the independent authority;
        it is not itself a proof that a caller may mint effects.
        """

        issued = time.time() if issued_at is None else issued_at
        return cls(
            subject=principal,
            parent_principal=principal,
            project_id=project_id,
            session_id=session_id,
            runtime_id=runtime_id,
            task_id=task_id,
            workspace_id=workspace_id,
            operation_family=operation_family,
            resource_scope=frozenset(resource_scope),
            policy_digest=policy_digest,
            expires_at=expires_at,
            nonce=nonce or secrets.token_hex(16),
            issued_at=issued,
        )

    def canonical(self) -> dict[str, object]:
        return {
            "subject": self.subject.canonical(),
            "parent_principal": self.parent_principal.canonical(),
            "project_id": self.project_id,
            "session_id": self.session_id,
            "runtime_id": self.runtime_id,
            "task_id": self.task_id,
            "workspace_id": self.workspace_id,
            "operation_family": self.operation_family,
            "resource_scope": sorted(self.resource_scope),
            "policy_digest": self.policy_digest,
            "expires_at": self.expires_at,
            "issued_at": self.issued_at,
            "nonce": self.nonce,
        }

    @property
    def digest(self) -> str:
        return _digest(self.canonical())

    def contains(self, child: DelegationScope) -> bool:
        """Return whether ``child`` is a strict non-widening subset."""

        return (
            child.parent_principal == self.subject
            and child.project_id == self.project_id
            and child.session_id == self.session_id
            and child.runtime_id == self.runtime_id
            and child.task_id == self.task_id
            and child.workspace_id == self.workspace_id
            and child.policy_digest == self.policy_digest
            and child.expires_at <= self.expires_at
            and _operation_is_narrower(self.operation_family, child.operation_family)
            and child.resource_scope.issubset(self.resource_scope)
        )


class DelegationAuthority:
    """In-memory lifecycle coordinator for one authority owner.

    Production callers place this state behind the durable authority daemon;
    the class itself deliberately has no transport or fallback behavior.
    """

    def __init__(self) -> None:
        self._live: dict[str, DelegationScope] = {}
        self._consumed: set[str] = set()
        self._lock = threading.RLock()

    def register_root(self, root: DelegationScope) -> str:
        if root.subject.kind is not PrincipalKind.HUMAN:
            raise PrincipalDelegationError("only a human may establish a root scope")
        with self._lock:
            if root.digest in self._live or root.digest in self._consumed:
                raise PrincipalDelegationError("delegation scope already registered")
            self._live[root.digest] = root
        return root.digest

    def delegate(
        self,
        parent: DelegationScope,
        child: Principal,
        *,
        operation_family: str,
        resource_scope: Iterable[str],
        expires_at: float,
        nonce: str | None = None,
        now: float | None = None,
    ) -> DelegationScope:
        """Issue one child scope only after validating the live parent."""

        current = time.time() if now is None else now
        if current >= parent.expires_at:
            raise PrincipalDelegationError("parent delegation has expired")
        if child.kind is PrincipalKind.HUMAN:
            raise PrincipalDelegationError("human authority cannot be delegated as a child")
        child_scope = DelegationScope(
            subject=child,
            parent_principal=parent.subject,
            project_id=parent.project_id,
            session_id=parent.session_id,
            runtime_id=parent.runtime_id,
            task_id=parent.task_id,
            workspace_id=parent.workspace_id,
            operation_family=operation_family,
            resource_scope=frozenset(resource_scope),
            policy_digest=parent.policy_digest,
            expires_at=expires_at,
            nonce=nonce or secrets.token_hex(16),
            issued_at=current,
        )
        with self._lock:
            if parent.digest not in self._live:
                raise PrincipalDelegationError("parent delegation is not live")
            if not parent.contains(child_scope):
                raise PrincipalDelegationError("delegation would widen parent authority")
            if child_scope.digest in self._live or child_scope.digest in self._consumed:
                raise PrincipalDelegationError("delegation nonce or scope was replayed")
            self._live[child_scope.digest] = child_scope
        return child_scope

    def consume(
        self,
        delegation: DelegationScope,
        *,
        principal: Principal,
        project_id: str,
        session_id: str,
        runtime_id: str,
        task_id: str,
        workspace_id: str,
        operation_family: str,
        resource_scope: Iterable[str],
        policy_digest: str,
        now: float | None = None,
    ) -> None:
        """Consume exactly one child scope at the effect boundary."""

        current = time.time() if now is None else now
        requested = DelegationScope(
            subject=principal,
            parent_principal=delegation.parent_principal,
            project_id=project_id,
            session_id=session_id,
            runtime_id=runtime_id,
            task_id=task_id,
            workspace_id=workspace_id,
            operation_family=operation_family,
            resource_scope=frozenset(resource_scope),
            policy_digest=policy_digest,
            expires_at=delegation.expires_at,
            nonce=delegation.nonce,
            issued_at=delegation.issued_at,
        )
        with self._lock:
            live = self._live.get(delegation.digest)
            if live is None or delegation.digest in self._consumed:
                raise PrincipalDelegationError("delegation is unknown or already consumed")
            if current >= live.expires_at:
                self._live.pop(delegation.digest, None)
                raise PrincipalDelegationError("delegation has expired")
            if live != delegation or not _same_effect_scope(live, requested):
                raise PrincipalDelegationError("delegation context or effect is not exact")
            self._live.pop(delegation.digest, None)
            self._consumed.add(delegation.digest)

    def revoke(self, delegation: DelegationScope) -> None:
        with self._lock:
            self._live.pop(delegation.digest, None)
            self._consumed.add(delegation.digest)


def _operation_is_narrower(parent: str, child: str) -> bool:
    return child == parent or child.startswith(parent + ".")


def _same_effect_scope(left: DelegationScope, right: DelegationScope) -> bool:
    """Compare all launch-time fields; consume never accepts a widening."""

    return (
        left.subject == right.subject
        and left.parent_principal == right.parent_principal
        and left.project_id == right.project_id
        and left.session_id == right.session_id
        and left.runtime_id == right.runtime_id
        and left.task_id == right.task_id
        and left.workspace_id == right.workspace_id
        and left.operation_family == right.operation_family
        and left.resource_scope == right.resource_scope
        and left.policy_digest == right.policy_digest
        and left.expires_at == right.expires_at
        and left.issued_at == right.issued_at
        and left.nonce == right.nonce
    )


def _digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
            "utf-8"
        )
    ).hexdigest()


__all__ = [
    "AutomationPrincipal",
    "BrowserPrincipal",
    "ChannelPrincipal",
    "DelegationAuthority",
    "DelegationScope",
    "GatewayPrincipal",
    "HumanPrincipal",
    "Principal",
    "PrincipalDelegationError",
    "PrincipalKind",
    "SubagentPrincipal",
    "principal_for_transport",
    "principal_from_kind",
]
