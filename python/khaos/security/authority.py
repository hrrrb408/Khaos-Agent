"""Immutable authority grants for privileged local effects.

An :class:`AuthorityEnvelope` is the common, typed context carried by local
control-plane operations.  It is not itself an effect authority: callers must
obtain an ``EffectCapability`` from ``AuthorityBroker`` before a privileged
runner accepts it.  Keeping the context separate from the broker-issued
capability makes audit identity explicit while requiring every envelope to be
created and owned by the broker that can issue its capability.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass, field

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$")
_DIGEST = re.compile(r"^[A-Za-z0-9_.:-]{1,256}$")
_DELEGATION_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_PRINCIPAL_KINDS = frozenset(
    {"human", "gateway", "channel", "automation", "subagent", "browser"}
)
_AUTHORITY_ISSUER = object()


@dataclass(frozen=True, slots=True, init=False)
class AuthorityEnvelope:
    """Bind a renewable grant to one immutable security context.

    A runner exchanges this grant for a short-lived, one-shot effect
    capability and must finish that receipt before returning the result.
    """

    principal_id: str
    project_id: str
    runtime_id: str
    task_id: str
    workspace_id: str
    workspace_generation: int
    policy_digest: str
    operation_class: str
    resource_digest: str
    authorization_epoch: int = 0
    schema_version: int = 1
    grant_id: str = ""
    grant_expires_at: float = 0.0
    principal_kind: str = ""
    parent_principal_id: str = ""
    session_id: str = ""
    delegation_digest: str = ""
    _broker: object | None = field(
        default=None, init=False, repr=False, compare=False
    )

    def __init__(
        self,
        *,
        principal_id: str,
        project_id: str,
        runtime_id: str,
        task_id: str,
        workspace_id: str,
        workspace_generation: int,
        policy_digest: str,
        operation_class: str,
        resource_digest: str,
        authorization_epoch: int = 0,
        schema_version: int = 1,
        grant_id: str = "",
        grant_expires_at: float = 0.0,
        principal_kind: str = "",
        parent_principal_id: str = "",
        session_id: str = "",
        delegation_digest: str = "",
        _issuer: object | None = None,
    ) -> None:
        if _issuer is not _AUTHORITY_ISSUER:
            raise TypeError(
                "AuthorityEnvelope instances can only be created by AuthorityBroker"
            )
        for name, value in (
            ("principal_id", principal_id),
            ("project_id", project_id),
            ("runtime_id", runtime_id),
            ("task_id", task_id),
            ("workspace_id", workspace_id),
            ("workspace_generation", workspace_generation),
            ("policy_digest", policy_digest),
            ("operation_class", operation_class),
            ("resource_digest", resource_digest),
            ("authorization_epoch", authorization_epoch),
            ("schema_version", schema_version),
            ("grant_id", grant_id),
            ("grant_expires_at", grant_expires_at),
            ("principal_kind", principal_kind),
            ("parent_principal_id", parent_principal_id),
            ("session_id", session_id),
            ("delegation_digest", delegation_digest),
        ):
            object.__setattr__(self, name, value)
        object.__setattr__(self, "_broker", None)
        self.__post_init__()

    @classmethod
    def _from_broker(
        cls,
        *,
        broker: object,
        principal_id: str,
        project_id: str,
        runtime_id: str,
        task_id: str,
        workspace_id: str,
        workspace_generation: int,
        policy_digest: str,
        operation_class: str,
        resource_digest: str,
        authorization_epoch: int = 0,
        schema_version: int = 1,
        grant_id: str,
        grant_expires_at: float,
        principal_kind: str = "",
        parent_principal_id: str = "",
        session_id: str = "",
        delegation_digest: str = "",
    ) -> AuthorityEnvelope:
        """Construct an envelope owned by one trusted AuthorityBroker."""
        envelope = cls(
            principal_id=principal_id,
            project_id=project_id,
            runtime_id=runtime_id,
            task_id=task_id,
            workspace_id=workspace_id,
            workspace_generation=workspace_generation,
            policy_digest=policy_digest,
            operation_class=operation_class,
            resource_digest=resource_digest,
            authorization_epoch=authorization_epoch,
            schema_version=schema_version,
            grant_id=grant_id,
            grant_expires_at=grant_expires_at,
            principal_kind=principal_kind,
            parent_principal_id=parent_principal_id,
            session_id=session_id,
            delegation_digest=delegation_digest,
            _issuer=_AUTHORITY_ISSUER,
        )
        object.__setattr__(envelope, "_broker", broker)
        return envelope

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise ValueError(f"unsupported authority envelope schema: {self.schema_version}")
        for label, value in (
            ("principal_id", self.principal_id),
            ("project_id", self.project_id),
            ("runtime_id", self.runtime_id),
            ("task_id", self.task_id),
            ("workspace_id", self.workspace_id),
            ("operation_class", self.operation_class),
        ):
            if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
                raise ValueError(f"invalid authority envelope {label}")
        if "." not in self.operation_class or "*" in self.operation_class:
            raise ValueError("invalid authority envelope operation class")
        for label, value in (
            ("policy_digest", self.policy_digest),
            ("resource_digest", self.resource_digest),
        ):
            if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
                raise ValueError(f"invalid authority envelope {label}")
        if self.workspace_generation <= 0:
            raise ValueError("authority envelope workspace generation must be positive")
        if self.authorization_epoch < 0:
            raise ValueError("authority envelope authorization epoch cannot be negative")
        if not isinstance(self.grant_id, str) or _IDENTIFIER.fullmatch(self.grant_id) is None:
            raise ValueError("authority envelope grant id is invalid")
        if not math.isfinite(self.grant_expires_at) or self.grant_expires_at <= 0:
            raise ValueError("authority envelope grant expiry is invalid")
        typed = (
            self.principal_kind,
            self.parent_principal_id,
            self.session_id,
            self.delegation_digest,
        )
        if any(typed) and not all(typed):
            raise ValueError("authority envelope typed principal binding is incomplete")
        if self.principal_kind and self.principal_kind not in _PRINCIPAL_KINDS:
            raise ValueError("authority envelope principal kind is invalid")
        if self.parent_principal_id and _IDENTIFIER.fullmatch(self.parent_principal_id) is None:
            raise ValueError("authority envelope parent principal is invalid")
        if self.session_id and _IDENTIFIER.fullmatch(self.session_id) is None:
            raise ValueError("authority envelope session id is invalid")
        if self.delegation_digest and _DELEGATION_DIGEST.fullmatch(self.delegation_digest) is None:
            raise ValueError("authority envelope delegation digest is invalid")

    @property
    def has_typed_principal_binding(self) -> bool:
        """Return whether the envelope carries the complete M6.4 tuple."""
        return bool(self.principal_kind)

    def payload(self) -> dict[str, object]:
        """Return the canonical, non-secret binding payload."""
        return {
            "schema_version": self.schema_version,
            "principal_id": self.principal_id,
            "project_id": self.project_id,
            "runtime_id": self.runtime_id,
            "task_id": self.task_id,
            "workspace_id": self.workspace_id,
            "workspace_generation": self.workspace_generation,
            "policy_digest": self.policy_digest,
            "operation_class": self.operation_class,
            "resource_digest": self.resource_digest,
            "authorization_epoch": self.authorization_epoch,
            "grant_id": self.grant_id,
            "grant_expires_at": self.grant_expires_at,
            **(
                {
                    "principal_kind": self.principal_kind,
                    "parent_principal_id": self.parent_principal_id,
                    "session_id": self.session_id,
                    "delegation_digest": self.delegation_digest,
                }
                if self.has_typed_principal_binding
                else {}
            ),
        }

    def digest(self) -> str:
        """Return the stable digest used by audit and child-owner bindings."""
        encoded = json.dumps(
            self.payload(), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def context_digest(self) -> str:
        """Return the stable owner digest excluding operation/resource labels."""
        encoded = json.dumps(
            {
                "schema_version": self.schema_version,
                "principal_id": self.principal_id,
                "project_id": self.project_id,
                "runtime_id": self.runtime_id,
                "task_id": self.task_id,
                "workspace_id": self.workspace_id,
                "workspace_generation": self.workspace_generation,
                "policy_digest": self.policy_digest,
                "authorization_epoch": self.authorization_epoch,
                **(
                    {
                        "principal_kind": self.principal_kind,
                        "parent_principal_id": self.parent_principal_id,
                        "session_id": self.session_id,
                        "delegation_digest": self.delegation_digest,
                    }
                    if self.has_typed_principal_binding
                    else {}
                ),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def derive(
        self,
        *,
        operation_class: str,
        resource_digest: str | None = None,
    ) -> AuthorityEnvelope:
        """Derive a narrower operation without changing its owner binding."""
        if self._broker is None:
            raise ValueError("authority envelope is not broker-owned")
        return self._from_broker(
            broker=self._broker,
            principal_id=self.principal_id,
            project_id=self.project_id,
            runtime_id=self.runtime_id,
            task_id=self.task_id,
            workspace_id=self.workspace_id,
            workspace_generation=self.workspace_generation,
            policy_digest=self.policy_digest,
            operation_class=operation_class,
            resource_digest=resource_digest or self.resource_digest,
            authorization_epoch=self.authorization_epoch,
            schema_version=self.schema_version,
            grant_id=self.grant_id,
            grant_expires_at=self.grant_expires_at,
            principal_kind=self.principal_kind,
            parent_principal_id=self.parent_principal_id,
            session_id=self.session_id,
            delegation_digest=self.delegation_digest,
        )

    def matches_context(
        self,
        *,
        principal_id: str,
        project_id: str,
        runtime_id: str,
        task_id: str,
        workspace_id: str,
        workspace_generation: int,
        policy_digest: str,
    ) -> bool:
        """Check the immutable owner/generation/policy portion of the envelope."""
        return (
            self.principal_id == principal_id
            and self.project_id == project_id
            and self.runtime_id == runtime_id
            and self.task_id == task_id
            and self.workspace_id == workspace_id
            and self.workspace_generation == workspace_generation
            and self.policy_digest == policy_digest
        )

    @classmethod
    def system(
        cls,
        *,
        broker: object,
        operation_class: str,
        resource_digest: str,
        task_id: str = "recovery",
        workspace_id: str = "system",
    ) -> AuthorityEnvelope:
        """Create the explicit envelope used by local recovery control paths."""
        issue_context = getattr(broker, "envelope", None)
        if not callable(issue_context):
            raise TypeError("system authority requires a live AuthorityBroker")
        return issue_context(
            principal_id="system",
            project_id="local",
            runtime_id="recovery",
            task_id=task_id,
            workspace_id=workspace_id,
            workspace_generation=1,
            policy_digest="system-recovery",
            operation_class=operation_class,
            resource_digest=resource_digest,
            authorization_epoch=1,
        )


# Security-facing name used by the lease/receipt design.  Keep the original
# class name for persisted and test fixtures.
AuthorityGrant = AuthorityEnvelope


__all__ = ["AuthorityEnvelope", "AuthorityGrant"]
