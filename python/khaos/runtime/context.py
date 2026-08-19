"""Immutable per-request security context.

M4 batch 3.1.16A-4-1: establishes :class:`RequestContext` as the sole
authority for transport-authenticated identity.  Service methods
receive this as their first parameter and use ``ctx.principal_id`` for
all principal-scoped operations — never reading ``principal_id`` from
the RPC payload (which could be forged by a compromised Gateway).

This closes the "three identities" gap identified in the M4 deep review:

* HTTP authenticated principal (Gateway)
* RPC auth envelope principal (authenticator)
* Python service principal (was: hardcoded ``local-uid``)

After A-4-1, there is one identity per request: ``ctx.principal_id``,
derived from the RPC auth envelope and verified against the payload's
claimed principal (if any) by :meth:`GatewayRPCAuthenticator.authenticate`.

A-4-1 only establishes the plumbing — the dispatcher builds ``ctx`` and
passes it to every service method.  A-4-2 will make service bodies
actually use ``ctx.principal_id`` for principal-scoped DB queries
(while A-4-1 leaves the existing ``local-uid`` service bindings in
place so the system keeps working).
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass

from khaos.security.principals import (
    Principal,
    PrincipalDelegationError,
    PrincipalKind,
    principal_for_transport,
    principal_from_kind,
    transport_root_delegation_digest,
)


def local_principal_id() -> str:
    """Return the local CLI principal without assuming POSIX ``getuid``.

    Windows native identity binding is enforced by the production authority
    boundary. This fallback only keeps CLI plumbing from crashing on a
    platform without ``os.getuid``; it is not proof of a Windows service
    identity.
    """
    try:
        uid: int | str = os.getuid()
    except AttributeError:
        uid = "windows"
    return f"local-uid:{uid}"


def _transport_delegation_digest(
    *,
    principal_id: str,
    principal_kind: str,
    parent_principal_id: str,
    project_id: str,
    session_id: str,
    runtime_id: str,
    source_transport: str,
    policy_digest: str,
) -> str:
    """Create the immutable transport-root delegation commitment.

    The commitment is deliberately only an identity binding.  The
    independent authority still decides whether this root may issue an
    effect; it is not a Python-side permission grant or a fallback authority.
    The recipe lives in khaos.security.principals so the authority daemon
    can recompute and check the identical commitment at grant time.
    """
    return transport_root_delegation_digest(
        principal_id=principal_id,
        principal_kind=principal_kind,
        parent_principal_id=parent_principal_id,
        project_id=project_id,
        session_id=session_id,
        runtime_id=runtime_id,
        source_transport=source_transport,
        policy_digest=policy_digest,
    )


@dataclass(frozen=True)
class RequestContext:
    """Immutable per-request security context.

    Instances are constructed by the RPC dispatcher (or the
    CLI / webhook / cron entry points) and passed to every service
    method as the first positional parameter.  The context is the
    sole authority for:

    * ``principal_id`` — who is making this request
    * ``project_id``   — which project state root this request targets
    * ``session_id``   — which chat session (may be empty for
                         non-session-scoped calls like ``TaskService.List``)
    * ``runtime_id``   — which runtime instance issued this request
                         (empty at the RPC boundary; populated inside
                         ``build_runtime`` for downstream tool calls)
    * ``source_transport`` — ``"rpc"`` / ``"webhook"`` / ``"cron"`` /
                              ``"cli"`` — used for audit attribution
    * ``policy_digest`` — the effective security policy digest bound
                          to this request (used by A-4-2 for permission
                          rule generation matching)

    The dataclass is frozen so a misbehaving handler cannot mutate the
    context mid-request and escalate identity.
    """

    principal_id: str
    project_id: str = ""
    session_id: str = ""
    runtime_id: str = ""
    source_transport: str = "rpc"
    policy_digest: str = ""
    # M6.4: the transport-derived principal kind is part of the immutable
    # request identity.  Empty means "derive from source_transport"; callers
    # cannot silently turn a channel/cron/subagent request into a human one.
    principal_kind: str = ""
    parent_principal_id: str = ""
    delegation_digest: str = ""

    def __post_init__(self) -> None:
        try:
            # Some service unit tests intentionally construct an empty
            # context and verify that the service rejects it.  Preserve that
            # fail-closed boundary while still assigning a typed kind; the
            # public ``for_rpc``/``for_webhook`` constructors reject empty
            # principals before a request can enter production.
            identity = self.principal_id or "context-placeholder"
            derived = principal_for_transport(identity, self.source_transport)
            requested = (
                PrincipalKind(self.principal_kind)
                if self.principal_kind
                else derived.kind
            )
        except (PrincipalDelegationError, ValueError) as exc:
            raise ValueError("request context principal identity is invalid") from exc
        if requested is not derived.kind:
            raise ValueError(
                "request context principal kind does not match its transport"
            )
        object.__setattr__(self, "principal_kind", requested.value)
        parent = self.parent_principal_id
        if self.principal_id and not parent:
            parent = f"{requested.value}:{self.principal_id}"
            object.__setattr__(self, "parent_principal_id", parent)
        if self.principal_id and parent == self.principal_id:
            raise ValueError("request context parent principal cannot equal subject")
        delegation_digest = self.delegation_digest
        if self.principal_id and not delegation_digest:
            delegation_digest = _transport_delegation_digest(
                principal_id=self.principal_id,
                principal_kind=requested.value,
                parent_principal_id=parent,
                project_id=self.project_id,
                session_id=self.session_id,
                runtime_id=self.runtime_id,
                source_transport=self.source_transport,
                policy_digest=self.policy_digest,
            )
            object.__setattr__(self, "delegation_digest", delegation_digest)
        if delegation_digest and (
            len(delegation_digest) != 64
            or any(character not in "0123456789abcdef" for character in delegation_digest)
        ):
            raise ValueError("request context delegation digest is malformed")

    @property
    def principal(self) -> Principal:
        """Return the concrete typed principal for this request."""
        return principal_from_kind(self.principal_id, self.principal_kind)

    @classmethod
    def for_rpc(
        cls,
        principal_id: str,
        *,
        project_id: str = "",
        policy_digest: str = "",
    ) -> RequestContext:
        """Build a context for an RPC call authenticated by the
        Gateway's auth envelope.

        ``principal_id`` is the transport-authenticated principal
        returned by :meth:`GatewayRPCAuthenticator.authenticate`.  It
        MUST be non-empty — an RPC with no authenticated principal is
        rejected at the dispatcher, never reaches a service method.
        """
        if not principal_id:
            raise ValueError("principal_id is required for RPC context")
        return cls(
            principal_id=principal_id,
            project_id=project_id,
            source_transport="rpc",
            policy_digest=policy_digest,
            principal_kind=PrincipalKind.GATEWAY.value,
        )

    @classmethod
    def for_cli(
        cls,
        *,
        project_id: str = "",
        policy_digest: str = "",
    ) -> RequestContext:
        """Build a context for a CLI invocation (single-user, local).

        The principal is the OS uid — same as the legacy ``local-uid``
        binding.  CLI is trusted because the user is already running
        commands as themselves.

        Windows doesn't have ``os.getuid()``; fall back to a stable
        local identifier.  The CLI on Windows doesn't run the UDS
        server (which is Unix-only), so this context is only
        constructed in tests on Windows — the fallback is safe.
        """
        return cls(
            principal_id=local_principal_id(),
            project_id=project_id,
            source_transport="cli",
            policy_digest=policy_digest,
            principal_kind=PrincipalKind.HUMAN.value,
        )

    @classmethod
    def for_webhook(
        cls,
        principal_id: str,
        *,
        project_id: str = "",
        policy_digest: str = "",
    ) -> RequestContext:
        """Build a context for a webhook-triggered chat turn.

        ``principal_id`` is the derived webhook principal
        (``webhook:<channel>:<platform>:<sender>``).
        """
        if not principal_id:
            raise ValueError("principal_id is required for webhook context")
        return cls(
            principal_id=principal_id,
            project_id=project_id,
            source_transport="webhook",
            policy_digest=policy_digest,
            principal_kind=PrincipalKind.CHANNEL.value,
        )

    @classmethod
    def for_cron(
        cls,
        principal_id: str,
        *,
        project_id: str = "",
        policy_digest: str = "",
    ) -> RequestContext:
        """Build a context for a cron-triggered chat turn.

        ``principal_id`` is the principal bound to the scheduled task
        at creation time (stamped on ``scheduled_tasks.principal_id``).
        """
        if not principal_id:
            raise ValueError("principal_id is required for cron context")
        return cls(
            principal_id=principal_id,
            project_id=project_id,
            source_transport="cron",
            policy_digest=policy_digest,
            principal_kind=PrincipalKind.AUTOMATION.value,
        )

    def with_session(self, session_id: str) -> RequestContext:
        """Return a copy of this context with ``session_id`` set.

        Used by ``AgentService.chat`` to bind the request's session_id
        into the context before forwarding it to ``build_runtime``.
        """
        return RequestContext(
            principal_id=self.principal_id,
            project_id=self.project_id,
            session_id=session_id,
            runtime_id=self.runtime_id,
            source_transport=self.source_transport,
            policy_digest=self.policy_digest,
            principal_kind=self.principal_kind,
            parent_principal_id=self.parent_principal_id,
            delegation_digest="",
        )

    def with_runtime_id(self, runtime_id: str) -> RequestContext:
        """Return a copy of this context with ``runtime_id`` set.

        Used by ``build_runtime`` to stamp the new runtime's UUID into
        the context before handing it to tools / subagents.
        """
        return RequestContext(
            principal_id=self.principal_id,
            project_id=self.project_id,
            session_id=self.session_id,
            runtime_id=runtime_id,
            source_transport=self.source_transport,
            policy_digest=self.policy_digest,
            principal_kind=self.principal_kind,
            parent_principal_id=self.parent_principal_id,
            delegation_digest="",
        )
