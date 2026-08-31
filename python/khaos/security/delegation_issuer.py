"""Authority-owned delegation issuance for production ingress points.

M6.9 BATCH 4: a child task must never reuse its parent's delegation
digest.  Every child receives an independent narrow delegation issued by
the authority daemon: unique nonce/digest, subset operation and resource
scope, expiry no later than the parent, exact context binding, one-shot
consumption, and cascade revocation.  The Python caller cannot self-attest
a delegation digest; it can only ask the authority owner to issue one.
"""

from __future__ import annotations

import time
from typing import Protocol

from khaos.runtime.context import RequestContext
from khaos.security.principals import (
    PRINCIPAL_DELEGATION_FAMILY,
    DelegationScope,
    PrincipalKind,
)

# Root delegations for subagent issuance live slightly longer than the
# child task so the child can always be renewed inside the parent window.
_ROOT_GRACE_SECONDS = 300.0
_UNBOUND = "unbound"


class SubAgentDelegationIssuer(Protocol):
    """Issue one authority-owned delegation digest for a spawned child."""

    def issue_subagent_delegation(
        self,
        ctx: RequestContext,
        *,
        task_id: str,
        tools: list[str],
        timeout_seconds: int,
        session_id: str = "",
        runtime_id: str = "",
        workspace_id: str = "",
    ) -> str: ...


class DelegationAuthorityClient(Protocol):
    """Minimal authority surface required to issue a child delegation."""

    def delegation_register_root(self, scope: DelegationScope) -> str:
        """Register an ingress root with the independent authority."""
        ...

    def delegation_issue_child(
        self,
        parent: DelegationScope,
        child_principal_id: str,
        child_principal_kind: str,
        *,
        operation_family: str,
        resource_scope: list[str],
        expires_at: float,
        session_id: str | None = None,
        runtime_id: str | None = None,
        task_id: str | None = None,
        workspace_id: str | None = None,
    ) -> DelegationScope:
        """Issue one narrow child delegation."""
        ...


class AuthorityDelegationIssuer:
    """Production issuer backed by the independent authority daemon."""

    def __init__(self, client: DelegationAuthorityClient) -> None:
        self._client = client

    def _root_scope(
        self,
        ctx: RequestContext,
        *,
        resources: list[str],
        expires_at: float,
    ) -> DelegationScope:
        return DelegationScope.root(
            ctx.principal,
            project_id=ctx.project_id or _UNBOUND,
            # The ingress request has no child execution identity yet.  The
            # real session/runtime are bound exactly once on the child scope
            # below, after the service has allocated the task identity.
            session_id=_UNBOUND,
            runtime_id=_UNBOUND,
            # A principal root is not an effect grant and therefore has no
            # task binding.  The child task is bound exactly once at issuance;
            # reusing the session id here made ``contains`` reject the real
            # child scope as an attempted rebind.
            task_id=_UNBOUND,
            workspace_id=_UNBOUND,
            operation_family=PRINCIPAL_DELEGATION_FAMILY,
            resource_scope=resources,
            policy_digest=ctx.policy_digest or "0" * 64,
            expires_at=expires_at,
        )

    def issue_subagent_delegation(
        self,
        ctx: RequestContext,
        *,
        task_id: str,
        tools: list[str],
        timeout_seconds: int,
        session_id: str = "",
        runtime_id: str = "",
        workspace_id: str = "",
    ) -> str:
        if ctx.principal.kind is PrincipalKind.SUBAGENT:
            # Single-layer delegation: a subagent may never issue further
            # delegations in its own name.
            raise PermissionError("subagents cannot issue child delegations")
        if not task_id:
            raise ValueError("task_id is required for delegation issuance")
        resources = sorted({tool for tool in tools if tool}) or ["subagent:none"]
        now = time.time()
        child_expires = now + max(timeout_seconds, 1) + _ROOT_GRACE_SECONDS
        root = self._root_scope(
            ctx,
            resources=resources,
            expires_at=child_expires + _ROOT_GRACE_SECONDS,
        )
        self._client.delegation_register_root(root)
        # The child scope is bound to the REAL subagent task and (when
        # known) workspace — the bound values are what the authority
        # matches at grant time, not the parent session placeholder.
        child = self._client.delegation_issue_child(
            root,
            f"subagent:{ctx.principal_id}:{task_id}",
            PrincipalKind.SUBAGENT.value,
            operation_family=PRINCIPAL_DELEGATION_FAMILY,
            resource_scope=resources,
            expires_at=child_expires,
            task_id=task_id,
            session_id=session_id or _UNBOUND,
            runtime_id=runtime_id or _UNBOUND,
            workspace_id=workspace_id or _UNBOUND,
        )
        return child.digest


class ProductionSubAgentDelegationIssuer:
    """Issue delegations through a short-lived, bound production channel.

    RPC subagent admission happens before a child runtime exists, so the
    issuer cannot borrow that child's effect broker.  It therefore creates a
    separate authority channel bound to the authenticated ingress principal
    and the child execution identity, issues the narrow delegation, and
    releases the channel immediately.  The child then creates its own READY
    broker for all effects.  Crucially, this path never constructs an
    unbound production ``AuthorityDaemonClient``.
    """

    def __init__(
        self,
        *,
        policy_digest: str,
        catalog_digest: str,
        project_id: str,
    ) -> None:
        if (
            type(policy_digest) is not str
            or len(policy_digest) != 64
            or any(character not in "0123456789abcdef" for character in policy_digest)
        ):
            raise ValueError("production delegation policy digest is invalid")
        if (
            type(catalog_digest) is not str
            or len(catalog_digest) != 64
            or any(character not in "0123456789abcdef" for character in catalog_digest)
        ):
            raise ValueError("production delegation catalog digest is invalid")
        if type(project_id) is not str or not project_id or "\x00" in project_id:
            raise ValueError("production delegation project_id is invalid")
        self._policy_digest = policy_digest
        self._catalog_digest = catalog_digest
        self._project_id = project_id

    def issue_subagent_delegation(
        self,
        ctx: RequestContext,
        *,
        task_id: str,
        tools: list[str],
        timeout_seconds: int,
        session_id: str = "",
        runtime_id: str = "",
        workspace_id: str = "",
    ) -> str:
        if ctx.project_id != self._project_id:
            raise PermissionError(
                "subagent delegation project does not match the production binding"
            )
        if ctx.policy_digest != self._policy_digest:
            raise PermissionError(
                "subagent delegation policy does not match the production binding"
            )
        if not runtime_id:
            raise ValueError("subagent delegation runtime_id is required")
        # The channel is authenticated as the ingress principal.  The child
        # runtime receives its own channel later; the two channels must not be
        # conflated because the authority uses the runtime identity as part of
        # the trust binding.
        from khaos.security.authority_broker import AuthorityBroker

        broker = AuthorityBroker.for_production(
            policy_digest=self._policy_digest,
            catalog_digest=self._catalog_digest,
            runtime_id=f"delegation:{runtime_id}",
            principal_id=ctx.principal_id,
            project_id=self._project_id,
            principal_kind=ctx.principal_kind,
        )
        try:
            return AuthorityDelegationIssuer(broker).issue_subagent_delegation(
                ctx,
                task_id=task_id,
                tools=tools,
                timeout_seconds=timeout_seconds,
                session_id=session_id,
                runtime_id=runtime_id,
                workspace_id=workspace_id,
            )
        finally:
            broker.close()


__all__ = [
    "AuthorityDelegationIssuer",
    "DelegationAuthorityClient",
    "ProductionSubAgentDelegationIssuer",
    "SubAgentDelegationIssuer",
]
