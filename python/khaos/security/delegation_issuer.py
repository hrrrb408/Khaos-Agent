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
from khaos.security.authorityd_protocol import AuthorityDaemonClient
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


class AuthorityDelegationIssuer:
    """Production issuer backed by the independent authority daemon."""

    def __init__(self, client: AuthorityDaemonClient) -> None:
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


__all__ = ["AuthorityDelegationIssuer", "SubAgentDelegationIssuer"]
