"""Tools for channel registration status management.

M4 batch 3.1.16A-4-4-3: the module-global ``_registry`` holder and the
``set_channel_registry`` setter have been removed.

Background — why the holder was problematic:

  ``set_channel_registry`` was called from production code
  (``grpc_server.py`` installed ``self.channel_registry`` into the holder
  at startup), so unlike ``history_tools`` the handlers were NOT dead
  code — they actually served live traffic.  The problem was that the
  holder carried no principal identity, so EVERY principal sharing the
  process could:

  * read the channel registry (``channel_list`` / ``channel_health``);
  * mutate it (``channel_enable`` / ``channel_disable``) — this is the
    CRITICAL risk: any authenticated principal could silently disable
    another principal's notification channel, or enable a channel the
    operator had deliberately disabled.

  The gRPC ``set_channel_enabled`` RPC path
  (``AgentService.set_channel_enabled``) already used ``ctx.principal_id``
  for authorization, but the tool path bypassed that check entirely.

Closure — per-call construction + admin gate (mirrors the
``permission_tools`` / ``cron_tools`` pattern):

  Every handler now receives ``channel_registry`` + ``principal_id`` as
  keyword arguments injected by :class:`ToolInvocationBroker` via the
  new ``channel.read`` / ``channel.manage`` capabilities declared in
  ``registry.py``.  Read-only handlers (``channel_list`` /
  ``channel_health``) accept any authenticated principal — channel
  health is operational metadata a principal needs to reason about its
  own notifications.  Mutation handlers (``channel_enable`` /
  ``channel_disable``) additionally receive ``channel_admins`` (a
  frozenset of principal identifiers compiled from
  ``khaos_policy.yaml``'s ``channels.admin_principals`` field with OR
  semantics across user ∩ project layers) and reject the call via
  ``_require_admin`` unless the caller's ``principal_id`` is in the
  set.

Fail-closed semantics:

  * Missing ``channel_registry`` → ``{"status": "unavailable"}``.
  * Empty ``principal_id`` → ``{"status": "unavailable", "error":
    "principal_id is required"}``.
  * Mutation without admin grant → ``{"status": "forbidden", "error":
    "principal is not a channel admin"}``.

  The admin gate is compiled into the immutable
  :class:`EffectiveSecurityPolicy` at startup (user ∪ project), so a
  misconfigured or malicious runtime cannot widen the admin set at
  tool-call time.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


def _require_registry(channel_registry: Any) -> dict[str, Any] | None:
    """Return an ``unavailable`` error dict if ``channel_registry`` is
    missing, else ``None``.

    A misconfigured tool context (no registry injected) fails
    gracefully rather than crashing — mirrors the original
    ``_registry is None`` behavior.
    """
    if channel_registry is None:
        return {"status": "unavailable", "error": "channel registry not configured"}
    return None


def _require_principal(principal_id: str) -> dict[str, Any] | None:
    """Return an ``unavailable`` error dict if ``principal_id`` is empty,
    else ``None``.

    M4 batch 3.1.16A-4-4-3: read tools must not fall open to an
    unscoped query when the caller's principal is missing — that would
    let a misconfigured tool context return channel state without an
    authenticated caller.  Empty principal is rejected (mirrors
    ``history_tools._require_principal`` /
    ``permission_tools._require_principal``).
    """
    if not principal_id:
        return {"status": "unavailable", "error": "principal_id is required"}
    return None


def _require_admin(
    principal_id: str, channel_admins: Any,
) -> dict[str, str] | None:
    """Return a ``forbidden`` error dict if ``principal_id`` is not in
    ``channel_admins``, else ``None``.

    M4 batch 3.1.16A-4-4-3: channel mutations (enable / disable) are
    gated on the admin principal allowlist compiled into the
    :class:`EffectiveSecurityPolicy`.  An empty ``channel_admins``
    (the default) means NO principal can mutate channels via the
    tool path — fail-closed until an admin is explicitly declared in
    ``khaos_policy.yaml``'s ``channels.admin_principals``.

    ``channel_admins`` is expected to be a frozenset[str] (the
    effective-policy compiled form).  A ``None`` value is treated as
    "no admins" (still fail-closed) so a misconfigured tool context
    cannot fall open.
    """
    if not channel_admins:
        return {
            "status": "forbidden",
            "error": "principal is not a channel admin",
        }
    if principal_id not in channel_admins:
        return {
            "status": "forbidden",
            "error": "principal is not a channel admin",
        }
    return None


async def channel_list(
    *,
    principal_id: str = "",
    channel_registry: Any = None,
    **kwargs: Any,
) -> dict[str, Any]:
    """List registered communication channels.

    Args:
        principal_id: Caller's principal ID (injected by broker via the
            ``channel.read`` capability).  Required — fail-closed on
            empty.
        channel_registry: Channel registry instance (injected by broker
            from ``tool_context``).
    """
    principal_error = _require_principal(principal_id)
    if principal_error is not None:
        return principal_error
    registry_error = _require_registry(channel_registry)
    if registry_error is not None:
        return registry_error
    return {
        "channels": [
            {
                "id": item.id,
                "type": item.channel_type.value,
                "enabled": item.is_enabled,
                "healthy": item.is_healthy,
                "status": item.health.status.value,
            }
            for item in channel_registry.list_all()
        ]
    }


async def channel_health(
    *,
    principal_id: str = "",
    channel_registry: Any = None,
    **kwargs: Any,
) -> dict[str, Any]:
    """Get channel health reports.

    Args:
        principal_id: Caller's principal ID (injected by broker).
        channel_registry: Channel registry instance (injected by broker
            from ``tool_context``).
    """
    principal_error = _require_principal(principal_id)
    if principal_error is not None:
        return principal_error
    registry_error = _require_registry(channel_registry)
    if registry_error is not None:
        return registry_error
    return {"report": channel_registry.get_health_report()}


async def channel_enable(
    channel_id: str,
    *,
    principal_id: str = "",
    channel_registry: Any = None,
    channel_admins: Any = None,
    **kwargs: Any,
) -> dict[str, str]:
    """Enable a registered channel (admin-gated).

    Args:
        channel_id: Channel ID to enable.
        principal_id: Caller's principal ID (injected by broker via the
            ``channel.manage`` capability).  Must be in
            ``channel_admins``.
        channel_registry: Channel registry instance (injected by broker
            from ``tool_context``).
        channel_admins: Frozenset of admin principal IDs compiled into
            the :class:`EffectiveSecurityPolicy` (injected by broker
            from ``tool_context``).
    """
    principal_error = _require_principal(principal_id)
    if principal_error is not None:
        return {"status": "unavailable", "channel_id": channel_id, "error": "principal_id is required"}
    admin_error = _require_admin(principal_id, channel_admins)
    if admin_error is not None:
        return {"status": admin_error["status"], "channel_id": channel_id, "error": admin_error["error"]}
    registry_error = _require_registry(channel_registry)
    if registry_error is not None:
        return {"status": "unavailable", "channel_id": channel_id, "error": registry_error["error"]}
    return {
        "status": "enabled" if channel_registry.enable(channel_id) else "not_found",
        "channel_id": channel_id,
    }


async def channel_disable(
    channel_id: str,
    *,
    principal_id: str = "",
    channel_registry: Any = None,
    channel_admins: Any = None,
    **kwargs: Any,
) -> dict[str, str]:
    """Disable a registered channel (admin-gated).

    Args:
        channel_id: Channel ID to disable.
        principal_id: Caller's principal ID (injected by broker).  Must
            be in ``channel_admins``.
        channel_registry: Channel registry instance (injected by broker
            from ``tool_context``).
        channel_admins: Frozenset of admin principal IDs compiled into
            the :class:`EffectiveSecurityPolicy` (injected by broker
            from ``tool_context``).
    """
    principal_error = _require_principal(principal_id)
    if principal_error is not None:
        return {"status": "unavailable", "channel_id": channel_id, "error": "principal_id is required"}
    admin_error = _require_admin(principal_id, channel_admins)
    if admin_error is not None:
        return {"status": admin_error["status"], "channel_id": channel_id, "error": admin_error["error"]}
    registry_error = _require_registry(channel_registry)
    if registry_error is not None:
        return {"status": "unavailable", "channel_id": channel_id, "error": registry_error["error"]}
    return {
        "status": "disabled" if channel_registry.disable(channel_id) else "not_found",
        "channel_id": channel_id,
    }


CHANNEL_TOOLS = [
    {"name": "channel_list", "description": "List registered communication channels.", "parameters": {"type": "object", "properties": {}}},
    {"name": "channel_health", "description": "Get channel health reports.", "parameters": {"type": "object", "properties": {}}},
    {"name": "channel_enable", "description": "Enable a registered channel (admin-gated).", "parameters": {"type": "object", "properties": {"channel_id": {"type": "string"}}, "required": ["channel_id"]}},
    {"name": "channel_disable", "description": "Disable a registered channel (admin-gated).", "parameters": {"type": "object", "properties": {"channel_id": {"type": "string"}}, "required": ["channel_id"]}},
]
