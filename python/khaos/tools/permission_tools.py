"""Permission management tools for security administration.

M4 batch 3.1.16A-4-4-1 (CRITICAL): the module-global
``_permission_engine`` / ``_audit_logger`` holders have been removed.

Background — why the holders were a CRITICAL bug:

  ``runtime/factory.py`` called ``init_permission_tools(engine, logger)``
  on every ``build_runtime()`` (i.e. every chat turn). In a multi-
  principal RPC server, principal A's ``build_runtime`` and principal
  B's ``build_runtime`` race — last-write-wins on the module global.
  When A subsequently called ``grant_permission`` the handler used B's
  engine, writing the rule under B's ``principal_id`` and stamping the
  audit row as B. Cross-principal rule injection + audit misattribution.

Closure — the cron_tools / orchestrator_tools pattern:

  Every handler now receives ``principal_id``, ``permission_engine`` and
  ``audit_logger`` as keyword arguments injected by the
  :class:`ToolInvocationBroker` via the new ``permission.read`` /
  ``permission.manage`` capabilities declared in ``registry.py``. The
  broker reads them from ``tool_context`` (assembled per-turn by
  :class:`AgentLoop`), so each call gets the caller's own principal-
  scoped engine / logger — no module-global state, no race.

Fail-closed semantics:

  Empty ``principal_id`` is rejected by ``_require_principal``. A
  missing ``permission_engine`` / ``audit_logger`` returns
  ``{"ok": False, "error": "not initialized"}`` rather than silently
  no-op'ing. The ``audit_logger.query`` call passes
  ``principal_id=principal_id`` explicitly so the server-lifecycle
  logger (bound to ``local-uid`` at startup) cannot leak another
  principal's audit trail.
"""

from __future__ import annotations

import logging
from typing import Any

from khaos.tools.scheduler import (
    EFFECT_APPLIED,
    EFFECT_NOT_APPLIED,
    ToolExecutionOutcome,
)

logger = logging.getLogger(__name__)


def _failure(payload: dict[str, Any]) -> ToolExecutionOutcome:
    error = str(payload.get("error") or "permission tool failed")
    return ToolExecutionOutcome(
        ok=False,
        output=payload,
        error=error,
        error_code=str(payload.get("error_code") or "PERMISSION_ERROR"),
        effect_status=EFFECT_NOT_APPLIED,
        retry_safe=True,
    )


def _success(payload: dict[str, Any]) -> ToolExecutionOutcome:
    return ToolExecutionOutcome(output=payload, effect_status=EFFECT_APPLIED)


def _require_principal(principal_id: str) -> ToolExecutionOutcome | None:
    """Return a typed failure if ``principal_id`` is empty,
    else ``None``.

    M4 batch 3.1.16A-4-4-1 (CRITICAL): permission tools must not fail
    open to a shared pseudo-principal when the caller's principal is
    missing — that would let a misconfigured tool context silently
    operate on another principal's rules or audit trail.  Empty
    principal is rejected (mirrors ``cron_tools._require_principal``).
    """
    if not principal_id:
        return _failure({"ok": False, "error": "principal_id is required"})
    return None


async def list_permission_rules(
    *,
    principal_id: str = "",
    permission_engine: Any = None,
    **kwargs: Any,
) -> dict[str, Any]:
    """List all permission rules owned by the caller's principal.

    Args:
        principal_id: Caller's principal ID (injected by broker via the
            ``permission.read`` capability).  Required.
        permission_engine: Caller's principal-scoped PermissionEngine
            (injected by broker from ``tool_context``).
    """
    principal_error = _require_principal(principal_id)
    if principal_error is not None:
        return principal_error
    if permission_engine is None:
        return {"ok": False, "error": "Permission engine not initialized"}
    rules = permission_engine._rules
    return {
        "ok": True,
        "rules": [
            {
                "id": rule.id,
                "pattern": rule.pattern,
                "level": rule.permission_level,
                "approval": rule.approval.value,
                "mode": rule.mode,
                "transport_class": rule.transport_class,
                "grant_lifetime": rule.grant_lifetime,
                "session_id": rule.session_id,
                "task_id": rule.task_id,
                "workspace_id": rule.workspace_id,
                "expires_at": rule.expires_at,
                "resource_type": rule.resource_type,
                "resource_spec": rule.resource_spec,
            }
            for rule in rules
        ],
        "total": len(rules),
    }


async def grant_permission(
    pattern: str,
    permission_level: str,
    approval: str = "auto-approve",
    mode: str = "all",
    *,
    principal_id: str = "",
    permission_engine: Any = None,
    source_transport: str | None = None,
    session_id: str = "",
    task_id: str = "",
    workspace_id: str = "",
    resource_type: str = "",
    resource_spec: dict[str, Any] | None = None,
    **kwargs: Any,
) -> ToolExecutionOutcome:
    """Grant a permission rule bound to the caller's principal.

    The rule is persisted with ``principal_id`` stamped by the engine
    (``PermissionEngine`` is constructed per-runtime with
    ``principal_id=cfg.principal_id``), so a different principal cannot
    see or revoke it.
    """
    principal_error = _require_principal(principal_id)
    if principal_error is not None:
        return principal_error
    if permission_engine is None:
        return _failure({"ok": False, "error": "Permission engine not initialized"})
    from khaos.permissions import is_interactive_transport

    # A model-visible permission-management tool cannot mint a project-wide
    # unattended grant. The trusted local CLI/TUI can create a project
    # interactive grant; other transports must use an explicit administrative
    # control plane rather than inheriting an interactive remember rule.
    if not is_interactive_transport(source_transport):
        return _failure({
            "ok": False,
            "error": "permission grants require an explicit interactive CLI/TUI transport",
        })
    from khaos.permissions.engine import (
        ApprovalMode,
        PermissionRule,
        validate_rule_pattern,
    )

    # P1-4: relaxing grants must use the typed resource DSL.  DENY and
    # ASK_EVERY may keep a generic glob because they cannot widen authority.
    try:
        approval_mode = ApprovalMode(approval)
    except ValueError as exc:
        return _failure({"ok": False, "error": f"invalid approval mode: {exc}"})
    if approval_mode in {ApprovalMode.AUTO_APPROVE, ApprovalMode.SUGGEST}:
        if not resource_type or not isinstance(resource_spec, dict):
            return _failure({
                "ok": False,
                "error": "auto-approve/suggest grants require a typed resource_type and resource_spec",
            })
    elif not resource_type:
        try:
            validate_rule_pattern(
                pattern, approval_mode, source="grant_permission"
            )
        except ValueError as exc:
            return _failure({"ok": False, "error": str(exc)})
    try:
        rule = await permission_engine.grant_rule(
            PermissionRule(
                id=None,
                pattern=pattern,
                permission_level=permission_level,
                approval=approval_mode,
                mode=mode,
                transport_class="interactive",
                grant_lifetime="project_interactive",
                session_id="",
                task_id=task_id,
                workspace_id=workspace_id,
                created_by=f"permission-tool:{source_transport}",
                resource_type=resource_type,
                resource_spec=resource_spec,
            )
        )
    except Exception as exc:  # noqa: BLE001 - tool API returns a structured failure
        return _failure({"ok": False, "error": str(exc)})
    return _success({
        "ok": True,
        "rule": {
            "id": rule.id,
            "pattern": rule.pattern,
            "level": rule.permission_level,
            "approval": rule.approval.value,
            "mode": rule.mode,
            "resource_type": rule.resource_type,
            "resource_spec": rule.resource_spec,
        },
    })


async def revoke_permission(
    rule_id: int,
    *,
    principal_id: str = "",
    permission_engine: Any = None,
    **kwargs: Any,
) -> ToolExecutionOutcome:
    """Revoke a permission rule owned by the caller's principal.

    The engine refuses to revoke a rule that does not belong to
    ``principal_id`` (defense-in-depth at the DB layer) — a foreign
    principal's rule_id is reported as "not found".
    """
    principal_error = _require_principal(principal_id)
    if principal_error is not None:
        return principal_error
    if permission_engine is None:
        return _failure({"ok": False, "error": "Permission engine not initialized"})
    try:
        await permission_engine.revoke_rule(rule_id)
    except Exception as exc:  # noqa: BLE001 - tool API returns a structured failure
        return _failure({"ok": False, "error": str(exc)})
    return _success({"ok": True, "revoked": rule_id})


async def query_audit_logs(
    action: str = "",
    result: str = "",
    limit: int = 50,
    *,
    principal_id: str = "",
    audit_logger: Any = None,
    **kwargs: Any,
) -> dict[str, Any]:
    """Query audit log entries owned by the caller's principal.

    M4 batch 3.1.16A-4-4-1 (CRITICAL): ``principal_id`` is passed
    explicitly to ``audit_logger.query`` to override the logger's
    default.  The server-lifecycle ``AuditLogger`` is bound to
    ``local-uid:{os.getuid()}`` at startup — without this override,
    every principal would see only the server-uid's audit trail.  With
    the override, each principal sees its own entries (admin opt-in is
    a future enhancement via ``principal_id=None``).
    """
    principal_error = _require_principal(principal_id)
    if principal_error is not None:
        return principal_error
    if audit_logger is None:
        return {"ok": False, "error": "Audit logger not initialized"}
    entries = await audit_logger.query(
        action=action or None,
        result=result or None,
        limit=limit,
        principal_id=principal_id,
    )
    return {
        "ok": True,
        "logs": [entry.to_dict() for entry in entries],
        "total": len(entries),
    }


async def security_status(
    *,
    principal_id: str = "",
    permission_engine: Any = None,
    audit_logger: Any = None,
    **kwargs: Any,
) -> dict[str, Any]:
    """Get security status overview for the caller's principal.

    Both the rule count and the audit sample are scoped to
    ``principal_id`` — a principal sees only its own rules and its own
    audit entries (including denials).
    """
    principal_error = _require_principal(principal_id)
    if principal_error is not None:
        return principal_error
    if permission_engine is None or audit_logger is None:
        return {"ok": False, "error": "Not initialized"}

    rules_count = len(permission_engine._rules)
    all_logs = await audit_logger.query(
        limit=100, principal_id=principal_id,
    )
    denied_count = sum(1 for log in all_logs if log.result == "denied")

    return {
        "ok": True,
        "rules_count": rules_count,
        "audit_entries_sample": len(all_logs),
        "recent_denials": denied_count,
    }
