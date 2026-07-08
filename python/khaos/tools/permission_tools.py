"""Permission management tools for security administration."""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

_permission_engine = None
_audit_logger = None


def init_permission_tools(permission_engine, audit_logger) -> None:
    """注入权限引擎和审计日志器的全局引用。"""
    global _permission_engine, _audit_logger
    _permission_engine = permission_engine
    _audit_logger = audit_logger


async def list_permission_rules() -> dict[str, Any]:
    """列出所有权限规则。"""
    if _permission_engine is None:
        return {"ok": False, "error": "Permission engine not initialized"}
    rules = _permission_engine._rules
    return {
        "ok": True,
        "rules": [
            {
                "id": rule.id,
                "pattern": rule.pattern,
                "level": rule.permission_level,
                "approval": rule.approval.value,
                "mode": rule.mode,
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
) -> dict[str, Any]:
    """授予一条权限规则。"""
    if _permission_engine is None:
        return {"ok": False, "error": "Permission engine not initialized"}
    from khaos.permissions.engine import ApprovalMode, PermissionRule

    try:
        rule = await _permission_engine.grant_rule(
            PermissionRule(
                id=None,
                pattern=pattern,
                permission_level=permission_level,
                approval=ApprovalMode(approval),
                mode=mode,
            )
        )
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
    return {
        "ok": True,
        "rule": {
            "id": rule.id,
            "pattern": rule.pattern,
            "level": rule.permission_level,
            "approval": rule.approval.value,
            "mode": rule.mode,
        },
    }


async def revoke_permission(rule_id: int) -> dict[str, Any]:
    """撤销一条权限规则。"""
    if _permission_engine is None:
        return {"ok": False, "error": "Permission engine not initialized"}
    try:
        await _permission_engine.revoke_rule(rule_id)
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
    return {"ok": True, "revoked": rule_id}


async def query_audit_logs(
    action: str = "",
    result: str = "",
    limit: int = 50,
) -> dict[str, Any]:
    """查询审计日志。"""
    if _audit_logger is None:
        return {"ok": False, "error": "Audit logger not initialized"}
    entries = await _audit_logger.query(
        action=action or None,
        result=result or None,
        limit=limit,
    )
    return {
        "ok": True,
        "logs": [entry.to_dict() for entry in entries],
        "total": len(entries),
    }


async def security_status() -> dict[str, Any]:
    """获取当前安全状态概览。"""
    if _permission_engine is None or _audit_logger is None:
        return {"ok": False, "error": "Not initialized"}

    rules_count = len(_permission_engine._rules)
    all_logs = await _audit_logger.query(limit=100)
    denied_count = sum(1 for log in all_logs if log.result == "denied")

    return {
        "ok": True,
        "rules_count": rules_count,
        "audit_entries_sample": len(all_logs),
        "recent_denials": denied_count,
    }
