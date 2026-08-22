"""Value types shared by the permission engine and pure evaluator."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

DEFAULT_EXEC_TOOLS = frozenset(
    {
        "terminal",
        "terminal_argv",
        "terminal_shell",
        "process",
        "sandbox_exec",
        "sandbox_build",
    }
)


class ApprovalMode(Enum):
    """Supported permission approval policies."""

    AUTO_APPROVE = "auto-approve"
    SUGGEST = "suggest"
    ASK_EVERY = "ask-every"
    DENY = "deny"


class SourceTransport(str, Enum):
    """Authenticated origin of a turn."""

    CLI = "cli"
    TUI = "tui"
    RPC = "rpc"
    WEBHOOK = "webhook"
    CRON = "cron"
    SUBAGENT = "subagent"
    INTERNAL_VERIFICATION = "internal_verification"


class TransportClass(str, Enum):
    """Coarse trust class used to scope persistent permission grants."""

    INTERACTIVE = "interactive"
    UNATTENDED = "unattended"
    ALL = "all"


class GrantLifetime(str, Enum):
    """Lifetime/scope of a persistent permission grant."""

    ONCE = "once"
    TURN = "turn"
    SESSION = "session"
    TASK = "task"
    PROJECT_INTERACTIVE = "project_interactive"
    PROJECT_ALL_TRANSPORTS = "project_all_transports"


@dataclass
class PermissionRule:
    """Persistent permission rule."""

    id: int | None
    pattern: str
    permission_level: str
    approval: ApprovalMode
    mode: str
    granted_at: float = 0.0
    policy_digest: str = ""
    generation: int = 0
    transport_class: str = ""
    grant_lifetime: str = ""
    session_id: str = ""
    task_id: str = ""
    workspace_id: str = ""
    expires_at: float | None = None
    created_by: str = ""
    resource_type: str = ""
    resource_spec: dict[str, Any] | None = None


@dataclass
class PermissionDecision:
    """Result of checking a tool call against permission rules."""

    approved: ApprovalMode
    reason: str
    target: str
    matched_rule: PermissionRule | None = None
    requires_user_confirm: bool = False


__all__ = [
    "DEFAULT_EXEC_TOOLS",
    "ApprovalMode",
    "GrantLifetime",
    "PermissionDecision",
    "PermissionRule",
    "SourceTransport",
    "TransportClass",
]
