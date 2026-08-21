"""Pure permission decision strategy.

The evaluator has no database, audit writer, or lifecycle state.  It receives
one immutable rule snapshot and returns a :class:`PermissionDecision`.  The
engine remains responsible for loading/reloading that snapshot and for
durable grant/revoke/audit operations.
"""

from __future__ import annotations

import fnmatch
import logging
import shlex
import time
from collections.abc import Iterable

from khaos.permissions.models import (
    DEFAULT_EXEC_TOOLS,
    ApprovalMode,
    GrantLifetime,
    PermissionDecision,
    PermissionRule,
    SourceTransport,
    TransportClass,
)
from khaos.permissions.resource import AuthorizationResource
from khaos.permissions.rules import is_relaxing_approval, match_typed_rule

logger = logging.getLogger(__name__)

_INTERACTIVE_TRANSPORTS = frozenset(
    {SourceTransport.CLI.value, SourceTransport.TUI.value}
)


class PermissionEvaluator:
    """Evaluate one tool request against a captured rule snapshot."""

    def __init__(
        self,
        *,
        rules: Iterable[PermissionRule],
        default_mode: ApprovalMode,
        commands_require_approval: frozenset[str],
        exec_tool_names: frozenset[str] | None = None,
    ) -> None:
        self._rules = tuple(rules)
        self._default_mode = default_mode
        self._commands_require_approval = frozenset(commands_require_approval)
        self._exec_tool_names = frozenset(exec_tool_names or DEFAULT_EXEC_TOOLS)

    def evaluate(
        self,
        tool_name: str,
        params: dict,
        permission_level: str,
        mode: str,
        target: str,
        resource: AuthorizationResource | None = None,
        *,
        source_transport: str | None = None,
        session_id: str | None = None,
        task_id: str | None = None,
        workspace_id: str | None = None,
    ) -> PermissionDecision:
        """Return the fail-closed decision for one already-normalized target."""
        if self._commands_require_approval and tool_name in self._exec_tool_names:
            command_text = _command_text(params)
            if _matches_required_approval(
                command_text, self._commands_require_approval
            ):
                return PermissionDecision(
                    approved=ApprovalMode.ASK_EVERY,
                    reason=f"Policy requires approval for command: {target}",
                    target=target,
                    requires_user_confirm=True,
                )

        read_only_terminal = (
            tool_name in {"terminal", "terminal_argv", "terminal_shell"}
            and _is_read_only_terminal_call(tool_name, params)
            and _is_interactive_transport(source_transport)
        )
        current_transport_class = _transport_class(source_transport)
        for rule in self._rules:
            if rule.mode != "all" and rule.mode != mode:
                continue
            if rule.permission_level != permission_level:
                continue
            if not _rule_scope_matches(
                rule,
                transport_class=current_transport_class,
                session_id=session_id,
                task_id=task_id,
                workspace_id=workspace_id,
            ):
                continue
            matched = self._matches_rule(
                rule,
                resource=resource,
                tool_name=tool_name,
                params=params,
                target=target,
                permission_level=permission_level,
            )
            if matched:
                match_label = (
                    f"{rule.resource_type} resource"
                    if rule.resource_type
                    else rule.pattern
                )
                return PermissionDecision(
                    approved=rule.approval,
                    reason=f"Matched rule: {match_label}",
                    target=target,
                    matched_rule=rule,
                    requires_user_confirm=rule.approval == ApprovalMode.ASK_EVERY,
                )

        if read_only_terminal:
            return PermissionDecision(
                approved=ApprovalMode.AUTO_APPROVE,
                reason="Read-only terminal command (no deny rule matched)",
                target=target,
                requires_user_confirm=False,
            )
        if self._default_mode == ApprovalMode.AUTO_APPROVE:
            return PermissionDecision(
                approved=ApprovalMode.AUTO_APPROVE,
                reason="No matching rule, default: auto-approve",
                target=target,
            )
        if self._default_mode == ApprovalMode.DENY:
            return PermissionDecision(
                approved=ApprovalMode.DENY,
                reason="No matching rule, default: deny",
                target=target,
            )
        return PermissionDecision(
            approved=self._default_mode,
            reason=f"No matching rule, default: {self._default_mode.value}",
            target=target,
            requires_user_confirm=True,
        )

    @staticmethod
    def _matches_rule(
        rule: PermissionRule,
        *,
        resource: AuthorizationResource | None,
        tool_name: str,
        params: dict,
        target: str,
        permission_level: str,
    ) -> bool:
        if rule.resource_type:
            try:
                return match_typed_rule(
                    rule.resource_type,
                    rule.resource_spec or {},
                    resource=resource,
                    tool_name=tool_name,
                    params=params,
                    target=target,
                    operation=permission_level,
                )
            except (TypeError, ValueError, KeyError) as exc:
                logger.warning(
                    "ignoring malformed typed permission rule id=%s: %s",
                    rule.id,
                    exc,
                )
                return False
        if not is_relaxing_approval(rule.approval):
            return fnmatch.fnmatch(target, rule.pattern)
        return False


def _is_interactive_transport(source_transport: str | None) -> bool:
    value = getattr(source_transport, "value", source_transport)
    return str(value or "").strip().lower() in _INTERACTIVE_TRANSPORTS


def is_interactive_transport(source_transport: str | None) -> bool:
    """Return true only for explicitly human-present transports."""
    return _is_interactive_transport(source_transport)


def _transport_class(source_transport: str | None) -> str:
    return (
        TransportClass.INTERACTIVE.value
        if _is_interactive_transport(source_transport)
        else TransportClass.UNATTENDED.value
    )


def _rule_scope_matches(
    rule: PermissionRule,
    *,
    transport_class: str,
    session_id: str | None,
    task_id: str | None,
    workspace_id: str | None,
) -> bool:
    if rule.expires_at is not None and rule.expires_at <= time.time():
        return False
    if rule.transport_class not in {TransportClass.ALL.value, transport_class}:
        return False
    if rule.workspace_id and rule.workspace_id != str(workspace_id or ""):
        return False
    if rule.grant_lifetime == GrantLifetime.PROJECT_INTERACTIVE.value:
        return transport_class == TransportClass.INTERACTIVE.value
    if rule.grant_lifetime == GrantLifetime.PROJECT_ALL_TRANSPORTS.value:
        return True
    if rule.grant_lifetime == GrantLifetime.SESSION.value:
        return bool(session_id) and rule.session_id == str(session_id)
    if rule.grant_lifetime == GrantLifetime.TASK.value:
        return bool(task_id) and rule.task_id == str(task_id)
    return False


def normalize_command_target(command: str) -> str:
    """Normalize the first shell segment to a stable command target."""
    segments = split_command_segments(command)
    if not segments:
        return ""
    first = segments[0]
    try:
        parts = shlex.split(first)
    except ValueError:
        return first.strip()
    return " ".join(parts)


def split_command_segments(command: str) -> list[str]:
    """Split a shell command at high-level control operators."""
    separators = {"|", ";", "&"}
    segments: list[str] = []
    current: list[str] = []
    in_single = False
    in_double = False
    index = 0
    while index < len(command):
        char = command[index]
        next_char = command[index + 1] if index + 1 < len(command) else ""
        if char == "'" and not in_double:
            in_single = not in_single
        elif char == '"' and not in_single:
            in_double = not in_double
        if not in_single and not in_double:
            pair = char + next_char
            if pair in {"&&", "||"}:
                _append_segment(segments, current)
                current = []
                index += 2
                continue
            if char in separators:
                _append_segment(segments, current)
                current = []
                index += 1
                continue
        current.append(char)
        index += 1
    _append_segment(segments, current)
    return segments


def _append_segment(segments: list[str], chars: list[str]) -> None:
    segment = "".join(chars).strip()
    if segment:
        segments.append(segment)


def _is_read_only_terminal_call(tool_name: str, params: dict) -> bool:
    from khaos.tools.terminal_tools import is_read_only_argv, is_read_only_command

    if tool_name == "terminal_argv":
        argv = params.get("argv")
        return isinstance(argv, list) and is_read_only_argv(argv)
    return is_read_only_command(_command_text(params))


def _command_text(params: dict) -> str:
    argv = params.get("argv")
    if isinstance(argv, list) and all(isinstance(item, str) for item in argv):
        return shlex.join(argv)
    return str(
        params.get("script") or params.get("command") or params.get("id") or ""
    )


def _matches_required_approval(
    command_text: str, approval_list: frozenset[str]
) -> bool:
    """Return whether any shell segment is covered by policy approval."""
    if not command_text or not approval_list:
        return False
    for raw in split_command_segments(command_text):
        normalized = normalize_command_target(raw)
        if not normalized:
            continue
        for entry in approval_list:
            entry = entry.strip()
            if entry and (
                normalized == entry
                or normalized.startswith(entry + " ")
                or fnmatch.fnmatch(normalized, entry)
            ):
                return True
    return False


__all__ = [
    "PermissionEvaluator",
    "is_interactive_transport",
    "normalize_command_target",
    "split_command_segments",
]
