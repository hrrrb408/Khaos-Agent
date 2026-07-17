"""Permission rules, target normalization, and audit logging."""

from __future__ import annotations

import fnmatch
import json
import os
import shlex
from dataclasses import dataclass
from enum import Enum
from typing import Optional
from urllib.parse import urlparse


class ApprovalMode(Enum):
    """Supported permission approval policies."""

    AUTO_APPROVE = "auto-approve"
    SUGGEST = "suggest"
    ASK_EVERY = "ask-every"
    DENY = "deny"


@dataclass
class PermissionRule:
    """Persistent permission rule."""

    id: Optional[int]
    pattern: str
    permission_level: str
    approval: ApprovalMode
    mode: str
    granted_at: float = 0.0


@dataclass
class PermissionDecision:
    """Result of checking a tool call against permission rules."""

    approved: ApprovalMode
    reason: str
    target: str
    matched_rule: Optional[PermissionRule] = None
    requires_user_confirm: bool = False


class PermissionEngine:
    """Rule matching and audit logging for tool calls."""

    def __init__(
        self,
        db,
        default_mode: ApprovalMode = ApprovalMode.ASK_EVERY,
        *,
        commands_require_approval: "frozenset[str] | None" = None,
    ):
        self.db = db
        self._default_mode = default_mode
        self._rules: list[PermissionRule] = []
        # H3: policy-level command approval list.  Checked BEFORE persistent
        # rules so an auto-approve rule can never bypass a policy that
        # requires explicit confirmation for a command.
        self._commands_require_approval = commands_require_approval or frozenset()

    async def load_rules(self) -> None:
        """Load persisted rules from SQLite."""
        rows = await self.db.list_permission_rules()
        self._rules = [
            PermissionRule(
                id=int(row["id"]),
                pattern=str(row["pattern"]),
                permission_level=str(row["permission_level"]),
                approval=ApprovalMode(str(row["approval"])),
                mode=str(row["mode"]),
                granted_at=float(row["granted_at"] or 0),
            )
            for row in rows
        ]

    async def check(
        self,
        tool_name: str,
        params: dict,
        permission_level: str,
        mode: str,
    ) -> PermissionDecision:
        """Check whether a tool call is approved, denied, or needs confirmation."""
        target = self.normalize_target(tool_name, params)
        # H4: policy-level required-approval list runs BEFORE every other
        # shortcut, including the read-only terminal shortcut.  Otherwise a
        # command classified as read-only (cat / grep / ls / rg / head /
        # tail …) would be AUTO_APPROVE'd even when the effective policy
        # explicitly requires confirmation for it, contradicting the
        # "policy approval requirement covers automatic approval" contract.
        # H3 (preserved): this also runs before the persistent-rule loop, so
        # a remembered auto-approve rule cannot bypass a command the
        # effective policy demands confirmation for.
        if self._commands_require_approval and tool_name in {"terminal", "process"}:
            command_text = str(params.get("command") or params.get("id") or "")
            if _matches_required_approval(command_text, self._commands_require_approval):
                return PermissionDecision(
                    approved=ApprovalMode.ASK_EVERY,
                    reason=f"Policy requires approval for command: {target}",
                    target=target,
                    requires_user_confirm=True,
                )
        if tool_name == "terminal" and _is_read_only_terminal_call(params):
            return PermissionDecision(
                approved=ApprovalMode.AUTO_APPROVE,
                reason="Read-only terminal command",
                target=target,
                requires_user_confirm=False,
            )
        for rule in self._rules:
            if rule.mode != "all" and rule.mode != mode:
                continue
            if rule.permission_level != permission_level:
                continue
            if fnmatch.fnmatch(target, rule.pattern):
                return PermissionDecision(
                    approved=rule.approval,
                    reason=f"Matched rule: {rule.pattern}",
                    target=target,
                    matched_rule=rule,
                    requires_user_confirm=rule.approval == ApprovalMode.ASK_EVERY,
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

    async def grant_rule(self, rule: PermissionRule) -> PermissionRule:
        """Persist and cache a permission rule."""
        rule_id = await self.db.insert_permission_rule(
            rule.pattern,
            rule.permission_level,
            rule.approval.value,
            rule.mode,
        )
        persisted = PermissionRule(
            id=rule_id,
            pattern=rule.pattern,
            permission_level=rule.permission_level,
            approval=rule.approval,
            mode=rule.mode,
            granted_at=rule.granted_at,
        )
        self._rules.insert(0, persisted)
        return persisted

    async def revoke_rule(self, rule_id: int) -> None:
        """Remove a permission rule from storage and cache."""
        await self.db.delete_permission_rule(rule_id)
        self._rules = [rule for rule in self._rules if rule.id != rule_id]

    async def audit(
        self,
        tool_name: str,
        target: str,
        result: str,
        detail: dict | None = None,
        session_id: str | None = None,
        risk_level: str = "safe",
    ) -> None:
        """Write a tool permission/execution audit log.

        ``risk_level`` (new, optional) tags the severity of the audited
        decision (e.g. ``"safe"``, ``"risky"``, ``"blocked"``). Existing
        callers that omit it keep the historical ``"safe"`` default.
        """
        enriched = dict(detail or {})
        if risk_level and "risk_level" not in enriched:
            enriched["risk_level"] = risk_level
        await self.db.insert_audit_log(
            action=tool_name,
            target=target,
            result=result,
            detail=json.dumps(enriched, ensure_ascii=False),
            session_id=session_id,
        )

    def normalize_target(self, tool_name: str, params: dict) -> str:
        """Normalize a file path, command, URL, or generic call target."""
        if tool_name in {"read_file", "write_file", "patch", "search_files"}:
            path = params.get("path") or params.get("root") or params.get("query") or "."
            return os.path.realpath(os.path.normpath(str(path)))
        if tool_name in {"terminal", "process"}:
            command = str(params.get("command") or params.get("id") or "")
            return normalize_command_target(command)
        if "url" in params:
            parsed = urlparse(str(params["url"]))
            return f"{parsed.scheme}://{parsed.netloc}"
        return f"{tool_name}:{json.dumps(params, sort_keys=True)}"

    def _match_pattern(self, pattern: str, target: str) -> bool:
        """Match a normalized target with a glob pattern."""
        return fnmatch.fnmatch(target, pattern)


def normalize_command_target(command: str) -> str:
    """Normalize a command into base command plus arguments."""
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
    """Split a shell command at high-level shell control operators."""
    separators = {"|", ";", "&"}
    segments: list[str] = []
    current: list[str] = []
    in_single = False
    in_double = False
    i = 0
    while i < len(command):
        char = command[i]
        nxt = command[i + 1] if i + 1 < len(command) else ""
        if char == "'" and not in_double:
            in_single = not in_single
        elif char == '"' and not in_single:
            in_double = not in_double
        if not in_single and not in_double:
            two = char + nxt
            if two in {"&&", "||"}:
                _append_segment(segments, current)
                current = []
                i += 2
                continue
            if char in separators:
                _append_segment(segments, current)
                current = []
                i += 1
                continue
        current.append(char)
        i += 1
    _append_segment(segments, current)
    return segments


def _append_segment(segments: list[str], chars: list[str]) -> None:
    segment = "".join(chars).strip()
    if segment:
        segments.append(segment)


def _is_read_only_terminal_call(params: dict) -> bool:
    from khaos.tools.terminal_tools import is_read_only_command

    return is_read_only_command(str(params.get("command") or ""))


def _matches_required_approval(command_text: str, approval_list: "frozenset[str]") -> bool:
    """Whether any segment of ``command_text`` triggers required approval.

    Each shell segment is normalized to ``base_cmd args`` and matched against
    the approval list.  An entry matches when the normalized segment equals it
    (e.g. ``rm``), starts with it followed by a space (e.g. ``git push origin``
    matches ``git push``), or matches it via fnmatch.  Every segment of a
    pipeline/chain is checked so ``ls; rm x`` is caught.
    """
    if not command_text or not approval_list:
        return False
    segments = split_command_segments(command_text)
    for raw in segments:
        normalized = normalize_command_target(raw)
        if not normalized:
            continue
        for entry in approval_list:
            entry = entry.strip()
            if not entry:
                continue
            if (
                normalized == entry
                or normalized.startswith(entry + " ")
                or fnmatch.fnmatch(normalized, entry)
            ):
                return True
    return False
