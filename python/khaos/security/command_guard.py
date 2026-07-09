"""Command injection prevention for terminal tools."""

from __future__ import annotations

import logging
import re
import shlex
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

DANGEROUS_COMMANDS = frozenset(
    {
        "rm -rf /",
        "rm -rf /*",
        "mkfs",
        "dd if=",
        ":(){ :|:& };:",
        "chmod 777",
        "chown root",
        "> /dev/sd",
        "> /dev/null",
        "wget ",
        "curl -o /etc/",
        "nc -l",
        "ncat -l",
    }
)

BLOCKED_COMMANDS = frozenset(
    {
        "sudo",
        "su ",
        "passwd",
        "visudo",
        "chroot",
        "iptables",
        "nft",
        "ufw",
        "mkfs.",
        "fdisk",
        "parted",
        "mount",
        "shutdown",
        "reboot",
        "halt",
        "poweroff",
        "systemctl",
        "service",
        "crontab",
        "at ",
        "useradd",
        "userdel",
        "usermod",
        "groupadd",
        "groupdel",
        "insmod",
        "modprobe",
        "env",
        "printenv",
    }
)

ALLOWED_SUDO_PREFIXES = frozenset(
    {
        "apt-get",
        "apt",
        "pip",
        "pip3",
        "npm",
        "yarn",
        "cargo",
        "docker",
        "podman",
        "kubectl",
        "brew",
        "port",
        "gem",
    }
)

RISKY_PATTERNS = re.compile(
    r"(?:rm\s+-|DROP\s+TABLE|DROP\s+DATABASE|DELETE\s+FROM|TRUNCATE\s+TABLE"
    r"|git\s+push\s+--force|git\s+reset\s+--hard|DROP\s+SCHEMA"
    r"|ALTER\s+TABLE.*DROP|INSERT\s+INTO.*SELECT"
    r"|os\.environ|getenv|ENV\[)",
    re.IGNORECASE,
)


@dataclass
class CommandCheckResult:
    """命令安全检查结果。"""

    safe: bool
    risk_level: str
    reason: str = ""
    matched_pattern: str = ""


class CommandGuard:
    """检测和防止命令注入。"""

    def __init__(
        self,
        block_dangerous: bool = True,
        confirm_risky: bool = True,
        allowed_commands: frozenset[str] | None = None,
    ):
        self.block_dangerous = block_dangerous
        self.confirm_risky = confirm_risky
        self._allowed_commands = allowed_commands

    def check(self, command: str) -> CommandCheckResult:
        """检查命令是否安全。"""
        stripped = command.strip()
        if not stripped:
            return CommandCheckResult(safe=True, risk_level="safe", reason="empty command")

        if self._allowed_commands is not None and not self._is_base_command_allowed(stripped):
            return CommandCheckResult(
                safe=False,
                risk_level="blocked",
                reason="base command is not in the allowlist",
                matched_pattern=_base_command(stripped),
            )

        blocked = _blocked_command_match(stripped)
        if blocked is not None:
            return CommandCheckResult(
                safe=False,
                risk_level="blocked",
                reason=f"blocked command: {blocked}",
                matched_pattern=blocked,
            )

        lowered = stripped.lower()
        for pattern in DANGEROUS_COMMANDS:
            if pattern.lower() in lowered:
                return CommandCheckResult(
                    safe=not self.block_dangerous,
                    risk_level="dangerous",
                    reason=f"dangerous command pattern: {pattern}",
                    matched_pattern=pattern,
                )

        injection = self._check_for_injection(stripped)
        if injection is not None:
            return injection

        match = RISKY_PATTERNS.search(stripped)
        if match is not None:
            return CommandCheckResult(
                safe=True,
                risk_level="risky",
                reason="risky command requires confirmation",
                matched_pattern=match.group(0),
            )

        return CommandCheckResult(safe=True, risk_level="safe", reason="no risk detected")

    def _check_for_injection(self, command: str) -> CommandCheckResult | None:
        """检测命令注入模式（管道/操作符后的危险命令）。"""
        for segment in _split_shell_segments(command):
            if not segment.strip():
                continue
            blocked = _blocked_command_match(segment)
            if blocked is not None:
                return CommandCheckResult(
                    safe=False,
                    risk_level="blocked",
                    reason=f"possible shell injection via blocked command: {blocked}",
                    matched_pattern=blocked,
                )
            lowered = segment.lower()
            for pattern in DANGEROUS_COMMANDS:
                if pattern.lower() in lowered:
                    return CommandCheckResult(
                        safe=False,
                        risk_level="dangerous",
                        reason=f"possible shell injection via dangerous pattern: {pattern}",
                        matched_pattern=pattern,
                    )
        return None

    def _is_base_command_allowed(self, command: str) -> bool:
        """检查基础命令是否在白名单中。"""
        base = _base_command(command)
        return bool(base and base in self._allowed_commands)


def _blocked_command_match(command: str) -> str | None:
    base = _base_command(command)
    if not base:
        return None
    parts = _split_words(command)
    if base == "sudo":
        if len(parts) > 1 and Path(parts[1]).name in ALLOWED_SUDO_PREFIXES:
            return None
        return "sudo"
    if base == "su":
        return "su"
    if base == "at":
        return "at"
    for pattern in BLOCKED_COMMANDS:
        normalized = pattern.strip()
        if normalized.endswith("."):
            if base.startswith(normalized):
                return pattern
        elif base == normalized:
            return pattern
    return None


def _base_command(command: str) -> str:
    parts = _split_words(command)
    if not parts:
        return ""
    return Path(parts[0]).name


def _split_words(command: str) -> list[str]:
    try:
        return shlex.split(command)
    except ValueError:
        return command.strip().split()


def _split_shell_segments(command: str) -> list[str]:
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
            if two in {"&&", "||", "$("}:
                _append_segment(segments, current)
                current = []
                i += 2
                continue
            if char in {"|", ";", "`", ")"}:
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
