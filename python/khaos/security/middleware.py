"""Security middleware that wraps tool execution with safety checks.

Orchestrates CommandGuard, PathGuard, SecretScanner into a unified
pre-execution / post-execution pipeline that ToolScheduler calls.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from khaos.security.command_guard import CommandGuard
from khaos.security.path_guard import PathGuard
from khaos.security.secret_scanner import ScanResult, SecretScanner

logger = logging.getLogger(__name__)

COMMAND_TOOLS = frozenset({"terminal", "process"})
READ_PATH_TOOLS = frozenset({"read_file", "search_files", "file_info", "list_directory", "tree_view"})
WRITE_PATH_TOOLS = frozenset({"write_file", "patch", "multi_edit", "copy_file", "move_file"})
WRITE_PATH_PARAMS = frozenset({"path", "file_path", "src", "dst"})


@dataclass
class SecurityCheckResult:
    """统一安全检查结果。"""

    allowed: bool
    risk_level: str
    reason: str = ""
    check_type: str = ""
    original_result: Any = None


class SecurityMiddleware:
    """工具执行的安全中间件。"""

    def __init__(
        self,
        command_guard: CommandGuard | None = None,
        path_guard: PathGuard | None = None,
        secret_scanner: SecretScanner | None = None,
        enabled: bool = True,
    ):
        self.command_guard = command_guard or CommandGuard()
        self.path_guard = path_guard or PathGuard()
        self.secret_scanner = secret_scanner or SecretScanner()
        self.enabled = enabled

    async def pre_check(self, tool_name: str, arguments: dict) -> SecurityCheckResult:
        """工具执行前的安全检查。"""
        if not self.enabled:
            return SecurityCheckResult(allowed=True, risk_level="safe")

        if tool_name in COMMAND_TOOLS:
            command = str(arguments.get("command", ""))
            if command:
                result = self.command_guard.check(command)
                if result.risk_level in {"dangerous", "blocked"}:
                    return SecurityCheckResult(
                        allowed=False,
                        risk_level=result.risk_level,
                        reason=result.reason,
                        check_type="command",
                        original_result=result,
                    )
                if result.risk_level == "risky":
                    logger.warning("Risky command: %s - %s", command, result.reason)

        if tool_name in WRITE_PATH_TOOLS:
            for param in WRITE_PATH_PARAMS:
                path = arguments.get(param, "")
                if path:
                    result = self.path_guard.check_write(str(path))
                    if not result.safe:
                        return SecurityCheckResult(
                            allowed=False,
                            risk_level=result.risk_level,
                            reason=result.reason,
                            check_type="path_write",
                            original_result=result,
                        )

        if tool_name in READ_PATH_TOOLS:
            path = str(arguments.get("path", "") or arguments.get("root", ""))
            if path:
                result = self.path_guard.check_read(path)
                if not result.safe:
                    return SecurityCheckResult(
                        allowed=False,
                        risk_level=result.risk_level,
                        reason=result.reason,
                        check_type="path_read",
                        original_result=result,
                    )

        return SecurityCheckResult(allowed=True, risk_level="safe")

    async def post_check(self, tool_name: str, output: Any) -> ScanResult:
        """工具执行后的敏感信息扫描。"""
        if not self.enabled or self.secret_scanner is None:
            return ScanResult(has_secrets=False)

        text = ""
        if isinstance(output, str):
            text = output
        elif isinstance(output, dict):
            text = str(output)
        return self.secret_scanner.scan_text(text)
