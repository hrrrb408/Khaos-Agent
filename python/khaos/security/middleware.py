"""Security middleware that wraps tool execution with safety checks.

Orchestrates CommandGuard, PathGuard, SecretScanner into a unified
pre-execution / post-execution pipeline that ToolScheduler calls.

When a :class:`SandboxPolicy` is supplied, its lists are merged into the
existing guards so behaviour stays backward-compatible: policy-denied paths
extend PathGuard's protected set, policy-blocked commands extend
CommandGuard's blocked set, and ``secrets_scan_on_output`` gates the
post-execution secret scan.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from khaos.security.command_guard import CommandGuard
from khaos.security.path_guard import PathGuard
from khaos.security.secret_scanner import ScanResult, SecretScanner

if TYPE_CHECKING:
    from khaos.audit.logger import AuditLogger
    from khaos.security.network_guard import NetworkGuard
    from khaos.security.policy import SandboxPolicy
    from khaos.security.sandbox import Sandbox

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
        policy: "SandboxPolicy | None" = None,
        sandbox: "Sandbox | None" = None,
        network_guard: "NetworkGuard | None" = None,
        audit_logger: "AuditLogger | None" = None,
    ):
        self.command_guard = command_guard or CommandGuard()
        self.path_guard = path_guard or PathGuard()
        self.secret_scanner = secret_scanner or SecretScanner()
        self.enabled = enabled
        self.policy = policy
        self.sandbox = sandbox
        self.network_guard = network_guard
        self.audit_logger = audit_logger
        # secrets_scan_on_output: when a policy is present, defer to it so a
        # user can disable output scanning in trusted setups.
        self._scan_on_output = (
            policy.secrets_scan_on_output if policy is not None else True
        )
        # Merge policy lists into the existing guards so the detection layer
        # also enforces the policy's extra denials (defense in depth).
        if policy is not None:
            self._apply_policy(policy)

    def _apply_policy(self, policy: "SandboxPolicy") -> None:
        """Merge policy lists into the existing guards (additive, instance-level)."""
        # Extend PathGuard's protected set with policy-denied paths.
        if policy.denied_paths:
            extra = frozenset(
                str(path)
                for path in policy.denied_paths
                if path and path != "."
            )
            if extra:
                existing = getattr(self.path_guard, "_protected", frozenset())
                self.path_guard._protected = existing | extra
        # Extend CommandGuard's blocked commands with policy-blocked ones.
        # Done instance-level (extra_blocked) — never mutates the module
        # global, so one middleware's policy can't leak into another guard.
        if policy.commands_blocked:
            self.command_guard = CommandGuard(
                block_dangerous=self.command_guard.block_dangerous,
                confirm_risky=self.command_guard.confirm_risky,
                allowed_commands=self.command_guard._allowed_commands,
                extra_blocked=frozenset(policy.commands_blocked),
            )

    async def pre_check(self, tool_name: str, arguments: dict) -> SecurityCheckResult:
        """工具执行前的安全检查。

        检查顺序（优先级从高到低）：
        sandbox capability → network → command → path write → path read。

        当任何检查拦截时，若有 ``audit_logger``，自动记录一条安全事件。
        """
        result = self._run_checks(tool_name, arguments)
        # Record security events for blocks, so denials are queryable/exportable.
        if not result.allowed and self.audit_logger is not None:
            try:
                await self.audit_logger.log_security_event(
                    event_type=result.check_type or "blocked",
                    tool_name=tool_name,
                    reason=result.reason,
                    detail={
                        "risk_level": result.risk_level,
                        "arguments_keys": list(arguments.keys()),
                    },
                )
            except Exception as exc:  # noqa: BLE001 — audit must never block enforcement
                logger.warning("security event audit failed: %s", exc)
        return result

    def _run_checks(self, tool_name: str, arguments: dict) -> SecurityCheckResult:
        """Run the actual check pipeline (no side effects)."""
        if not self.enabled:
            return SecurityCheckResult(allowed=True, risk_level="safe")

        # 沙箱 capability 检查（优先级最高）
        if self.sandbox is not None:
            sandbox_result = self.sandbox.check_tool(tool_name)
            if not sandbox_result.allowed:
                return SecurityCheckResult(
                    allowed=False,
                    risk_level="blocked",
                    reason=sandbox_result.reason,
                    check_type="sandbox",
                )

        # 网络访问检查
        if self.network_guard is not None:
            net_result = self.network_guard.check_tool(tool_name, arguments)
            if not net_result.allowed:
                return SecurityCheckResult(
                    allowed=False,
                    risk_level="blocked",
                    reason=net_result.reason,
                    check_type="network",
                )

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
        if not self.enabled or not self._scan_on_output or self.secret_scanner is None:
            return ScanResult(has_secrets=False)

        text = ""
        if isinstance(output, str):
            text = output
        elif isinstance(output, dict):
            text = str(output)
        return self.secret_scanner.scan_text(text)
