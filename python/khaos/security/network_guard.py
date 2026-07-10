"""Network access control based on sandbox policy.

When the policy disables network access (the default), this guard inspects
tool calls that would touch the network — ``terminal`` running curl/wget,
``browser_navigate``, or any tool carrying a ``url`` — and blocks them unless
the destination domain is on the allowlist.

The guard is intentionally conservative: when in doubt about whether a command
reaches the network it blocks, matching Codex's "deny by default" stance.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# 命令中的网络相关关键词
NETWORK_COMMAND_KEYWORDS = frozenset(
    {
        "curl",
        "wget",
        "nc",
        "ncat",
        "telnet",
        "ssh",
        "scp",
        "rsync",
        "ping",
        "traceroute",
        "nslookup",
        "dig",
        "ftp",
        "python",
        "python3",
        "node",
        "npm",
        "pip",
        "cargo",
        "docker",
        "podman",
        "kubectl",
        "git",  # git push/pull/fetch/clone 涉及网络
    }
)

NETWORK_GIT_SUBCOMMANDS = frozenset({"push", "pull", "fetch", "clone", "remote", "ls-remote"})


@dataclass
class NetworkCheckResult:
    """网络访问检查结果。"""

    allowed: bool
    reason: str = ""
    domain: str = ""


class NetworkGuard:
    """根据策略检查工具调用是否涉及网络访问。"""

    def __init__(
        self,
        network_enabled: bool = False,
        allowed_domains: list[str] | None = None,
        blocked_domains: list[str] | None = None,
    ):
        self.network_enabled = network_enabled
        self._allowed = set(allowed_domains or [])
        self._blocked = set(blocked_domains or [])

    def check_tool(self, tool_name: str, arguments: dict) -> NetworkCheckResult:
        """检查工具调用是否涉及网络访问。

        规则：
        - network_enabled=True → 全部放行
        - network_enabled=False → 默认拦截网络工具，除非匹配 allowed_domains
        """
        if self.network_enabled:
            return NetworkCheckResult(allowed=True)

        if tool_name.startswith("github_"):
            return NetworkCheckResult(
                allowed=False,
                reason="GitHub network access disabled by policy",
                domain="github.com",
            )

        if tool_name == "terminal":
            return self._check_terminal_command(arguments.get("command", ""))

        if tool_name == "browser_navigate":
            return self._check_url(arguments.get("url", ""))

        if "url" in arguments:
            return self._check_url(str(arguments["url"]))

        return NetworkCheckResult(allowed=True, reason="not a network tool")

    def _check_terminal_command(self, command: str) -> NetworkCheckResult:
        """检查终端命令是否涉及网络。"""
        base = self._base_command(command)
        if base not in NETWORK_COMMAND_KEYWORDS:
            return NetworkCheckResult(allowed=True, reason="not a network command")

        # git 特殊处理：只在网络子命令时拦截
        if base == "git":
            parts = command.split()
            if len(parts) >= 2 and parts[1] in NETWORK_GIT_SUBCOMMANDS:
                return NetworkCheckResult(
                    allowed=False,
                    reason=f"network git command: git {parts[1]}",
                )
            # git add/commit/diff/log 等本地操作放行
            return NetworkCheckResult(allowed=True, reason="local git command")

        # curl/wget: 检查域名是否在白名单
        domain = self._extract_domain(command)
        if domain:
            if self._is_domain_allowed(domain):
                return NetworkCheckResult(
                    allowed=True,
                    reason=f"domain {domain} in allowlist",
                    domain=domain,
                )
            return NetworkCheckResult(
                allowed=False,
                reason=f"network access blocked: {base} to {domain}",
                domain=domain,
            )

        return NetworkCheckResult(
            allowed=False,
            reason=f"network command blocked: {base}",
        )

    def _check_url(self, url: str) -> NetworkCheckResult:
        """检查 URL 访问。"""
        if not url:
            return NetworkCheckResult(allowed=True, reason="empty url")

        domain = self._extract_domain(url)
        if domain:
            if self._is_domain_allowed(domain):
                return NetworkCheckResult(
                    allowed=True,
                    reason=f"domain {domain} in allowlist",
                    domain=domain,
                )
            return NetworkCheckResult(
                allowed=False,
                reason=f"network access blocked to {domain}",
                domain=domain,
            )

        return NetworkCheckResult(
            allowed=False,
            reason="network access blocked",
        )

    def _is_domain_allowed(self, domain: str) -> bool:
        """检查域名是否在白名单中（支持子域名通配）。

        优先级：blocked > allowed。即一个域名同时匹配两者时按 blocked 处理。
        有白名单时，未命中的域名一律拦截（deny-by-default）。无白名单且
        网络关闭时，所有域名都被拦截（返回 False）。
        """
        for blocked in self._blocked:
            if domain == blocked or domain.endswith(f".{blocked}"):
                return False
        for allowed in self._allowed:
            if domain == allowed or domain.endswith(f".{allowed}"):
                return True
        # 有白名单则未命中→拦截；无白名单且网络关闭也拦截。
        return False

    def _extract_domain(self, text: str) -> str:
        """从命令或 URL 中提取域名。"""
        # 尝试解析为 URL
        url_match = re.search(r"https?://([^\s/:\"'`]+)", text)
        if url_match:
            return url_match.group(1)
        return ""

    def _base_command(self, command: str) -> str:
        parts = command.strip().split()
        return parts[0] if parts else ""
