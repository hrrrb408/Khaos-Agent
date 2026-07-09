"""Load and apply sandbox policy from YAML configuration.

The policy file (``khaos_policy.yaml``) is the single user-editable source of
truth for Khaos's permission boundary: sandbox mode, network access, allowed /
denied paths, command approval lists, secret-scan toggles, and audit settings.

When no policy file is found — or a file fails to parse — a safe default
policy (``workspace-write``, network off) is returned. A bad file never blocks
Khaos from starting.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

DEFAULT_POLICY_PATHS = [
    Path("khaos_policy.yaml"),
    Path("~/.khaos/policy.yaml"),
]

# Defaults mirror the template in khaos_policy.yaml so that a missing file and
# an empty file behave identically.
_DEFAULT_DENIED_PATHS = [
    "~/.ssh",
    "~/.aws",
    "~/.gnupg",
    "~/.config/gcloud",
    "/etc/shadow",
    "/etc/passwd",
    "/etc/sudoers",
]

_DEFAULT_REQUIRE_APPROVAL = [
    "git push",
    "rm",
    "curl",
    "wget",
    "docker",
    "npm publish",
    "pip install",
    "cargo publish",
]


@dataclass
class SandboxPolicy:
    """Global sandbox policy loaded from YAML."""

    # sandbox 模式: "workspace-write" | "read-only" | "full-access" | "yolo"
    mode: str = "workspace-write"

    # 网络控制
    network_enabled: bool = False
    network_allowed_domains: list[str] = field(default_factory=list)
    network_blocked_domains: list[str] = field(default_factory=list)

    # 文件系统控制
    allowed_paths: list[str] = field(default_factory=lambda: ["."])
    denied_paths: list[str] = field(default_factory=lambda: list(_DEFAULT_DENIED_PATHS))

    # 命令控制
    commands_allowed: list[str] = field(default_factory=list)
    commands_require_approval: list[str] = field(
        default_factory=lambda: list(_DEFAULT_REQUIRE_APPROVAL)
    )
    commands_blocked: list[str] = field(default_factory=list)

    # 敏感信息扫描
    secrets_scan_on_output: bool = True
    secrets_scan_before_tool_result: bool = True
    secrets_block_env_dump: bool = True

    # 审计
    audit_enabled: bool = True
    audit_log_path: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SandboxPolicy":
        """从字典构建策略，未知字段忽略。"""
        if not isinstance(data, dict):
            return cls()
        sandbox = data.get("sandbox", {}) or {}
        commands = data.get("commands", {}) or {}
        secrets = data.get("secrets", {}) or {}
        audit = data.get("audit", {}) or {}

        return cls(
            mode=sandbox.get("mode", "workspace-write"),
            network_enabled=sandbox.get("network", False),
            network_allowed_domains=sandbox.get("allowed_domains", []),
            network_blocked_domains=sandbox.get("blocked_domains", []),
            allowed_paths=sandbox.get("allowed_paths", ["."]),
            denied_paths=sandbox.get("denied_paths", list(_DEFAULT_DENIED_PATHS)),
            commands_allowed=commands.get("allow", []),
            commands_require_approval=commands.get(
                "require_approval", list(_DEFAULT_REQUIRE_APPROVAL)
            ),
            commands_blocked=commands.get("block", []),
            secrets_scan_on_output=secrets.get("scan_on_output", True),
            secrets_scan_before_tool_result=secrets.get(
                "scan_before_tool_result", True
            ),
            secrets_block_env_dump=secrets.get("block_env_dump", True),
            audit_enabled=audit.get("enabled", True),
            audit_log_path=audit.get("log_path"),
        )


def load_policy(path: Path | None = None) -> SandboxPolicy:
    """从文件加载策略。如果 path 为 None，按优先级搜索默认路径。

    优先级：显式指定路径 > 项目根 khaos_policy.yaml > ~/.khaos/policy.yaml > 默认值。

    Any read/parse error falls back to the default policy rather than raising,
    so a malformed policy file never prevents Khaos from starting.
    """
    candidates: list[Path] = [path] if path else DEFAULT_POLICY_PATHS
    for candidate in candidates:
        if candidate is None:
            continue
        try:
            resolved = candidate.expanduser().resolve()
        except (OSError, RuntimeError) as exc:
            logger.warning("cannot resolve policy path %s: %s", candidate, exc)
            continue
        if not resolved.is_file():
            continue
        try:
            logger.info("Loading sandbox policy from %s", resolved)
            with open(resolved, encoding="utf-8") as handle:
                data = yaml.safe_load(handle) or {}
            return SandboxPolicy.from_dict(data if isinstance(data, dict) else {})
        except (OSError, yaml.YAMLError) as exc:
            # Malformed YAML must not crash startup — fall back to defaults.
            logger.warning(
                "Failed to parse policy %s (%s); using default policy",
                resolved,
                exc,
            )
            return SandboxPolicy()
    logger.info("No policy file found, using defaults")
    return SandboxPolicy()
