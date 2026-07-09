"""Capability-based sandbox enforcement.

Unlike ``command_guard`` (a *detection* layer that inspects command text),
the sandbox is a *constraint* layer: it wraps tool execution so that even if
detection misses something, an operation cannot exceed the capability set of
the active sandbox mode.

Four modes mirror ``khaos_policy.yaml``'s ``sandbox.mode``:

* ``read-only``       — read tools only; no writes, no terminal.
* ``workspace-write`` — reads + writes confined to the workspace + terminal.
* ``full-access``     — every tool allowed (empty set = allow-all).
* ``yolo``            — allow-all AND skip all other security checks.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

logger = logging.getLogger(__name__)


class SandboxMode(Enum):
    """沙箱模式，对应 khaos_policy.yaml 的 sandbox.mode。"""

    READ_ONLY = "read-only"
    WORKSPACE_WRITE = "workspace-write"
    FULL_ACCESS = "full-access"
    YOLO = "yolo"


# 每个 sandbox 模式的 capability 集合。
#
# ``FULL_ACCESS`` deliberately maps to an *empty* set: ``check_tool`` treats an
# empty capability set as "no restriction", so every tool passes. This is the
# documented contract — do not "fix" it by listing all tools.
CAPABILITIES: dict[SandboxMode, set[str]] = {
    SandboxMode.READ_ONLY: {
        "read_file",
        "search_files",
        "list_directory",
        "tree_view",
        "file_info",
        "git_status",
        "git_log",
        "git_diff",
        "git_branch",
        "test_run",  # 测试只读
    },
    SandboxMode.WORKSPACE_WRITE: {
        "read_file",
        "search_files",
        "list_directory",
        "tree_view",
        "file_info",
        "git_status",
        "git_log",
        "git_diff",
        "git_branch",
        "test_run",
        "terminal",
        "process",
        "write_file",
        "patch",
        "multi_edit",
        "copy_file",
        "move_file",
        "git_commit",
        "git_smart_commit",
        "git_undo",
        "git_create_branch",
        "git_push",
        "git_pr_body",
        "spawn_subagent",
        "collect_results",
        "execute_plan",
        "subagent_status",
        "browser_navigate",
        "browser_snapshot",
        "browser_click",
        "browser_type",
        "browser_press",
    },
    SandboxMode.FULL_ACCESS: {
        # Empty set = allow-all (see check_tool).
    },
    SandboxMode.YOLO: {
        # Empty set = allow-all; yolo also bypasses other security checks.
    },
}


@dataclass
class SandboxCheckResult:
    """沙箱检查结果。"""

    allowed: bool
    reason: str = ""
    mode: str = ""


class Sandbox:
    """全局沙箱执行约束。"""

    def __init__(
        self,
        mode: SandboxMode = SandboxMode.WORKSPACE_WRITE,
        workspace_root: Path | None = None,
    ):
        self.mode = mode
        self.workspace_root = (
            workspace_root.expanduser().resolve()
            if workspace_root
            else Path.cwd().resolve()
        )
        self._allowed_tools = CAPABILITIES.get(mode, set())

    def check_tool(self, tool_name: str) -> SandboxCheckResult:
        """检查工具是否在当前沙箱模式的 capability 集合内。

        An empty capability set (FULL_ACCESS / YOLO) means "allow all".
        """
        if self.mode == SandboxMode.YOLO:
            return SandboxCheckResult(allowed=True, mode=self.mode.value)

        # Empty set → allow all (FULL_ACCESS). Non-empty → membership check.
        if not self._allowed_tools or tool_name in self._allowed_tools:
            return SandboxCheckResult(allowed=True, mode=self.mode.value)

        return SandboxCheckResult(
            allowed=False,
            reason=f"tool '{tool_name}' not allowed in {self.mode.value} mode",
            mode=self.mode.value,
        )

    def check_write_path(self, path: str) -> SandboxCheckResult:
        """检查写入路径是否在 workspace 内（workspace-write 模式）。"""
        if self.mode in (SandboxMode.FULL_ACCESS, SandboxMode.YOLO):
            return SandboxCheckResult(allowed=True, mode=self.mode.value)

        if self.mode == SandboxMode.READ_ONLY:
            return SandboxCheckResult(
                allowed=False,
                reason=f"write not allowed in {self.mode.value} mode",
                mode=self.mode.value,
            )

        # workspace-write: 只允许写 workspace 内
        resolved = Path(path).expanduser().resolve()
        try:
            resolved.relative_to(self.workspace_root)
            return SandboxCheckResult(allowed=True, mode=self.mode.value)
        except ValueError:
            return SandboxCheckResult(
                allowed=False,
                reason=f"path '{resolved}' outside workspace '{self.workspace_root}'",
                mode=self.mode.value,
            )

    @classmethod
    def from_policy_mode(
        cls, mode_str: str, workspace_root: Path | None = None
    ) -> "Sandbox":
        """从策略字符串构建沙箱。未知模式回退到 workspace-write。"""
        try:
            mode = SandboxMode(mode_str)
        except ValueError:
            logger.warning(
                "Unknown sandbox mode '%s', falling back to workspace-write",
                mode_str,
            )
            mode = SandboxMode.WORKSPACE_WRITE
        return cls(mode=mode, workspace_root=workspace_root)
