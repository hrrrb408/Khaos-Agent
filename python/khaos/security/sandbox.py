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
        "file_search_content",
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
        "file_search_content",
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
        "github_create_pr",
        "github_read_issue",
        "github_comment_issue",
        "github_request_review",
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
        *,
        root_capabilities: "set[Path] | frozenset[Path] | None" = None,
    ):
        self.mode = mode
        self.workspace_root = (
            workspace_root.expanduser().resolve()
            if workspace_root
            else Path.cwd().resolve()
        )
        self._allowed_tools = CAPABILITIES.get(mode, set())
        # B2: distinguish ``None`` (not set → confine to workspace_root, the
        # legacy default) from an empty frozenset (explicitly no path is
        # allowed → deny all).  Previously an empty set was treated as
        # "no restriction", which fail-opened when ``allowed_paths: []`` or
        # ``allowed_paths: [../outside]`` compiled to an empty set.
        if root_capabilities is None:
            self._root_capabilities: "frozenset[Path] | None" = None
        else:
            self._root_capabilities = frozenset(root_capabilities)

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
        candidate = Path(path).expanduser()
        if not candidate.is_absolute():
            candidate = self.workspace_root / candidate
        resolved = candidate.resolve()
        try:
            resolved.relative_to(self.workspace_root)
        except ValueError:
            return SandboxCheckResult(
                allowed=False,
                reason=f"path '{resolved}' outside workspace '{self.workspace_root}'",
                mode=self.mode.value,
            )
        # B2: when root_capabilities are compiled from allowed_paths, confine
        # writes to those capabilities.  ``None`` = not set (legacy: confine
        # to workspace_root only).  An empty frozenset = explicitly no path
        # allowed → deny all (fail closed, not fail open).
        if self._root_capabilities is not None:
            denied_reason = self._capability_denial_reason(resolved, "write")
            if denied_reason is not None:
                return SandboxCheckResult(
                    allowed=False, reason=denied_reason, mode=self.mode.value
                )
        return SandboxCheckResult(allowed=True, mode=self.mode.value)

    def check_read_path(self, path: str) -> SandboxCheckResult:
        """Constrain default reads to the fixed Workspace root.

        External files are deliberately not inferred from an approval or a
        path string.  A future user-selected file capability must be passed as
        a separate, one-shot authority; until then external reads fail closed.
        """
        if self.mode in (SandboxMode.FULL_ACCESS, SandboxMode.YOLO):
            return SandboxCheckResult(allowed=True, mode=self.mode.value)

        candidate = Path(path).expanduser()
        if not candidate.is_absolute():
            candidate = self.workspace_root / candidate
        resolved = candidate.resolve()
        try:
            resolved.relative_to(self.workspace_root)
        except ValueError:
            return SandboxCheckResult(
                allowed=False,
                reason=(
                    f"read path '{resolved}' outside workspace "
                    f"'{self.workspace_root}'"
                ),
                mode=self.mode.value,
            )
        # B2: confine reads to compiled root_capabilities when present.
        # ``None`` = not set (legacy: workspace_root only).  Empty frozenset
        # = deny all reads (fail closed).
        if self._root_capabilities is not None:
            denied_reason = self._capability_denial_reason(resolved, "read")
            if denied_reason is not None:
                return SandboxCheckResult(
                    allowed=False, reason=denied_reason, mode=self.mode.value
                )
        return SandboxCheckResult(allowed=True, mode=self.mode.value)

    def _capability_denial_reason(
        self, resolved: Path, op: str
    ) -> str | None:
        """Return a denial reason if ``resolved`` is outside all capabilities.

        A capability is a directory; a path under any capability is allowed.
        Returns ``None`` when the path is permitted.
        """
        for capability in self._root_capabilities:
            try:
                resolved.relative_to(capability)
                return None
            except ValueError:
                continue
        return (
            f"{op} path '{resolved}' outside allowed_paths capabilities "
            f"({', '.join(sorted(str(c) for c in self._root_capabilities))})"
        )

    @classmethod
    def from_policy_mode(
        cls, mode_str: str, workspace_root: Path | None = None
    ) -> "Sandbox":
        """Build a sandbox from a policy mode string.

        H3: an unknown mode now fails closed (raises ``ValueError``) instead
        of silently degrading to the more-permissive ``workspace-write``.  A
        typo in ``khaos_policy.yaml``'s ``sandbox.mode`` must surface at
        startup, not grant unintended write/terminal access.
        """
        try:
            mode = SandboxMode(mode_str)
        except ValueError as exc:
            valid = [m.value for m in SandboxMode]
            raise ValueError(
                f"Unknown sandbox mode '{mode_str}'; expected one of {valid}"
            ) from exc
        return cls(mode=mode, workspace_root=workspace_root)
