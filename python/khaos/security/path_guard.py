"""Path traversal prevention for file tools."""

from __future__ import annotations

import fnmatch
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

PROTECTED_DIRS = frozenset(
    {
        "/etc",
        "/usr",
        "/bin",
        "/sbin",
        "/boot",
        "/dev",
        "/proc",
        "/sys",
        "/lib",
        "/lib64",
        "/private/etc",
        "/System",
        "/Library",
        "/Applications",
    }
)

SENSITIVE_FILES = frozenset(
    {
        "/etc/shadow",
        "/etc/passwd",
        "/etc/sudoers",
        "/etc/ssh/sshd_config",
        "/etc/ssh/ssh_host_*",
        "/.ssh/id_rsa",
        "/.ssh/id_ed25519",
        "/.gnupg/",
        "~/.aws/credentials",
        "~/.config/gcloud/credentials",
    }
)


@dataclass
class PathCheckResult:
    """路径安全检查结果。"""

    safe: bool
    risk_level: str
    reason: str = ""
    normalized_path: str = ""


class PathGuard:
    """防止路径遍历和访问受保护资源。"""

    def __init__(
        self,
        allow_writes_to_home: bool = True,
        project_root: Optional[str] = None,
        extra_protected: frozenset[str] | None = None,
    ):
        self.allow_writes_to_home = allow_writes_to_home
        self.project_root = Path(project_root).expanduser().resolve() if project_root else None
        self._protected = PROTECTED_DIRS | (extra_protected or frozenset())

    def check_read(self, path: str) -> PathCheckResult:
        """检查读取权限。"""
        normalized = self._normalize(path)
        if self._is_sensitive_path(normalized):
            return PathCheckResult(
                safe=False,
                risk_level="sensitive",
                reason="path points to a sensitive file",
                normalized_path=str(normalized),
            )
        if self.project_root is not None and not _is_relative_to(normalized, self.project_root):
            return PathCheckResult(
                safe=False,
                risk_level="protected",
                reason="path escapes the project root",
                normalized_path=str(normalized),
            )
        return PathCheckResult(safe=True, risk_level="safe", normalized_path=str(normalized))

    def check_write(self, path: str) -> PathCheckResult:
        """检查写入权限。"""
        raw_path = Path(path).expanduser()
        normalized = self._normalize(path)
        if self._is_protected_path(normalized):
            return PathCheckResult(
                safe=False,
                risk_level="protected",
                reason="writes to protected system directories are blocked",
                normalized_path=str(normalized),
            )
        if self.project_root is not None and not _is_relative_to(normalized, self.project_root):
            if not self.allow_writes_to_home or not _is_relative_to(normalized, Path.home()):
                return PathCheckResult(
                    safe=False,
                    risk_level="protected",
                    reason="write path escapes the project root",
                    normalized_path=str(normalized),
                )
        if raw_path.is_symlink() and self._is_symlink_escape(raw_path, normalized):
            return PathCheckResult(
                safe=False,
                risk_level="protected",
                reason="symlink points outside the allowed scope",
                normalized_path=str(normalized),
            )
        return PathCheckResult(safe=True, risk_level="safe", normalized_path=str(normalized))

    def _normalize(self, path: str) -> Path:
        """解析路径为绝对路径，处理 ~ 和相对路径。"""
        return Path(path).expanduser().resolve(strict=False)

    def _is_symlink_escape(self, path: Path, target: Path) -> bool:
        """检查符号链接是否指向允许范围外。"""
        if self.project_root is None:
            return False
        try:
            return not _is_relative_to(target.resolve(strict=False), self.project_root)
        except OSError:
            logger.warning("failed to resolve symlink target: %s", path)
            return True

    def _is_protected_path(self, path: Path) -> bool:
        return any(_is_relative_to(path, Path(protected)) for protected in self._protected)

    def _is_sensitive_path(self, path: Path) -> bool:
        path_text = str(path)
        for pattern in SENSITIVE_FILES:
            expanded = os.path.expanduser(pattern)
            candidates = {expanded, os.path.realpath(expanded)}
            if pattern.startswith("/.") and fnmatch.fnmatch(path_text, f"{Path.home()}{pattern}*"):
                return True
            for candidate in candidates:
                if candidate.endswith("/"):
                    if path_text == candidate.rstrip("/") or path_text.startswith(candidate):
                        return True
                elif fnmatch.fnmatch(path_text, candidate):
                    return True
        return False


def _is_relative_to(path: Path, base: Path) -> bool:
    try:
        path.relative_to(base)
    except ValueError:
        return False
    return True
