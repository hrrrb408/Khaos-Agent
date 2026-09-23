"""项目约定文件加载器（对标 Claude Code 的 CLAUDE.md + Codex 的 AGENTS.md）。

支持层级式项目指令文件：

1. KHAOS.md — 项目根目录的全局指令（最高优先级）
2. AGENTS.md — 也可以作为项目指令文件（兼容）
3. 子目录 KHAOS.md / AGENTS.md — 子模块级指令

加载规则：

- 从 project_root 开始向上查找 KHAOS.md 或 AGENTS.md（最多到 home 目录）
- 读取找到的文件内容
- 扫描 project_root 下的子目录，读取第一层的 KHAOS.md / AGENTS.md
- 所有内容合并为一个字符串，子目录的排在根目录的之后
- 去重：如果子目录文件内容已被根目录包含，跳过
"""

from __future__ import annotations

import hashlib
import logging
import os
from collections import OrderedDict
from pathlib import Path

logger = logging.getLogger(__name__)

VALID_NAMES = frozenset({"KHAOS.md", "AGENTS.md", "khaos.md", "agents.md"})
VALID_NAME_ORDER = ("KHAOS.md", "AGENTS.md", "khaos.md", "agents.md")
MAX_INSTRUCTION_BYTES = 128 * 1024

# Directories that never carry meaningful project instructions and may be
# large — skip them during subdirectory scans.
SKIP_DIRS = frozenset({
    ".git",
    "node_modules",
    "__pycache__",
    ".next",
    "target",
    "dist",
    "build",
    "venv",
    ".venv",
    ".idea",
    ".vscode",
    "coverage",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
})

# Sentinel key used in the in-memory cache for the root-level instructions.
_ROOT_KEY = "__root__"


class ProjectContextLoader:
    """加载层级式项目约定文件（KHAOS.md / AGENTS.md）。"""

    def __init__(self, project_root: str | Path | None = None):
        self.project_root = (
            Path(project_root).expanduser().resolve() if project_root else None
        )
        self._cache: dict[str, str] = {}
        self._resolve_cache: OrderedDict[str, str] = OrderedDict()
        self._loaded = False

    def load(self) -> str:
        """加载并返回合并后的项目上下文文本。

        Returns:
            合并后的文本，如果没有找到任何文件则返回空字符串。
        """
        if self._loaded:
            return self._format_cached()
        self._loaded = True

        if self.project_root is None or not self.project_root.is_dir():
            return ""

        # 1. 从 project_root 向上查找根级 KHAOS.md / AGENTS.md
        root_content = self._find_root_context(self.project_root)

        # 2. 扫描 project_root 的直接子目录
        subdir_contents = self._scan_subdirectories(self.project_root, max_depth=1)

        # 3. 缓存并格式化（子目录内容去重，根级总是排第一）
        parts: list[str] = []
        if root_content:
            self._cache[_ROOT_KEY] = root_content
            parts.append(root_content)
        for name, content in subdir_contents:
            if content in parts:  # 去重：内容已被根级或前一个子目录包含
                continue
            self._cache[name] = content
            parts.append(content)

        return "\n\n".join(parts)

    def reload(self) -> str:
        """清除缓存并重新加载。"""
        self._cache.clear()
        self._resolve_cache.clear()
        self._loaded = False
        return self.load()

    def _find_root_context(self, project_root: Path) -> str:
        """从 project_root 向上遍历查找 KHAOS.md / AGENTS.md。

        遍历到 home 目录为止（不含 home 之外）。在每一层，按 VALID_NAMES
        的顺序匹配，命中即返回。同一层只取第一个命中的文件。
        """
        home = Path.home()
        current = project_root
        while True:
            for name in VALID_NAME_ORDER:
                candidate = current / name
                content = self._read_instruction(candidate)
                if content is not None:
                    return content

            # Stop at home (do not read home-level files) or filesystem root.
            if current == home or current == current.parent:
                break
            current = current.parent
        return ""

    def _scan_subdirectories(
        self, project_root: Path, max_depth: int = 1
    ) -> list[tuple[str, str]]:
        """扫描 project_root 下 max_depth 层子目录的项目指令文件。

        每个（子）目录最多读取一个匹配文件。返回 (相对路径, 内容) 列表，
        按路径字典序排序。当前实现仅处理 ``max_depth == 1``。
        """
        del max_depth  # 仅支持 depth=1，保留参数以匹配接口
        results: list[tuple[str, str]] = []
        try:
            entries = sorted(project_root.iterdir(), key=lambda p: p.name)
        except OSError as exc:
            logger.warning("Failed to scan subdirectories: %s", exc)
            return results

        for entry in entries:
            if not entry.is_dir():
                continue
            # 跳过版本控制、构建产物、隐藏目录等。
            if entry.name in SKIP_DIRS or entry.name.startswith("."):
                continue
            for name in VALID_NAME_ORDER:
                candidate = entry / name
                content = self._read_instruction(candidate)
                if content is not None:
                    rel = entry.relative_to(project_root)
                    results.append((str(rel), content))
                    break  # 每个目录只读一个文件

        return results

    def _format_cached(self) -> str:
        """将缓存的内容格式化为一个字符串。"""
        parts: list[str] = []
        if _ROOT_KEY in self._cache:
            parts.append(self._cache[_ROOT_KEY])
        for name, content in self._cache.items():
            if name == _ROOT_KEY:
                continue
            if content in parts:
                continue
            parts.append(content)
        return "\n\n".join(parts)

    def resolve(self, path: str | Path | None = None) -> str:
        """Resolve instructions from the project root to one scoped path.

        ``load()`` intentionally keeps its historical shallow, whole-project
        projection for compatibility.  New context-engine callers use this
        method so only the root-to-target chain is included; sibling module
        instructions never leak into the current step.
        """

        if self.project_root is None or not self.project_root.is_dir():
            return ""
        target = self._safe_target(path)
        if target is None:
            return ""
        root_contexts = self._find_root_context_files(self.project_root)
        root_paths = {candidate for candidate, _ in root_contexts}
        instruction_records = list(root_contexts)
        parts: list[str] = []
        parts.extend(content for _, content in root_contexts)
        try:
            relative = target.relative_to(self.project_root)
        except ValueError:
            return ""
        directories = [self.project_root]
        current = self.project_root
        for component in relative.parts:
            current = current / component
            if current.is_file():
                current = current.parent
                break
            directories.append(current)
        for directory in directories:
            for name in VALID_NAME_ORDER:
                candidate = directory / name
                content = self._read_instruction(candidate)
                if content is None or candidate in root_paths:
                    continue
                instruction_records.append((candidate, content))
                if content in parts:
                    continue
                parts.append(content)
        resolved = "\n\n".join(parts)
        cache_key = self._resolve_cache_key(target, instruction_records)
        cached = self._resolve_cache.get(cache_key)
        if cached is not None:
            self._resolve_cache.move_to_end(cache_key)
            return cached
        self._resolve_cache[cache_key] = resolved
        self._resolve_cache.move_to_end(cache_key)
        while len(self._resolve_cache) > 128:
            self._resolve_cache.popitem(last=False)
        return resolved

    def _resolve_cache_key(
        self,
        target: Path,
        records: list[tuple[Path, str]],
    ) -> str:
        """Bind scoped instruction cache entries to project/path/content."""

        return hashlib.sha256(
            repr(
                (
                    str(self.project_root),
                    str(target),
                    tuple(
                        (str(path), hashlib.sha256(content.encode("utf-8")).hexdigest())
                        for path, content in records
                    ),
                )
            ).encode("utf-8")
        ).hexdigest()

    def _find_root_context_files(self, project_root: Path) -> list[tuple[Path, str]]:
        """Return all supported root instruction files from the nearest scope."""

        home = Path.home()
        current = project_root
        while True:
            matches: list[tuple[Path, str]] = []
            for name in VALID_NAME_ORDER:
                candidate = current / name
                content = self._read_instruction(candidate)
                if content is not None:
                    matches.append((candidate, content))
            if matches:
                return matches
            if current == home or current == current.parent:
                break
            current = current.parent
        return []

    def _safe_target(self, path: str | Path | None) -> Path | None:
        """Resolve a target without allowing symlink/path escape."""

        root_path = self.project_root
        if root_path is None:
            return None
        if path is None:
            return root_path
        candidate = Path(path).expanduser()
        if not candidate.is_absolute():
            candidate = root_path / candidate
        try:
            target = candidate.resolve(strict=False)
            root = root_path.resolve(strict=True)
            if os.path.commonpath((str(root), str(target))) != str(root):
                return None
            return target
        except (OSError, ValueError):
            return None

    @staticmethod
    def _read_instruction(candidate: Path) -> str | None:
        if candidate.name not in VALID_NAMES or candidate.is_symlink() or not candidate.is_file():
            return None
        try:
            size = candidate.stat().st_size
            if size > MAX_INSTRUCTION_BYTES:
                logger.warning("Project instruction exceeds bound: %s", candidate)
                return None
            return candidate.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            logger.warning("Failed to read %s: %s", candidate, exc)
            return None


class InstructionResolver:
    """Small adapter used by Context Engine and direct callers."""

    def __init__(self, loader_or_root: ProjectContextLoader | str | Path | None = None):
        self.loader = (
            loader_or_root
            if isinstance(loader_or_root, ProjectContextLoader)
            else ProjectContextLoader(loader_or_root)
        )

    def resolve(self, path: str | Path | None = None) -> str:
        """Return root-to-target scoped instructions."""

        return self.loader.resolve(path)
