"""Repository structure indexing for coding mode."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


EXCLUDED_DIRS = {
    ".git",
    ".next",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "target",
    "venv",
}

ENTRY_FILE_NAMES = {
    "app.py",
    "index.ts",
    "index.tsx",
    "main.go",
    "main.py",
    "manage.py",
    "server.py",
}

ENTRY_RELATIVE_PATHS = {
    Path("cmd/gateway/main.go"),
    Path("src/main.rs"),
}

CONFIG_FILE_NAMES = {
    ".eslintrc",
    ".eslintrc.cjs",
    ".eslintrc.js",
    ".eslintrc.json",
    ".gitignore",
    "Cargo.toml",
    "go.mod",
    "package.json",
    "pyproject.toml",
    "tsconfig.json",
}

TEST_DIR_NAMES = {"__tests__", "test", "tests"}


@dataclass
class RepoIndexer:
    """Scan a repository and identify files relevant to coding tasks."""

    max_tree_entries: int = 500
    excluded_dirs: set[str] = field(default_factory=lambda: set(EXCLUDED_DIRS))

    def scan(self, project_root: Path) -> dict[str, Any]:
        """Scan project structure and return a repository index."""
        root = project_root.expanduser().resolve()
        logger.info("Scanning repository: root=%s", root)
        if not root.exists():
            raise FileNotFoundError(f"project root does not exist: {root}")
        if not root.is_dir():
            raise NotADirectoryError(f"project root is not a directory: {root}")

        files: list[Path] = []
        entry_files: list[Path] = []
        config_files: list[Path] = []
        test_dirs: set[Path] = set()
        total_dirs = 0

        for path in sorted(root.rglob("*")):
            if self._is_excluded(path, root):
                continue
            if path.is_dir():
                total_dirs += 1
                if path.name in TEST_DIR_NAMES:
                    test_dirs.add(path)
                continue
            if not path.is_file():
                continue

            files.append(path)
            relative_path = path.relative_to(root)
            if self._is_entry_file(path, relative_path):
                entry_files.append(path)
            if path.name in CONFIG_FILE_NAMES:
                config_files.append(path)
            if path.name.endswith("_test.go"):
                test_dirs.add(path.parent)

        tree = self._build_tree(root, files)
        result = {
            "tree": tree,
            "files": files,
            "entry_files": entry_files,
            "config_files": config_files,
            "test_dirs": sorted(test_dirs),
            "total_files": len(files),
            "total_dirs": total_dirs,
        }
        logger.info(
            "Repository scan complete: files=%d dirs=%d entries=%d configs=%d",
            len(files),
            total_dirs,
            len(entry_files),
            len(config_files),
        )
        return result

    def _is_excluded(self, path: Path, root: Path) -> bool:
        relative_parts = path.relative_to(root).parts
        return any(part in self.excluded_dirs for part in relative_parts)

    def _is_entry_file(self, path: Path, relative_path: Path) -> bool:
        return path.name in ENTRY_FILE_NAMES or relative_path in ENTRY_RELATIVE_PATHS

    def _build_tree(self, root: Path, files: list[Path]) -> str:
        directories = {
            file_path.parent
            for file_path in files
            if file_path.parent != root and not self._is_excluded(file_path.parent, root)
        }
        entries = sorted([root, *directories, *files])
        lines = [f"{root.name}/"]
        visible_count = 0

        for path in entries:
            if path == root:
                continue
            if visible_count >= self.max_tree_entries:
                remaining = len(entries) - visible_count - 1
                if remaining > 0:
                    lines.append(f"... ({remaining} more entries)")
                break
            relative = path.relative_to(root)
            depth = len(relative.parts) - 1
            suffix = "/" if path.is_dir() else ""
            lines.append(f"{'  ' * depth}{path.name}{suffix}")
            visible_count += 1

        return "\n".join(lines)
