"""Context collection for coding mode."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from khaos.agent.core import SimpleTokenEngine
from khaos.coding.indexer import CONFIG_FILE_NAMES, RepoIndexer
from khaos.coding.parser import CodeParser, build_dependency_graph

logger = logging.getLogger(__name__)


SOURCE_SUFFIXES = {
    ".go",
    ".js",
    ".jsx",
    ".md",
    ".py",
    ".rs",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".yaml",
    ".yml",
}

TOKEN_BUDGET = 60000
PATH_MATCH_SCORE = 50
IMPORT_MATCH_SCORE = 25
TEST_SCORE = 15
CONFIG_SCORE = 10
DEFAULT_SCORE = 1
# Files that import, or are imported by, a target file. Boosted because a
# change to a target can ripple through its dependency neighbourhood.
DEPENDENCY_MATCH_SCORE = 30


@dataclass
class CodingContextBuilder:
    """Build a compact file context for a coding task."""

    token_budget: int = TOKEN_BUDGET
    token_engine: SimpleTokenEngine = field(default_factory=SimpleTokenEngine)
    indexer: RepoIndexer = field(default_factory=RepoIndexer)
    parser: CodeParser = field(default_factory=CodeParser)
    # Cached dependency graph keyed by ``project_root``. Rebuilt only when the
    # root changes, so repeated ``build()`` calls reuse the same analysis.
    _dependency_graph: dict[Path, set[Path]] | None = field(default=None, repr=False)
    _dependency_graph_root: Path | None = field(default=None, repr=False)

    def build(
        self,
        task_description: str,
        project_root: Path,
        target_files: list[Path] | None,
    ) -> list[dict[str, Any]]:
        """Collect relevant file contents for a coding task."""
        root = project_root.expanduser().resolve()
        index = self.indexer.scan(root)
        files = [path for path in index["files"] if self._is_text_candidate(path)]
        target_set = self._normalize_targets(root, target_files or [])
        keywords = self._extract_keywords(task_description)
        imports_by_file = {
            path: self.parser.parse_imports(path)
            for path in files
            if path.suffix == ".py"
        }
        dependency_graph = self._get_dependency_graph(root, files)

        scored_files: list[tuple[int, int, Path, str]] = []
        for path in files:
            score, relevance = self._score_file(
                path,
                root,
                keywords,
                target_set,
                imports_by_file,
                dependency_graph,
            )
            if score <= 0:
                continue
            scored_files.append((score, self._priority_bucket(path, target_set), path, relevance))

        scored_files.sort(key=lambda item: (-item[1], -item[0], str(item[2])))
        context: list[dict[str, Any]] = []
        used_tokens = 0

        for score, _bucket, path, relevance in scored_files:
            try:
                content = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as exc:
                logger.warning("Skipping unreadable context file: path=%s error=%s", path, exc)
                continue

            token_count = self.token_engine.count_tokens(content)
            if token_count == 0:
                continue
            if used_tokens + token_count > self.token_budget and path not in target_set:
                logger.debug(
                    "Skipping file over token budget: path=%s tokens=%d",
                    path,
                    token_count,
                )
                continue
            if used_tokens + token_count > self.token_budget and context:
                break

            used_tokens += token_count
            context.append(
                {
                    "path": path,
                    "content": content,
                    "relevance": relevance if relevance else f"score:{score}",
                }
            )

        logger.info(
            "Built coding context: files=%d tokens=%d budget=%d",
            len(context),
            used_tokens,
            self.token_budget,
        )
        return context

    def _normalize_targets(self, root: Path, target_files: list[Path]) -> set[Path]:
        targets: set[Path] = set()
        for file_path in target_files:
            path = file_path.expanduser()
            if not path.is_absolute():
                path = root / path
            targets.add(path.resolve())
        return targets

    def _extract_keywords(self, task_description: str) -> set[str]:
        words = {
            word.lower()
            for word in re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,}", task_description)
        }
        return {word for word in words if word not in {"and", "for", "the", "with"}}

    def _score_file(
        self,
        path: Path,
        root: Path,
        keywords: set[str],
        target_set: set[Path],
        imports_by_file: dict[Path, list[str]],
        dependency_graph: dict[Path, set[Path]] | None = None,
    ) -> tuple[int, str]:
        reasons: list[str] = []
        score = 0

        if path in target_set:
            return 1000, "target_file"

        relative_text = str(path.relative_to(root)).lower()
        matched_keywords = sorted(keyword for keyword in keywords if keyword in relative_text)
        if matched_keywords:
            score += PATH_MATCH_SCORE * len(matched_keywords)
            reasons.append(f"path_keywords:{','.join(matched_keywords)}")

        imported_targets = self._matching_import_targets(path, root, target_set, imports_by_file)
        if imported_targets:
            score += IMPORT_MATCH_SCORE * len(imported_targets)
            reasons.append(f"imports:{','.join(imported_targets)}")

        # Dependency-graph boost: files that import a target (callers, who may
        # break when the target's interface changes) or are imported by a
        # target (dependencies, whose behaviour the target relies on) are both
        # relevant to a change in the target.
        if dependency_graph and target_set:
            dep_reason = self._dependency_match_reason(path, dependency_graph, target_set)
            if dep_reason:
                score += DEPENDENCY_MATCH_SCORE
                reasons.append(dep_reason)

        if self._is_test_file(path):
            score += TEST_SCORE
            reasons.append("test")

        if path.name in CONFIG_FILE_NAMES:
            score += CONFIG_SCORE
            reasons.append("config")

        if (
            not keywords
            and not target_set
            and (path.name in CONFIG_FILE_NAMES or self._is_test_file(path))
        ):
            score += DEFAULT_SCORE
            reasons.append("default")

        return score, ";".join(reasons)

    def _get_dependency_graph(
        self, root: Path, files: list[Path]
    ) -> dict[Path, set[Path]]:
        """Return the cached dependency graph, rebuilding it if the root moved.

        The graph is computed once per project root and reused across
        ``build()`` calls; only a root change triggers a rebuild.
        """
        if self._dependency_graph is None or self._dependency_graph_root != root:
            self._dependency_graph = build_dependency_graph(root, files)
            self._dependency_graph_root = root
            logger.debug(
                "rebuilt dependency graph: %d files under %s",
                len(self._dependency_graph),
                root,
            )
        return self._dependency_graph

    @staticmethod
    def _dependency_match_reason(
        path: Path,
        dependency_graph: dict[Path, set[Path]],
        target_set: set[Path],
    ) -> str:
        """Return a relevance tag if ``path`` is in a target's dependency hood."""
        imports = dependency_graph.get(path, set())
        # path imports a target → caller side.
        if imports & target_set:
            return "imports_target"
        # a target imports path → dependency side.
        for target in target_set:
            if path in dependency_graph.get(target, set()):
                return "imported_by_target"
        return ""

    def _matching_import_targets(
        self,
        path: Path,
        root: Path,
        target_set: set[Path],
        imports_by_file: dict[Path, list[str]],
    ) -> list[str]:
        if path.suffix != ".py" or not target_set:
            return []
        imports = imports_by_file.get(path, [])
        target_modules = {
            self._module_name(root, target)
            for target in target_set
            if target.suffix == ".py"
        }
        return sorted(
            target_module
            for target_module in target_modules
            if target_module
            and any(
                target_module.endswith(import_name)
                or import_name.endswith(target_module)
                for import_name in imports
            )
        )

    def _module_name(self, root: Path, file_path: Path) -> str:
        try:
            relative = file_path.relative_to(root).with_suffix("")
        except ValueError:
            return ""
        parts = [part for part in relative.parts if part != "__init__"]
        return ".".join(parts)

    def _priority_bucket(self, path: Path, target_set: set[Path]) -> int:
        if path in target_set:
            return 4
        if path.name in CONFIG_FILE_NAMES:
            return 1
        if self._is_test_file(path):
            return 2
        return 3

    def _is_test_file(self, path: Path) -> bool:
        parts = set(path.parts)
        return (
            bool({"tests", "test", "__tests__"} & parts)
            or path.name.endswith("_test.go")
            or path.name.startswith("test_")
        )

    def _is_text_candidate(self, path: Path) -> bool:
        return path.suffix in SOURCE_SUFFIXES or path.name in CONFIG_FILE_NAMES
