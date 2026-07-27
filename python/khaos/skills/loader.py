"""Load skill files from disk.

Each skill is a single Markdown file. A leading ``---`` fenced block is parsed
as YAML frontmatter; the remainder is the skill body. Files without valid
frontmatter (or missing required ``name``/``description``) are skipped with a
warning rather than aborting the whole scan, mirroring Hermes' tolerant loader.
"""

from __future__ import annotations

import logging
import os
import stat
from pathlib import Path

import yaml

from khaos.skills.skill import Skill, SkillParseError

logger = logging.getLogger(__name__)

# Recognized skill filenames: Hermes convention plus any .md in a skills dir.
_SKILL_FILENAMES = {"SKILL.md", "skill.md"}
_SKILL_SUFFIX = ".md"

_FRONTMATTER_DELIM = "---"
MAX_SKILL_FILES = 128
MAX_SKILL_FILE_BYTES = 1_048_576
MAX_SKILL_FRONTMATTER_BYTES = 65_536
MAX_SKILL_YAML_DEPTH = 16
MAX_SKILL_BODY_CHARS = 500_000
# Batch 9.6 (round-9 §二十): cap the number of CANDIDATE files scanned
# (opened + parsed), not just the number of successfully-loaded skills.
# Without this an attacker can place thousands of invalid YAML / missing-
# field / duplicate-name files that never increment ``len(skills)`` but
# each incur an open + read + parse + YAML compose.  The candidate cap
# stops the scan BEFORE any parse work.
MAX_SKILL_CANDIDATES = MAX_SKILL_FILES * 4  # 512 — tolerance for invalid files
# Batch 10.6 (round-10 §十): cap the number of directory ENTRIES scanned
# per directory (before any skill-file filtering).  Without this a skills
# root with millions of noise files is fully materialised into a list
# before the first yield.  The cap stops the scandir loop early.
MAX_SKILL_DIR_ENTRIES = 4096
# Batch 10.6 (round-10 §十): cap the total number of composed YAML nodes
# traversed during depth checking.  A pathological YAML document can have
# a huge flat structure that is within the depth limit but has millions
# of nodes, consuming CPU.  This budget aborts the traversal early.
MAX_SKILL_YAML_NODES = 10_000


class SkillLoader:
    """Scan directories for skill files and parse them into Skill objects."""

    def __init__(self, roots: list[Path] | None = None):
        self.roots = [Path(root) for root in (roots or [])]

    def load_all(self) -> list[Skill]:
        """Load every parseable skill from all roots.

        Order: roots are scanned in the order given; within a root, files are
        sorted by name for deterministic output. First ``name`` wins on
        collision (shadowing), mirroring Hermes' first-match-wins rule.

        Batch 9.6 (round-9 §二十): the file-count cap now counts
        CANDIDATES (files opened/parsed), not just successfully-loaded
        skills.  Previously an attacker could place thousands of invalid
        YAML / missing-field / duplicate-name files that never incremented
        ``len(skills)`` but each incurred an open + read + parse.  The
        candidate cap (MAX_SKILL_CANDIDATES) stops the scan before any
        parse work on the (N+1)th file.
        """
        seen_names: set[str] = set()
        skills: list[Skill] = []
        candidates_scanned = 0
        for root in self.roots:
            for path in self._iter_skill_files(root):
                candidates_scanned += 1
                if candidates_scanned > MAX_SKILL_CANDIDATES:
                    logger.warning(
                        "skill candidate limit reached (%d scanned, %d "
                        "accepted); remaining files in %s ignored",
                        MAX_SKILL_CANDIDATES, len(skills), root,
                    )
                    return skills
                if len(skills) >= MAX_SKILL_FILES:
                    logger.warning(
                        "skill limit reached (%d); remaining files ignored",
                        MAX_SKILL_FILES,
                    )
                    return skills
                try:
                    skill = self.load_file(path)
                except SkillParseError as exc:
                    logger.warning("skipping skill %s: %s", path, exc)
                    continue
                except OSError as exc:
                    logger.warning("cannot read skill %s: %s", path, exc)
                    continue
                except RecursionError as exc:
                    # Batch 10.6: a cyclic YAML alias graph can blow the
                    # Python recursion limit.  Skip the offending skill
                    # instead of crashing the whole load_all() scan.
                    logger.warning("skipping skill %s: YAML recursion: %s", path, exc)
                    continue
                if skill.name in seen_names:
                    logger.debug("skill %s shadowed by earlier root", skill.name)
                    continue
                seen_names.add(skill.name)
                skills.append(skill)
        return skills

    def load_file(self, path: Path) -> Skill:
        """Parse a single skill file. Raise SkillParseError on invalid input."""
        path = Path(path)
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(path, flags)
        except OSError as exc:
            raise SkillParseError(f"{path}: secure open failed: {exc}") from exc
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise SkillParseError(f"{path}: skill must be a regular file")
            if hasattr(os, "getuid") and info.st_uid != os.getuid():
                raise SkillParseError(f"{path}: skill is not owned by current user")
            if info.st_size > MAX_SKILL_FILE_BYTES:
                raise SkillParseError(
                    f"{path}: skill exceeds {MAX_SKILL_FILE_BYTES} bytes"
                )
            raw = os.read(fd, MAX_SKILL_FILE_BYTES + 1)
        finally:
            os.close(fd)
        if len(raw) > MAX_SKILL_FILE_BYTES:
            raise SkillParseError(f"{path}: skill exceeds size limit")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SkillParseError(f"{path}: skill is not UTF-8") from exc
        frontmatter, body = self._split_frontmatter(text)
        if frontmatter is None:
            raise SkillParseError(f"{path}: missing YAML frontmatter")
        if len(frontmatter.encode("utf-8")) > MAX_SKILL_FRONTMATTER_BYTES:
            raise SkillParseError(f"{path}: YAML frontmatter exceeds size limit")
        try:
            node = yaml.compose(frontmatter, Loader=yaml.SafeLoader)
            if node is not None and _yaml_depth(node) > MAX_SKILL_YAML_DEPTH:
                raise SkillParseError(
                    f"{path}: YAML nesting exceeds {MAX_SKILL_YAML_DEPTH}"
                )
            data = yaml.safe_load(frontmatter)
        except yaml.YAMLError as exc:
            raise SkillParseError(f"{path}: invalid YAML frontmatter: {exc}") from exc
        except RecursionError as exc:
            # Batch 10.6: a cyclic YAML alias graph blows the recursion
            # limit before the depth check can catch it.  Convert to a
            # parse error so load_all() can skip this single skill.
            raise SkillParseError(
                f"{path}: YAML frontmatter has a cyclic alias graph"
            ) from exc
        if not isinstance(data, dict):
            raise SkillParseError(f"{path}: frontmatter must be a mapping")

        name = str(data.get("name", "")).strip()
        description = str(data.get("description", "")).strip()
        if not name:
            raise SkillParseError(f"{path}: missing required field 'name'")
        if not description:
            raise SkillParseError(f"{path}: missing required field 'description'")

        category = str(data.get("category", "general")).strip() or "general"
        raw_triggers = data.get("triggers", []) or []
        if not isinstance(raw_triggers, list):
            raise SkillParseError(f"{path}: 'triggers' must be a list")

        body = body.strip()
        if len(body) > MAX_SKILL_BODY_CHARS:
            raise SkillParseError(f"{path}: skill body exceeds prompt budget")
        return Skill(
            name=name,
            description=description,
            category=category,
            triggers=[str(trigger) for trigger in raw_triggers],
            body=body,
            path=Path(path),
        )

    @staticmethod
    def _split_frontmatter(text: str) -> tuple[str | None, str]:
        """Split leading ``---\\n...\\n---\\n`` from the body.

        Returns ``(frontmatter_text_or_None, body)``. Only a frontmatter block
        that starts on the very first line is recognized.
        """
        stripped = text.lstrip("\ufeff")  # tolerate BOM
        if not stripped.startswith(_FRONTMATTER_DELIM):
            return None, text
        # First line is the opening delimiter.
        newline = stripped.find("\n")
        if newline == -1:
            return None, text
        rest = stripped[newline + 1 :]
        # Find the closing delimiter on its own line.
        close = rest.find(f"\n{_FRONTMATTER_DELIM}")
        if close == -1:
            return None, text
        frontmatter = rest[:close]
        after = rest[close + 1 + len(_FRONTMATTER_DELIM) :]
        # Skip the trailing newline after the closing delim.
        if after.startswith("\n"):
            after = after[1:]
        return frontmatter, after

    @staticmethod
    def _iter_skill_files(root: Path):
        """Yield candidate skill files under ``root`` (non-recursive top level
        plus one level of subdirectories named after the skill).

        Batch 10.6 (round-10 §十): the round-9 fix still collected EVERY
        directory entry into ``top_level`` / ``subdirs`` lists before
        sorting+yielding — a directory with millions of noise files was
        fully materialised.  Now we cap the scandir loop at
        ``MAX_SKILL_DIR_ENTRIES`` per directory: once the budget is
        exhausted we stop scanning and log a warning, so a huge
        directory never gets fully read into memory.  Within the budget
        we still collect + sort for deterministic output order (the
        budget is generous — 4096 entries — so legitimate skills roots
        are unaffected).
        """
        try:
            root_info = root.lstat()
        except OSError:
            return
        if not stat.S_ISDIR(root_info.st_mode) or root.is_symlink():
            return
        if hasattr(os, "getuid") and root_info.st_uid != os.getuid():
            logger.warning("skill root is not owned by current user: %s", root)
            return
        # Top-level skill files — collect up to MAX_SKILL_DIR_ENTRIES,
        # then sort the bounded list for deterministic order.
        top_level: list[Path] = []
        subdirs: list[Path] = []
        entries_scanned = 0
        budget_exceeded = False
        try:
            with os.scandir(root) as entries:
                for entry in entries:
                    entries_scanned += 1
                    if entries_scanned > MAX_SKILL_DIR_ENTRIES:
                        budget_exceeded = True
                        break
                    entry_path = Path(entry.path)
                    if entry.is_file(follow_symlinks=False) and _is_skill_filename(entry_path):
                        top_level.append(entry_path)
                    elif entry.is_dir(follow_symlinks=False):
                        subdirs.append(entry_path)
        except OSError as exc:
            logger.warning("cannot scan skill root %s: %s", root, exc)
            return
        if budget_exceeded:
            logger.warning(
                "skill root %s has more than %d entries; scan truncated "
                "(some skills may be missed)", root, MAX_SKILL_DIR_ENTRIES,
            )
        for path in sorted(top_level, key=lambda p: p.name):
            yield path
        # Subdirectory skills: <root>/<name>/SKILL.md
        for sub in sorted(subdirs, key=lambda p: p.name):
            child_files: list[Path] = []
            child_scanned = 0
            child_budget_exceeded = False
            try:
                with os.scandir(sub) as children:
                    for child in children:
                        child_scanned += 1
                        if child_scanned > MAX_SKILL_DIR_ENTRIES:
                            child_budget_exceeded = True
                            break
                        child_path = Path(child.path)
                        if child.is_file(follow_symlinks=False) and _is_skill_filename(child_path):
                            child_files.append(child_path)
            except OSError as exc:
                logger.debug("cannot scan skill subdir %s: %s", sub, exc)
                continue
            if child_budget_exceeded:
                logger.debug(
                    "skill subdir %s has more than %d entries; truncated",
                    sub, MAX_SKILL_DIR_ENTRIES,
                )
            for child_path in sorted(child_files, key=lambda p: p.name):
                yield child_path


def _yaml_depth(
    node: yaml.Node,
    depth: int = 1,
    visited: set[int] | None = None,
    *,
    node_count: list[int] | None = None,
) -> int:
    """Return maximum composed YAML node depth without constructing data.

    Batch 10.6 (round-10 §十): added cycle detection (``visited`` set of
    ``id(node)``) so a recursive YAML alias graph (``&a [*a]``) returns a
    depth exceeding the limit instead of recursing forever.  Also added
    a total-node-count budget (``node_count``) so a huge flat document
    cannot consume unbounded CPU.
    """
    if visited is None:
        visited = set()
    if node_count is None:
        node_count = [0]
    node_id = id(node)
    if node_id in visited:
        # Cycle detected — report a depth that exceeds any reasonable
        # limit so the caller rejects the document.
        return MAX_SKILL_YAML_DEPTH + 1
    visited.add(node_id)
    node_count[0] += 1
    if node_count[0] > MAX_SKILL_YAML_NODES:
        return MAX_SKILL_YAML_DEPTH + 1
    if isinstance(node, yaml.MappingNode):
        children = [item for pair in node.value for item in pair]
    elif isinstance(node, yaml.SequenceNode):
        children = list(node.value)
    else:
        children = []
    return max(
        [depth, *(_yaml_depth(child, depth + 1, visited, node_count=node_count) for child in children)]
    )


def _is_skill_filename(path: Path) -> bool:
    name = path.name
    if name in _SKILL_FILENAMES:
        return True
    return name.endswith(_SKILL_SUFFIX) and path.parent != Path(".")
