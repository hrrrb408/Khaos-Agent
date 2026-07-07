"""Load skill files from disk.

Each skill is a single Markdown file. A leading ``---`` fenced block is parsed
as YAML frontmatter; the remainder is the skill body. Files without valid
frontmatter (or missing required ``name``/``description``) are skipped with a
warning rather than aborting the whole scan, mirroring Hermes' tolerant loader.
"""

from __future__ import annotations

import logging
from pathlib import Path

import yaml

from khaos.skills.skill import Skill, SkillParseError

logger = logging.getLogger(__name__)

# Recognized skill filenames: Hermes convention plus any .md in a skills dir.
_SKILL_FILENAMES = {"SKILL.md", "skill.md"}
_SKILL_SUFFIX = ".md"

_FRONTMATTER_DELIM = "---"


class SkillLoader:
    """Scan directories for skill files and parse them into Skill objects."""

    def __init__(self, roots: list[Path] | None = None):
        self.roots = [Path(root) for root in (roots or [])]

    def load_all(self) -> list[Skill]:
        """Load every parseable skill from all roots.

        Order: roots are scanned in the order given; within a root, files are
        sorted by name for deterministic output. First ``name`` wins on
        collision (shadowing), mirroring Hermes' first-match-wins rule.
        """
        seen_names: set[str] = set()
        skills: list[Skill] = []
        for root in self.roots:
            for path in sorted(self._iter_skill_files(root)):
                try:
                    skill = self.load_file(path)
                except SkillParseError as exc:
                    logger.warning("skipping skill %s: %s", path, exc)
                    continue
                except OSError as exc:
                    logger.warning("cannot read skill %s: %s", path, exc)
                    continue
                if skill.name in seen_names:
                    logger.debug("skill %s shadowed by earlier root", skill.name)
                    continue
                seen_names.add(skill.name)
                skills.append(skill)
        return skills

    def load_file(self, path: Path) -> Skill:
        """Parse a single skill file. Raise SkillParseError on invalid input."""
        text = Path(path).read_text(encoding="utf-8")
        frontmatter, body = self._split_frontmatter(text)
        if frontmatter is None:
            raise SkillParseError(f"{path}: missing YAML frontmatter")
        try:
            data = yaml.safe_load(frontmatter)
        except yaml.YAMLError as exc:
            raise SkillParseError(f"{path}: invalid YAML frontmatter: {exc}") from exc
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

        return Skill(
            name=name,
            description=description,
            category=category,
            triggers=[str(trigger) for trigger in raw_triggers],
            body=body.strip(),
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
        plus one level of subdirectories named after the skill)."""
        if not root.exists() or not root.is_dir():
            return
        # Top-level skill files.
        for entry in sorted(root.iterdir()):
            if entry.is_file() and _is_skill_filename(entry):
                yield entry
            elif entry.is_dir():
                # Subdirectory skill: <root>/<name>/SKILL.md
                for child in sorted(entry.iterdir()):
                    if child.is_file() and _is_skill_filename(child):
                        yield child


def _is_skill_filename(path: Path) -> bool:
    name = path.name
    if name in _SKILL_FILENAMES:
        return True
    return name.endswith(_SKILL_SUFFIX) and path.parent != Path(".")
