"""Skill data model and on-disk frontmatter contract."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from khaos.exceptions import KhaosError


class SkillParseError(KhaosError):
    """Raised when a skill file cannot be parsed or fails validation."""

    pass


@dataclass
class Skill:
    """One loaded skill.

    On-disk format (Hermes SKILL.md compatible, extended with Khaos triggers)::

        ---
        name: python-expert            # required, kebab-case
        description: Python expert.    # required, <=1024 chars
        category: coding               # optional, default "general"
        triggers: [python, pip]        # optional, keyword list; default []
        ---
        Markdown body...

    A skill without ``triggers`` never auto-matches and must be loaded manually
    via ``/skills load <name>``. The body is injected verbatim into the system
    prompt when the skill is active.
    """

    name: str
    description: str
    category: str = "general"
    triggers: list[str] = field(default_factory=list)
    body: str = ""
    path: Optional[Path] = None
    enabled: bool = True

    def __post_init__(self) -> None:
        if not self.name:
            raise SkillParseError("skill name is required")
        if not self.description:
            raise SkillParseError(f"skill {self.name}: description is required")
        if len(self.description) > 1024:
            raise SkillParseError(
                f"skill {self.name}: description exceeds 1024 characters"
            )
        # Normalize triggers to plain strings, deduplicated, lowercased for
        # case-insensitive matching downstream.
        seen: set[str] = set()
        normalized: list[str] = []
        for trigger in self.triggers:
            value = str(trigger).strip().lower()
            if value and value not in seen:
                seen.add(value)
                normalized.append(value)
        self.triggers = normalized
