"""Skill data model and on-disk frontmatter contract."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from khaos.exceptions import KhaosError


class SkillParseError(KhaosError):
    """Raised when a skill file cannot be parsed or fails validation."""


class SkillTrustTier(str, Enum):
    """Trust tier of a loaded skill (P2-5).

    * ``BUILTIN``  — shipped with Khaos itself (highest trust).
    * ``USER``     — loaded from the user's ``~/.khaos/skills`` (the OS user
                     owns these; they are trusted guidance).
    * ``PROJECT``  — loaded from the repository's ``<project>/skills``
                     directory.  Repository content is untrusted (a malicious
                     clone can place one), so project skills are rendered in
                     the prompt inside an explicit ``untrusted`` wrapper and
                     cannot elevate capability or change approval policy.
    """

    BUILTIN = "builtin"
    USER = "user"
    PROJECT = "project"


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

    P2-5: ``trust_tier`` records where the skill was loaded from so the prompt
    renderer can mark repository-provided (PROJECT) skills as untrusted.
    """

    name: str
    description: str
    category: str = "general"
    triggers: list[str] = field(default_factory=list)
    body: str = ""
    path: Path | None = None
    enabled: bool = True
    # P2-5: default PROJECT (most restricted) — loaders override to USER for
    # ~/.khaos/skills and BUILTIN for shipped skills.  Prompt rendering wraps
    # PROJECT skills in an explicit untrusted marker.
    trust_tier: SkillTrustTier = SkillTrustTier.PROJECT
    # M8.7 extension metadata.  These fields remain descriptive: a skill is
    # declarative prompt guidance and can never load Python or grant a tool.
    version: str = "1"
    skill_id: str = ""
    package_digest: str = ""
    required_tools: tuple[str, ...] = ()
    optional_tools: tuple[str, ...] = ()
    applicable_paths: tuple[str, ...] = ()
    applicable_languages: tuple[str, ...] = ()

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
        if not isinstance(self.version, str) or not self.version or len(self.version) > 128:
            raise SkillParseError(f"skill {self.name}: version is invalid")
        if not self.skill_id:
            self.skill_id = self.name
        if not isinstance(self.skill_id, str) or not self.skill_id or len(self.skill_id) > 256:
            raise SkillParseError(f"skill {self.name}: skill_id is invalid")
        if self.package_digest and (
            len(self.package_digest) != 64
            or any(char not in "0123456789abcdef" for char in self.package_digest)
        ):
            raise SkillParseError(f"skill {self.name}: package_digest is invalid")
        for label in ("required_tools", "optional_tools", "applicable_paths", "applicable_languages"):
            values = getattr(self, label)
            if not isinstance(values, (list, tuple)):
                raise SkillParseError(f"skill {self.name}: {label} must be a list")
            normalized_values = tuple(sorted({str(value).strip() for value in values if str(value).strip()}))
            if len(normalized_values) > 64 or any(len(value) > 512 for value in normalized_values):
                raise SkillParseError(f"skill {self.name}: {label} exceeds its bound")
            setattr(self, label, normalized_values)
