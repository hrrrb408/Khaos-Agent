"""Scene-aware skill matching and prompt formatting."""

from __future__ import annotations

import logging
from pathlib import Path

from khaos.skills.loader import SkillLoader
from khaos.skills.registry import SkillRegistry
from khaos.skills.skill import Skill

logger = logging.getLogger(__name__)

# Default cap on the number of skills injected per turn, to keep the system
# prompt bounded. Higher-confidence / more-trigger matches sort first.
DEFAULT_MATCH_LIMIT = 5


class SkillManager:
    """Match enabled skills against the current mode + user message.

    Matching is keyword-based (case-insensitive substring). A skill matches when
    any of its ``triggers`` appears in the lowercased ``user_text``. Skills with
    no triggers never auto-match; they must be manually enabled via
    ``/skills load <name>`` and are then always injected (forced skills).

    Manually loaded (forced) skills are always returned by ``match`` regardless
    of triggers, sorted after trigger-matched ones.
    """

    def __init__(
        self,
        registry: SkillRegistry | None = None,
        match_limit: int = DEFAULT_MATCH_LIMIT,
    ):
        self.registry = registry or SkillRegistry()
        self.match_limit = match_limit
        # Names explicitly loaded by the user; always injected.
        self._forced: set[str] = set()

    def load_from_dir(self, root: Path | str) -> list[Skill]:
        """Load every skill from ``root`` into the registry.

        Re-registering an existing name is skipped (so calling this with
        multiple roots accumulates rather than crashes). Returns the newly
        loaded skills.
        """
        loader = SkillLoader([Path(root)])
        loaded: list[Skill] = []
        for skill in loader.load_all():
            if skill.name in self.registry:
                logger.debug("skill %s already registered, skipping", skill.name)
                continue
            self.registry.register(skill)
            loaded.append(skill)
        return loaded

    def match(self, mode: str, user_text: str) -> list[Skill]:
        """Return skills active for this turn, best matches first.

        Order: forced (manually loaded) skills first, then trigger-matched
        skills by number of trigger hits descending, capped at match_limit.
        Disabled skills are never returned.
        """
        haystack = (user_text or "").lower()
        mode_value = (mode or "").lower()

        forced = [
            self.registry.get(name)
            for name in self._forced
            if name in self.registry and self.registry.get(name).enabled
        ]

        scored: list[tuple[int, Skill]] = []
        for skill in self.registry.list(only_enabled=True):
            if skill.name in self._forced:
                continue
            hits = self._count_hits(skill, haystack, mode_value)
            if hits > 0:
                scored.append((hits, skill))

        # Sort by hit count desc, then name for stable ordering.
        scored.sort(key=lambda item: (-item[0], item[1].name))
        matched = [skill for _, skill in scored]

        combined = forced + matched
        return combined[: self.match_limit]

    def format_for_prompt(self, skills: list[Skill]) -> str:
        """Render matched skill bodies as a system-prompt section.

        Returns an empty string when no skills are supplied so callers can
        unconditionally concatenate the result.
        """
        if not skills:
            return ""
        blocks: list[str] = []
        for skill in skills:
            header = f"# Skill: {skill.name}"
            if skill.description:
                header += f"\n# {skill.description}"
            body = skill.body.strip()
            blocks.append(f"{header}\n\n{body}" if body else header)
        return "# Active skills\n\n" + "\n\n---\n\n".join(blocks)

    # --- manual load / unload (CLI) ----------------------------------------

    def load(self, name: str) -> bool:
        """Mark a skill as forced (always injected). Returns True if applied.

        Returns False if the skill is unknown.
        """
        if name not in self.registry:
            return False
        self._forced.add(name)
        self.registry.enable(name)
        return True

    def unload(self, name: str) -> bool:
        """Remove a skill from the forced set. Returns True if it was forced."""
        if name in self._forced:
            self._forced.discard(name)
            return True
        return False

    @property
    def forced(self) -> list[str]:
        """Names of manually loaded skills, sorted."""
        return sorted(self._forced)

    # --- internal ----------------------------------------------------------

    @staticmethod
    def _count_hits(skill: Skill, haystack: str, mode_value: str) -> int:
        """Count trigger keywords present in the lowercased user text.

        Category match contributes a small bonus so a skill whose category
        equals the current mode is slightly preferred in ties.
        """
        hits = 0
        for trigger in skill.triggers:
            if trigger and trigger in haystack:
                hits += 1
        if mode_value and skill.category and skill.category.lower() == mode_value:
            hits += 1
        return hits
