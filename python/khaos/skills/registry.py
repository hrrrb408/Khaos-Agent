"""In-memory skill registry: register, list, enable/disable."""

from __future__ import annotations

from khaos.skills.skill import Skill, SkillParseError


class SkillRegistry:
    """Registry holding loaded skills keyed by name.

    The registry is a flat dict by ``name``; category views are computed on
    demand. Enable/disable is a runtime concern (does not unload the skill),
    so a disabled skill is still listed but excluded from matching.
    """

    def __init__(self, skills: list[Skill] | None = None):
        self._skills: dict[str, Skill] = {}
        for skill in skills or []:
            self.register(skill)

    def register(self, skill: Skill) -> None:
        """Register a skill. Re-registering an existing name raises."""
        if skill.name in self._skills:
            raise SkillParseError(f"skill already registered: {skill.name}")
        self._skills[skill.name] = skill

    def unregister(self, name: str) -> Skill:
        """Remove and return a registered skill. Raise if absent."""
        try:
            return self._skills.pop(name)
        except KeyError as exc:
            raise SkillParseError(f"skill not found: {name}") from exc

    def get(self, name: str) -> Skill:
        """Return a registered skill by name. Raise if absent."""
        try:
            return self._skills[name]
        except KeyError as exc:
            raise SkillParseError(f"skill not found: {name}") from exc

    def list(self, category: str | None = None, only_enabled: bool = False) -> list[Skill]:
        """List skills, optionally filtered by category and enabled state.

        Returned sorted by name for deterministic output.
        """
        skills = list(self._skills.values())
        if category is not None:
            skills = [skill for skill in skills if skill.category == category]
        if only_enabled:
            skills = [skill for skill in skills if skill.enabled]
        return sorted(skills, key=lambda skill: skill.name)

    def categories(self) -> list[str]:
        """Return distinct category names, sorted."""
        return sorted({skill.category for skill in self._skills.values()})

    def enable(self, name: str) -> None:
        """Enable a skill."""
        self.get(name).enabled = True

    def disable(self, name: str) -> None:
        """Disable a skill (excluded from matching but still listed)."""
        self.get(name).enabled = False

    def __len__(self) -> int:
        return len(self._skills)

    def __contains__(self, name: object) -> bool:
        return name in self._skills
