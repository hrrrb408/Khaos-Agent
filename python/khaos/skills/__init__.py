"""Khaos skill system.

A skill is a YAML-frontmatter + Markdown-body file (Hermes SKILL.md compatible)
that augments the agent's system prompt when its declared triggers match the
current scene. See ``skill.py`` for the on-disk format.
"""

from khaos.skills.loader import SkillLoader
from khaos.skills.manager import SkillManager
from khaos.skills.registry import SkillRegistry
from khaos.skills.skill import Skill, SkillParseError

__all__ = [
    "Skill",
    "SkillParseError",
    "SkillRegistry",
    "SkillManager",
    "SkillLoader",
]
