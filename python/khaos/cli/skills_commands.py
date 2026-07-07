"""``/skills`` slash-command handling.

Implemented as a pure function over a SkillManager so it can be unit-tested
without a running REPL. Returns a human-readable string for the REPL to print.
"""

from __future__ import annotations

from dataclasses import dataclass

from khaos.skills import SkillManager


@dataclass
class SkillCommandResult:
    """Outcome of a /skills command."""

    handled: bool
    message: str

    def __str__(self) -> str:
        return self.message


def handle_skills_command(line: str, manager: SkillManager) -> SkillCommandResult:
    """Parse and execute a ``/skills ...`` command line.

    Supported forms:
      /skills                  -> list all skills
      /skills list             -> list all skills
      /skills load <name>      -> force-load a skill
      /skills unload <name>    -> remove a skill from the forced set

    Returns ``handled=False`` for any non-/skills input so the caller can fall
    through to normal message handling.
    """
    stripped = line.strip()
    if not stripped.startswith("/skills"):
        return SkillCommandResult(handled=False, message="")
    # Accept "/skills" and "/skillsX" boundary precisely.
    if stripped != "/skills" and not stripped.startswith("/skills "):
        return SkillCommandResult(handled=False, message="")

    parts = stripped.split()
    # parts[0] == "/skills"
    if len(parts) == 1 or parts[1] == "list":
        return SkillCommandResult(handled=True, message=_format_list(manager))

    sub = parts[1]
    if sub == "load" and len(parts) >= 3:
        name = parts[2]
        if manager.load(name):
            return SkillCommandResult(handled=True, message=f"loaded skill: {name}")
        return SkillCommandResult(handled=True, message=f"unknown skill: {name}")

    if sub == "unload" and len(parts) >= 3:
        name = parts[2]
        if manager.unload(name):
            return SkillCommandResult(handled=True, message=f"unloaded skill: {name}")
        return SkillCommandResult(
            handled=True, message=f"skill not loaded: {name}"
        )

    return SkillCommandResult(
        handled=True, message="usage: /skills [list|load <name>|unload <name>]"
    )


def _format_list(manager: SkillManager) -> str:
    skills = manager.registry.list()
    if not skills:
        return "no skills registered"
    forced = set(manager.forced)
    lines = ["skills:"]
    for skill in skills:
        flag = "*" if skill.name in forced else " "
        state = "on" if skill.enabled else "off"
        lines.append(f"  {flag} {skill.name} [{skill.category}] ({state})")
    return "\n".join(lines)
