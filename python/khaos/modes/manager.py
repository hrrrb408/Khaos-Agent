"""Office/coding mode management."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional


class Mode(Enum):
    """Supported Khaos interaction modes."""

    OFFICE = "office"
    CODING = "coding"


@dataclass(frozen=True)
class ModeConfig:
    """Static configuration for a mode."""

    mode: Mode
    system_prompt_file: str
    allowed_tools: list[str]
    preferred_model_function: str
    interaction_style: str


MODE_CONFIGS = {
    Mode.OFFICE: ModeConfig(
        mode=Mode.OFFICE,
        system_prompt_file="prompts/office.md",
        allowed_tools=["all"],
        preferred_model_function="agent_loop",
        interaction_style="conversational",
    ),
    Mode.CODING: ModeConfig(
        mode=Mode.CODING,
        system_prompt_file="prompts/coding.md",
        allowed_tools=[
            "read_file",
            "write_file",
            "patch",
            "multi_edit",
            "search_files",
            "terminal",
            "process",
            "sandbox_exec",
            "sandbox_build",
            "todo_read",
            "todo_write",
            "todo_update",
            "test_run",
            "git_status",
            "git_smart_commit",
            "git_undo",
        ],
        preferred_model_function="coding",
        interaction_style="autonomous",
    ),
}


class ModeManager:
    """Mode switch manager backed by user_config."""

    def __init__(self, db, project_root: Path | None = None):
        self.db = db
        self.project_root = project_root or Path.cwd()
        self._current_mode = Mode.OFFICE
        self._intent_buffer = ""

    @property
    def current_mode(self) -> Mode:
        """Return the active mode."""
        return self._current_mode

    @property
    def mode_config(self) -> ModeConfig:
        """Return active mode configuration."""
        return MODE_CONFIGS[self._current_mode]

    async def load(self) -> Mode:
        """Load current mode from persisted user configuration."""
        value = await self.db.get_config("current_mode", Mode.OFFICE.value)
        self._current_mode = Mode(value)
        return self._current_mode

    async def switch(self, target_mode: Mode, intent_context: str = "") -> Mode:
        """Switch mode and persist the user's current preference."""
        self._intent_buffer = intent_context
        self._current_mode = target_mode
        await self.db.set_config("current_mode", target_mode.value)
        return self._current_mode

    async def detect_and_suggest(self, user_input: str) -> Optional[Mode]:
        """Suggest a mode without switching automatically."""
        text = user_input.lower()
        coding_markers = (".py", ".go", ".rs", "git ", "def ", "class ", "func ", "cargo ", "pytest")
        office_markers = ("整理", "总结", "搜索", "会议", "文档", "邮件")
        if self._current_mode is not Mode.CODING and any(marker in text for marker in coding_markers):
            return Mode.CODING
        if self._current_mode is not Mode.OFFICE and any(marker in text for marker in office_markers):
            return Mode.OFFICE
        return None

    async def load_system_prompt(self) -> str:
        """Read the active mode's system prompt file."""
        prompt_path = self.project_root / self.mode_config.system_prompt_file
        return prompt_path.read_text(encoding="utf-8")

    @staticmethod
    def parse(value: str) -> Mode:
        """Parse a user-facing mode string."""
        normalized = value.strip().lower()
        if normalized in {"office", "办公"}:
            return Mode.OFFICE
        if normalized in {"coding", "code", "编码"}:
            return Mode.CODING
        raise ValueError(f"unknown mode: {value}")
