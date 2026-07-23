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
            # Phase 6 browser tools (Playwright-backed, also available in office)
            "browser_launch",
            "browser_close",
            "browser_navigate",
            "browser_click",
            "browser_type",
            "browser_snapshot",
            "browser_screenshot",
            "browser_scroll",
            "browser_vision",
            "browser_evaluate",
            "browser_file_upload",
            # Phase 6 web content tools (fetch/tables/metadata)
            "web_fetch",
            "web_extract_tables",
            "web_metadata",
        ],
        preferred_model_function="coding",
        interaction_style="autonomous",
    ),
}


class ModeManager:
    """Mode switch manager backed by the principal_modes table.

    M4 batch 3.1.16A-2 (CRITICAL #4): mode is now principal-scoped.
    Each principal has its own current mode, optionally overridden per
    session.  The lookup order in ``load()`` is:

      1. ``(principal_id, session_id)`` — session-specific override
      2. ``(principal_id, '')``         — principal default
      3. system default (office)

    Legacy behaviour stored mode in the global ``user_config.current_mode``
    key, so every principal on the same database shared one mode.  The
    global key is no longer read or written; ``user_config`` is retained
    for genuinely global settings (API keys etc.).

    H-09 (round-5 Batch 5.3): mode is now ALSO project-scoped.  The
    lookup order becomes:

      1. ``(project_id, principal_id, session_id)`` — session override
      2. ``(project_id, principal_id, '')``         — principal default
      3. system default (office)

    This closes cross-project mode leakage on shared DBs: Project A's
    coding mode (which gates System Prompt, Tool Availability, Routing)
    is no longer loaded by Project B for the same principal.
    ``project_id=''`` (the default) preserves legacy/test behaviour.
    """

    def __init__(
        self,
        db,
        project_root: Path | None = None,
        *,
        principal_id: str = "legacy",
        session_id: str = "",
        project_id: str = "",
    ):
        self.db = db
        self.project_root = project_root or Path.cwd()
        self._principal_id = principal_id
        self._session_id = session_id
        self._project_id = project_id
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
        """Load current mode from the principal_modes table.

        Lookup order: ``(project_id, principal_id, session_id)`` →
        ``(project_id, principal_id, '')`` → system default (office).
        """
        value = await self.db.get_principal_mode(
            self._principal_id,
            session_id=self._session_id,
            default=Mode.OFFICE.value,
            project_id=self._project_id,
        )
        self._current_mode = Mode(value)
        return self._current_mode

    async def switch(self, target_mode: Mode, intent_context: str = "") -> Mode:
        """Switch mode and persist the principal's current preference.

        Writes to ``(project_id, principal_id, session_id)``.  When
        ``session_id`` is empty (the default), the write targets the
        principal's default row for that project — every session
        without its own override sees it.  When ``session_id`` is set,
        only that session is affected.
        """
        self._intent_buffer = intent_context
        self._current_mode = target_mode
        await self.db.set_principal_mode(
            self._principal_id,
            target_mode.value,
            session_id=self._session_id,
            project_id=self._project_id,
        )
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
