"""Main Textual App wiring the agent loop into the TUI."""

from __future__ import annotations

import asyncio
import logging
import os
import threading
import time
import uuid
from pathlib import Path

from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.widgets import Static
from rich.text import Text

from khaos.agent import AgentConfig, AgentLoop
from khaos.agent.compressor import ContextCompressor
from khaos.agent.core import Message
from khaos.agent.error_handler import ErrorHandler
from khaos.config import PROVIDER_DEFAULTS, check_needs_setup, write_provider_config
from khaos.db import Database
from khaos.db.state_root import project_id as compute_project_id
from khaos.memory import MemoryBudget, MemoryManager, MemoryStore
from khaos.modes import ModeManager
from khaos.permissions import PermissionEngine
from khaos.routing.router import create_default_router
from khaos.skills import SkillManager
from khaos.tools import create_runtime_registry
from khaos.tools.scheduler import ToolScheduler
from khaos.tui.chat_panel import ChatPanel
from khaos.tui.commands import TuiContext, handle_command, is_command
from khaos.tui.input_panel import InputPanel
from khaos.tui.permission_dialog import PermissionDialog
from khaos.tui.status_bar import StatusBar
from khaos.tui.view_model import tool_diff_preview

logger = logging.getLogger(__name__)


class KhaosApp(App):
    """Khaos full-screen TUI.

    Layout: a scrolling ChatPanel filling the screen, a one-line InputPanel
    docked at the bottom, and a StatusBar underneath it. User input that starts
    with ``/`` is dispatched as a command; everything else is fed to the
    AgentLoop and its streamed events are rendered live.
    """

    CSS = """
    Screen {
        layout: vertical;
        background: #0d0d0d;
        color: #e0e0e0;
    }
    #header {
        height: 1;
        padding: 0 2;
        background: #15110a;
        color: #e0e0e0;
    }
    #chat {
        height: 1fr;
        margin: 0 2;
    }
    """

    BINDINGS = [
        Binding("ctrl+c", "quit", "Quit", show=False, priority=True),
        Binding("ctrl+l", "clear_chat", "Clear"),
    ]

    def __init__(
        self,
        db_path: str = "khaos.db",
        project_root: Path | None = None,
        mode: str = "",
    ) -> None:
        super().__init__()
        self.db_path = db_path
        self.project_root = project_root or Path.cwd()
        self.mode_override = mode
        # Runtime — populated in on_mount. ``agent_loop`` avoids shadowing
        # Textual's own App attributes.
        self.db: Database | None = None
        self.mode_manager: ModeManager | None = None
        self.router = None
        self.memory_manager: MemoryManager | None = None
        self.task_manager = None
        self._runtime = None
        self.skill_manager = SkillManager()
        self.agent_loop: AgentLoop | None = None
        self.session_id = str(uuid.uuid4())
        self._pending_confirmations: dict[str, asyncio.Future] = {}
        self._total_tokens = 0
        self._setup_step = ""
        self._setup_provider = ""

    # --- layout ------------------------------------------------------------

    def compose(self) -> ComposeResult:  # type: ignore[override]
        yield HeaderBar()
        yield ChatPanel()
        yield InputPanel()
        yield StatusBar()

    async def on_mount(self) -> None:  # type: ignore[override]
        configured = await self._bootstrap()
        self._sync_status()
        chat = self.query_one(ChatPanel)
        if not configured:
            chat.append_welcome_dashboard(
                mode=self._mode_label(),
                model="setup",
                session_id=self.session_id,
                project_root=self.project_root,
                viewport_width=self.size.width,
            )
            self._begin_setup_flow()
            return
        chat.append_welcome_dashboard(
            mode=self._mode_label(),
            model=self._current_model_label(),
            session_id=self.session_id,
            project_root=self.project_root,
            viewport_width=self.size.width,
        )
        if self.mode_manager is not None and self.mode_manager.current_mode.value == "coding":
            self._show_project_overview()

    def _show_project_overview(self) -> None:
        """Scan the project once and append a compact overview line.

        Only runs in coding mode. Failures (non-git dir, missing files) are
        logged and silently skipped — the overview is a nicety, not a gate.
        """
        try:
            from khaos.coding import RepoIndexer
        except ImportError:
            return
        try:
            index = RepoIndexer().scan(self.project_root)
        except (OSError, FileNotFoundError, NotADirectoryError) as exc:
            logger.debug("project overview skipped: %s", exc)
            return
        except Exception as exc:  # noqa: BLE001 — overview must never break boot
            logger.debug("project overview errored: %s", exc)
            return

        name = self.project_root.name
        files = index.get("total_files", 0)
        dirs = index.get("total_dirs", 0)
        entries = [
            f"Entry: {', '.join(p.name for p in index.get('entry_files', []))}"
        ] if index.get("entry_files") else []
        tests = [
            f"Tests: {', '.join(p.name + '/' for p in index.get('test_dirs', []))}"
        ] if index.get("test_dirs") else []
        configs = [
            f"Config: {', '.join(p.name for p in index.get('config_files', []))}"
        ] if index.get("config_files") else []

        summary = "  ".join(
            [f"📁 Project: {name} ({files} files, {dirs} dirs)", *entries, *tests, *configs]
        )
        try:
            self.query_one(ChatPanel).append_text(summary, markdown=False)
        except Exception as exc:  # noqa: BLE001
            logger.debug("project overview render failed: %s", exc)

    async def _bootstrap(self) -> bool:
        self.db = Database(self.db_path)
        await self.db.connect()
        await self.db.run_migrations()
        # A2-5: bind the TUI's ModeManager to the local-uid principal so
        # mode switches are principal-scoped (matching the runtime below).
        self.mode_manager = ModeManager(
            self.db, project_root=self.project_root,
            principal_id=f"local-uid:{os.getuid()}",
            source_transport="tui",
            foreground_session=True,
        )
        await self.mode_manager.load()
        if self.mode_override:
            await self.mode_manager.switch(ModeManager.parse(self.mode_override))
        await self.db.create_session(
            self.session_id, self.mode_manager.current_mode.value,
            principal_id=f"local-uid:{os.getuid()}",
            # M4 batch 3.1.16A-5-1b: stamp the project identity on every
            # TUI session row.  ``self._tui_project_id`` is computed once
            # in ``__init__`` (or here on first use) from the TUI's
            # project_root and reused for every session / runtime so the
            # stamps stay in sync.
            project_id=self._tui_project_id,
        )
        if check_needs_setup():
            return False
        await self._bootstrap_agent_runtime()
        return True

    @property
    def _tui_project_id(self) -> str:
        """M4 batch 3.1.16A-5-1b: lazily compute and cache the project
        identity from the TUI's ``project_root``.  Cached on the instance
        so every session / runtime in this TUI process stamps the SAME
        value (a mid-process cwd change would otherwise produce drift).
        """
        cached = getattr(self, "_cached_project_id", None)
        if cached is None:
            cached = compute_project_id(self.project_root)
            self._cached_project_id = cached
        return cached

    async def _bootstrap_agent_runtime(self) -> None:
        if self.db is None or self.mode_manager is None:
            return
        from khaos.runtime import RuntimeConfig, build_runtime
        runtime = await build_runtime(RuntimeConfig(
            db=self.db, project_root=self.project_root, mode_manager=self.mode_manager,
            confirm_callback=self._confirm_callback,
            coding_context_builder=self._build_coding_context_builder(),
            skill_manager=self.skill_manager,
            principal_id=f"local-uid:{os.getuid()}",
            # M4 batch 3.1.16A-5-1b: pass the cached project identity so
            # the runtime's AgentLoop._bound_project_id matches the
            # session row's stamp above.
            project_id=self._tui_project_id,
        ))
        self.router = runtime.loop.router
        self.agent_loop = runtime.loop
        self.memory_manager = runtime.memory_manager
        self.task_manager = runtime.task_manager
        self._runtime = runtime

    async def on_unmount(self) -> None:  # type: ignore[override]
        """Await TUI runtime and database cleanup before the loop exits."""
        if self._runtime is not None:
            from khaos.runtime import close_runtime_or_register
            await close_runtime_or_register(self._runtime)
        if self.db is not None:
            await self.db.close()

    def _build_coding_context_builder(self):
        """Construct a CodingContextBuilder, or None if coding pkg is absent."""
        try:
            from khaos.coding import CodingContextBuilder
        except ImportError:
            logger.debug("coding module unavailable; skipping context builder")
            return None
        return CodingContextBuilder()

    # --- input handling ----------------------------------------------------

    def on_input_panel_submitted(self, event: InputPanel.Submitted) -> None:
        """Dispatch user input: commands synchronously, chat asynchronously."""
        value = event.value.strip()
        if not value:
            return
        if self._setup_step:
            self._handle_setup_input(value)
            return
        if is_command(value):
            self._handle_command(value)
        else:
            self._echo_user(value)
            self._run_turn(value)

    def _handle_command(self, line: str) -> None:
        ctx = self._build_context()
        # Clear/quit callbacks are applied synchronously by the command handler.
        work_coro = handle_command(line, ctx)

        async def _run():
            result = await work_coro
            chat = self.query_one(ChatPanel)
            if result.should_clear:
                chat.clear()
            if result.message:
                chat.append_text(result.message, markdown=True)
            if result.should_quit:
                self.exit()
            self._sync_status()

        self.run_worker(_run())

    @work(exclusive=True)
    async def _run_turn(self, user_input: str) -> None:
        """Run one agent turn in a Textual worker."""
        await self._run_turn_impl(user_input)

    async def _run_turn_impl(self, user_input: str) -> None:
        """Stream one agent turn into the chat panel."""
        if self.agent_loop is None:
            return
        chat = self.query_one(ChatPanel)
        turn_tokens = 0
        try:
            async for message in self.agent_loop.run(user_input, self.session_id):
                self._render_message(message)
                if _is_done_message(message):
                    turn_tokens = message.token_count
        except Exception as exc:  # noqa: BLE001 — surface any error to the user
            logger.exception("agent turn failed")
            chat.append_error(f"turn failed: {exc}")
        if turn_tokens > 0:
            self._total_tokens += turn_tokens
        self._sync_status()

    def _render_message(self, message: Message) -> None:
        chat = self.query_one(ChatPanel)
        chat.append_message(message)
        # After a successful write-class tool call, render a diff artifact when
        # the restricted tool result already contains one. The UI never runs
        # host Git to synthesize this preview.
        if self._is_write_tool_result(message):
            self._maybe_show_diff(message)

    # Tools whose success should trigger an automatic diff preview.
    _DIFF_TRIGGER_TOOLS = frozenset({"write_file", "patch", "multi_edit"})

    def _is_write_tool_result(self, message: Message) -> bool:
        if message.event != "tool_result":
            return False
        meta = message.metadata or {}
        return meta.get("success") is True and meta.get("name") in self._DIFF_TRIGGER_TOOLS

    def _maybe_show_diff(self, message: Message) -> None:
        meta = message.metadata or {}
        preview = tool_diff_preview(meta)
        if preview is None:
            logger.debug("diff preview skipped: tool result has no trusted diff artifact")
            return
        file_path, diff_text = preview
        try:
            self.query_one(ChatPanel).append_diff(file_path, diff_text)
        except Exception as exc:  # noqa: BLE001 — never let the preview crash the turn
            logger.debug("diff render failed: %s", exc)

    @staticmethod
    def _extract_changed_path(meta: dict) -> str:
        """Best-effort path extraction from a write-class tool result."""
        output = meta.get("output")
        if isinstance(output, dict):
            for key in ("path", "file", "file_path"):
                value = output.get(key)
                if isinstance(value, str) and value:
                    return value
        if isinstance(output, str) and output:
            return output.splitlines()[0][:120]
        arguments = meta.get("arguments")
        if isinstance(arguments, dict):
            for key in ("path", "file", "file_path"):
                value = arguments.get(key)
                if isinstance(value, str) and value:
                    return value
        return ""

    def _echo_user(self, text: str) -> None:
        self.query_one(ChatPanel).append_user_echo(text)

    # --- first-run setup ---------------------------------------------------

    def _begin_setup_flow(self) -> None:
        self._setup_step = "provider"
        self._setup_provider = ""
        self._set_input_secret(False)
        self._set_input_placeholder("选择 provider [1]")
        self.query_one(ChatPanel).append_text(
            "\n[b]检测到未配置模型 API Key[/]\n\n"
            "支持的 Provider：\n"
            "  1. NVIDIA NIM (免费额度，推荐)\n"
            "  2. Anthropic Claude\n"
            "  3. OpenAI\n\n"
            "请输入 provider：1/nvidia、2/anthropic 或 3/openai。",
            markdown=True,
        )

    def _handle_setup_input(self, value: str) -> None:
        if self._setup_step == "provider":
            provider = self._parse_setup_provider(value)
            if provider is None:
                self.query_one(ChatPanel).append_error("请输入 1/nvidia、2/anthropic 或 3/openai。")
                return
            self._setup_provider = provider
            self._setup_step = "api_key"
            self._set_input_secret(True)
            self._set_input_placeholder("输入 API Key")
            label = PROVIDER_DEFAULTS[provider]["label"]
            self.query_one(ChatPanel).append_text(
                f"已选择 [b]{label}[/]。\n请输入 API Key（输入框会隐藏显示）。",
                markdown=True,
            )
            return

        if self._setup_step == "api_key":
            api_key = value.strip()
            if len(api_key) <= 10:
                self.query_one(ChatPanel).append_error("API Key 不能为空，且长度需要大于 10。")
                return
            write_provider_config(self._setup_provider, api_key)
            self._setup_step = ""
            self._setup_provider = ""
            self._set_input_secret(False)
            self._set_input_placeholder("Message Khaos…  (/help for commands)")
            self.query_one(ChatPanel).append_text(
                "✓ 已保存到 ~/.khaos/config.yaml，正在初始化 Agent…",
                markdown=False,
            )
            self.run_worker(self._finish_setup())

    async def _finish_setup(self) -> None:
        try:
            await self._bootstrap_agent_runtime()
        except Exception as exc:  # noqa: BLE001
            logger.exception("setup completed but runtime bootstrap failed")
            self.query_one(ChatPanel).append_error(f"配置已保存，但 Agent 初始化失败: {exc}")
            return
        self.query_one(ChatPanel).append_text("配置完成。Type /help for commands.", markdown=False)
        self._sync_status()

    @staticmethod
    def _parse_setup_provider(value: str) -> str | None:
        aliases = {
            "": "nvidia",
            "1": "nvidia",
            "nvidia": "nvidia",
            "2": "anthropic",
            "anthropic": "anthropic",
            "claude": "anthropic",
            "3": "openai",
            "openai": "openai",
        }
        return aliases.get(value.strip().lower())

    def _set_input_secret(self, secret: bool) -> None:
        input_panel = self.query_one(InputPanel)
        if hasattr(input_panel, "password"):
            input_panel.password = secret

    def _set_input_placeholder(self, placeholder: str) -> None:
        self.query_one(InputPanel).placeholder = placeholder

    # --- permission flow ---------------------------------------------------

    async def _confirm_callback(self, request: dict) -> dict:
        """Bridge the scheduler's permission request to a modal dialog."""
        expires_at = float(request.get("expires_at") or 0.0)
        if expires_at and expires_at <= time.time():
            return {"approved": False, "remember": False}
        if request["id"] in self._pending_confirmations:
            logger.warning("duplicate pending approval denied: %s", request["id"])
            return {"approved": False, "remember": False}
        future: asyncio.Future[bool] = asyncio.get_event_loop().create_future()
        self._pending_confirmations[request["id"]] = future

        def _on_result(approved: bool) -> None:
            if not future.done():
                future.set_result(approved)

        def _show() -> None:
            self.push_screen(PermissionDialog(request), _on_result)

        if threading.get_ident() == getattr(self, "_thread_id", None):
            _show()
        else:
            self.call_from_thread(_show)
        try:
            approved = await future
            if expires_at and expires_at <= time.time():
                approved = False
            return {"approved": approved, "remember": False}
        finally:
            self._pending_confirmations.pop(request["id"], None)

    # --- helpers -----------------------------------------------------------

    def _build_context(self) -> TuiContext:
        return TuiContext(
            loop=self.agent_loop,
            mode_manager=self.mode_manager,
            memory_store=self.memory_manager.store if self.memory_manager else None,
            registry=create_runtime_registry(),
            router=self.router,
            db=self.db,
            skill_manager=self.skill_manager,
            task_manager=self.task_manager,
            session_id=self.session_id,
            # M4 batch 3.1.16A-5-1b: pass the cached project identity so
            # slash commands (e.g. ``/mode``) stamp the SAME project_id
            # on session rows as the runtime.
            project_id=self._tui_project_id,
            on_clear=lambda: self.query_one(ChatPanel).clear(),
            on_quit=self.exit,
            on_new_session=self._new_session,
        )

    def _new_session(self, _unused: str = "") -> str:
        self.session_id = str(uuid.uuid4())
        self._total_tokens = 0
        if self.db is not None and self.mode_manager is not None:
            asyncio.ensure_future(
                self.db.create_session(
                    self.session_id, self.mode_manager.current_mode.value,
                    principal_id=f"local-uid:{os.getuid()}",
                    # M4 batch 3.1.16A-5-1b: stamp the cached project
                    # identity (see ``_tui_project_id``).
                    project_id=self._tui_project_id,
                )
            )
        self._sync_status()
        return self.session_id

    def _mode_label(self) -> str:
        if self.mode_manager is None:
            return "office"
        return self.mode_manager.current_mode.value

    def _sync_status(self) -> None:
        bar = self.query_one(StatusBar)
        bar.set_mode(self._mode_label())
        bar.set_session(self.session_id)
        bar.set_tokens(self._total_tokens)
        if self.router is None:
            bar.set_model("setup")
            self.query_one(HeaderBar).set_state(
                self._mode_label(),
                "setup",
                self.session_id,
                self._total_tokens,
            )
            return
        try:
            model = self._current_model_label()
            bar.set_model(model)
        except Exception:
            bar.set_model("mock")
            model = "mock"
        self.query_one(HeaderBar).set_state(
            self._mode_label(),
            model,
            self.session_id,
            self._total_tokens,
        )

    def action_clear_chat(self) -> None:
        self.query_one(ChatPanel).clear()

    def _current_model_label(self) -> str:
        if self.router is None:
            return "setup"
        return next(iter(self.router.provider_manager._models.keys()), "mock")


class HeaderBar(Static):
    """Compact product header for the TUI."""

    def __init__(self) -> None:
        super().__init__("", id="header")

    def set_state(self, mode: str, model: str, session_id: str, tokens: int) -> None:
        self.update(
            Text.assemble(
                (" Khaos", "bold #f59e0b"),
                ("  "),
                (mode.upper(), "bold #f59e0b"),
                ("  ·  ", "dim"),
                (_compact(model, 40), "white"),
                ("  ·  ", "dim"),
                (session_id[:8], "#9ca3af"),
                ("  ·  ", "dim"),
                (str(tokens), "#9ca3af"),
                (" tok", "dim"),
            )
        )


def _compact(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    return value[: limit - 1] + "…"


def _is_done_message(message: Message) -> bool:
    return message.event == "done" or (message.role == "system" and message.content == "done")


def run_tui(
    db_path: str = "khaos.db",
    project_root: Path | None = None,
    mode: str = "",
) -> None:
    """Entry point used by the CLI / Makefile."""
    app = KhaosApp(db_path=db_path, project_root=project_root, mode=mode)
    app.run()


__all__ = ["KhaosApp", "run_tui"]
