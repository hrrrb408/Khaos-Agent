"""Main Textual App wiring the agent loop into the TUI."""

from __future__ import annotations

import asyncio
import logging
import uuid
from pathlib import Path

from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding

from khaos.agent import AgentConfig, AgentLoop
from khaos.agent.compressor import ContextCompressor
from khaos.agent.core import Message
from khaos.agent.error_handler import ErrorHandler
from khaos.config import PROVIDER_DEFAULTS, check_needs_setup, write_provider_config
from khaos.db import Database
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
    }
    #chat {
        height: 1fr;
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
        self.skill_manager = SkillManager()
        self.agent_loop: AgentLoop | None = None
        self.session_id = str(uuid.uuid4())
        self._pending_confirmations: dict[str, asyncio.Future] = {}
        self._total_tokens = 0
        self._setup_step = ""
        self._setup_provider = ""

    # --- layout ------------------------------------------------------------

    def compose(self) -> ComposeResult:  # type: ignore[override]
        yield ChatPanel()
        yield InputPanel()
        yield StatusBar()

    async def on_mount(self) -> None:  # type: ignore[override]
        configured = await self._bootstrap()
        chat = self.query_one(ChatPanel)
        if not configured:
            chat.append_text(
                f"Khaos ready. session [b]{self.session_id}[/], mode "
                f"[b]{self._mode_label()}[/].",
                markdown=False,
            )
            self._begin_setup_flow()
            self._sync_status()
            return
        chat.append_text(
            f"Khaos ready. session [b]{self.session_id}[/], mode "
            f"[b]{self._mode_label()}[/]. Type /help for commands.",
            markdown=False,
        )
        self._sync_status()

    async def _bootstrap(self) -> bool:
        self.db = Database(self.db_path)
        await self.db.connect()
        await self.db.run_migrations()
        self.mode_manager = ModeManager(self.db, project_root=self.project_root)
        await self.mode_manager.load()
        if self.mode_override:
            await self.mode_manager.switch(ModeManager.parse(self.mode_override))
        await self.db.create_session(self.session_id, self.mode_manager.current_mode.value)
        if check_needs_setup():
            return False
        await self._bootstrap_agent_runtime()
        return True

    async def _bootstrap_agent_runtime(self) -> None:
        if self.db is None or self.mode_manager is None:
            return
        self.router = create_default_router()
        permission_engine = PermissionEngine(self.db)
        await permission_engine.load_rules()
        memory_store = MemoryStore(self.db)
        self.memory_manager = MemoryManager(
            memory_store,
            budget=MemoryBudget(),
            mode_getter=lambda: self.mode_manager.current_mode,
            intent_getter=lambda: getattr(self.mode_manager, "_intent_buffer", ""),
        )
        compressor = ContextCompressor(self.router, memory_manager=self.memory_manager)
        skills_dir = self.project_root / "skills"
        if skills_dir.is_dir():
            self.skill_manager.load_from_dir(skills_dir)
        self.agent_loop = AgentLoop(
            AgentConfig(),
            self.mode_manager,
            self.router,
            self.db,
            tool_scheduler=ToolScheduler(create_runtime_registry(), permission_engine),
            confirm_callback=self._confirm_callback,
            context_compressor=compressor,
            memory_manager=self.memory_manager,
            error_handler=ErrorHandler(db=self.db, router=self.router, compressor=compressor),
            skill_manager=self.skill_manager if len(self.skill_manager.registry) > 0 else None,
        )

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
        """Stream one agent turn into the chat panel."""
        if self.agent_loop is None:
            return
        chat = self.query_one(ChatPanel)
        try:
            async for message in self.agent_loop.run(user_input, self.session_id):
                self._render_message(message)
                self._total_tokens = max(self._total_tokens, message.token_count)
        except Exception as exc:  # noqa: BLE001 — surface any error to the user
            logger.exception("agent turn failed")
            chat.append_error(f"turn failed: {exc}")
        self._sync_status()

    def _render_message(self, message: Message) -> None:
        chat = self.query_one(ChatPanel)
        chat.append_message(message)

    def _echo_user(self, text: str) -> None:
        from rich.text import Text
        t = Text.assemble(("you:", "cyan"), " ", text)
        self.query_one(ChatPanel).write(t)

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
        future: asyncio.Future[bool] = asyncio.get_event_loop().create_future()
        self._pending_confirmations[request["id"]] = future

        def _on_result(approved: bool) -> None:
            if not future.done():
                future.set_result(approved)

        def _show() -> None:
            self.push_screen(PermissionDialog(request), _on_result)

        self.call_from_thread(_show)
        approved = await future
        return {"approved": approved, "remember": False}

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
            session_id=self.session_id,
            on_clear=lambda: self.query_one(ChatPanel).clear(),
            on_quit=self.exit,
            on_new_session=self._new_session,
        )

    def _new_session(self, _unused: str = "") -> str:
        self.session_id = str(uuid.uuid4())
        if self.db is not None and self.mode_manager is not None:
            asyncio.ensure_future(
                self.db.create_session(self.session_id, self.mode_manager.current_mode.value)
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
            return
        try:
            model = next(iter(self.router.provider_manager._models.keys()), "mock")
            bar.set_model(model)
        except Exception:
            bar.set_model("mock")

    def action_clear_chat(self) -> None:
        self.query_one(ChatPanel).clear()


def run_tui(
    db_path: str = "khaos.db",
    project_root: Path | None = None,
    mode: str = "",
) -> None:
    """Entry point used by the CLI / Makefile."""
    app = KhaosApp(db_path=db_path, project_root=project_root, mode=mode)
    app.run()


__all__ = ["KhaosApp", "run_tui"]
