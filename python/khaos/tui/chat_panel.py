"""Scrolling chat log that renders agent messages."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from rich.align import Align
from rich.console import Console, ConsoleOptions, RenderResult
from rich.console import Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from textual.widgets import RichLog

from khaos.agent.core import Message
from khaos.tui.brand import brand_art
from khaos.tui.markdown import markdown_to_rich, render_message, to_rich


class ChatPanel(RichLog):
    """A RichLog that renders Khaos messages with Markdown-aware streaming."""

    DEFAULT_CSS = """
    ChatPanel {
        background: #111111;
        color: #e0e0e0;
        padding: 1 0;
        scrollbar-background: #0d0d0d;
        scrollbar-color: #d99021;
        scrollbar-color-hover: #f59e0b;
    }
    """

    def __init__(self) -> None:
        super().__init__(wrap=True, auto_scroll=True)
        self._entries: list[Any] = []
        self._assistant_stream_buffer: list[str] = []
        self._assistant_stream_index: int | None = None
        self._welcome_dashboard: _WelcomeDashboard | None = None

    def append_message(self, message: Message) -> None:
        """Render one agent message into the log.

        Assistant chunks are shown immediately as plain text while a turn is
        streaming, then replaced by a single Rich Markdown renderable at the
        next non-text event boundary. This preserves live output without
        parsing partial Markdown such as split ``**bold**`` or fenced code.
        """
        if message.event is None and message.role == "assistant" and message.content:
            self._append_assistant_chunk(message.content)
            return

        self.flush_markdown()
        rendered = render_message(message)
        if message.event is None and message.role == "user" and message.content:
            self._write_entry(_prompt_line(message.content))
        else:
            self._write_entry(to_rich(rendered))

    def _append_assistant_chunk(self, chunk: str) -> None:
        """Append a streaming assistant chunk and redraw the live placeholder."""
        self._assistant_stream_buffer.append(chunk)
        renderable = _labeled_block(
            "● Khaos",
            Text("".join(self._assistant_stream_buffer), style="white"),
            "bold #f59e0b",
        )
        if self._assistant_stream_index is None:
            self._assistant_stream_index = len(self._entries)
            self._entries.append(renderable)
            super().write(renderable)
            return
        self._entries[self._assistant_stream_index] = renderable
        self._redraw()

    def flush_markdown(self) -> None:
        """Replace the live assistant placeholder with final Markdown output."""
        if not self._assistant_stream_buffer:
            return
        text = "".join(self._assistant_stream_buffer)
        self._assistant_stream_buffer.clear()
        index = self._assistant_stream_index
        self._assistant_stream_index = None
        if index is None:
            if text.strip():
                self._write_entry(markdown_to_rich(text))
            return
        if text.strip():
            self._entries[index] = _labeled_block("● Khaos", markdown_to_rich(text), "bold #f59e0b")
        else:
            del self._entries[index]
        self._redraw()

    def append_welcome_dashboard(
        self,
        *,
        mode: str,
        model: str,
        session_id: str,
        project_root: Path,
        viewport_width: int | None = None,
    ) -> None:
        """Append a branded startup dashboard before the transcript."""
        self.flush_markdown()
        dashboard = _WelcomeDashboard(
            mode=mode,
            model=model,
            session_id=session_id,
            project_root=project_root,
            viewport_width=viewport_width,
        )
        self._welcome_dashboard = dashboard
        self._write_entry(dashboard)

    def append_text(self, text: str, *, markdown: bool = False) -> None:
        """Append a free-form string (used for command echoes)."""
        self.flush_markdown()
        if markdown:
            self._write_entry(_labeled_block("◆ System", markdown_to_rich(text), "bold #9ca3af"))
        else:
            self._write_entry(_labeled_block("◆ System", Text.from_markup(text), "bold #9ca3af"))

    def append_user_echo(self, text: str) -> None:
        """Append a user prompt echo without parsing user input as markup."""
        self.flush_markdown()
        self._write_entry(_prompt_line(text))

    def append_error(self, text: str) -> None:
        self.flush_markdown()
        self._write_entry(_labeled_block("Error", Text(text, style="bold red"), "bold red"))

    def append_diff(self, file_path: str, diff_text: str) -> None:
        """Append a colourised diff block to the chat panel.

        ``diff_text`` is the raw output of ``git diff --color=never``. Lines
        starting with ``+``/``-``/``@@`` are tinted green/red/yellow; context
        and header lines keep the default colour. Empty diffs render a single
        dim note so the user knows the tool ran.
        """
        self.flush_markdown()
        self._write_entry(build_diff_renderable(file_path, diff_text))

    def clear(self) -> None:
        """Clear all chat content and reset streaming state."""
        self._entries.clear()
        self._assistant_stream_buffer.clear()
        self._assistant_stream_index = None
        self._welcome_dashboard = None
        super().clear()

    def clear_chat(self) -> None:
        """Clear all chat content and reset buffers."""
        self.clear()

    def _write_entry(self, renderable: Any) -> None:
        self._entries.append(renderable)
        super().write(renderable)

    def _redraw(self) -> None:
        super().clear()
        for entry in self._entries:
            super().write(entry)

    def on_resize(self, event: Any) -> None:
        """Keep the startup dashboard responsive after terminal resizes."""
        if self._welcome_dashboard is None:
            return
        size = getattr(event, "size", None)
        width = getattr(size, "width", None)
        if not isinstance(width, int) or width <= 0:
            return
        self._welcome_dashboard.viewport_width = width
        self._redraw()


def _labeled_block(label: str, body: Any, label_style: str) -> Group:
    return Group(
        Text.assemble(("\n", ""), (label, label_style)),
        body,
    )


def build_diff_renderable(file_path: str, diff_text: str) -> Group:
    """Build a Rich renderable for a colourised git diff.

    Header rule ``── diff: <path> ──`` and a trailing ``────`` rule wrap the
    body. ``@@`` hunks are yellow, ``+`` lines green, ``-`` lines red, and
    everything else (context lines, ``diff --git`` headers, index lines) keeps
    the default style. A trailing footer line is always emitted so multi-file
    diffs are visually closed.
    """
    if not diff_text or not diff_text.strip():
        return Group(
            Text.assemble(
                ("\n", ""),
                (f"── diff: {file_path} ", "dim"),
                ("(no changes)", "dim italic"),
                (" ──", "dim"),
            )
        )

    rule_width = 60
    header_rule = f"── diff: {file_path} ".ljust(rule_width, "─")
    footer_rule = "─" * rule_width

    spans: list[tuple[str, str]] = [("\n", ""), (header_rule, "dim")]
    for raw_line in diff_text.splitlines():
        if raw_line.startswith("@@"):
            spans.append((raw_line, "yellow"))
        elif raw_line.startswith("+"):
            spans.append((raw_line, "green"))
        elif raw_line.startswith("-"):
            spans.append((raw_line, "red"))
        else:
            spans.append((raw_line, ""))
    spans.append((footer_rule, "dim"))

    return Group(Text.assemble(*spans))


def _prompt_line(text: str) -> Text:
    return Text.assemble(
        ("\n› ", "bold #f59e0b"),
        (text, "bold white reverse"),
    )


class _WelcomeDashboard:
    """Responsive startup dashboard for the first TUI screen."""

    def __init__(
        self,
        *,
        mode: str,
        model: str,
        session_id: str,
        project_root: Path,
        viewport_width: int | None,
    ) -> None:
        self.mode = mode
        self.model = model
        self.session_id = session_id
        self.project_root = project_root
        self.viewport_width = viewport_width

    def __rich_console__(
        self,
        console: Console,
        options: ConsoleOptions,
    ) -> RenderResult:
        max_width = max(60, self.viewport_width or options.max_width)
        if max_width >= 150:
            yield self._wide_layout()
            return
        yield self._stacked_layout(max_width=max_width)

    def _wide_layout(self) -> Table:
        layout = Table.grid(expand=False)
        layout.add_column(width=64)
        layout.add_column(width=4)
        layout.add_column(width=84)
        layout.add_row(
            Align.left(brand_art(width=64)),
            "",
            Align.left(self._status_panel(width=84, vertical_padding=8)),
        )
        return layout

    def _stacked_layout(self, *, max_width: int) -> Group:
        brand_width = min(68, max(48, max_width - 4))
        return Group(
            Align.left(brand_art(width=brand_width)),
            self._status_panel(width=min(84, max_width - 4), vertical_padding=1),
        )

    def _status_panel(self, *, width: int, vertical_padding: int) -> Panel:
        meta = Table.grid(expand=True)
        meta.add_column(ratio=1)
        meta.add_column(ratio=2)
        meta.add_row(
            Text.assemble(
                ("mode ", "dim"),
                (self.mode, "bold #f59e0b"),
                ("\nmodel ", "dim"),
                (self.model, "white"),
                ("\nsession ", "dim"),
                (self.session_id[:8], "#9ca3af"),
            ),
            Text.assemble(
                ("workspace\n", "bold #f59e0b"),
                (str(self.project_root), "white"),
                ("\n\n/help", "bold #f59e0b"),
                (" commands  ·  ", "dim"),
                ("/mode", "bold #f59e0b"),
                (" switch  ·  ", "dim"),
                ("/clear", "bold #f59e0b"),
                (" reset transcript", "dim"),
            ),
        )
        return Panel(
            meta,
            title="[bold #f59e0b]Khaos Agent[/]",
            subtitle="[dim]ready[/]",
            border_style="#d99021",
            padding=(vertical_padding, 3),
            width=width,
        )
