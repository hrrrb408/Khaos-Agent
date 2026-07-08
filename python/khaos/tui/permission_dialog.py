"""Permission confirmation modal."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Static


class PermissionDialog(ModalScreen[bool]):
    """A y/n modal shown when the agent requests tool permission.

    Posts ``True`` (approve) or ``False`` (deny) via :meth:`Screen.dismiss`.
    """

    DEFAULT_CSS = """
    PermissionDialog {
        align: center middle;
    }
    PermissionDialog > Vertical {
        width: 52;
        height: auto;
        padding: 1 2;
        border: round $warning;
        background: $surface;
    }
    PermissionDialog Static {
        margin: 0 0 1 0;
    }
    PermissionDialog Horizontal {
        align: center middle;
        height: 3;
    }
    PermissionDialog Button {
        margin: 0 2;
    }
    """

    BINDINGS = [("y", "approve", "Allow"), ("n", "deny", "Deny"), ("escape", "deny", "Deny")]

    def __init__(self, request: dict) -> None:
        super().__init__()
        self.request = request

    def compose(self) -> ComposeResult:  # type: ignore[override]
        name = self.request.get("name", "tool")
        target = _friendly_target(self.request)
        with Vertical():
            yield Static(
                f"[b]Allow {name}?[/]\n"
                + (f"[dim]{target}[/]" if target else "[dim]This action needs permission.[/]"),
                markup=True,
            )
            with Horizontal():
                yield Button("Allow (y)", id="allow", variant="success")
                yield Button("Deny (n)", id="deny", variant="error")

    def on_mount(self) -> None:  # type: ignore[override]
        self.query_one("#allow", Button).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:  # type: ignore[override]
        self.dismiss(event.button.id == "allow")

    def action_approve(self) -> None:
        self.dismiss(True)

    def action_deny(self) -> None:
        self.dismiss(False)


def _friendly_target(request: dict) -> str:
    """Return a concise user-facing target string for permission prompts."""
    arguments = request.get("arguments")
    if isinstance(arguments, dict):
        for key in ("path", "root", "url", "command", "src", "dst"):
            value = arguments.get(key)
            if value:
                return str(value)
    target = str(request.get("target", ""))
    if ":" in target and "{" in target:
        return target.split(":", 1)[0]
    return target
