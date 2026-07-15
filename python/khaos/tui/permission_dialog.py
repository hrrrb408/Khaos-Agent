"""Permission confirmation modal."""

from __future__ import annotations

from rich.markup import escape
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Static

from khaos.tui.view_model import build_approval_view


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
        view = build_approval_view(self.request)
        expiry = "EXPIRED — approval will be denied" if view.expired else f"expires in {view.expires_in_seconds}s"
        with Vertical():
            yield Static(
                f"[b]Allow {escape(view.name)}?[/]\n"
                f"[dim]{escape(view.target or view.reason)}[/]\n"
                f"level={escape(view.level)} principal={escape(view.principal_id)}\n"
                f"task={escape(view.task_id)} workspace={escape(view.workspace_id)}\n"
                f"binding={view.binding_digest} args={view.arguments_digest}\n"
                f"profile={view.profile_digest} {expiry}",
                markup=True,
            )
            with Horizontal():
                yield Button(
                    "Allow (y)", id="allow", variant="success", disabled=view.expired
                )
                yield Button("Deny (n)", id="deny", variant="error")

    def on_mount(self) -> None:  # type: ignore[override]
        self.query_one("#allow", Button).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:  # type: ignore[override]
        self.dismiss(event.button.id == "allow")

    def action_approve(self) -> None:
        self.dismiss(not build_approval_view(self.request).expired)

    def action_deny(self) -> None:
        self.dismiss(False)


def _friendly_target(request: dict) -> str:
    """Return a concise user-facing target string for permission prompts."""
    return build_approval_view(request, now=0.0).target
