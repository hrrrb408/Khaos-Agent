"""Wire request value objects for the Python RPC services.

Transport framing and authentication stay in khaos.grpc_server; these
small dataclasses are the typed boundary passed from the dispatcher to services.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ChatRequest:
    """A single authenticated chat request."""

    session_id: str
    message: str
    mode: str = ""
    principal_id: str = ""


@dataclass(frozen=True, slots=True)
class ConfirmRequest:
    """A one-shot permission decision bound to a transport principal."""

    session_id: str
    tool_call_id: str
    approved: bool
    remember: bool = False
    principal_id: str = ""
    binding_digest: str = ""


__all__ = ["ChatRequest", "ConfirmRequest"]
