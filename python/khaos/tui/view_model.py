"""Dependency-light, side-effect-free TUI event view models."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ApprovalView:
    """Safe fields rendered for one immutable approval challenge."""

    name: str
    target: str
    level: str
    reason: str
    principal_id: str
    task_id: str
    workspace_id: str
    binding_digest: str
    arguments_digest: str
    profile_digest: str
    expires_in_seconds: int
    expired: bool


def build_approval_view(request: dict[str, Any], *, now: float | None = None) -> ApprovalView:
    """Build a display model without mutating or authorizing the request."""
    current_time = time.time() if now is None else now
    expiry = float(request.get("expires_at") or 0.0)
    expires_in = max(0, int(expiry - current_time)) if expiry else 0
    return ApprovalView(
        name=str(request.get("name") or "tool"),
        target=_friendly_target(request),
        level=str(request.get("level") or "unknown"),
        reason=str(request.get("reason") or "This action needs permission."),
        principal_id=str(request.get("principal_id") or "unknown"),
        task_id=str(request.get("task_id") or "unknown"),
        workspace_id=str(request.get("workspace_id") or "unknown"),
        binding_digest=_short_digest(request.get("binding_digest")),
        arguments_digest=_short_digest(request.get("arguments_digest")),
        profile_digest=_short_digest(request.get("profile_digest")),
        expires_in_seconds=expires_in,
        expired=bool(expiry and expiry <= current_time),
    )


def tool_diff_preview(metadata: dict[str, Any]) -> tuple[str, str] | None:
    """Return a backend-provided diff; never invoke Git or read the host tree."""
    output = metadata.get("output")
    if not isinstance(output, dict):
        return None
    diff = output.get("diff") or output.get("patch")
    if not isinstance(diff, str) or not diff.strip():
        return None
    path = "working tree"
    for key in ("path", "file", "file_path"):
        value = output.get(key)
        if isinstance(value, str) and value:
            path = value
            break
    return path, diff.strip()


def _friendly_target(request: dict[str, Any]) -> str:
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


def _short_digest(value: Any) -> str:
    digest = str(value or "")
    return digest[:16] if digest else "unavailable"
