"""Workspace-domain errors shared by lifecycle and artifact owners."""

from __future__ import annotations


class WorkspaceError(RuntimeError):
    """Raised when a workspace operation cannot complete safely."""


__all__ = ["WorkspaceError"]
