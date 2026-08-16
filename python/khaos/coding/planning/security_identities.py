"""Nominal security identities used at lifecycle and quarantine boundaries.

These aliases intentionally have the same runtime representation as ``str``.
They exist so static type checking can distinguish security resources that are
not interchangeable, even when their persistence layer stores text values.
"""
from __future__ import annotations

from typing import NewType

CanonicalWorkspaceId = NewType("CanonicalWorkspaceId", str)
VerificationRunId = NewType("VerificationRunId", str)
DisposableWorkspaceId = NewType("DisposableWorkspaceId", str)
SandboxInstanceId = NewType("SandboxInstanceId", str)

__all__ = [
    "CanonicalWorkspaceId",
    "DisposableWorkspaceId",
    "SandboxInstanceId",
    "VerificationRunId",
]
