"""Stable security identity contracts shared by low-level authorities.

These nominal identities intentionally retain their string representation.
They live in the security layer because workspace identity is part of the
resource-scope contract, not a planning implementation detail.  Higher-level
planning modules may re-export the canonical type for compatibility, but the
security foundation must not import the planning package to obtain it.
"""

from __future__ import annotations

from typing import NewType

CanonicalWorkspaceId = NewType("CanonicalWorkspaceId", str)

__all__ = ["CanonicalWorkspaceId"]
