"""Immutable ownership rules for memory persistence.

The database stores private memories under a principal and shared memories
under the empty principal.  Keeping that mapping in one value object prevents
individual store methods from accidentally applying different visibility
rules.
"""

from __future__ import annotations

from dataclasses import dataclass

PRIVATE_NAMESPACE = "private"
SESSION_NAMESPACE = "session"
SHARED_NAMESPACE = "shared"
SUPPORTED_NAMESPACES = frozenset(
    {PRIVATE_NAMESPACE, SESSION_NAMESPACE, SHARED_NAMESPACE}
)


@dataclass(frozen=True, slots=True)
class MemoryOwner:
    """Principal/project binding captured when a store is constructed."""

    principal_id: str = "legacy"
    project_id: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.principal_id, str) or not self.principal_id:
            raise ValueError("principal_id must be a non-empty string")
        if not isinstance(self.project_id, str):
            raise TypeError("project_id must be a string")

    def effective_principal(self, namespace: str) -> str:
        """Return the row principal for a validated namespace."""

        validate_namespace(namespace)
        if namespace == SHARED_NAMESPACE:
            return ""
        return self.principal_id

    def validate(self, namespace: str, session_id: str) -> None:
        """Validate the complete namespace/session identity."""

        validate_namespace(namespace)
        if not isinstance(session_id, str):
            raise TypeError("session_id must be a string")
        if namespace == SESSION_NAMESPACE and not session_id:
            raise ValueError("session namespace requires a session_id")


def validate_namespace(namespace: str) -> None:
    """Reject unknown namespaces before they reach the persistence adapter."""

    if namespace not in SUPPORTED_NAMESPACES:
        raise ValueError(
            f"unsupported memory namespace {namespace!r}; "
            f"expected one of {sorted(SUPPORTED_NAMESPACES)}"
        )


__all__ = [
    "PRIVATE_NAMESPACE",
    "SESSION_NAMESPACE",
    "SHARED_NAMESPACE",
    "SUPPORTED_NAMESPACES",
    "MemoryOwner",
    "validate_namespace",
]
