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
class MemoryVisibility:
    """Immutable read/mutation view for one memory namespace.

    ``namespace=None`` is the durable view: principal-private and
    project-shared rows with an empty session id.  A concrete namespace is an
    exact partition, and the session namespace consequently requires a
    non-empty session id.  Keeping this distinction in one value object stops
    list/search/touch/delete callers from accidentally widening a session
    query into the whole principal partition.
    """

    namespace: str | None = None
    session_id: str = ""

    def __post_init__(self) -> None:
        if self.namespace is not None:
            validate_namespace(self.namespace)
        if not isinstance(self.session_id, str):
            raise TypeError("session_id must be a string")
        if self.namespace is None and self.session_id:
            raise ValueError("durable memory visibility cannot carry a session_id")
        if self.namespace == SESSION_NAMESPACE and not self.session_id:
            raise ValueError("session visibility requires a session_id")
        if (
            self.namespace is not None
            and self.namespace != SESSION_NAMESPACE
            and self.session_id
        ):
            raise ValueError(
                "only session memory visibility may carry a session_id"
            )

    @classmethod
    def durable(cls) -> MemoryVisibility:
        """Return the principal-private/project-shared durable view."""

        return cls()

    @classmethod
    def for_namespace(
        cls,
        namespace: str,
        *,
        session_id: str = "",
    ) -> MemoryVisibility:
        """Return an exact namespace view after validating its identity."""

        return cls(namespace=namespace, session_id=session_id)

    @classmethod
    def for_session(cls, session_id: str) -> MemoryVisibility:
        """Return the session-private view for one non-empty session id."""

        return cls(namespace=SESSION_NAMESPACE, session_id=session_id)

    @property
    def is_durable(self) -> bool:
        """Whether this view intentionally excludes session-private rows."""

        return self.namespace is None


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
    "MemoryVisibility",
    "validate_namespace",
]
