"""The policy boundary for lease validation."""

from .authority import AuthorityLease


def require_active(lease: AuthorityLease, project_id: str) -> None:
    """Enforce the active-and-project-bound lease invariant."""

    if not lease.active:
        raise PermissionError("inactive lease")
    if lease.project_id != project_id:
        raise PermissionError("project mismatch")
