"""Consumer-side use of the authority lease."""

from .authority import AuthorityLease


def consume_lease(lease: AuthorityLease, project_id: str) -> str:
    """Return a project-scoped operation marker for an active lease."""

    if not lease.active or lease.project_id != project_id:
        raise PermissionError("lease is not active for this project")
    return f"operation:{project_id}"
