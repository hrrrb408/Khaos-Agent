"""Issue short-lived leases owned by a project."""

from dataclasses import dataclass


@dataclass(frozen=True)
class AuthorityLease:
    """A lease that is valid only for its owning project."""

    project_id: str
    active: bool = True


def issue_lease(project_id: str) -> AuthorityLease:
    """Create an active lease for one project."""

    return AuthorityLease(project_id=project_id)
