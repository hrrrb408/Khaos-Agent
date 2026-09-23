"""Typed runtime profile contract with a narrow legacy compatibility edge."""

from __future__ import annotations

import os
from enum import Enum


class RuntimeProfile(str, Enum):
    """Immutable security semantics selected for one runtime composition."""

    # ``LOCAL`` is the supported single-user desktop composition. It keeps
    # the in-process policy, workspace, approval, execution, verification and
    # completion boundaries, but does not require the independently deployed
    # production authority/control plane.
    LOCAL = "local"
    PRODUCTION = "production"
    DEVELOPMENT = "development"
    TESTING = "testing"

    @property
    def is_production(self) -> bool:
        """Return whether production security boundaries are mandatory."""
        return self is RuntimeProfile.PRODUCTION

    @property
    def is_local(self) -> bool:
        """Return whether this is the lightweight single-user composition."""
        return self is RuntimeProfile.LOCAL


def resolve_legacy_runtime_profile() -> RuntimeProfile:
    """Translate the legacy environment switch at one compatibility edge."""
    return (
        RuntimeProfile.TESTING
        if os.environ.get("KHAOS_DEV_MODE") == "1"
        else RuntimeProfile.PRODUCTION
    )


def resolve_runtime_profile(
    profile: RuntimeProfile | str | None,
) -> RuntimeProfile:
    """Resolve an explicit profile, using legacy input only when absent."""
    if profile is None:
        return resolve_legacy_runtime_profile()
    if isinstance(profile, RuntimeProfile):
        return profile
    try:
        return RuntimeProfile(profile)
    except ValueError as exc:
        raise ValueError(f"unknown runtime profile: {profile!r}") from exc
