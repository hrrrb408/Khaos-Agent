"""Explicit authority transport and deployment-profile selection.

The authority protocol is shared by every platform, but its *transport* is a
deployment decision.  Keeping that decision in one small module prevents the
client, daemon, and composition code from independently inferring transport
from ``sys.platform``.  In particular, macOS community installations use a
private Unix socket and do not require Apple code-signing material; the
native launchd/XPC path remains available only through the explicit
``native-production`` profile.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING

from khaos.runtime_profile import RuntimeProfile, resolve_runtime_profile
from khaos.security.local_trust import (
    LocalTrustRootError,
    local_authority_root,
    validate_trusted_local_path,
)
from khaos.security.production_trust import (
    ProductionTrustBinding,
    ProductionTrustError,
    deployment_environment_digest,
)

if TYPE_CHECKING:
    from khaos.security.authorityd_protocol import AuthorityDaemonClient
    from khaos.security.identity_isolation import AuthorityIdentityContract


class AuthorityTransportError(ValueError):
    """The authority deployment profile or transport is invalid."""


class ClosureStatus(str, Enum):
    """Machine-readable status vocabulary for deployment-profile evidence."""

    PASS = "pass"
    FAIL = "fail"
    BLOCKED_EXTERNAL = "blocked_external"
    NOT_APPLICABLE = "not_applicable"
    NOT_RUN = "not_run"
    OPTIONAL_PROFILE_NOT_ENABLED = "optional_profile_not_enabled"


class AuthorityProfile(str, Enum):
    """Supported deployment profiles."""

    COMMUNITY = "community"
    NATIVE_PRODUCTION = "native-production"


class AuthorityTransport(str, Enum):
    """Wire transports understood by the Python authority client/daemon."""

    UNIX = "unix"
    NATIVE = "native"


def _is_windows_platform(platform_name: str) -> bool:
    """Return whether a platform label uses the Windows transport family."""

    return platform_name.startswith(("win", "cygwin", "msys"))


@dataclass(frozen=True, slots=True)
class AuthorityTransportConfig:
    """Validated transport selection shared by all authority entrypoints."""

    profile: AuthorityProfile
    transport: AuthorityTransport
    platform_name: str
    os_name: str
    runtime_profile: RuntimeProfile = RuntimeProfile.PRODUCTION

    @classmethod
    def from_environment(
        cls,
        *,
        platform_name: str | None = None,
        os_name: str | None = None,
        runtime_profile: RuntimeProfile | str | None = None,
    ) -> AuthorityTransportConfig:
        """Resolve the explicit profile without probing or inventing secrets.

        macOS defaults to the community profile because an unsigned local
        installation is the supported baseline.  Linux and Windows preserve
        their existing production identity requirements unless an operator
        explicitly selects another profile.  An explicit unknown value is
        always rejected.
        """

        current_platform = sys.platform if platform_name is None else platform_name
        resolved_runtime_profile = resolve_runtime_profile(runtime_profile)
        current_os = (
            ("nt" if _is_windows_platform(current_platform) else "posix")
            if os_name is None
            else os_name
        )
        platform_is_windows = _is_windows_platform(current_platform)
        if os_name is not None and platform_is_windows != (current_os == "nt"):
            raise AuthorityTransportError(
                "authority platform and OS family are inconsistent"
            )
        if platform_is_windows:
            supported_platform = True
        else:
            supported_platform = current_platform == "darwin" or current_platform.startswith(
                "linux"
            )
        if not supported_platform:
            raise AuthorityTransportError(
                f"authority transport is unsupported on platform {current_platform!r}"
            )
        raw_profile = os.environ.get("KHAOS_AUTHORITY_PROFILE", "").strip()
        if raw_profile:
            try:
                profile = AuthorityProfile(raw_profile)
            except ValueError as exc:
                allowed = ", ".join(profile.value for profile in AuthorityProfile)
                raise AuthorityTransportError(
                    f"KHAOS_AUTHORITY_PROFILE must be one of: {allowed}"
                ) from exc
        elif current_platform == "darwin":
            profile = AuthorityProfile.COMMUNITY
        else:
            profile = AuthorityProfile.NATIVE_PRODUCTION

        if profile is AuthorityProfile.COMMUNITY:
            if platform_is_windows:
                raise AuthorityTransportError(
                    "the community authority profile requires a Unix socket; "
                    "Windows must use native-production"
                )
            transport = AuthorityTransport.UNIX
        elif platform_is_windows or current_platform == "darwin":
            transport = AuthorityTransport.NATIVE
        else:
            # Linux keeps the existing dedicated-UID Unix backend.  It is a
            # Unix transport, but not the same-user community profile.
            transport = AuthorityTransport.UNIX

        return cls(
            profile=profile,
            transport=transport,
            platform_name=current_platform,
            os_name=current_os,
            runtime_profile=resolved_runtime_profile,
        )

    @property
    def is_community(self) -> bool:
        """Whether this is the personal/community deployment profile."""

        return self.profile is AuthorityProfile.COMMUNITY

    @property
    def is_native(self) -> bool:
        """Whether the platform-native frontend is part of the boundary."""

        return self.transport is AuthorityTransport.NATIVE

    def validate_contract(self, contract: AuthorityIdentityContract) -> None:
        """Validate identity fields for this profile and transport."""

        contract.validate(
            production=True,
            transport=self.transport.value,
            profile=self.profile.value,
        )

    def socket_path(self) -> Path:
        """Return the configured absolute Unix socket for this transport."""

        value = os.environ.get("KHAOS_AUTHORITYD_SOCKET", "").strip()
        if not value and self.is_community:
            value = str(local_authority_root() / "authorityd.sock")
        if not value:
            raise AuthorityTransportError(
                "KHAOS_AUTHORITYD_SOCKET is required for the Unix authority transport"
            )
        path = Path(value).expanduser()
        if not path.is_absolute():
            raise AuthorityTransportError(
                "KHAOS_AUTHORITYD_SOCKET must be an absolute path"
            )
        if self.is_community and self.runtime_profile.is_production:
            try:
                path = validate_trusted_local_path(
                    path,
                    kind="socket",
                    root=local_authority_root(),
                    allow_missing=True,
                )
            except LocalTrustRootError as exc:
                raise AuthorityTransportError(str(exc)) from exc
        return path

    def public_key_path(self) -> Path | None:
        """Return the receipt trust anchor for a Unix authority transport."""

        value = os.environ.get("KHAOS_AUTHORITYD_PUBLIC_KEY_PATH", "").strip()
        if not value and self.is_community:
            value = str(local_authority_root() / "authorityd.pub")
        if not value:
            return None
        path = Path(value).expanduser()
        if not path.is_absolute():
            raise AuthorityTransportError(
                "KHAOS_AUTHORITYD_PUBLIC_KEY_PATH must be an absolute path"
            )
        if self.is_community and self.runtime_profile.is_production:
            try:
                path = validate_trusted_local_path(
                    path,
                    kind="file",
                    root=local_authority_root(),
                    allow_missing=True,
                )
            except LocalTrustRootError as exc:
                raise AuthorityTransportError(str(exc)) from exc
        return path

    def expected_authority_uid(
        self, contract: AuthorityIdentityContract
    ) -> int | None:
        """Return the socket owner expected by the client-side admission gate."""

        if contract.authority_uid is not None:
            return contract.authority_uid
        if self.is_community:
            # Community authorityd is a separate process, but intentionally
            # remains same-user on a personal machine.  The private socket,
            # kernel peer UID, signed receipts, and policy scope remain in
            # force; a different local OS user is not claimed to be isolated.
            return os.geteuid()
        return None

    def authority_id(self) -> str:
        """Return the operator-selected authority identity for this profile."""
        configured = os.environ.get("KHAOS_AUTHORITYD_ISSUER_ID", "").strip()
        if configured:
            return configured
        return (
            "khaos-authorityd-community"
            if self.is_community
            else "khaos-authorityd"
        )

    def environment_digest(self) -> str:
        """Return the canonical platform/transport deployment digest."""
        configured = os.environ.get(
            "KHAOS_AUTHORITYD_ENVIRONMENT_DIGEST", ""
        ).strip()
        if configured:
            return configured
        return deployment_environment_digest(
            platform_name=self.platform_name,
            profile=self.profile.value,
            transport=self.transport.value,
        )

    def client(
        self,
        contract: AuthorityIdentityContract,
        *,
        trust_binding: ProductionTrustBinding | None = None,
    ) -> AuthorityDaemonClient:
        """Build the one client shape allowed by this deployment profile."""

        from khaos.security.authorityd_protocol import AuthorityDaemonClient

        if trust_binding is not None:
            if trust_binding.authority_id != self.authority_id():
                raise AuthorityTransportError(
                    "authority trust binding identity does not match the deployment"
                )
            try:
                if trust_binding.environment_digest != self.environment_digest():
                    raise AuthorityTransportError(
                        "authority trust binding environment does not match the deployment"
                    )
            except ProductionTrustError as exc:
                raise AuthorityTransportError(
                    "authority trust binding environment is invalid"
                ) from exc
            if self.runtime_profile.is_production and self.public_key_path() is None:
                raise AuthorityTransportError(
                    "production authority trust handshake requires a public key"
                )

        if self.is_native:
            from khaos.security.native_authority import (
                build_native_authority_adapter,
            )

            adapter = build_native_authority_adapter(
                production=True,
                contract=contract,
            )
            return AuthorityDaemonClient(
                expected_authority_uid=self.expected_authority_uid(contract),
                native_adapter=adapter,
                transport=self.transport.value,
                runtime_profile=self.runtime_profile,
                public_key_path=self.public_key_path(),
                trust_binding=trust_binding,
            )

        socket_path = self.socket_path()
        return AuthorityDaemonClient(
            socket_path,
            expected_authority_uid=self.expected_authority_uid(contract),
            public_key_path=self.public_key_path(),
            trusted_local_root=(
                local_authority_root()
                if self.is_community and self.runtime_profile.is_production
                else None
            ),
            transport=self.transport.value,
            runtime_profile=self.runtime_profile,
            trust_binding=trust_binding,
            community_local=self.is_community,
        )


__all__ = [
    "AuthorityProfile",
    "AuthorityTransport",
    "AuthorityTransportConfig",
    "AuthorityTransportError",
    "ClosureStatus",
]
