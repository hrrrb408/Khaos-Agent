"""Production entrypoint for the independent authority daemon."""

from __future__ import annotations

import os
import stat
from pathlib import Path, PureWindowsPath

from khaos.security.authority_transport import (
    AuthorityProfile,
    AuthorityTransportConfig,
)
from khaos.security.authorityd import (
    JsonlAuditWriter,
    build_local_daemon,
    build_production_daemon,
    serve_unix,
)
from khaos.security.authorityd_protocol import _O_BINARY
from khaos.security.identity_isolation import read_contract_from_environment
from khaos.security.local_trust import (
    LocalTrustRootError,
    local_authority_root,
    validate_trusted_local_path,
)
from khaos.security.remote_audit import writer_from_environment
from khaos.security.resource_scope import ResourceScopeError, TypedResourcePartialOrder


def main() -> int:
    if os.environ.get("KHAOS_DEV_MODE") == "1":
        raise SystemExit("authorityd refuses to run in KHAOS_DEV_MODE")
    deployment = AuthorityTransportConfig.from_environment()
    contract = read_contract_from_environment()
    deployment.validate_contract(contract)
    transport_path = _authority_transport_path(deployment)
    key_value = os.environ.get("KHAOS_AUTHORITYD_KEY_PATH")
    if not key_value and deployment.is_community:
        key_value = str(local_authority_root() / "authorityd.pem")
    if not key_value:
        raise SystemExit(
            "KHAOS_AUTHORITYD_KEY_PATH is required"
        )
    catalog_value = os.environ.get("KHAOS_TYPED_RESOURCE_CATALOG_PATH")
    if not catalog_value:
        raise SystemExit("KHAOS_TYPED_RESOURCE_CATALOG_PATH is required")
    audit_value = os.environ.get("KHAOS_AUTHORITYD_AUDIT_PATH")
    if not audit_value and deployment.is_community:
        audit_value = str(local_authority_root() / "authorityd.audit.jsonl")
    public_key_value = os.environ.get("KHAOS_AUTHORITYD_PUBLIC_KEY_PATH")
    if not public_key_value and deployment.is_community:
        public_key_value = str(local_authority_root() / "authorityd.pub")
    if deployment.is_community:
        _validate_community_paths(
            key_path=Path(key_value),
            catalog_path=Path(catalog_value),
            audit_path=Path(audit_value or ""),
            public_key_path=Path(public_key_value or ""),
        )
    try:
        resource_order = TypedResourcePartialOrder.from_json_file(
            Path(catalog_value),
            expected_policy_digest=os.environ.get("KHAOS_EFFECTIVE_POLICY_DIGEST"),
        )
    except ResourceScopeError as exc:
        raise SystemExit(f"typed resource catalog is invalid: {exc}") from exc
    if deployment.profile is AuthorityProfile.COMMUNITY:
        audit_path = Path(
            os.environ.get(
                "KHAOS_AUTHORITYD_AUDIT_PATH",
                str(audit_value or transport_path.with_name("authorityd.audit.jsonl")),
            )
        ).expanduser()
        if not audit_path.is_absolute():
            raise SystemExit(
                "KHAOS_AUTHORITYD_AUDIT_PATH must be an absolute path"
            )
        daemon = build_local_daemon(
            socket_path=transport_path,
            key_path=Path(key_value),
            audit_writer=JsonlAuditWriter(audit_path),
            resource_order=resource_order,
        )
    else:
        daemon = build_production_daemon(
            socket_path=transport_path,
            key_path=Path(key_value),
            audit_writer=writer_from_environment(),
            resource_order=resource_order,
        )
    _publish_public_key(
        Path(public_key_value or str(transport_path.with_name("authorityd.pub"))),
        daemon.public_key_bytes,
    )
    if os.name == "nt":
        # Windows production: serve the Named-Pipe backend consumed by the
        # native Service-SID frontend.  There is no agent-reachable Unix
        # socket transport on this platform.
        from khaos.security.authorityd_windows import serve_windows_backend

        serve_windows_backend(daemon, production=True)
        return 0
    serve_unix(
        daemon,
        production=True,
        transport=deployment.transport.value,
        profile=deployment.profile.value,
    )
    return 0


def _authority_transport_value(*, platform_name: str | None = None) -> str:
    """Return the selected authority backend transport identifier."""
    current_platform = os.name if platform_name is None else platform_name
    if current_platform == "nt":
        value = os.environ.get("KHAOS_AUTHORITYD_BACKEND_PIPE", "")
        if not value or not value.startswith("\\\\.\\pipe\\"):
            raise SystemExit(
                "KHAOS_AUTHORITYD_BACKEND_PIPE must be a local named pipe"
            )
        if not PureWindowsPath(value).is_absolute():
            raise SystemExit(
                "KHAOS_AUTHORITYD_BACKEND_PIPE must be an absolute named pipe"
            )
        return value
    value = os.environ.get("KHAOS_AUTHORITYD_SOCKET", "")
    if not value:
        raise SystemExit("KHAOS_AUTHORITYD_SOCKET is required")
    return value


def _authority_transport_path(
    deployment: AuthorityTransportConfig | None = None,
) -> Path:
    """Build the absolute path object used by the daemon transport boundary."""
    if deployment is not None and not deployment.is_native:
        value = str(deployment.socket_path())
    else:
        value = _authority_transport_value()
    path = Path(value)
    if not path.is_absolute():
        raise SystemExit("authorityd transport path must be absolute")
    return path


def _validate_community_paths(
    *,
    key_path: Path,
    catalog_path: Path,
    audit_path: Path,
    public_key_path: Path,
) -> None:
    """Reject project-controlled authority inputs in the local profile."""

    root = local_authority_root()
    try:
        validate_trusted_local_path(
            key_path, kind="file", root=root, allow_missing=True
        )
        validate_trusted_local_path(catalog_path, kind="file", root=root)
        validate_trusted_local_path(
            audit_path, kind="file", root=root, allow_missing=True
        )
        validate_trusted_local_path(
            public_key_path, kind="file", root=root, allow_missing=True
        )
    except LocalTrustRootError as exc:
        raise SystemExit(f"Community authority path is not trusted: {exc}") from exc


def _publish_public_key(path: Path, payload: bytes) -> None:
    """Publish an immutable public trust anchor for the agent client."""
    path = path.expanduser().absolute()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        info = path.lstat()
    except FileNotFoundError:
        info = None
    except OSError as exc:
        raise SystemExit("authorityd public key cannot be inspected") from exc
    if info is not None:
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise SystemExit("authorityd public key is not a regular file")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | _O_BINARY)
        try:
            existing = os.read(descriptor, len(payload) + 1)
        finally:
            os.close(descriptor)
        if existing != payload:
            raise SystemExit("authorityd public key changed unexpectedly")
        return
    descriptor = os.open(
        path,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | _O_BINARY,
        0o644,
    )
    try:
        written = 0
        while written < len(payload):
            count = os.write(descriptor, payload[written:])
            if count <= 0:
                raise OSError("authorityd public-key write made no progress")
            written += count
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


if __name__ == "__main__":
    raise SystemExit(main())
