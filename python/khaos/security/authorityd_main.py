"""Production entrypoint for the independent authority daemon."""

from __future__ import annotations

import os
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
from khaos.security.identity_isolation import read_contract_from_environment
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
    if not key_value:
        raise SystemExit(
            "KHAOS_AUTHORITYD_KEY_PATH is required"
        )
    catalog_value = os.environ.get("KHAOS_TYPED_RESOURCE_CATALOG_PATH")
    if not catalog_value:
        raise SystemExit("KHAOS_TYPED_RESOURCE_CATALOG_PATH is required")
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
                str(transport_path.with_name("authorityd.audit.jsonl")),
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
        Path(os.environ.get(
            "KHAOS_AUTHORITYD_PUBLIC_KEY_PATH",
            str(transport_path.with_name("authorityd.pub")),
        )),
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
    value = _authority_transport_value()
    if deployment is not None and not deployment.is_native:
        value = str(deployment.socket_path())
    path = Path(value)
    if not path.is_absolute():
        raise SystemExit("authorityd transport path must be absolute")
    return path


def _publish_public_key(path: Path, payload: bytes) -> None:
    """Publish an immutable public trust anchor for the agent client."""
    path = path.expanduser().absolute()
    path.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    if path.exists():
        if path.read_bytes() != payload:
            raise SystemExit("authorityd public key changed unexpectedly")
        return
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
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
