"""Production entrypoint for the independent authority daemon."""

from __future__ import annotations

import os
from pathlib import Path

from khaos.security.authorityd import build_production_daemon, serve_unix
from khaos.security.identity_isolation import read_contract_from_environment
from khaos.security.remote_audit import writer_from_environment


def main() -> int:
    if os.environ.get("KHAOS_DEV_MODE") == "1":
        raise SystemExit("authorityd refuses to run in KHAOS_DEV_MODE")
    contract = read_contract_from_environment()
    contract.validate(production=True)
    socket_value = os.environ.get("KHAOS_AUTHORITYD_SOCKET")
    key_value = os.environ.get("KHAOS_AUTHORITYD_KEY_PATH")
    if not socket_value or not key_value:
        raise SystemExit(
            "KHAOS_AUTHORITYD_SOCKET and KHAOS_AUTHORITYD_KEY_PATH are required"
        )
    daemon = build_production_daemon(
        socket_path=Path(socket_value),
        key_path=Path(key_value),
        audit_writer=writer_from_environment(),
    )
    _publish_public_key(
        Path(os.environ.get(
            "KHAOS_AUTHORITYD_PUBLIC_KEY_PATH",
            str(Path(socket_value).with_name("authorityd.pub")),
        )),
        daemon.public_key_bytes,
    )
    serve_unix(daemon, production=True)
    return 0


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
