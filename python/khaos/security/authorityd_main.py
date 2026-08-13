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
    serve_unix(daemon, production=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
