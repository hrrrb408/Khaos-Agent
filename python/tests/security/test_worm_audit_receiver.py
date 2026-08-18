"""CI WORM audit receiver tests (M6.9 BATCH 6).

The production authority daemon refuses to run without a remote HTTPS WORM
endpoint.  CI deployments use this receiver as a genuinely TLS-verified,
append-only sink: records are written exclusively once, replays are
rejected with 409, and malformed records never reach the directory.
"""

from __future__ import annotations

import hashlib
import http.server
import importlib.util
import ssl
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest
from khaos.security.protocol_boundary import canonical_json_bytes

_SCRIPT = (
    Path(__file__).resolve().parents[2].parent / "scripts" / "run_worm_audit_receiver.py"
)


def _module():
    spec = importlib.util.spec_from_file_location("worm_receiver", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def worm_server(tmp_path: Path):
    module = _module()
    tls = tmp_path / "tls"
    tls.mkdir()
    ca_cert = tls / "ca.pem"
    ca_key = tls / "ca-key.pem"
    server_cert = tls / "server.pem"
    server_key = tls / "server-key.pem"
    module._generate_ca(ca_cert, ca_key)
    module._generate_server_cert(ca_cert, ca_key, server_cert, server_key)
    records = tmp_path / "records"
    records.mkdir()
    handler = type("_H", (module._WormHandler,), {"directory": records})
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    port = server.server_address[1]
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(server_cert), str(server_key))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    client_context = ssl.create_default_context(cafile=str(ca_cert))
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=client_context),
    )
    try:
        yield {"port": port, "opener": opener, "records": records}
    finally:
        server.shutdown()
        server.server_close()


def _append(worm_server, record: dict) -> int:
    body = canonical_json_bytes(
        {
            "schema_version": 1,
            "record": record,
            "record_digest": hashlib.sha256(
                canonical_json_bytes(record)
            ).hexdigest(),
        }
    )
    request = urllib.request.Request(
        f"https://127.0.0.1:{worm_server['port']}/append",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with worm_server["opener"].open(request, timeout=10) as response:
            return response.status
    except urllib.error.HTTPError as exc:
        return exc.code


def test_worm_append_once_and_reject_replay(worm_server) -> None:
    record = {"kind": "authority.grant", "grant_id": "g1"}
    assert _append(worm_server, record) == 204
    # The same record digest is a replay: WORM rejects it.
    assert _append(worm_server, record) == 409
    stored = list(worm_server["records"].iterdir())
    assert len(stored) == 1


def test_worm_rejects_malformed_records(worm_server) -> None:
    request = urllib.request.Request(
        f"https://127.0.0.1:{worm_server['port']}/append",
        data=b'{"schema_version":1,"record":{},"record_digest":"short"}',
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with worm_server["opener"].open(request, timeout=10) as response:
            status = response.status
    except urllib.error.HTTPError as exc:
        status = exc.code
    assert status == 400
    assert not list(worm_server["records"].iterdir())


def test_worm_health_and_audit_content_stay_local(worm_server) -> None:
    with worm_server["opener"].open(
        f"https://127.0.0.1:{worm_server['port']}/healthz", timeout=10
    ) as response:
        assert response.status == 204
    try:
        worm_server["opener"].open(
            f"https://127.0.0.1:{worm_server['port']}/records", timeout=10
        )
        status = 200
    except urllib.error.HTTPError as exc:
        status = exc.code
    assert status == 404
