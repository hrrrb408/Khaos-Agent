#!/usr/bin/env python3
"""Run a real TLS append-only WORM audit receiver for CI deployments.

The production authority daemon refuses to operate without a remote
HTTPS WORM endpoint.  This receiver gives CI a genuinely TLS-verified,
append-only audit sink: it generates a runner-local CA, serves HTTPS on
localhost, appends every record to a write-once directory (files are
created exclusively and never rewritten), and returns non-2xx on any
attempt to rewrite.  The CA is installed into the runner's system trust
store by the workflow so the production ``RemoteWormAuditWriter`` (which
uses the default CA bundle) verifies the connection normally.

This is CI evidence infrastructure, not a production audit service: the
closure report never treats the CI WORM as production audit evidence.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import http.server
import ipaddress
import json
import os
import ssl
import tempfile
from pathlib import Path


def _generate_ca(ca_cert: Path, ca_key: Path) -> None:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "khaos-ci-worm-ca")])
    now = datetime.datetime.now(datetime.UTC)
    # Strict OpenSSL chain verification (Python 3.13's, and
    # `openssl verify -x509_strict`) requires a CA that carries a path
    # length to also assert the keyCertSign key usage, and rejects CAs
    # without an Authority Key Identifier.  Emit a fully RFC 5280
    # compliant CA so the TLS-verified WORM submission path works on
    # every supported platform.
    ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(hours=12))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(ski, critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    ca_cert.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    ca_key.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )


def _generate_server_cert(
    ca_cert: Path, ca_key: Path, cert: Path, key: Path
) -> None:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    ca = x509.load_pem_x509_certificate(ca_cert.read_bytes())
    ca_private = serialization.load_pem_private_key(ca_key.read_bytes(), password=None)
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(hours=12))
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(server_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca.public_key()),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .sign(ca_private, hashes.SHA256())
    )
    cert.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key.write_bytes(
        server_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )


class _WormHandler(http.server.BaseHTTPRequestHandler):
    directory: Path = Path("/tmp/khaos-worm-records")

    def do_POST(self) -> None:
        if self.path != "/append":
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > 1024 * 1024:
            self.send_error(413)
            return
        body = self.rfile.read(length)
        try:
            record = json.loads(body.decode("utf-8"))
            digest = record.get("record_digest")
            if not isinstance(digest, str) or len(digest) != 64:
                raise ValueError("record digest is malformed")
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            self.send_error(400)
            return
        # Append-only: each record is a new exclusively-created file.  A
        # digest replay is rejected with 409, matching a WORM policy.
        target = self.directory / f"{digest}.json"
        try:
            descriptor = os.open(
                target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400
            )
        except FileExistsError:
            self.send_error(409)
            return
        except OSError:
            self.send_error(500)
            return
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
        self.send_response(204)
        self.end_headers()

    def do_GET(self) -> None:
        # The receiver exposes only liveness; audit content never leaves
        # the runner.
        if self.path == "/healthz":
            self.send_response(204)
            self.end_headers()
            return
        self.send_error(404)

    def log_message(self, format: str, *args: object) -> None:
        # Keep CI logs small: record the digest-relevant fact only.
        print(
            f"worm: {self.address_string()} "
            f"{hashlib.sha1(format.encode()).hexdigest()[:8]}",
            flush=True,
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--emit-ca", type=Path, default=None)
    args = parser.parse_args()
    args.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="khaos-worm-tls-") as tmp:
        tls = Path(tmp)
        ca_cert = tls / "ca.pem"
        ca_key = tls / "ca-key.pem"
        server_cert = tls / "server.pem"
        server_key = tls / "server-key.pem"
        _generate_ca(ca_cert, ca_key)
        _generate_server_cert(ca_cert, ca_key, server_cert, server_key)
        if args.emit_ca is not None:
            args.emit_ca.write_bytes(ca_cert.read_bytes())
        handler = type(
            "_BoundWormHandler", (_WormHandler,), {"directory": args.directory}
        )
        server = http.server.ThreadingHTTPServer(("127.0.0.1", args.port), handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(server_cert), str(server_key))
        server.socket = context.wrap_socket(server.socket, server_side=True)
        print(
            f"worm receiver listening on https://localhost:{args.port}/append",
            flush=True,
        )
        # Serve until the workflow tears the job down.
        try:
            server.serve_forever()
        finally:
            server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
