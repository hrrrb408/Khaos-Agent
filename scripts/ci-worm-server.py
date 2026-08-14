#!/usr/bin/env python3
"""Minimal HTTPS append-only WORM fixture for the production compose gate.

This is a CI fixture, not a deployable audit service.  Its only purpose is to
make the compose test exercise the real HTTPS writer and authorityd lifecycle
instead of a health-only placeholder.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

MAX_BODY_BYTES = 1024 * 1024


class _Store:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.lock = threading.Lock()
        self.keys: set[str] = set()

    def append(self, key: str, payload: dict[str, object]) -> bool:
        with self.lock:
            if key in self.keys:
                return False
            self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            line = json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"
            with self.path.open("a", encoding="utf-8") as output:
                output.write(line)
                output.flush()
                import os

                os.fsync(output.fileno())
            self.keys.add(key)
            return True


def _handler(store: _Store) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "khaos-ci-worm/1"

        def do_GET(self) -> None:
            if self.path != "/healthz":
                self.send_error(404)
                return
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok\n")

        def do_POST(self) -> None:
            if self.path != "/ci-worm-audit":
                self.send_error(404)
                return
            key = self.headers.get("Idempotency-Key", "")
            if len(key) != 64 or any(character not in "0123456789abcdef" for character in key):
                self.send_error(400, "invalid idempotency key")
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self.send_error(400, "invalid content length")
                return
            if not 0 < length <= MAX_BODY_BYTES:
                self.send_error(413)
                return
            try:
                raw = self.rfile.read(length)
                payload = json.loads(raw.decode("utf-8"))
                if not isinstance(payload, dict):
                    raise ValueError("payload is not a mapping")
                record = payload["record"]
                record_digest = payload["record_digest"]
                if not isinstance(record, dict) or not isinstance(record_digest, str):
                    raise ValueError("record envelope is malformed")
                if hashlib.sha256(
                    json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
                ).hexdigest() != record_digest:
                    raise ValueError("record digest mismatch")
            except (KeyError, TypeError, ValueError, UnicodeError, json.JSONDecodeError) as exc:
                self.send_error(400, str(exc))
                return
            store.append(key, payload)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"accepted\n")

        def log_message(self, _format: str, *_args: object) -> None:
            return

    return Handler


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9443)
    parser.add_argument("--cert", required=True, type=Path)
    parser.add_argument("--key", required=True, type=Path)
    parser.add_argument("--store", required=True, type=Path)
    args = parser.parse_args()
    store = _Store(args.store)
    server = ThreadingHTTPServer((args.bind, args.port), _handler(store))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(args.cert, args.key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
