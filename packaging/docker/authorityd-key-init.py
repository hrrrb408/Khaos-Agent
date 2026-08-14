#!/usr/bin/env python3
"""Create the authorityd key once and publish its public trust anchor.

The private key stays in the authorityd state volume.  The public key is
placed in the separate runtime volume so the agent can read it without being
able to write or replace the signer key.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from khaos.security.authorityd_protocol import Ed25519KeyStore


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--key", type=Path, required=True)
    parser.add_argument("--public", type=Path, required=True)
    parser.add_argument("--uid", type=int, default=None)
    parser.add_argument("--gid", type=int, default=None)
    args = parser.parse_args()

    key = Ed25519KeyStore.load_or_create(args.key, create=True)
    public_key = key.public_key().public_bytes_raw()
    args.public.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    if args.public.exists():
        current = args.public.read_bytes()
        if current != public_key:
            raise SystemExit("authorityd public key changed unexpectedly")
    else:
        descriptor = os.open(
            args.public,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o644,
        )
        try:
            os.write(descriptor, public_key)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    if args.uid is not None:
        os.chown(args.key, args.uid, args.gid if args.gid is not None else -1)
        os.chown(args.public, args.uid, args.gid if args.gid is not None else -1)
    os.chmod(args.key, 0o600)
    os.chmod(args.public, 0o644)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
