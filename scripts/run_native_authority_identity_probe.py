#!/usr/bin/env python3
"""Run the real platform-native authority *identity* probe.

This proves only the native transport identity chain: the launchd/XPC or
Windows Service-SID/Named-Pipe deployment exists, the peer identity is
verified, the transport is verified, and the protected key is configured.
It is deliberately NOT a full production E2E: it does not prove that the
authority backend executed a transaction.  Use
``scripts/run_native_authority_e2e.py`` for that.

The command intentionally has no mock mode.  It exits non-zero when the
native deployment is absent or when a proof field is incomplete.
"""

from __future__ import annotations

import json
import sys
from dataclasses import asdict

from khaos.security.identity_isolation import read_contract_from_environment
from khaos.security.native_authority import build_native_authority_adapter


def main() -> int:
    try:
        adapter = build_native_authority_adapter(
            production=True,
            contract=read_contract_from_environment(),
        )
    except Exception as exc:  # noqa: BLE001 - CLI must turn every missing proof into failure
        print(f"native authority identity probe failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 78
    print(json.dumps(asdict(adapter.proof), sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
