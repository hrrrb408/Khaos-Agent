#!/usr/bin/env python3
"""Run the real platform-native authority probe.

This command intentionally has no mock mode.  It exits non-zero when the
launchd/XPC or Windows Service-SID/Named-Pipe deployment is absent or when a
proof field is incomplete.  The output is suitable for an uploaded CI
artifact, but the caller must still bind it to the exact commit and run.
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
        print(f"native authority probe failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 78
    print(json.dumps(asdict(adapter.proof), sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
