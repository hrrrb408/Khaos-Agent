#!/usr/bin/env python3
"""Machine-verify the production runtime composition (M6.9 BATCH 10).

Builds a REAL production runtime (the same factory the CLI and the
compose agent use — no dev mode, no injected test components) and
verifies the exact component types plus the absence of every forbidden
fallback component, emitting a digest-bound composition manifest.

This is the runtime half of the three-layer evidence model:

1. static production import reachability (generate_production_reachability),
2. runtime composition proof (this script),
3. kernel/native proofs (platform CI jobs).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path


async def _build_and_verify(output: Path) -> int:
    if os.environ.get("KHAOS_DEV_MODE") == "1":
        print("composition proof refuses KHAOS_DEV_MODE=1", file=sys.stderr)
        return 1
    from khaos.db.database import Database
    from khaos.runtime import ProductionRuntimeConfig, build_production_runtime
    from khaos.security.production_composition_manifest import (
        verify_runtime_composition,
    )

    with tempfile.TemporaryDirectory(prefix="khaos-composition-") as tmp:
        db = Database(Path(tmp) / "composition.db")
        await db.connect()
        await db.run_migrations()
        runtime = None
        try:
            runtime = await build_production_runtime(
                ProductionRuntimeConfig(
                    db=db,
                    principal_id="composition-proof",
                    source_transport="cli",
                    foreground_session=False,
                    project_id="composition-proof",
                )
            )
            manifest = verify_runtime_composition(runtime)
        finally:
            if runtime is not None:
                from khaos.runtime import close_runtime_or_register

                await close_runtime_or_register(runtime)
            await db.close()
    payload = manifest.to_payload()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    if not manifest.valid:
        for error in manifest.errors:
            print(f"composition violation: {error}", file=sys.stderr)
        return 1
    print(f"production composition verified: {len(manifest.components)} components")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("docs/generated/production-composition.json"),
    )
    args = parser.parse_args(argv)
    return asyncio.run(_build_and_verify(args.output))


if __name__ == "__main__":
    raise SystemExit(main())
