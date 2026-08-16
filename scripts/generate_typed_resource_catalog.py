#!/usr/bin/env python3
"""Generate a host-reviewed typed resource catalog for one project root.

The generated file is an input to both the production Agent runtime and the
independent authority daemon.  It is intentionally explicit: adding another
repository, executable, network origin, or credential requires a new reviewed
catalog rather than silently falling back to an opaque resource hash.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from khaos.security.effective_policy import load_effective_policy
from khaos.security.resource_scope import ResourceScopeError


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace-root", type=Path, required=True)
    parser.add_argument("--policy-digest", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    workspace_root = args.workspace_root.expanduser().resolve(strict=True)
    if not workspace_root.is_dir():
        raise SystemExit("workspace root must be a directory")
    try:
        policy = load_effective_policy(workspace_root)
    except (OSError, ResourceScopeError, ValueError) as exc:
        raise SystemExit(f"effective policy cannot be compiled: {exc}") from exc
    if policy.digest != args.policy_digest:
        raise SystemExit(
            "policy digest does not match the compiled effective policy: "
            f"{policy.digest}"
        )
    catalog = policy.resource_order
    if catalog is None:
        raise SystemExit("effective policy did not compile a typed resource catalog")
    args.output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if args.output.exists() or args.output.is_symlink():
        raise SystemExit(f"refusing to overwrite existing catalog: {args.output}")
    args.output.write_text(
        json.dumps(catalog.manifest(), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    args.output.chmod(0o444)
    print(catalog.catalog_digest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
