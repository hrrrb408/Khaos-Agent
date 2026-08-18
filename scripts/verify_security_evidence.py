#!/usr/bin/env python3
"""Verify fetched security evidence manifests against the release contract.

Consumes the manifest bundle produced by ``fetch_security_evidence.py``,
re-runs full provenance verification against the expected repository,
release SHA, and release policy digest, optionally re-digests the local
artifact files, and writes a verified bundle (with an integrity digest)
for the closure report builder.  Any failure produces no verified bundle
and a non-zero exit: there is no partial verification.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from khaos.security.security_evidence import (
    SecurityEvidenceError,
    SecurityEvidenceManifest,
    build_verified_manifest,
    verify_artifact_digest,
    verify_evidence_manifests,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--policy-digest", required=True)
    parser.add_argument(
        "--artifact-root",
        type=Path,
        default=None,
        help="directory containing downloaded artifacts to re-digest",
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        bundle = json.loads(args.manifest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"manifest bundle is unreadable: {exc}", file=sys.stderr)
        return 1
    if not isinstance(bundle, dict) or not isinstance(
        bundle.get("manifests"), list
    ):
        print("manifest bundle is malformed", file=sys.stderr)
        return 1
    try:
        manifests = [
            SecurityEvidenceManifest.from_payload(payload)
            for payload in bundle["manifests"]
        ]
        verification = verify_evidence_manifests(
            manifests,
            expected_commit=args.commit,
            expected_policy_digest=args.policy_digest,
        )
        if not verification.ok:
            for error in verification.errors:
                print(f"evidence rejected: {error}", file=sys.stderr)
            return 1
        if args.artifact_root is not None:
            for manifest in manifests:
                verify_artifact_digest(args.artifact_root / f"{manifest.artifact_id}.zip", manifest)
        verified = build_verified_manifest(
            manifests, verification=verification
        )
    except SecurityEvidenceError as exc:
        print(f"evidence verification failed: {exc}", file=sys.stderr)
        return 1
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(verified, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"verified {len(manifests)} evidence manifests -> {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
