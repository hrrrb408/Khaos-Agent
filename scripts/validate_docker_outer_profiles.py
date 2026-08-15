#!/usr/bin/env python3
"""Validate Docker outer-profile attestation before production Compose."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))

from khaos.security.docker_profiles import (
    DockerProfileValidationError,
    validate_disposable_environment,
    validate_profile_manifest,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--manifest",
        type=Path,
        help="JSON manifest containing exact options and profile SHA-256 values",
    )
    parser.add_argument(
        "--disposable",
        action="store_true",
        help="allow explicit temporary CI outer profiles; never use for production",
    )
    args = parser.parse_args()
    try:
        if args.disposable:
            validate_disposable_environment()
            print("validated disposable Docker outer-profile options")
            return 0
        if args.manifest is None:
            parser.error("--manifest is required for production validation")
        digest = validate_profile_manifest(args.manifest)
    except DockerProfileValidationError as error:
        parser.error(str(error))
    print(f"validated Docker outer-profile manifest sha256={digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
