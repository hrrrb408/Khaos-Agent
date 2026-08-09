#!/usr/bin/env python3
"""Generate release checksums, an SPDX SBOM, and commit-bound metadata.

The release workflow keeps these files as GitHub Release assets instead of
depending on expiring Actions artifacts.  The official GitHub attestation
action signs the checksum subjects and the SPDX document separately.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import tomllib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


_GENERATED_NAMES = {
    "release-checksums.txt",
    "release-manifest.json",
    "release-gate-evidence.json",
    "sbom.spdx.json",
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _git_timestamp(repo_root: Path, commit: str) -> str:
    timestamp = subprocess.check_output(
        ["git", "-C", str(repo_root), "show", "-s", "--format=%ct", commit],
        text=True,
    ).strip()
    return datetime.fromtimestamp(int(timestamp), tz=timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )


def _spdx_id(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9.-]+", "-", value).strip("-")
    return cleaned or "unknown"


def _spdx_package(name: str, version: str, ecosystem: str) -> dict[str, Any]:
    package_id = f"SPDXRef-Package-{_spdx_id(ecosystem)}-{_spdx_id(name)}-{_spdx_id(version)}"
    return {
        "SPDXID": package_id,
        "name": name,
        "versionInfo": version,
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "copyrightText": "NOASSERTION",
        "externalRefs": [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": ecosystem,
                "referenceLocator": f"{name}@{version}",
            }
        ],
    }


def _locked_packages(repo_root: Path) -> list[dict[str, Any]]:
    packages: dict[tuple[str, str, str], dict[str, Any]] = {}

    uv_lock = repo_root / "uv.lock"
    uv_data = tomllib.loads(uv_lock.read_text(encoding="utf-8"))
    for package in uv_data.get("package", []):
        name = str(package.get("name", ""))
        version = str(package.get("version", ""))
        if name and version:
            packages[("PYPI", name, version)] = _spdx_package(name, version, "PYPI")

    cargo_lock = repo_root / "rust/khaos-core/Cargo.lock"
    cargo_data = tomllib.loads(cargo_lock.read_text(encoding="utf-8"))
    for package in cargo_data.get("package", []):
        name = str(package.get("name", ""))
        version = str(package.get("version", ""))
        if name and version:
            packages[("CARGO", name, version)] = _spdx_package(name, version, "CARGO")

    go_mod = (repo_root / "go/go.mod").read_text(encoding="utf-8")
    in_require_block = False
    for raw_line in go_mod.splitlines():
        line = raw_line.strip()
        if line.startswith("require ("):
            in_require_block = True
            continue
        if in_require_block and line == ")":
            in_require_block = False
            continue
        if not in_require_block and not line.startswith("require "):
            continue
        entry = line.removeprefix("require ").split("//", 1)[0].split()
        if len(entry) >= 2:
            name, version = entry[:2]
            packages[("GO-MODULE", name, version)] = _spdx_package(
                name, version, "GO-MODULE"
            )

    return [packages[key] for key in sorted(packages)]


def _build_sbom(repo_root: Path, commit: str, tag: str, lock_digests: dict[str, str]) -> dict[str, Any]:
    namespace_material = json.dumps(
        {"commit": commit, "tag": tag, "locks": lock_digests},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    namespace_hash = hashlib.sha256(namespace_material).hexdigest()
    root_package_id = "SPDXRef-Package-Khaos"
    packages = [
        {
            "SPDXID": root_package_id,
            "name": "Khaos",
            "versionInfo": tag,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "MIT",
            "licenseDeclared": "MIT",
            "copyrightText": "NOASSERTION",
        },
        *_locked_packages(repo_root),
    ]
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"Khaos-{tag}",
        "documentNamespace": f"https://khaos.dev/releases/{namespace_hash}",
        "creationInfo": {
            "created": _git_timestamp(repo_root, commit),
            "creators": ["Tool: Khaos release evidence generator"],
        },
        "documentDescribes": [root_package_id],
        "packages": packages,
    }


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--artifact-dir", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--gate-evidence", type=Path, required=True)
    return parser.parse_args()


def _load_gate_evidence(path: Path, commit: str) -> dict[str, Any]:
    """Validate the exact successful gate evidence selected for this release."""
    try:
        evidence = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"invalid release gate evidence: {exc}") from exc
    if not isinstance(evidence, dict):
        raise SystemExit("release gate evidence must be a JSON object")
    if evidence.get("schema") != "khaos.release-gate-evidence.v1":
        raise SystemExit("unsupported release gate evidence schema")
    if evidence.get("commit") != commit:
        raise SystemExit(
            f"release gate evidence commit mismatch: {evidence.get('commit')} != {commit}"
        )
    supplied_digest = evidence.get("evidence_digest")
    unsigned = dict(evidence)
    unsigned.pop("evidence_digest", None)
    if supplied_digest != _canonical_digest(unsigned):
        raise SystemExit("release gate evidence digest mismatch")
    gates = evidence.get("gates")
    if not isinstance(gates, dict):
        raise SystemExit("release gate evidence has no gate records")
    required = {
        "security_closure": "security-closure-gate.yml",
        "product_integrity": "product-integrity-gate.yml",
    }
    for name, workflow in required.items():
        record = gates.get(name)
        if not isinstance(record, dict):
            raise SystemExit(f"missing required release gate: {name}")
        if (
            record.get("workflow") != workflow
            or record.get("head_sha") != commit
            or record.get("status") != "completed"
            or record.get("conclusion") != "success"
        ):
            raise SystemExit(f"required release gate is not successful: {name}")
    return evidence


def _canonical_digest(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def main() -> int:
    args = _parse_args()
    repo_root = args.repo_root.resolve()
    artifact_dir = args.artifact_dir.resolve()
    artifact_dir.mkdir(parents=True, exist_ok=True)
    gate_evidence_path = args.gate_evidence.resolve()
    gate_evidence = _load_gate_evidence(gate_evidence_path, args.commit)

    actual_commit = subprocess.check_output(
        ["git", "-C", str(repo_root), "rev-parse", "HEAD"], text=True
    ).strip()
    if actual_commit != args.commit:
        raise SystemExit(
            f"release evidence commit mismatch: HEAD={actual_commit} expected={args.commit}"
        )

    lock_paths = (
        repo_root / "uv.lock",
        repo_root / "go/go.mod",
        repo_root / "rust/khaos-core/Cargo.lock",
    )
    lock_digests = {
        str(path.relative_to(repo_root)): _sha256(path) for path in lock_paths
    }
    sbom = _build_sbom(repo_root, args.commit, args.tag, lock_digests)
    sbom_path = artifact_dir / "sbom.spdx.json"
    sbom_path.write_text(json.dumps(sbom, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    artifacts = sorted(
        path for path in artifact_dir.iterdir() if path.is_file() and path.name not in _GENERATED_NAMES
    )
    if not artifacts:
        raise SystemExit("release evidence requires at least one release artifact")
    artifact_records = [
        {"name": path.name, "sha256": _sha256(path), "bytes": path.stat().st_size}
        for path in artifacts
    ]
    checksums_path = artifact_dir / "release-checksums.txt"
    checksums_path.write_text(
        "".join(f"{record['sha256']}  {record['name']}\n" for record in artifact_records),
        encoding="utf-8",
    )
    manifest = {
        "schema": "khaos.release-evidence.v1",
        "tag": args.tag,
        "commit": args.commit,
        "lockfiles": lock_digests,
        "artifacts": artifact_records,
        "sbom": {
            "name": sbom_path.name,
            "sha256": _sha256(sbom_path),
        },
        "checksums": {
            "name": checksums_path.name,
            "sha256": _sha256(checksums_path),
        },
        "required_gates": {
            "evidence_file": gate_evidence_path.name,
            "evidence_sha256": _sha256(gate_evidence_path),
            "evidence_digest": gate_evidence["evidence_digest"],
            "gates": {
                name: {
                    "workflow": record["workflow"],
                    "run_id": record["run_id"],
                    "run_attempt": record.get("run_attempt"),
                    "url": record.get("url"),
                    "head_sha": record["head_sha"],
                    "run_evidence_digest": record["run_evidence_digest"],
                    "artifact_digests": [
                        artifact.get("digest", "")
                        for artifact in record.get("artifacts", [])
                        if artifact.get("digest")
                    ],
                }
                for name, record in sorted(gate_evidence["gates"].items())
            },
        },
    }
    (artifact_dir / "release-manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
