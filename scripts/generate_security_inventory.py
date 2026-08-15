#!/usr/bin/env python3
"""Generate the repository security inventory.

The inventory is intentionally source-derived and deterministic.  It records
the security contract a reviewer must inspect and keeps verified local facts
separate from Linux/CI-only acceptance gates and explicitly unknown coverage.
Run ``python scripts/generate_security_inventory.py --check`` in CI to reject
stale generated documentation.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "docs" / "generated" / "security-inventory.md"
ACTION_SHA_RE = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")
IMAGE_DIGEST_RE = re.compile(r"@sha256:[0-9a-f]{64}")


def repo_relative(path: Path) -> str:
    """Render repository paths with stable POSIX separators on every host."""
    return path.relative_to(ROOT).as_posix()


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def git_output(*args: str) -> str:
    try:
        result = subprocess.run(
            ["git", *args], cwd=ROOT, check=True,
            capture_output=True, text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return "unavailable"
    return result.stdout.strip() or "unavailable"


def canonical_bytes(path: Path) -> bytes:
    """Return deterministic bytes for repository text files on every host."""
    return path.read_bytes().replace(b"\r\n", b"\n").replace(b"\r", b"\n")


def sha256(path: Path) -> str:
    """Hash source text independently of Git's Windows line-ending policy."""
    return hashlib.sha256(canonical_bytes(path)).hexdigest()


def permission_types() -> list[tuple[str, str]]:
    source = read(ROOT / "python" / "khaos" / "permissions" / "rules.py")
    block = re.search(
        r"class PermissionResourceType\([^\n]+\):(?P<body>.*?)(?=\n\n_RELAXING_APPROVALS)",
        source, re.DOTALL,
    )
    if block is None:
        return []
    return re.findall(r"^\s+([A-Z_]+)\s*=\s*\"([^\"]+)\"", block.group("body"), re.MULTILINE)


def docker_digests() -> list[tuple[str, str]]:
    candidates = [
        ROOT / "Dockerfile",
        *sorted(ROOT.glob("*compose*.yml")),
        *sorted(ROOT.glob("*compose*.yaml")),
        *sorted((ROOT / "packaging" / "docker").glob("*")),
    ]
    entries: list[tuple[str, str]] = []
    for path in candidates:
        if not path.is_file():
            continue
        for line_number, line in enumerate(read(path).splitlines(), 1):
            for digest in IMAGE_DIGEST_RE.findall(line):
                entries.append((f"{repo_relative(path)}:{line_number}", digest[1:]))
    return entries


def workflow_actions() -> tuple[list[str], list[str]]:
    pinned: list[str] = []
    unpinned: list[str] = []
    for path in sorted((ROOT / ".github" / "workflows").glob("*.y*ml")):
        for line_number, line in enumerate(read(path).splitlines(), 1):
            match = re.search(r"\buses:\s*([^\s#]+)", line)
            if not match:
                continue
            action = match.group(1)
            location = f"{repo_relative(path)}:{line_number}"
            if action.startswith("./"):
                pinned.append(f"{location} {action} (local reusable workflow)")
            elif ACTION_SHA_RE.match(action):
                pinned.append(f"{location} {action}")
            else:
                unpinned.append(f"{location} {action}")
    return pinned, unpinned


def render() -> str:
    protocol_source = read(ROOT / "python" / "khaos" / "grpc_server.py")
    protocol_version = re.search(r"^RPC_PROTOCOL_VERSION\s*=\s*(\d+)", protocol_source, re.MULTILINE)
    protocol_min = re.search(r"^RPC_PROTOCOL_MIN_VERSION\s*=\s*(\d+)", protocol_source, re.MULTILINE)
    protocol_max = re.search(r"^RPC_PROTOCOL_MAX_VERSION\s*=\s*(\d+)", protocol_source, re.MULTILINE)
    schema = re.search(r"^RPC_SCHEMA_VERSION\s*=\s*(\d+)", protocol_source, re.MULTILINE)
    method_schema = re.search(r"^RPC_METHOD_SCHEMA_VERSION\s*=\s*(\d+)", protocol_source, re.MULTILINE)
    pinned, unpinned = workflow_actions()
    lockfiles = [
        ROOT / "uv.lock",
        ROOT / "python" / "bootstrap-requirements.txt",
        ROOT / "python" / "requirements-lock.txt",
    ]
    lock_entries = [
        (repo_relative(path), sha256(path))
        for path in lockfiles if path.is_file()
    ]
    source_fingerprints = [
        ("python/khaos/audit/anchor.py", sha256(ROOT / "python" / "khaos" / "audit" / "anchor.py")),
        ("python/khaos/channels/webhook.py", sha256(ROOT / "python" / "khaos" / "channels" / "webhook.py")),
        ("python/khaos/permissions/engine.py", sha256(ROOT / "python" / "khaos" / "permissions" / "engine.py")),
        ("python/khaos/permissions/rules.py", sha256(ROOT / "python" / "khaos" / "permissions" / "rules.py")),
        ("python/khaos/coding/execution/authority.py", sha256(ROOT / "python" / "khaos" / "coding" / "execution" / "authority.py")),
        ("python/khaos/coding/execution/identity.py", sha256(ROOT / "python" / "khaos" / "coding" / "execution" / "identity.py")),
        ("python/khaos/coding/execution/models.py", sha256(ROOT / "python" / "khaos" / "coding" / "execution" / "models.py")),
        ("python/khaos/coding/execution/native_launcher.py", sha256(ROOT / "python" / "khaos" / "coding" / "execution" / "native_launcher.py")),
        ("python/khaos/coding/execution/platform.py", sha256(ROOT / "python" / "khaos" / "coding" / "execution" / "platform.py")),
        ("python/khaos/coding/execution/service.py", sha256(ROOT / "python" / "khaos" / "coding" / "execution" / "service.py")),
        ("python/khaos/coding/execution/binding.py", sha256(ROOT / "python" / "khaos" / "coding" / "execution" / "binding.py")),
        ("python/khaos/coding/execution/supervisor.py", sha256(ROOT / "python" / "khaos" / "coding" / "execution" / "supervisor.py")),
        ("python/khaos/coding/workspace/manager.py", sha256(ROOT / "python" / "khaos" / "coding" / "workspace" / "manager.py")),
        ("python/khaos/coding/workspace/trusted_git.py", sha256(ROOT / "python" / "khaos" / "coding" / "workspace" / "trusted_git.py")),
        ("python/khaos/security/authority.py", sha256(ROOT / "python" / "khaos" / "security" / "authority.py")),
        ("python/khaos/security/authority_broker.py", sha256(ROOT / "python" / "khaos" / "security" / "authority_broker.py")),
        ("python/khaos/security/authorityd.py", sha256(ROOT / "python" / "khaos" / "security" / "authorityd.py")),
        ("python/khaos/security/authorityd_protocol.py", sha256(ROOT / "python" / "khaos" / "security" / "authorityd_protocol.py")),
        ("python/khaos/security/docker_profiles.py", sha256(ROOT / "python" / "khaos" / "security" / "docker_profiles.py")),
        ("python/khaos/security/identity_isolation.py", sha256(ROOT / "python" / "khaos" / "security" / "identity_isolation.py")),
        ("python/khaos/security/production_composition_probe.py", sha256(ROOT / "python" / "khaos" / "security" / "production_composition_probe.py")),
        ("python/khaos/security/remote_audit.py", sha256(ROOT / "python" / "khaos" / "security" / "remote_audit.py")),
        ("python/khaos/security/network_broker.py", sha256(ROOT / "python" / "khaos" / "security" / "network_broker.py")),
        ("python/khaos/coding/workspace/boundary.py", sha256(ROOT / "python" / "khaos" / "coding" / "workspace" / "boundary.py")),
        ("rust/khaos-core/src/bin/khaos-exec-launcher.rs", sha256(ROOT / "rust" / "khaos-core" / "src" / "bin" / "khaos-exec-launcher.rs")),
        ("rust/khaos-core/src/bin/khaos-sandbox-launcher.rs", sha256(ROOT / "rust" / "khaos-core" / "src" / "bin" / "khaos-sandbox-launcher.rs")),
        ("python/khaos/grpc_server.py", sha256(ROOT / "python" / "khaos" / "grpc_server.py")),
        ("go/internal/api/handler.go", sha256(ROOT / "go" / "internal" / "api" / "handler.go")),
        ("go/cmd/gateway/main.go", sha256(ROOT / "go" / "cmd" / "gateway" / "main.go")),
        ("go/internal/platform/python_client.go", sha256(ROOT / "go" / "internal" / "platform" / "python_client.go")),
    ]
    type_pairs = permission_types()

    lines = [
        "# Generated Security Inventory",
        "",
        "> Generated by `scripts/generate_security_inventory.py`; do not edit manually.",
        "> The Security Evidence Artifact binds this inventory to a specific commit and CI run.",
        "",
        "## Protocol and authorization contract",
        "",
        f"- Internal JSON-line RPC selected version: `{protocol_version.group(1) if protocol_version else 'missing'}`; supported window: `{protocol_min.group(1) if protocol_min else 'missing'}..{protocol_max.group(1) if protocol_max else 'missing'}`.",
        f"- Envelope schema: `{schema.group(1) if schema else 'missing'}`; method schema: `{method_schema.group(1) if method_schema else 'missing'}`.",
        "- Production requires `RPC.Initialize`, HMAC-bound negotiation metadata, project/policy claims, typed method schema, enumerated errors, and reject-unknown-fields.",
        "- Permission relaxation (`auto-approve`/`suggest`) uses typed resource specs; legacy glob patterns remain available only for non-relaxing deny/ask rules or safe unambiguous migration.",
        "- Typed resource kinds detected in source: " + (", ".join(f"`{value}`" for _name, value in type_pairs) if type_pairs else "`missing`") + ".",
        "",
        "## Audit integrity",
        "",
        "- SQLite audit rows use append-only triggers plus a `prev_hash` chain.",
        "- Production runtimes additionally maintain a dirfd/no-follow `chain-head-<project>.json` anchor under `~/.khaos/audit/`; startup and append paths replay and compare the chain.",
        "- Boundary: this is a local independent detection point, not a remote WORM service and not protection against an actor who can rewrite both trusted files and the database.",
        "",
        "## Container and supply-chain inventory",
        "",
        "- Docker base/service images found with immutable digests:",
    ]
    if docker_digests():
        lines.extend(f"  - `{location}`: `{digest}`" for location, digest in docker_digests())
    else:
        lines.append("  - `missing`")
    lines.append("- Lockfile fingerprints:")
    lines.extend(f"  - `{path}`: `{digest}`" for path, digest in lock_entries)
    if not lock_entries:
        lines.append("  - `missing`")
    lines.extend([
        "",
        "## GitHub Actions governance",
        "",
        f"- Workflow action references inspected: `{len(pinned) + len(unpinned)}`; immutable SHA-pinned/local references: `{len(pinned)}`.",
        "- Unpinned third-party actions (must remain empty): " + ("; ".join(f"`{item}`" for item in unpinned) if unpinned else "none") + ".",
        "- Security-sensitive paths are covered by `.github/CODEOWNERS`; the repository reference ruleset preserves sole-maintainer liveness, so independent approval remains an external release prerequisite and is not verified locally.",
        "",
        "## Platform and evidence boundary",
        "",
        "| Area | Current contract | Evidence class |",
        "| --- | --- | --- |",
        "| Linux namespace/cgroup/nftables and Compose isolation | Uses a helper-only netns root, but must pass real Linux CI with kernel capabilities | CI-only |",
        "| macOS Seatbelt | Fail-closed/native contract tests and hosted macOS security job | Local/CI |",
        "| Windows | Native restricted-token/AppContainer/Job/ACL/WFP helper; native commands and trusted Python network=none use AppContainer, trusted Python stages the base executable and grants exact temporary ACLs only to the disposable runtime tree, brokered mode uses restricted-token + exact loopback WFP; missing probe evidence refuses Host fallback | Windows native CI gate |",
        "| Remote audit/WORM and independent human review | Not implemented by this repository | Unknown/external gate |",
        "",
        "## Source fingerprints",
        "",
    ])
    lines.extend(f"- `{path}`: `{digest}`" for path, digest in source_fingerprints)
    lines.extend([
        "",
        "## Required release gates",
        "",
        "- `Security Closure Gate` must pass on the exact release commit, including real-kernel, Docker/Compose, supply-chain, protocol, authorization, lifecycle, and adversarial evidence jobs.",
        "- A local pass cannot replace the Linux real-kernel gate; see `docs/platform-security-ci.md` and `docs/security-release-governance.md`.",
        "",
    ])
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args(argv)
    output = args.output if args.output.is_absolute() else ROOT / args.output
    rendered = render()
    if args.check:
        if not output.is_file() or output.read_text(encoding="utf-8") != rendered:
            print(f"stale security inventory: {output}", file=sys.stderr)
            return 1
        return 0
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
