#!/usr/bin/env python3
"""Generate the effect-decision TCB inventory (M6.9 BATCH 11).

The inventory lists, for each security-relevant ownership category, the
exact production module that owns it.  It is derived from a curated,
reviewed owner map — the point is to make the true effect-decision TCB
explicit and diffable in review, not to mechanically list every file.

Categories follow the ADR-021/ADR-022 ownership model:
security decision, mutable state, privileged spawn, secret, network,
workspace, and effect owners.
"""

from __future__ import annotations

import argparse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "docs" / "generated" / "tcb-inventory.md"

# owner category -> (owner module, responsibility, pure/typed boundary)
TCB_OWNERS: dict[str, tuple[tuple[str, str, str], ...]] = {
    "Security decision owners": (
        (
            "python/khaos/security/authorityd.py",
            "grant registry, receipt state machine, policy kernel, signed attestations",
            "AuthorityPolicyKernel + protocol_boundary.require_receipt_transition are pure",
        ),
        (
            "python/khaos/security/principals.py",
            "typed principals and the delegation lifecycle (root/child/consume/revoke)",
            "DelegationAuthority: pure typed records, no transport",
        ),
        (
            "python/khaos/security/shell_semantics.py",
            "SAFE/SEMANTIC_UNKNOWN/BLOCKED shell + argv semantic authority",
            "parser + per-command argv predicates are pure functions",
        ),
        (
            "python/khaos/security/effective_policy.py",
            "EffectiveSecurityPolicy compilation (user ∩ project ∩ platform)",
            "compiled once, immutable at runtime",
        ),
        (
            "python/khaos/permissions/engine.py",
            "PermissionEngine admission + commands_require_approval gate",
            "rule matching over the compiled policy",
        ),
        (
            "python/khaos/security/protocol_boundary.py",
            "canonical serialization + receipt transition legality",
            "pure functions with Hypothesis coverage",
        ),
        (
            "python/khaos/security/production_trust.py",
            "protocol, authority, policy, catalog, key, and environment binding",
            "immutable secret-free startup witness; mismatch fails closed",
        ),
    ),
    "Mutable security state owners": (
        (
            "python/khaos/security/authorityd.py",
            "live grants, pending receipts, terminal tombstones, delegation registry",
            "all mutations flow through audited daemon transitions",
        ),
        (
            "python/khaos/security/credential_broker.py",
            "capability token registry and live grant handles",
            "broker-owned records; callers cannot mint handles",
        ),
        (
            "python/khaos/db/database.py",
            "sessions, messages, audit mirror, scheduled tasks",
            "WORM authority is the remote writer, never this database",
        ),
    ),
    "Privileged spawn owners": (
        (
            "rust/khaos-core/src/bin/",
            "coding/browser sandbox launchers, authorityd frontends (TCB binaries)",
            "zero-capability postconditions verified post-exec",
        ),
        (
            "python/khaos/security/native_authority.py",
            "native authority client process domain (session leader, kill ladder)",
            "incremental budgets + SIGTERM->SIGKILL process-group termination",
        ),
        (
            "python/khaos/security/credential_provider_host.py",
            "hosted credential provider execution domains",
            "provider terminal proof covers the whole process domain",
        ),
        (
            "python/khaos/coding/execution/supervisor.py",
            "ProcessSupervisor: owned execution trees and their terminal proof",
            "cgroup/job-object terminal evidence",
        ),
    ),
    "Secret owners": (
        (
            "python/khaos/security/credential_broker.py",
            "credential leases; secrets materialize only in final trusted environments",
            "no plaintext in the agent process",
        ),
        (
            "khaos-authorityd (backend daemon)",
            (
                "Ed25519 signing key held as a 0400 file owned by the authority "
                "UID; the platform keychain (macOS) / DPAPI (Windows) item is a "
                "protected-key-slot presence marker bound to the service "
                "identity, NOT the signing key itself"
            ),
            "agent holds only the public verification key",
        ),
        (
            "packaging/*/agent-secret-init.py",
            "compose secret materialization for the agent identity",
            "file-permission enforced",
        ),
    ),
    "Network owners": (
        (
            "python/khaos/security/network_broker.py",
            "NetworkLease/NetworkReservation: DNS resolution, pinning, unsafe-IP rejection",
            "one-shot prerequisite fence for git push authority",
        ),
        (
            "python/khaos/security/network_guard.py",
            "allow/block domain policy enforcement for tools",
            "compiled from EffectiveSecurityPolicy",
        ),
        (
            "python/khaos/security/browser_egress_proxy.py",
            "browser kernel egress proxy",
            "kernel-enforced nftables boundary",
        ),
    ),
    "Workspace owners": (
        (
            "python/khaos/coding/workspace/storage.py",
            "WorkspaceStorageAuthority: baseline, quotas, quarantine",
            "mutation fence + asyncio.shield",
        ),
        (
            "python/khaos/coding/workspace/office_authority.py",
            "OfficeMutationAuthority for copy/move effects",
            "reuses the storage authority's fence",
        ),
        (
            "python/khaos/coding/workspace/trusted_git.py",
            "trusted Git plumbing with exact-effect binding",
            "allowlisted plumbing only; no porcelain/filters",
        ),
    ),
    "Effect owners": (
        (
            "python/khaos/coding/execution/service.py",
            "ExecutionService: the only path to privileged local effects",
            "backend selection is fail-closed; host backend is forbidden",
        ),
        (
            "python/khaos/security/authority_broker.py",
            "EffectCapability issuance/claim/complete through authorityd",
            "one-shot, receipt-bound",
        ),
        (
            "python/khaos/audit/logger.py",
            "audit logging; WORM submission is remote HTTPS with no local fallback",
            "audit failure refuses the effect",
        ),
    ),
    "Native transport TCB": (
        (
            "python/khaos/security/authority_transport.py",
            "explicit community/native-production profile selection and transport ownership",
            "unknown profile fails closed; no in-process or platform inference fallback",
        ),
        (
            "python/khaos/security/local_trust.py",
            "Community Local Trust Root path and ownership admission",
            "fixed ~/.khaos/authorityd root; no symlink, project path, or non-private socket",
        ),
        (
            "packaging/macos/khaos-authorityd-xpc.m",
            "launchd/XPC frontend: audit token + designated code requirement + backend ownership",
            "platform TCB; no Python fallback",
        ),
        (
            "rust/khaos-core/src/bin/khaos-authorityd-windows.rs",
            "Service-SID Named-Pipe frontend: SID validation + backend identity + deadlines",
            "platform TCB; no same-UID fallback",
        ),
        (
            "rust/khaos-core/src/bin/khaos-authorityd-backend-windows.rs",
            "SCM host for the Python authority backend: isolated spawn + child lifecycle",
            "platform TCB; kill-on-close Job Object and terminal wait",
        ),
        (
            "python/khaos/security/authorityd_windows.py",
            "Windows backend Named-Pipe server (DACL: SYSTEM + Service SID only)",
            "per-connection token-SID validation",
        ),
    ),
}


def render() -> str:
    lines = [
        "# Generated Effect-Decision TCB Inventory",
        "",
        "> Generated by `scripts/generate_tcb_inventory.py`; do not edit manually.",
        "> Curated owner map reviewed per change; the goal is a smaller true",
        "> effect-decision TCB, not more files.",
        "",
    ]
    total = 0
    for category, owners in TCB_OWNERS.items():
        lines.extend([f"## {category}", "", "| Owner | Responsibility | Boundary |", "| --- | --- | --- |"])
        for module, responsibility, boundary in owners:
            lines.append(f"| `{module}` | {responsibility} | {boundary} |")
            total += 1
        lines.append("")
    lines.extend(
        [
            "## Reduction direction",
            "",
            "- Authority decisions concentrate in the authorityd backend daemon;",
            "  the Python agent is a typed client with only the public key.",
            "- Receipt/delegation/shell policy transitions are pure typed functions",
            "  (protocol_boundary, principals, shell_semantics) with property tests.",
            "- The native frontends are the only platform TCB transports; both are",
            "  fail-closed with no Python/same-UID fallback.",
            f"- Total curated TCB owners: `{total}`.",
            "",
        ]
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args(argv)
    rendered = render()
    output = args.output if args.output.is_absolute() else ROOT / args.output
    if args.check:
        if not output.is_file() or output.read_text(encoding="utf-8") != rendered:
            print(f"stale TCB inventory: {output}")
            return 1
        return 0
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(rendered, encoding="utf-8")
    print(f"TCB inventory written to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
