# Memory V2 Production Closure Report

Status: **PASS for Community Local Profile**

This is a profile-scoped Memory V2 closure report. It is not a second Memory
Core redesign. PR #216 and main commit
`ec02d5386f32cf3b06b3828149b6b587c4c9fa7a` remain the completed Memory V2
baseline.

## Closure result

| Result | Status | Boundary |
| --- | --- | --- |
| Memory V2 A-Y | `PASS` | Historical PR #216/main evidence is preserved; the canonical ledger, Broker, provider, verification, maintenance, runtime integration, and Trust-Kernel audit contracts are unchanged. |
| Community Local Profile | `PASS` | Production local authorityd, fixed owner-only trust root, 0600 peer-authenticated AF_UNIX, Ed25519 receipt verification, policy/catalog binding, approval, verification, and audit gates. No Apple membership is required. |
| Memory V2 Production Closure (new Z) | `PASS` | Z is evaluated against the Community Local Profile. Optional Apple signing is not a prerequisite. |
| macOS Signed Distribution Profile | `OPTIONAL_PROFILE_NOT_ENABLED` / `NOT CERTIFIED` | No explicit `KHAOS_NATIVE_MACOS_E2E=true` enablement and no Team ID/certificate/notarization evidence are present in this local environment. |

`PASS` here means the Community profile's required gates pass. It does not
claim that the optional signed macOS profile was certified, and it does not
upgrade the separate generic M6 report, whose stricter native/WORM evidence
contract remains independent.

## Community Local Trust Root

```text
local user/runtime identity
  -> trusted ~/.khaos/authorityd ownership and permissions
  -> protected local capability + AF_UNIX peer UID
  -> Runtime Authority / khaos-authorityd
  -> local Ed25519 authority key
  -> effective policy + typed resource catalog digest
  -> approval -> verification -> signed receipt -> audit
```

The production path rejects arbitrary-user access, world-writable parents,
symlinks, project-controlled socket/key/catalog/audit paths, unauthenticated
RPC, missing policy or catalog binding, in-process/host fallback, and disabled
approval/verification/audit postconditions. The Community profile is a
same-UID personal boundary; a hostile same-UID process can still impersonate a
local client, and that residual is explicitly documented rather than hidden
behind an Apple-signing claim.

The local audit JSONL is diagnostic evidence, not independent WORM retention.
Deployments requiring multi-user/code-signing identity or independently
administered audit must select the signed/native profile or a separately
provisioned equivalent.

## Status vocabulary

The machine-readable profile vocabulary is:

```text
PASS | FAIL | BLOCKED_EXTERNAL | NOT_APPLICABLE | NOT_RUN |
OPTIONAL_PROFILE_NOT_ENABLED
```

The native authority workflow emits
`deployment-profile-results.json`. When the optional signed profile is
explicitly enabled, missing Team ID, signing certificate, protected key,
launchd/XPC proof, or artifact provenance is `FAIL`; no fake identity or
substitute artifact is accepted.

## Evidence map

| Evidence family | Sources | Classification |
| --- | --- | --- |
| Memory V2 Core | `python/tests/memory/test_memory_v2.py`, `test_memory_v2_production_surfaces.py`, `test_memory_v2_closure_edges.py`, `docs/adr/ADR-065-memory-v2-production-closure.md` | inherited PR #216 baseline |
| Local trust and profile | `python/tests/security/test_local_trust.py`, `test_authority_transport.py`, `test_authorityd_protocol.py`, `test_ci_security_policy.py` | local regression + required CI |
| Runtime/RPC/security aggregates | Security Closure Gate, Product Integrity Gate, runtime/RPC production composition | exact protected-main CI evidence |
| Native signed distribution | `.github/workflows/native-authority-production-e2e.yml`, macOS launchd/XPC artifact | optional; not enabled in Community closure |

The separate `docs/m6-security-closure-report.md` remains evidence-bound for
generic M6 and must not be rewritten from this profile-scoped result.

## Local verification snapshot

With the locked `uv` environment and elevated local execution where the host
allows it, the final Memory/Security/Runtime/gRPC aggregate completed with
`1309 passed, 21 skipped, 0 failed`. The real Community AF_UNIX authorityd
round-trip completed separately with `6 passed`; the native authority/process
negative suite completed with `51 passed, 1 skipped`.
The supplemental browser-tool, process-supervisor, managed-process, and
network-authority regression set completed with `73 passed`.

The 21 skips are not hidden green results: Linux kernel browser sandbox and
nftables tests require a privileged Linux runner, one native credential test
requires Linux `SO_PEERCRED`, one production-composition test requires a
deployed authorityd, and one Windows path test is not applicable on macOS.
Those gates remain CI/platform evidence and are not required by the Community
profile's no-Apple local Z result.
