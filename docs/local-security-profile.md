# Khaos Community Local Security Profile

This document is the canonical threat-model boundary for a personal/local
Khaos deployment. The machine decision is produced by
`python/khaos/security/local_closure.py` and
`scripts/build_local_security_closure_report.py`; this document never carries
a closure status by itself.

## Profile selection

`community-local` is the default personal macOS/POSIX profile. It reuses the
existing authority transport and Trust Kernel:

`local user/runtime identity -> owner-only ~/.khaos/authorityd -> private
AF_UNIX peer credentials -> runtime authority -> Ed25519 receipt -> effective
policy and typed resource catalog -> approval/verification/audit`.

The authority root is not selected by a repository, project, model, plugin, or
raw environment path. `local_trust.py` owns the owner/mode/no-symlink checks,
and `authority_transport.py` owns profile selection.

`macos-signed-distribution` is a separate, explicit profile. It may require
launchd/XPC, Apple Team ID, protected signing keys, and notarization. Those
controls are not prerequisites for `community-local`. If that profile is not
enabled, the result is exactly `OPTIONAL_PROFILE_NOT_ENABLED`.

`windows-native` remains native-or-fail-closed and is not inferred from local
macOS execution.

## Threat model

Untrusted inputs include model tool calls and arguments, gateway/RPC payloads,
plugin and integration data, repository contents and symlinks, project-local
configuration, environment variables, executable paths, approval callback
responses, mutable scheduler state, and any local artifact claiming that a
test or gate passed.

The protected Community Local goals are:

- no project-controlled authority root or symlink escape;
- no host-process fallback reachable from production composition;
- no production reachability to testing composition, mock authority, or a
  testing sandbox;
- no reuse of raw model arguments after admission to rebuild permission,
  sandbox, network, or execution authority;
- no approval replay or approval-substitution path can replace the admitted
  arguments, resource, policy, or authority binding;
- monotonic scheduler phases and exact argument/resource/policy/effect
  binding through dispatch;
- bounded process, workspace, network, credential, audit, and resource-owner
  lifecycles;
- closure evidence bound to the exact commit, effective policy digest,
  producer artifact digest, GitHub `push` event, `main` branch, original run
  attempt, and protected-main ancestry.

The adversarial regression matrix includes workspace/path escape, symlink and
TOCTOU substitution, approval replay and binding drift, scheduler argument
mutation, process-tree escape, resource-owner leaks, network isolation,
credential-host teardown, authority receipt/policy/catalog mismatch, and
production composition fallback injection.

## Explicit non-claims

Community Local does not claim hostile same-UID isolation from a process that
can already execute as the same user. Its machine status is `NOT_CLAIMED`.
Community Local does not claim a second-maintainer independent review when the
repository has one maintainer. Its machine status is `NOT_CLAIMED`; this does
not block the Community Local closure decision.

The profile does not claim Apple Developer Program membership, Team ID,
Signed XPC, launchd distribution identity, or notarization. Those are
`NOT_APPLICABLE` to the Community Local prerequisite set and belong only to
the optional signed-distribution profile.

The local audit JSONL/SQLite chain is local evidence, not a remote WORM claim.
Kernel, native Windows, signed macOS, and other unavailable platform
properties remain `NOT_RUN`, `BLOCKED_EXTERNAL`, or
`OPTIONAL_PROFILE_NOT_ENABLED` until producer-owned CI evidence proves them.

## Closure contract

`CLOSED` requires all mandatory Community Local proof names, no known P0/P1,
an exact current commit, matching policy/security-facts/reachability/
composition digests, the verified Security Closure manifest and commit
attestation, and separately verified GitHub provenance. The evaluator accepts
only the non-serializable `VerifiedGitHubProvenance` capability issued after a
live GitHub API check. A local JSON file, a handwritten status, a boolean, a
mock artifact, or a skipped/queued test cannot create `CLOSED`.

The absence of exact-main CI evidence is reported as
`CLOSURE_PENDING_EXACT_SHA_CI_EVIDENCE` and the profile remains
`NOT_CLOSED`. The optional signed profile is reported separately and must not
be conflated with the Community Local decision.

## Exact proof and gate names

The exact machine contract is maintained in `docs/security_facts.yaml`. The
Community Local evaluator currently requires these ten producer-owned proofs:

`community_authority`, `platform_kernel`, `production_reachability`,
`production_composition`, `workspace_escape`, `approval_replay`,
`approval_substitution`, `process_tree_escape`, `resource_owner_closure`, and
`network_isolation`.

Its required aggregate gates are `Security Closure Gate` and `Product Integrity
Gate`. The separate `Community Local Security Closure` workflow verifies the
exact protected-main push and producer artifacts; a saved report remains audit
evidence only.
