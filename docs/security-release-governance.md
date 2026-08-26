# Security Release Governance

This repository has one declared maintainer (the current
`single-maintainer` compatibility mode), so repository ownership and
independent review are separate controls.  A security-sensitive change is not
release-ready merely because the maintainer can approve it.

`docs/security_facts.yaml` is the machine-facing source for the deployment
profiles, exact closure gates, proof names, accepted residuals, supported
platform claims, and type-check TCB set described below. This governance
document explains their meaning; prose here cannot replace live exact-SHA
verification.

## Required controls

1. Protect `main` against force-push and deletion.
2. Require the `Security Closure Gate` on the exact pull-request head.
3. When a second maintainer is available, require at least one approving
   review from a reviewer who is not the author of the change for paths
   covered by `.github/CODEOWNERS`. Until then, record the independent-review
   control as an explicit release prerequisite rather than claiming that the
   single-maintainer ruleset provides it.
   The machine-readable preparation artifact is
   `scripts/github-m6-hardened-ruleset.json`; it enables code-owner review,
   last-push approval, stale-review dismissal, and one approving review, but
   it is not the active repository ruleset while this repository has one
   maintainer.
4. Require GitHub-verified signed, annotated, non-retargetable release tags,
   successful `Security Closure
   Gate` and `Product Integrity Gate` runs for the exact tagged commit, a
   commit-bound SBOM/provenance attestation, and retain the gate evidence with
   the release record.
5. Keep GitHub Actions pinned to immutable commit SHAs; the generated
   inventory check must fail if an unpinned action is introduced.
6. Release assets are write-once: the provenance workflow must not replace an
   existing asset (`gh release upload` without `--clobber`). Tag/release
   immutability is enforced by repository settings and the signed-tag review
   prerequisite; the workflow also verifies the checked-out tag SHA before
   attesting it.
7. Do not merge Docker, lockfile, workflow, permission, audit, RPC, or native
   helper changes while the corresponding real-kernel or supply-chain job is
   skipped, cancelled, or unavailable.
8. Keep every closure-critical or release-critical Actions artifact for at
   least 90 days. The complete upload classification is machine-checked by
   `scripts/validate_evidence_retention.py` from `docs/security_facts.yaml`;
   diagnostic artifacts remain explicitly separate from the re-verification
   chain.

## Deployment profile evidence

The machine-facing Community Local decision is `CLOSED` or `NOT_CLOSED` and is
generated only by `python/khaos/security/local_closure.py` from producer-owned
exact-SHA evidence plus a non-serializable capability issued by the live
GitHub release verifier. A saved JSON release record is audit evidence only;
it is not accepted by the evaluator as that capability. It is separate from
the older generic M6 closure report;
the generic report must not import native-profile requirements into Community
Local or turn a local test result into release closure.

Memory V2 production closure is profile-scoped. The Community Local Profile is
allowed to reach `CLOSED` without Apple membership, Team ID, signing
certificate, notarization, or signed launchd/XPC. Its required evidence still
includes the independent authorityd process, owner-only local trust root,
private peer-authenticated socket, Ed25519 receipt verification, effective
policy and typed catalog binding, approval, verification, and audit.

The macOS Signed Distribution Profile is optional and explicit. When it is not
enabled, record `OPTIONAL_PROFILE_NOT_ENABLED`; do not turn
that state into a Memory or Community failure. When
`KHAOS_NATIVE_MACOS_E2E=true` enables the profile, missing Team ID, certificate,
protected key, launchd/XPC proof, notarization, or artifact provenance is a
fail-closed failure. The workflow publishes both profile results in
`deployment-profile-results.json`.

The finite transport status vocabulary is `PASS`, `FAIL`, `BLOCKED_EXTERNAL`,
`NOT_APPLICABLE`, `NOT_RUN`, and `OPTIONAL_PROFILE_NOT_ENABLED`. The local
closure vocabulary additionally uses `CLOSED`, `NOT_CLOSED`, `REJECTED`, and
`NOT_CLAIMED`. Hostile same-UID isolation and second-maintainer independent
review are explicitly `NOT_CLAIMED`; neither blocks Community Local closure.
Generic M6 closure has its own stricter evidence contract and must not be
silently upgraded by a Community result.

The Security Closure Gate also runs the structural
`COMMUNITY_LOCAL_PRE_CLOSURE` contract on pull requests. It may report only
`PASS` or `FAIL`; it checks proof and artifact wiring but does not certify a
main push or create live provenance. Final Community Local certification still
comes from `community-local-closure.yml` after an exact `main` push, original
attempt, producer artifacts, and live GitHub verification.

## Runtime profile authority

Runtime security semantics are selected by the immutable typed
khaos.runtime_profile.RuntimeProfile. build_production_runtime() and the
production CLI/RPC entrypoints fix PRODUCTION explicitly; KHAOS_DEV_MODE
is retained only as a legacy resolver for untyped direct/test adapters. It
cannot disable injection checks, host-fallback rejection, native authority,
local-trust validation, browser/sandbox enforcement, or RPC negotiation.
scripts/generate_production_reachability.py fails if a production-reachable
module reads KHAOS_DEV_MODE outside the compatibility resolver.

## Evidence boundary

Local Python/Go/Rust tests prove source-level contracts only. Linux namespace,
cgroup, nftables, Docker Compose, and Windows native helper acceptance remain
CI-only on this macOS workstation. Windows is native-or-fail-closed, not a
claim of browser-specific Linux netns parity. The local audit chain anchor detects database rollback or
history edits, but a remote WORM audit sink and independent human review are
external release controls and are not implemented by this repository.

Runtime retention is explicit rather than an implicit delete-on-start policy:
terminal chat/turn journals and no-effect tool-operation claims are pruned only
after their configured replay windows. Applied/partial/unknown operation rows
remain replay-suppression tombstones. The audit JSONL side trail rotates into
trusted segments, enforces a disk ceiling, and requires an explicit signed
archive/tombstone workflow before source segments are removed. Maintenance
also performs a passive WAL checkpoint. The SQLite audit chain has an explicit
signed gzip export/tombstone workflow, but rows are never deleted implicitly;
any database rotation must be a separately approved administrative action.
Export/archive evidence before reducing any window.

## Release checklist

- `python scripts/generate_security_inventory.py --check`
- `python scripts/generate_browser_kernel_protocol.py --check`
- `git diff --check`
- Security Closure Gate and Product Integrity Gate both passed for the exact
  release commit; their run IDs and evidence digests are in the release
  manifest.
- Release SBOM, checksum manifest, and GitHub artifact provenance attestation
  are attached to the release; the release workflow must fail on digest drift.
- Gate evidence artifact, reviewer identity, GitHub-verified signed annotated
  non-retargetable tag, and
  any CI-only skips are recorded together. Existing release assets are never
  overwritten.

The release workflow already preserves the exact gate evidence, checksums,
SBOM, and signed attestation bundles as release assets without `--clobber`
(`ALREADY_SATISFIED`). These saved records are audit evidence only; they do
not replace the live exact-SHA GitHub verifier or issue a closure capability.
After that live verifier succeeds for the Community Local profile, the
generator also publishes `community-local-closure-bundle-<SHA>.json`. It
contains the closure report fields, exact gate identities, producer and proof
digests, policy/schema digests, accepted residuals, and the machine decision;
its machine contract explicitly records that it cannot issue provenance.

## M6 governance preparation

`docs/security_facts.yaml` is the canonical machine-readable inventory of
security-critical paths. `scripts/validate_m6_governance.py` rejects duplicate
or dead inventory entries and verifies that every declared path is covered by
`.github/CODEOWNERS`. The hardened ruleset template remains a preparation
artifact until a second maintainer is available. Changes to an inventory path
or its owner require a manual maintainer diff review; autonomous merge is not
allowed. A green local validation proves only that the preparation artifacts
are internally consistent; it is not evidence of an independent human review.
