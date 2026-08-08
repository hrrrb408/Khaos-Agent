# Security Release Governance

This repository has one declared maintainer, so repository ownership and
independent review are separate controls.  A security-sensitive change is not
release-ready merely because the maintainer can approve it.

## Required controls

1. Protect `main` against force-push and deletion.
2. Require the `Security Closure Gate` on the exact pull-request head.
3. When a second maintainer is available, require at least one approving
   review from a reviewer who is not the author of the change for paths
   covered by `.github/CODEOWNERS`. Until then, record the independent-review
   control as an explicit release prerequisite rather than claiming that the
   single-maintainer ruleset provides it.
4. Require signed release tags, a commit-bound SBOM/provenance attestation,
   and retain the Security Evidence Artifact with the release record.
5. Keep GitHub Actions pinned to immutable commit SHAs; the generated
   inventory check must fail if an unpinned action is introduced.
6. Do not merge Docker, lockfile, workflow, permission, audit, RPC, or native
   helper changes while the corresponding real-kernel or supply-chain job is
   skipped, cancelled, or unavailable.

## Evidence boundary

Local Python/Go/Rust tests prove source-level contracts only.  Linux namespace,
cgroup, nftables, Docker Compose, and native helper acceptance remain CI-only
on this macOS workstation.  Windows is a fail-closed unsupported platform,
not a parity claim.  The local audit chain anchor detects database rollback or
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
- Security Closure Gate passed for the release commit.
- Release SBOM, checksum manifest, and GitHub artifact provenance attestation
  are attached to the release; the release workflow must fail on digest drift.
- Evidence artifact, reviewer identity, signed tag, and any CI-only skips are
  recorded together.
