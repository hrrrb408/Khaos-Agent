# Khaos Security Invariants

This file is the compact invariant ledger for the local security boundary. It
does not turn local tests into independent deployment evidence: the evidence
class for each invariant remains explicit below.

## Authority and audit invariants

1. A production `AuthorityDaemon` only signs an intent that carries a live,
   non-expired grant registered by that daemon. The grant binds principal,
   project, runtime, task, workspace, workspace generation, policy digest,
   authorization epoch, operation family, and an initial resource scope from
   the immutable policy-bound typed catalog.
   Direct effects must stay inside that scope; a resource transition is
   accepted only through a live parent narrow transaction. Revocation, epoch
   rotation, and workspace-generation rotation atomically remove the live
   record and invalidate its still-launchable PREPARING/PREPARED/NARROWING
   descendants; CLAIMED receipts remain completable for terminal accounting.
2. `AuthorityGrant`/`AuthorityEnvelope` is context, not effect authority.
   `EffectCapability` is minted and validated by the broker registry, and a
   capability cannot widen its operation family or resource digest.
3. A successful `narrow` is one-shot: the parent receipt leaves the pending
   registry and receives a `narrowed` terminal tombstone; only the child
   remains launchable. The parent cannot be claimed, completed, or reused.
4. Every state transition that removes or consumes authority reserves bounded
   audit capacity before the transition. A failed WORM append becomes a
   retryable obligation with a stable `event_id`; exhaustion fails closed and
   leaves the authority state available for reconciliation rather than
   dropping evidence.
5. Resource narrowing is cryptographically linked to the parent digest,
   target operation, and requested scope. Production authorityd requires a
   `TypedResourcePartialOrder` whose catalog digest is bound to the effective
   policy digest; the runtime compiles the baseline catalog from that policy
   and rejects a host manifest whose catalog digest differs. It resolves both
   typed catalog entries, requires the requested scope to be contained by the
   parent, and requires the exact target action to be allowed by the requested
   scope. Missing or malformed entries, policy mismatch, action widening, and
   expired-receipt renewal widening fail closed. Opaque derived-resource
   behavior is limited to the explicit development/test compatibility adapter;
   native execution additionally retains its exact launch-binding digest.

6. A `NarrowTransaction` owns its parent/child receipts, descendant
   reservation, audit reservation, and planned abort event until commit or
   abort. Invalidation commits the exact planned event and reason; it does
   not reconstruct a second hard-coded reason at the terminal boundary.
   `GitEffect` binds the exact repository, ref/action, argv, and effect
   parameters. Worktree add/move/remove paths must be strict descendants of
   the `TrustedGitRunner` authority root (never the root itself, outside it,
   or a symlink-resolved escape), and `apply_index_file` rechecks the bound
   patch length and SHA-256 immediately before Git spawn. Rejected effects
   create no Git process owner. Credential use is represented by a short-lived
   broker-owned lease whose target, operation, policy, and principal are
   bound; secret material is never part of the lease or audit identity.

## Orchestration phase evidence

The Agent turn and tool dispatch pipelines expose immutable phase snapshots,
not mutable status labels. A snapshot records the admitted identity,
phase-specific evidence digests, and only an allowed transition edge; the
phase digest is evidence of orchestration state, not an authority grant,
approval, or proof that an external effect succeeded.

`AgentLoop` must not skip its admission, context, model, tool, verification,
and finalization boundaries. A tool call admitted to dispatch must cross raw-call
validation, resource resolution, permission, approval, authorization, dispatch,
and terminal-result boundaries. A call whose identity or arguments change
after admission, or a transition outside the phase graph, fails closed. A
rejected call may terminate before dispatch and therefore does not receive a
false terminal-effect claim; the absence of a dispatch terminal snapshot is
not evidence that an effect occurred.

## Process and workspace ownership invariants

7. The Windows native backend publishes a pending spawn owner before invoking
   `create_subprocess_exec`. Cancellation cannot erase the pending record.
   A late process is adopted or retained as an orphan; kill/wait/output proof
   must complete before the owner is released. Cleanup failure never produces a
   false `closed` postcondition.
8. Every lifecycle owner exposes the shared `ResourceOwner` proof surface.
   `inspect_resource_owner()` reads admission fences, quarantine state,
   terminal postcondition, and the independent owned-resource oracle as one
   immutable snapshot; callers must not treat an unreadable or quarantined
   owner as closed.
9. The Docker verification backend publishes every CLI child through a
   pending/active owner registry backed by `ProcessSupervisor`. Cancellation
   must reap the CLI owner, then prove the daemon-side container is absent by
   deterministic name plus exact Khaos-label ownership; an inspect/daemon
   error is unknown, not absence. A disposable verification workspace cannot
   reach terminal release until that container-absence proof succeeds.
10. Workspace bootstrap records own the authority grant and every Git resource
   from admission through controlled publish or rollback. Preflight failure,
   cancellation, grant-revocation failure, and worktree cleanup failure stay
   retryable/quarantined until both Git ownership and the grant are terminal.
   Verification quarantine scopes are keyed by the canonical `TaskWorkspace`
   identity; `VerificationRunId` and disposable verification-workspace IDs may
   appear only in poison-owner metadata. Missing or ambiguous identity
   resolution fails closed instead of creating a phantom workspace fence.
11. A workspace authority uses the permission engine's current authorization
   epoch. The positive epoch default is only a library safety floor; production
   runtime construction supplies the database-backed snapshot.

## Deployment and evidence boundaries

12. Linux production composition evidence must traverse the real
   `AuthorityDaemonClient`/WORM path, `ExecutionService`,
   `ProcessSupervisor`, the `exec.host` receipt, native launcher, actual
   bwrap, and an external `/proc` identity oracle. The probe uses
   `network=none`; the real-kernel gate owns the broader network-policy matrix.
13. Production Docker composition requires three host-reviewed, hash-pinned
    outer profile values. `scripts/validate_docker_outer_profiles.py` matches
    the exact options, verifies seccomp/AppArmor source SHA-256 values, and
    requires `systempaths=default`. Explicit `unconfined` values are allowed
    only by the disposable `scripts/compose-security-e2e.sh` probe and are not
    production defaults. Khaos does not claim one universal profile across
    host runtimes; the manifest is the deployment-specific pin.
14. Production Docker execution also requires a separate, host-reviewed
    delegated cgroup v2 subtree through `KHAOS_EXECUTION_CGROUP_SOURCE`; it is
    mounted only at the non-root Agent's `/run/khaos-execution-cgroup`; the
    Compose service must also set the required
    `KHAOS_EXECUTION_CGROUP_PARENT` so Docker places its service cgroup below
    that delegated parent. The Agent explicitly joins the host cgroup
    namespace so it can migrate within that delegated subtree; only the
    explicit subtree bind mount is writable and the Agent has no `SYS_ADMIN`
    capability;
    backend verifies that destination is a real cgroup2 mount, requires the
    `cpu`, `memory`, `pids`, and `io` controllers, and is distinct from the
    privileged browser helper's cgroup subtree. Missing or incomplete
    delegation fails closed. The production exact-effect probe must apply
    `io.max` to a block-backed `/app/data` filesystem; its CI path supplies
    `KHAOS_PRODUCTION_DATA_SOURCE` from a loop-backed ext4 mount and rejects
    overlay or pseudo-device sources before starting Compose.
15. Coding execution and browser authority use separate Linux launcher inodes.
    `KHAOS_EXECUTION_SANDBOX_LAUNCHER` must resolve to the capability-free
    execution copy; `KHAOS_SANDBOX_LAUNCHER` is reserved for the authenticated
    browser helper transition and must never be a coding fallback. Missing or
    invalid execution-launcher packaging fails closed.
16. Local unit tests, local Linux probes, CI-only Windows/Docker/kernel jobs,
    remote WORM evidence, and organization governance are reported as separate
    evidence classes. No local result is promoted to a Codex-equivalent or
    independently administered security claim.

## Verification map

- Authority lifecycle, grant liveness, narrowing, and WORM obligations:
  `python/tests/security/test_authorityd_protocol.py` and
  `python/tests/security/test_authority_broker.py`.
- Exact Git effect and path/digest binding:
  `python/tests/coding/test_trusted_git_process_owner.py`,
  `python/tests/security/test_resource_scope.py`, and
  `python/tests/coding/test_changeset_apply.py`.
- Credential owner/lease lifecycle and orchestration phase boundaries:
  `python/tests/security/test_credential_broker.py`,
  `python/tests/security/test_orchestration_components.py`, and
  `python/tests/security/test_orchestration_phases.py`.
- Windows ownership/cancellation/kill/wait contracts:
  `python/tests/coding/test_windows_process_ownership.py`.
- Exact Linux composition helpers and identity oracle:
  `python/tests/security/test_production_composition_probe.py` plus the
  opt-in production composition job.
- Docker profile and native TCB packaging contracts:
  `python/tests/security/test_native_tcb_packaging.py` and
  `python/tests/security/test_docker_outer_profiles.py`; deployment manifest
  format: `docs/docker-profile-manifest.md`.

The opt-in real-platform jobs remain required for a release closure; skipped
or unavailable jobs are not successful evidence.
