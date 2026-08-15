# Khaos Security Invariants

This file is the compact invariant ledger for the local security boundary. It
does not turn local tests into independent deployment evidence: the evidence
class for each invariant remains explicit below.

## Authority and audit invariants

1. A production `AuthorityDaemon` only signs an intent that carries a live,
   non-expired grant registered by that daemon. The grant binds principal,
   project, runtime, task, workspace, workspace generation, policy digest,
   authorization epoch, operation family, and an initial resource scope.
   Direct effects must stay inside that scope; a resource transition is
   accepted only through a live parent narrow transaction. Revocation and
   epoch rotation remove the live record before stale objects can issue again.
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
   target operation, and requested scope by `derive_resource_digest`. The
   daemon enforces the operation-family transition. Semantic interpretation of
   a resource scope remains the higher-level policy/typed-resource authority;
   the daemon does not claim to be a complete PDP.

## Process and workspace ownership invariants

6. The Windows native backend publishes a pending spawn owner before invoking
   `create_subprocess_exec`. Cancellation cannot erase the pending record.
   A late process is adopted or retained as an orphan; kill/wait/output proof
   must complete before the owner is released. Cleanup failure never produces a
   false `closed` postcondition.
7. Workspace bootstrap records own the authority grant and every Git resource
   from admission through controlled publish or rollback. Preflight failure,
   cancellation, grant-revocation failure, and worktree cleanup failure stay
   retryable/quarantined until both Git ownership and the grant are terminal.
8. A workspace authority uses the permission engine's current authorization
   epoch. The positive epoch default is only a library safety floor; production
   runtime construction supplies the database-backed snapshot.

## Deployment and evidence boundaries

9. Linux production composition evidence must traverse the real
   `AuthorityDaemonClient`/WORM path, `ExecutionService`,
   `ProcessSupervisor`, the `exec.host` receipt, native launcher, actual
   bwrap, and an external `/proc` identity oracle. The probe uses
   `network=none`; the real-kernel gate owns the broader network-policy matrix.
10. Production Docker composition requires three host-reviewed, hash-pinned
    outer profile values. `scripts/validate_docker_outer_profiles.py` matches
    the exact options, verifies seccomp/AppArmor source SHA-256 values, and
    requires `systempaths=default`. Explicit `unconfined` values are allowed
    only by the disposable `scripts/compose-security-e2e.sh` probe and are not
    production defaults. Khaos does not claim one universal profile across
    host runtimes; the manifest is the deployment-specific pin.
11. Production Docker execution also requires a separate, host-reviewed
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
12. Coding execution and browser authority use separate Linux launcher inodes.
    `KHAOS_EXECUTION_SANDBOX_LAUNCHER` must resolve to the capability-free
    execution copy; `KHAOS_SANDBOX_LAUNCHER` is reserved for the authenticated
    browser helper transition and must never be a coding fallback. Missing or
    invalid execution-launcher packaging fails closed.
13. Local unit tests, local Linux probes, CI-only Windows/Docker/kernel jobs,
    remote WORM evidence, and organization governance are reported as separate
    evidence classes. No local result is promoted to a Codex-equivalent or
    independently administered security claim.

## Verification map

- Authority lifecycle, grant liveness, narrowing, and WORM obligations:
  `python/tests/security/test_authorityd_protocol.py` and
  `python/tests/security/test_authority_broker.py`.
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
