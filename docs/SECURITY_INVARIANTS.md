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
   When `KHAOS_WORKTREE_AUTHORITY_ROOT` is configured, the effective typed
   `GitRefScope` and `WorkspaceManager` must bind the exact same private root;
   without it, the runner's private root remains the final local TCB and the
   catalog is not independent pathname evidence.

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
17. `terminal_argv` and `terminal_shell` are separate security contracts.
    The argv contract binds the exact argv vector; the shell contract binds
    the exact script digest plus the immutable semantic AST digest/status.
    Only a complete literal executable graph covered by command-specific argv
    policy may be `safe`/read-only. Brace, glob, tilde, parameter, command,
    arithmetic, or process expansion; escape ambiguity; redirection,
    here-doc/here-string, pipeline/compound/subshell, evaluator, assignment,
    and callback semantics are `semantic-unknown` and require approval. A
    literal or nested blocked executable is hard blocked. Syntax acceptance or
    a first/base executable is never evidence of a safe effect.
18. Principal kind is derived from the authenticated transport and is
    immutable for the request. `HumanPrincipal`, `GatewayPrincipal`,
    `ChannelPrincipal`, `AutomationPrincipal`, `SubagentPrincipal`, and
    `BrowserPrincipal` cannot be interchanged by payload self-reporting.
    Delegation is narrow-only and binds subject, parent, project, session,
    runtime, task, workspace, operation family, resource scope, policy
    digest, expiry, and nonce. A child scope cannot widen any parent field;
    its nonce is consumed once, and cross-principal/context replay is
    rejected. The typed foundation never replaces the signed authority or
    exact-effect receipt, and missing production integration evidence remains
    unclosed.
19. Production composition is machine-checked from explicit runtime roots.
    The reachability inventory resolves repository imports and declared lazy
    exports, rejects unresolved internal imports, and rejects development,
    Host, and compatibility execution modules on the production graph.
    Removing a call site is not sufficient if the forbidden implementation
    remains reachable through a public compatibility hook. The generated
    inventory is a commit-bound artifact and a stale or locally edited report
    fails closed in CI.
20. macOS and Windows production authority transport is native-only. macOS
    requires a launchd Mach service/XPC audit-token and code-signature proof
    plus a Keychain access-group protected key; Windows requires a Service-SID
    process, an ACL-protected Named Pipe, and a protected-key proof. Missing,
    stale, same-UID, or test-process evidence is unavailable evidence and
    cannot authorize a receipt.
21. Security-critical transport, serialization, schema, effect-binding,
    receipt-state, and resource-owner transitions are pure typed boundaries.
    The orchestration modules may own I/O and locks, but they must call the
    pure transition/digest functions; an object reaching `CLOSED` without an
    external terminal postcondition and an empty owner registry is invalid.
22. The hardened M6 ruleset is a preparation template, not current evidence.
    It requires an independent approving review, CODEOWNER review, last-push
    approval, resolved threads, `Security Closure Gate`, and `Product Integrity
    Gate`; the current single-maintainer ruleset must not claim those controls.
23. The upstream Codex watch is metadata-only and review-only. It binds the
    comparison to a fixed SHA, filters security-relevant paths/subjects, and
    cannot copy, apply, or synchronize upstream source.
24. The M6 closure report is evidence-bound. `CLOSED` requires exact CI
    evidence, both real native authority proofs, explicit all-gates-success,
    and independent resource oracles; missing evidence remains UNKNOWN,
    QUARANTINED, or FAILED.

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
- Shell semantic authority and exact approval binding:
  `python/tests/security/test_shell_semantics.py`,
  `python/tests/tools/test_terminal_tools.py`, and
  `python/tests/permissions/test_authorization_resource.py`.
- Typed principal transport/delegation:
  `python/tests/security/test_typed_principals.py` and
  `python/tests/runtime/test_request_context_316a_4_1.py`.
- Production composition reachability and forbidden Host/dev edges:
  `python/tests/security/test_production_reachability.py` and
  `scripts/generate_production_reachability.py --check`.
- Native authority transport admission:
  `python/tests/security/test_native_authority.py`; native E2E evidence is
  produced only by the macOS/Windows platform jobs when signed service
  artifacts and platform identity proofs are present.
- Pure TCB protocol/effect/state boundaries:
  `python/tests/security/test_protocol_boundary.py`,
  `python/khaos/security/protocol_boundary.py`, and the authorityd receipt
  transition calls.
- M6 governance, upstream watch, adversarial postconditions, and report
  evidence:
  `python/tests/security/test_m6_governance.py`,
  `python/tests/security/test_upstream_codex_security_watch.py`,
  `python/tests/security/test_m6_adversarial_matrix.py`, and
  `python/tests/security/test_m6_closure_report.py`.

The opt-in real-platform jobs remain required for a release closure; skipped
or unavailable jobs are not successful evidence.
