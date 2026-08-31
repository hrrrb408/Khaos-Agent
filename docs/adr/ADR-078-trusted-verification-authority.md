# ADR-078: Trusted Verification Authority

**Status:** Accepted — M7.4

## Context

Khaos already has several verification-related layers.  Planning verification
intents describe what a plan should check; `VerifyFixLoop` observes individual
test executions; the M4 approval/verification runtime owns sandboxed execution
and append-only success evidence; and M7 completion evaluation consumes typed
facts.  None of those records, by itself, is a current trusted verification
judgment for a task snapshot.

The legacy `khaos.coding.verification.pipeline` remains a compatibility-only,
production-forbidden path.  M7.4 must not make it reachable by renaming,
wrapping, or importing it from the runtime factory.

## Decision

M7.4 introduces `TrustedVerificationAuthority` and the immutable
`VerificationAssessment` ledger.

1. **Evidence is not authority.**  A tool result, stdout claim, repository
   text, model response, planning intent, `VerificationObservation`, or an
   `EvidenceRef` is not a trusted pass.  The authority accepts only bounded,
   typed evidence descriptors and asks an evidence owner to revalidate them.
2. **The input is an exact snapshot.**  `TrustedVerificationInput` binds
   principal/project/task, GoalSpec identity and digest, workspace, repository,
   base revision, published plan identity, post-change generation/change
   identity, verification policy/catalog digests, requirements, and evidence.
   Its digest is produced by the shared canonical JSON/digest owner.  Random
   record identities and transport timestamps are excluded from semantic
   identity.
3. **Published and latest plans are different.**  Verification binds to the
   exact published `PlanRevision`; latest planning history is never used as a
   fallback for an `IMPLEMENTING` task.  A missing published identity fails
   closed.
4. **Verification freshness is post-change freshness.**  M7.2 context/index
   generation is not verification freshness.  A successful result for G2 is
   not current after a workspace mutation to G3.  Current positive assessment
   projection therefore requires an audited current-snapshot reader and exact
   identity matching.
5. **The durable assessment is passive history.**  `VerificationAssessment`
   is immutable, owner/project/task scoped, and append-only.  Its canonical
   contract contains typed checks, references, digests, and bounded diagnostics,
   never raw stdout/stderr, patches, or mutable semantic dictionaries.  The
   v21 ledger has immutable database triggers and no historical backfill.
6. **Planning intent is declarative.**  `PlanningVerificationIntent` is turned
   into deterministic requirement identities; it does not mean a command ran,
   passed, or is trusted.  A low-level Verify-Fix observation likewise remains
   an execution observation and is not silently converted into an assessment.
7. **M4 integration is an adapter boundary.**  `M4VerificationEvidenceValidator`
   reads only the existing M4 read handle and execution read model.  It checks
   canonical M4 success evidence, authority identity/digest, execution and
   verification binding, published-plan binding, workspace/repository/base,
   post-change generation, final mutation attestation, complete termination,
   and exit status.  It does not read host paths or instantiate the legacy
   pipeline.  Until an audited M4 runtime supplies this adapter, the production
   factory uses `FailClosedVerificationEvidenceValidator`.
   The adapter keeps the M4 evidence owners separate: `PlanExecutionRun` and
   `PlanExecutionReadModel` own execution facts; `VerificationExecutionRun`
   is exposed to M7.4 only through the narrow, authority-bound
   `VerificationReadHandle.verification_run_binding()` projection;
   `VerificationStepRun` owns per-check facts; and `FinalMutationAttestation`
   owns the sealed post-change mutation identity.  M7.4 joins these typed
   projections and never requires a synthetic object that merges verification
   fields into `PlanExecutionRun`.
8. **Completion remains a separate authority.**  `TrustedVerificationFactProvider`
   projects only a current durable assessment into bounded completion facts.
   `CompletionEvaluator` remains pure; `CompletionDecision` remains passive;
   only `CompletionGate` may project `TaskStatus.COMPLETED`.  The authority
   never mutates a task, grants approval/tool/workspace/sandbox/lease access,
   changes memory visibility, or becomes Trusted Verification merely because a
   positive enum was supplied.
9. **Restart does not replay authority.**  Durable assessments can be read
   after restart, but currentness is revalidated.  No assessment read reruns a
   check, replays a capability, invokes a model, or calls Completion Gate.
10. **Platform fail-closed behavior is preserved.**  Windows or any platform
    without an audited secure source/evidence boundary returns unavailable or
    fails closed.  No pathname/cwd/Host fallback is introduced, and
    `KHAOS_TYPED_RESOURCE_CATALOG_PATH` is never bypassed.

## Consequences

The v21 assessment ledger is a new durable history source.  Positive
assessments are useful only when the configured evidence owner can revalidate
the exact current snapshot; the default runtime consequently reports missing
or unavailable verification rather than claiming completion.  Future batches
may add the audited M4 current-snapshot adapter and orchestration, but must not
turn an assessment into lifecycle authority or broaden existing security
boundaries.

The M7.4 modules are composed explicitly by `runtime/factory.py`, while the
development-only completion fact-provider seam remains separate from the
production runtime configuration.  This keeps test composition useful without
making model- or caller-controlled authority injectable in production.

Verification observability uses the typed `VerificationObservationEvent` and
the optional `VerificationEventSink`.  The `TurnVerificationEventSink`
adapter can append bounded `verification.started`, `verification.assessed`,
`verification.stale`, and `verification.unavailable` events to the existing
turn ledger when a verification orchestration owner supplies a turn.  These
events contain only IDs, digests, dispositions, counters, and bounded reason
codes; they never contain raw logs and are never read as verification
authority.  M7.4 does not invent a verification execution controller, so no
turn is synthesized by the passive assessment service.
