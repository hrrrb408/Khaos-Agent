# ADR-082: Deterministic Capability Evaluation

Status: accepted

## Decision

M7.9 adds an observation-only capability evaluation bounded context:

```text
M7.1–M7.8 durable authority evidence
        -> coherent SQLite read snapshot
        -> pure CapabilityEvaluator
        -> typed capability vector
        -> append-only evaluation history / report
```

`CapabilityEvaluationPolicy`, `CapabilityEvaluationRequest`,
`CapabilityEvidenceSnapshot`, metric groups, and `CapabilityEvaluation` are
immutable contracts.  A snapshot records owner/task identity, GoalSpec
identity, task/control projection, source availability, exact source
high-water marks, policy digest, and its own digest.  The evaluator reads no
database, filesystem, network, tool, model, planner, verification, recovery,
completion gate, or approval service.

The `agent_capability_evaluations` v26 table is an owner/project/task-scoped,
sequence-allocated append-only ledger.  Canonical JSON and duplicated scalar
columns are cross-checked on read; malformed rows fail closed.  Evaluation
history is historical observation, not current authority.

## Boundaries

Metrics are observations, not authority.  Audit evidence is not task
authority, and assistant self-report is not outcome evidence.  Historical
success is not current authority.  Security integrity is a hard dimension and
cannot be averaged away by functional success.  Insufficient evidence is an
explicit disposition rather than a zero or an assumed pass.

The evaluation service is not imported by Planner, Tool Router, Permission or
Approval, CompletionGate, Trusted Verification, Recovery, Memory retrieval
policy, or Sub-Agent policy.  Evaluation is not injected into Agent prompts
and cannot publish plans, complete tasks, grant permissions, suppress
approval, or change production policy.

Benchmark manifests are trusted material external to the tested model.  A
security invariant failure is always a benchmark hard failure.  Benchmark
results, capability vectors, and reports do not replace Product Integrity,
Security Contract Matrix, Batch 5, Browser, Platform Sandbox, or Docker
required gates.

Raw credentials, bearer material, cookies, private keys, environment secrets,
chain-of-thought, private reasoning, and bulk stdout/stderr are excluded from
evidence.  Operational telemetry that is unavailable remains unavailable.

## Consequences

The read transaction provides one SQLite observation point and prevents a
verification/plan/recovery/task half-before/half-after combination.  Source
history is bounded; truncation is explicit and produces insufficient evidence
for a complete evaluation.  The evaluator digest excludes capture and append
timestamps so the same snapshot, policy, and algorithm produce the same
semantic evaluation bytes and digest.

M7.9 does not deploy production trust material or enable score-driven
self-optimization.  Typed resource catalog and authorityd integration remain
the separate post-M7 stage.
