# ADR-077: Deterministic Planning and Durable Plan Revisions

Status: accepted for M7.3

## Context

Khaos already has a deterministic planning service and a workspace-bound M7.2
context service, but the two were not one production control-plane path.  The
legacy planner accepts a repository path and an index facade, which is useful
for compatibility and historical tests but is not an acceptable current-source
authority for an autonomous task.  M7.3 therefore adds a context-bound adapter
around the existing deterministic planner rules.

The planning result must survive process restart and must be safe under
concurrent runtimes.  A plan is an intent/evidence record, not approval,
execution authority, verification authority, or task completion authority.

## Decision

The production planning path is:

```text
GoalSpec (immutable declaration)
        +
fresh ContextBundle (SafeWorkspaceFS and exact workspace binding)
        +
current owner-scoped task/cognitive snapshot
        ↓
PlanningInput (deterministic snapshot digest)
        ↓
DeterministicPlanningService.plan_from_context()
        ↓
PlanRevision (immutable semantic body)
        ↓
PlanRevisionRepository.append() (owner-scoped, append-only sequence)
        ↓
READY / BLOCKED / STALE / INVALID disposition
        ↓
only the exact READY ledger head, under one publication transaction, may
move PLANNING → IMPLEMENTING
```

`PlanningInput`, `PlanningStep`, `PlanningRisk`, verification intents,
diagnostics, evidence references, and `PlanRevision` are frozen/slotted typed
value objects.  Canonical semantic payloads contain only typed values at the
Python boundary; JSON dictionaries exist only at serialization boundaries.

The existing `DeterministicPlanningService` remains the planner rule owner.
`plan_from_context()` uses the same deterministic risk, verification-intent,
and DAG validation components, but it consumes only a fresh M7.2
`ContextBundle`; it does not read a repository path or invoke the legacy
`CodeQueryService` in the production path.

## Snapshot and freshness contract

Planning requires:

* exact task, principal, project, GoalSpec id/digest, workspace, repository,
  base revision, context bundle/request, repository generation, and index
  generation bindings;
* `ContextFreshness.FRESH`; stale, unavailable, or mixed-generation context
  produces a non-READY disposition;
* a physical SQL cognitive-state/version and task-status snapshot;
* a non-wildcard base revision whenever the workspace exposes one.

`PlanningInput` and the persisted revision include the snapshot bindings and
deterministic digests.  They do not include `trusted`, `approved`,
`authorized`, `verified`, `safe`, or `complete` flags.  Repository content is
data/evidence, never planning instructions.

## Plan dispositions and state ownership

`PlanDisposition` is deliberately not `TaskStatus` and not
`AgentCognitiveState`:

* `READY` means deterministic planning produced a structurally valid intent;
* `BLOCKED` means a bounded ambiguity, missing target, global truncation, or
  other deterministic planning condition prevents safe readiness;
* `STALE` means the context/snapshot cannot be used as current evidence;
* `INVALID` means the plan contract or DAG is structurally invalid.

The planner never mutates cognitive state.  `PlanningControlCoordinator` is
the only M7.3 orchestration owner for the legal CAS transitions
`... → PLANNING` and `PLANNING → IMPLEMENTING`.  A READY plan is not approval,
execution permission, verification success, or completion.

Both cognitive publications carry the task lifecycle status observed by the
coordinator as an additional SQL predicate.  This status fence prevents a
planner that started from a stale active-task snapshot from publishing a
cognitive result after another lifecycle owner has changed the task.  The
fence protects the planning publication boundary; it does not make the
cognitive CAS a general `coding_tasks` row version.

The latest plan revision and the published implementation plan are separate
concepts.  The latest revision is the newest owner/task history head; the
published revision is the exact READY revision that legally caused the current
`IMPLEMENTING` phase.  M7.3's closure fence is a single `BEGIN IMMEDIATE`
transaction that strictly decodes the head, requires the requested revision to
still be that head, revalidates GoalSpec/workspace/repository/base/cognitive
state/version/task-status bindings, performs the cognitive CAS, and writes
`coding_tasks.published_plan_revision_id`.  Therefore a newer READY revision
cannot appear as the head between validation and publication, and the durable
task row proves which revision caused `IMPLEMENTING`.

`published_plan_revision_id` is a descriptive control-plane projection, not a
Tool, Approval, Workspace, Sandbox, Verification, or execution capability.
Readers that need the current implementation plan use the exact published
identity and fail closed on a missing or malformed referenced revision; they do
not silently fall back to the latest history head.

## Durable plan revisions

Migration v19 adds the owner/project/task-scoped
`agent_plan_revisions` append-only ledger.  Migration v20 adds the nullable
physical `published_plan_revision_id` projection and its owner/task lookup
index; legacy tasks remain unpublished (`NULL`).  The repository allocates the
monotonic per-task `revision_sequence` inside the shared `BEGIN IMMEDIATE`
transaction and binds `parent_revision_id` to the current history head.  A
caller cannot overwrite a revision or select its sequence.  Database triggers
reject UPDATE and DELETE, and a unique owner/task/sequence constraint provides
defense in depth.

The `plan_semantic_digest` covers the task and current snapshot binding,
planner versions, disposition, deterministic steps, impacts, risks,
verification intents, diagnostics, and evidence.  It excludes storage
identity and ordering metadata: `plan_revision_id`, owner fields, sequence,
parent revision id, and `created_at`.  Thus the same semantic plan has the
same digest across storage allocations, while a changed task/snapshot or plan
content changes the digest.  The canonical JSON retains the complete bounded
storage envelope and is strictly decoded on read; a malformed latest revision
is an integrity error and never falls back to an older revision.

## Verification and approval boundary

Verification intents are descriptive requirements only.  M7.3 does not run
commands and does not compose the legacy `VerificationPipeline` or Trusted
Verification.  `requires_approval` and risk fields describe what a later
authority may need to inspect; they do not approve anything and do not widen
ToolScheduler, Approval, Workspace, Sandbox, Memory, or execution authority.

No plan outcome projects `TaskStatus.BLOCKED`, `FAILED`, or `COMPLETED`.
Only a fresh `READY` revision plus the atomic publication fence can enter
`IMPLEMENTING`; task lifecycle and completion remain owned by their existing
control-plane gates.  A later history append cannot replace the published
identity, and a stale planning revision cannot publish after the task has
entered `IMPLEMENTING`.

## Restart and mutation semantics

Restart reads plan history through owner-scoped APIs.  It does not execute a
plan, automatically replan, invoke a model, or replay authority.  Existing
TaskManager restart semantics remain unchanged.  Subsequent workspace or
task mutations make a previously bound plan stale for future consumers; M7.3
does not silently relabel old evidence as fresh.

## Compatibility and deferred work

The legacy `ImplementationPlan`/path-based planner API remains available for
existing approval and planning tests, but is isolated from the production
M7.3 context-bound composition.  `control_state_version` is already owned by
the M7.1.3 cognitive CAS domain and is used as a snapshot fence; it does not
claim to protect unrelated `coding_tasks` fields.

The planning package does not eagerly import the workspace-bound orchestration
coordinator during package initialization.  Its package-level coordinator
exports are lazy, while the production runtime factory imports the coordinator
explicitly.  This keeps security resource-scope identity imports from
recursing through workspace initialization; it is an import-boundary
invariant, not a new runtime authority or capability path.

The following are explicitly deferred: M7.4 Trusted Verification, M7.5
Recovery/Replan execution, M7.6 Tool Router, M7.7 Memory policy, M7.8
Sub-Agent control, and M7.9 metrics.

## Consequences

The production planner has less information than an unrestricted host-path
planner, by design.  Ambiguous or truncated context becomes BLOCKED rather
than a guessed target.  The additional durable ledger and snapshot binding
make restart, audit, and cross-runtime reasoning explicit, while preserving
the established security boundary: the agent proposes desired engineering
work; the security runtime decides what work is allowed.
