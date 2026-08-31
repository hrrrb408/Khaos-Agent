# ADR-068: GoalSpec Authority and Durable Persistence

- Status: accepted
- Date: 2026-08-26
- Scope: M7.1.2

## Context

`CodingTask.goal` was previously the only durable representation of a coding
task's objective.  That field is useful for existing RPC/TUI projections, but
it does not provide a typed declaration that can be reconstructed and
integrity-checked after a process restart.  M7 needs a durable goal contract
without conflating the user's declaration with mutable execution assessment or
security authority.

## Decision

1. `GoalSpec` is an immutable declaration of one coding task's goal.  It is
   stored canonically in `agent_goal_specs`; `CodingTask.goal` remains a
   backward-compatible display projection.
2. Goal assessment is separate mutable state.  Status, evidence references,
   verification results, and plan state do not belong to `GoalSpec` and will be
   represented by later typed assessment/completion contracts.
3. The canonical GoalSpec contains no status, evidence references,
   verification result, or current plan state.  Its semantic digest therefore
   remains stable throughout task execution.
4. `GoalSource` distinguishes explicit user declarations from future inferred,
   repository-policy, and verification-policy declarations.  M7.1.2 creates
   only `EXPLICIT_USER` requirements; it does not interpret goals with a model.
5. GoalSpec is not security authority.  It cannot grant tools, permissions,
   approvals, workspace access, sandbox capability, or network authority.
   Memory, sub-agents, and prompt content cannot rewrite the canonical row.
6. The GoalSpec owner boundary is `(principal_id, project_id, task_id)`.  It is
   deliberately not bound to `workspace_id`: task creation precedes workspace
   creation, and a workspace is an execution scope rather than goal identity.
7. Task creation and GoalSpec creation share the existing `Database.transaction`
   owner and one `BEGIN IMMEDIATE` transaction.  The task event is published
   only after that transaction commits; a failure rolls back both rows.
8. GoalSpec insertion is immutable and conflict-raising.  There is no update,
   delete, or `INSERT OR REPLACE` production API.  Duplicate task/identity
   insertion is an explicit conflict rather than silent replacement.
9. Migration v16 performs a conservative, deterministic backfill for legacy
   `coding_tasks`: it preserves the stored goal and creates one required
   `EXPLICIT_USER` requirement, with no inferred acceptance criteria.  Malformed
   or inconsistent rows fail closed, and the migration is idempotent.
10. `semantic_digest` uses the existing security canonical JSON serializer and
    SHA-256 digest convention.  It covers schema version and semantic goal
    fields only; it excludes GoalSpec identity, owner/task identity, timestamps,
    database IDs, and all mutable execution state.  Requirement and criterion
    collections are sorted by their stable IDs before digesting.
11. The canonical body uses frozen/slotted dataclasses, enums, and tuples of
    typed values.  Serialization mappings are temporary wire representations,
    not mutable semantic fields.
12. `coding_tasks.state_version` is deferred.  M7.1.2 does not add a JSON or
    SQL placeholder; the future CAS fence will be designed with the cognitive
    state transitions in M7.1.3/M7.1.8.

## Consequences

- Restart recovery resolves the owner-scoped GoalSpec and verifies the task
  goal/reference projection before loading the task into memory.  Existing
  active-task restart behavior still changes the task to `BLOCKED`; a durable
  GoalSpec is not resume authority.
- AgentLoop may inject bounded GoalSpec identity and explicit requirement facts,
  but the canonical JSON is not copied into arbitrary task metadata or
  unbounded model context.
- Low-level compatibility calls that insert a `coding_tasks` row directly do
  not become an authority bypass: v16 startup backfills/validates their
  declaration, and TaskManager load fails closed if the owner-scoped GoalSpec
  cannot be resolved.
- Workspace, approval, sandbox, tool-capability, and authority composition is
  unchanged.

## Non-goals for M7.1.2

Completion Gate, AgentCognitiveState, planning, verification integration,
Recovery/Replan, context intelligence, model-based goal interpretation, and
GoalSpec revisions are later batches.
