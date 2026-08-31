# ADR-081: Plan-bound sub-agent v2

## Status

Accepted for M7.8.

## Decision

Coding sub-agents are admitted only through an immutable `SubAgentAssignment`
that binds one parent-owned GoalSpec, one current published `PlanRevision`,
one plan step, the parent task/workspace/repository/generation/epoch, and a
reviewed tool subset. The child execution principal is
`subagent:<parent-owner>:<assignment-id>` and the assignment depth is exactly
one.

The child receives a `DelegatedExecutionContext` and attaches to the existing
parent workspace. It does not create a coding task, workspace, plan,
completion decision, recovery decision, or nested delegation tree. Generic
free-form sub-agent Spawn remains a legacy office path and is forced to office
mode; its JSON fields cannot create coding authority.

Assignment rows are immutable. Run state is a separate compare-and-swap
projection. Route admission reloads the assignment and current plan state,
and the completion gate blocks while a child run is `PENDING` or `ACTIVE`.
Replanning marks assignments bound to older published revisions stale in the
same publication transaction. Restart reconciliation marks unfinished runs
`ORPHANED`; no legacy `subagent_tasks` row is backfilled as authority.

Malformed or cyclic legacy plans fail closed and produce no executable layer.
An invalid, blocked, or stale published plan cannot spawn a child or invoke a
fallback coding path.

## Consequences

This adds v25 assignment/run persistence and actor/owner fields to the route
ledger. Child reports are bounded low-trust observations; durable step state,
route records, approvals, recovery, and completion remain authoritative. The
parent owner remains the plan and lifecycle scope while the child actor is
recorded separately for audit and route identity.
