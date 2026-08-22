# ADR-062: Finish the PlanApprovalStore boundary migration

## Status

Accepted — 2026-08-22

## Context

The approval refactor had introduced four explicit owners, but
`PlanApprovalStore` still exposed compatibility methods for approval reads,
execution reads, execution writes, and edit-journal writes.  That kept the
largest facade looking like the domain owner and allowed new production code
to bypass the intended ports.

## Decision

- `PlanApprovalReadModel` is injected into `PlanExecutionGate`,
  `PlanApprovalService`, `WorkspaceMutationEngine`, and
  `TrustedVerificationRunner` for approval queries.
- `PlanExecutionReadModel`, `PlanExecutionWriter`, and
  `PlanExecutionJournalWriter` are injected into the mutation, recovery,
  verification, and runtime composition paths.
- `PlanApprovalStore` owns only approval-ledger mutations, receipt/lease/epoch
  state, poison scopes, and the connection/schema bootstrap it still needs.
  It no longer forwards read or planned-execution methods.
- Verified execution-read authority is configured on the execution read model
  itself, so moving a call site cannot silently remove the fail-closed proof
  check.
- Tests use the same explicit owners and assert that removed facade methods do
  not exist.  No test-only compatibility shim is allowed.

## Evidence and deletion record

- `test_approval_read_model_boundary.py`,
  `test_execution_read_model_boundary.py`, and
  `test_execution_writer_boundary.py` cover owner identity, no-delegate
  negatives, read-only connection behavior, and writer transaction behavior.
- Approval, workspace mutation/recovery, rollback directory-sync, terminal
  hardening, and trusted-verification suites cover the unchanged state
  machines and proof checks after caller migration.
- The deleted surface includes approval read delegates, execution read/write
  delegates, journal delegates, `_row_to_execution_run`, and the store's
  dynamic execution audit hook.  Future changes must target the named owner
  rather than reintroducing a facade method.
