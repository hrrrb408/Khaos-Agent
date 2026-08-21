# ADR-046: Give the planned-execution journal one writer

状态：accepted

日期：2026-08-22

## 背景

Execution-run lifecycle and edit-journal phases have different state machines, but both were
implemented inside `PlanApprovalStore`. The journal includes additional rollback identity and
directory-sync evidence; keeping that SQL in the approval facade made it possible for a future
approval change to bypass journal CAS or proof requirements.

## 决策

`python/khaos/coding/planning/approval/execution_journal_writer.py` 的
`PlanExecutionJournalWriter` is the sole writer for durable edit-journal state. It owns:

- journal event insertion and the run journal-count increment;
- forward and rollback phase transitions with phase/version CAS;
- rollback filesystem identity evidence;
- rollback directory-sync digest and terminal sync proof;
- the legacy `update_edit_event` call shape as a constrained compatibility wrapper.

The writer receives an already-open SQLite connection and an audit callback. Every mutation is
performed in one `BEGIN IMMEDIATE` transaction and rolls back on validation, CAS, or audit
failure. It does not own connection lifecycle, approval/lease state, or filesystem effects.
`PlanApprovalStore` keeps only parameter-preserving compatibility delegates for one migration
cycle. The static digest helper delegates to this owner so callers cannot accidentally create a
second canonical digest implementation.

## 证据与删除条件

- `python/tests/coding/test_execution_writer_boundary.py` proves facade delegation and direct
  journal CAS behavior while the external connection remains usable.
- Existing durability, rollback ownership, directory-sync, and terminal-hardening suites cover
  the complete phase graph and fail-closed evidence checks.
- After production callers use `PlanExecutionJournalWriter` or a higher-level coordinator,
  remove the store delegates, the legacy `update_edit_event` entry point, and the static helper.
