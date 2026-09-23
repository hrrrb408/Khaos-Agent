# Khaos Fresh GLM-5.3-Flash P4-v3 Qualification Report

Date: 2026-09-13

## Qualification verdict

```text
ENVIRONMENT_BLOCKED
```

The run stopped before any Provider request because the fresh process had a
locked `CredentialSession`. The persistent credential presence check reported
that the `zhipu-coding` credential is present, but the runtime credential was
unavailable. The Agent did not unlock it.

No P4-v3 model result exists for this attempt. The model must not be scored,
and no rerun was performed.

## Repository identity

| Field | Result |
| --- | --- |
| Branch | `codex/m8-coding-evaluation` |
| Exact HEAD | `3c1095ff69b1a5d800d96eb61e8b88a47fceca14` |
| Working-tree identity before/after | `e81db9a7499a8172182d8e3c7547131247c31890034bfcf2b29107fe7c19e6f2` |
| Source identity before/after | `3c1095ff69b1a5d800d96eb61e8b88a47fceca14` |
| Source mutated during qualification | `NO`; qualification did not start |
| Identity exclusions | protected report and this blocked report |
| Commit / push / PR / merge / rebase | none |

The worktree was already dirty. Existing changes were preserved.

## Protected report

`docs/local-security-closure-report.md`: **UNCHANGED**, untracked and
unstaged. Safe metadata remained mode `0644`, size `851` bytes, mtime
`1787640581`. Its contents were not read.

## Provider and credential gate

| Field | Result |
| --- | --- |
| Provider | `zhipu-coding` |
| Requested model | `glm-5.3-flash` |
| Effective model | NOT REACHED |
| Persistent credential presence | `PRESENT` (presence only; secret not read) |
| CredentialSession | `LOCKED` |
| Runtime credential | `UNAVAILABLE` |
| Credential secret reads/materializations | `0` |
| Agent unlock attempts | `0` |
| Provider requests | `0` |
| HTTP responses | `0` |
| Retries | `0` |

The stop reason is exactly `CREDENTIAL_SESSION_UNLOCK_REQUIRED`, classified as
`ENVIRONMENT_BLOCKED`.

## Historical boundary

| Historical lineage | Preserved result |
| --- | --- |
| GLM-5.3 P4-v2 | mechanical FAIL 0/3 |
| GLM-5.3-Flash P4-v2 | mechanical FAIL 0/3 |
| Fresh Flash lineage #1 | `HARNESS_INVALIDATED` |
| Fresh Flash lineage #2 | `BENCHMARK_ONTOLOGY_MISMATCH` |

Historical P4-v2 artifacts were not modified or rescored. P4-v2 and P4-v3
remain non-comparable.

## Preflight

| Check | Result |
| --- | --- |
| Fresh Router import/bootstrap | PASS |
| Router Provider calls | `0` |
| Router credential materialization | `0` |
| Qualification bootstrap after credential stop | NOT REACHED |
| P4-v3 contract freeze | NOT REACHED |
| Context Selection identity | NOT REACHED |
| Typed-Finding evidence | NOT REACHED |
| CompletionGate telemetry | NOT REACHED |
| Source freeze | NOT REACHED |

The gate stopped at the credential-session precondition, before the P4-v3
contract could be used for a model run.

## Experiment identity

| Field | Value |
| --- | --- |
| Qualification lineage ID | `m8-p4-v3-preflight-52ce5da9f93b476ca7f3e64b5a41af27` |
| P4 run ID | NOT CREATED; blocked before Provider activity |
| Scenario | `p4-readonly-authority-v3` (requested only) |
| Scenario version | `3` (requested only) |
| Scenario/Prompt/fixture/schema digests | NOT VERIFIED in this blocked run |
| Oracle/evaluator/tool-schema/policy digests | NOT VERIFIED in this blocked run |
| Trace/observability/typed-finding/context schemas | NOT REACHED |

## P4-v3 Provider execution

No model request was sent.

```text
Model turns: NOT REACHED
Tool calls: NOT REACHED
Files read: NOT REACHED
Editing calls: 0
Execution/test calls: 0
Browser calls: 0
Source unchanged: YES
```

## Output, findings, context, and completion

All are **NOT REACHED** because the credential precondition failed:

- response contract: NOT REACHED;
- typed findings and count reconciliation: NOT REACHED;
- Context Selection history and final identity reconciliation: NOT REACHED;
- semantic Oracle comparison: NOT REACHED;
- CompletionGate telemetry: NOT REACHED;
- raw model response persistence: none.

## Validity

| Dimension | Result |
| --- | --- |
| Provider validity | NOT REACHED |
| Benchmark validity | NOT REACHED |
| Harness validity for a real run | NOT REACHED |
| Typed-Finding evidence | NOT REACHED |
| Context evidence | NOT REACHED |
| Security | PASS; no Provider activity or secret materialization |
| Qualification evidence | INVALID for model scoring because environment was blocked |

## Final qualification

```text
ENVIRONMENT_BLOCKED
```

Primary attribution: **NOT_APPLICABLE**. No model capability conclusion is
allowed from this attempt.

## Capability state

```text
GLM-5.3-Flash P4-v3: NOT QUALIFIED
Real Coding: UNMEASURED
Full Corpus: NOT READY
Browser: UNMEASURED
Production: NOT READY
M9: NOT STARTED
```

The next valid run requires an explicit operator-unlocked
`CredentialSession` for `zhipu-coding` before the qualification process starts.
The Agent must not unlock it. After that external precondition is satisfied, a
new user-authorized run must create a new lineage/P4 run and may execute
exactly one P4-v3 only; this blocked attempt must remain preserved.

## Repository state

Qualification artifacts: this blocked report only; no qualification JSONL was
created because no P4 run started. Git publication: **UNCOMMITTED**.

`READY TO COMMIT / NOT READY`: **NOT READY**. No commit or push was performed.
