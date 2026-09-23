# Khaos GLM-5.3-Flash Candidate Model Qualification Report

This is a fresh candidate qualification for `zhipu-coding / glm-5.3-flash`.
It used the repaired M8 P0-v2 through P4-v2 path and stopped after the single
candidate lineage. It did not run Coding, the full corpus, Browser, GLM-5.3,
or M9.

## Repository identity

| Field | Result |
|---|---|
| Branch | `codex/m8-coding-evaluation` |
| Exact HEAD | `3c1095ff69b1a5d800d96eb61e8b88a47fceca14` |
| Working-tree identity during run | `1c7883bca8483a1e7072681449b3da059def849b89c8ed180fa893152c2a665d` |
| Working-tree identity after run | Same identity when excluding the protected report and this report |
| Source identity before/after | HEAD unchanged: `3c1095ff69b1a5d800d96eb61e8b88a47fceca14` |
| Source frozen | `YES` during qualification; no qualification-time source mutation |
| Protected report | `UNCHANGED`, untracked, unstaged |
| Commit / push / PR / merge / rebase | none |

The working tree was intentionally dirty before the run. The evidence is
bound to the exact HEAD and working-tree identity above; it is not a claim of
clean exact-SHA reproducibility.

Protected report metadata after the run: `docs/local-security-closure-report.md`,
mode `-rw-r--r--`, size `851` bytes, SHA-256
`85dbfe1ee17475154a0f48a6d308750b252aec75f3b67dd4f2e47f06b25597a1`.

## Credential and Provider gate

| Check | Result | Evidence |
|---|---|---|
| Credential Authority | `PASS` | Operator explicitly unlocked the existing opaque Keychain reference |
| Secretless configuration | `PASS` | No API key or Authorization header in artifacts |
| Provider requests | `8` | P0 `1`, P1 `2`, P2 `1`, P3 `2`, P4 `2` |
| HTTP statuses | `8 x 200` | No 429, 5xx, transport, authentication, or invalid-model failure |
| Provider retries | `0` | No retry was needed |
| Usage accounting | `UNAVAILABLE / PROVIDER_NOT_REPORTED` | Input/output/total tokens are `null`; no zero was fabricated |
| Provider returned model ID | `UNKNOWN / PROVIDER_NOT_REPORTED` | The configured model identity is retained |
| Agent credential unlocks | `0` | Unlock was performed through the explicit operator CLI path |
| Agent credential materialization | `0` | The Agent never accessed credential material |

## Candidate

| Field | Value |
|---|---|
| Provider | `zhipu-coding` |
| Requested model | `glm-5.3-flash` |
| Effective model | `glm-5.3-flash` |
| Provider type | `openai_compatible` |
| Endpoint profile | `https://open.bigmodel.cn/api/coding/paas/v4` |
| Credential reference | `khaos/providers/zhipu-coding/default` |
| Qualification lineage / run ID | `m8-qualification-3bb8c844af124b8d9b2ca3602bf3af0e` |
| Adapter | `ModelRouter -> ModelClient -> openai_compatible` |
| Reasoning / sampling | `UNKNOWN / NOT_REPORTED` |
| Qualification config digest | `0e40d79f711250ab8f60bccf6381ce804331aff7768013a41f8d8b13935f1529` |

Artifacts were retained separately:

- `/tmp/khaos-glm53-flash-p0-p4-v2.0LeCWL/qualification.json`
  - SHA-256: `78ccd01aeb39bb79cec2ded5ca8ef0279ea8c5bb9a72b2c427a6e141f4bac590`
- `/tmp/khaos-glm53-flash-p0-p4-v2.0LeCWL/qualification.jsonl`
  - SHA-256: `e2fa41b8cb567cfeb6f9d65af9697bb548c482d5d7bfd0304e90b9b57b00c7a8`

## Comparability Gate

The valid post-parser-repair GLM-5.3 reference was
`m8-qualification-67a866dc6a4147eda4fad21e7f9efc8e`. The candidate changed
only the selected model identity from `glm-5.3` to `glm-5.3-flash`.

| Check | Result | Evidence |
|---|---|---|
| GLM-5.3 reference qualification | `VALID` | Historical reference and artifacts preserved |
| Same Provider family | `YES` | `zhipu-coding` |
| Same Provider config | `YES` | Qualification config digest unchanged; safe full provider configuration unchanged |
| Same Harness | `YES` | Same source HEAD and production qualification path |
| Same P4 scenario | `YES` | `p4-readonly-authority` |
| Same scenario version | `YES` | `2` |
| Same P4 prompt digest | `YES` | `d5a06983c8c5b6f1b827977bda163613a78bc39f6c2caa14a9be9c293c12c42c` |
| Same fixture digest | `YES` | `864d4713661e2e803890f143eaf0268458186b2fbb74c7bfa2d47382fc745b99` |
| Same Oracle / evaluator | `YES` | Same frozen manifest and semantic evaluator |
| Same tool schema | `YES` | 73 tools; digest `401eab0fb0a481a1f5c20b506f84f1dda42234ff344937807c338eec1fcf1f98` |
| Same policy | `YES` | `cf1bc0a3a97c13e0c9e00a7954a5c168a999671ffaa83a3a58ab33d17e758f93` |
| Same system prompt | `YES` | `c58fa0da8673fe4e9895877877b1a0d5ae876db9efc27b563400cb0bf99b8356` |
| Same budgets | `YES` | P3 `8 turns / 8 tools / 120s`; P4 `12 turns / 24 tools / 300s` |
| Same timeout | `YES` | P3 `120s`; P4 `300s` |
| Same Observability schema | `YES` | `1` |
| Same Trace schema | `YES` | `2` |
| Comparability | `PASS` | All frozen qualification digests and identities were consistent |

## Preflight

```text
Router cold import: PASS
Qualification bootstrap: PASS
Trace: PASS
Observability: PASS
Typed JSONL: PASS
Hidden Oracle Isolation: PASS
Provider calls before qualification: 0
Credential materialization before qualification: 0
Deterministic preflight tests: 31 passed
```

The independent post-run checks also passed operational JSON parsing, one-line
typed JSONL parsing, record-digest validation, JSON/JSONL identity agreement,
and the secret-marker/raw-response durability audit.

## P0-v2

```text
Run ID: m8-qualification-3bb8c844af124b8d9b2ca3602bf3af0e (shared lineage)
Provider requests: 1
HTTP statuses: 200 x 1
Usage: UNKNOWN / PROVIDER_NOT_REPORTED
Response: exact ACK; terminal response present; no tool calls
Result: PASS
```

## P1-v2

```text
Run ID: m8-qualification-3bb8c844af124b8d9b2ca3602bf3af0e (shared lineage)
Provider requests: 2
Tool: synthetic echo_ack
Tool correlation: PASS
Tool result round-trip: PASS
Completion: PASS
Trace: PASS
JSONL: PASS
Result: PASS
```

## P2-v2

```text
Run ID: m8-qualification-3bb8c844af124b8d9b2ca3602bf3af0e (shared lineage)
Production tool count: 73
Schema accepted: YES
Provider status: HTTP 200; no typed Provider error
Result: PASS
```

## P3-v2

```text
Run ID: m8-qualification-3bb8c844af124b8d9b2ca3602bf3af0e (shared lineage)
Real AgentLoop: YES
Workspace authority: YES; side_effect_free=true; source_unchanged=true
Provider requests: 2; HTTP 200 x 2
Model turns: 2
Tool calls: 1
Exact tools: read_file
Automatic repo context: 13 repository-derived items; 18 selected context items;
3 public structure paths; 6 symbols; truncated=false
CompletionGate: reached; status=not_complete; reason=NOT_COMPLETE;
model_finalized=false; accepted completions=0
Trace: PASS; 12 events; reconciliation PASS; truncated=false
Result: PASS
```

## P4-v2

```text
Run ID: m8-qualification-3bb8c844af124b8d9b2ca3602bf3af0e (shared lineage)
Scenario: p4-readonly-authority
Version: 2
Model turns: 2
Tool calls: 1
Exact tools: read_file (README.md)
Provider requests: 2
HTTP 200: 2
429: 0
5xx: 0
Transport failures: 0
Retries: 0
```

## P4 Automatic Repository Context

```text
Repo bundle digest: 1207cb85ca8d1ae33a8f4a9af2d813014c886ce17b399c20097da4d834c06331
Documents: 4
Symbols: 5
Relations/evidence: 22
Context items: 19 selected; 14 automatic repository items; 8 non-repository items
Evicted: 0
Truncated: NO
Context bytes: UNKNOWN / NOT_REPORTED
Context token estimate: UNKNOWN / NOT_REPORTED
```

The model had repository context available and selected a read-only file tool;
zero write/edit/test/browser/terminal calls occurred.

## P4 Final Response

```text
Present: YES
Bytes: 1597
Format: FENCED_JSON
JSON decode: PASS
Schema: PASS
Typed parse: PASS
Parse error: NONE
Typed findings: 3
Raw answer durably persisted: NO
```

## P4 Semantic Review

```text
Required findings: 3
Submitted findings: 3
Matched: 0
Unmatched: 3
Extra: 3
Semantic review: FAIL
```

The response satisfied the structured response contract but none of its three
typed findings matched the frozen oracle. This is separate from JSON/schema
compliance and is the decisive P4 result.

## P4 Completion

```text
Model finalized: NO
CompletionGate reached: YES
CompletionGate status: not_complete
CompletionGate reason: NOT_COMPLETE
Agent terminal: completed
Qualification terminal: FAIL
False completion accepted: 0
```

CompletionGate did not accept an invalid completion. No stale or incomplete
evidence was promoted to success.

## P4 Integrity

| Check | Result | Evidence |
|---|---|---|
| Read-only contract | `PASS` | `side_effect_free=true`; no edits or test/terminal calls |
| Trace | `PASS` | 13 events; reconciliation PASS; no truncation |
| Observability | `PASS` | Required P4 response/context/completion fields present |
| JSONL | `PASS` | One typed record; record digest valid |
| Summary/event reconciliation | `PASS` | Model turns `2`, tool calls `1`, no mismatches |
| Hidden Oracle Isolation | `PASS` | No hidden content or grading metadata exposed |
| Source unchanged | `YES` | Fixture and repository working-tree identity remained bound |
| Secret leakage | `PASS` | Boolean marker scan found no credential-shaped material |

## Failure Attribution

```text
Provider valid: YES
Harness valid: YES
Benchmark valid: YES
Security valid: YES
Primary classification: MODEL_LIMITATION_CONFIRMED
Subtype: SEMANTIC_TASK_FAILURE
Severity: HIGH
Confidence: HIGH
Explanation: Flash completed P0-P3 and produced a valid fenced JSON response
with three typed findings. The P4 oracle matched zero of the three required
findings and classified all three as extra. Provider responses were HTTP 200,
the parser/schema/typed contract passed, repository context was available,
the read-only invariant held, and CompletionGate correctly rejected completion.
This is a semantic model limitation, not a Harness, Provider, Benchmark, or
Security defect.
Rerun performed: NO
Offline attribution: YES; zero additional Provider requests
Budget changed: NO
Prompt changed: NO
Oracle changed: NO
Harness changed: NO
```

No Harness fixes were applied. The first Flash attempt is preserved in the
original JSON/JSONL artifacts and this report; it was not overwritten and was
not rerun to green.

## Candidate Qualification

```text
P0: PASS
P1: PASS
P2: PASS
P3: PASS
P4: FAIL

GLM-5.3-Flash qualification: FAIL
GLM-5.3-Flash primary coding: BLOCKED
Provider integration: PASS for this qualification wire/runtime path
Real AgentLoop traversal: PASS through P3/P4 read-only lifecycle
Real Coding capability: NOT EVALUATED
Real Browser capability: UNMEASURED
Full Corpus readiness: NOT READY
Production readiness: NOT READY
M9: NOT STARTED
Current M8 capability status: EARLY SIGNAL ONLY; full coding capability remains UNMEASURED
```

This five-probe qualification is not a coding benchmark and does not support
competitive claims. The next authorized phase, if desired, would require a
separate decision and must not silently reinterpret this P4 semantic failure.

## Repository state

```text
docs/local-security-closure-report.md: UNCHANGED
Historical GLM-5.3 reports: PRESERVED
Source changed by qualification: NO
Commit: NO
Push: NO
PR #230 update: NO
Repository state: NOT READY / UNCOMMITTED
```
