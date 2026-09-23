# Khaos Fresh GLM-5.3-Flash Semantic-Attribution Qualification Report

Date: 2026-09-13

This report records one fresh, operator-started GLM-5.3-Flash P0-P4
qualification lineage. It did not run Coding, the full corpus, Browser,
GLM-5.3, or M9. The first attempt is preserved and was not rerun.

## Qualification verdict

The provider and real AgentLoop path were reached successfully:

~~~text
P0 PASS
P1 PASS
P2 PASS
P3 PASS
P4 mechanical result FAIL 0/3
~~~

The formal fresh qualification is:

~~~text
HARNESS_INVALIDATED
~~~

Both P3 and P4 contain a non-reconcilable context_selection_detail
observation. The final Context Engine metrics snapshot differs from the only
context_selected Trace event. Per the gate, the official P4 binary result is
preserved, but semantic capability is not scored or attributed from this
lineage.

## Repository identity

| Field | Result |
| --- | --- |
| Branch | codex/m8-coding-evaluation |
| Exact HEAD | 3c1095ff69b1a5d800d96eb61e8b88a47fceca14 |
| Working-tree identity before | 77b4740de229b9e82aa283079187f95acbd037eb2a84ef09218402a8cba941dc |
| Working-tree identity after | same, excluding the protected report and this report |
| Source identity before/after | HEAD/source SHA unchanged: 3c1095ff69b1a5d800d96eb61e8b88a47fceca14 |
| Source mutated during qualification | NO |
| Source freeze | YES; no qualification-time source mutation observed |
| Commit / push / PR / merge / rebase | none |

The repository was already dirty. Existing changes and reports were preserved.
The qualification output itself was written outside the repository.

## Protected report

docs/local-security-closure-report.md: UNCHANGED, untracked, unstaged;
mode 0644, size 851 bytes. Its contents were not read or modified.

## Provider and credential gate

| Field | Result |
| --- | --- |
| Provider | zhipu-coding |
| Requested model | glm-5.3-flash |
| Effective model | glm-5.3-flash |
| Provider type | openai_compatible |
| Endpoint profile | https://open.bigmodel.cn/api/coding/paas/v4 |
| Adapter | ModelRouter -> ModelClient -> openai_compatible |
| Credential reference | khaos/providers/zhipu-coding/default |
| Qualification config digest | 0e40d79f711250ab8f60bccf6381ce804331aff7768013a41f8d8b13935f1529 |
| Provider-returned model ID | UNKNOWN / PROVIDER_NOT_REPORTED |
| Reasoning / sampling | UNKNOWN / NOT_REPORTED |
| Total Provider requests | 8 |
| HTTP result | 8 x 200 |
| Provider retries | 0 |
| Credential Authority | PASS |
| Agent direct credential reads | 0 |
| Agent credential unlocks | 0; unlock was explicitly operator-started through --unlock zhipu-coding |
| Secret values printed | false |

The provider transport reached the configured endpoint through the existing
CredentialBroker boundary. No credential value or authorization header was
persisted in the qualification artifacts.

Usage accounting was not reported by the provider adapter:

~~~text
input_tokens: null
output_tokens: null
total_tokens: null
Usage Accounting: UNAVAILABLE / PROVIDER_NOT_REPORTED
~~~

No unavailable usage was fabricated as zero. Provider failure mapping is
PASS for the deterministic typed mapping regression; no live provider error
branch occurred in this lineage.

## Experiment identity

| Field | Value |
| --- | --- |
| Qualification lineage / run ID | m8-qualification-9b3ccf143eee4dbd92c40161e358dfb5 |
| P4 scenario | p4-readonly-authority |
| P4 version | 2 |
| P4 prompt digest | d5a06983c8c5b6f1b827977bda163613a78bc39f6c2caa14a9be9c293c12c42c |
| P4 fixture digest | 864d4713661e2e803890f143eaf0268458186b2fbb74c7bfa2d47382fc745b99 |
| P4 scenario digest | 314b8022fd0eb325bd8199379135d22f3673cf2e27f9ef0a9d1c3b171eb9fa58 |
| Manifest digest | acc964e299b00ca276f0c9943d29f984d77553ba0da1104728f9474cf4887aca |
| Oracle/evaluator digest | d025f1e0812cc2d66fa19ca046f3b0731c78bb46039c7c2612d209a528ce9a31 |
| Tool-schema digest | 401eab0fb0a481a1f5c20b506f84f1dda42234ff344937807c338eec1fcf1f98 |
| Production tool count | 73 |
| Policy digest | cf1bc0a3a97c13e0c9e00a7954a5c168a999671ffaa83a3a58ab33d17e758f93 |
| System-prompt digest | c58fa0da8673fe4e9895877877b1a0d5ae876db9efc27b563400cb0bf99b8356 |
| Trace schema | 2 |
| Observability schema | 1 |
| Typed-finding evidence schema | 1 |
| Context-selection evidence schema | 1 |
| P4 repository base revision | 5a499966272316ca967d4a366ace2808134f691d |

Frozen budgets were unchanged: P3 8 turns / 8 tools / 120 seconds; P4
12 turns / 24 tools / 300 seconds.

## Preflight

~~~text
Router / qualification bootstrap: PASS
Pre-qualification Provider requests: 0
Pre-qualification credential materialization: 0
CredentialSession: UNLOCKED by the explicit operator CLI path
Benchmark semantics changed: NO
Legacy artifact reader: PASS
Historical candidate detail sentinel: NOT_AVAILABLE_LEGACY_ARTIFACT
Hidden Oracle isolation: PASS
~~~

The qualification source SHA and working-tree identity remained unchanged.
The CLI record does not emit a separate file-level source digest; the source
identity above is therefore bound to the unchanged exact HEAD.

## P0

~~~text
Result: PASS
Provider requests: 1
HTTP: 1 x 200
Provider retries: 0
Exact acknowledgement: PASS
Unexpected tool calls: 0
~~~

This is a real provider smoke response, not a fake-model result.

## P1

~~~text
Result: PASS
Provider requests: 2
HTTP: 2 x 200
Synthetic tool: echo_ack
Valid tool call: YES
Tool-result round trip: YES
Unexpected retries: 0
~~~

## P2

~~~text
Result: PASS
Provider requests: 1
HTTP: 1 x 200
Production tool count: 73
Schema accepted: YES
Unexpected tool calls: 0
~~~

## P3

~~~text
Result: PASS
Real model: YES
Real AgentLoop: YES
Provider requests: 2
HTTP: 2 x 200
Model turns: 2
Tool calls: 1
Exact tool: read_file
Editing calls: 0
Test calls: 0
Browser calls: 0
Agent status: COMPLETED
Side-effect-free: YES
Source unchanged: YES
CompletionGate: reached; status=not_complete; reason=NOT_COMPLETE; authority=CompletionGate
~~~

P3 response formatting was NON_JSON_TEXT, so no semantic finding was
attempted. This did not prevent the read-only AgentLoop probe from completing.

## P4 mechanical result

~~~text
Result from canonical evaluator: FAIL
Official semantic score: 0/3
Provider requests: 2
HTTP: 2 x 200
Model turns: 2
Tool calls: 4
Exact tool: read_file
Editing calls: 0
Test calls: 0
Browser calls: 0
Normal completion: YES
Read-only invariant: YES
~~~

Response and typed parsing were structurally valid:

~~~text
Format: FENCED_JSON
JSON decode: PASS
Schema: PASS
Typed parse: PASS
Typed findings: 3
Required findings: 3
Matched: 0
Unmatched: not persisted by the safe projection
Extra: 3
Semantic review: FAIL
~~~

CompletionGate telemetry was correct and did not falsely accept completion:

~~~text
model_finalized: false
proposal_reached: true
proposal_status: recorded
gate_reached: true
gate_status: not_complete
gate_reason_code: NOT_COMPLETE
gate_authority: CompletionGate
completion_acceptances: 0
completion_rejections: 0
~~~

The normal AgentLoop terminal status is not treated as CompletionGate
acceptance.

## Candidate typed findings

The durable projection contains safe structural metadata only. Concept values
were represented by redaction sentinels and are not reproduced here.

| Finding | Ordinal | Safe category | Safe file | Concepts | Safe finding digest | Redacted | Projection truncated |
| --- | ---: | --- | --- | --- | --- | --- | --- |
| 1 | 0 | authority_definition | src/authority.py | REDACTED, 2 values | f1ca30d6e432405d233b2fc9b16aa0294f36a09b6d6e726c5e6eec32c79d4f90 | YES | NO |
| 2 | 1 | consumer | src/consumer.py | REDACTED, 3 values | a2b6863e6710d17c1dbee2cb225e7ae1ae048ac73d3919fd622536fb74ff57a6 | YES | NO |
| 3 | 2 | enforcement_boundary | src/policy.py | REDACTED, 3 values | d7a1f8882d02d6be8422a79d80f2c688cb7ffe4c2cb07f2eba81d95e2132cd14 | YES | NO |

~~~text
Typed parser count: 3
Persisted candidate count: 3
Evaluator submitted count: 3
Count reconciliation: PASS
~~~

The safe projection therefore proves cardinality and file/category metadata,
but not exact concept overlap. This is an evidence boundary, not a claim that
the hidden concept values were empty.

## Candidate-to-oracle offline comparison

The offline comparison was performed only against the evaluator-owned oracle;
oracle contents and finding identifiers are not written into this report or
the candidate JSONL.

| Candidate | File proximity | Exact category match | Concept join | Safe interpretation |
| --- | --- | --- | --- | --- |
| 1 | EXACT | NO | UNKNOWN; values redacted | Correct target file; label is a semantic/serialization near miss |
| 2 | EXACT | NO | UNKNOWN; values redacted | Correct target file; label is generic relative to the oracle role |
| 3 | EXACT | NO | UNKNOWN; values redacted | Correct target file; label is a semantic/serialization near miss |

All three candidate files correspond to the three public review roles, but the
canonical evaluator uses exact category matching. The visible labels use
underscore forms while the evaluator's expected category form is not disclosed
in this report. Because context selection is not reconcilable and concepts are
redacted, this remains a possible benchmark-ontology mismatch rather than a
confirmed model limitation.

## Automatic Context Selection

The event-level P4 selection projection was complete and untruncated:

~~~text
Selected items: 19
Automatic repository-derived items: 14
Tool-acquired items: 0
Non-repository items: 5
Evicted: 0
Compressed: 0
Selection projection: 19 original / 19 persisted
Projection truncated: NO
~~~

The candidate files were present in the event-level automatic context:

| Candidate/oracle file | Event selection ordinal | Source channel | Kind | Selected |
| --- | ---: | --- | --- | --- |
| src/authority.py | 5 | automatic_repo_context | file_region | YES |
| src/consumer.py | 7 | automatic_repo_context | file_region | YES |
| src/policy.py | 8 | automatic_repo_context | file_region | YES |

The unrelated fixture file was also selected at ordinal 6. The final summary
reported 19 selected items but 22 projection items and no selected repository
paths. That summary is not a second valid context selection; it is the
reconciliation defect described below.

### P3/P4 context reconciliation evidence

| Probe | Event digest | Event original/persisted | Summary digest | Summary original/persisted | Result |
| --- | --- | --- | --- | --- | --- |
| P3 | 29e6465056806d82c8e5227ba6ccaf41f543f91a535437530aa3b79c49afa201 | 18 / 18 | f1201242e35889a5841fba340108c9b621e05c4c0d6de47efd10d0e0c98e39ce | 21 / 21 | OBSERVABILITY_DEFECT |
| P4 | 12b9798448e271427238bf99d7150460823164490d45194d1372cd5d31b4f95a | 19 / 19 | dc1cade65885c6a651a2d282a23156a2299783e51f134292e44c77ac61179316 | 22 / 22 | OBSERVABILITY_DEFECT |

Neither projection was truncated. The mismatch is a join/identity problem,
not an evidence-size limit.

## Verification behavior

~~~text
Repository tools used: read_file
Exact P4 tool calls: 4 x read_file
Editing: none
Execution/terminal: none
Tests/verification commands: none
Browser: none
Verification style: INITIAL_CONTEXT_ONLY / UNKNOWN for this read-only review
Missed verification opportunity: INCONCLUSIVE; P4 has no executable-change oracle
~~~

The model stopped after read-only inspection, which is allowed by the P4-v2
natural-stop contract. No security boundary was bypassed.

## Harness defect review

| Defect | Reproduction/evidence | Severity | Affected subsystem | Generalizable | Security impact | Recommended fix |
| --- | --- | --- | --- | --- | --- | --- |
| Final context summary does not reconcile with the last context_selected event | P3 and P4 both report context_selection_detail; rebalance_messages() calls build() and updates the Context Engine last-selection snapshot, while AgentLoop emits context_selected only in _build_context(); the invoker later records the final metrics snapshot | HIGH | Context Engine observability / Trace reconciliation | YES | None observed; blocks trustworthy qualification attribution | Future isolated gate: emit/identify every selection, including rebalance, or bind the final summary to the matching event projection; add build+rebalance deterministic regression |

The relevant current-path evidence is visible in:

- python/khaos/agent/core.py:3418-3454 — the event is recorded after
  build_for_agent().
- python/khaos/coding/context_engine/service.py:701-865 — rebalance calls
  build() without emitting a collector event.
- python/khaos/coding/context_engine/service.py:1645-1666 — each build
  replaces the last selection snapshot.
- python/khaos/evaluation/coding/runtime_invoker.py:318-321 — the final
  snapshot is recorded after the AgentLoop ends.
- python/khaos/evaluation/coding/metrics.py:1238-1345 and :2100-2128 —
  summary/event comparison and mismatch classification.

No repair was applied in this gate because the frozen protocol explicitly
forbids Context Engine repair and reruns after the first P4.

Severity summary:

~~~text
BLOCKER: 0
HIGH: 1 candidate Harness defect
MEDIUM: 0
LOW: 0
INFO: typed concept values are redacted in the safe projection; not classified as a defect without the transient raw values
~~~

Harness fixes applied: NONE.

## Hypothesis evaluation

### H_A — Khaos scaffolding under-elicits verification

Evidence for: the model used only read_file and stopped without any separate
verification action.

Evidence against: P4 is a read-only repository-understanding task; no code
mutation or executable verification is required, and normal stopping is part
of the contract.

Verdict: INCONCLUSIVE.

### H_B — P4 ontology is unusually Khaos-specific

Evidence for: all three target files were located exactly, while all three
safe category labels failed exact evaluator matching; the prompt describes
natural-language roles rather than exposing canonical machine labels.

Evidence against: exact concept values are redacted, and context telemetry is
invalidated, so the complete semantic relation cannot be reconstructed.

Verdict: POSSIBLE, not confirmed.

### H_C — GLM-5.3-Flash has a genuine semantic repository-reasoning limitation

Evidence for: official evaluator result is FAIL 0/3.

Evidence against: the model found all three expected files and returned three
typed findings; category/ontology and concept evidence cannot be separated from
the invalid context join.

Verdict: INCONCLUSIVE; no model limitation claim.

### H_D — Context salience biases the model toward wrong entities

Evidence for: none from the valid event-level projection.

Evidence against: all three target files were automatically selected and had
file-region entries; the final summary is inconsistent and cannot be used for
ranking.

Verdict: INCONCLUSIVE, not supported.

## Primary semantic attribution

~~~text
Primary classification: INCONCLUSIVE
Secondary tags:
  OBSERVABILITY_DEFECT / context_selection_detail
  POSSIBLE_BENCHMARK_ONTOLOGY_MISMATCH
  SAFE_CONCEPT_DETAIL_REDACTED
Confidence: HIGH that the evidence is invalidated; LOW for semantic cause
Interpretation: INCONCLUSIVE
~~~

The official FAIL 0/3 is retained as a mechanical result. It is not
converted into GENUINE_MODEL_SEMANTIC_LIMITATION, because the gate requires
reconcilable typed finding and context evidence before semantic attribution.

## Historical vs fresh Flash

~~~text
Historical Flash P4: FAIL 0/3
Historical detailed cause: INCONCLUSIVE
Fresh Flash P4 mechanical result: FAIL 0/3
Fresh detailed cause: INCONCLUSIVE / HARNESS_INVALIDATED
Same broad failure: YES, both official mechanical results are 0/3
Same exact finding pattern: UNKNOWN HISTORICALLY
Historical result changed: NO
~~~

## Security, artifacts, and offline validation

Artifacts were retained separately and not overwritten:

~~~text
/private/tmp/khaos-glm53-flash-semantic.EquBMY/qualification.json
SHA-256: eb3d8ceed83b8c690ec65ec8964e8800fcd78d5b5247c6c0e876a942ea8c84d8

/private/tmp/khaos-glm53-flash-semantic.EquBMY/qualification.jsonl
SHA-256: 02685ef6b5a791bd9cf7e925b5fb435dd0d2f73284e4732bd92e0957912cb47e
~~~

~~~text
qualification.json permission: 0644
qualification.jsonl permission: 0600
JSONL records: 1
Typed JSONL reader: PASS
JSONL result state: FAILURE (official P4 mechanical failure)
JSONL identity binding: PASS
Raw response fields: absent
Credential-shaped artifact matches: 0
Hidden-path markers: 0
Non-empty hidden finding IDs: 0
Timestamp ordering: PASS
Trace truncation: NO; dropped events: 0
CompletionGate telemetry: PASS; gate rejected completion as NOT_COMPLETE
~~~

Offline deterministic regression subset: 54 passed.

This included P4 qualification/parser tests, typed-finding projection and
offline join tests, context/Trace reconciliation tests, hidden-oracle
isolation, CompletionGate telemetry, and typed Provider failure mapping.

## Capability state

~~~text
Provider Integration: PASS
Real AgentLoop path: PASS for P3/P4 traversal
Fresh Flash Qualification: HARNESS_INVALIDATED
Real Coding: UNMEASURED
Full Corpus: NOT READY
Real Browser: UNMEASURED
Production Readiness: NOT READY
M9: NOT STARTED
~~~

No competitive or capability-strength claim is made from this invalidated
single P4 lineage.

## Recommended next gate

~~~text
BLOCKED_BY_HARNESS_DEFECT
~~~

First close the generalizable context event/snapshot identity defect with an
isolated deterministic build-plus-rebalance regression. Only then run a new
fresh Flash P4 lineage to decide whether the category mismatch is a benchmark
ontology issue, an output-contract issue, or a model limitation. Do not repair
the Oracle or prompt based on this result, and do not rerun this lineage.

## Repository state

~~~text
Source mutated during qualification: NO
Qualification artifacts: structurally VALID but qualification evidence INVALIDATED
Git publication: UNCOMMITTED
Full corpus readiness: NOT READY
READY TO COMMIT / NOT READY: NOT READY
~~~

No commit, push, PR update, merge, rebase, reset, or clean operation was
performed.
