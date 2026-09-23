# M8 GLM-5.3 P4-v2 False Completion Offline Diagnostic Gate

Status: DIAGNOSTIC COMPLETE — OFFLINE ONLY

This document is a separate forensic report for the preserved qualification
attempt. It is not a rerun, confirmation run, benchmark result, or capability
claim. No source, evaluator, prompt, fixture, oracle, budget, timeout, policy,
provider adapter, Trace v2 contract, or CompletionGate implementation was
changed by this gate.

## Decision summary

- Target P4 result remains `FAIL`.
- Primary root-cause classification: `INCONCLUSIVE`.
- Secondary signal: `MODEL_LIMITATION_SUSPECTED`, with low-to-medium confidence;
  the persisted evidence cannot prove that the model emitted no findings.
- No provider, environment, security, benchmark-oracle, or CompletionGate
  functional defect was established.
- One general observability limitation was recorded; no repair was applied.
- Real Provider calls during this diagnostic: `0`.
- Credential reads/unlocks during this diagnostic: `0`.
- P0–P4 were not rerun. The large corpus was not started.

## Provenance and preservation

| Field | Value |
|---|---|
| Branch | `codex/m8-coding-evaluation` |
| Current base commit | `3c1095ff69b1a5d800d96eb61e8b88a47fceca14` |
| Target run | `m8-qualification-776d42ccfa69473a98bdeb0514ea158b` |
| Provider | `zhipu-coding` |
| Model | `glm-5.3` |
| Target source SHA | `3c1095ff69b1a5d800d96eb61e8b88a47fceca14` |
| Target working-tree identity | `6df93ba62ab869164830e9830565f760608f0bc44a247206d1b40f6554b2ed64` |
| Provider config digest | `0e40d79f711250ab8f60bccf6381ce804331aff7768013a41f8d8b13935f1529` |
| Scenario | `p4-readonly-authority` v2 |
| Scenario digest | `314b8022fd0eb325bd8199379135d22f3673cf2e27f9ef0a9d1c3b171eb9fa58` |
| Fixture digest | `864d4713661e2e803890f143eaf0268458186b2fbb74c7bfa2d47382fc745b99` |
| Prompt digest | `d5a06983c8c5b6f1b827977bda163613a78bc39f6c2caa14a9be9c293c12c42c` |
| System prompt digest | `c58fa0da8673fe4e9895877877b1a0d5ae876db9efc27b563400cb0bf99b8356` |
| Production tool-schema digest | `401eab0fb0a481a1f5c20b506f84f1dda42234ff344937807c338eec1fcf1f98` |
| Policy digest | `cf1bc0a3a97c13e0c9e00a7954a5c168a999671ffaa83a3a58ab33d17e758f93` |
| Qualification record digest | `cd8f7e07a1229d96d2b972326fa03dcf13493ffc91978e91984088d7c4e034a1` |

The preserved artifacts were not overwritten:

- `/tmp/khaos-glm53-p0-p4-v2.AS0MxP/qualification.json` — 29,170 bytes,
  SHA-256 `18b0e504dc720083307b1f4c716ee4daed6f0cd88ac637f134cd8fe26f700c3d`.
- `/tmp/khaos-glm53-p0-p4-v2.AS0MxP/qualification.jsonl` — 21,186 bytes,
  SHA-256 `c767cdd9cd60dcf871d47efaba5f61d6090eb8fc4f3679f49e9c2bee9c70aeab`.
- `docs/m8-fresh-glm53-p0-p4-v2-qualification-run-776d42ccfa69473a98bdeb0514ea158b.md`
  remains the original qualification report and was not edited.

The protected file `docs/local-security-closure-report.md` was inspected only
through safe metadata. It remains untracked, unchanged, and unstaged:

- mode `100644`
- size `851` bytes
- SHA-256 `85dbfe1ee17475154a0f48a6d308750b252aec75f3b67dd4f2e47f06b25597a1`

The current worktree already contains unrelated/pre-existing modifications and
untracked files. No reset, checkout, clean, stage, commit, push, rebase, or PR
operation was performed.

The post-diagnostic working-tree identity, excluding both the protected report
and this new diagnostic report, is
`bd66ef7e0481a46d07032a91edf80cdfdb8c745c1cd25f41a7c92749335b3b01`.
It does not equal the target record's `6df93ba...` identity; the mismatch is
retained as provenance and is not silently normalized. This gate did not
attribute or remove the pre-existing dirty-worktree changes.

## P4 mechanical evidence

The preserved JSONL record validates as `CodingQualificationRecordV1`; its
record digest matches. The P4 stage contains:

| Metric | Observed value |
|---|---:|
| Provider requests | 1 |
| HTTP status | 200 |
| Typed provider errors | none |
| Provider retries | 0 |
| Real model | yes |
| Real AgentLoop | yes |
| Model turns | 1 |
| Tool calls | 0 |
| Edits / terminal / tests / browser | 0 / 0 / 0 / 0 |
| Agent status | `COMPLETED` |
| Source unchanged | `true` |
| Side-effect free | `true` |
| Cleanup | `true` |
| Trace v2 events | 6 |
| Trace truncated/dropped | `false` / `0` |
| Trace reconciliation | `PASS` |
| Usage | `UNKNOWN / PROVIDER_NOT_REPORTED` |
| Input/output/total tokens | `null` / `null` / `null` |

The evaluator result is:

- required finding count: `3`
- submitted typed finding count: `0`
- matched finding IDs: empty
- extra finding count: `0`
- review findings pass: `false`
- normal loop completion: `true`
- read-only invariant: `true`

This is a genuine mechanical P4 failure. It is not a provider error,
timeout, tool-budget exhaustion, write violation, or fixture mutation.

## Public prompt and budget audit

The public P4 prompt in `python/khaos/evaluation/coding/pack/manifest.yaml`
(lines 293–317) requires one JSON object with a findings array covering the
authority definition, its consumer, and the enforcement boundary. Each finding
must contain `category`, `file`, and `concepts` grounded in the files. The
prompt permits bounded read-only tools and explicitly forbids edits, commands,
network/browser access, and write/test tools.

The configured P4 budget was not reached or changed:

- max model turns: `12`
- max tool calls: `24`
- timeout: `300` seconds
- max output bytes: `65,536`
- max tool events: `256`

The coding system prompt encourages repository reading and tool-assisted code
navigation. No contradictory system instruction requiring direct answering or
forbidding repository inspection was found. The absence of a tool call is
therefore an allowed model decision, not by itself a harness failure.

## Tool surface audit

The runtime registry contains 73 coding-mode definitions. The P4 review
allowlist in `python/khaos/evaluation/coding/runtime_invoker.py` (lines 31–44)
contains 12 names, and all 12 are present:

`read_file`, `search_files`, `list_directory`, `file_info`, `tree_view`,
`file_search_content`, `code_search`, `code_symbols`, `git_diff`, `git_log`,
`git_status`, `git_pr_body`.

The first ten are declared read-only in the registry. `code_search` and
`code_symbols` are exposed as bounded repository-read surfaces; their effect
metadata is `unknown`, but no write, execution, test, or browser tool is in the
P4 allowlist. A deterministic registry inspection found no missing allowlisted
tool and no schema-construction error.

The AgentLoop passes the tool schema through the provider-neutral router. The
OpenAI-compatible client adds `tools` when the model advertises tool support,
but does not send an explicit `tool_choice` (`python/khaos/routing/model_client.py`
lines 181–188). This leaves selection to the provider/model default, which is
compatible with the P4 wording “as needed”. No tool-admission defect is shown.

## Model-visible context reconstruction

The qualification artifacts do not persist the full model-facing context or
the Repo Intelligence/Context Engine counters. To close that evidence gap
without invoking a provider, the same public fixture and production-shaped
`ContextIntelligenceService` and `ContextEngineService` path were exercised
offline. Only the public `repo/` tree was used; no hidden-oracle contents were
read.

The deterministic reconstruction produced:

- fresh repository bundle, no partial/truncation condition;
- 4 source documents: `src/authority.py`, `src/unrelated.py`,
  `src/consumer.py`, and `src/policy.py`;
- 5 indexed symbols and 22 bounded relation/evidence records;
- structure paths for the public README and the four source files;
- Context Engine selection of 16 items, including 14 repository-derived
  items, with 0 evicted and 0 truncated items;
- approximately 9,001 context bytes / 2,255 context tokens in the offline
  reconstruction;
- the three authority-related source files were present in the model-facing
  repository context before any model tool call.

Consequently:

| Question | Finding |
|---|---|
| Repository tool calls in target P4 | `0` |
| Automatic Repo Intelligence evidence | `YES` in the same production composition |
| Tool-based repository inspection | `NO` |
| Could the task be solved from initial context alone? | `YES` in the offline reconstruction |
| Exact target context bytes/digest recoverable from artifacts? | `NO`; active facts/history/context counters were not persisted |

The correct interpretation is therefore “zero tool calls with repository
evidence already available”, not “zero repository evidence”. This weakens the
case for a tool-use convergence defect and makes an immediate one-turn answer
plausible. It does not prove that the model's final answer was correct or
incorrect because the final text was not retained.

## Sanitized trajectory

The target P4 Trace v2 is complete and reconciles with the summary counters.
Its bounded event sequence is:

1. `model_response` — one model turn; content retained only as a digest.
2. `completion_evaluated`.
3. `completion_gated`.
4. `recovery_control`.
5. `done`.
6. `terminal` with terminal reason `completed`.

There were no tool calls, permission requests, edits, verification runs,
subagents, browser sessions, or human interventions. No raw model response,
tool arguments, repository contents, or credential material is present in the
durable trace.

`RuntimeCodingAgentInvoker` keeps bounded assistant output in memory only,
extracts typed `ReviewFinding` values, and returns the typed tuple
(`python/khaos/evaluation/coding/runtime_invoker.py` lines 245–263 and
293–320). The durable record therefore proves `submitted_finding_count=0`,
but cannot distinguish:

1. no findings were emitted;
2. the final response was not valid JSON;
3. the response used a shape or field that the typed parser rejects; or
4. a semantically useful answer was outside the exact declared output
   contract.

The offline parser audit confirmed that a conforming plain JSON answer parses
to three typed findings, and a conforming fenced JSON answer also parses. A
natural-language prefix, unknown field, or missing concepts are rejected. This
matches the public “only one JSON object” requirement; it is not evidence of a
benchmark evaluator defect.

## Completion pipeline and false-completion test

The AgentLoop's natural end-turn path invokes completion proposal, then
`_evaluate_completion_gate`, then recovery (`python/khaos/agent/core.py`
lines 2248–2295 and 2923–2958). The production factory composes
`CompletionGate` with its fail-closed default authority policy
(`python/khaos/runtime/factory.py` lines 2293–2303).

The live `completion_gated` message includes a typed `gate_status`, but the
qualification Trace v2 projection intentionally retains only bounded event
identity/digests. The preserved trace has the event name but no recoverable
gate status. `completion_acceptances=0` and `completion_rejections=0` are
event counters; they are not a gate verdict. The gate's exact status is
`UNKNOWN / NOT_RECOVERABLE` from this run.

The `completed` value used by the P4 evaluator is the AgentExecution natural
terminal status. It is not proof that the task lifecycle was projected to
completed. `_finalize_task` explicitly leaves successful task projection to
CompletionGate (`python/khaos/agent/core.py` lines 3296–3359).

Strict false-completion determination:

- model natural completion/proposal: `YES`;
- P4 semantic evidence in the persisted parser result: missing;
- CompletionGate accepted the missing evidence: `UNKNOWN`;
- CompletionGate rejected it: `UNKNOWN`;
- confirmed false CompletionGate acceptance: `NO EVIDENCE`;
- confirmed CompletionGate defect: `NO`.

The result is a false-completion candidate, not a proven false completion.
P4 remains failed because the external typed review oracle did not receive the
required findings, while lifecycle authority remains unproven rather than
declared broken.

## Root-cause classification

| Candidate | Classification | Confidence | Severity | Conclusion |
|---|---|---:|---|---|
| Missing P4 findings in typed evaluator input | `INCONCLUSIVE`; `MODEL_LIMITATION_SUSPECTED` secondary | medium-low | INFO | Raw final response is unavailable, so literal model omission is not proven. |
| No tool call | none | high | INFO | Public source evidence was automatically injected; no tool requirement was violated. |
| Provider/adapter failure | none | high | INFO | One HTTP 200 response, no typed error, no retry. |
| Fixture/oracle isolation defect | none | high | INFO | The public fixture path and typed oracle separation were preserved. |
| CompletionGate functional defect | none established | high | INFO | The semantic review oracle is external to CompletionGate, and gate status is not recoverable. |
| Trace lacks typed gate verdict | `HARNESS_LIMITATION` | high | MEDIUM | General observability gap; record only in this gate. |
| Raw final answer not retained | `HARNESS_LIMITATION` | high | MEDIUM | Privacy-preserving design prevents model/parser attribution; no repair in this gate. |
| Qualification top-level timestamps equal despite nonzero elapsed time | `HARNESS_LIMITATION` | high | LOW | Provenance-quality issue, not causal for P4. |
| P4 stage omits Repo Intelligence/Context Engine counters | `HARNESS_LIMITATION` | high | MEDIUM | Offline reconstruction supplies a bounded substitute; target-run exact counters are unavailable. |

No `BLOCKER` or `HIGH` functional Harness defect was found. No code fix,
regression, or rerun is authorized by this gate. A future observability repair
must be a separate gate and must preserve redaction; it must not persist raw
model text or hidden oracle contents merely to make this diagnosis easier.

## Required status after this gate

| Status | Verdict |
|---|---|
| Provider integration | `PASS` according to preserved P0–P2 smoke evidence; not rerun here |
| P4 semantic review | `FAIL` |
| Real AgentLoop path | `PASS` for traversal, with P4 semantic failure |
| Real coding capability | `UNMEASURED / EARLY SIGNAL ONLY` |
| Real browser capability | `UNMEASURED` |
| Full corpus readiness | `NOT READY` |
| Production readiness | `NOT READY` |
| M9 | `NOT STARTED` |

The preserved P4 failure must remain a failure. It must not be promoted to a
strong model-capability claim or used for competitive comparison. The next
safe action is a separately authorized observability/diagnostic design gate,
followed only later by a fresh qualification run if its evidence contract is
repaired.

## Gate closure

- Real Provider calls during this diagnostic: `0`.
- Credential authority accessed: `NO`.
- Secret leakage scan of preserved JSON/JSONL: `PASS`.
- Hidden-oracle source read: `NO`.
- Original qualification artifacts preserved: `YES`.
- Protected local security report: `UNCHANGED / UNTRACKED / UNSTAGED`.
- Harness fixes applied: `NONE`.
- Commit/push/PR operation: `NONE`.
- Repository state: `NOT READY` (pre-existing dirty worktree retained; this
  report is a new untracked diagnostic artifact).

## Observability closure follow-up (2026-09-13)

The historical GLM-5.3 P4-v2 result remains `FAIL`.

Its root cause remains `INCONCLUSIVE`.

The offline follow-up added only passive O1-O4 telemetry and deterministic
read/shape tests. It did not rerun the Provider, read credentials, reconstruct
the historical response, or change the historical artifact. CompletionGate
verdict and target-run context counters therefore remain unavailable for the
historical run. Real coding capability remains `UNMEASURED`; full corpus and
production readiness remain `NOT READY`.
