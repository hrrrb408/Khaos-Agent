# Khaos Fresh GLM-5.3 P0–P4-v2 Qualification under Observability v1

## Final result

The real-provider qualification completed against `zhipu-coding / glm-5.3`.

- P0 cold-router/provider smoke: `PASS`
- P1 synthetic tool round-trip: `PASS`
- P2 production tool-surface compatibility: `PASS`
- P3 real AgentLoop read-only probe: `PASS`
- P4 sustained read-only authority probe: operational result `FAIL`, offline attribution `HARNESS_INVALIDATED`
- Qualification verdict: `HARNESS_INVALIDATED`
- Real coding capability: `NOT EVALUATED`
- Full corpus readiness: `NOT READY`

The P4 result is not classified as a confirmed model limitation. The bounded
offline reproduction identifies a general Harness defect in streamed structured
response parsing. No source repair or rerun was performed in this lineage.

## Scope and guardrails

This was the fresh GLM-5.3 P0-v2 → P1-v2 → P2-v2 → P3-v2 → P4-v2
qualification only. It did not run the 3–5 coding sanity corpus, browser
coding, the full benchmark corpus, Flash, or M9. The provider was not called
during offline attribution. No prompt, fixture, evaluator, parser,
CompletionGate, budget, or Harness source was changed after the run.

The operator supplied the Keychain session unlock through the command line.
The model/agent did not receive credential material and did not perform an
automatic unlock.

## Run identity

| Field | Value |
|---|---|
| Branch | `codex/m8-coding-evaluation` |
| Exact source HEAD | `3c1095ff69b1a5d800d96eb61e8b88a47fceca14` |
| Run ID | `m8-qualification-fb705f0c39984239ad6a1d97ab6f0447` |
| Qualification version | `m8-provider-qualification v2` |
| Observability schema | `1` |
| Trace schema | `2` |
| Working-tree identity during run | `bd3908a8b7858a6434973c2f893345b88c2562585b48e17a4bdb187858cb89ab` |
| Working-tree identity after report | Same digest when excluding the protected report and this report; all other existing user changes remain included |
| Run interval | `2026-09-12T16:35:13.301327+00:00` – `2026-09-12T16:36:04.046343+00:00` |
| Wall time | `50747 ms` |
| Provider | `zhipu-coding` |
| Model | `glm-5.3` |
| Provider-returned model ID | `UNKNOWN / PROVIDER_NOT_REPORTED` |
| Adapter | `ModelRouter -> ModelClient -> openai_compatible` |
| Reasoning / sampling | `UNKNOWN / NOT_REPORTED` |
| Provider/config digest | `0e40d79f711250ab8f60bccf6381ce804331aff7768013a41f8d8b13935f1529` |
| Policy digest | `cf1bc0a3a97c13e0c9e00a7954a5c168a999671ffaa83a3a58ab33d17e758f93` |
| Suite digest | `5b130e35bbc32a7fa6adf91a5767a5521a54287db83c8e008988332f96530185` |
| P4 scenario digest | `314b8022fd0eb325bd8199379135d22f3673cf2e27f9ef0a9d1c3b171eb9fa58` |
| P4 fixture digest | `864d4713661e2e803890f143eaf0268458186b2fbb74c7bfa2d47382fc745b99` |
| Production tool schema digest | `401eab0fb0a481a1f5c20b506f84f1dda42234ff344937807c338eec1fcf1f98` |

Run artifacts:

- `/private/tmp/khaos-glm53-p0-p4-v2.0MHQRc/qualification.json`
  - SHA-256: `42c12211c8420bc3b247aad9553b0a5ae03d16a62ef634f0e3334f43c65d40fb`
- `/private/tmp/khaos-glm53-p0-p4-v2.0MHQRc/qualification.jsonl`
  - SHA-256: `f58fdff7c5bc7f53540c39d29f0ecf7dbcd80bfd71e42034edf3dfd5754d8324`

The earlier preflight-only blocked attempt remains separately recorded in
`docs/m8-fresh-glm53-p0-p4-v2-observability-v1-qualification-26ab9a2b-208a-4c03-8de6-2fd85605aaa3.md`; it was not overwritten.

## Provider and credential gate

| Check | Result | Evidence |
|---|---|---|
| Credential authority | `PASS` | `zhipu-coding` resolved through the host macOS Keychain authority using ref `khaos/providers/zhipu-coding/default` |
| Provider construction | `PASS` | Production router/client/openai-compatible adapter constructed |
| Real response | `PASS` | 7 real requests; all returned HTTP 200 |
| Model/config resolution | `PASS` for configured model | Configured model was `glm-5.3`; provider returned no separate model ID |
| Usage accounting | `UNAVAILABLE / PROVIDER_NOT_REPORTED` | Input/output/total token fields are `null`; zero was not fabricated |
| Provider failure mapping | `PASS` for observed path | No provider failure occurred or was misclassified; negative cases were not triggered |
| Secret leakage | `PASS` | No credential, authorization header, or raw model response in JSON/JSONL |

Provider accounting was `1 + 2 + 1 + 2 + 1 = 7` requests, with no retries,
HTTP 429, 5xx, or transport failures. The operator-side unlock was not an
agent unlock.

## Fixed budgets

| Probe | Max model turns | Max tool calls | Timeout |
|---|---:|---:|---:|
| P3 | 8 | 8 | 120 s |
| P4 | 12 | 24 | 300 s |

Budgets were not changed after observing results. No subagents, checkpoint,
rewind, or human intervention occurred in P3/P4.

## Probe results

### P0 — cold router/provider smoke

`PASS`: 1 request, HTTP 200, `1767 ms`, 2 response chunks, exact short
acknowledgement true, terminal response true, 0 tool calls, typed provider
error `none`. Usage was `UNKNOWN / PROVIDER_NOT_REPORTED`.

### P1 — synthetic tool round-trip

`PASS`: 2 requests, both HTTP 200, `9104 ms`, synthetic tool `echo_ack`,
1 valid tool call, successful tool-result round trip, terminal response true,
and no typed provider error.

### P2 — production tool-surface compatibility

`PASS`: 1 request, HTTP 200, `4708 ms`, 73 production tool schemas accepted,
0 unexpected tool calls, terminal response true. The production schema digest
is `401eab0fb0a481a1f5c20b506f84f1dda42234ff344937807c338eec1fcf1f98`.

### P3 — real AgentLoop read-only probe

`PASS`.

| Metric | Value |
|---|---|
| Real model / real AgentLoop | `YES / YES` |
| Requests / statuses | `2 / 200, 200` |
| Wall time | `12906 ms` |
| Agent / completion status | `COMPLETED / completed` |
| Model turns / tool calls | `2 / 1` |
| Tool | `read_file` (1 call) |
| Edit / terminal / test / browser calls | `0 / 0 / 0 / 0` |
| Source unchanged / side-effect-free | `true / true` |
| Trace | 12 events, not truncated, 0 dropped, reconciliation `PASS` |

Repository Intelligence and context were observed: 3 documents, 6 symbols,
12 evidence items, and relevant paths `src/cache.py`, `src/keys.py`, and
`src/service.py`. Automatic context selected 13 repository and 8 non-repository
items; the bundle was not truncated. CompletionGate was reached and recorded
`not_complete / NOT_COMPLETE`; no false completion was accepted.

### P4 — sustained read-only authority probe

Operational result: `FAIL`
Final attribution: `HARNESS_INVALIDATED`

| Metric | Value |
|---|---|
| Real model / real AgentLoop | `YES / YES` |
| Requests / status | `1 / 200` |
| Wall time | `20584 ms` |
| Agent / completion status | `COMPLETED / completed` |
| Model turns / tool calls | `1 / 0` |
| Explicit read-file / terminal / test / edit / browser calls | `0 / 0 / 0 / 0 / 0` |
| Automatic context | 14 repository and 7 non-repository items |
| Repository context | 4 documents, 5 symbols, 22 evidence items, not truncated |
| Source unchanged / side-effect-free | `true / true` |
| Trace | 9 events, not truncated, 0 dropped, reconciliation `PASS` |

P4 repository context included `src/authority.py`, `src/consumer.py`,
`src/policy.py`, and `src/unrelated.py`. Zero explicit tool calls is recorded
as an observation, not automatically `TOOL_AVOIDANCE`, because automatic
repository context was present and the probe did not require a minimum
explicit-tool count.

P4 semantic review required 3 findings, received 0 typed findings, matched 0,
and had 0 extras. The read-only and normal-completion invariants were true,
but `review_findings_pass=false` because the structured response was not
successfully typed. CompletionGate was reached and recorded
`not_complete / NOT_COMPLETE`; `model_finalized=false`. No false completion
was accepted.

Safe response telemetry only (raw response was not retained):

```text
present=true
byte_count=2618
format=PLAIN_JSON_OBJECT
json_decode_status=FAIL
schema_validation_status=FAIL
typed_parse_status=NOT_ATTEMPTED
parse_error_code=WRONG_TOP_LEVEL_TYPE
truncated=false
```

## P4 offline attribution

`python/khaos/evaluation/coding/runtime_invoker.py:359-360` concatenates
output chunks for response-shape telemetry. The same function then loops over
individual chunks at `:369-387` and invokes JSON decoding per chunk. A bounded
offline reproduction with one valid JSON object split across two chunks
produced JSON-shaped aggregate telemetry but zero typed findings and an
`INVALID_JSON` parse error.

This proves a general stream-boundary mismatch: a valid structured response
can be recognized as an aggregate JSON shape but fail typed parsing when each
chunk is parsed independently. The exact P4 boundaries are unavailable by
design because raw response text is not persisted, so attribution confidence
is `MEDIUM`, not `HIGH`. This is sufficient to invalidate P4 as a clean model
measurement; it is not evidence of a confirmed model limitation.

| Defect | Reproduction | Severity | Subsystem | Generalizable | Security impact |
|---|---|---|---|---|---|
| Streamed structured-response parser boundary mismatch | Split a valid JSON response at a stream boundary; aggregate shape succeeds while per-chunk typed parse fails | `HIGH` | `RuntimeCodingAgentInvoker` review parser / qualification evidence | `YES` | `NO` identified |

Recommended future fix: parse one bounded concatenated response, with bounded
fenced extraction, before schema validation; add a deterministic split-chunk
regression; then start a fresh P0 lineage. No fix was applied here.

## Required report fields

### Task/stage summary

| Stage | Category | Result | Requests | Turns | Tokens | Tools | Edits | Verification | Repair | CompletionGate |
|---|---|---|---:|---:|---|---:|---:|---|---:|---|
| P0 | Provider smoke | `PASS` | 1 | N/A | `null / null / null` | 0 | 0 | N/A | 0 | N/A |
| P1 | Tool round trip | `PASS` | 2 | N/A | `null / null / null` | 1 | 0 | Tool result correlated | 0 | N/A |
| P2 | Production tool surface | `PASS` | 1 | N/A | `null / null / null` | 0 | 0 | Schema accepted | 0 | N/A |
| P3 | Real AgentLoop read-only | `PASS` | 2 | 2 | `null / null / null` | 1 | 0 | `read_file`; no mutation | 0 | reached, `not_complete` |
| P4 | Sustained read-only authority | `INVALIDATED` (raw `FAIL`) | 1 | 1 | `null / null / null` | 0 | 0 | Semantic review unscoreable | 0 | reached, `not_complete` |

This qualification intentionally did not run the requested 3–5 coding tasks;
real coding and browser capability therefore remain unevaluated. There were
no approvals, human interventions, subagents, merge attempts, browser
sessions/actions/checks, checkpoints, or rewinds.

### Classifications

- Primary qualification classification: `HARNESS_DEFECT`
- Qualification state: `HARNESS_INVALIDATED`
- Secondary classification: `STRUCTURED_RESPONSE_PARSER_BOUNDARY_MISMATCH`
- Severity: `HIGH`
- Model limitation: `NOT CONFIRMED`
- Provider defect: `NOT OBSERVED`
- Benchmark defect: `NOT OBSERVED`
- Environment defect: `NOT OBSERVED`
- Security failure: `NOT OBSERVED`
- False completion attempts: `0` accepted; Gate recorded `NOT_COMPLETE`
- Harness fixes applied: `NONE`

The operational JSON record remains preserved with its original
`qualification=FAIL`. This report adds offline attribution and does not
overwrite the first attempt.

## Integrity and isolation

| Check | Result | Evidence |
|---|---|---|
| Operational JSON + typed JSONL validation | `PASS` | Operational JSON parsed; one JSONL `CodingQualificationRecordV1` parsed; record digest valid |
| JSON/JSONL identity | `PASS` | Run ID, source SHA, working-tree identity, provider, model, and digests agree |
| Observability/trace reconciliation | `PASS` | P3/P4 event counts match summaries; no truncation or dropped events |
| Hidden oracle isolation | `PASS` | No hidden oracle content or grading metadata in agent-visible artifacts |
| Raw-response durability | `PASS` | No raw response/output fields in JSON/JSONL |
| Secret leakage | `PASS` | No credential, auth header, or API-key-shaped value in generated artifacts |
| Source frozen during run | `PASS` | Source SHA stayed `3c1095ff...`; no qualification-time mutation |
| Protected report | `UNCHANGED` | Untracked and unstaged; mode `-rw-r--r--`, size `851`, SHA-256 `85dbfe1ee17475154a0f48a6d308750b252aec75f3b67dd4f2e47f06b25597a1` |
| Diff whitespace | `PASS` | `git diff --check` passed for the report/source view |

## Conservative capability verdict

| Dimension | Verdict |
|---|---|
| Provider integration | `PASS` |
| Production tool surface | `PASS` |
| Real AgentLoop execution | `PASS` for P3/P4 lifecycle execution; P4 evidence invalidated |
| Sustained read-only qualification | `INCONCLUSIVE / HARNESS_INVALIDATED` |
| Real coding capability | `UNMEASURED` |
| Real browser capability | `UNMEASURED` |
| Real model used | `YES` |
| Real browser runtime / app runtime | `NO / NO` |
| Full corpus readiness | `NOT READY` |
| Current M8 capability status | `EARLY SIGNAL ONLY`; full capability remains `UNMEASURED` |
| Production readiness | `NOT READY` |
| GLM-5.3-Flash | `NOT RUN` |
| M9 | `NOT STARTED` |

The passing probes establish provider connectivity, tool-call compatibility,
the production tool surface, and real AgentLoop traversal. They do not justify
coding-capability or competitive-performance claims.

## Repository state

- Existing user changes were preserved.
- No commit, push, PR update, merge, rebase, or force push was performed.
- This report is a new untracked artifact.
- Delivery state: `NOT READY` for qualification closure because the P4 Harness
  defect remains unresolved; the working tree remains `UNCOMMITTED` by
  instruction.

The next authorized phase is a new lineage: repair the general streamed
structured-response parser, add its deterministic regression, rerun the
affected local regression and then a fresh P0–P4 qualification. Do not start
the full corpus until that new lineage passes its closure gates.
