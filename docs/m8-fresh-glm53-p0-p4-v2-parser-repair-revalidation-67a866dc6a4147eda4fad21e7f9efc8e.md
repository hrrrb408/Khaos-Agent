# Khaos GLM-5.3 P0–P4-v2 Parser Repair Revalidation

## Result

The general streamed structured-response parser defect from the previous
qualification was repaired and revalidated with a fresh real-provider run.

- P0: `PASS`
- P1: `PASS`
- P2: `PASS`
- P3: `PASS`
- P4 response decode/schema/typed parse: `PASS`
- P4 semantic review: `FAIL`
- P4 primary attribution: `MODEL_LIMITATION`
- Qualification result: `FAIL`
- Harness parser defect: `FIXED`
- Full corpus readiness: `NOT READY`

The remaining P4 failure is not a parser, provider, environment, security,
or CompletionGate failure. The model submitted three typed findings, but the
oracle matched zero and classified all three as extra. This run is therefore
a valid negative capability signal for this probe, not a reason to weaken the
oracle or inject hints into the Harness.

## Lineage and scope

This is a new P0-v2 → P1-v2 → P2-v2 → P3-v2 → P4-v2 lineage created after
the parser repair. The original run remains preserved in its own report and
JSON/JSONL artifacts. This run did not execute the 3–5 coding sanity corpus,
browser coding, the full benchmark corpus, GLM-5.3-Flash, or M9. No further
Provider rerun is justified by this result.

## Run identity

| Field | Value |
|---|---|
| Branch | `codex/m8-coding-evaluation` |
| Source HEAD | `3c1095ff69b1a5d800d96eb61e8b88a47fceca14` |
| Run ID | `m8-qualification-67a866dc6a4147eda4fad21e7f9efc8e` |
| Suite | `m8-provider-qualification v2` |
| Scenario | `p4-readonly-authority v2` |
| Observability schema | `1` |
| Trace schema | `2` |
| Working-tree identity | `50023357b665adbec6d7a6cbbfb2e0402628d062e67a9bc7009bae67b8ee628c` |
| Provider | `zhipu-coding` |
| Model | `glm-5.3` |
| Provider-returned model ID | `UNKNOWN / PROVIDER_NOT_REPORTED` |
| Adapter | `ModelRouter -> ModelClient -> openai_compatible` |
| Reasoning / sampling | `UNKNOWN / NOT_REPORTED` |
| Config/provider digest | `0e40d79f711250ab8f60bccf6381ce804331aff7768013a41f8d8b13935f1529` |
| Policy digest | `cf1bc0a3a97c13e0c9e00a7954a5c168a999671ffaa83a3a58ab33d17e758f93` |
| Suite digest | `5b130e35bbc32a7fa6adf91a5767a5521a54287db83c8e008988332f96530185` |
| Fixture digest | `864d4713661e2e803890f143eaf0268458186b2fbb74c7bfa2d47382fc745b99` |
| Tool schema digest | `401eab0fb0a481a1f5c20b506f84f1dda42234ff344937807c338eec1fcf1f98` |
| Wall time | `66557 ms` |

The retained artifacts are:

- `/tmp/khaos-glm53-p0-p4-v2-repair.Y3RTPA/qualification.json`
  - SHA-256: `3b383c664e8ae78dd614e5603801b3c1f4be0f6df5930ab0093ea4356945e34c`
- `/tmp/khaos-glm53-p0-p4-v2-repair.Y3RTPA/qualification.jsonl`
  - SHA-256: `df88a61bd8468a0fc6f1dc3083f0bcbf0556a0a7258c31972b5d5423814ad681`

## Credential and Provider gate

| Check | Result | Evidence |
|---|---|---|
| Credential authority | `PASS` | Operator explicitly unlocked `zhipu-coding`; credential reference remained opaque |
| Credential boundary | `PASS` | No credential value was sent to the model or written to artifacts |
| Provider response | `PASS` | 7 requests, all HTTP 200 |
| Provider failures | `NONE OBSERVED` | No 429, 5xx, transport, authentication, or invalid-model failure |
| Usage accounting | `UNAVAILABLE / PROVIDER_NOT_REPORTED` | Input/output/total tokens remain `null` |
| Secret leakage | `PASS` | No raw secret, authorization header, or API-key-shaped field in JSON/JSONL |

The provider returned no separate model identity. The configured identity was
`zhipu-coding / glm-5.3`.

## Probe summary

| Probe | Result | Requests | Main evidence |
|---|---|---:|---|
| P0 | `PASS` | 1 | HTTP 200; exact acknowledgement; terminal response |
| P1 | `PASS` | 2 | `echo_ack` tool call and result round trip |
| P2 | `PASS` | 1 | 73 production schemas; 0 unexpected tool calls |
| P3 | `PASS` | 2 | Real AgentLoop; 1 `read_file`; source unchanged; side-effect-free |
| P4 | `FAIL` | 1 | Typed response valid, semantic oracle mismatch |

All seven requests had no provider failure class. Usage was unavailable from
the provider and was not represented as zero.

## P3 real AgentLoop

P3 passed with `real_model=true` and `real_agent_loop=true`.

- Agent status: `COMPLETED`
- Model turns: `2`
- Tool calls: `1` (`read_file`)
- Edit/terminal/test/browser calls: `0`
- Source unchanged: `true`
- Side-effect-free: `true`
- Trace: 12 events, not truncated, 0 dropped
- Trace reconciliation: `PASS`
- CompletionGate: reached, `not_complete / NOT_COMPLETE`

Repository context and automatic context were observed without truncation.
No false completion was accepted.

## P4 after parser repair

P4 traversed the real model and real AgentLoop path and completed without
mutation. The model used one model turn and no explicit tool calls; automatic
context contained all four relevant repository paths and was not truncated.
This is recorded as an observation, not automatically as tool avoidance.

### Structured response evidence

Only shape-safe telemetry was retained:

```text
present=true
format=FENCED_JSON
byte_count=2280
json_decode_status=PASS
schema_validation_status=PASS
typed_parse_status=PASS
typed_finding_count=3
finding_field_count=3
all_required_fields_present=true
unknown_field_count=0
parse_error_code=null
truncated=false
```

This directly confirms that the previous chunk-boundary parser defect is no
longer present in the real Provider path.

### Semantic evidence

```text
required_count=3
submitted_count=3
matched_count=0
extra_count=3
passed=false
read_only_invariant=true
normal_completion=true
```

The evaluator correctly rejected the response on semantic grounds. The
response was well-formed but did not identify the required findings. Because
the response parser succeeded, this is classified as `MODEL_LIMITATION`, not
`HARNESS_DEFECT`.

### Completion and trace

- Agent status: `COMPLETED`
- Completion status: `completed`
- CompletionGate: reached, authority `CompletionGate`
- Gate status: `not_complete`
- Gate reason: `NOT_COMPLETE`
- Completion acceptances: `0`
- Model finalized: `false`
- Trace events: `9`
- Trace reconciliation: `PASS`
- Trace truncated/dropped: `false / 0`
- No false completion was accepted.

## Repair applied

The repaired parser in
`python/khaos/evaluation/coding/runtime_invoker.py` now:

- joins bounded assistant response chunks before typed parsing;
- applies the existing fenced-JSON extraction to the aggregate response;
- enforces the 64 KiB aggregate bound before decoding; and
- preserves the existing schema, finding-count, and safe telemetry checks.

Regression coverage was added in
`python/tests/evaluation/test_p4_qualification_v2.py` for split ordinary JSON
and split fenced JSON. No oracle, prompt, budget, CompletionGate, or provider
behavior was altered.

## Verification

- Targeted parser/AgentLoop tests: `28 passed`.
- Complete Python evaluation test directory: `167 passed`.
- Touched-file Ruff check: `PASS`.
- Touched-file Ruff format check: `PASS`.
- Touched-file Pyright: `0 errors, 0 warnings, 0 informations`.
- Targeted compile: `PASS`.
- `git diff --check` for touched source/test paths: `PASS`.
- Operational JSON parsing: `PASS`.
- Typed JSONL parsing and record digest: `PASS`.
- JSON/JSONL run identity binding: `PASS`.
- Trace reconciliation: `PASS`.
- Hidden oracle isolation: `PASS`.
- Raw-response durability check: `PASS`.

The whole evaluation directory still contains unrelated pre-existing Ruff
findings outside the touched files; those were not changed as part of this
parser repair.

## Final classification

| Dimension | Verdict |
|---|---|
| Provider integration | `PASS` |
| Parser Harness defect | `FIXED` and real-path revalidated |
| Real AgentLoop traversal | `PASS` |
| P4 structured response | `PASS` |
| P4 semantic capability | `FAIL / MODEL_LIMITATION` |
| Benchmark defect | `NOT OBSERVED` |
| Provider defect | `NOT OBSERVED` |
| Environment defect | `NOT OBSERVED` |
| Security failure | `NOT OBSERVED` |
| False completion | `0` accepted |
| Real coding capability | `UNMEASURED` |
| Real browser capability | `UNMEASURED` |
| Full corpus readiness | `NOT READY` |
| Production readiness | `NOT READY` |
| GLM-5.3-Flash | `NOT RUN` |
| M9 | `NOT STARTED` |

Do not rerun this stochastic P4 until a separate experiment changes the
provider/model or the task configuration with an explicitly recorded reason.
Do not modify the Harness to convert this semantic miss into a pass.

## Repository state

- Existing user changes were preserved.
- The previous qualification report and this report are separate untracked
  artifacts.
- `docs/local-security-closure-report.md` remains unchanged, untracked, and
  unstaged; its verified SHA-256 is
  `85dbfe1ee17475154a0f48a6d308750b252aec75f3b67dd4f2e47f06b25597a1`.
- No commit, push, PR update, merge, rebase, or force push was performed.
- Repository delivery state: `NOT READY / UNCOMMITTED`.

The parser repair is locally and on the real Provider path usable. The
qualification as a whole remains below the full-corpus gate because GLM-5.3
did not pass the P4 semantic oracle.
