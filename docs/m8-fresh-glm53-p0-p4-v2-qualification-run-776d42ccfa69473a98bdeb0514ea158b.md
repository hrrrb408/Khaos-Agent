# Khaos Fresh GLM-5.3 P0–P4-v2 Qualification Run Report

This is the first valid real-provider qualification lineage after the Router
import-cycle closure. It completed P0–P4 through the production-shaped
provider and AgentLoop path. The overall qualification failed at P4 because
the model stopped without submitting the required review findings. This is a
qualification result, not a five-task sanity run, a full corpus result, or a
competitive capability claim.

## Run identity

| Field | Result |
| --- | --- |
| Branch | `codex/m8-coding-evaluation` |
| Exact HEAD / source SHA | `3c1095ff69b1a5d800d96eb61e8b88a47fceca14` |
| Working-tree identity captured by run | `6df93ba62ab869164830e9830565f760608f0bc44a247206d1b40f6554b2ed64` |
| Provider | `zhipu-coding` |
| Requested model | `glm-5.3` |
| Adapter | `ModelRouter -> ModelClient -> openai_compatible` |
| Run ID | `m8-qualification-776d42ccfa69473a98bdeb0514ea158b` |
| Suite | `m8-provider-qualification` v2 |
| Overall qualification | `FAIL` |
| Provider requests | `7` |
| Elapsed time | `65177 ms` |
| Result artifact | `/tmp/khaos-glm53-p0-p4-v2.AS0MxP/qualification.json` |
| JSONL artifact | `/tmp/khaos-glm53-p0-p4-v2.AS0MxP/qualification.jsonl` |

The qualification record binds the following safe identities:

```text
config_digest / emitted provider_config_digest:
  0e40d79f711250ab8f60bccf6381ce804331aff7768013a41f8d8b13935f1529
suite_digest:
  5b130e35bbc32a7fa6adf91a5767a5521a54287db83c8e008988332f96530185
scenario: p4-readonly-authority v2
scenario_digest:
  314b8022fd0eb325bd8199379135d22f3673cf2e27f9ef0a9d1c3b171eb9fa58
fixture_digest:
  864d4713661e2e803890f143eaf0268458186b2fbb74c7bfa2d47382fc745b99
prompt_digest:
  d5a06983c8c5b6f1b827977bda163613a78bc39f6c2caa14a9be9c293c12c42c
system_prompt_digest:
  c58fa0da8673fe4e9895877877b1a0d5ae876db9efc27b563400cb0bf99b8356
production_tool_schema_digest:
  401eab0fb0a481a1f5c20b506f84f1dda42234ff344937807c338eec1fcf1f98
policy_digest:
  cf1bc0a3a97c13e0c9e00a7954a5c168a999671ffaa83a3a58ab33d17e758f93
```

The `repository_base_revision` values in the P3/P4 records are disposable
fixture revisions and are distinct from the Khaos source SHA.

## Credential and security result

```text
Credential authority: PASS
Persistent credential: PRESENT in macOS Keychain
Credential ref: khaos/providers/zhipu-coding/default
Secretless configuration: PASS
Runtime unlock: operator supplied --unlock zhipu-coding
Secret values printed: false
```

The safe credential status output contained only provider metadata and the
opaque credential reference. No API key, authorization header, response body,
or environment dump was retained in the qualification artifacts.

The two result files were checked without printing their contents. The JSONL
file contains exactly one record, has mode `0600`, and its typed record and
record digest validate successfully:

```text
qualification.json SHA-256:
  18b0e504dc720083307b1f4c716ee4daed6f0cd88ac637f134cd8fe26f700c3d
qualification.jsonl SHA-256:
  c767cdd9cd60dcf871d47efaba5f61d6090eb8fc4f3679f49e9c2bee9c70aeab
record_digest:
  cd8f7e07a1229d96d2b972326fa03dcf13493ffc91978e91984088d7c4e034a1
typed JSONL record: PASS
record digest match: PASS
credential-shaped key scan: PASS
authorization/bearer pattern scan: PASS
```

The protected `docs/local-security-closure-report.md` remained untracked,
unstaged, mode `-rw-r--r--`, 851 bytes, with SHA-256
`85dbfe1ee17475154a0f48a6d308750b252aec75f3b67dd4f2e47f06b25597a1`.

## Stage results

| Probe | Result | Provider requests | Safe evidence |
| --- | --- | ---: | --- |
| P0 | `PASS` | 1 | Exact `ACK`; HTTP 200; no tool call |
| P1 | `PASS` | 2 | Valid `echo_ack` call and result round-trip; HTTP 200 |
| P2 | `PASS` | 1 | 73 production tool schemas; no unexpected tool call; HTTP 200 |
| P3 | `PASS` | 2 | Real model and real AgentLoop; one `read_file`; no writes, terminal, tests, or browser |
| P4 | `FAIL` | 1 | Natural completion after one model turn; zero tools and zero submitted findings |

All seven provider requests returned HTTP 200 with no typed provider errors or
retries. The provider did not report input, output, or total token usage, so
usage remains `UNKNOWN / PROVIDER_NOT_REPORTED`; it is not recorded as zero.
The provider also did not report a returned model identifier, reasoning effort,
or sampling configuration.

### P3 trace

```text
real_model: true
real_agent_loop: true
model_turns: 2
tool_calls: 1 (`read_file`)
read_file_calls: 1
editing_calls: 0
terminal_calls: 0
test_calls: 0
browser_calls: 0
completion_status: completed
source_unchanged: true
side_effect_free: true
Trace v2: 10 events, not truncated, reconciliation PASS
```

### P4 trace

```text
real_model: true
real_agent_loop: true
model_turns: 1
tool_calls: 0
read_file_calls: 0
editing_calls: 0
terminal_calls: 0
test_calls: 0
browser_calls: 0
completion_status: completed
source_unchanged: true
side_effect_free: true
required findings: 3
submitted findings: 0
matched findings: 0
review_findings_pass: false
Trace v2: 6 events, not truncated, reconciliation PASS
```

The trace contains `completion_evaluated` and `completion_gated` events. The
safe qualification projection does not retain a typed `gate_status`, and both
completion acceptance/rejection counters are zero. Therefore the fact that the
CompletionGate was invoked is proven, but whether that gate rejected or
accepted this particular proposal is not independently recoverable from the
durable qualification record.

## Failure classification

The P4 result is primarily classified as `MODEL_LIMITATION`, with secondary
`FALSE_COMPLETION` / review-convergence failure. The model had a validated
production tool surface and had already used the real read-only AgentLoop in
P3; P4 nevertheless stopped after one response without reading the fixture or
emitting the required three structured findings. There was no Provider error,
timeout, rate limit, authentication failure, tool-adapter error, write, or
fixture mutation.

No `HARNESS_DEFECT`, `PROVIDER_DEFECT`, `BENCHMARK_DEFECT`, or
`ENVIRONMENT_DEFECT` is established by this run.

### Observability follow-ups (not fixes in this run)

| Severity | Observation | Classification | Recommendation |
| --- | --- | --- | --- |
| INFO | `completion_gated` is recorded without a bounded typed gate status | evidence gap | Add a safe gate-status projection and deterministic regression before relying on gate-level statistics |
| INFO | `started_at` and `finished_at` are identical although elapsed time is non-zero | result metadata defect | Correct timestamp construction in a separate harness change with a regression test |
| INFO | The qualification implementation emits the config-file digest in both `config_digest` and `provider_config_digest` | identity-label ambiguity | Define and test the canonical provider-specific digest before full-corpus use |

These observations do not justify changing the model prompt, increasing
budgets, or rerunning the stochastic qualification until green. No source,
test, fixture, prompt, tool schema, budget, or policy change was made for this
run.

## Gate verdict

```text
Provider Integration: PASS
Real AgentLoop path: PASS for P3 read-only traversal
Real-provider qualification: PARTIAL / overall FAIL at P4
Real coding capability: UNMEASURED
Real browser capability: UNMEASURED
Real model used: YES
Real browser runtime used: NO
Real app runtime used: NO
JSONL validation: PASS
Hidden oracle isolation: PASS
Full corpus readiness: NOT READY
Production readiness: NOT READY
M9: NOT STARTED
```

The five-task real-agent sanity and the full real-provider corpus were not
started. This run must remain a separate lineage from the earlier pre-P0
credential-session block and the Router-import-cycle-invalidated attempt.

## Repository state

```text
Source mutated during qualification: NO
Existing worktree changes: PRESERVED
Protected local report: UNCHANGED / UNTRACKED / UNSTAGED
Commit/push/PR/merge: NONE
Current repository state: DIRTY, uncommitted
Repository readiness: NOT READY
```
