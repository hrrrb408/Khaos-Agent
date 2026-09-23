# M8 GLM-5.3-Flash Semantic-Attribution Qualification Gate — Fresh Lineage 2

Date: 2026-09-13 (Asia/Shanghai)

This is a forensic report for exactly one fresh `P0-v2 -> P4-v2` lineage. It is
not a full coding benchmark, not a five-task coding sanity set, not a browser
benchmark, and not an M9 run.

## Executive result

- Provider integration: **PASS**.
- Real production-shaped AgentLoop path: **PASS for this bounded read-only probe**.
- P0, P1, P2, and P3: **PASS**.
- P4 mechanical evaluator result: **FAIL** (`0/3` oracle findings matched).
- Offline semantic attribution: **BENCHMARK_INVALIDATED / INCONCLUSIVE for concept-level model attribution**.
- Primary explanation: **BENCHMARK_DEFECT — `BENCHMARK_ONTOLOGY_MISMATCH`**, with a supported output-label/serialization variant.
- No confirmed in-scope BLOCKER/HIGH Harness defect was found, so no code fix was applied.
- Real coding capability: **UNMEASURED**.
- Real browser capability: **UNMEASURED**.
- Full corpus readiness: **NOT READY**.
- M9: **NOT STARTED**.

The P4 result must not be promoted to a model-capability failure. The
candidate selected the three oracle files exactly, while its category labels
used underscore-style natural-language variants. The public task prompt does
not publish the exact category token contract, and the evaluator compares
category strings case-insensitively but does not normalize separators or role
specificity. Concepts are intentionally redacted in the persisted
observability projection, so concept-level correctness remains unknown.

## Run identity and preservation

| Field | Value |
|---|---|
| Branch | `codex/m8-coding-evaluation` |
| Source SHA / HEAD before and after | `3c1095ff69b1a5d800d96eb61e8b88a47fceca14` |
| Run ID | `m8-qualification-1c2b698b7ac54d32890430526995f570` |
| Qualification version | `2` |
| Suite | `m8-provider-qualification` v2 |
| Scenario | `p4-readonly-authority` v2 |
| Repository fixture base revision | `5a499966272316ca967d4a366ace2808134f691d` |
| Provider | `zhipu-coding` |
| Requested model | `glm-5.3-flash` |
| Provider-returned model ID | `UNKNOWN / PROVIDER_NOT_REPORTED` |
| Adapter | `ModelRouter -> ModelClient -> openai_compatible` |
| Provider endpoint profile | `https://open.bigmodel.cn/api/coding/paas/v4` |
| Credential reference | `khaos/providers/zhipu-coding/default` |
| Config/provider-config digest | `0e40d79f711250ab8f60bccf6381ce804331aff7768013a41f8d8b13935f1529` |
| Policy digest | `cf1bc0a3a97c13e0c9e00a7954a5c168a999671ffaa83a3a58ab33d17e758f93` |
| Suite digest | `5b130e35bbc32a7fa6adf91a5767a5521a54287db83c8e008988332f96530185` |
| Scenario digest | `314b8022fd0eb325bd8199379135d22f3673cf2e27f9ef0a9d1c3b171eb9fa58` |
| Fixture digest | `864d4713661e2e803890f143eaf0268458186b2fbb74c7bfa2d47382fc745b99` |
| Prompt digest | `d5a06983c8c5b6f1b827977bda163613a78bc39f6c2caa14a9be9c293c12c42c` |
| System prompt digest | `c58fa0da8673fe4e9895877877b1a0d5ae876db9efc27b563400cb0bf99b8356` |
| Tool schema digest | `401eab0fb0a481a1f5c20b506f84f1dda42234ff344937807c338eec1fcf1f98` |
| Working-tree identity before | `f6f47522bc88aa26c8da831cfcc29c5f858ce9f29c051ffe56e06725cabb20f1` |
| Working-tree identity after | same digest, recomputed excluding this report and the protected report |

The working tree was already dirty. Existing unrelated changes were retained.
No commit, push, PR update, merge, rebase, reset, or cleanup was performed.
The first failed result remains at:

- `/tmp/khaos-glm53-flash-lineage2.json`
- `/tmp/khaos-glm53-flash-lineage2.jsonl`

No second provider lineage or stochastic rerun was launched.

The historical invalidated lineage
`m8-qualification-9b3ccf143eee4dbd92c40161e358dfb5` remains unchanged and is
not overwritten by this report.

## Preflight and credential boundary

Offline preflight completed before the supplied provider command:

```text
81 passed, 1 warning in 14.48s
router cold import: PASS
provider requests during cold import: 0
credential materialization during cold import: 0
```

The selected tests covered the context-selection identity, qualification
contract, oracle, P4-v2, typed-finding attribution, runtime, and runner
surfaces. Provider failure mapping was verified offline for authentication,
invalid model/endpoint, context limit, rate limit, internal error, transport
error, and timeout categories.

The operator supplied the explicit `--unlock zhipu-coding` provisioning/session
action for the actual run. The agent did not unlock credentials. The safe
credential status path identified a Keychain-backed credential reference and
did not expose credential material. The actual request completed through the
configured provider path.

**Credential Authority: PASS**

The run artifact contains only the credential reference and safe provider
metadata. No API key, token, authorization header, or credential value was
printed or persisted.

## Provider smoke and request accounting

Exactly eight provider requests were made for this lineage:

| Stage | Result | Requests | HTTP statuses | Retries | Provider failure |
|---|---:|---:|---|---:|---|
| P0 minimal acknowledgement | PASS | 1 | `200 x1` | 0 | none |
| P1 tool-call round trip | PASS | 2 | `200 x2` | 0 | none |
| P2 production tool surface | PASS | 1 | `200 x1` | 0 | none |
| P3 read-only AgentLoop probe | PASS | 2 | `200 x2` | 0 | none |
| P4 typed semantic review | FAIL | 2 | `200 x2` | 0 | none |
| **Total** |  | **8** | **`200 x8`** | **0** | **none** |

P0 returned the exact acknowledgement required by the smoke probe. P1
returned a valid synthetic tool call and completed the tool-result round trip.
P2 exposed 73 production coding tools with the recorded production tool schema
digest and no unexpected tool calls.

Usage accounting is **UNAVAILABLE / PROVIDER_NOT_REPORTED**. Input, output,
and total token fields are null for all five stages. No zero was substituted.
Reasoning and sampling configuration were also reported as
`UNKNOWN / NOT_REPORTED` by the run artifact.

No live negative requests were induced to spend provider quota. The typed
offline mapping tests passed; the successful live lineage had no provider
error to classify.

**Provider Smoke: PASS**

**Provider Failure Mapping: PASS (offline contract); no live failure injection**

## Production path evidence

P3 and P4 both report `real_model=true` and `real_agent_loop=true`. The
observed adapter was the normal Khaos Router/ModelClient/OpenAI-compatible
provider path. The run did not use a direct provider-to-patch evaluator
shortcut.

The bounded task path exercised:

```text
provider abstraction
  -> ModelRouter / ModelClient
  -> AgentLoop
  -> Goal / context selection
  -> ToolAdmission / read_file
  -> trace and observability
  -> completion proposal
  -> CompletionGate
  -> typed response parser / P4 evaluator
```

The task remained read-only. No edit transaction, terminal, test, browser, or
source mutation was recorded.

## Stage details

### P3 read-only probe

- Result: `PASS`.
- Provider requests: 2; all HTTP 200; retries 0.
- Model turns: 2.
- Tool calls: 1, `read_file`.
- Editing/terminal/test/browser calls: 0/0/0/0.
- Trace events: 14; trace truncated: false.
- Trace reconciliation: `PASS`; event and summary counts both report 2 model turns and 1 tool call.
- Source unchanged: true.
- Side-effect-free: true.
- Cleanup: true.
- Response shape: `NON_JSON_TEXT`; parse result `INVALID_JSON`; no typed finding was expected from this probe.
- Completion proposal: recorded.
- CompletionGate: reached, `not_complete`, reason `NOT_COMPLETE`, authority `CompletionGate`, `model_finalized=false`.

### P4 typed semantic review

- Result: `FAIL` under the current mechanical evaluator.
- Budget: 12 maximum model turns, 24 maximum tool calls, 300 seconds.
- Actual model turns: 2.
- Provider requests: 2; all HTTP 200; retries 0; provider failure none.
- Tool calls: 1, `read_file`.
- Editing/terminal/test/browser calls: 0/0/0/0.
- Trace events: 15; trace truncated: false.
- Trace reconciliation: `PASS`; event and summary counts both report 2 model turns and 1 tool call.
- Source unchanged: true.
- Side-effect-free: true.
- Cleanup: true.
- Response shape: `FENCED_JSON`; JSON decode `PASS`; schema validation `PASS`; typed parse `PASS`.
- Typed findings: 3 original, 3 persisted, projection not truncated, all finding values redacted.
- P4 evaluator evidence: `required=3`, `submitted=3`, `matched=0`, `extra=3`, `review_findings_pass=false`, `read_only_invariant=true`, `normal_completion=true`.
- Completion proposal: recorded.
- CompletionGate: reached, `not_complete`, reason `NOT_COMPLETE`, authority `CompletionGate`, `model_finalized=false`.

The model proposed a completed response, but the CompletionGate did not accept
completion. This is one rejected false-completion proposal, not a false
completion acceptance.

## P4 candidate evidence (safe projection only)

The persisted artifacts contain safe typed projections. Concepts are shown only
as redaction metadata; raw concept values and raw model output were not read or
reconstructed.

| Ordinal | Candidate category | Candidate file | Concept metadata | Safe finding digest |
|---:|---|---|---|---|
| 0 | `authority_definition` | `src/authority.py` | redacted; original/persisted count 4/4 | `443b9d21b49afe42df76e083e1542d5b23328c56cf8ba533331c731acd792189` |
| 1 | `consumer` | `src/consumer.py` | redacted; original/persisted count 4/4 | `7652f2b8818ba077d7c1337a5d84538ec6c33fd3546a0de79ef5272e8b880f3a` |
| 2 | `enforcement_boundary` | `src/policy.py` | redacted; original/persisted count 4/4 | `813b9e940b32b8e4126ca924413e6e088ac614746ae693daef9ca349958b777` |

The safe projection intentionally sets `typed_finding_values_redacted=true`.
Therefore the concept comparison is `UNKNOWN / SECURITY_BOUNDARY`, not a
negative concept match.

## Context-selection and evidence lineage

P4 recorded three context selections and the final model response followed the
third selection event. The identity chain is internally consistent:

| Selection | Sequence | Reason | Selection digest |
|---|---:|---|---|
| `ctxsel-1` | 1 | `INITIAL_BUILD` | `f8673c7e5a080c2a43e913c9664aa6789344390b7b0e650e06ad2b565a79e2a6` |
| `ctxsel-2` | 2 | `REBALANCE` | `19f553c242d6890d1b7ba9cf0a4d8c6243fcadff3d288ae4642c2b185805c931` |
| `ctxsel-3` | 3 | `REBALANCE` | `7f27462d377844f05efe4644e4fb9d4fe35d93285bc531cd952b16afab9ba014` |

Final selection identity:

```text
selection_id=ctxsel-3
selection_sequence=3
selection_reason=REBALANCE
selection_identity_digest=19f0b80170ca103e75271520a3d537e65971319ef8d8cf27996561a466d1e810
selected_count=22
selection_items_original=22
selection_items_persisted=22
projection_truncated=false
selection_detail_status=AVAILABLE
context reconciliation=PASS
```

The final `context_selected` event is sequence 7, immediately before the
second model response at sequence 8. The event contains the same selection ID,
sequence, reason, digest, and selection history. This proves snapshot/event
identity continuity, not that a particular hidden solution was supplied.

The safe context projection reports 22 rows but `path=null` for all 22 rows and
an empty `selected_repository_paths` list. Repository structure metadata was
available separately, but exact row-to-file membership is not recoverable from
the safe artifact. This is recorded as an attribution limitation, not as
evidence that Context Engine omitted the required files and not as a confirmed
Harness defect.

The agent made one read-only inspection call and did not perform a second
cross-file verification call. This is consistent with a possible
verification/scaffolding limitation, but the safe artifact cannot bind the
read call to a repository path or reveal concepts, so no model-failure claim is
made.

## Offline candidate-to-oracle attribution

The hidden-oracle comparison was performed offline after the provider stopped.
No provider request occurred during attribution (`0` additional requests).
Oracle concept values were not copied into the candidate JSONL or this report.

The oracle requires these canonical category/file pairs:

| Oracle role | Canonical category | File | Candidate category | File comparison | Category attribution |
|---|---|---|---|---|---|
| Authority definition | `authority-definition` | `src/authority.py` | `authority_definition` | exact | `CATEGORY_FORMAT_VARIANT` |
| Authority consumer | `authority-consumer` | `src/consumer.py` | `consumer` | exact | `CATEGORY_ROLE_NEAR_MISS` / underspecified role label |
| Enforcement boundary | `enforcement-boundary` | `src/policy.py` | `enforcement_boundary` | exact | `CATEGORY_FORMAT_VARIANT` |

Safe evidence establishes exact file agreement for 3/3 candidates. It does not
establish concept agreement because the values were redacted before durable
observability persistence. The mechanical evaluator's exact category/file/
concept comparison consequently records 0/3 matches and 3 extras, but that
score is not a valid pure model-convergence score under the public prompt
contract.

### Category ontology audit

The model-visible P4 prompt asks for “the authority definition, its consumer,
the enforcement boundary” and requires a `category` field, but does not publish
the exact hyphenated tokens. The typed parser accepts a category string without
an enum constraint. The evaluator then uses case-insensitive exact equality;
it does not normalize underscore/hyphen separators and does not infer the
`authority-` role qualifier for `consumer`.

This creates a hidden-label/visible-natural-language mismatch. The result is
classified as:

```text
primary:   BENCHMARK_DEFECT / BENCHMARK_ONTOLOGY_MISMATCH
secondary: MODEL_OUTPUT_CONTRACT_VARIANT
confidence: MEDIUM
concept attribution: INCONCLUSIVE / redacted
```

This report does not change the evaluator, prompt, category matcher, or
historical result. A subsequent gate should audit and explicitly contract the
category ontology before another qualification run is authorized.

## Hypothesis matrix

| Hypothesis | Status | Evidence and boundary |
|---|---|---|
| H-A: scaffolding under-elicits verification | `POSSIBLE` | Only one read-only tool call and two model turns; no cross-file verification. Exact read target is intentionally absent from the safe trace. |
| H-B: benchmark ontology mismatch | `SUPPORTED` | 3/3 files exact; candidate labels are natural-language/underscore variants; exact canonical labels are not stated in the public prompt; evaluator has no separator normalization. |
| H-C: genuine model semantic limitation | `INCONCLUSIVE` | Concepts are redacted and exact read-file binding is unavailable; current evidence cannot separate this from contract mismatch. |
| H-D: context salience/ranking failure | `INCONCLUSIVE` | Selection identity and reconciliation pass, but safe projection does not expose row-to-file membership or rank semantics. |
| H-E: output contract/serialization issue | `SUPPORTED` | Candidate output parsed successfully but category token spelling/specificity differs from the evaluator's exact oracle labels. |

The most defensible attribution is H-B/H-E, not H-C. The formal qualification
evidence remains invalidated for capability scoring until the contract is
audited.

## Harness-defect review

| Severity | Candidate defect | Reproduction/evidence | Classification | Action |
|---|---|---|---|---|
| BLOCKER | none | No provider, security, authority-chain, or trace-integrity blocker observed | none confirmed | none |
| HIGH | none | P3/P4 trace reconciliation `PASS`; typed parse/persistence counts reconcile; CompletionGate rejected incomplete evidence | none confirmed | none |
| MEDIUM | none confirmed | Safe path omission limits forensic attribution but does not prove runtime selection loss | diagnostic limitation, not yet a Harness defect | defer to separate observability audit |
| LOW | none | No functional regression identified | none | none |
| INFO | Context safe projection has `path=null` for 22/22 rows and empty selected path list | Selection IDs, digests, counts, event linkage, and reconciliation remain valid | attribution limitation | record only; no source change under this gate |

No benchmark-specific workaround, expected filename injection, context boost,
category special case, or CompletionGate relaxation was introduced.

## Security and artifact audit

- Secret leakage check: **PASS**.
- `secret_values_printed`: `false`.
- No API-key-shaped or Bearer-like value was found in the two generated artifacts.
- No raw model response was persisted; only bounded safe digests, byte counts, parse status, and redacted typed projections were present.
- JSONL is exactly one record and is append-only typed format.
- JSONL mode was `0600`; the JSON summary and JSONL were stored under `/tmp` and were not added to the repository.
- `CodingQualificationRecordV1.from_payload` accepted the record.
- Recomputed record digest matched the stored digest.
- JSON summary and JSONL identity fields matched for the run/provider/model/source/config/scenario digests.
- The candidate JSONL contains no hidden-oracle concepts or reference patch.
- Hidden-oracle comparison was offline only; additional provider requests during attribution: `0`.
- No provider request was made after P4.

**JSONL Validation: PASS**

**Hidden Oracle Isolation: PASS**

**Security Validity: PASS**

## Fixes and rerun decision

**Harness Fixes Applied: none.**

No genuine BLOCKER/HIGH Harness defect was identified. Consequently, no
deterministic regression or real-provider rerun was justified. The original
attempt is preserved as the authoritative first attempt for this lineage.

The next authorized gate should be a read-only
`P4_CATEGORY_ONTOLOGY_CONTRACT_AUDIT` that decides whether the public prompt,
typed schema, and evaluator must publish/normalize one category vocabulary.
That is a new benchmark-contract decision; it is not silently applied here.

## Final verdict

```text
Provider Integration: PASS
Credential Authority: PASS
Secret Leakage Check: PASS
Provider Smoke: PASS
Usage Accounting: UNAVAILABLE / PROVIDER_NOT_REPORTED
Provider Failure Mapping: PASS (offline contract)
Real Model: YES
Real AgentLoop: YES
Real Browser Runtime: NO / NOT RUN
Real App Runtime: NO / NOT RUN
P0-P3: PASS
P4 mechanical result: FAIL
Fresh semantic attribution: BENCHMARK_INVALIDATED / INCONCLUSIVE
Real Agent Harness: PASS for bounded read-only path
Real Coding Capability: UNMEASURED
Real Browser Capability: UNMEASURED
Full Corpus Readiness: NOT READY
Current M8 Capability Status: EARLY SIGNAL ONLY
Production Readiness: NOT READY
M9: NOT STARTED
```

### Protected report invariant

`docs/local-security-closure-report.md` remains **untracked, unchanged,
unstaged**. It was not read, opened, hashed, modified, deleted, staged, or
overwritten. Safe metadata remained `size=851`, `mtime=1787640581`, mode
`0644`.

### Repository state

The new report is an uncommitted local artifact. Existing user changes remain
present. No commit or push was performed.

**Repository state: NOT READY (uncommitted; no delivery authorization).**
