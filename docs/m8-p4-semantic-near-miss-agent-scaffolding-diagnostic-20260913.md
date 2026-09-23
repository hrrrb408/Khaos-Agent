# Khaos M8 P4 Semantic Near-Miss & Agent Scaffolding Diagnostic Report

本报告是对既有 GLM-5.3 与 GLM-5.3-Flash P0–P4-v2 资格运行的离线
取证分析。它不是新的模型运行，也不是资格结果重评或 benchmark 修改。

## Freeze and safety boundary

Branch: codex/m8-coding-evaluation

Exact HEAD: 3c1095ff69b1a5d800d96eb61e8b88a47fceca14

Working-tree identity (current, excluding the protected report and this
diagnostic): 0a9154d11c2764b2ba72be314bc11dcef339489d91f970df78ce5379e2c958b8

Provider calls: 0

Credential reads: 0

Credential unlocks: 0

Protected report:
docs/local-security-closure-report.md = UNCHANGED

Protected-report metadata at the start and end of this gate:

| Field | Value |
|---|---|
| State | untracked, unstaged |
| Mode | 0644 |
| Size | 851 bytes |
| SHA-256 | 85dbfe1ee17475154a0f48a6d308750b252aec75f3b67dd4f2e47f06b25597a1 |

No Provider, CredentialBroker, Keychain, credential session, UI, browser,
AgentLoop, or Coding execution was invoked by this diagnostic.

## Target Runs

### GLM-5.3

Run ID: m8-qualification-67a866dc6a4147eda4fad21e7f9efc8e

Artifacts:

| Artifact | SHA-256 |
|---|---|
| /tmp/khaos-glm53-p0-p4-v2-repair.Y3RTPA/qualification.json | 3b383c664e8ae78dd614e5603801b3c1f4be0f6df5930ab0093ea4356945e34c |
| /tmp/khaos-glm53-p0-p4-v2-repair.Y3RTPA/qualification.jsonl | df88a61bd8468a0fc6f1dc3083f0bcbf0556a0a7258c31972b5d5423814ad681 |

Provider: zhipu-coding

Model: glm-5.3

Recorded P4 provider requests: 1

Recorded P4 model turns: 1

Recorded P4 tool calls: 0

Recorded P4 elapsed time: 31,010 ms

### GLM-5.3-Flash

Run ID: m8-qualification-3bb8c844af124b8d9b2ca3602bf3af0e

Artifacts:

| Artifact | SHA-256 |
|---|---|
| /tmp/khaos-glm53-flash-p0-p4-v2.0LeCWL/qualification.json | 78ccd01aeb39bb79cec2ded5ca8ef0279ea8c5bb9a72b2c427a6e141f4bac590 |
| /tmp/khaos-glm53-flash-p0-p4-v2.0LeCWL/qualification.jsonl | e2fa41b8cb567cfeb6f9d65af9697bb548c482d5d7bfd0304e90b9b57b00c7a8 |

Provider: zhipu-coding

Model: glm-5.3-flash

Recorded P4 provider requests: 2

Recorded P4 model turns: 2

Recorded P4 tool calls: 1

Recorded P4 tool: read_file on README.md; the tool result was successful.

Recorded P4 elapsed time: 89,266 ms

### Identity comparison

| Identity field | GLM-5.3 vs Flash |
|---|---|
| Provider | equal: zhipu-coding |
| Provider configuration digest | equal: 0e40d79f711250ab8f60bccf6381ce804331aff7768013a41f8d8b13935f1529 |
| Scenario | equal: p4-readonly-authority |
| Scenario version | equal: 2 |
| Scenario digest | equal: 314b8022fd0eb325bd8199379135d22f3673cf2e27f9ef0a9d1c3b171eb9fa58 |
| Public + hidden fixture digest | equal: 864d4713661e2e803890f143eaf0268458186b2fbb74c7bfa2d47382fc745b99 |
| Prompt digest | equal: d5a06983c8c5b6f1b827977bda163613a78bc39f6c2caa14a9be9c293c12c42c |
| System prompt digest | equal: c58fa0da8673fe4e9895877877b1a0d5ae876db9efc27b563400cb0bf99b8356 |
| Recorded tool-schema digest | equal: 401eab0fb0a481a1f5c20b506f84f1dda42234ff344937807c338eec1fcf1f98 |
| Policy digest | equal: cf1bc0a3a97c13e0c9e00a7954a5c168a999671ffaa83a3a58ab33d17e758f93 |
| Suite digest | equal: 5b130e35bbc32a7fa6adf91a5767a5521a54287db83c8e008988332f96530185 |
| Repository base revision | equal: 5a499966272316ca967d4a366ace2808134f691d |
| Budgets | equal: P3 8/8/120s; P4 12/24/300s |
| Reasoning and sampling | equal: UNKNOWN / NOT_REPORTED |
| Source HEAD | equal: 3c1095ff69b1a5d800d96eb61e8b88a47fceca14 |
| Recorded working-tree identity | different: GLM 50023357b665adbec6d7a6cbbfb2e0402628d062e67a9bc7009bae67b8ee628c; Flash 1c7883bca8483a1e7072681449b3da059def849b89c8ed180fa893152c2a665d |

Strict byte-identical working-tree comparability is therefore FAIL. All
recorded execution-relevant digests are equal and the intended independent
variable is the model, so pair-internal execution comparability is PASS with
this limitation. The current checkout also produces 73 tool schemas with
digest 8ab1d9b500c7b2d73e6c12fdb448efd3e6e5a1ad22fb0783cd643510e7e0e598,
which differs from the recorded run digest. No current checkout result is
retroactively substituted for either target run.

## Official Results

GLM-5.3:

- P0: PASS
- P1: PASS
- P2: PASS
- P3: PASS
- P4: FAIL
- P4 semantic match: 0/3
- Qualification: FAIL

GLM-5.3-Flash:

- P0: PASS
- P1: PASS
- P2: PASS
- P3: PASS
- P4: FAIL
- P4 semantic match: 0/3
- Qualification: FAIL

These official results were modified: NO.

Both P4 responses had fenced JSON, JSON decoding PASS, schema validation PASS,
typed parse PASS, three submitted typed findings, three extra findings, and
zero matched Oracle findings. Both runs were side-effect-free and left the
fixture source unchanged. Provider status was HTTP 200 with no typed Provider
failure. Usage fields were null and remain UNKNOWN / PROVIDER_NOT_REPORTED.

## Evidence Retention Limitation

The exact candidate finding values cannot be extracted from the preserved
qualification artifacts. The artifacts retain:

- typed_finding_count = 3;
- finding_field_count = 3;
- semantic submitted_count = 3;
- matched_finding_ids = [];
- extra_count = 3;
- a redacted-response digest and bounded byte count.

They do not retain category, workspace-relative file, concepts, line, severity,
or summary for any candidate. The JSON and JSONL contain no finding object with
category/file/concepts. The runtime parser creates typed ReviewFinding values
transiently, but the durable response observer records shape-only metadata.
The response digest is not reversible.

Consequently, candidate-to-Oracle semantic distance, role confusion, concept
overlap, and candidate defensibility are NOT COMPUTABLE from the preserved
evidence. This is an evidence boundary, not an inference that the candidates
were unrelated or near-miss.

## Oracle Findings

The Oracle is inspected only in this offline diagnostic scope. It was not
injected into either run and neither model-visible fixture was modified.

### Table A — Oracle Findings

| Oracle ID | Role | Expected file | Expected concepts | Architectural layer | Ontology ambiguity |
|---|---|---|---|---|---|
| authority-definition | authority definition | src/authority.py | AuthorityLease, issue_lease, definition | lease type and issuance | LOW–MEDIUM: class and factory share one file |
| authority-consumer | authority consumer | src/consumer.py | consume_lease, AuthorityLease, consumer | consumer-side use | MEDIUM: consumer also repeats the guard |
| enforcement-boundary | enforcement boundary | src/policy.py | require_active, project_id, invariant | policy validation | MEDIUM: same active/project condition is duplicated in consumer |

### Public architectural map

The definition is code-explicit: src/authority.py defines the frozen
AuthorityLease dataclass and issue_lease factory.

The consumer is code-explicit: src/consumer.py defines consume_lease and
accepts an AuthorityLease plus project_id.

The policy boundary is code-explicit: src/policy.py is documented as the policy
boundary and require_active documents enforcement of the active-and-project
bound invariant.

The fixture contains a real ontology overlap: consume_lease independently
checks both lease.active and lease.project_id, while require_active repeats
those checks in the policy module. A response identifying consumer.py as a
place where enforcement occurs could be partially technically defensible, but
the module/function documentation and prompt identify policy.py as the
intended enforcement boundary. This is a benchmark ambiguity risk, not a
confirmed benchmark defect.

## GLM-5.3 Submitted Findings

The three submitted finding slots are present, but their typed values are not
persisted. Every row below is deliberately marked unavailable rather than
reconstructed from a digest.

### Table B — GLM-5.3 Findings

| Candidate | Closest Oracle | File proximity | Concept proximity | Role error | Near-miss class | Distance | Defensibility |
|---|---|---|---|---|---|---|---|
| 1 | NOT AVAILABLE | NOT COMPUTABLE | NOT COMPUTABLE | NOT COMPUTABLE | NOT CLASSIFIABLE | INCONCLUSIVE | NOT ASSESSABLE |
| 2 | NOT AVAILABLE | NOT COMPUTABLE | NOT COMPUTABLE | NOT COMPUTABLE | NOT CLASSIFIABLE | INCONCLUSIVE | NOT ASSESSABLE |
| 3 | NOT AVAILABLE | NOT COMPUTABLE | NOT COMPUTABLE | NOT COMPUTABLE | NOT CLASSIFIABLE | INCONCLUSIVE | NOT ASSESSABLE |

### Structured evidence

GLM-5.3 P4 response format: FENCED_JSON.

GLM-5.3 P4 response bytes: 2,280.

GLM-5.3 P4 typed parse: PASS.

GLM-5.3 P4 semantic evidence digest:
c63676248d1d560b3cafbd6dd7b438e0e64f0a7e97c8b53dbc291bfc7b563781.

## GLM-5.3-Flash Submitted Findings

The three submitted finding slots are present, but their typed values are not
persisted. Every row below is deliberately marked unavailable.

### Table C — GLM-5.3-Flash Findings

| Candidate | Closest Oracle | File proximity | Concept proximity | Role error | Near-miss class | Distance | Defensibility |
|---|---|---|---|---|---|---|---|
| 1 | NOT AVAILABLE | NOT COMPUTABLE | NOT COMPUTABLE | NOT COMPUTABLE | NOT CLASSIFIABLE | INCONCLUSIVE | NOT ASSESSABLE |
| 2 | NOT AVAILABLE | NOT COMPUTABLE | NOT COMPUTABLE | NOT COMPUTABLE | NOT CLASSIFIABLE | INCONCLUSIVE | NOT ASSESSABLE |
| 3 | NOT AVAILABLE | NOT COMPUTABLE | NOT COMPUTABLE | NOT COMPUTABLE | NOT CLASSIFIABLE | INCONCLUSIVE | NOT ASSESSABLE |

### Structured evidence

GLM-5.3-Flash P4 response format: FENCED_JSON.

GLM-5.3-Flash P4 response bytes: 1,597.

GLM-5.3-Flash P4 typed parse: PASS.

GLM-5.3-Flash P4 semantic evidence digest:
c63676248d1d560b3cafbd6dd7b438e0e64f0a7e97c8b53dbc291bfc7b563781.

## Cross-Model Error Pattern

### Table D — Shared Error Pattern

| Dimension | GLM-5.3 | Flash | Shared? |
|---|---|---|---|
| Same wrong files | candidate values unavailable | candidate values unavailable | INCONCLUSIVE |
| Same wrong concepts | candidate values unavailable | candidate values unavailable | INCONCLUSIVE |
| Same role-confusion pattern | candidate values unavailable | candidate values unavailable | INCONCLUSIVE |
| Same architectural layer | candidate values unavailable | candidate values unavailable | INCONCLUSIVE |
| Structured shape | 3 typed findings, parse PASS | 3 typed findings, parse PASS | YES |
| Exact semantic match | 0/3 | 0/3 | YES |
| Verification trajectory | initial context only | README-only read | NO |

The only confirmed shared semantic pattern is failure to satisfy the exact
Oracle contract. Shared wrong-file, wrong-concept, or role-confusion claims are
not confirmed.

## Initial Context Evidence

### GLM-5.3

- Trace v2: 9 events, reconciliation PASS, no truncation.
- Initial context selection event: 19 selected items, 14 automatic repository
  items, 5 non-repository items, 0 tool-acquired items.
- Selected repository paths in the Trace event:
  src/authority.py, src/consumer.py, src/policy.py, src/unrelated.py.
- Repository context bundle: 4 documents, 22 evidence items, 5 symbols, and
  structure paths README.md plus the four source modules.
- No explicit repository tool call.
- P4 CompletionGate was reached with not_complete / NOT_COMPLETE; model_finalized
  was false and no completion was accepted.

### GLM-5.3-Flash

- Trace v2: 13 events, reconciliation PASS, no truncation.
- Initial context selection event: 19 selected items, 14 automatic repository
  items, 5 non-repository items, 0 tool-acquired items.
- Selected repository paths in the Trace event:
  src/authority.py, src/consumer.py, src/policy.py, src/unrelated.py.
- Repository context bundle: 4 documents, 22 evidence items, 5 symbols, and
  structure paths README.md plus the four source modules.
- One successful read_file call read README.md; no source-module cross-check
  call was observed.
- P4 CompletionGate was reached with not_complete / NOT_COMPLETE; model_finalized
  was false and no completion was accepted.

The final stage-level context_observability projection reports an empty
selected_repository_paths list for both runs, while the Trace v2
context_selected event reports the four source paths above. It also reports
different final non-repository counts (7 and 8) from the Trace event count of 5.
This is a low-severity observability projection inconsistency; the Trace retains
the useful path-level evidence and there is no indication that context was
truncated.

### Table E — Context Availability

| Oracle finding | Correct file in context? | Correct concepts present? | Salience | Additional verification needed? |
|---|---|---|---|---|
| authority-definition | YES at Trace path level | YES in public source; exact selected excerpt UNKNOWN | UNKNOWN | YES |
| authority-consumer | YES at Trace path level | YES in public source; exact selected excerpt UNKNOWN | UNKNOWN | YES |
| enforcement-boundary | YES at Trace path level | YES in public source; exact selected excerpt UNKNOWN | UNKNOWN | YES |

Context sufficiency: PARTIAL. Path-level repository context was complete and
untruncated, but the safe artifacts do not retain selected content, token
counts, byte counts, layer rank, or item salience.

## Context Salience

The following is static public-fixture prominence, not a claim about the
model-visible token ranking:

| Concept | Static occurrences | Location summary |
|---|---:|---|
| AuthorityLease | 7 | authority.py, consumer.py, policy.py |
| issue_lease | 1 | authority.py |
| definition | 2 | README.md |
| consume_lease | 1 | consumer.py |
| consumer | 3 | README.md and consumer.py docstring |
| require_active | 1 | policy.py |
| project_id | 8 | all three authority-chain modules |
| invariant | 2 | README.md and policy.py |

Oracle concepts have clear public-source presence. The most salient shared
identifiers are AuthorityLease and project_id. The competing role signal is
that consume_lease contains the same active/project checks as require_active;
format_label in unrelated.py is a clear distractor with no authority concepts.
Candidate concepts are unavailable, so candidate-vs-Oracle salience cannot be
quantified.

Context salience risk: MEDIUM as a hypothesis, because duplicated enforcement
logic can compete with the policy label and the selection rank is not
persisted.

Context salience bias: INCONCLUSIVE, not supported by the preserved evidence.

## Verification Behavior

GLM-5.3 repository tool calls: 0. The model answered from the initial context
as observable; no explicit cross-check was recorded.

GLM-5.3-Flash repository tool calls: 1 successful read_file on README.md. No
read_file call for the three source modules and no search/symbol/reference
query was recorded.

GLM-5.3 verification style: INITIAL_CONTEXT_ONLY.

GLM-5.3-Flash verification style: PARTIAL / README_ONLY.

No test, terminal, edit, browser, or network tool was used, consistent with the
P4 read-only task contract. This means the absence of test execution is not a
defect. The missed diagnostic opportunity was a bounded cross-file confirmation
of the authority definition, consumer, and policy boundary.

## System Prompt, Tool, and Repo-Intelligence Audit

The shared system prompt digest is
c58fa0da8673fe4e9895877877b1a0d5ae876db9efc27b563400cb0bf99b8356.

The system prompt:

- strongly encourages repository reading and semantic code navigation;
- encourages bounded search, symbols, callers/callees, references, and related
  tests;
- encourages planning for multi-file or high-risk changes;
- strongly encourages verification in ordinary Coding workflow;
- requires evidence-grounded reporting through the P4 user prompt;
- strongly encourages a natural stop after enough evidence;
- does not require a review checklist that maps each requested role to a
  distinct file and relationship;
- does not explicitly require a self-reflection or ambiguity-resolution pass;
- does not expose a model-facing signal describing the exact selected context
  or its salience/partiality.

The P4 prompt itself says read-only tools are available “as needed” and says to
stop when enough evidence is available. It requires one JSON object with three
findings, but does not require reading all three source modules or performing a
cross-file verification before answering.

The selected production tool descriptions are generic:

| Tool | Relevant description | Diagnostic implication |
|---|---|---|
| read_file | Read a bounded file page with one-based line numbers | usable but no role-mapping guidance |
| search_files | Search filenames or file contents | available, optional |
| file_search_content | Search contents with bounded pattern matching | available, optional |
| code_search | Search the repository index semantically, with lexical fallback | available, optional |
| code_symbols | Extract indexed symbols from a source file | available, optional |
| file_info/tree_view | Inspect metadata or structure | available, optional |

No tool description says that code review should cross-check a definition,
consumer, and enforcement boundary as a three-node relationship. This supports
an elicitation mismatch hypothesis but does not prove causality.

## Khaos Scaffolding Audit

### Table F — Scaffolding

| Behavior | Required? | Encouraged? | Observed? | Potential impact |
|---|---|---|---|---|
| plan | NO for this small P4 task | YES in general workflow | no explicit plan event retained | no externalized role decomposition |
| search | NO | STRONGLY | GLM NO; Flash no search query | relevant evidence may be left to initial context |
| read | PARTIAL: findings must be grounded, no minimum file set | STRONGLY | GLM no explicit read; Flash README only | source-level relationship may remain unchecked |
| cross-check | NO explicit requirement | INDIRECTLY | NOT OBSERVED | duplicated consumer/policy guard remains ambiguous |
| verify | NO test/command allowed; no semantic checklist | MODERATE in general workflow | runtime parser/gate only; model verification not observed | shape correctness can be mistaken for semantic sufficiency |
| reflect | NO | NOT EXPLICIT | NOT OBSERVED | no correction pass is externally visible |
| answer | YES: one JSON object with three findings | STRONGLY | YES; parse/schema/typed shape PASS | output format works, semantic mapping still fails |

Context uncertainty signal: ABSENT as a model-facing selection/salience
indicator. Repository freshness and trust boundaries are described, but they do
not tell the model which evidence was actually selected or whether role
ambiguity remains.

Potential scaffolding mismatch: YES as a hypothesis; INCONCLUSIVE as a causal
finding.

## P4 Ontology Audit

Authority definition: CODE-EXPLICIT. The class and factory are in
src/authority.py and are named in the Oracle.

Consumer: CODE-EXPLICIT. consume_lease accepts and uses AuthorityLease in
src/consumer.py.

Enforcement boundary: CODE-EXPLICIT but partially overlapping. src/policy.py
calls itself the policy boundary and require_active documents the invariant,
while src/consumer.py repeats the enforcement condition.

Overall ontology ambiguity: MEDIUM.

Candidate alternatives technically defensible: PARTIAL. A finding that calls
consumer.py an enforcement location would have code support, but it would not
identify the intended policy boundary. Because the actual candidates are not
persisted, this remains a benchmark-level ambiguity assessment rather than a
candidate classification.

Benchmark defect confirmed: NO. The task wording, README, module docstrings,
function names, and policy documentation make the intended interpretation
reasonably derivable. The duplicated guard merits a future ontology review, not
an automatic score change.

## Hypothesis Evaluation

### H_A — Capability sufficient but Khaos fails to elicit verification

Evidence for: the task leaves tools “as needed”; the system workflow does not
require a three-file role checklist; GLM used no explicit tool and Flash only
read README; neither trace shows a model-side cross-check.

Evidence against: both models had untruncated path-level source context, and
the candidate typed values are unavailable. No controlled scaffold comparison
exists.

Verdict: POSSIBLE.

### H_B — P4 ontology is unusually Khaos-specific

Evidence for: “enforcement boundary” is a role label and the consumer and
policy modules duplicate the same active/project guard.

Evidence against: the public prompt, README, module docstring, and
require_active docstring explicitly describe the intended policy boundary.

Verdict: POSSIBLE, not a confirmed benchmark defect.

### H_C — GLM family genuinely lacks the required semantic reasoning

Evidence for: two related models produced valid three-finding structures and
both scored 0/3 on the same semantic contract.

Evidence against: strict working-tree identity comparability fails; exact
candidate values are not retained; no scaffolding control exists; no
candidate-to-Oracle distance can be measured.

Verdict: POSSIBLE, not confirmed.

### H_D — Context salience biases the model toward wrong architecture concepts

Evidence for: source paths were available, the consumer repeats the policy
condition, and exact salience ranks are absent.

Evidence against: candidate concepts are unavailable; context was not
truncated; no competing candidate frequency or selected-content ranking is
stored.

Verdict: INCONCLUSIVE.

## Primary Diagnosis

Primary classification: INCONCLUSIVE.

Secondary classifications:

- AGENT_SCAFFOLDING_ELICITATION_MISMATCH — POSSIBLE.
- BENCHMARK_ONTOLOGY_MISMATCH — POSSIBLE, not confirmed.
- CONTEXT_SALIENCE_BIAS — INCONCLUSIVE.
- OBSERVABILITY_EVIDENCE_RETENTION_GAP — CONFIRMED as a forensic limitation,
  not as the cause of the P4 semantic failure.

Confidence: HIGH for the evidence-retention conclusion; LOW–MEDIUM for any
causal explanation of the model's semantic miss.

Explanation: 0/3 proves that none of the three submitted typed findings
satisfied the exact Oracle matching predicate. It does not prove that the
answers were completely unrelated, near-misses, role swaps, or technically
defensible alternatives. The missing candidate projection prevents that
distinction.

## Interpretation of 0/3

0/3 means: INCONCLUSIVE for semantic distance.

Reason: the preserved record has a valid structured response with three
submitted findings and zero exact matches, but only counts and digests. The
candidate file/symbol/role/relationship/concept fields needed for a near-miss
analysis are absent.

It is therefore not valid to relabel 0/3 as COMPLETELY_WRONG,
ARCHITECTURAL_NEAR_MISS, or ROLE_MAPPING_FAILURE from this evidence alone.

## Candidate Harness Defect Review

No BLOCKER or HIGH causal Harness defect was found. Two lower-severity
observability issues are recorded for a future authorized change.

Severity summary:

- BLOCKER: none.
- HIGH: none.
- MEDIUM: P4 typed candidate projection is not persisted.
- LOW: final context summary loses selected paths while Trace retains them.

| Defect | Reproduction | Severity | Affected subsystem | Generalizable? | Security impact | Recommended fix |
|---|---|---|---|---|---|---|
| P4 typed candidate projection is not persisted | Both artifacts have typed_finding_count=3 and extra_count=3, but no category/file/concepts finding objects | MEDIUM | response observability and qualification artifact projection | YES | none observed; preserve current no-raw-output rule | Persist a bounded, sanitized candidate projection containing only category, validated workspace-relative file, and concepts; add schema/redaction/oracle-isolation tests |
| Final context summary loses selected paths | Stage summary has selected_repository_paths=[], while Trace v2 context_selected retains four source paths; non-repository counts also differ | LOW | observability summary merge | YES | none observed; Trace remains safe | Preserve the last exact selection projection when attaching aggregate context metrics |

Neither issue was fixed in this gate because the gate explicitly freezes source,
semantic evaluator, observability implementation, prompt, fixture, and Oracle.
No rerun was performed and no historical result was overwritten.

## False Completion and Runtime Integrity

Observed completion proposals: 2 total, one per target run.

Accepted completions: 0.

CompletionGate: reached for both runs with not_complete / NOT_COMPLETE.

False completion accepted: NO.

Whether the unpersisted candidate findings represented a semantically
premature proposal cannot be determined. The runtime correctly kept the
completion state from becoming accepted.

Trace integrity: PASS for both runs; no truncation and no reconciliation
mismatch.

Read-only invariant: PASS for both runs; side_effect_free=true and
source_unchanged=true.

## Security Scan

Target JSON/JSONL artifacts:

- secret_values_printed=false in both aggregate records;
- no raw response body, credential value, or authentication header is stored;
- only opaque credential reference metadata is present;
- no hidden Oracle content or grading mapping is present in model-visible
  fixture files.

Public fixture isolation:

- public fixture contains README.md and the four intended source modules only;
- no .oracle-hidden directory or verify.py exists under the public fixture root;
- hidden Oracle material remains in the evaluator-only hidden directory;
- the current fixture digest equals the recorded digest
  864d4713661e2e803890f143eaf0268458186b2fbb74c7bfa2d47382fc745b99.

Diagnostic report scan: PASS. No credential-shaped value, raw authentication
material, or hidden answer mapping was added.

## JSONL Validation

GLM-5.3 JSONL: PASS.

GLM-5.3-Flash JSONL: PASS.

Evidence: each JSONL contains one coding_qualification record; the typed
CodingQualificationRecordV1 parser accepted it; record_digest validation
passed; the JSON aggregate and JSONL identity fields agree.

Hidden Oracle Isolation: PASS.

The hidden directory was used only for offline Oracle inspection. It was not
copied into the model-visible public fixture, prompt, report artifacts used by
future qualification, or either target run.

## Role Confusion Matrix

| Intended role | Candidate value available? | Static overlap risk | Classification |
|---|---|---|---|
| definition | NO | class and factory share src/authority.py | UNKNOWN |
| consumer | NO | consumer imports the authority and repeats the guard | UNKNOWN |
| enforcement boundary | NO | policy and consumer both check active/project | UNKNOWN |

## Impact on Qualification

GLM-5.3 Qualification: FAIL.

GLM-5.3-Flash Qualification: FAIL.

Should either official result be retroactively changed: NO.

Real Coding: UNMEASURED.

Real Browser Capability: UNMEASURED.

Full Corpus: NOT READY.

Production: NOT READY.

## Recommended Next Action

MIXED_CAUSE_REQUIRES_FURTHER_OFFLINE_ANALYSIS.

The next useful experiment is a controlled scaffolding differential, but it
must wait for a separately authorized artifact projection that safely retains
candidate category/file/concepts. The differential must keep the model,
fixture, semantic target, provider configuration, and budget fixed, and vary
only a bounded evidence/checklist scaffold. It must not inject the Oracle's
golden files, concepts, finding IDs, or answer mapping.

## Future Differential Experiment

Design only; execution authorized: NO.

Model held constant: GLM-5.3-Flash (candidate).

Fixture held constant: p4-readonly-authority, version 2, same public and hidden
fixture digest.

Semantic target held constant: same frozen REVIEW_FINDING Oracle, same
allow_extra_findings=false and ALL matching.

Khaos scaffold: current production system prompt plus current P4 prompt.

Comparison scaffold: an otherwise identical prompt that asks the model to
create a bounded role map, cite one public evidence item per finding, perform a
three-file cross-check, and only then emit the same JSON shape. It must not
name or imply the expected file/concept mapping.

Independent variable: elicitation scaffold only.

Dependent variables: tool use, cross-check behavior, candidate typed-field
projection, semantic matches, completion behavior, and false-completion
proposals.

No Provider request, rerun, benchmark mutation, or differential execution was
performed here.

## Capability State

Harness: PASS for the frozen qualification path.

Observability: PASS for schema/reconciliation; INSUFFICIENT for candidate-level
forensic attribution.

Provider: PASS for the historical target runs.

GLM-5.3 Qualification: FAIL.

GLM-5.3-Flash Qualification: FAIL.

Qualified Coding Candidate: NONE.

Real Coding: UNMEASURED.

Full Corpus: NOT READY.

Browser: UNMEASURED.

Production: NOT READY.

M9: NOT STARTED.

## Repository State

Source modified by this diagnostic: NO.

Prompt modified: NO.

Fixture modified: NO.

Oracle modified: NO.

Historical reports modified: NO.

Diagnostic artifact:
docs/m8-p4-semantic-near-miss-agent-scaffolding-diagnostic-20260913.md

Git publication: UNCOMMITTED.

No commit, push, PR update, rebase, reset, clean, or merge was performed.

Repository state: NOT READY. The diagnostic is complete and remains
uncommitted; the accumulated worktree changes and the strict comparability
caveat require a separate user-authorized delivery decision.
