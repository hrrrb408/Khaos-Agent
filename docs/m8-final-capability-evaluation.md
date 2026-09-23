# Khaos M8 Final Capability Evaluation

This is the current evidence record for the M8 final evaluation. It is
intentionally conservative: deterministic harness evidence is not presented
as real-provider coding capability.

## 0.0 Latest real-provider run (2026-09-15)

This section is the latest evidence for the current working tree; the older
checkpoint sections below remain historical and are not overwritten.

```text
Provider: zhipu-coding
Model: glm-5.3-flash
Provider integration: PASS
Real-provider built-in corpus: 12/17 SUCCESS, 3 FAILURE, 2 TIMEOUT
Real-provider capability: EARLY SIGNAL ONLY / NOT CONFIRMED
Full corpus infrastructure readiness: READY
Production readiness: NOT READY
```

The sanitized append-only result file is
`/private/tmp/khaos-glm53-full-final.ctODM4/benchmark.jsonl`. Its 17 records
bind source SHA `3c1095ff69b1a5d800d96eb61e8b88a47fceca14`, provider/model
identity, policy/config/manifest digests, fixture base revisions, and result
digests. Twelve scenarios passed, three completed scenarios failed, and two
scenarios timed out. Earlier results remain preserved and are not rewritten.

Provider usage tokens were not reported by the adapter (`PROVIDER_NOT_REPORTED`);
request counts and bounded trace metrics were recorded. Fifteen CompletionGate
attempts were reached and remained fail-closed at `not_complete`; two timeout
records did not reach the gate and no false completion was accepted. Browser
scenarios used the real model, controlled browser runtime, and task-local app
processes, with external egress disabled.

## 1. Verdict at this checkpoint

```text
Engineering baseline: PASS
Security / exact-SHA baseline: PASS
Provider integration: PASS (current run; 152 HTTP-200 observations)
Real-provider corpus: PARTIAL (current run; 12/17 SUCCESS)
Real-provider capability: EARLY SIGNAL ONLY / NOT CONFIRMED
Full corpus readiness: NOT READY
Production readiness: NOT READY
```

The current post-fix corpus is meaningful reproducible evidence, but its five
non-success records still prevent confirmation of complete Coding capability.
The report remains open for a future authorized capability phase.

## 0.0.1 P4-v3 contract follow-up (2026-09-15)

The original full-corpus failure is preserved above and was not overwritten.
Two separately recorded, affected-scenario-only follow-ups were then run
through the same production-shaped path:

| Attempt | Artifact | Result | Evidence |
| --- | --- | --- | --- |
| Prompt-format follow-up | `/private/tmp/khaos-glm53-p4v3-promptfix-zQCI4D/benchmark.jsonl` | `FAILURE` | Plain JSON parse and schema validation passed; semantic review failed. Run ID `m8-5e6d33ccfa484f4e84069ecc65b75b17`. |
| Source-identifier guidance follow-up | `/private/tmp/khaos-glm53-p4v3-concepts-vfxvqt/benchmark.jsonl` | `FAILURE` | Plain JSON parse and schema validation passed; categories/files were correct, but the model did not provide all required source-grounded concepts. Run ID `m8-5150b234b8c44591964d622a4b846c94`. |

The Coding system prompt now contains two general rules: machine-readable
contracts take precedence over prose/fences, and structured review evidence
should use exact identifiers observed in source. The affected deterministic
tests passed (`54 passed`), the evaluation suite passed (`227 passed`), and
the second real follow-up still failed at semantic attribution. This is
classified as a model limitation, not a Harness defect; the parser, typed
schema, read-only boundary, and hidden Oracle were not weakened.

The full real-provider coding capability therefore remains
`EARLY SIGNAL ONLY / NOT CONFIRMED`. The full corpus was not relaunched after
these targeted diagnostic attempts.

## 0.1 Credential isolation security-gate checkpoint (2026-09-12)

This checkpoint is a security-closure run, not a real-provider capability run.
No live Provider request, real Coding task, benchmark corpus, browser runtime,
or M9 work was started. The historical smoke/sanity records below remain
historical evidence and were not reused as fresh evidence for this gate.

The canonical CredentialBroker now owns provider credential-store resolution;
normal provider configuration carries only an opaque `credential_ref`, and
Memory HTTP providers use the same broker at the transport boundary. Legacy
provider secret fields and `*_env` credential selectors are rejected. Synthetic
regressions cover defensive secret serialization, cross-provider denial,
unavailable-backend fail-closed behavior, secretless config writes, child
environment isolation, brokered HTTP headers, and metadata-only diagnostics.

The targeted security/routing/configuration/execution regression set passed
with `83 passed, 1 skipped`; the evaluation-contract subset passed with `27
passed`, and the CLI/RPC/Memory subset passed with `57 passed, 4 skipped`.
The native macOS Keychain round-trip was attempted once with a synthetic
credential and returned a generic host Keychain write failure. It did not
block, expose a secret, or authorize a provider request; it remains
`ENVIRONMENT_BLOCKED`/unverified rather than a Harness regression. Ruff/Pyright
are unavailable in this local virtual environment. The full real-provider
corpus remains `NOT READY`.

Current security-gate boundary: secretless configuration, synthetic transport
isolation, task HOME/environment isolation, and safe diagnostics are covered;
the production macOS Keychain gate is not closed until the host can complete
the native synthetic put/get/delete test.

Previously exposed provider credentials remain compromised and require
rotation outside this run. No credential value is recorded here.

## 2. Source and Phase 0 evidence

| Field | Evidence |
| --- | --- |
| Branch | `codex/m8-coding-evaluation` |
| Existing PR | `#230` |
| Baseline Khaos SHA | `3c1095ff69b1a5d800d96eb61e8b88a47fceca14` |
| M8.8 exact-SHA CI | 10 required workflows, attempt 1, terminal success |
| Exact-SHA run IDs | Recorded in [M8.8 closure](m8.8-browser-app-coding-closure.md#43-ci-evidence) |
| Protected local report | `docs/local-security-closure-report.md`: unchanged and untracked |

The local evaluation-plane changes associated with this working record are
uncommitted and therefore are not covered by the baseline SHA's remote CI.

## 3. Provider smoke and bounded sanity

The existing provider abstraction, Router, AgentLoop, evaluation runner, and
authority-controlled tools were used. No provider SDK or benchmark-only raw
provider path was added.

The effective host configuration resolved the configured Coding Plan provider
as `zhipu-coding` with model `glm-5.2`. A minimal real request returned the
exact acknowledgement `ACK` through the OpenAI-compatible Khaos adapter. The
smoke made one request, received a response, and did not expose credential
material. The adapter did not report usage or provider-returned model identity;
these remain `UNKNOWN / PROVIDER_NOT_REPORTED`, not zero.

Five sequential real-agent scenarios were then attempted with a 120-second
task budget and the existing fixture-only browser policy:

```text
bugfix-python-cache       TIMEOUT  MODEL_TOOL_USE_LIMIT (final rerun)
multifile-python-settings TIMEOUT  PROVIDER_DEFECT
bugfix-go-counter         TIMEOUT  MODEL_TOOL_USE_LIMIT (after Harness rerun)
refactor-python-repository TIMEOUT PROVIDER_DEFECT
browser-fullstack-bug     TIMEOUT  MODEL_TOOL_USE_LIMIT
```

The real trajectories exposed three generalizable Harness contract defects:
injected Git/terminal authority arguments and the Registry-injected
`workspace_manager` argument for `test_run`. The original attempts are
preserved, regression tests were added, and affected scenarios were rerun
after the fixes. The raw and classified artifacts are held outside the repository at
`/tmp/khaos-m8-real-sanity.8w7Hcy/results.jsonl` and
`results-classified-with-policy-v2.jsonl`; the five-task final view is
`results-final-selected-v2.jsonl`.

The original raw JSONL intentionally preserves attempts made before the policy
binding fix, so its earliest records have a null policy digest. The classified
and final-selected artifacts are the validated report views and bind the
effective policy digest on every record.

The browser-tagged task used the real model, but recorded zero browser calls,
zero browser sessions, and no confirmed app runtime. It is integration
evidence only, not strict real-browser readiness.

## 4. Corpus status

The pre-repair checked-in M8.0 pack contained 15 deterministic isolated
scenarios. The current working-tree manifest contains 16 after adding the
versioned P4-v2 qualification fixture; this remains below the requested
20-task real-repository minimum and is not a substitute for Layer B/C
evaluation.

| Dimension | Current Layer A pack |
| --- | ---: |
| Tasks | 16 (including P4-v2 qualification) |
| Languages | Python, TypeScript/JavaScript, Go, Rust |
| Difficulty | easy 1, medium 8, hard 6 |
| Browser-tagged tasks | 3 |
| Long-horizon tasks | 0 |
| External real-repository corpus | not run |
| Hidden-oracle leakage | none observed in the checked-in fixture path |

Layer B real-repository tasks, Layer C long-horizon tasks, repeated stochastic
runs, serial/full-harness comparison, and competitor comparison are therefore
`NOT RUN`.

## 5. Implemented evaluation-plane hardening

- Added `CodingBenchmarkResultV1` with typed states including `MODEL_ERROR`,
  `INFRASTRUCTURE_ERROR`, `SECURITY_FAILURE`, and `QUARANTINED`.
- Added secret-free, bounded, append-only JSONL artifacts with configuration,
  scenario, policy/source digests, task seed, and p50/p75/p90 aggregation.
- Added provider-failure taxonomy instead of collapsing unavailable models into
  fixture errors.
- Fixed failed runtime adapters so an untrusted external final-root value is
  never inspected after model/provider failure; the runner uses only the
  fixture-owned baseline tree.
- Extended scenario contracts for the final benchmark categories and
  `long_horizon` difficulty without adding a functional M8.9 milestone.

## 6. Local verification

| Check | Result |
| --- | --- |
| Coding evaluation and affected authority tests | `146 passed` |
| Security reachability/inventory focused tests | `7 passed` |
| Ruff on touched evaluation/CLI files | `PASS` |
| Python compile check | `PASS` |
| `git diff --check` | `PASS` |
| Real-provider smoke | PASS; usage unavailable from adapter |
| Five-task sanity | 5 distinct tasks, 9 preserved attempts, all TIMEOUT |
| JSONL schema / secret scan / policy binding | PASS |
| Real provider full corpus | not run |

## 7. Capability questions

The following remain unanswered and must stay `UNKNOWN` until the real corpus
runs: reliable real bug fixing, medium feature implementation, multi-file
refactoring quality, test-repair recovery, effective parallel delegation,
browser debugging, long-horizon completion, human-intervention rate, and
same-model harness delta. The sanity run supplies only an early diagnostic
signal and no capability rate.

## 8. Security questions

No authority escape, approval replay, stale-completion acceptance, credential
leakage, or browser/MCP resource claim was produced by the smoke/sanity
traces. The bounded run did not constitute a full adversarial release audit.

## 9. Next gate

Resolve the provider stability and browser-environment boundaries, then run the
full corpus through the existing CLI with a fresh task scope and a
`--results-jsonl` artifact. Do not infer full capability from this sanity run.

## 10. GLM-5.3-Flash stabilization sanity

The follow-up run used the configured `zhipu-coding` OpenAI-compatible
provider with model `glm-5.3-flash`, through the production router and
AgentLoop. The provider smoke returned the exact acknowledgement and the
real AgentLoop tool microprobe completed one `file_info` call followed by the
expected continuation. Provider-returned model identity and token usage were
not exposed by the current streaming adapter and remain explicitly unknown.

The five canonical sanity scenarios were run sequentially with the existing
120-second, 128-turn, 512-tool, no-network, fixture-only-browser policy:

| Scenario | Result | Observed boundary |
| --- | --- | --- |
| `bugfix-python-cache` | `TIMEOUT` | One patch and one targeted test; no completion gate result. |
| `bugfix-go-counter` | `TIMEOUT` | Repository inspection only; no edit. |
| `multifile-python-settings` | `TIMEOUT` | Four file reads; no edit or test. |
| `refactor-python-repository` | `TIMEOUT` | Four context tools; no edit or test. |
| `browser-fullstack-bug` | `TIMEOUT` | Investigation only; `browser_calls=0`. |

The raw typed records are retained at
`/tmp/khaos-m8-glm53-sanity.jQ5ITb/results.jsonl`; the Task 1 rerun remains
separate at
`/tmp/khaos-m8-glm53-sanity.jQ5ITb/results-task1-after-state-root-fix.jsonl`.
The results are an early diagnostic signal, not a capability rate. Real
browser runtime and real app runtime remain unmeasured, and the full corpus
remains `NOT READY`.

## 10.9. Stable provider Model-B selection and closed-loop disambiguation gate

On 2026-09-12 the final Model-B selection gate ran on branch
`codex/m8-coding-evaluation` at exact HEAD
`3c1095ff69b1a5d800d96eb61e8b88a47fceca14`. The dirty working tree was
preserved. A deterministic working-tree identity computed over the sorted
`git ls-files -co --exclude-standard` path/content set was
`3c93f6bd6a470d459b51525bbdec375ca4e833b09e14dcbffb20595f3b1cc32e`.
The protected untracked file `docs/local-security-closure-report.md` remained
unchanged and unstaged with SHA-256
`85dbfe1ee17475154a0f48a6d308750b252aec75f3b67dd4f2e47f06b25597a1` and
851 bytes.

The configured candidates were NVIDIA
`deepseek-ai/deepseek-v4-flash-0731`, Zhipu Coding Plan `glm-5.3-flash`, and
SiliconFlow `Qwen/Qwen3.5-27B`. GLM remains the Model-A baseline and was not
used as Model-B. SiliconFlow remains excluded from this gate because its
immutable prior Coding revalidation was provider-invalidated by sustained
HTTP 429 responses. NVIDIA passed P0 text, P1 minimal tool, P2 production
read-only tool schema, and P3 real AgentLoop `read_file` probes. Its first P4
replacement-eligible session timed out at the provider boundary before a
meaningful session; the one permitted fresh replacement reached four HTTP 200
requests and 16 read-only tool calls, then timed out on its fifth request.
There were no 429s or 5xx responses, but the repeated transport timeout means
NVIDIA did not qualify as a stable Model-B. No other eligible configured
candidate remained.

Therefore the Stable Model-B Selection Gate is `FAIL`, and the run stopped
before `bugfix-python-cache` Coding. No Coding JSONL record, GLM same-state
control, secondary task, browser task, or full corpus was launched. Provider
usage and provider-returned model identity remain explicitly unavailable from
the adapter. The stdin-only P3 wrapper failure was isolated as a probe
launcher issue with zero provider requests and was not classified as a
provider, model, or Harness failure.

The post-gate evaluation integrity tests passed (`27 passed`, one existing
Hypothesis collection warning). No Harness or provider source fix was needed,
and no new BLOCKER/HIGH Harness defect was found. The secret scan found zero
matches for current configured credentials and zero Authorization-bearing
leaks; four bounded API/bearer-shaped matches were existing noncredential
historical examples in scanned documentation. Real AgentLoop and tool use
remain `PROVEN`, M8.3 verification/repair/CompletionGate remain `NOT PROVEN`,
real coding capability remains `EARLY SIGNAL ONLY`, full corpus readiness is
`NOT READY`, and production readiness remains `NOT READY`.

Two general defects found during the gate were fixed with deterministic
regressions: new state-root databases are now created as owner-only `0600`
files, and provider HTTP failures are typed as model/provider availability
failures instead of generic internal errors. No secret was found in the
generated artifacts or durable evaluation database.

## 10.1. GLM-5.3 Harness defect repair attempts

The first five records are preserved unchanged. A deterministic scheduler
regression then reproduced a general budget defect: pessimistic parallel
output reservations rejected later small reads even when the earlier calls
would release capacity. The scheduler now defers such calls to the serial
phase; the scheduler/security/evaluation regression set passed with `242
passed` in the final run.

The five canonical tasks were rerun with the same budgets at
`/tmp/khaos-m8-glm53-sanity.jQ5ITb/results-after-tool-budget-fix.jsonl`.
All remained bounded `TIMEOUT`, but the false reservation failures no longer
occurred. A second general capability-mapping defect was fixed after Task 5:
Coding Repo Intelligence and M8.8 browser tools were declared by the
registry but absent from the workspace-write sandbox capability set. The
affected Task 5 rerun is preserved at
`/tmp/khaos-m8-glm53-sanity.jQ5ITb/results-task5-after-sandbox-capability-fix.jsonl`.
It still timed out without a browser call; the remaining failures were model
tool-use limits (including invalid `read_file` offsets), not a browser-tool
admission denial.

These fixes close the observed generalizable Harness defects for this gate,
but do not establish coding or real-browser capability. The full corpus was
not started.

## 10.2. GLM-5.3-Flash real-agent tool-use convergence gate

On 2026-09-11, the controlled convergence follow-up continued to use the
production `zhipu-coding` provider, model `glm-5.3-flash`, and the real
AgentLoop/tool path. It did not start the full corpus or M8.9. The unchanged
per-attempt limits were 128 model turns, 512 tool calls, 120 seconds, no
external network, and fixture-only browser policy.

The four additional typed records are preserved separately at
`/tmp/khaos-m8-glm53-convergence.sIi4Y1/`:

| Record | Result | Forensic primary classification | Evidence |
| --- | --- | --- | --- |
| `task1-attempt1.jsonl` (`m8-ec5bf3af4ef449dba79b60bc0fd78c96`) | `TIMEOUT` | `HARNESS_DEFECT` | The pre-repair file/verification contracts exposed pagination, parent-directory, and process-handler injection mismatches. |
| `task1-attempt2.jsonl` (`m8-0c655ba9000e4ac29b24d07e75b0ee70`) | `TIMEOUT` | `HARNESS_DEFECT` | `test_run` still rejected Broker-injected `principal_id`; the stale approval rejection was fail-closed and was not a Harness failure. |
| `task1-attempt3.jsonl` (`m8-74be3967765b48e897efcb5da10053db`) | `TIMEOUT` | `MODEL_LIMITATION` | The model independently localized and applied the correct cache fix through `patch`, but did not reach testing or CompletionGate before the 120-second limit. |
| `secondary-feature-python-index.jsonl` (`m8-c4ddab1802ee4eafadcf9e88bf7d985f`) | `TIMEOUT` | `PROVIDER_DEFECT` | The provider returned an empty model response, retried once, and produced no model turn or tool call; this was not counted as a coding failure. |

The per-record metrics were, respectively, 5 turns/10 tools/1 edit/1 test
attempt, 5/9/3 edit attempts/1 test attempt, 3/6/1 successful patch/0 tests,
and 0/0/0/0. All four records have `input_tokens`, `output_tokens`, and
`total_tokens` as `null` because the current streaming adapter does not
report provider usage. No record reached an accepted CompletionGate result;
all browser counters were zero. The JSONL validator accepted all four
records, including result, scenario, manifest, policy, config, and trace
digests. Root-cause buckets above are forensic analysis kept separate from
the runner's `root_cause=null` field; the original records were not changed.

The convergence work fixed four generalizable production-path contracts:
positive one-based `read_file` pagination, transactional `write_file` parent
directory creation with rollback cleanup, the common Broker-injected process
metadata contract for `test_run`, and the corresponding contract for
`sandbox_exec`. The affected deterministic regression set passed with
`140 passed, 6 skipped`; evaluation contract tests passed with `32 passed`.
Source Ruff, compilation, and `git diff --check` passed. A full Python run
was intentionally stopped after `2345 passed, 22 skipped, 1 warning` at
42% collection progress; it is incomplete evidence, not a full-suite pass.
The existing five Pyright errors in unrelated `file_tools.py` type inference
remain a baseline boundary.

The provider smoke remains `PASS`, credential and secret-leak checks remain
`PASS`, and provider error mapping remains typed and covered. The real model
was used, but no real browser runtime or real app process was exercised in
this convergence follow-up. The conservative status is therefore
provider integration `PASS`, real-agent convergence `PARTIAL`, real coding
capability `UNMEASURED`/early signal only, real-browser capability
`UNMEASURED`, and full-corpus readiness `NOT READY`.

## 10.3. GLM-5.3-Flash completion convergence probe

The 2026-09-11 probe changed one bounded runtime variable for the primary
`bugfix-python-cache` scenario: the total task timeout was increased from 120
seconds to 240 seconds. Provider/model, prompt, task seed, tool schemas,
tool/policy budgets, network/browser policy, fixture/base revision, scenario
and hidden-oracle inputs were held constant at runtime. The comparison is not
a pristine same-source-SHA experiment: generic evaluation-only timeout
override plumbing was added first, then two observed generalizable Harness
defects were fixed between the preserved attempts. The scenario digest and
manifest digest remained unchanged across all records.

The original 120-second attempt and each 240-second attempt are preserved as
separate typed artifacts:

| Attempt | Result and metrics | Forensic classification | Evidence |
| --- | --- | --- | --- |
| 120-second baseline, `m8-74be3967765b48e897efcb5da10053db` | `TIMEOUT`; 3 model turns, 6 tools, 1 successful patch, 0 tests, 0 verification calls, 120163 ms | `MODEL_TOOL_USE_LIMIT` | Correctly localized and edited the cache bug, but did not reach verification. |
| 240-second pre-fix, `m8-5a4b2c37d69b40ca906b68e506f18fd7` | `TIMEOUT`; 9 turns, 16 tools, 5 edit attempts, 0 tests, 0 verification calls, 240161 ms | `HARNESS_DEFECT` + `MODEL_TOOL_USE_LIMIT` | Two schema-valid `file_search_content` calls failed because the handler still required omitted `path`; the model then repeated edits and reads. |
| 240-second after file-search fix, `m8-4fe1ed7b801744ec98b181f91d350ea6` | `TIMEOUT`; 8 turns, 10 tools, 3 edit attempts, 2 test calls, 2 failed test runs, 2 verification commands, 240160 ms | `HARNESS_DEFECT` + `MODEL_TOOL_USE_LIMIT` | `test_run(cwd=".")` was rejected as outside the task workspace because its injected workspace manager was ignored by the handler. |
| 240-second after cwd fix, `m8-467749cd35834df4b3b5874e9095b685` | `TIMEOUT`; 11 turns, 20 tools, 6 edit attempts, 2 blocked terminal calls, 0 tests, 0 verification calls, 240159 ms | `MODEL_TOOL_USE_LIMIT` + `ENVIRONMENT_DEFECT` | The model chose `terminal_argv(python3 -c ...)`, which the existing security policy blocked; `git_diff` also encountered missing macOS developer tooling. |

The 240-second records are at
`/tmp/khaos-m8-glm53-240.xDkMPy/task1-timeout-240.jsonl`,
`/tmp/khaos-m8-glm53-240-post-search.mG9sEA/task1-timeout-240-post-search.jsonl`,
and
`/tmp/khaos-m8-glm53-240-post-cwd.1aWPDr/task1-timeout-240-post-cwd.jsonl`.
All four records validate against `CodingBenchmarkResultV1`, have unique run
IDs, and retain the same scenario/manifest/policy/base identity. Provider
input/output/total token usage remains `UNKNOWN / PROVIDER_NOT_REPORTED`; the
adapter does not expose it. Exact per-request latency is also unavailable,
although the durable trace shows roughly 228 seconds in inter-turn/model
response gaps in the pre-fix 240-second attempt; this is not attributed to a
provider defect without request-level evidence.

Two generalizable fixes were applied and regression-tested. The file-content
search handler now honors the registry's optional `path` default and rejects a
missing pattern explicitly. Process-backed test execution now resolves a
relative cwd against the active TaskWorkspace through the existing shared
workspace resolver. The combined affected regression set passed with `125
passed, 1 warning`; source Ruff, compilation, and `git diff --check` passed.
No benchmark-specific hint, expected filename, oracle, or security relaxation
was added.

Targeted Pyright is clean for `test_tools.py`, `terminal_tools.py`,
`runner.py`, and `eval_commands.py`. The touched `file_tools.py` retains five
pre-existing type-inference errors outside the changed search handler, and
`main.py` retains its existing unrelated diagnostics; full-project Pyright is
not a clean gate in this working tree.

The real production AgentLoop and tool-authority path was exercised for the
primary task, including repository inspection and bounded workspace edits. A
complete green verification/repair/CompletionGate loop was not proven:
`repair_cycles=0`, CompletionGate remained `null`, no accepted completion was
observed, and no false-completion attempt occurred. No secondary task was run
because the primary did not reach a successful verification/repair path.

The typed artifact scan of the four JSONL records and state database found no
credential match or scanner hit. Separately, one local diagnostic search in
this session accidentally printed host configuration credential lines. No key
was written to the repository, JSONL, or state database, but the session-level
secret check must therefore remain `FAIL` until the exposure is handled; this
is distinct from the artifact scan result. Full-corpus readiness remains
`NOT READY`, strict real-browser capability remains `UNMEASURED`, and the
conservative capability status is `EARLY SIGNAL ONLY`.

## 10.4. GLM-5.3-Flash model capability disambiguation gate

The 2026-09-11 A/B gate used the real Khaos AgentLoop and coding evaluation
path on HEAD `3c1095ff69b1a5d800d96eb61e8b88a47fceca14`. Both models used the
same `bugfix-python-cache` scenario, manifest, policy, fixture, prompt, and
bounded runtime policy (`240s`, `128` model turns, `512` tool calls, network
disabled, browser not used). The scenario, manifest, policy, and fixture
digests were respectively
`3dd8cfa381f133df97f71b4781da716e3deea14e57916ae1b4bc7c0f1758eccb`,
`afeaf160e11a25d18472e43f75538d41be18d44ccd0fc2a684ea7b941006f756`,
`cf1bc0a3a97c13e0c9e00a7954a5c168a999671ffaa83a3a58ab33d17e758f93`, and
`e3bf978072defd1a0f7f755d0e26cb777d9b2e4337c0bbd02c542c0d53727da5`.

Model A was `zhipu-coding / glm-5.3-flash`; Model B was
`nvidia / deepseek-ai/deepseek-v4-flash-0731`.

- Model B provider smoke passed with a real response. The provider did not
  expose exact usage or a returned model identifier, so those fields remain
  `UNKNOWN / PROVIDER_NOT_REPORTED` and `null`; no zero was fabricated.
- A separate read-only real-AgentLoop probe passed: the real model completed
  one authorized `read_file` call with no edits or command execution.
- Model B's first primary record (`m8-8e1758b187d04ad5a5ab35c014e17d6f`)
  stopped after a redacted `ReadTimeout` at about 121 seconds, with zero model
  turns and zero tool calls. Its original JSONL result is preserved. The
  runner initially classified this provider timeout as a tool failure; the
  general timeout classification was repaired and regression-tested. The
  preserved B attempt 2 (`m8-11b6a67ab57f4a09aa99aa3a9864d653`) has the same
  provider-side outcome and is correctly classified as `PROVIDER_FAILURE`.
- Model A's primary record (`m8-b1596870729b44c7988677d30e168351`) timed out
  at 240 seconds after 7 model turns and 14 tool calls. It made one applied
  edit, attempted one test, and did not reach a green verification or
  CompletionGate acceptance. This is an early model/tool-use convergence
  signal, not evidence of a Harness defect.
- The three current JSONL records round-trip with valid result digests and
  hidden-oracle isolation. The current run artifact/state scan found no
  credential match; the earlier historical diagnostic exposure remains
  documented above and the operator has attested that the old key was rotated.

No secondary feature task or browser task was started after the primary gate
failed to establish a stable coding loop. The disambiguation result is
`INCONCLUSIVE`: provider integration is `PASS`, real coding capability is only
`EARLY SIGNAL ONLY` / otherwise `UNMEASURED`, and the full corpus remains
`NOT READY`. No competitive claim is made.

## 10.5. SiliconFlow Qwen3.8-27B controlled model disambiguation gate

On 2026-09-11 the gate resolved the current user configuration through Khaos:
provider `siliconflow`, configured model `Qwen/Qwen3.8-27B`, using the
configured SiliconFlow OpenAI-compatible endpoint. The exact code state was
HEAD `3c1095ff69b1a5d800d96eb61e8b88a47fceca14` on
`codex/m8-coding-evaluation` with a pre-existing dirty working tree. The
historical GLM records above were not treated as same-state controls because
the working tree contains later local provider/evaluation changes. A fresh GLM
control was intentionally not run after the Qwen pre-Coding gate failed.

The Qwen Provider Smoke passed through the production-shaped
`ModelRouter -> ModelClient -> openai_compatible` path: the exact short
acknowledgement was returned with `end_turn` in 1,489 ms. Provider-returned
model identity, request/retry counters, and token usage were not exposed by the
adapter and remain `UNKNOWN`/`null`; no zero values were fabricated.

The required real-AgentLoop read-only microprobe then failed after planning was
published and before any tool call or tool result. The durable evidence is a
typed provider failure with HTTP status 400 surfaced as `MODEL_UNAVAILABLE`;
there were zero tool operations and zero successful read-only results. The
redacted provider response was retained only as bounded metadata/hash and is
not reproduced here. This is provider/endpoint tool-capability rejection
evidence, not `MODEL_TOOL_USE_LIMIT` evidence, and no Coding benchmark task was
started.

The current persistent artifact/state scan passed: no current SiliconFlow key
or API-key-shaped secret was found and no secret was printed. The historical
credential incident remains separately recorded as closed/rotated. No Khaos
Harness code was changed during this gate, so no new Harness fix or regression
rerun was justified. No new Coding JSONL record was created after the
pre-Coding stop; existing records remain preserved.

The controlled A/B experiment is `INVALID`: a same-state fresh GLM control was
not established, and Provider B could not produce valid tool-use evidence.
Same-scenario coding, oracle, verification, repair, CompletionGate, and browser
comparisons were therefore not run. The conservative verdict is provider
integration smoke `PASS`, Qwen tool microprobe `FAIL`, real coding capability
`UNMEASURED`, Khaos closed-loop proof `NOT PROVEN`, full corpus `NOT READY`,
and production readiness `NOT READY`.

## 10.6. SiliconFlow Qwen3.5-27B tool-calling and closed-loop validation gate

On 2026-09-11 the effective Khaos configuration resolved to provider
`siliconflow` and model `Qwen/Qwen3.5-27B` through the normal project-plus-user
configuration path. The exact code state was HEAD
`3c1095ff69b1a5d800d96eb61e8b88a47fceca14` on
`codex/m8-coding-evaluation` with a pre-existing dirty working tree. Public
provider config digest was `904f3b1e4fbb3a4db6ca413cea83f37189ded1eb3e79f4b9365fbbb2384c4ea4`.
Reasoning and sampling were not configured; the resolved model metadata exposed
128,000 context tokens and 4,096 maximum output tokens.

Credential authority passed. The pre- and post-run scans resolved the current
credential only in memory and found no exact key or API-key-shaped secret in
the scanned artifacts; no secret was printed. The historical Zhipu incident
remains preserved as historical evidence.

The text Smoke passed through `ModelRouter -> ModelClient ->
openai_compatible`: exact ACK, `end_turn`, three response chunks, 5 response
bytes, and 5,397 ms latency. Provider-returned model identity, request/retry
counters, and token usage were not exposed and remain `UNKNOWN`/`null`.

The minimal one-tool compatibility probe also passed through the same Khaos
Router/ModelClient path. A synthetic, read-only, non-production `probe_echo`
function was accepted over streaming HTTP 200, and exactly one normalized call
returned with valid `value=HELLO_TOOL` arguments. The probe did not execute the
function or enter the Coding surface. Tool compatibility for this minimal
provider request is therefore `PROVIDER_CAPABILITY_OK`.

The real AgentLoop read-only microprobe then failed after planning started and
the planning revision was published, but before any production tool call or
tool result. The durable state has one failed turn, zero `tool_operations`, and
an audit action of `error:MODEL_UNAVAILABLE`; redaction-safe metadata records
HTTP 400. This is classified as `PROVIDER_DEFECT` with secondary
`PROVIDER_ENDPOINT_TOOL_CAPABILITY_MISMATCH` / adapter compatibility candidate,
not as a model tool-use limitation. No Coding task was started.

The gate therefore proves minimal Khaos tool-call normalization but does not
prove production AgentLoop tool compatibility or any coding loop. No Harness
code was changed, no Qwen Coding JSONL record was created, and no GLM control,
secondary task, browser task, or full corpus was run. The Qwen3.5 closed-loop
result is `NOT PROVEN`, real coding capability remains `UNMEASURED`, the model
disambiguation comparison is `INCONCLUSIVE`, full corpus readiness is `NOT
READY`, and production readiness is `NOT READY`.

## 10.7. SiliconFlow Qwen3.5-27B production tool-surface compatibility bisect

This compatibility-only follow-up preserved the preceding Qwen3.5 HTTP 400
evidence and isolated the smallest failing request dimension before changing
source. The exact repository HEAD remained
`3c1095ff69b1a5d800d96eb61e8b88a47fceca14` on
`codex/m8-coding-evaluation`; the working tree was already dirty and all
unrelated changes were preserved. No Coding benchmark task or Coding JSONL
record was created.

The passing baseline had one `user` message, one synthetic read-only tool
(`303` serialized tool bytes; largest schema `155` bytes), `stream=true`, and
only `max_tokens=4096` among optional request fields. The preserved failing
production baseline had 20 messages containing three `system` messages and 12
production tools (`5,045` serialized tool bytes; largest schema `392` bytes),
with the same stream and request-option shape; the provider returned HTTP 400
before any tool operation. Raw request bodies were not persisted.

The live bisection accepted the full production tool catalog with minimal
messages at tool prefixes 1, 4, 8, and 12. Each individual production schema
was therefore not a failing discriminator, and the result is not a tool-count
or schema incompatibility. Each individual system message was accepted, but
every tested pair of system messages returned HTTP 400. One merged system
message plus the same user content was accepted. No `developer` role was
present; stream, tool-choice, parallel-tool, response-format, and reasoning
options were unchanged/absent. The exact root cause is:

`PROVIDER_ENDPOINT_LIMITATION`: the SiliconFlow Qwen3.5 endpoint rejects
requests containing two or more `system` messages.

The general fix is provider-boundary serialization. `ProviderConfig` now
resolves a provider capability profile, SiliconFlow is marked as not
supporting multiple system messages, and `ModelClient` deterministically
coalesces system contents while preserving all non-system message order. A
system message carrying tool calls is rejected rather than silently dropped.
The same provider boundary now also reports only HTTP status for streamed
provider errors; raw provider response bodies are not placed in exception or
audit text. Deterministic regression coverage and the affected routing,
context, error, and benchmark-contract set passed (`86 passed, 1 warning`),
with Ruff, Pyright, compileall, and `git diff --check` passing.

The final live compatibility sequence passed P0 text smoke, P1 minimal tool
calling, and P2 full production tool-surface acceptance. A post-fix AgentLoop
probe completed one real `read_file` call through the normal authority path,
received the result, continued, and reached `COMPLETED`; this proves the
production tool-calling path. One later same-task probe completed without a
tool call despite HTTP 200 and is retained as a model/tool-choice limitation,
not retried until green, and not classified as a Harness or provider defect.
Credential scans found no exact key, shaped key, or raw provider-error marker;
no secret was printed. Provider usage and returned model identity remain
`UNKNOWN`/`null` because the adapter does not expose them. The compatibility
gate is `PASS`, real AgentLoop tool-calling is `PROVEN`, readiness for the
separate closed-loop Coding validation is `YES`, full corpus readiness remains
`NOT READY`, real coding capability remains `EARLY SIGNAL ONLY`, and
production readiness remains `NOT READY`.

## 10.8. SiliconFlow rate-limit attribution and stable closed-loop revalidation

On 2026-09-11 the configured provider/model remained
`siliconflow / Qwen/Qwen3.5-27B` at exact HEAD
`3c1095ff69b1a5d800d96eb61e8b88a47fceca14` on
`codex/m8-coding-evaluation`. The existing dirty working tree was preserved;
`docs/local-security-closure-report.md` remained untracked, unchanged,
unstaged, and its content hash remained
`85dbfe1ee17475154a0f48a6d308750b252aec75f3b67dd4f2e47f06b25597a1`.

The prior real Qwen3.5 Coding run
`m8-dc24a2fb64714e5abcfb160dae91d585` remains immutable. Its HTTP 429
provider failure is not reinterpreted as a model or Harness failure. The
provider boundary now exposes only bounded, redaction-safe per-attempt
metadata: status, latency, first-byte latency, request id, an allowlisted set
of rate-limit headers, typed error metadata, and bounded retry delay. It does
not read or persist an unbounded provider error body. Retries remain bounded
to three attempts, use `Retry-After` when safely parseable, otherwise use
bounded exponential delays of 100ms and 200ms, and preserve cancellation.

The post-change low-concurrency capacity sequence passed: P0 text smoke, P1
minimal tool calling, and two sequential P2 requests all returned HTTP 200.
The real AgentLoop read-only microprobe then executed one successful
`read_file` call and reached `COMPLETED`, proving the Khaos production-shaped
AgentLoop/tool path. Provider usage and provider-returned model identity were
not reported by the adapter and remain `UNKNOWN`/`null`.

One fresh, bounded `bugfix-python-cache` Coding attempt was then run with
240-second timeout, 128 model turns, 512 tool calls, no external network,
fixture-only browser policy, and the normal
`CodingEvaluationRunner -> RuntimeCodingAgentInvoker -> build_runtime ->
AgentLoop` path. It reached 21 model turns and 21 tool calls, including 8
reads, 4 patches, and 3 test runs; all three tests failed before a completion
proposal. The first 21 provider attempts returned HTTP 200. The final logical
request received HTTP 429 on all three bounded attempts, with no
`Retry-After`, rate-limit window headers, or request id. The typed terminal
error was `PROVIDER_FAILURE` / `MODEL_ERROR`; the safe attribution is
`RATE_LIMIT_CONFIRMED_SUBTYPE_UNKNOWN`. This is provider-side capacity/rate
limit evidence, not evidence of a model reasoning failure or a Khaos Harness
defect. No second Coding rerun was made.

The immutable result is stored at
`/private/tmp/khaos-m8-qwen35-rate-limit-revalidation-20260911-1/bugfix-python-cache.jsonl`;
its schema and digest validate, its bounded state trace has 86 events, and
hidden-oracle isolation passed. No CompletionGate decision was reached, so
closed-loop Coding capability remains `NOT PROVEN`; full real coding
capability remains `UNMEASURED` (the trajectory is only an early,
provider-invalidated signal). Browser capability and full-corpus readiness
remain `UNMEASURED` and `NOT READY`, respectively. Production readiness
remains `NOT READY`.

## 10.9. macOS Keychain credential-isolation closure gate

The 2026-09-12 closure gate used exact HEAD
`3c1095ff69b1a5d800d96eb61e8b88a47fceca14` on
`codex/m8-coding-evaluation` with the dirty working tree preserved. No real
provider call, real credential read, Coding task, browser run, full corpus, or
M9 work was started. The historical exposed credential remains treated as
compromised and requires operator rotation; no credential value was read or
repeated.

The native macOS Security.framework diagnostic returned bounded status
`-25308`, category `INTERACTION_REQUIRED`, with Khaos interaction policy
disabled. The default/login Keychain therefore requires interaction in this
session. This is `OS_POLICY_BLOCKED / ENVIRONMENT_BLOCKED`, not a provider or
synthetic-HOME defect. Khaos preserved fail-closed behavior and did not enable
dialogs or add a plaintext fallback. The generic native error observability
gap was fixed with typed, redaction-safe diagnostics.

Synthetic credential round-trip and output-firewall coverage passed. The
firewall covered AgentLoop, tool results, provider errors, audit, memory,
supervision/checkpoints/subagents, MCP/hooks/skills events, browser/app
diagnostics, and benchmark JSONL. Targeted Ruff, Pyright, compileall, and
`git diff --check` passed. The native integrated sequence was attempted once,
stopped at `put`, and was not retried. Credential isolation is closed for the
synthetic path, but real-provider integration and real coding capability remain
`UNMEASURED`; full corpus and production readiness remain `NOT READY`.

## 10.10. macOS credential provisioning/runtime separation gate

The 2026-09-12 follow-up implemented the explicit operator provisioning versus
non-interactive runtime split. `khaos credentials set|replace|delete` is an
operator-only path using hidden input; `khaos credentials status` and all
AgentLoop/provider transport reads use runtime mode and explicitly forbid
Keychain UI. Provider model discovery is the only explicit provisioning
transport path and is limited to `provider.discovery`; builtin tools cannot
invoke it.

Deterministic tests cover process-global interaction-policy restoration,
typed `-25308` interaction failures, typed provisioning cancellation, missing
versus interaction-required status, cross-provider binding, atomic replacement
rollback, hidden CLI input, discovery mode, output isolation, and absence of
provisioning tools. The final isolated target run passed **104 tests** with
one existing skip. Ruff, targeted compileall, and `git diff --check` passed.

No real provider request, real credential read, real model, browser, Coding
task, or M9 work was started. The native Keychain evidence remains
`-25308 / errSecInteractionNotAllowed` in the current session and is classified
`OS_POLICY_BLOCKED / ENVIRONMENT_BLOCKED`; no UI automation or plaintext
fallback was used. The native backend remains legacy `SecKeychain*` with DPK
disabled, and the DPK decision is
`PACKAGING_PREREQUISITE_BLOCKS_SWITCH` pending a stable signed runtime identity
and entitlements. Full real capability remains `UNMEASURED`, full corpus
readiness remains `NOT READY`, and production readiness remains `NOT READY`.
The previous credential exposure remains an operator rotation action.

## Local-first CredentialSession update (2026-09-12)

The canonical local credential path is now explicit session unlock under the
existing `CredentialBroker`: persistent Keychain storage is read once during a
human-initiated unlock, runtime requests use the Broker's bounded in-memory
lease, and locked/replaced/deleted/restarted sessions fail closed without a
runtime Keychain read or UI prompt. Deterministic synthetic coverage passed
for the lifecycle and three fake provider requests; no real Provider request
or real credential read occurred.

This is a security/lifecycle update, not new coding-capability evidence.
Real-provider capability remains `UNMEASURED`, full corpus readiness remains
`NOT READY`, and DPK/signed macOS packaging remain optional future hardening.

## 10.11. Manual native synthetic Keychain acceptance

One fresh synthetic native macOS Keychain lifecycle passed on exact HEAD
`3c1095ff69b1a5d800d96eb61e8b88a47fceca14`. SET, safe locked STATUS,
pre-unlock `CREDENTIAL_SESSION_LOCKED`, explicit unlock, three fake Provider
requests, lock/re-unlock, replace, shutdown/restart, replacement unlock, and
delete all passed. Runtime persistent-store reads and Keychain UI were `0`
after unlock; post-delete runtime returned the distinct
`CREDENTIAL_MISSING`; synthetic leftovers were `0`.

This is credential persistence/lifecycle evidence only. It does not add real
model or coding capability evidence. Real Provider calls and real credential
reads remained `0`; GLM-5.3, GLM-5.3-Flash, full corpus, browser benchmark, and
M9 were not run. Real credential rotation remains `OPERATOR ACTION REQUIRED`.

## P4-v2 offline Harness repair gate (2026-09-12)

This addendum supersedes no historical provider result. It records an offline
working-tree repair only: real Provider calls and real credential reads were
both `0`; no credential session was unlocked; GLM-5.3, GLM-5.3-Flash, the
Coding corpus, browser benchmark, and M9 were not run.

P4-v1 remains `FAIL` with mechanical cause `TOOL_BUDGET_EXHAUSTED`, Harness
integrity `FAIL`, and convergence attribution `INVALID / INCONCLUSIVE`.
P4-v2 is a version-2 read-only synthetic authority fixture with a natural
stopping instruction and no visible minimum turn/tool target. The repaired
runtime owns tool-budget exhaustion as typed `TOOL_BUDGET_EXHAUSTED`; the
collector is observational and marks storage truncation instead of raising
into AgentLoop. Trace v2, exact tool/category accounting, pending-result
states, redaction-safe digests, event/summary reconciliation, typed
qualification JSONL, and dirty working-tree identity are covered by
deterministic regressions.

Fake efficient and normal P4-v2 AgentLoop paths passed, early completion was
accepted, wrong-answer and tool-error paths were typed, over-exploration
terminated with `TOOL_BUDGET_EXHAUSTED`, and the hidden oracle stayed outside
the agent root. This is Harness evidence only. Fresh real qualification must
restart at P0 and the full real-provider corpus remains `NOT READY`.

See the [P4-v2 repair closure report](m8-p4-qualification-harness-repair-v2-closure.md)
for the defect table and exact local verification boundary.

## Router import-cycle closure (2026-09-12)

An offline dependency-direction gate repaired the production Router cold-import
cycle by moving `CanonicalWorkspaceId` to the neutral security identity
contract and keeping the planning import as a compatibility re-export. The
fresh-process import matrix, Router construction, and qualification bootstrap
now pass. No real Provider request, credential-material read, credential
unlock, GLM qualification, browser benchmark, or M9 run occurred.

This adds Harness readiness evidence only. Real Provider/coding capability is
still `UNMEASURED`, the full corpus is `NOT READY`, and production readiness is
`NOT READY`. Details are in the [Router import-cycle closure report](m8-router-import-cycle-closure.md).

## Qualification observability closure (2026-09-13)

An offline-only gate closed the passive qualification observability gaps:
typed CompletionGate outcomes, final-response/parser shape metadata, actual
Repo Intelligence/Context Engine selection metadata, and timestamp provenance
are now recorded in versioned, secret-free traces and qualification records.
Deterministic observability, parser, context, JSONL compatibility, redaction,
and gate-matrix tests passed. No Provider or credential operation occurred.
This is additional Harness evidence only; the historical P4-v2 result remains
`FAIL` with an `INCONCLUSIVE` root cause, real coding remains `UNMEASURED`, and
full-corpus/production readiness remain `NOT READY`. See the
[observability closure report](m8-qualification-observability-closure-2026-09-13.md).

## Fresh GLM-5.3-Flash real-provider corpus gate (2026-09-14)

The `zhipu-coding` / `glm-5.3-flash` path was exercised through the production
Coding AgentLoop, Repo Intelligence, Context Engine, ToolAdmission,
EditTransaction, ExecutionService, verification, repair, CompletionGate, and
BrowserCodingService path. The fresh sequential corpus was recorded at
`/private/tmp/khaos-glm53-full-corpus-final3-20260914/benchmark.jsonl` with
17 immutable SQLite-backed runs. It produced 4 `SUCCESS`, 9 `FAILURE`, and 4
`TIMEOUT` results. All 157 provider requests returned HTTP 200 with no typed
provider error; usage remained `UNKNOWN / PROVIDER_NOT_REPORTED`. No security
violation, quarantine, or trace truncation was recorded.

The real browser dimension was exercised: real model `YES`, real browser
runtime `YES`, and task-local app process `YES`. Browser app/session lifecycle
events were recorded and browser policy remained `fixture-only` with network
policy `none`. The failures were dominated by model convergence, verification,
edit-scope, and bounded-resource outcomes; they are not reclassified as
provider failures. P4 review misses remain review/model evidence, not Coding
completion evidence.

During closure, generalizable Harness fixes were regression-tested for parent
directory EditTransactions, transcript context ordering, Python test cache
hygiene, environment-prefixed test commands, macOS Seatbelt local-listener
syntax, Trusted Git selection, Coding browser injection, and equivalent hidden
oracle semantics. The final offline Coding/tool/evaluation regression set then
passed `2825` tests with `8` expected skips. A justified single-task
observability rerun additionally confirmed that the effective GLM output
ceiling is recorded as `32768` without exposing credential material.

Conservative status after this corpus gate:

```text
Provider Integration: PASS
Real Provider Sanity: PASS / PARTIAL
Full Real Coding Capability: EARLY SIGNAL ONLY
Full Corpus Readiness: NOT READY
Production Readiness: NOT READY
```

The corpus is evidence for diagnosis, not a competitive claim. No commit,
push, merge, PR update, or M9 work was performed.

## Fresh final4 real-provider rerun and offline closure (2026-09-14)

After the browser tool-surface/prompt and working-tree provenance changes, a
fresh sequential rerun was preserved at
`/private/tmp/khaos-glm53-full4-20260914/benchmark.jsonl`. It recorded all 17
scenario records with the same `zhipu-coding` / `glm-5.3-flash` identity and
working-tree identity. The result was 5 `SUCCESS`, 6 `FAILURE`, and 6
`TIMEOUT`, across 174 observed requests, 172 model turns, 224 tool calls, and
34 browser calls. Provider observations were available for every record;
173 requests returned HTTP 200 and one cancellation had no HTTP response.
Usage remained `PROVIDER_NOT_REPORTED`. There were zero security violations,
zero trace truncations, and zero dropped trace events.

The successful trajectories independently exercised Python, Go,
cross-language, frontend/browser, and full-stack/browser work through the
production-shaped AgentLoop. The remaining failures are attributed to model
convergence/tool-use limits, bounded wall-time under high provider latency,
strict review-output contract misses, or oracle-enforced edit-scope misses;
the traces show no missing production tool, admission bypass, stale browser
evidence, provider HTTP error, or CompletionGate authority defect. The first
attempts and the justified affected-task reruns remain separate artifacts.

One genuine offline compatibility regression was fixed: a cache-only
`TaskService` can now construct its manager cache without fabricating a
database-backed supervision service; production database composition remains
unchanged and fail-closed. The generated reachability, security, and
privileged-spawn inventories were regenerated and checked. The full offline
suite then passed `5734` tests with `31` expected skips and one Hypothesis
warning.

Conservative status after final4:

```text
Provider Integration: PASS
Real Provider Sanity: PASS / PARTIAL
Full Real Coding Capability: EARLY SIGNAL ONLY
Full Corpus Readiness: NOT READY
Production Readiness: NOT READY
```

No commit, push, merge, PR update, or M9 work was performed.

## Fresh GLM-5.3-Flash corpus after structured-output guidance (2026-09-15)

The fresh sequential corpus is preserved at
`/private/tmp/khaos-glm53-full-final3-XwsE4S/benchmark.jsonl`. It contains all
17 manifest scenarios and ran through `zhipu-coding` / `glm-5.3-flash` using
the production-shaped Coding AgentLoop and tool path. It produced 14
`SUCCESS` and 3 `FAILURE` records. The aggregate recorded 153 Provider
requests, 153 model turns, 194 tool calls, 507 Repo Intelligence queries,
170 context selections, 45 edit attempts, 43 modified files, 13 verification
calls, 12 failed verification observations, 17 repair cycles, 0 subagents,
29 browser calls, 193 approval observations, and 0 human interventions.

All 153 Provider observations were HTTP 200 with typed error `NONE`; usage was
explicitly `PROVIDER_NOT_REPORTED`. All 17 CompletionGate observations were
`not_complete`, with zero accepted or falsely accepted completions. Trace
truncation, dropped events, security violations, and quarantines were zero.
The three browser scenarios again exercised the real model, task-local app
process, and Playwright/browser path under fixture-only/no-network policy.

The three failures are retained as model evidence, not Harness defects:
`p4-readonly-authority` missed one required semantic review concept,
`p4-readonly-authority-v3` returned valid JSON and the correct categories and
files but omitted required role concepts, and `refactor-typescript-client`
left an excessive diff containing temporary files. A targeted follow-up after
the generic cleanup guidance removed the temporary files and left only the two
requested files, but its hidden test still failed; it used 15 HTTP-200
Provider requests and ended with `TEST_FAILURE`. A second targeted P4-v3
follow-up remained schema-valid but semantically incomplete after the generic
short-concept guidance. No evaluator, oracle, permission, or editing
transaction workaround was added.

The five relevant artifacts are independently preserved and their JSONL
records have valid canonical digests, unique identities, hidden-oracle
separation, and zero secret-pattern hits. The deterministic evaluation suite
passes `227` tests; prompt/context regression tests pass `17` tests. The
conservative status remains:

```text
Provider Integration: PASS
Real Provider Corpus: PASS / PARTIAL
Full Real Coding Capability: NOT CONFIRMED (early signal only)
Full Corpus / Release Readiness: NOT READY
Production Readiness: NOT READY
```

No commit, push, merge, PR update, or M9 work was performed.

## Final5 real-provider validation after context admission repair (2026-09-14)

The production-shaped sequential run is preserved at
`/private/tmp/khaos-glm53-full5-20260914/benchmark.jsonl`. It contains all 17
scenario records for `zhipu-coding` / `glm-5.3-flash`: 7 `SUCCESS`, 7
`FAILURE`, and 3 `TIMEOUT`. The run observed 149 provider requests (148 HTTP
200 responses and one cancellation without an HTTP response), 147 model
turns, 200 tool calls, 40 edit attempts, 16 verification runs, 14 repair
cycles, and 32 browser calls. Provider usage was explicitly
`PROVIDER_NOT_REPORTED` for all records. No security violation, quarantine,
trace truncation, or dropped trace event was recorded, and there were no
human interventions.

One generalizable Harness defect found before this run was fixed: an oversized
L0 project instruction could evict the current GOAL, producing a provider
request with only system messages. Goal admission is now prioritized while
wire ordering remains layered, and a deterministic regression test covers the
case. Production CLI smoke and an affected real-provider rerun then passed.
The runtime factory principal-binding regression introduced during hardening
was also corrected and covered by targeted tests. The full offline suite after
these changes passed `5741` tests with `31` expected skips and one warning.

Failure evidence remains conservative and typed: one cross-language run was
rejected for excessive model-chosen diff scope; Rust, Go, and Python runs had
model-generated verification failures; three bounded tasks timed out; and
three read-only review tasks missed findings or the output contract. The
traces do not show a missing production tool, provider HTTP error, security
bypass, stale CompletionGate acceptance, or new generalizable Harness defect.

The JSONL records are canonical and digest-valid, context/provider
observability is present for all 17 records, hidden-oracle markers are absent,
and the secret-pattern audit found no hits. Real model, browser runtime, and
task-local app process were exercised under fixture-only/no-network policy.

Conservative status after final5:

```text
Provider Integration: PASS
Real Provider Sanity: PASS / PARTIAL
Full Real Coding Capability: NOT CONFIRMED (7/17 corpus scenarios passed)
Full Corpus / Release Readiness: NOT READY
Production Readiness: NOT READY
```

The GLM-5.3-Flash model's remaining failures are retained as model or
bounded-resource evidence; no benchmark-specific success shortcut was added.
No commit, push, merge, PR update, or M9 work was performed.

## Verification trace observability repair (2026-09-15)

The first real-provider rerun after the final5 baseline exposed one
generalizable observability defect: M8.3 autonomous verification messages were
persisted safely but were not forwarded to the passive Coding trace collector.
The fix persists the bounded observation first and then streams it; it does
not grant autonomous observations trusted completion authority. A deterministic
regression covers the persist-before-stream ordering, and the related agent,
runtime, and M8.3 tests pass (`66 passed`, one existing Hypothesis warning).

The affected real-provider run is preserved at
`/private/tmp/khaos-glm53-observability-reprobe-6Ubred/benchmark.jsonl`.
`bugfix-python-cache` remained `SUCCESS` with 10 provider requests, 10 model
turns, 10 tool calls, 2 verification plans, 2 verification checks, and 2
negative verification observations followed by bounded repair attempts. The
trace contains two typed `verification_result` events; CompletionGate still
returned `not_complete` as required by the fail-closed trusted-verification
boundary. Usage remains `PROVIDER_NOT_REPORTED`, with no security violation,
quarantine, trace truncation, or dropped event.

This repair improves evidence quality but does not change the conservative
capability verdict: full real Coding capability remains `NOT CONFIRMED`, full
corpus/release readiness remains `NOT READY`, and production readiness remains
`NOT READY`.

## Full real-provider corpus after applied-effect receipt repair (2026-09-15)

The fresh sequential corpus is preserved at
`/private/tmp/khaos-glm53-full-v2-final-20260915/benchmark.jsonl`. It contains
all 17 manifest scenarios using `zhipu-coding` / `glm-5.3-flash` through the
production-shaped AgentLoop and tool path. The result was 10 `SUCCESS` and 7
`FAILURE`; there were no timeouts. The run recorded 176 Provider requests,
all HTTP 200 with typed error `NONE`, 176 model turns, 240 tool calls, 49 edit
attempts, 15 verification calls, 17 repair cycles, and 36 browser calls.
Usage was explicitly `PROVIDER_NOT_REPORTED`; human interventions,
security violations, quarantines, trace truncations, and dropped trace events
were all zero.

The run confirmed the general applied-effect receipt repair: the versioned
`multifile-python-settings` scenario passed after a previous bounded result-
delivery failure had applied the edit but lost its verbose tool result. The
repair preserves a bounded typed receipt, avoids an unsafe blind retry, and
allows the AgentLoop to continue to verification. The three browser scenarios
also passed through `browser_app_open`, `browser_action`, and
`browser_observe` with the task-local Playwright/app path.

One benchmark-contract defect was found and isolated: v2 did not publicly
state that `RepositoryPort` belongs in `src/repository.py`, while its oracle
required that location. The scenario was versioned to v3 with that location
made public; the affected rerun is preserved at
`/private/tmp/khaos-glm53-v3-refactor-python-20260915.zxPHr1/benchmark.jsonl`
and passed with two changed files and three passing tests. The original v2
record remains unchanged.

The remaining six non-benchmark failures are retained as model limitations:
one excessive Go diff, one Rust verification failure, two read-only review
misses/output-contract failures, one TypeScript refactor verification failure,
and one cache-race review miss. All 17 CompletionGate attempts were reached
and returned fail-closed `not_complete`; no completion was accepted and no
false completion was recorded.

Canonical JSONL/digest validation, provider/context observability, hidden-oracle
separation, and secret-pattern checks all pass. The conservative status is:

```text
Provider Integration: PASS
Real Provider Sanity: PASS / PARTIAL
Full Real Coding Capability: NOT CONFIRMED (10/17; 11/17 including the corrected v3 rerun)
Full Corpus / Release Readiness: NOT READY
Production Readiness: NOT READY
```

No commit, push, merge, PR update, or M9 work was performed.

## Prompt/tool-surface alignment follow-ups (2026-09-15)

The Coding prompt was aligned with the actual model-visible tool surface. A
direct `delete_file` instruction was removed because the Context Engine
intentionally hides that legacy mutation tool; temporary cleanup is now
described through the canonical `apply_edit_transaction` `delete` operation
with its preview/apply CAS requirements. The structured-review guidance also
states that public semantic role words and source identifiers are separate
evidence items. The deterministic prompt regression passes `17` tests.

The P4-v3 follow-up at
`/private/tmp/khaos-glm53-p4v3-rolewords-6cAT21/benchmark.jsonl` remained
plain-JSON/schema/typed-parse valid but semantically incomplete after this
guidance; its single Provider request was HTTP 200 with error `NONE`. The
TypeScript follow-up at
`/private/tmp/khaos-glm53-refactor-ts-canonical-cleanup-20ZyEV/benchmark.jsonl`
ended at the fixed 600-second timeout after 12 HTTP-200 Provider requests,
with no final diff and no Provider error. These independent attempts reinforce
model convergence limitations and do not justify changing the Oracle,
CompletionGate, tool authority, or task budgets.

Full real Coding capability remains `NOT CONFIRMED`; no commit, push, merge,
PR update, or M9 work was performed.

## Effective 600-second full corpus after final prompt alignment (2026-09-15)

The valid run at
`/var/folders/l3/00y511gj4q55gj2z6zdqzrs00000gn/T/khaos-glm53-full-valid-current.IicrTEWg7f/benchmark.jsonl`
completed all 17 scenarios sequentially with the effective 600-second task
budget. It produced 8 `SUCCESS`, 6 `FAILURE`, and 3 `TIMEOUT` records. The
run used `zhipu-coding` / `glm-5.3-flash` through the production-shaped
AgentLoop path and recorded 181 Provider requests, 178 model turns, 238 tool
calls, 320 Repo Intelligence queries, 198 context selections, 57 edit
attempts, 52 modified-file observations, 18 verification calls, 13 repair
cycles, 0 subagents, 26 browser calls, 233 approval requests, and 0 human
interventions. Provider status was 180 HTTP 200 responses plus one bounded
`NO_HTTP_RESPONSE` cancellation caused by a task timeout; all 181 typed error
observations were `NONE`. Usage remained explicitly
`PROVIDER_NOT_REPORTED`.

The three timeouts were `browser-fullstack-bug`, `feature-python-index`, and
`multifile-python-settings`. The completed-task failures were the browser
feature's hidden command, P4-v2 semantic matching, P4-v3 non-canonical fenced
JSON, the cache-race review semantic finding, the TypeScript refactor hidden
command, and a Python refactor recovery path that failed closed when a second
pre-edit checkpoint was unavailable after a failed verification. These are
model convergence/recovery signals; the deterministic checkpoint and
execution regression set passed 83 tests, so no generalizable Harness defect
was identified.

The run retained 17 unique result identities with zero digest mismatches,
zero secret-pattern matches, zero hidden-oracle markers, zero trace drops or
truncation, zero security violations, and zero quarantines. CompletionGate
was reached for 13 records, returned `not_complete` for all reached gates,
and accepted zero completions. Real model, browser runtime, and task-local
app processes were exercised for the browser scenarios.

This effective run does not confirm complete Coding capability: the current
full-corpus result is `8/17`, and the best preserved prior run was `14/17`.
The conservative status remains `Provider Integration: PASS`, `Real Provider
Corpus: PASS / PARTIAL`, `Full Real Coding Capability: NOT CONFIRMED`,
`Full Corpus / Release Readiness: NOT READY`, and `Production Readiness: NOT
READY`. No commit, push, merge, PR update, or M9 work was performed.

## Typed root-cause persistence repair (2026-09-15)

The benchmark projection had a general evaluation-artifact defect: non-success
records could be emitted with `root_cause: null`, even though the M8 report
contract requires a primary forensic bucket. The projection now infers a
typed, conservative root cause from the recorded failure reason; explicit
security/quarantine handling remains separate, and evidence that cannot be
attributed safely remains `UNKNOWN`. This changes result metadata only; it
does not change the AgentLoop, model prompt, oracle, CompletionGate, or task
budgets.

The repair is covered by the benchmark and evaluator regression tests. The
original post-fix corpus remains preserved and untouched at
`/private/tmp/khaos-glm53-full-post-checkpoint.3scJkF/benchmark.jsonl`.
Using the trusted run ledger, a separate post-hoc typed projection was written
to
`/private/tmp/khaos-glm53-full-post-checkpoint.3scJkF/benchmark-with-root-causes.jsonl`;
it contains the same 17 run identities and unchanged 12/4/1 outcome counts,
with five non-success records classified as `MODEL_REASONING_LIMIT` and all
12 successes carrying no root cause. The derivative has zero digest
mismatches, zero hidden-oracle markers, and zero secret-pattern matches. No
Provider request or credential read was performed for this projection.

Complete real Coding capability remains `NOT CONFIRMED`; full corpus and
production readiness remain `NOT READY`.

## Checkpoint rejection projection repair and post-fix full corpus (2026-09-15)

The prior `refactor-python-repository` failure exposed a general AgentLoop
projection defect: when the required pre-edit checkpoint could not be
captured after a failed verification, the whole mutation batch was safely
withheld but the prerequisite failure escaped as an outer `AGENT_ERROR`.
That misclassified a no-effect, retryable admission observation as a runtime
failure. The repair keeps the checkpoint fence fail-closed, rejects the whole
mutation-bearing batch atomically, emits typed `CHECKPOINT_UNAVAILABLE` /
`EFFECT_NOT_STARTED` / `retry_safe` tool results, and leaves owner/binding
integrity errors terminal.

The repair has a deterministic AgentLoop/evaluation regression and the
checkpoint, execution-authority, and ToolScheduler regression set passed
`2 + 1 + 83` tests. Ruff, compileall, and `git diff --check` also passed. The
affected real rerun is preserved at
`/private/tmp/khaos-glm53-refactor-python-checkpoint.WEJTZX/benchmark.jsonl`;
it passed with 10 Provider requests, 10 model turns, 10 tool calls, four edit
attempts, two verification calls, two failed verification observations, one
repair cycle, two PRE_EDIT checkpoints, and two applied edit generations.

The post-fix sequential full corpus is preserved at
`/private/tmp/khaos-glm53-full-post-checkpoint.3scJkF/benchmark.jsonl`. All 17
records are present: 12 `SUCCESS`, four `FAILURE`, and one `TIMEOUT`. The run
used the production-shaped `zhipu-coding` / `glm-5.3-flash` path with the
baseline source SHA
`3c1095ff69b1a5d800d96eb61e8b88a47fceca14`, working-tree identity bound in
the record, and a 600-second per-task timeout. It recorded 174 Provider
requests (all HTTP 200 with typed error `NONE`), 173 model turns, 221 tool
calls, 449 Repo Intelligence queries, 191 context selections, 51 edit
attempts, 47 modified files, 11 verification calls, 16 repair cycles, 34
browser calls, 219 approvals, and zero human interventions. Provider usage
remained explicitly `PROVIDER_NOT_REPORTED`.

The single timeout was `browser-validated-feature`. The completed failures
were `feature-python-index` command verification, P4-v2/P4-v3 semantic
review misses, and `review-python-cache-race` missing the required semantic
finding. Their traces show model convergence or task-output limitations, not
provider, workspace, tool-admission, EditTransaction, verification-authority,
or oracle defects. No new generalizable Harness defect was found.

JSONL identity/digest validation passed for all 17 unique records; secret and
hidden-oracle marker scans were clean; all traces were complete with zero
drops/truncation; security violations and quarantines were zero. Sixteen
CompletionGate paths reached a decision, all were rejected fail-closed, and
none were accepted. Real model, browser runtime, and task-local App processes
were used for browser scenarios.

The repair improves Harness correctness and the full run raises the observed
signal to 12/17, but complete Coding capability is still not confirmed. The
conservative status remains `Provider Integration: PASS`, `Real Provider
Corpus: PASS / PARTIAL`, `Full Real Coding Capability: NOT CONFIRMED`, `Full
Corpus / Release Readiness: NOT READY`, and `Production Readiness: NOT
READY`. No commit, push, merge, PR update, or M9 work was performed.

## Review contract v4 and homogeneous full corpus (2026-09-15)

The previous corpus was retained unchanged at
`/private/tmp/khaos-glm53-full-current.1KZ7ML/benchmark.jsonl`. Its
`review-python-cache-race` result exposed a benchmark contract defect: the
public/system contract asked for source-grounded identifiers, while the v3
Oracle required hidden semantic words that were neither source identifiers nor
publicly required. The scenario was versioned to v4 with a public instruction
to use exact source identifiers and stable anchors (`get_or_compute`,
`_values`, `_compute`). The browser fixture's earlier baseline defect remains
fixed and versioned separately as browser scenario v3. No historical result
was rewritten.

The v4 review repair passed the deterministic offline contract/oracle tests
(`50 passed`, Ruff, compileall, and `git diff --check` passed). Its affected
real rerun is preserved at
`/private/tmp/khaos-cache-review-v4.N45p0F/benchmark.jsonl`: `SUCCESS`, two
Provider requests, two model turns, one read-only tool call, Oracle `2/2`,
CompletionGate `not_complete`, and a matching result digest. No secret or
hidden-oracle marker was found.

The homogeneous post-repair corpus is preserved at
`/private/tmp/khaos-glm53-full-final.ctODM4/benchmark.jsonl`. It binds:

| Field | Value |
| --- | --- |
| Source SHA | `3c1095ff69b1a5d800d96eb61e8b88a47fceca14` |
| Working-tree identity | `fe33c98f33e1b20007482bc08dc55bb56382f89855334b276fe0726164925f89` |
| Provider / model | `zhipu-coding` / `glm-5.3-flash` |
| Model version / reasoning | unavailable / unspecified |
| Config / policy digest | `d33720f0f5b09b9f6641c488f15e45f7d2c4aab61f8da1637017476773058b59` / `cf1bc0a3a97c13e0c9e00a7954a5c168a999671ffaa83a3a58ab33d17e758f93` |
| Manifest digest | `aab196e84761d6c46eac65e9f99679c8b42b36f57e3313fb8ae85fc94adb9e89` |
| Budgets | 128 turns, 512 tools, 32768 max output tokens, 600 s/task |
| Network / browser | none / fixture-only |

The result is `12 SUCCESS`, `3 FAILURE`, and `2 TIMEOUT`. Safe per-task
classification is:

| Task | Result | Primary classification | Bounded evidence |
| --- | --- | --- | --- |
| `browser-frontend-bug` | SUCCESS | — | browser path and task-local app completed |
| `browser-fullstack-bug` | SUCCESS | — | full-stack browser path completed |
| `browser-validated-feature` | FAILURE | `MODEL_REASONING_LIMIT` | browser/edit path ran; hidden command failed while diff check passed |
| `bugfix-go-counter` | SUCCESS | — | command/diff Oracle passed |
| `bugfix-python-cache` | SUCCESS | — | command/diff Oracle passed |
| `bugfix-typescript-config` | SUCCESS | — | command/diff Oracle passed |
| `cross-language-python-go-contract` | SUCCESS | — | cross-language Oracle passed |
| `cross-language-typescript-go-config` | SUCCESS | — | cross-language Oracle passed |
| `feature-python-index` | SUCCESS | — | command/diff Oracle passed |
| `feature-rust-parser` | FAILURE | `MODEL_REASONING_LIMIT` | edit-scope failure after a failed verification/tool path |
| `multifile-go-pipeline` | TIMEOUT | `MODEL_REASONING_LIMIT` | bounded 600-second timeout without Provider error |
| `multifile-python-settings` | SUCCESS | — | command/diff Oracle passed |
| `p4-readonly-authority` | SUCCESS | — | legacy qualification Oracle passed; v2 remains separately versioned |
| `p4-readonly-authority-v3` | FAILURE | `MODEL_REASONING_LIMIT` | schema/output path reached; semantic review evidence incomplete |
| `refactor-python-repository` | SUCCESS | — | command/diff Oracle passed after checkpoint repair |
| `refactor-typescript-client` | TIMEOUT | `MODEL_REASONING_LIMIT` | 600-second timeout; context selections remained `AVAILABLE` |
| `review-python-cache-race` | SUCCESS | — | v4 source-identifier Oracle passed `2/2` |

Aggregate bounded metrics were 152 Provider requests, 150 model turns, 203
tool calls, 352 Repo Intelligence queries, 169 context selections, 55 edit
attempts, 45 modified files, 10 verification calls, 11 failed verification
observations, 15 repair cycles, 25 browser calls, 194 approvals, zero human
interventions, and 1048 trace events. Provider request details were available
for all 17 records, all 152 responses were HTTP 200, and no detail was
truncated. Provider token usage stayed explicitly
`PROVIDER_NOT_REPORTED`.

JSONL identity/digest validation passed for all 17 records; scenario identity,
trace digest, and fixture/base bindings matched. Secret-pattern and
hidden-oracle scans were both zero, trace drops/truncation were zero, and
security violations/quarantines were zero. Fifteen CompletionGate decisions
were reached and all were rejected fail-closed; two timeout tasks did not
reach the gate. No false completion was accepted.

The only benchmark defects identified in this work are the already-fixed
browser baseline mismatch and the v3 review concept-contract mismatch. Both
were repaired by versioned, generalizable fixture/contract changes with
deterministic regression coverage. No unresolved BLOCKER/HIGH Harness defect,
Provider defect, or environment defect was found. The stale-context warning
observed during the TypeScript timeout was non-fatal: the persisted context
events were `AVAILABLE` and the trace shows ordinary model/tool activity.

Real model, controlled browser runtime, and task-local app runtime were all
used for browser tasks. This is an early real-provider Coding signal, not a
confirmation of complete capability: five records remain non-success, so
`Full Corpus Readiness: NOT READY`, `Current M8 Capability Status: EARLY
SIGNAL ONLY / NOT CONFIRMED`, and `Production Readiness: NOT READY`. No
additional Provider run, commit, push, merge, PR update, or M9 work is
authorized or performed after this analysis.

## Fresh GLM-5.3-Flash full-run audit and observability repair (2026-09-15)

The latest homogeneous run is preserved at
`/tmp/khaos-glm53-full-600.wtnpES/benchmark.jsonl`. It ran all 17 manifest
scenarios sequentially through the real `zhipu-coding` / `glm-5.3-flash`
Provider, production-shaped AgentLoop, ToolAdmission, Workspace,
EditTransaction, ExecutionService, verification, repair, and CompletionGate
observation path, with a 600-second per-task bound and no external network.
The outcome was `10 SUCCESS`, `5 FAILURE`, and `2 TIMEOUT`.

The seven non-success records were conservatively attributed to
`MODEL_REASONING_LIMIT`: three verification failures, one edit-scope failure,
one semantic review failure, and two resource-limit timeouts. All 174 Provider
request observations were typed with no Provider error; 173 were HTTP 200 and
one `NO_HTTP_RESPONSE` occurred on a timed-out task. Provider usage totaled
2,053,856 input tokens, 172,020 output tokens, and 2,225,876 total tokens;
15 task records were fully reported and the two timed-out records were
explicitly `PROVIDER_PARTIAL`.

The 17 result digests, run/scenario identities, 1,171 Trace v2 events, event
digests, event identities, and bounded Provider observations passed structural
validation. Trace drops/truncation, security violations, quarantines, secret
patterns, and hidden-oracle patterns were zero. Fifteen tasks reached
CompletionGate and were rejected fail-closed as `not_complete`; two timed out
before reaching it. A general observability defect was found because the
serialized completion counters did not project `completion_gated` outcomes.
It was fixed without changing authority, and the affected real
`bugfix-go-counter` rerun is separately preserved at
`/tmp/khaos-glm53-metrics-rerun.8BUJP0/benchmark.jsonl`: Oracle `SUCCESS`,
10 Provider requests, complete usage, and one recorded CompletionGate
rejection. The original 17 records remain untouched.

A follow-up qualification after the usage and identity repairs is preserved at
`/tmp/khaos-glm53-digest-qualification.aXDkfc/qualification.jsonl`. It used
`zhipu-coding` / `glm-5.3-flash`, recorded 7 Provider requests and complete
reported usage (`31,504` input, `3,635` output, `35,139` total tokens), and
passed P0-P3 while P4 remained a semantic-review `FAIL` with no Provider
failure. The `provider_config_digest` now matches the canonical secret-free
Provider digest (`f65d2629...`) rather than the whole config-file SHA; the
scoped-digest regression and the qualification JSONL identity check pass.

Strict browser dimensions for this local run are: real model `YES`, real
browser runtime `NO` (only the controlled fixture BrowserCoding path was
available), and task-local app runtime `YES`. Complete real Coding capability,
full-corpus readiness, and production readiness remain `NOT CONFIRMED` /
`NOT READY`. No commit, push, merge, PR update, or M9 work was performed.

## Formal coding-run Provider identity closure (2026-09-16)

The formal `coding run` path had one general observability defect: it still
seeded the run-level configuration digest from the complete config-file SHA,
rather than the canonical secret-free digest of the selected Provider. The
qualification path had already been corrected; the regular run path now uses
the same Provider-scoped helper before binding timeout and working-tree
identity. This changes only reproducibility metadata and does not expose or
read credential material beyond the existing explicit unlock boundary.

The deterministic CLI/evaluation tests passed (`236 passed` for the offline
evaluation suite, plus Ruff, Pyright, compile, production reachability, and
generated-inventory freshness checks). The affected real read-only rerun is
preserved at `/tmp/khaos-glm53-provider-digest-run.3xSnbz/benchmark.jsonl`:
`review-python-cache-race` passed with two Provider requests, complete usage
(`14,285` input, `1,981` output, `16,266` total), one recorded fail-closed
CompletionGate rejection, and no secret or hidden-oracle pattern matches.
Its run config digest was independently recomputed from the canonical
`zhipu-coding` Provider digest plus the recorded working-tree identity and
matched exactly. Earlier full-corpus artifacts remain preserved and were not
rewritten.

This closes the formal-run identity defect but does not turn stochastic model
failures into Harness failures. Complete real Coding capability remains
`NOT CONFIRMED`; full-corpus and production readiness remain `NOT READY`.

## Fresh GLM-5.3-Flash full corpus run on macOS (2026-09-17)

A fresh sequential 17-scenario run was completed through the production-shaped
Coding evaluator and is preserved at
`/tmp/khaos-glm53-full-20260916.jsonl`. It used the real
`zhipu-coding` / `glm-5.3-flash` Provider, source SHA
`3c1095ff69b1a5d800d96eb61e8b88a47fceca14`, working-tree identity
`b91f5f5633b799d41ad54b5db8dbbe6ccd0e7dfe1036167aebca0bc3cd8075ae`, manifest
digest `aab196e84761d6c46eac65e9f99679c8b42b36f57e3313fb8ae85fc94adb9e89`,
run config digest `4b44284eb508f09dd0f03532d67292b254b460d197425df527529fc6b925b941`,
and policy digest `cf1bc0a3a97c13e0c9e00a7954a5c168a999671ffaa83a3a58ab33d17e758f93`.
The per-task timeout was 600 seconds, with 128 model turns, 512 tool calls,
`network_policy=none`, and `browser_policy=fixture-only`.

The result was `9 SUCCESS`, `4 FAILURE`, and `4 TIMEOUT`. The eight non-success
records were conservatively classified as `MODEL_REASONING_LIMIT`: four
verification/semantic failures and four resource-limit timeouts. There was no
typed Provider failure. The run recorded 161 Provider requests,
1,922,341 input tokens, 163,059 output tokens, and 2,085,400 total tokens;
13 records reported complete usage and 4 timeout records were explicitly
`PROVIDER_PARTIAL`.

The 17 JSONL result digests, unique run/scenario identities, source/manifest
bindings, Trace v2 schema, and bounded metrics passed validation. The run had
1,086 trace events with zero dropped events, zero security violations, zero
quarantines, zero hidden-oracle/secret-pattern matches, and no subagents,
checkpoints, rewinds, or human interventions. Thirteen tasks reached
CompletionGate and were rejected fail-closed as `not_complete`; four timed out
before reaching the gate. No false completion was accepted.

The browser records used the controlled fixture BrowserCoding path only; strict
real-browser runtime capability remains unmeasured. The offline evaluator and
security regression set passed `302 tests` with `4 skipped`. No generalizable
BLOCKER/HIGH Harness defect was found, so no code fix was applied. This result
is a fresh early signal, not confirmation of complete real Coding capability:
full corpus/release readiness and production readiness remain `NOT READY`, and
complete real Coding capability remains `NOT CONFIRMED`. The Ubuntu guest
post-reboot readback remains environment-blocked at its graphical login screen;
the pre-reboot temporary security changes had already been restored.

## Real Playwright installation and targeted browser rechecks (2026-09-17)

Playwright-managed Chromium was installed in the host cache, and the real
browser E2E gate was run with `KHAOS_RUN_BROWSER_E2E=1`: all 19 tests passed.
This proves the real Playwright/browser-manager lifecycle and route-guard path;
it does not claim the Linux kernel-isolated production browser backend.

Two fresh, sequential GLM-5.3-Flash browser Coding rechecks were then run
through `CodingEvaluationRunner -> RuntimeCodingAgentInvoker -> build_runtime
-> AgentLoop`, with source SHA
`3c1095ff69b1a5d800d96eb61e8b88a47fceca14`, manifest digest
`aab196e84761d6c46eac65e9f99679c8b42b36f57e3313fb8ae85fc94adb9e89`,
`zhipu-coding` / `glm-5.3-flash`, no external network, and the manifest's
120-second task bound. The sanitized records are preserved separately:

| Scenario | Result | Safe trajectory summary | Artifact |
| --- | --- | --- | --- |
| `browser-frontend-bug` | `TIMEOUT` | 6 model turns, 7 successful tool calls, 3 browser calls, 2 edit previews, 0 verification calls; `MODEL_REASONING_LIMIT` | `/tmp/khaos-glm53-browser-rerun.aQNvZo/browser-frontend-bug.jsonl` |
| `browser-validated-feature` | `TIMEOUT` | 6 model turns, 6 successful tool calls, 2 browser calls, 2 edit previews, 0 verification calls; `MODEL_REASONING_LIMIT` | `/tmp/khaos-glm53-browser-feature-rerun.POKKEr/browser-validated-feature.jsonl` |

Both records have valid schema/result digests, no security violation or
quarantine, and `CompletionGate=NOT_REACHED` because the model timed out
before proposing completion. The timeout is retained as a separate attempt
and is not converted into a Harness defect. The 19-test real-browser result
and these two records strengthen the browser-runtime evidence, but complete
real Coding capability remains `NOT CONFIRMED`; full-corpus and production
readiness remain `NOT READY`.

## Fresh GLM-5.3 five-task sanity gate (2026-09-19)

A bounded five-task sanity run used the production-shaped `zhipu-coding /
glm-5.3` path with a 600-second task ceiling. The run produced four
`SUCCESS` records and one `FAILURE` record. It made 77 Provider requests,
recorded Provider-reported usage (`994,414` input, `49,112` output,
`1,043,526` total tokens), and retained one append-only JSONL record per
task. The failed browser/full-stack task is typed
`VERIFICATION_FAILURE / MODEL_REASONING_LIMIT`; it did not produce a false
CompletionGate acceptance.

The five records are retained at:

- `/tmp/khaos-m8-glm53-task1-timeout600-20260919.jsonl`
- `/tmp/khaos-m8-glm53-task2-timeout600-glm53-20260919.jsonl`
- `/tmp/khaos-m8-glm53-task3-timeout600-20260919.jsonl`
- `/tmp/khaos-m8-glm53-task4-timeout600-20260919.jsonl`
- `/tmp/khaos-m8-glm53-task5-timeout600-20260919.jsonl`

Strict real-browser capability remains environment-blocked on this macOS
run: the task used `fixture-only` browser policy and the proxy-only egress
layer rejected a request without `Proxy-Authorization`. No BLOCKER/HIGH
Harness defect was found, no full corpus was launched, and no M9 work was
started. The conservative status is `EARLY SIGNAL ONLY`, with full real
Coding capability and production readiness still `NOT CONFIRMED` /
`NOT READY`.

## Fresh GLM-5.3 full corpus gate (2026-09-19)

The current 17-scenario manifest was executed sequentially through the
production-shaped `zhipu-coding / glm-5.3` path with a fixed 600-second task
budget. The immutable result artifact is
`/tmp/khaos-m8-glm53-full.mWMcjX/results.jsonl` and contains 17 records:
`10 SUCCESS`, `5 FAILURE`, and `2 TIMEOUT`. The run made 253 Provider
requests and recorded `3,348,456` input, `226,694` output, and `3,575,150`
total tokens; 15 records have `PROVIDER_REPORTED` usage and the two timeout
records are explicitly `PROVIDER_PARTIAL`.

The seven non-success records are typed as model-limited outcomes:
`browser-fullstack-bug` and `feature-python-index` are bounded resource
timeouts; `browser-validated-feature`, `bugfix-typescript-config`, and
`review-python-cache-race` are verification failures; `feature-rust-parser`
is an edit-scope failure; and `p4-readonly-authority-v3` is a semantic-review
failure. Each records `MODEL_REASONING_LIMIT` as root cause. No Provider,
oracle, workspace, security, quarantine, or Harness BLOCKER/HIGH defect was
identified.

CompletionGate was reached for 15 tasks and rejected all 15 completion
proposals; the two timeouts did not reach the gate. There were zero false
acceptances. Browser calls were recorded, but this Darwin run remained
`fixture-only`/proxy-only and therefore does not establish strict real-browser
capability. Full real Coding capability remains `NOT CONFIRMED`, and release
and production readiness remain `NOT READY`. No automatic rerun, M9 work,
commit, or push was performed.

## Benchmark oracle correction and affected-task revalidation (2026-09-19)

The initial full-corpus classification of two records as model limitations was
corrected after evaluator-side forensic review. The review did not expose any
hidden oracle material to the model. In `bugfix-typescript-config`, the model's
`input.enabled === undefined ? true : input.enabled` implementation preserved
explicit `false`, but the version-1 hidden verifier accepted only narrower
spellings. In `browser-validated-feature`, the model produced a valid semantic
filter with a live status region and change handler, while the verifier still
required literal `result-count`/`visible.length` spellings despite claiming to
accept equivalent accessible forms.

Both are `BENCHMARK_DEFECT`, not Harness or model failures. The verifiers were
generalized, deterministic regression coverage was added, and the scenarios
were versioned to TypeScript `v2` and browser `v4`. The original records remain
preserved at `/tmp/khaos-m8-glm53-full.mWMcjX/results.jsonl`; the affected
real-provider revalidations are retained separately at:

- `/tmp/khaos-m8-glm53-benchmark-fix.C8lvpa/browser-validated-feature.jsonl`
  — `SUCCESS`, Oracle pass, 13 Provider requests, 156,023 input and 5,832
  output tokens.
- `/tmp/khaos-m8-glm53-benchmark-fix.C8lvpa/bugfix-typescript-config.jsonl`
  — `SUCCESS`, Oracle pass, 9 Provider requests, 100,620 input and 5,121
  output tokens.

Both records are bound to `glm-5.3`, `zhipu-coding`, source SHA
`3c1095ff69b1a5d800d96eb61e8b88a47fceca14`, the new manifest digest, Trace v2,
and observability schema v1. Both reached CompletionGate, which rejected the
completion proposal fail-closed; neither was falsely accepted. The affected
offline regression set passed `43 tests`, Ruff and `git diff --check` passed,
and the JSONL/digest/secret/hidden-oracle audit passed with owner-only `0600`
artifacts.

This changes the evidence classification, not the capability claim: the
remaining three failures and two timeouts from the initial 17-task run still
require separate model/timeout analysis. Strict real-browser capability is
still unmeasured on Darwin's fixture-only policy. Full real Coding capability,
full-corpus release readiness, and production readiness remain
`NOT CONFIRMED` / `NOT READY`. No commit, push, PR update, or M9 work was
performed.

## Long-budget GLM-5.3 targeted revalidation (2026-09-19)

The two initial resource-limit timeouts were rerun as separate attempts with
the same production-shaped `zhipu-coding / glm-5.3` path and a new bounded
1,800-second task ceiling. The artifacts are retained under
`/tmp/khaos-m8-glm53-long.PhiHsU/` with owner-only `0600` permissions:

- `browser-fullstack-bug` — `SUCCESS`, 26 Provider requests, 338,523 input
  and 13,067 output tokens, 9 browser calls, Oracle `2/2`.
- `feature-python-index` — `SUCCESS`, 6 Provider requests, 72,386 input and
  7,775 output tokens, 1 verification run, Oracle `2/2`.
- `feature-rust-parser` — `FAILURE`, `EDIT_SCOPE_FAILURE`; the model still
  changed only `src/parser.rs` and omitted the required `src/lib.rs` change.
- `p4-readonly-authority-v3` — `FAILURE`, `SEMANTIC_REVIEW_FAILURE`; valid
  canonical categories and read-only output but missing the Oracle role
  concepts.
- `review-python-cache-race` — `FAILURE`, `VERIFICATION_FAILURE`; the model
  still emitted an unrequested `description` field despite the no-prose
  output contract, so the typed parser correctly rejected the finding.

All five records have valid result digests, provider/model/source bindings,
Trace v2 and observability v1, no secret or hidden-oracle markers, and no
security violation or quarantine. CompletionGate reached all five and
rejected each proposal fail-closed as `NOT_COMPLETE`; no false completion was
accepted. The two former timeouts are therefore attributable to the original
600-second ceiling, while the remaining three are reproducible model/output
limitations rather than Harness defects.

Across the 17 scenarios, combining the preserved first attempts with the
versioned benchmark corrections and these targeted rechecks yields 14 passing
outcomes and 3 unresolved model-limited outcomes. This is stronger early
signal, not confirmation of complete real Coding capability. Strict real
browser runtime remains unmeasured on Darwin's fixture-only policy; full-corpus
readiness and production readiness remain `NOT READY`. No commit, push, PR
update, merge, or M9 work was performed.

## Rust v5 benchmark-contract correction and revalidation (2026-09-19)

Forensic review showed that `feature-rust-parser v4` had been over-constrained:
the public fixture already exported `parser` and `Record` from `src/lib.rs`,
and the public task explicitly required preserving that module layout. Requiring
`src/lib.rs` to change was therefore a benchmark defect, not a model failure.
The scenario was versioned to `v5`; its expected and required changed-file
sets now correctly contain only `src/parser.rs`. The affected contract tests
passed `32 tests`, with Ruff, compilation, and `git diff --check` passing.

The original v4 record remains preserved. A new real-provider attempt at
`/tmp/khaos-m8-glm53-rust-v5-final.YNDMgs/feature-rust-parser.jsonl` passed:
`SUCCESS`, Oracle `2/2`, 10 Provider requests, 127,148 input tokens, 7,254
output tokens, and 134,402 total tokens. The model changed only
`src/parser.rs`; one intermediate verification failed and one repair cycle
followed. CompletionGate was reached and rejected the completion proposal
fail-closed as `NOT_COMPLETE`; no security violation or quarantine occurred.

A prior v5 attempt is retained separately at
`/tmp/khaos-m8-glm53-rust-v5.n5K01K/` and is classified as a Provider
transport failure with `PROVIDER_PARTIAL`, not as a coding result. A subsequent
retry was briefly blocked by five stale restart-marked tasks consuming the
active-task quota; those tasks were cancelled through the supported Khaos
`task cancel` path, without direct database mutation, and the valid v5 run
then completed. This was operational state recovery, not evidence for a model
or Harness capability claim.

The consolidated evidence is now `15` passing outcomes and `2` unresolved
model/output limitations across the 17 scenarios. This remains early signal
only: strict real-browser runtime is unmeasured under Darwin's fixture-only
policy, full-corpus readiness is `NOT READY`, and production readiness is
`NOT READY`. No commit, push, PR update, merge, or M9 work was performed.

## Post-run forensic audit (2026-09-19)

The full offline `python/tests/evaluation` suite passed `241 tests` after the
Rust v5 manifest correction. The focused P4 ontology/typed-attribution/oracle
set passed `82 tests`, and the runtime/metrics/runner set passed `44 tests`.
The P4-v3 real response was JSON/schema/typed-parser valid with three typed
findings; its failure was solely semantic concept matching. The cache-review
response was valid JSON but was rejected for one unknown `description` field,
consistent with the public no-prose contract. No new Harness defect, security
failure, hidden-oracle exposure, or CompletionGate defect was found.

This strengthens attribution but does not change the verdict: real Coding
capability remains `EARLY SIGNAL ONLY / NOT CONFIRMED`, strict real-browser
capability remains `UNMEASURED`, and production readiness remains `NOT READY`.

## Final P4/cache contract closure and composite 17-scenario audit (2026-09-19)

The two remaining review failures were re-examined without weakening the
typed parser, semantic oracle, workspace boundary, or CompletionGate. The
P4-v3 contract was versioned to `v5`: its hidden oracle now requires the
category-specific primary guard symbol rather than an arbitrary second source
symbol. The cache-review contract was also versioned to `v5`: the public
prompt now explicitly states that a finding contains only
`category`, `file`, `line`, `concepts`, and `severity`, and forbids
`summary`, `description`, and other keys. The original v3/v4 records remain
preserved as separate first attempts.

The affected real-provider revalidations both passed through the production
AgentLoop path with `zhipu-coding / glm-5.3`:

- `p4-readonly-authority-v3` v5 at
  `/private/tmp/khaos-m8-p4-v5.WVGymV/p4-readonly-authority-v3.jsonl`:
  `SUCCESS`, one Provider request, 7,756 input, 308 output, and 8,064 total
  reported tokens; three typed findings matched with zero unmatched or extra
  findings.
- `review-python-cache-race` v5 at
  `/tmp/khaos-m8-cache-v5.G4kOY7/review-python-cache-race.jsonl`:
  `SUCCESS`, two Provider requests, 14,361 input, 1,309 output, and 15,670
  total reported tokens; one typed finding parsed with zero unknown fields and
  passed the semantic oracle.

The final bounded composite selects the preserved first attempt for unaffected
scenarios and the versioned affected-task rerun for each repaired scenario.
It contains 17 unique current scenario identities, all `SUCCESS`; result
digests, scenario digests, provider/model identities, and JSONL shape validate.
Secret-pattern and hidden-oracle scans are zero, all selected artifacts are
owner-only `0600`, and no record is marked `security_violation` or
`quarantined`. The evidence is intentionally identified as a composed,
append-only set across versioned reruns rather than one homogeneous process
run. The full offline evaluation suite now passes `242 tests`; targeted Ruff
and `git diff --check` also pass.

The CompletionGate remains fail-closed: all 17 reached completion observations
were rejected as untrusted completion proposals and zero false completions
were accepted. Browser tasks used the real model and task-local app/browser
path, but Darwin policy remained fixture/proxy-only; strict real-browser
runtime capability is therefore still `UNMEASURED`.

Current conservative verdict:

```text
Provider Integration: PASS
Real Provider Corpus: PASS (17/17 composed final outcomes)
Real Coding Capability: EARLY SIGNAL ONLY / current pack closed, not a universal claim
Strict Real Browser Capability: UNMEASURED
Full Corpus Readiness: READY for a future homogeneous run
Production Readiness: NOT READY
```

No commit, push, merge, PR update, or M9 work was performed.
