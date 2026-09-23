# Khaos M8 Final Closure Report

This report is the index and phase-exit classification for the current M8
execution checkpoint. It references the detailed reports rather than copying
their raw evidence.

## Latest real-provider evidence (2026-09-15)

The latest real-provider run supersedes only the older capability status
wording; all historical sections remain preserved for provenance.

```text
Provider: zhipu-coding
Model: glm-5.3-flash
Provider integration: PASS
Built-in real-provider corpus: 12/17 SUCCESS, 3 FAILURE, 2 TIMEOUT
Full real coding capability: NOT CONFIRMED
Full corpus infrastructure readiness: READY
Production readiness: NOT READY
```

The 17 sanitized records are retained at
`/private/tmp/khaos-glm53-full-final.ctODM4/benchmark.jsonl` and pass schema,
identity, and digest validation. The remaining failures are one browser
feature verification failure, one Rust edit-scope failure, one bounded
multi-file Go timeout, one P4-v3 semantic review miss, and one TypeScript
refactor timeout. No provider error, security violation, secret leak, or false
CompletionGate acceptance was observed.

## Credential isolation security-gate checkpoint (2026-09-12)

The current checkpoint intentionally stopped before Provider Smoke and before
any real-agent sanity task. It exercised only synthetic CredentialBroker,
secretless configuration, brokered transport, task-environment, and metadata
redaction contracts. The earlier real-provider smoke/sanity sections in this
report are preserved historical records, not evidence from this checkpoint.

Current conservative classification:

```text
Credential authority: SYNTHETIC PASS; native Keychain round-trip ENVIRONMENT_BLOCKED
Provider smoke: NOT RUN — SECURITY GATE
Real provider sanity: NOT RUN
Full real capability: UNMEASURED
Production readiness: NOT READY
Previously exposed credentials: ROTATION STILL REQUIRED
```

The native Keychain test used only a synthetic credential, returned a generic
host write failure, and was not retried. No real provider, full corpus, browser
runtime, commit, push, or M9 work was performed in this checkpoint.

## Evidence reports

- [M8 final capability evaluation](m8-final-capability-evaluation.md)
- [M8 release hardening](m8-release-hardening.md)
- [M8.8 browser/app/coding closure](m8.8-browser-app-coding-closure.md)

## Phase status

| Phase | Status | Boundary |
| --- | --- | --- |
| Phase 0: branch/PR/M8.8 reconciliation | PASS | Existing branch/PR preserved; baseline SHA and exact-SHA runs verified. |
| Phase 1: real-provider smoke/sanity/corpus | PASS / PARTIAL | Current smoke and 17-scenario real-provider corpus passed the provider boundary; outcome is 12/17 and not a complete-capability pass. |
| Phase 2: failure analysis | PASS / PARTIAL | All five current non-success trajectories were inspected and classified as model convergence/output limitations; no new high Harness defect was found. |
| Phase 3: production hardening | PASS / PARTIAL | Security and lifecycle controls remain intact; complete real Coding capability and production readiness remain unconfirmed. |
| Phase 4: exact-SHA CI | PASS for baseline | Does not cover current uncommitted working-tree changes. |

## Direct answers

The current corpus shows successful real-agent execution across bug fixes,
multi-file changes, refactors, and browser/app tasks, but it cannot yet
establish complete reliability: five of 17 scenarios remain unsuccessful.
Human-intervention, efficiency, and same-model harness-delta metrics remain
limited or `UNKNOWN` where the current artifact does not report them.

The provider smoke and corpus traces produced no credential leak, authority
escape, approval replay, stale completion acceptance, child contamination, or
browser/MCP resource leak. This is capability evidence, not a claim of
complete real-provider reliability.

## P4-v3 follow-up classification (2026-09-15)

The original `p4-readonly-authority-v3` failure remains preserved as the first
attempt. Two affected-scenario-only real-provider reruns were retained as
separate append-only artifacts. Both produced valid plain JSON with passing
schema/typed parsing and then failed the semantic review because the model's
source-grounded concept evidence was incomplete. The second rerun was made
after adding a general source-identifier guidance rule to the Coding system
prompt; it did not change the semantic outcome.

No provider error, security violation, hidden-oracle exposure, workspace
mutation, or false CompletionGate acceptance occurred. The failure is
classified as `MODEL_LIMITATION`, not `HARNESS_DEFECT`. The full real coding
capability is therefore still `NOT CONFIRMED`; no full-corpus rerun was
started merely to seek a green result.

Installation, platform guarantees, restart behavior, bounded cleanup, and
diagnostic paths are covered by the existing security/lifecycle tests and
reports, with platform-specific CI still authoritative where applicable.

## Phase-exit classification

```text
M8 ENGINEERING COMPLETE — REAL PROVIDER EARLY SIGNAL ONLY
PROVIDER INTEGRATION PASS — FULL CAPABILITY UNMEASURED
```

This is not an M8 release-candidate or M9 start signal. The next required
action is to run the versioned full corpus with the sanitized JSONL artifact
after provider stability and secure real-browser availability are established,
then reassess the release verdict.

No commit, push, new PR, PR metadata change, or merge was performed in this
checkpoint.

## GLM-5.3-Flash stabilization checkpoint

The follow-up evidence preserves the same boundary: real provider smoke and
the production AgentLoop tool microprobe passed, while all five canonical
sanity tasks timed out within their unchanged budgets. The task traces show
planning, tool admission, bounded tool results, and timeout interruption; no
task reached a CompletionGate acceptance, and the browser task recorded no
browser runtime call.

The state-root file-permission defect and provider HTTP-error classification
defect were fixed and covered by deterministic tests. Usage/model identity
remain explicitly unavailable from the current adapter. The raw first-pass
records and the separate Task 1 rerun are preserved outside the repository;
the complete corpus remains not ready and was not launched.

## GLM-5.3 post-sanity repair checkpoint

The preserved first-pass records were followed by a same-budget rerun after
fixing the parallel output-reservation defect, then one affected Task 5 rerun
after fixing the missing workspace capability mapping for Coding Repo
Intelligence and M8.8 browser tools. Both repairs have deterministic
regressions and the final selected regression set passed with `242 passed`.
All real-provider task attempts remained bounded `TIMEOUT`; no CompletionGate
acceptance or browser runtime call occurred. The status therefore remains
provider integration `PASS`, sanity `PARTIAL`, full capability `UNMEASURED`,
and production readiness `NOT READY`.

## GLM-5.3-Flash real-agent convergence gate

The 2026-09-11 convergence follow-up preserved four additional typed JSONL
attempts under `/tmp/khaos-m8-glm53-convergence.sIi4Y1/`. Task 1 attempts 1
and 2 reproduced general Harness contract defects and were preserved as
first-attempt evidence; after repair, attempt 3 showed the model correctly
investigating and patching `src/cache.py` but timing out before verification.
A bounded secondary feature attempt received an empty provider response and
made no tool call. These outcomes are classified separately as Harness,
model/tool-use, and provider boundaries; none is treated as a generic coding
failure.

The JSONL records validate against the existing schema and digest bindings.
Usage remains explicitly unavailable (`UNKNOWN / PROVIDER_NOT_REPORTED`), no
CompletionGate acceptance occurred, and no browser/app runtime was exercised.
The generalizable fixes and deterministic regressions are recorded in the
capability report; no unresolved deterministic BLOCKER/HIGH Harness defect
remains from this phase. Provider integration is `PASS`, real-agent
convergence is `PARTIAL`, full real capability remains `UNMEASURED`, and
production readiness remains `NOT READY`. The full corpus was not launched.

## GLM-5.3-Flash completion convergence probe

The controlled follow-up increased only the primary Task 1 total timeout from
120 to 240 seconds at runtime. The scenario, manifest, policy, fixture/base
revision, provider/model, prompt/seed, tool schemas, budgets, network, and
browser settings stayed the same. This is explicitly not a pristine same-code
comparison because the generic evaluation timeout override and two subsequent
generalizable Harness repairs are part of the current working tree; all
attempts remain preserved separately.

The 120-second baseline (`m8-74be3967765b48e897efcb5da10053db`) timed out after
3 turns and 6 tools with a correct cache edit but no verification. The first
240-second record (`m8-5a4b2c37d69b40ca906b68e506f18fd7`) exposed the mismatch
between the optional `file_search_content.path` schema and its required
handler argument. After that fix, the next record
(`m8-4fe1ed7b801744ec98b181f91d350ea6`) exposed relative `test_run` cwd being
resolved from the process directory instead of the active TaskWorkspace. Both
defects were fixed with deterministic regressions and both pre-fix records are
preserved. The final 240-second record
(`m8-467749cd35834df4b3b5874e9095b685`) reached no green verification: the
model selected security-blocked `terminal_argv(python3 -c ...)`, repeated
edits/reads, and encountered a separate missing macOS developer-tool failure
on `git_diff`.

The affected regression set passed (`125 passed, 1 warning`), and all four
typed JSONL records round-tripped with valid result digests and unique run IDs.
The real AgentLoop/tool path was exercised, but repair cycles and CompletionGate
acceptance remained zero/null. No secondary task, browser runtime, or app
runtime was run. Provider integration remains `PASS`; completion convergence is
`FAIL` for this probe, full real capability is `UNMEASURED`, and full-corpus
readiness remains `NOT READY`.

The JSONL/state artifact scan found no credential match. A separate session
diagnostic command accidentally printed host-configuration credential lines;
no repository, JSONL, or state-database write contained the key, but overall
session-level secret hygiene is recorded as `FAIL` rather than being silently
reported as clean. This does not change the fail-closed security behavior that
blocked the model's direct Python terminal calls.

## GLM-5.3-Flash model capability disambiguation gate

The final bounded A/B gate ran on 2026-09-11 through the real Khaos AgentLoop
and coding authority chain at HEAD `3c1095ff69b1a5d800d96eb61e8b88a47fceca14`.
Model A was `zhipu-coding / glm-5.3-flash`; Model B was
`nvidia / deepseek-ai/deepseek-v4-flash-0731`. Both used the same deterministic
cache-bug task and bounded 240-second / 128-turn / 512-tool policy with
network and browser disabled.

NVIDIA provider smoke passed, as did a separate read-only real-AgentLoop probe
that completed one authorized file read. Provider usage and returned model ID
were not reported. The original NVIDIA primary attempt is preserved as a
provider timeout; after a general timeout-taxonomy fix, its second attempt is
also preserved and correctly classified as `PROVIDER_FAILURE`. The GLM primary
attempt timed out after 7 turns and 14 tool calls with one applied edit and no
successful verification or CompletionGate acceptance. The comparative coding
gate is therefore `INCONCLUSIVE`, with only an early model/tool-use signal.

Current JSONL schema/digest validation and hidden-oracle isolation passed, and
the current artifacts/state databases contained no credential match. No
secondary task, browser/app runtime, or full corpus was launched. Provider
integration remains `PASS`; full real capability remains `UNMEASURED`, full
corpus readiness is `NOT READY`, and production readiness is `NOT READY`.

## SiliconFlow Qwen3.8-27B controlled model disambiguation gate

On 2026-09-11 the current Khaos configuration resolved to provider
`siliconflow` and model `Qwen/Qwen3.8-27B` at HEAD
`3c1095ff69b1a5d800d96eb61e8b88a47fceca14` on
`codex/m8-coding-evaluation`. The working tree was preserved as found. Older
GLM records were not treated as same-state A/B evidence, and no fresh GLM
control was launched after the Qwen pre-Coding gate failed.

The SiliconFlow provider smoke passed through the Khaos Router. The real
AgentLoop microprobe reached planning but received a provider HTTP 400 before
any tool operation or tool result; the typed provider failure was surfaced as
`MODEL_UNAVAILABLE`. Consequently, no real Coding task or benchmark JSONL
record was created for Qwen, and no coding, verification, repair,
CompletionGate, browser, or full-corpus claim can be made.

The current secret scan passed with no key match, no API-key-shaped match, and
no printed secret. No Harness fix was applied. The controlled comparison is
`INVALID`, provider integration is `PASS` at smoke level, Qwen tool-use and
real coding capability are `UNMEASURED`, Khaos closed-loop proof is `NOT
PROVEN`, full corpus readiness is `NOT READY`, and production readiness is
`NOT READY`.

## SiliconFlow Qwen3.5-27B tool-calling and closed-loop validation gate

On 2026-09-11 Khaos resolved the configured SiliconFlow model as
`Qwen/Qwen3.5-27B` at HEAD
`3c1095ff69b1a5d800d96eb61e8b88a47fceca14` on
`codex/m8-coding-evaluation`. The text Smoke passed through the production
Router/ModelClient path. A minimal one-tool streaming probe likewise passed:
the provider accepted the schema and returned one valid normalized
`probe_echo` call.

The real AgentLoop microprobe reached planning, then failed with a provider
HTTP 400 before any production tool call or result. Its typed error was mapped
to `MODEL_UNAVAILABLE`; no edit, verification, repair, CompletionGate, or
Coding benchmark was reached. This is provider/endpoint tool-surface
compatibility evidence, not model capability evidence.

Secret handling passed and no secret was printed or persisted in scanned
artifacts. No Harness code was changed and no Qwen3.5 Coding JSONL record was
created. Minimal tool compatibility is `PASS`, production AgentLoop tool
compatibility is `FAIL`, closed-loop validation is `FAIL`, model
disambiguation is `INCONCLUSIVE`, real coding capability is `UNMEASURED`, full
corpus readiness is `NOT READY`, and production readiness is `NOT READY`.

## SiliconFlow Qwen3.5-27B production tool-surface compatibility bisect

The prior Qwen3.5 production AgentLoop HTTP 400 is preserved. A bounded
pre-fix bisect found the exact discriminator: minimal messages plus the full
12-tool production catalog passed, while the AgentLoop request failed only
when it contained two or more `system` messages. Tool prefixes 1, 4, 8, and 12
all passed; individual schemas did not fail; no developer role or request
option difference was present. This is classified as
`PROVIDER_ENDPOINT_LIMITATION`, specifically SiliconFlow Qwen3.5 rejection of
multiple system messages.

The general provider serialization fix adds a SiliconFlow wire-capability
profile, coalesces system instructions at the ModelClient boundary without
altering AgentLoop authority semantics, and rejects system tool calls if they
cannot be preserved. Streamed provider errors no longer copy raw response
bodies into typed errors or audit text. The deterministic regression set
passed (`86 passed, 1 warning`), with Ruff, Pyright, compileall, and
`git diff --check` passing. The final secret scan found no exact credential,
API-key-shaped value, or raw provider-error marker, and no secret was printed.

P0 text smoke, P1 minimal tool calling, and P2 full production tool-surface
acceptance passed. A real AgentLoop run executed `read_file` through the normal
Khaos path, received the result, continued, and reached `COMPLETED`, proving
the production tool-calling loop. One later same-task run ended without a tool
call; this is retained as a model/tool-choice limitation and not treated as a
Harness defect. The compatibility gate is `PASS`, real AgentLoop tool-calling
is `PROVEN`, closed-loop Coding is ready for a separate phase, full corpus
readiness is `NOT READY`, and production readiness is `NOT READY`.

## SiliconFlow Qwen3.5-27B rate-limit attribution and stable revalidation

The 2026-09-11 stabilization gate ran against exact HEAD
`3c1095ff69b1a5d800d96eb61e8b88a47fceca14` on
`codex/m8-coding-evaluation`, with the pre-existing dirty working tree
preserved. The protected untracked file
`docs/local-security-closure-report.md` was unchanged and unstaged.

Provider-boundary observability is now bounded and secret-free. It records
per-attempt HTTP status, latency, first-byte latency, request id, allowlisted
rate-limit headers, typed error metadata, and effective retry delay without
retaining a provider response body. Retry behavior is bounded to three
attempts, honors a bounded `Retry-After` value when present, otherwise uses
100ms/200ms exponential delays, and remains cancellation-aware.

P0 text, P1 tool, and sequential P2 capacity probes all passed with HTTP
200. A fresh real AgentLoop microprobe also performed one successful
`read_file` call and completed. Usage and provider-returned model identity
remain explicitly unavailable from the adapter.

Exactly one valid fresh Coding attempt was run after that gate. It produced
immutable JSONL run
`m8-6e4d5b955f4748f6a671c7ed4505147c` at
`/private/tmp/khaos-m8-qwen35-rate-limit-revalidation-20260911-1/bugfix-python-cache.jsonl`.
The run reached 21 model turns, 21 tool calls, 4 successful patch operations,
and 3 failed tests. The final provider request returned HTTP 429 on all three
bounded attempts; no `Retry-After` or rate-limit window metadata was supplied.
The result is therefore a provider-side
`RATE_LIMIT_CONFIRMED_SUBTYPE_UNKNOWN` / `PROVIDER_FAILURE`, not a model or
Harness failure. CompletionGate was not reached and no Coding rerun was
performed.

JSONL digest validation and hidden-oracle isolation passed. The state ledger
retained 86 bounded trace events, including planning, tool calls/results,
approvals, and the terminal error, with no raw provider body or credential.
The earlier stdin-only launcher attempt is retained separately as an
invalidated setup artifact with zero provider requests; it is not counted as
capability evidence. Full real coding capability remains `UNMEASURED`, with
only an early provider-invalidated signal. Browser capability, full corpus
readiness, and production readiness remain `NOT READY`.
readiness, and production readiness remain `NOT READY`.

## Stable Model-B selection and closed-loop disambiguation gate

The 2026-09-12 gate ran at exact HEAD
`3c1095ff69b1a5d800d96eb61e8b88a47fceca14` on
`codex/m8-coding-evaluation` with the existing dirty tree preserved. The
working-tree identity was
`3c93f6bd6a470d459b51525bbdec375ca4e833b09e14dcbffb20595f3b1cc32e`.
`docs/local-security-closure-report.md` remained untracked, unchanged,
unstaged, 851 bytes, SHA-256
`85dbfe1ee17475154a0f48a6d308750b252aec75f3b67dd4f2e47f06b25597a1`.

Candidate qualification used the configured NVIDIA
`deepseek-ai/deepseek-v4-flash-0731`, while excluding GLM-5.3-Flash as the
Model-A baseline and excluding SiliconFlow Qwen3.5-27B because of its
preserved sustained-429 Coding evidence. NVIDIA passed P0/P1/P2 and the real
AgentLoop P3 read-only probe. P4 failed the stability gate twice: the first
attempt timed out before meaningful work, and the only permitted replacement
reached four HTTP 200 requests and 16 read-only tool calls before a fifth
request timed out. The candidate was rejected as unstable; no qualified
Model-B remained.

The Stable Model-B Selection Gate is `FAIL`. The run correctly stopped before
the primary Coding task, so there is no new Coding JSONL result and no
controlled GLM comparison. No Harness defect or source fix was identified.
Evaluation integrity tests passed (`27 passed`, one existing warning), current
credential matches and Authorization-bearing leaks were zero, and the four
API/bearer-shaped scan hits were noncredential historical examples. Real
AgentLoop/tool use remains proven, but M8.3, repair, CompletionGate, and the
real Coding closed loop remain unproven. Full corpus readiness and production
readiness remain `NOT READY`.

## macOS Keychain environment and credential-isolation closure gate

On 2026-09-12, exact HEAD remained
`3c1095ff69b1a5d800d96eb61e8b88a47fceca14` on
`codex/m8-coding-evaluation`. The protected untracked local security report
remained unchanged and unstaged. This gate made zero real provider calls and
read zero real credentials. The prior credential exposure remains an operator
rotation action and is not repeated here.

The trusted macOS backend audit confirmed Security.framework native APIs,
default Keychain selection, and interaction disabled. The bounded native
diagnostic returned `-25308 / INTERACTION_REQUIRED`; the current Keychain
requires user interaction while Khaos forbids it. The classification is
`OS_POLICY_BLOCKED / ENVIRONMENT_BLOCKED`. No dialog automation, system
Keychain modification, or plaintext fallback was used. Typed safe native
diagnostics and the canonical output firewall were added; synthetic round-trip
and cross-boundary canary tests passed. The one integrated native attempt
stopped at `put` and was not retried. Real provider/coding/browser capability
remains `UNMEASURED`, full corpus readiness is `NOT READY`, and production
readiness remains `NOT READY`.

## 10.10. macOS credential provisioning/runtime final gate

At exact HEAD `3c1095ff69b1a5d800d96eb61e8b88a47fceca14`, the credential gate
added `CredentialAccessMode.PROVISIONING` and `CredentialAccessMode.RUNTIME`.
Provisioning is reachable only through explicit operator CLI/config/TUI paths;
runtime status, handle issuance, authorization, and model chat remain
non-interactive. `SecKeychainSetUserInteractionAllowed` is serialized and
restored to `False` after every operation. No real provider or credential was
used; no coding/browser benchmark was started.

The native backend audit is legacy `SecKeychain*`, DPK `NO`, accessibility
`UNSPECIFIED_LEGACY`, ACL/access control `NONE`, user presence `NO`, sync `NO`,
and access group `NONE`. DPK decision:
`PACKAGING_PREREQUISITE_BLOCKS_SWITCH`. The prior native `-25308 /
INTERACTION_REQUIRED` remains `OS_POLICY_BLOCKED / ENVIRONMENT_BLOCKED`; it was
not retried or worked around. Hidden-input/no-secret-argv, runtime no-popup,
typed error mapping, no runtime auto-delete, and atomic replace rollback are
covered by deterministic tests. The final isolated target run was **104
passed, 1 skipped**; Ruff, targeted compileall, and `git diff --check` passed.

Credential Provisioning Gate is deterministic `PASS` but native confirmation is
`MANUAL_PROVISIONING_CONFIRMATION_REQUIRED`; Non-Interactive Runtime Gate is
policy `PASS` but native item access is environment-blocked. Full real coding
capability is `UNMEASURED`, real browser capability is `UNMEASURED`, full corpus
readiness is `NOT READY`, production readiness is `NOT READY`, and the exposed
credential still requires operator rotation.

## Local-first CredentialSession decision (2026-09-12)

The earlier packaging-dependent DPK path is no longer a local usage
requirement. The existing Broker now owns an explicit `CredentialSession`:
`LOCKED` at startup, human-only unlock, one persistent-store read during
unlock, memory-only runtime lease, typed locked-session failure, and
invalidation on lock/replace/delete/shutdown/restart. The TUI/line chat expose
only explicit human commands; no Agent tool can unlock or provision.

Synthetic deterministic validation passed with three fake runtime Provider
requests and zero runtime Store reads after unlock. No real credential or real
Provider was used. `SESSION_UNLOCK_CANONICAL` is the local-first decision;
Data Protection Keychain, formal signing, and Apple Developer infrastructure
remain `OPTIONAL_FUTURE_HARDENING`. Historical credential rotation is still
`OPERATOR ACTION REQUIRED`.

## Manual native synthetic acceptance gate (2026-09-12)

The manual gate completed one fresh synthetic lifecycle in the real macOS
login Keychain. SET, safe STATUS, locked preflight, explicit unlock, three
fake Provider requests, lock, re-unlock, replacement, shutdown/restart,
replacement unlock, and delete passed. The persistent-store read count during
the first unlock was `1`; runtime persistent-store reads and runtime Keychain
UI were `0`. Post-delete runtime returned `CREDENTIAL_MISSING`, distinct from
`CREDENTIAL_SESSION_LOCKED`, and synthetic leftovers were `0`.

The native acceptance closes the persistent-store gate for the local-first
synthetic path. It does not authorize real Provider evaluation: real Provider
calls and real credential reads stayed at `0`, real credential rotation is
still `OPERATOR ACTION REQUIRED`, and full real capability/full corpus remain
`UNMEASURED`/`NOT READY`.

## P4 Qualification Harness Repair & Benchmark v2 Closure (2026-09-12)

This is an offline working-tree repair gate. It made zero real Provider calls,
read zero real credentials, did not unlock a credential session, and did not
run GLM-5.3, GLM-5.3-Flash, the Coding corpus, browser evaluation, or M9.

The historical P4-v1 qualification artifact remains immutable and retains
`FAIL` with mechanical cause `TOOL_BUDGET_EXHAUSTED`. Its Harness integrity is
`FAIL` and its convergence attribution is `INVALID / INCONCLUSIVE`; it is not
reclassified as a GLM limitation. The new P4-v2 scenario is version 2 and
uses a small public synthetic authority fixture with a separate oracle-owned
hidden directory. Its prompt permits natural early completion and exposes no
minimum turn/tool target.

The repaired execution chain keeps the canonical runtime tool budget in the
AgentLoop/Scheduler path. Exhaustion produces typed
`TOOL_BUDGET_EXHAUSTED` terminal evidence. Trace storage is observational:
overflow marks `trace_truncated` and `dropped_event_count` without raising
into the AgentLoop. Trace v2 preserves bounded turn/call/result identity,
exact tool names, separate categories, pending terminal states, typed errors,
safe result metadata, redaction-before-digest, and summary/event
reconciliation. Qualification now has versioned typed append-only JSONL with
source HEAD, dirty working-tree, provider/model, fixture, prompt, system
prompt, tool schema, policy, budget, and opaque credential-reference binding.

Deterministic acceptance passed for fake efficient and normal P4-v2 AgentLoop
paths, accepted early completion, classified wrong answers as failures,
classified tool failures and over-exploration with typed outcomes, and kept
the hidden oracle outside the agent root. The exact evaluation/security
results and defect table are recorded in
[the dedicated P4-v2 closure report](m8-p4-qualification-harness-repair-v2-closure.md).

Conservative status after this gate:

```text
M8 Engineering: COMPLETE
Security: PASS for this offline gate
Provider Integration: NOT RUN
Real Provider Sanity: NOT RUN
Full Real Capability: UNMEASURED
Full Corpus Readiness: NOT READY
Production Readiness: NOT READY
```

No commit, push, PR update, merge, or cleanup was performed.

## Router import-cycle closure (2026-09-12)

The production Router cold-import blocker was closed offline. A neutral
security identity module now owns `CanonicalWorkspaceId`; planning re-exports
the same type for compatibility, so security resource scope no longer imports
the planning package. Fresh import-order, identity-reuse, Router, and
qualification-bootstrap regressions pass, with zero real Provider requests and
zero credential materialization/session/unlock activity.

This is not real-provider or coding-capability evidence. Full real capability
remains `UNMEASURED`, full-corpus readiness remains `NOT READY`, and production
readiness remains `NOT READY`. See the [Router import-cycle closure report](m8-router-import-cycle-closure.md).

## Qualification observability closure (2026-09-13)

The offline O1-O4 observability gate passed its deterministic trace, parser,
context, CompletionGate, JSONL compatibility, timing, and secret-canary tests.
It made no Provider request and read no credential. This improves diagnosis
readiness only; it does not qualify GLM-5.3/Flash, change the historical P4-v2
`FAIL`/`INCONCLUSIVE` result, or make the full corpus or production ready. See
the [observability closure report](m8-qualification-observability-closure-2026-09-13.md).

## Fresh real-provider corpus gate (2026-09-14)

The fresh `zhipu-coding` / `glm-5.3-flash` sequential Coding corpus completed
17 runs through the production AgentLoop and BrowserCoding path. The result
was 4 `SUCCESS`, 9 `FAILURE`, and 4 `TIMEOUT`; all 157 provider requests were
HTTP 200 with typed provider error `NONE`, usage
`PROVIDER_NOT_REPORTED`, zero security violations, zero quarantines, and no
trace truncation. Real model, browser runtime, and task-local app process were
all used. The complete coding capability gate therefore remains
`EARLY SIGNAL ONLY`, and full-corpus/production readiness remain `NOT READY`.

The detailed evidence is in
[M8 final capability evaluation](m8-final-capability-evaluation.md), with
JSONL and SQLite artifacts under
`/private/tmp/khaos-glm53-full-corpus-final3-20260914/`. No commit, push, PR
update, merge, or M9 work was performed.

## Final4 rerun and offline closure (2026-09-14)

The post-hardening sequential rerun is preserved at
`/private/tmp/khaos-glm53-full4-20260914/benchmark.jsonl` with 17 append-only
records: 5 `SUCCESS`, 6 `FAILURE`, and 6 `TIMEOUT`. It used
`zhipu-coding` / `glm-5.3-flash`, recorded 174 provider requests (173 HTTP
200 and one cancellation without an HTTP response), and reported usage as
`PROVIDER_NOT_REPORTED`. Security violations, trace truncation, and dropped
events were all zero. Browser frontend and full-stack paths used the real
model, Playwright browser runtime, and task-local app process under the
fixture-only/no-network policy.

No real-path Harness defect remained in the final4 traces. Model wrong-file
choices, strict review JSON misses, repeated verification, and bounded
timeouts are retained as model/provider-latency evidence rather than hidden
by evaluator changes. A separate offline `TaskService(db=None)` cache-path
regression and three stale generated inventories were fixed; the complete
offline suite passed `5734` tests with `31` expected skips. Full real coding
capability remains `EARLY SIGNAL ONLY`, and full-corpus/production readiness
remain `NOT READY`.

## Final5 provider run and closure (2026-09-14)

After the context-admission repair, the preserved sequential run at
`/private/tmp/khaos-glm53-full5-20260914/benchmark.jsonl` contains 17 records:
7 `SUCCESS`, 7 `FAILURE`, and 3 `TIMEOUT`. It used
`zhipu-coding` / `glm-5.3-flash`, with 149 provider requests (148 HTTP 200 and
one cancellation without an HTTP response), 200 tool calls, 40 edit attempts,
16 verification runs, 14 repair cycles, and 32 browser calls. Usage was
`PROVIDER_NOT_REPORTED`; security violations, quarantines, trace truncation,
dropped events, and human interventions were all zero.

The oversized-project-instruction/evicted-goal defect was fixed with a
general selector rule and deterministic regression. Production CLI smoke,
the affected real task, generated security inventories, and the complete
offline suite all pass; the final offline result is `5741 passed, 31 skipped`.
The remaining real-task failures are model convergence, verification,
edit-scope, output-contract, or bounded-resource outcomes, with no new
generalizable Harness defect evidenced.

JSONL digest/canonical validation, provider/context observability, hidden
oracle isolation, and secret-pattern audit all pass. Real coding capability is
therefore still `NOT CONFIRMED` (7/17), and full corpus/release and production
readiness remain `NOT READY`.

## Verification trace observability repair (2026-09-15)

M8.3 autonomous verification was already persisted as an untrusted
observation, but the production-shaped AgentLoop did not stream that safe
message to the passive trace collector. The general fix now persists before
streaming for both normal and infrastructure-unavailable observations; it does
not alter CompletionGate or trusted verification authority. The regression and
related M8.3/runtime tests pass (`66 passed`, one existing Hypothesis warning).

The fresh real run at
`/private/tmp/khaos-glm53-observability-reprobe-6Ubred/benchmark.jsonl`
remained `SUCCESS`, recorded 10 provider requests and 2 typed verification
plans, and kept CompletionGate fail-closed at `not_complete`. No provider,
security, or oracle boundary was weakened. Full real Coding capability and
production readiness remain `NOT READY`.

## Full corpus after applied-effect receipt repair (2026-09-15)

The preserved fresh run at
`/private/tmp/khaos-glm53-full-v2-final-20260915/benchmark.jsonl` completed all
17 scenarios sequentially through the real `zhipu-coding` /
`glm-5.3-flash` production-shaped Coding path. It produced 10 `SUCCESS` and 7
`FAILURE` records, 176 HTTP 200 Provider requests, 240 tool calls, 49 edit
attempts, 15 verification calls, 17 repair cycles, and 36 browser calls.
Provider usage remained `PROVIDER_NOT_REPORTED`. No Provider error, security
violation, quarantine, trace loss, or human intervention occurred.

The applied-effect receipt repair was validated by the fresh passing
`multifile-python-settings` run. It is a general result-delivery fix, not a
benchmark shortcut. The original ambiguous `refactor-python-repository` v2
failure is preserved; its public file-location contract was versioned to v3
and the affected real rerun is preserved at
`/private/tmp/khaos-glm53-v3-refactor-python-20260915.zxPHr1/benchmark.jsonl`,
which passed. The remaining six failures are model convergence, tool-use,
scope-control, or review-output limitations.

All 17 CompletionGate attempts were reached with `not_complete`, zero accepted
completion decisions, and no false completion acceptance. JSONL identity and
digest checks, hidden-oracle isolation, context/provider observability, and
secret-pattern checks pass. Real model, Playwright browser runtime, and
task-local app processes were exercised for the browser scenarios.

```text
Provider Integration: PASS
Real Provider Corpus: PASS / PARTIAL
Full Real Coding Capability: NOT CONFIRMED
Full Corpus / Release Readiness: NOT READY
Production Readiness: NOT READY
```

No commit, push, merge, PR update, or M9 work was performed.

## Fresh GLM-5.3-Flash full-run audit and observability repair (2026-09-15)

The current full run is preserved at
`/tmp/khaos-glm53-full-600.wtnpES/benchmark.jsonl` and is bound to source SHA
`3c1095ff69b1a5d800d96eb61e8b88a47fceca14`, provider `zhipu-coding`, model
`glm-5.3-flash`, the current manifest/policy digests, and a 600-second task
bound. It contains 17 records: `10 SUCCESS`, `5 FAILURE`, and `2 TIMEOUT`.
The non-success records are early model-convergence evidence only, not a
Harness or Provider success claim.

Provider accounting is complete for successful/finished requests: 174 typed
request observations, 173 HTTP 200 responses, one timeout-side
`NO_HTTP_RESPONSE`, and no typed Provider error. Aggregate usage is
2,053,856 input, 172,020 output, and 2,225,876 total tokens; the two timed-out
records remain explicitly `PROVIDER_PARTIAL`. JSONL digest/identity checks,
Trace v2 integrity (1,171 events), secret scans, hidden-oracle scans, and
security/quarantine checks all passed.

CompletionGate evidence is fail-closed: 15 decisions reached
`not_complete`, and two timed-out tasks did not reach the gate. A general
counter-projection defect was repaired and tested; the affected real rerun is
preserved independently at
`/tmp/khaos-glm53-metrics-rerun.8BUJP0/benchmark.jsonl` and records one
CompletionGate rejection with complete Provider usage. The original full-run
artifact remains unchanged.

A follow-up qualification after the usage and identity repairs is preserved at
`/tmp/khaos-glm53-digest-qualification.aXDkfc/qualification.jsonl`. It used
`zhipu-coding` / `glm-5.3-flash`, recorded 7 Provider requests and complete
reported usage (`31,504` input, `3,635` output, `35,139` total tokens), and
passed P0-P3 while P4 remained a semantic-review `FAIL` with no Provider
failure. The `provider_config_digest` matches the canonical secret-free
Provider digest (`f65d2629...`); the scoped-digest regression and qualification
JSONL identity check pass.

Strict browser dimensions are real model `YES`, real browser runtime `NO`
(the local environment exposed only the controlled fixture BrowserCoding
path), and task-local app runtime `YES`. No unresolved BLOCKER/HIGH Harness
defect or Provider defect was found in this audit, but complete real Coding
capability, full-corpus readiness, and production readiness remain
`NOT CONFIRMED` / `NOT READY`. No commit, push, merge, PR update, or M9 work
was performed.

## Effective 600-second full corpus after final prompt alignment (2026-09-15)

The valid sequential run is preserved at
`/var/folders/l3/00y511gj4q55gj2z6zdqzrs00000gn/T/khaos-glm53-full-valid-current.IicrTEWg7f/benchmark.jsonl`.
All 17 scenarios completed under the explicit 600-second task budget:
8 `SUCCESS`, 6 `FAILURE`, and 3 `TIMEOUT`. It recorded 181 Provider
requests (180 HTTP 200 and one bounded timeout cancellation), 178 model
turns, 238 tool calls, 320 Repo Intelligence queries, 198 context selections,
57 edit attempts, 52 modified-file observations, 18 verification calls, 13
repair cycles, 26 browser calls, 233 approval requests, and 0 human
interventions. Every typed Provider error observation was `NONE`; usage was
`PROVIDER_NOT_REPORTED`.

The failures were retained as model convergence or recovery evidence: three
resource-limit timeouts, browser-feature and TypeScript hidden-command
failures, P4-v2 semantic mismatch, P4-v3 fenced-output contract failure,
cache-race review mismatch, and a Python refactor recovery path that failed
closed after a failed verification when its next pre-edit checkpoint was
unavailable. The related deterministic checkpoint/execution/tool regression
set passed 83 tests. No new BLOCKER/HIGH Harness defect was found and no
authority, budget, Oracle, or CompletionGate boundary was weakened.

The JSONL contains 17 unique identities with zero digest mismatches, zero
secret-pattern matches, zero hidden-oracle markers, zero trace loss, zero
security violations, and zero quarantines. CompletionGate was reached 13
times, rejected every reached completion as `not_complete`, and accepted
zero. Real model, browser runtime, and task-local app execution were used.

The conservative closure result is `Provider Integration: PASS`, `Real
Provider Corpus: PASS / PARTIAL`, `Full Real Coding Capability: NOT
CONFIRMED`, `Full Corpus / Release Readiness: NOT READY`, and `Production
Readiness: NOT READY`. No commit, push, merge, PR update, or M9 work was
performed.

## Prompt/tool-surface alignment follow-ups (2026-09-15)

The Coding prompt now matches the real model-visible surface: it no longer
mentions the intentionally hidden legacy `delete_file` tool and directs any
temporary-file cleanup through canonical `apply_edit_transaction` delete
operations with preview/apply CAS. It also separates semantic role words from
source identifiers in structured evidence. The prompt regression passes 17
tests.

The preserved P4-v3 follow-up
`/private/tmp/khaos-glm53-p4v3-rolewords-6cAT21/benchmark.jsonl` was
schema-valid but semantically incomplete, with one HTTP-200 Provider request
and typed error `NONE`. The preserved TypeScript follow-up
`/private/tmp/khaos-glm53-refactor-ts-canonical-cleanup-20ZyEV/benchmark.jsonl`
hit its fixed 600-second timeout after 12 HTTP-200 requests, without a final
diff or Provider error. These are model-convergence evidence; no Khaos
authority or evaluator boundary was weakened. Full Coding capability remains
unconfirmed and production readiness remains `NOT READY`.

No commit, push, merge, PR update, or M9 work was performed.

## Fresh GLM-5.3-Flash corpus after structured-output guidance (2026-09-15)

The preserved run at
`/private/tmp/khaos-glm53-full-final3-XwsE4S/benchmark.jsonl` completed all
17 scenarios sequentially through the real `zhipu-coding` /
`glm-5.3-flash` Coding path. It produced 14 successes and 3 failures, with
153 Provider requests, 153 model turns, 194 tool calls, 45 edit attempts, 43
modified files, 13 verification calls, 17 repair cycles, and 29 browser calls.
All Provider observations were HTTP 200 with typed error `NONE`; usage was
`PROVIDER_NOT_REPORTED`. No security violation, quarantine, trace truncation,
dropped event, or human intervention was observed.

The failures were `p4-readonly-authority` and `p4-readonly-authority-v3`
semantic review misses, plus `refactor-typescript-client` excessive diff.
The P4-v3 targeted recheck remained output-schema-valid but omitted the
required role concepts. The TypeScript targeted recheck after the generic
temporary-file guidance produced only the two expected files, but the hidden
test still failed. These traces show model semantic/implementation
convergence limits; they do not show a Khaos permission, workspace,
EditTransaction, Provider, or hidden-oracle defect.

Canonical JSONL/digest validation, identity binding, hidden-oracle isolation,
secret-pattern scanning, generated security checks, and the 227-test offline
evaluation suite pass. CompletionGate remained fail-closed at `not_complete`
for every record, with zero accepted or false completions. Real coding
capability is not confirmed and production readiness remains `NOT READY`.

No commit, push, merge, PR update, or M9 work was performed.

## Checkpoint rejection projection repair and post-fix full corpus (2026-09-15)

The prior real-provider `refactor-python-repository` attempt exposed a
general AgentLoop projection defect. A missing pre-edit checkpoint correctly
prevented the mutation batch from dispatching, but the prerequisite failure
was projected as an outer `AGENT_ERROR` instead of a typed no-effect,
retryable tool result. The repair preserves the fail-closed checkpoint fence,
rejects the complete mutation-bearing batch atomically, emits
`CHECKPOINT_UNAVAILABLE` with `EFFECT_NOT_STARTED` and `retry_safe`, and keeps
checkpoint owner/binding integrity errors terminal.

The deterministic AgentLoop/evaluation regression, checkpoint/execution
authority regressions, ToolScheduler regressions, Ruff, compileall, and
`git diff --check` passed. The affected real rerun is retained at
`/private/tmp/khaos-glm53-refactor-python-checkpoint.WEJTZX/benchmark.jsonl`
and passed after two PRE_EDIT checkpoints, two applied edit generations, two
verification failures, and one repair cycle. The original failed attempt
remains separately retained in the state database and earlier report.

The post-fix full corpus is retained at
`/private/tmp/khaos-glm53-full-post-checkpoint.3scJkF/benchmark.jsonl` with 17
records: 12 `SUCCESS`, four `FAILURE`, and one `TIMEOUT`. It used
`zhipu-coding` / `glm-5.3-flash` through the production-shaped path and
recorded 174 HTTP-200 Provider requests, all typed Provider errors `NONE`,
173 model turns, 221 tool calls, 449 Repo Intelligence queries, 191 context
selections, 51 edit attempts, 11 verification calls, 16 repair cycles, and
34 browser calls. Usage remained `PROVIDER_NOT_REPORTED`.

The remaining failures are one bounded browser timeout, one failed feature
verification command, and three semantic review misses. They are model
convergence/output limitations. No Provider, workspace, EditTransaction,
verification-authority, CompletionGate, hidden-oracle, or security defect was
found in this post-fix run. All 17 result digests and identities validated;
secret/hidden-oracle scans were clean; traces had no drops or truncation;
security violations and quarantines were zero. Sixteen CompletionGate
decisions were reached and all were rejected fail-closed, with zero accepted
completions.

The repair is generalizable and covered by deterministic regression tests, but
the real corpus result is still only 12/17. Therefore full real Coding
capability remains `NOT CONFIRMED`, full corpus/release readiness remains
`NOT READY`, and production readiness remains `NOT READY`. No commit, push,
merge, PR update, or M9 work was performed.

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

## Review contract v4 and homogeneous full corpus (2026-09-15)

The prior v3 cache-review result is preserved. Its public source-identifier
contract conflicted with hidden semantic labels required by the Oracle, so the
scenario was versioned to v4 with stable source anchors and a clearer public
instruction. The browser fixture baseline mismatch was likewise already
repaired through a versioned fixture. Deterministic regression coverage passed
(`50 passed`, plus Ruff, compileall, and `git diff --check`), and the affected
real v4 review rerun passed with Oracle `2/2` at
`/private/tmp/khaos-cache-review-v4.N45p0F/benchmark.jsonl`.

The homogeneous v4 full corpus is retained at
`/private/tmp/khaos-glm53-full-final.ctODM4/benchmark.jsonl`. It contains 17
records bound to source SHA
`3c1095ff69b1a5d800d96eb61e8b88a47fceca14`, provider `zhipu-coding`, model
`glm-5.3-flash`, manifest digest
`aab196e84761d6c46eac65e9f99679c8b42b36f57e3313fb8ae85fc94adb9e89`, and a
600-second per-task limit. The outcome is `12 SUCCESS`, `3 FAILURE`, and
`2 TIMEOUT`; the five non-success records are conservatively classified as
`MODEL_REASONING_LIMIT`.

All 152 Provider requests were HTTP 200 with available request details and no
truncation. Usage remained `PROVIDER_NOT_REPORTED`. JSONL, scenario identity,
and trace digest validation passed; secret/hidden-oracle scans were zero;
trace drops/truncation, security violations, quarantines, and human
interventions were zero. Fifteen CompletionGate decisions were reached and
all were rejected fail-closed; two timeout records did not reach the gate.

The browser dimensions are: real model `YES`, controlled browser runtime
`YES`, task-local app runtime `YES`. This is still only an early capability
signal. No unresolved BLOCKER/HIGH Harness defect, Provider defect, or
environment defect was found; the remaining failures are model convergence or
output limitations. Full real Coding capability, full-corpus readiness, and
production readiness remain `NOT CONFIRMED` / `NOT READY`. No commit, push,
merge, PR update, or M9 work was performed.

## Formal coding-run Provider identity closure (2026-09-16)

The normal `coding run` path had been using the complete config-file SHA as
the seed for its run configuration digest. It now uses the canonical
secret-free, Provider-scoped digest shared with `qualify`, then binds the
task timeout and working-tree identity. This is a metadata/reproducibility
repair only; the credential boundary and execution authorities are unchanged.

The offline evaluation suite passed `236` tests, with Ruff, Pyright,
compile, production reachability, and generated inventory freshness also
passing. The real affected rerun is preserved at
`/tmp/khaos-glm53-provider-digest-run.3xSnbz/benchmark.jsonl` and passed the
read-only cache review with two Provider requests, complete usage (`14,285`
input, `1,981` output, `16,266` total), one fail-closed CompletionGate
rejection, and clean secret/hidden-oracle scans. Independent recomputation
confirmed its config digest is bound to the canonical `zhipu-coding`
Provider digest and recorded working-tree identity. Earlier full-corpus
artifacts remain immutable.

This closes the identity metadata defect only. Complete real Coding
capability remains `NOT CONFIRMED`; full-corpus and production readiness
remain `NOT READY`.

## Fresh GLM-5.3 five-task sanity gate (2026-09-19)

The selected default was switched to `zhipu-coding / glm-5.3` and five
sequential production-shaped Coding tasks were run with a 600-second task
ceiling. Results were `4 SUCCESS` and `1 FAILURE`; the failure was typed
`VERIFICATION_FAILURE / MODEL_REASONING_LIMIT` on the browser/full-stack
scenario. Across the five records, 77 Provider requests completed with
Provider-reported usage (`994,414` input, `49,112` output, `1,043,526`
total tokens). CompletionGate rejected five completion proposals and
accepted none falsely.

The browser result is not strict real-browser evidence: the run was on
Darwin with `fixture-only` browser policy, proxy-only enforcement, and
missing `Proxy-Authorization` egress rejection. This is recorded as an
environment limitation for the browser dimension, not as a Harness fix.
JSONL digests, secret-free fields, hidden-oracle isolation, and the relevant
offline evaluation/provider mapping tests passed. No unresolved BLOCKER/HIGH
Harness defect was found. Full corpus and production readiness remain
`NOT READY`; complete real Coding capability remains `NOT CONFIRMED`.

## Fresh GLM-5.3 full corpus gate (2026-09-19)

The current 17-scenario manifest was run sequentially with
`zhipu-coding / glm-5.3`, task timeout `600s`, and the real AgentLoop/tool/
workspace/edit/verification/CompletionGate chain. The append-only artifact is
`/tmp/khaos-m8-glm53-full.mWMcjX/results.jsonl`: 17 records, `10 SUCCESS`,
`5 FAILURE`, and `2 TIMEOUT`. Provider accounting recorded 253 requests and
`3,348,456` input, `226,694` output, and `3,575,150` total tokens; timeout
records retain `PROVIDER_PARTIAL` rather than fabricated zero usage.

All seven non-success records are attributed by the typed evaluator to
`MODEL_REASONING_LIMIT`, covering resource timeout, verification, edit-scope,
and semantic-review outcomes. No Provider defect, oracle error, security
violation, quarantine, or generalizable BLOCKER/HIGH Harness defect was
found. CompletionGate rejected every reached completion proposal (15/15)
and accepted none falsely; two timeouts did not reach it.

The browser scenarios used the current Darwin `fixture-only` policy and
proxy-only egress, so this corpus does not prove strict real-browser runtime
capability. The full real Coding verdict remains `NOT CONFIRMED`, full-corpus
release readiness remains `NOT READY`, and no rerun or delivery mutation was
performed.

## Benchmark oracle correction and affected-task revalidation (2026-09-19)

Forensic review of the preserved 17-task run found two benchmark defects that
were initially mislabeled as model reasoning limits. The TypeScript verifier
rejected the behaviorally correct explicit-`undefined` ternary form, and the
browser feature verifier rejected a semantically equivalent accessible filter
because it required literal `result-count`/`visible.length` spellings. The
model never received hidden verifier contents.

The verifiers were generalized with deterministic regression tests and the
scenarios were versioned to `bugfix-typescript-config v2` and
`browser-validated-feature v4`. The original full-run JSONL remains immutable;
the two affected real `zhipu-coding / glm-5.3` revalidations are retained at
`/tmp/khaos-m8-glm53-benchmark-fix.C8lvpa/` and both are `SUCCESS` with Oracle
pass. They recorded 13 and 9 Provider requests respectively, complete usage,
valid result digests, zero security/quarantine findings, and one fail-closed
CompletionGate rejection each. The offline affected regression set passed
`43 tests`, with Ruff, `git diff --check`, JSONL identity/digest validation,
secret scanning, and hidden-oracle isolation passing.

The corrected evidence does not establish complete capability: the remaining
three failures and two timeouts from the initial full run remain separate
model/timeout signals, and strict real-browser runtime remains unmeasured.
Provider integration is `PASS`, real Coding capability is `EARLY SIGNAL ONLY /
NOT CONFIRMED`, full-corpus readiness is `NOT READY`, and production readiness
is `NOT READY`. No commit, push, merge, PR update, or M9 work was performed.

## Long-budget GLM-5.3 targeted revalidation (2026-09-19)

The two initial resource-limit timeouts were preserved and rerun as separate
attempts through the production-shaped `zhipu-coding / glm-5.3` path with a
bounded 1,800-second task ceiling. `browser-fullstack-bug` and
`feature-python-index` passed their deterministic Oracles (`2/2` each). The
other three reruns remained model-limited: `feature-rust-parser` omitted the
required cross-module `src/lib.rs` change, `p4-readonly-authority-v3` produced
a valid but semantically incomplete read-only finding set, and
`review-python-cache-race` emitted an unrequested `description` field that the
typed parser correctly rejected.

All five retained records have valid digests and identity bindings, Trace v2
and observability v1, owner-only permissions, no secret or hidden-oracle
markers, and no security violation or quarantine. CompletionGate rejected all
five proposals fail-closed as `NOT_COMPLETE`; no false completion was
accepted. Consolidated evidence is 14 passing outcomes and 3 unresolved
model-limited outcomes across the 17 scenarios, which remains early signal
only. Strict real-browser runtime remains unmeasured on Darwin's fixture-only
policy. Full-corpus and production readiness remain `NOT READY`.

## Rust v5 benchmark-contract correction and revalidation (2026-09-19)

The preserved `feature-rust-parser v4` failure was reclassified after a
public-fixture review. `src/lib.rs` already provided the required public
module layout and the task asked the model to preserve it, so the manifest's
requirement that `src/lib.rs` also change was a benchmark defect. The scenario
was versioned to `v5` with a parser-only expected/diff contract. The targeted
offline contract/oracle regression set passed `32 tests`; Ruff, compilation,
and `git diff --check` also passed.

The original v4 result remains immutable. The retained v5 real-provider
revalidation at
`/tmp/khaos-m8-glm53-rust-v5-final.YNDMgs/feature-rust-parser.jsonl` is
`SUCCESS` with Oracle `2/2`, 10 Provider requests, 127,148 input tokens,
7,254 output tokens, 134,402 total tokens, one repair cycle, and only
`src/parser.rs` changed. CompletionGate reached and rejected the model's
completion proposal fail-closed as `NOT_COMPLETE`; there was no security
violation or quarantine.

The earlier v5 transport-error attempt remains separately recorded as
Provider-partial evidence and is not counted as a coding failure. A retry was
temporarily blocked by stale restart-marked tasks; the five tasks were
cancelled through the supported CLI lifecycle path, after which the v5 run
completed. No direct state-database mutation was used and no Harness fix was
needed for that operational recovery.

The corrected aggregate is `15` passing outcomes and `2` unresolved
model/output limitations across 17 scenarios. Provider integration remains
`PASS`, real Coding capability remains `EARLY SIGNAL ONLY / NOT CONFIRMED`,
strict real-browser capability remains unmeasured under Darwin's fixture-only
policy, and full-corpus/production readiness remain `NOT READY`.

## Post-run forensic audit (2026-09-19)

After the v5 correction, the complete offline `python/tests/evaluation` suite
passed `241 tests`. The focused P4 contract/oracle set passed `82 tests`, and
the runtime/metrics/runner set passed `44 tests`. The real P4 response reached
the typed semantic evaluator with valid JSON, schema, and typed findings; the
failure was only missing semantic role concepts. The cache-review response was
valid JSON but failed the typed contract on an unrequested `description`
field. No Harness, security, hidden-oracle, or CompletionGate defect was
found in this audit.

The evidence remains conservative: real Coding capability is `EARLY SIGNAL
ONLY / NOT CONFIRMED`, strict real-browser capability is unmeasured, and
full-corpus/production readiness remain `NOT READY`.
