# Khaos M8 Release Hardening

This is the current evidence-bound release-hardening report for the existing
`codex/m8-coding-evaluation` branch. It deliberately separates local working
tree evidence from the already verified exact-SHA CI evidence for
`3c1095ff69b1a5d800d96eb61e8b88a47fceca14`.

## 0.0 Latest real-provider run (2026-09-15)

The latest evidence is a real `zhipu-coding` / `glm-5.3-flash` run through the
production-shaped Coding AgentLoop and controlled browser path. The post-fix
17-scenario corpus produced 12 SUCCESS, three FAILURE, and two TIMEOUT. The
review scenario is now version 4 after a general source-identifier contract
repair; the browser fixture baseline mismatch was previously versioned and
repaired. Remaining failures are retained as model convergence/output
limitations; no model-specific Oracle workaround was added.

The sanitized JSONL artifact is
`/private/tmp/khaos-glm53-full-final.ctODM4/benchmark.jsonl`; schema/digest
validation, hidden-oracle isolation, and secret-pattern scan passed. Provider
token usage remains `PROVIDER_NOT_REPORTED`. CompletionGate was reached 15
times and remained fail-closed with zero accepted false completions; two
timeout records did not reach it.

```text
Provider integration: PASS
Real-provider capability: EARLY SIGNAL ONLY / NOT CONFIRMED
Full corpus infrastructure readiness: READY
Production readiness: NOT READY
```

### P4-v3 targeted follow-ups

The first full-corpus result and both subsequent affected-scenario attempts
are retained separately. After the general Coding prompt was clarified for
machine-readable output and source-grounded identifiers, each targeted
attempt reached `PLAIN_JSON_OBJECT` with passing schema and typed parsing, but
the model still failed the semantic review. This is a reproducible
`MODEL_LIMITATION`, not a reason to weaken the strict parser or hidden Oracle.
The targeted offline tests passed (`54 passed`) and the evaluation suite
passed (`227 passed`). Full real-provider capability remains unconfirmed.

## 0.1 Credential isolation security-gate checkpoint (2026-09-12)

This checkpoint did not execute a live Provider request or any real-agent
sanity task. It is limited to synthetic security contracts and targeted local
regressions; the historical real-provider results in Section 5 remain
unchanged and are not being reclassified as fresh evidence.

The provider path is now secretless by contract: opaque `credential_ref`
configuration, the canonical CredentialBroker, platform-store abstraction,
transport-only resolution, exact-value redaction, task HOME/TMP isolation, and
fail-closed legacy environment/secret fields. Memory HTTP credentials use the
same broker instead of an `api_key_env` fallback. The targeted regression set
passed with `83 passed, 1 skipped`; the evaluation-contract subset passed with
`27 passed`, and the CLI/RPC/Memory subset passed with `57 passed, 4 skipped`.
The native macOS Keychain round-trip was attempted once with a synthetic
credential and returned a generic host write failure. It did not block or
expose a secret, so it is classified as `ENVIRONMENT_BLOCKED` and not retried.
Ruff/Pyright are unavailable in the local virtual environment. Full
real-provider readiness remains `NOT READY`.

Previously exposed provider credentials remain compromised and still require
rotation. No credential value is recorded in this report.

## 1. Release Candidate SHA

The verified M8.8 baseline SHA is:

`3c1095ff69b1a5d800d96eb61e8b88a47fceca14`

The current evaluation-plane changes are uncommitted working-tree changes and
are not represented by that SHA.

## 2. Security Gate Status

PASS for the baseline SHA. The ten required attempt-1 GitHub workflows are
terminal `completed / success`; their run IDs are recorded in
[the M8.8 closure report](m8.8-browser-app-coding-closure.md#43-ci-evidence).

The protected untracked `docs/local-security-closure-report.md` remains
untracked and 851 bytes; it was not edited or staged.

## 3. Full Regression

The earlier full local regression, before the final provider-evaluation
classification additions, reported:

- Python: `5482 passed, 50 skipped`.
- Go: `make test-go` passed for all tested packages.
- Rust: `make test-rust` passed, including 18 library tests and 5 launcher
  receipt tests.
- The final affected-path regression reported `146 passed`; touched-file Ruff,
  Python compile, and `git diff --check` also passed.

These are local results. They do not extend the baseline SHA's remote CI
evidence to the uncommitted working tree.

## 4. Platform Matrix

The checked-in platform and security matrix remains the authority for
Linux/Docker, macOS, Windows, browser-kernel, and native-helper applicability.
This macOS run does not replace Linux kernel, Docker, Windows native, or
hosted-provider evidence. Platform-specific skips remain explicitly skipped.

## 5. Real-provider smoke and sanity

The host credential authority resolved `zhipu-coding` / `glm-5.2`. One minimal
request returned `ACK` through the Khaos provider abstraction. Secret leakage
checks over the generated artifacts found no authorization header, bearer
value, provider token, or API-key-shaped value. Usage is explicitly unavailable
from the current streaming adapter.

Five sequential task attempts were completed under the existing bounded
sanity configuration; all five distinct scenarios timed out. Two provider-side
empty-response cases were classified `PROVIDER_DEFECT`. Real trajectories
exposed and were followed by generalizable Harness fixes for injected
Git/terminal authority arguments and the Registry-injected `workspace_manager`
argument for `test_run`. The remaining coding trajectories were classified as
model tool-use limits. No unresolved BLOCKER/HIGH Harness defect remains from
this run. The browser-tagged task used the real model but recorded no browser
session or browser action, so real-browser readiness remains unknown.

The append-only raw JSONL and separately classified, policy-bound JSONL are
stored under `/tmp/khaos-m8-real-sanity.8w7Hcy/`; the five-task final view is
`results-final-selected-v2.jsonl`, and original attempts were not overwritten.

## 6. Crash / Restart

Existing Python, runtime, scheduler, tool, browser, and subagent restart
regressions passed in the full suite. No new real-provider crash/restart run
was performed in this bounded sanity phase.

## 7. Cancellation

Existing cancellation, timeout, quarantine, process-terminal, and scheduler
recovery tests passed. Real-provider cancellation and long-running task
supervision remain `NOT RUN`.

## 8. Process / FD / Memory Leaks

The existing bounded process, descriptor, credential-host, browser cleanup,
and event-loop tests passed. A real-provider soak/leak measurement was not run;
therefore no production leak claim is made here.

## 9. Worktree Cleanup

Fixture cleanup and workspace security tests passed. The evaluation writer uses
bounded append-only output and no-follow file handling. A real-repository
multi-task cleanup soak remains `NOT RUN`.

## 10. Browser Cleanup

Existing browser cleanup, egress, lifecycle, and TCB tests passed. The real
provider browser coding benchmark remains `NOT RUN`; the M8.8 report keeps its
capability delta `UNKNOWN`.

## 11. MCP Cleanup

Existing MCP admission, hooks, skills, and extension-plane tests passed. No
new MCP resource was claimed by the provider preflight probe.

## 12. DB / Migration

The full Python suite, including migration, owner-scope, audit, and repository
boundary tests, passed. The new benchmark JSONL artifact is independent of the
durable capability-evaluation ledger and does not introduce a database schema
change.

## 13. Large Repo

The pre-repair deterministic pack contained 15 isolated scenarios; the
current working-tree manifest contains 16 after adding versioned P4-v2
qualification. A meaningful 20-task minimum real-repository corpus (30–50
target) has not run, so large-repository behavior is `UNKNOWN`.

## 14. Long-Horizon

The checked-in pack contains no long-horizon scenario. Contract support for
`long_horizon` was added, but execution evidence is `NOT RUN`.

## 15. Performance

The full local regression completed without a failure. No real-provider
latency, token, tool-call, parallelism, or soak baseline exists yet.

## 16. Packaging

Existing native packaging, launcher, receipt, and production-reachability
checks passed. Provider packaging and deployment reproducibility are not
closed by a local model-unavailable probe.

## 17. Doctor

The effective provider configuration is now usable for a minimal real request.
No credential material was copied into the repository, task prompts, traces,
or result artifacts.

## 18. Documentation

The M8.8 closure report now reflects exact-SHA success and preserves the
real-provider `UNKNOWN` boundary. The capability and closure reports link to
this hardening report instead of combining raw evidence into one file.

## 19. Known Limitations

- Provider usage accounting is unavailable from the current streaming adapter.
- Provider stability is not sufficient to treat the five-task sanity as a
  capability result.
- Layer B real-repository and Layer C long-horizon evaluation are not run.
- Browser coding capability with a real provider is not proven.
- No same-model harness delta, competitor comparison, or human-intervention
  rate is available.
- Local working-tree changes have no remote exact-SHA CI evidence yet.

## 20. BLOCKER/HIGH Status

No unresolved code/security BLOCKER or HIGH Harness finding remains from this
sanity phase. Provider stability and secure real-browser availability remain
evaluation release blockers, not reasons to weaken provider, approval,
workspace, or execution authority.

## 21. Release Verdict

```text
Engineering hardening: PASS for the verified baseline and local regression
Security hardening: PASS for the verified baseline; local checks PASS
Provider integration: PASS
Real-provider sanity: PARTIAL
Real-provider capability: UNMEASURED
Release candidate: NOT READY
```

The next release gate is a stable full-corpus run and failure analysis. No
secret should be placed in the repository or chat.

## 22. GLM-5.3-Flash stabilization gate

The `zhipu-coding` / `glm-5.3-flash` provider passed the real router smoke
and the real AgentLoop tool microprobe. The five-task sequential sanity set
completed with five bounded `TIMEOUT` results; the model reached planning and
tool admission on every task, but only the Python cache task reached a patch
and targeted-test attempt. The browser-tagged task made zero browser calls,
so strict real-browser capability is still `UNMEASURED`.

Usage and provider-returned model identity were not reported by the current
streaming adapter and are recorded as `UNKNOWN_PROVIDER_NOT_REPORTED`; no
zero values were synthesized. The credential was resolved from the existing
owner-only Khaos user configuration for this local run; no key was placed in
prompts, traces, JSONL, repository files, or the durable state database.

The gate fixed and regression-tested the state-root `0600` creation defect and
the provider-error classification defect. Repeated non-fatal native-memory
`IntegrityError` diagnostics were observed during task-local failure-memory
admission; they did not affect the authority chain or task result and remain a
low-priority observability candidate, not a release-blocking finding.

The conservative verdict remains: provider integration `PASS`, real-provider
sanity `PARTIAL`, full real capability `UNMEASURED`, and production readiness
`NOT READY`. The full corpus was not started.

## 23. Post-sanity Harness repairs

The original five-task JSONL and the separate Task 1 state-root rerun remain
preserved. A subsequent bounded rerun is stored at
`/tmp/khaos-m8-glm53-sanity.jQ5ITb/results-after-tool-budget-fix.jsonl`, and
the affected browser-task rerun is stored at
`/tmp/khaos-m8-glm53-sanity.jQ5ITb/results-task5-after-sandbox-capability-fix.jsonl`.

Two generalizable Harness defects were fixed with deterministic regressions:
parallel tool budget reservations now defer temporarily unreservable calls
instead of emitting false reservation failures, and the workspace sandbox
now admits the registered Coding Repo Intelligence and M8.8 browser tools
under their existing workspace/approval contracts. The final affected
regression set passed (`242 passed`, one existing warning); no commit or push
was performed.

The reruns still produced bounded timeouts and no browser runtime call. The
remaining signal is conservative model/tool-use limitation plus the separate
Go sandbox executable availability boundary; it is not evidence for full
provider capability. Full-corpus readiness remains `NOT READY`.

## 24. GLM-5.3-Flash tool-use convergence closure gate

The controlled 2026-09-11 follow-up used the real `zhipu-coding` /
`glm-5.3-flash` provider through Khaos production authorities. It preserved
four new JSONL records rather than overwriting prior attempts. Two early Task
1 records exposed and reproduced general tool-contract defects; the repaired
Task 1 attempt successfully applied the correct cache patch but timed out
before verification. A secondary feature attempt recorded an empty provider
response and no model/tool turn, so it is a provider-boundary observation,
not a coding score.

The repaired contracts cover one-based bounded file pagination, transactional
parent-directory creation, common process metadata injection for test
execution, and sandbox execution injection. Deterministic affected tests
passed (`140 passed, 6 skipped`) and evaluation contract tests passed (`32
passed`). The four typed records validate with their run/config/policy/
scenario/trace digests; usage is `UNKNOWN / PROVIDER_NOT_REPORTED`. No secret
leak, security violation, false completion acceptance, or human intervention
was observed. A full Python suite was observed through `2345 passed, 22
skipped, 1 warning` and then intentionally interrupted as incomplete.

No real browser runtime or real app process ran in this phase. The resulting
release gate remains: provider integration `PASS`, real-provider sanity
`PARTIAL`, full real capability `UNMEASURED`, and production readiness
`NOT READY`. No commit or push was performed.

## 25. GLM-5.3-Flash completion convergence probe

The bounded 2026-09-11 probe used `zhipu-coding` / `glm-5.3-flash` through the
real Khaos AgentLoop path and changed only the primary Task 1 total timeout
from 120 to 240 seconds at runtime. The scenario/manifest/policy/fixture
identity and runtime tool/budget policies stayed constant. Because generic
timeout override plumbing and two real Harness fixes were introduced between
attempts, this is a controlled operational probe, not a same-source-SHA
benchmark comparison. The complete corpus was not started.

The preserved 240-second records are:

| Record | Result | Primary evidence |
| --- | --- | --- |
| `m8-5a4b2c37d69b40ca906b68e506f18fd7` | `TIMEOUT` | `file_search_content` omitted-path schema/handler mismatch; 9 turns, 16 tools, no verification. |
| `m8-4fe1ed7b801744ec98b181f91d350ea6` | `TIMEOUT` | Relative `test_run` cwd escaped the handler's process-directory resolution; 2 attempted tests were rejected before execution. |
| `m8-467749cd35834df4b3b5874e9095b685` | `TIMEOUT` | After both fixes, no Harness contract error appeared; model tool-use remained non-convergent and macOS developer tooling blocked `git_diff`. |

The two contracts were repaired without weakening workspace or execution
authority, and the affected regression set passed (`125 passed, 1 warning`).
Ruff, compilation, and `git diff --check` passed. JSONL schema/digest
validation passed for the 120-second baseline plus all three 240-second
records; hidden-oracle isolation remained intact, but the oracle did not run
after timeout. Usage is `UNKNOWN / PROVIDER_NOT_REPORTED`, CompletionGate is
unproven, repair cycles are zero, and strict real-browser capability is
unmeasured.

The generated artifact/state scan found no secret. One operator diagnostic
search in the session did print host configuration credential lines by mistake;
no key was committed or written to the repository, JSONL, or state database,
but the session-level secret check is intentionally `FAIL` and must not be
converted into a release pass without handling that exposure. The release
verdict therefore remains provider integration `PASS`, completion convergence
`FAIL`, full corpus `NOT READY`, and production readiness `NOT READY`.

## 26. GLM-5.3-Flash model capability disambiguation gate

On 2026-09-11, a bounded A/B gate exercised the real Khaos AgentLoop and
production coding path at HEAD `3c1095ff69b1a5d800d96eb61e8b88a47fceca14`.
Model A was `zhipu-coding / glm-5.3-flash`; Model B was
`nvidia / deepseek-ai/deepseek-v4-flash-0731`. Both used the same deterministic
cache-bug scenario and identity digests, with a 240-second, 128-turn,
512-tool-call budget, network disabled, and no browser runtime.

The NVIDIA smoke request and a read-only real-AgentLoop `read_file` probe both
passed. Provider usage and returned model identity were unavailable and remain
explicitly unknown. The first NVIDIA primary attempt timed out in a redacted
`ReadTimeout` before any model turn; that record is preserved. A generalizable
runner fix now maps redacted provider timeout class names to `PROVIDER_FAILURE`,
and the preserved second attempt confirms the corrected taxonomy. The GLM
primary attempt produced 7 turns and 14 tool calls, one applied edit, and one
failed test attempt before the 240-second bound; it did not reach verification
or CompletionGate. This is insufficient to claim real coding capability and
does not establish a Harness defect.

All three current JSONL records passed schema, digest, and hidden-oracle
checks. The current run artifacts and state databases passed the credential
scan; the historical diagnostic exposure and operator-attested key rotation
remain separately recorded. No browser/app runtime, secondary task, or full
corpus was run. Release status remains provider integration `PASS`, real
capability `EARLY SIGNAL ONLY` / `UNMEASURED`, full corpus `NOT READY`, and
production readiness `NOT READY`.

## 27. SiliconFlow Qwen3.8-27B controlled model disambiguation gate

The 2026-09-11 controlled gate resolved the actual current configuration as
`siliconflow / Qwen/Qwen3.8-27B` on branch `codex/m8-coding-evaluation` at
HEAD `3c1095ff69b1a5d800d96eb61e8b88a47fceca14`, with the pre-existing dirty
working tree preserved. The historical GLM evidence was not reused as a
same-state control. A fresh GLM run was not started because the required Qwen
pre-Coding microprobe failed.

SiliconFlow Provider Smoke passed through the Khaos Router and returned the
exact bounded acknowledgement. Model identity and usage fields unavailable
from the adapter remain explicitly unknown. The real AgentLoop microprobe
reached planning, then received a provider HTTP 400 before any tool call or
tool result; the typed failure was surfaced as `MODEL_UNAVAILABLE`. This is
not valid tool-use or coding-capability evidence, so no Coding task, secondary
task, browser task, or full corpus was launched.

The post-run secret scan passed with no current key or API-key-shaped match and
no printed secret. No Harness code was changed and no new Coding JSONL result
was fabricated. The A/B comparison is `INVALID`, Khaos closed-loop capability
is `NOT PROVEN`, real coding capability is `UNMEASURED`, full corpus readiness
is `NOT READY`, and production readiness remains `NOT READY`.

## 28. SiliconFlow Qwen3.5-27B tool-calling and closed-loop validation gate

The 2026-09-11 gate resolved the actual configured model as
`siliconflow / Qwen/Qwen3.5-27B` at HEAD
`3c1095ff69b1a5d800d96eb61e8b88a47fceca14` on
`codex/m8-coding-evaluation`; the dirty working tree was preserved. Provider
Smoke passed with exact ACK and `end_turn`. A minimal single-function
`probe_echo` request also passed through Khaos ModelRouter/ModelClient with a
valid normalized tool call.

The real AgentLoop read-only microprobe reached planning but received a
provider HTTP 400 before any production tool operation or result. The typed
failure was surfaced as `MODEL_UNAVAILABLE`; no Coding task was launched. The
result is classified as a provider/endpoint production-tool-surface
compatibility failure, not a model coding failure. No Harness change or
provider workaround was applied.

The post-run credential scan passed with no exact or shaped secret match and no
printed secret. No current Qwen3.5 Coding JSONL record exists because the
pre-Coding gate failed. Minimal tool compatibility is `PASS`, AgentLoop tool
compatibility is `FAIL`, closed-loop validation is `FAIL`, capability
disambiguation is `INCONCLUSIVE`, full corpus readiness is `NOT READY`, and
production readiness remains `NOT READY`.

## 29. SiliconFlow Qwen3.5-27B production tool-surface compatibility bisect

The follow-up was intentionally limited to provider compatibility and stopped
before Coding. At the same HEAD `3c1095ff69b1a5d800d96eb61e8b88a47fceca14`,
the preserved production request differed from the passing minimal request in
both tool surface and message history. Bounded live probes ruled out the
production tool count and schemas: all 1/4/8/12-tool prefixes were accepted
with minimal messages. Message bisection showed that every individual system
message was accepted but every pair was rejected with HTTP 400. The exact
provider limitation is therefore multiple-system-message rejection by the
SiliconFlow Qwen3.5 endpoint.

The provider boundary now owns a capability profile and merges multiple
system messages deterministically for SiliconFlow. It preserves user/tool
message order and fails closed if merging would discard system tool calls. A
related error-path hardening change removes raw streamed provider response
bodies from `ProviderError`/audit text and retains only the HTTP status.
Routing/provider regression coverage passed (`86 passed, 1 warning`), as did
Ruff, Pyright, compileall, and `git diff --check`; secret scans found no key
or raw provider-error marker.

P0 text smoke, P1 minimal tool calling, and P2 full 12-tool production-surface
acceptance passed. One real post-fix AgentLoop run executed `read_file`,
received the result, continued, and completed. A later non-tool completion is
preserved as a model tool-choice limitation and was not repeatedly rerun. The
SiliconFlow production tool-surface gate is `PASS` and real AgentLoop
tool-calling is `PROVEN`; closed-loop Coding is merely ready for a separate
authorized phase. Full corpus and production readiness remain `NOT READY`.

## 30. SiliconFlow rate-limit attribution and closed-loop revalidation gate

The 2026-09-11 run used `siliconflow / Qwen/Qwen3.5-27B` at exact HEAD
`3c1095ff69b1a5d800d96eb61e8b88a47fceca14` on
`codex/m8-coding-evaluation`. The protected local security closure report
remained untracked, unchanged, and unstaged.

The provider adapter now has bounded request observability and safe error
handling. Only status, bounded timing, request id, allowlisted rate-limit
headers, typed provider error metadata, and bounded retry delay are observed;
raw provider response bodies are not read into errors or durable audit data.
Three-attempt retry behavior is bounded, `Retry-After` is capped and honored
when present, exponential fallback delays are 100ms/200ms, and cancellation
is preserved. Deterministic routing/error/model-client regression coverage
passed: 41 targeted tests passed, with Ruff, Pyright, compileall, and
`git diff --check` passing.

The post-change capacity gate passed P0 text, P1 tool, and sequential P2
probes (4 observed attempts, all HTTP 200). The real AgentLoop `read_file`
microprobe also passed. One and only one valid Coding revalidation was then
allowed. It ran 21 model turns and 21 tools before a final logical request
returned HTTP 429 three times; the adapter recorded 24 attempts total (21
HTTP 200, 3 HTTP 429). No Retry-After or rate-limit window headers were
provided, so the subtype remains `UNKNOWN`. The provider-side rate limit is
the primary failure; it is not a Harness defect and was not chased with
additional stochastic reruns.

The immutable JSONL record is schema/digest-valid and the state ledger holds
86 bounded trace events. No CompletionGate decision, full Coding success,
browser runtime, secondary task, or full corpus was started. Provider
integration is `PASS`, capacity evidence is `PASS` for low-concurrency
probes, closed-loop revalidation is `FAIL` because the only valid Coding run
was provider-invalidated, full real coding capability is `UNMEASURED` with
an early signal only, full corpus readiness is `NOT READY`, and production
readiness remains `NOT READY`.

## 31. Stable provider Model-B selection gate

The 2026-09-12 selection gate preserved the existing branch and dirty tree at
HEAD `3c1095ff69b1a5d800d96eb61e8b88a47fceca14`. Working-tree identity was
`3c93f6bd6a470d459b51525bbdec375ca4e833b09e14dcbffb20595f3b1cc32e`.
The protected untracked local security report was unchanged and unstaged; its
SHA-256 remained
`85dbfe1ee17475154a0f48a6d308750b252aec75f3b67dd4f2e47f06b25597a1`.

The only eligible Model-B candidate after the required exclusions was NVIDIA
`deepseek-ai/deepseek-v4-flash-0731`. It passed text, minimal-tool,
production-read-only-tool, and real-AgentLoop read-file probes. It failed the
bounded sustained-session prerequisite: one initial provider transport timeout
and one permitted fresh replacement that produced four HTTP 200 requests and
16 read-only tool calls before a fifth request timed out. The qualification
result is therefore `FAIL`; this is provider reliability evidence, not a
model reasoning failure. GLM-5.3-Flash remains reserved as Model-A, and the
SiliconFlow Qwen3.5-27B 429 evidence remains immutable and excluded.

No `bugfix-python-cache` Coding run was started, no GLM A/B control was run,
and no source change or Harness defect fix was required. The evaluation
integrity subset passed (`27 passed`, one existing warning). Current
credential and Authorization-bearing leak checks were zero; regex-shaped
historical examples were not current secrets. Stable Model-B selection,
closed-loop validation, and full corpus readiness remain `FAIL`/`NOT RUN` and
`NOT READY`, respectively. Production readiness remains `NOT READY`.

## 32. macOS Keychain credential-isolation closure gate

The 2026-09-12 gate preserved exact HEAD
`3c1095ff69b1a5d800d96eb61e8b88a47fceca14` and the existing dirty tree. It
made no real provider calls and read no real credentials. A previous exposed
credential remains compromised and requires operator rotation; no value was
handled in this run.

Security.framework native audit and typed status diagnostics identified
`-25308 / INTERACTION_REQUIRED`: the default/login Keychain requires
interaction in the current session, while Khaos keeps interaction disabled.
This is `OS_POLICY_BLOCKED / ENVIRONMENT_BLOCKED`. The fail-closed boundary,
no-dialog rule, and no-plaintext-fallback rule were preserved. Synthetic
credential and output-firewall regressions passed across provider errors,
tools, audit, memory, supervision, extensions, browser/app diagnostics, and
JSONL. The integrated native sequence was attempted once and stopped at
`put`; no retry or provider benchmark was started. Real capability remains
`UNMEASURED`, full corpus readiness is `NOT READY`, and production readiness
remains `NOT READY`.

## 33. macOS provisioning/runtime credential hardening

Release hardening now separates explicit operator provisioning from normal
runtime use. The operator commands use hidden input and never accept a secret
in argv; runtime status and provider transport calls explicitly disable
Keychain interaction. Provisioning-only model discovery is a named,
provider-discovery-limited path, and the builtin model-visible tool catalog has
no credential provisioning command. Replacement rollback restores the previous
wrapped credential when config publication fails.

The native implementation remains on legacy `SecKeychain*`; the audit records
DPK `NO`, legacy accessibility, no ACL/userPresence/sync/access group, and
runtime UI `FAIL`. The explicit DPK decision is
`PACKAGING_PREREQUISITE_BLOCKS_SWITCH`. The current host's preserved
`-25308 / errSecInteractionNotAllowed` evidence is
`OS_POLICY_BLOCKED / ENVIRONMENT_BLOCKED`; dialogs were not automated and no
plaintext fallback was added. Deterministic credential/provider/CLI tests pass
(`104 passed, 1 skipped` in the final isolated target run), with Ruff,
targeted compileall, and `git diff --check` passing. Real providers, Coding, browser,
and full-corpus evaluation remain blocked; production readiness remains
`NOT READY`; operator credential rotation remains required.

## Local-first session unlock update (2026-09-12)

The production-local design now separates persistent storage from runtime
use. The existing CredentialBroker owns `CredentialSession`; explicit human
unlock loads a provider credential once from the persistent Keychain into a
memory-only wrapped lease, while runtime transport uses the lease and performs
zero Keychain reads or UI interaction. Lock/replace/delete/shutdown/restart
invalidate the lease. Synthetic lifecycle and fake-provider regression passed
with zero real Provider requests.

`SESSION_UNLOCK_CANONICAL` is the local-first decision. The legacy
`SecKeychain*` backend remains supported with its documented macOS compatibility
risk. DPK, stable signed identity, and Apple Developer packaging are optional
future hardening and are not blockers for ordinary local Khaos usage. Full
real-provider capability and production readiness remain `NOT READY`; exposed
historical credentials still require operator rotation.

## Manual native synthetic acceptance (2026-09-12)

The real macOS login Keychain accepted one unique synthetic SET/UNLOCK/REPLACE/
DELETE lifecycle. Safe status stayed locked before unlock; the first unlock
read the persistent store once; three fake Provider requests passed with zero
runtime persistent-store reads and zero runtime Keychain UI. Lock, replacement,
shutdown/restart, replacement unlock, and post-delete `CREDENTIAL_MISSING`
semantics passed. Cleanup reported zero synthetic leftovers.

This confirms the local-first native persistence/session boundary only. No real
Provider, real credential, GLM model, browser benchmark, full corpus, or M9
run was started. DPK and Apple Developer infrastructure remain optional;
historical real credential rotation remains `OPERATOR ACTION REQUIRED`.

## 23. P4 Qualification Harness Repair & Benchmark v2 (2026-09-12)

This is an offline, uncommitted Harness repair gate. Real Provider calls and
real credential reads were `0`; no credential session was unlocked, and no
GLM model, Coding corpus, browser benchmark, or M9 work was started.

Historical P4-v1 remains an immutable `FAIL` caused mechanically by
`TOOL_BUDGET_EXHAUSTED`; its Harness integrity failed and its model-convergence
attribution is invalid/inconclusive. P4-v2 is versioned separately and uses a
small read-only synthetic fixture. The prompt allows natural stopping and
reveals no minimum turns or tools. The runtime now owns the canonical typed
tool budget, while the Trace v2 collector only observes and safely truncates.
Qualification records use typed append-only JSONL with source HEAD, dirty
working-tree, fixture, prompt, system, tool-schema, policy, budget, and opaque
credential-reference identity.

Deterministic fake efficient/normal, over-explorer, wrong-answer, tool-error,
collector-capacity, redaction, pending-result, and hidden-oracle tests passed.
This closes the offline Harness repair gate, not real model capability. Full
real-provider corpus readiness and production readiness remain `NOT READY`.
Details are in the [dedicated P4-v2 report](m8-p4-qualification-harness-repair-v2-closure.md).

## Router import-cycle closure (2026-09-12)

The offline Router dependency-direction gate is closed. The shared workspace
identity now belongs to a neutral security contract module, the planning
compatibility export reuses that canonical object, and the fresh-process import
matrix plus Router/qualification bootstrap pass. No real Provider request,
credential material read, credential unlock, GLM run, browser run, or M9 work
was performed. Real capability and production readiness remain `NOT READY`.

See the [Router import-cycle closure report](m8-router-import-cycle-closure.md)
for the defect classification and verification boundary.

## Qualification observability closure (2026-09-13)

The offline O1-O4 gate passed typed CompletionGate projections, final-response
parser diagnostics, actual Repo Intelligence/Context Engine selection
metadata, timestamp provenance, JSONL legacy reads, and secret-canary tests.
No Provider request or credential read occurred. The full Python suite remains
non-green due to three pre-existing worktree failures; no unrelated fix was
applied. Real capability, full-corpus readiness, and production readiness
remain `NOT READY`. See the [observability closure report](m8-qualification-observability-closure-2026-09-13.md).

## Fresh real-provider corpus evidence (2026-09-14)

The `zhipu-coding` / `glm-5.3-flash` production-shaped Coding run completed
the 17-scenario corpus sequentially. It recorded 4 successes, 9 failures, and
4 bounded timeouts. All 157 observed provider requests returned HTTP 200 with
no typed provider errors; usage was explicitly
`UNKNOWN / PROVIDER_NOT_REPORTED`. Real browser runtime and task-local app
processes were exercised under `fixture-only`/`none` policy, with zero
security violations, quarantines, or trace truncation.

This is early diagnostic capability evidence, not release readiness. The
offline Coding/tool/evaluation regression set passed 2825 tests with 8
expected skips, but model convergence remains insufficient for a complete
coding-capability or production-ready verdict. Full corpus readiness remains
`NOT READY`; no commit or push was performed.

## 34. Final4 provider rerun and offline regression closure (2026-09-14)

The final sequential rerun is preserved at
`/private/tmp/khaos-glm53-full4-20260914/benchmark.jsonl`: 17 records, with 5
successes, 6 failures, and 6 bounded timeouts. The configured provider/model
was `zhipu-coding` / `glm-5.3-flash`; 174 provider requests were observed,
with 173 HTTP 200 responses and one cancellation without an HTTP response.
Usage stayed explicitly `PROVIDER_NOT_REPORTED`; no secret, security
violation, trace truncation, or dropped trace event was recorded. Browser
tasks used the task-local Playwright/app path under fixture-only/no-network
policy.

The only new deterministic regression outside the real traces was a
cache-only `TaskService(db=None)` construction path; it was repaired without
creating a fake supervision authority. Reachability, security, and
privileged-spawn generated inventories were refreshed and checked. The full
offline suite passed `5734` tests with `31` expected skips and one warning.
The conservative release gate remains: Provider Integration `PASS`, Real
Provider Sanity `PASS / PARTIAL`, Full Real Coding Capability `EARLY SIGNAL
ONLY`, Full Corpus Readiness `NOT READY`, and Production Readiness `NOT
READY`.

## Final5 real-provider closure evidence (2026-09-14)

The post-selector-repair run is preserved at
`/private/tmp/khaos-glm53-full5-20260914/benchmark.jsonl`: 17 sequential
records, 7 successes, 7 failures, and 3 bounded timeouts. It used
`zhipu-coding` / `glm-5.3-flash` through the production-shaped Coding path,
observing 149 provider requests (148 HTTP 200 and one cancellation without an
HTTP response), 147 model turns, 200 tool calls, 40 edit attempts, 16
verification runs, 14 repair cycles, and 32 browser calls. Usage remained
explicitly `PROVIDER_NOT_REPORTED`. There were zero security violations,
quarantines, trace truncations, dropped trace events, and human interventions.

The general context defect in which an oversized L0 instruction could remove
the current goal was fixed and regression-tested. Generated inventories are
fresh, the complete offline suite is green at `5741 passed, 31 skipped`, and
JSONL digest/canonical, hidden-oracle, context/provider observability, and
secret-pattern checks pass. The remaining failed scenarios are retained as
model convergence, verification, edit-scope, output-contract, or bounded
resource evidence. Full real coding capability is not confirmed and
production readiness remains `NOT READY`; no commit or push was performed.

## Verification trace observability repair (2026-09-15)

The real-path review found that safe M8.3 verification observations were
written to the session ledger but omitted from the passive Coding trace. The
AgentLoop now persists each observation before streaming it to the collector,
for both normal results and fail-closed infrastructure errors. This is an
observability-only repair: autonomous verification remains advisory and
CompletionGate remains the completion authority. The deterministic regression
and related runtime tests pass (`66 passed`, one existing Hypothesis warning).

Fresh evidence is preserved at
`/private/tmp/khaos-glm53-observability-reprobe-6Ubred/benchmark.jsonl`:
`bugfix-python-cache` passed with 10 provider requests and 2 typed verification
plans. No provider error, security violation, quarantine, trace truncation, or
dropped event was observed. Usage remains `PROVIDER_NOT_REPORTED`; full real
Coding capability and production readiness remain `NOT READY`.

## Full real-provider corpus and contract correction (2026-09-15)

The fresh 17-scenario sequential run is preserved at
`/private/tmp/khaos-glm53-full-v2-final-20260915/benchmark.jsonl`. It used
`zhipu-coding` / `glm-5.3-flash` through the production Coding path and
recorded 10 successes and 7 failures. All 176 Provider requests returned
HTTP 200 with typed error `NONE`; usage was explicitly
`PROVIDER_NOT_REPORTED`. It recorded 176 model turns, 240 tool calls, 49 edit
attempts, 15 verification calls, 17 repair cycles, and 36 browser calls. No
security violation, quarantine, trace truncation, dropped event, or human
intervention was observed.

The fresh run validated the bounded applied-effect receipt repair on
`multifile-python-settings`: an applied edit whose verbose delivery exceeded
the result budget is now represented by a safe typed receipt, with no blind
retry. A separate benchmark-contract ambiguity was corrected by versioning
`refactor-python-repository` from v2 to v3 and publicly stating that
`RepositoryPort` belongs in `src/repository.py`; the preserved affected rerun
at `/private/tmp/khaos-glm53-v3-refactor-python-20260915.zxPHr1/benchmark.jsonl`
passed. The v2 failure remains preserved.

The remaining six failures are attributed to model reasoning/tool-use,
verification convergence, diff scope, and structured review output.
CompletionGate was reached for all 17 records and remained fail-closed at
`not_complete`, with zero accepted or falsely accepted completions. JSONL
canonical/digest, hidden-oracle, secret-pattern, context/provider-observability,
and browser path checks pass. Full real coding capability is still `NOT
CONFIRMED`, full corpus/release readiness is `NOT READY`, and production
readiness is `NOT READY`.

## Fresh GLM-5.3-Flash corpus after structured-output guidance (2026-09-15)

The fresh 17-scenario sequential run is preserved at
`/private/tmp/khaos-glm53-full-final3-XwsE4S/benchmark.jsonl`. It used
`zhipu-coding` / `glm-5.3-flash` through the production Coding path and
recorded 14 successes and 3 failures. It recorded 153 Provider requests,
153 model turns, 194 tool calls, 507 Repo Intelligence queries, 170 context
selections, 45 edit attempts, 43 modified files, 13 verification calls, 17
repair cycles, 0 subagents, and 29 browser calls. All Provider observations
were HTTP 200 with typed error `NONE`; usage was explicitly
`PROVIDER_NOT_REPORTED`.

The three failures were P4-v2/P4-v3 semantic review misses and a TypeScript
refactor scope/convergence failure. The targeted P4-v3 recheck remained
schema-valid but semantically incomplete. The targeted TypeScript recheck
after generic cleanup guidance narrowed the diff to the two expected files,
but its hidden test still failed. No Provider, security, workspace,
EditTransaction, CompletionGate, evaluator, or hidden-oracle defect was
found. Canonical JSONL/digest, identity, hidden-oracle isolation,
secret-pattern, generated security, and offline evaluation checks pass.

The conservative hardening gate remains:

```text
Provider Integration: PASS
Real Provider Corpus: PASS / PARTIAL
Full Real Coding Capability: NOT CONFIRMED (early signal only)
Full Corpus / Release Readiness: NOT READY
Production Readiness: NOT READY
```

No commit, push, merge, PR update, or M9 work was performed.

## Fresh GLM-5.3-Flash full-run audit and observability repair (2026-09-15)

The latest 600-second-per-task run is retained at
`/tmp/khaos-glm53-full-600.wtnpES/benchmark.jsonl`. All 17 scenarios used
`zhipu-coding` / `glm-5.3-flash` through the production-shaped Coding path,
sequentially and with external network disabled. The result was `10 SUCCESS`,
`5 FAILURE`, and `2 TIMEOUT`; the seven non-success tasks were conservatively
classified as `MODEL_REASONING_LIMIT` (verification, edit-scope, semantic
review, or bounded resource-limit outcomes).

The run recorded 174 typed Provider requests, 173 HTTP 200 responses, and one
`NO_HTTP_RESPONSE` caused by a timed-out task; Provider error classification
remained `NONE`. Reported usage was 2,053,856 input, 172,020 output, and
2,225,876 total tokens, with two timeout records explicitly marked
`PROVIDER_PARTIAL`. All 17 JSONL result digests and identities validated;
Trace v2 had 1,171 events with no drops or truncation, and secret,
hidden-oracle, security-violation, and quarantine scans were clean.

The full-run artifact exposed a general metrics projection defect: observed
`completion_gated` outcomes were present but not reflected in the top-level
completion counters. The repair is covered by deterministic tests and by the
separate real `bugfix-go-counter` rerun at
`/tmp/khaos-glm53-metrics-rerun.8BUJP0/benchmark.jsonl` (Oracle `SUCCESS`,
complete Provider usage, one CompletionGate rejection). The initial 17-task
artifact was not rewritten.

A follow-up qualification after the usage and identity repairs is preserved at
`/tmp/khaos-glm53-digest-qualification.aXDkfc/qualification.jsonl`. It used
`zhipu-coding` / `glm-5.3-flash`, recorded 7 Provider requests and complete
reported usage (`31,504` input, `3,635` output, `35,139` total tokens), and
passed P0-P3 while P4 remained a semantic-review `FAIL` with no Provider
failure. The `provider_config_digest` matches the canonical secret-free
Provider digest (`f65d2629...`); a scoped-digest regression and qualification
JSONL identity check pass.

Strict browser classification is real model `YES`, real browser runtime `NO`
(fixture-only controlled browser path), and task-local app runtime `YES`.
Complete real Coding capability and production readiness remain
`NOT CONFIRMED` / `NOT READY`. No commit, push, merge, PR update, or M9 work
was performed.

## Effective 600-second full corpus after final prompt alignment (2026-09-15)

The final valid run is preserved at
`/var/folders/l3/00y511gj4q55gj2z6zdqzrs00000gn/T/khaos-glm53-full-valid-current.IicrTEWg7f/benchmark.jsonl`.
It used the production-shaped `zhipu-coding` / `glm-5.3-flash` path and
completed all 17 scenarios with 8 successes, 6 failures, and 3 resource-limit
timeouts. The run recorded 181 Provider requests, 178 model turns, 238 tool
calls, 320 Repo Intelligence queries, 198 context selections, 57 edit
attempts, 18 verification calls, 13 repair cycles, 0 subagents, 26 browser
calls, 233 approvals, and 0 human interventions. Provider observations were
180 HTTP 200 plus one timeout cancellation, with typed error `NONE` throughout;
usage was explicitly `PROVIDER_NOT_REPORTED`.

The failed tasks are model convergence/recovery evidence, including structured
review semantics, canonical JSON adherence, browser/full-stack completion,
multi-file convergence, and one fail-closed checkpoint recovery path. The
checkpoint/execution/tool deterministic regression set passed 83 tests. No
generalizable BLOCKER/HIGH Harness defect was identified, and the security,
workspace isolation, hidden-oracle, EditTransaction, Provider, and
CompletionGate boundaries were preserved.

Artifact validation passed: 17 unique result identities, zero result-digest
mismatches, zero secret-pattern matches, zero hidden-oracle markers, zero
trace drops/truncation, zero security violations, and zero quarantines.
CompletionGate was reached for 13 records, returned `not_complete` every time,
and accepted zero completions. Full real Coding capability remains
`NOT CONFIRMED`; full-corpus/release readiness and production readiness remain
`NOT READY`. No commit, push, merge, PR update, or M9 work was performed.

## Prompt/tool-surface alignment follow-ups (2026-09-15)

The Coding prompt was corrected to match the production-shaped model surface:
the intentionally hidden legacy `delete_file` tool is not named as an
available cleanup path; cleanup is specified through canonical
`apply_edit_transaction` delete operations with preview/apply CAS. Structured
review evidence now separately records public role words and source
identifiers. The deterministic prompt regression passes 17 tests.

The P4-v3 role-word follow-up at
`/private/tmp/khaos-glm53-p4v3-rolewords-6cAT21/benchmark.jsonl` remained
schema-valid but semantically incomplete after one HTTP-200 request. The
TypeScript canonical-cleanup follow-up at
`/private/tmp/khaos-glm53-refactor-ts-canonical-cleanup-20ZyEV/benchmark.jsonl`
timed out at 600 seconds after 12 HTTP-200 requests and no Provider error.
No Oracle, CompletionGate, workspace, or tool-admission workaround was
introduced. Full real Coding capability remains `NOT CONFIRMED` and
production readiness remains `NOT READY`.

No commit, push, merge, PR update, or M9 work was performed.

## Checkpoint rejection projection repair and post-fix full corpus (2026-09-15)

The real-provider `refactor-python-repository` failure identified one
generalizable Harness defect: a safely withheld mutation batch was surfaced as
an outer AgentLoop error when its required pre-edit checkpoint was unavailable
after a failed verification. The repair retains the fail-closed checkpoint
prerequisite, rejects the whole mutation batch without dispatch, and returns a
typed `CHECKPOINT_UNAVAILABLE` / `EFFECT_NOT_STARTED` / `retry_safe` result so
the model can re-read and replan. Durable checkpoint binding and collision
errors remain terminal.

The deterministic AgentLoop/evaluation, checkpoint, execution-authority, and
ToolScheduler regressions passed, as did Ruff, compileall, and `git diff
--check`. The affected real rerun passed and is preserved at
`/private/tmp/khaos-glm53-refactor-python-checkpoint.WEJTZX/benchmark.jsonl`.

The post-fix full corpus is preserved at
`/private/tmp/khaos-glm53-full-post-checkpoint.3scJkF/benchmark.jsonl`: 17/17
records, 12 successes, four completed failures, and one bounded timeout. It
recorded 174 HTTP-200 Provider requests with typed error `NONE`, 173 model
turns, 221 tool calls, 449 Repo Intelligence queries, 191 context selections,
51 edit attempts, 11 verification calls, 16 repair cycles, 34 browser calls,
and 219 approvals. Usage stayed explicitly `PROVIDER_NOT_REPORTED`.

Artifact identity/digest, secret, hidden-oracle, trace completeness, security,
and quarantine checks all passed. Sixteen CompletionGate decisions were
reached and all were rejected fail-closed; none were accepted. The remaining
failures are a bounded browser timeout, a model-produced feature verification
failure, and three semantic review misses. No new Harness defect was found.

The current evidence improves the early signal to 12/17 but does not confirm
complete real Coding capability. Full corpus/release readiness and production
readiness remain `NOT READY`. No commit, push, merge, PR update, or M9 work
was performed.

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

## Review contract v4 and final homogeneous corpus (2026-09-15)

The cache-review Oracle had a general contract mismatch: the model-visible
instruction and Coding prompt required source-grounded identifiers, while v3
required hidden semantic terms not present as identifiers in the fixture. The
scenario is now version 4 with source anchors and deterministic regression
coverage. The affected real run passed at
`/private/tmp/khaos-cache-review-v4.N45p0F/benchmark.jsonl`; the earlier v3
attempt remains preserved.

The subsequent single-manifest full run is retained at
`/private/tmp/khaos-glm53-full-final.ctODM4/benchmark.jsonl`. It ran all 17
scenarios sequentially through the real Provider/AgentLoop/tool/edit/
verification path under a 600-second task timeout and fixture-only browser /
no-network policy. Results were 12 SUCCESS, 3 FAILURE, and 2 TIMEOUT. The
five non-success records are `MODEL_REASONING_LIMIT`: browser feature
verification, Rust edit scope, multi-file Go timeout, P4-v3 semantic review,
and TypeScript refactor timeout. No Provider error, security violation,
quarantine, or human intervention was recorded.

There were 152 HTTP-200 Provider requests, 150 model turns, 203 tool calls,
352 Repo Intelligence queries, 169 context selections, 55 edit attempts, 10
verification calls, 15 repair cycles, 25 browser calls, 194 approvals, and
1048 trace events. Usage was explicitly `PROVIDER_NOT_REPORTED`. All 17
JSONL/result/trace identities validated; trace and Provider details had zero
truncation; secret and hidden-oracle scans were zero. Fifteen CompletionGate
decisions were reached and all were rejected fail-closed.

No unresolved BLOCKER/HIGH Harness defect was found. The real-browser
dimensions are real model `YES`, controlled browser runtime `YES`, and
task-local app runtime `YES`; this remains an early signal only. Full real
Coding capability and production readiness are `NOT CONFIRMED` / `NOT READY`.
No commit, push, merge, PR update, or M9 work was performed.

## Formal coding-run Provider identity closure (2026-09-16)

The regular `coding run` path was corrected to derive its run configuration
digest from the canonical secret-free digest of the selected Provider before
binding task overrides and working-tree identity. Previously this path used
the complete config-file SHA; the qualification path already used the scoped
helper. No credential value is persisted or exposed by this repair.

Offline evaluation passed `236` tests, and the affected real
`review-python-cache-race` rerun is retained at
`/tmp/khaos-glm53-provider-digest-run.3xSnbz/benchmark.jsonl`: Oracle
`SUCCESS`, two Provider requests, complete usage (`14,285` input, `1,981`
output, `16,266` total), and one fail-closed CompletionGate rejection. The
record's config digest matches an independent recomputation from the
canonical `zhipu-coding` Provider digest and its recorded working-tree
identity. Secret and hidden-oracle scans are clean; prior full-corpus records
were not overwritten.

The identity repair is closed, but the overall real Coding capability verdict
remains `NOT CONFIRMED` and release/production readiness remains `NOT READY`.

## Fresh GLM-5.3 five-task sanity gate (2026-09-19)

The bounded sanity gate used `zhipu-coding / glm-5.3` through the real
Provider, AgentLoop, tool, workspace, edit, verification, and CompletionGate
path. Four of five tasks succeeded. The browser/full-stack task failed with
the typed `VERIFICATION_FAILURE / MODEL_REASONING_LIMIT` outcome after 30
model turns and 12 browser calls; CompletionGate did not falsely accept it.
The five records contain 77 Provider requests and Provider-reported usage of
`994,414` input, `49,112` output, and `1,043,526` total tokens.

The strict real-browser dimension remains `ENVIRONMENT_BLOCKED`: this Darwin
run was explicitly `fixture-only`, used the proxy-only fallback, and logged
missing `Proxy-Authorization` egress rejection. No unrestricted browser was
launched and no network policy was weakened. JSONL/digest/secret/oracle
checks and targeted evaluation/provider tests passed; no BLOCKER/HIGH
Harness defect was identified. The full corpus was not launched, and the
release verdict remains `EARLY SIGNAL ONLY` / `NOT READY`.

## Fresh GLM-5.3 full corpus gate (2026-09-19)

The 17-scenario manifest completed sequentially through the real Provider and
production-shaped Coding authorities using `zhipu-coding / glm-5.3` and a
fixed 600-second task budget. The retained artifact is
`/tmp/khaos-m8-glm53-full.mWMcjX/results.jsonl`; its result distribution is
`10 SUCCESS`, `5 FAILURE`, and `2 TIMEOUT`. It contains 253 Provider requests
with `3,348,456` input, `226,694` output, and `3,575,150` total tokens. The
two timeout records explicitly retain partial Provider usage.

The evaluator classified the seven non-success records as model reasoning
limits: two resource timeouts, three verification failures, one edit-scope
failure, and one semantic-review failure. No Provider/oracle/security defect,
quarantine, or unresolved BLOCKER/HIGH Harness defect was found. CompletionGate
was reached 15 times, rejected all 15 proposals, and never falsely accepted;
the two timeout tasks did not reach it.

The browser portion remains controlled fixture evidence only: Darwin used
`fixture-only`/proxy-only browser enforcement and cannot establish strict
real-browser capability. Full Coding capability is therefore still
`NOT CONFIRMED`, and production/release readiness remains `NOT READY`. No
automatic reruns, commits, pushes, or M9 work were performed.

## Benchmark oracle correction and affected-task revalidation (2026-09-19)

The initial 17-task result required one classification correction pass. Two
verification failures were benchmark defects rather than model or Harness
failures: the TypeScript oracle was too narrow for an equivalent
false-preserving implementation, and the browser-feature oracle contradicted
its own equivalence rule by requiring literal DOM/count identifiers. The
hidden oracle remained evaluator-only throughout.

The two verifiers now use bounded semantic alternatives, each has a
deterministic regression, and the affected scenarios are versioned `v2` and
`v4`. The first-attempt artifact remains untouched at
`/tmp/khaos-m8-glm53-full.mWMcjX/results.jsonl`. Separate real-provider
revalidations at `/tmp/khaos-m8-glm53-benchmark-fix.C8lvpa/` both passed their
Oracles under `zhipu-coding / glm-5.3`: browser `13` Provider requests and
TypeScript `9`, with complete reported usage and owner-only JSONL files. Both
reached CompletionGate and were rejected fail-closed; no false acceptance,
security violation, or quarantine occurred.

The affected offline regression set passed `43 tests`, Ruff and
`git diff --check` passed, and the JSONL/digest/secret/hidden-oracle audit
passed. The remaining three failures and two timeouts are not converted to
green by this correction. Strict real-browser capability remains unmeasured;
full real Coding capability and production readiness remain `NOT CONFIRMED`
and `NOT READY`. No commit, push, merge, PR update, or M9 work was performed.

## Long-budget GLM-5.3 targeted revalidation (2026-09-19)

The two initial 600-second resource-limit timeouts were rerun as separate
attempts through the production-shaped `zhipu-coding / glm-5.3` path with a
bounded 1,800-second task ceiling. `browser-fullstack-bug` and
`feature-python-index` passed their deterministic Oracles (`2/2` each). The
remaining three reruns stayed model-limited: the Rust task omitted a required
cross-module edit, the P4 read-only task missed required semantic role
concepts, and the cache-review task emitted an unrequested field rejected by
the typed parser.

The retained records have valid digests and identity bindings, owner-only
permissions, no secret or hidden-oracle markers, and no security violation or
quarantine. CompletionGate rejected all five proposals fail-closed as
`NOT_COMPLETE`. The consolidated evidence is 14 passing outcomes and 3
unresolved model-limited outcomes; strict real-browser runtime remains
unmeasured under Darwin's fixture-only policy, and full-corpus/production
readiness remain `NOT READY`.

## Rust v5 benchmark-contract correction and revalidation (2026-09-19)

The `feature-rust-parser v4` edit-scope failure was a benchmark defect. The
fixture already had the required `src/lib.rs` public re-export, while the
public task required preserving that module layout; requiring a second file
change was not a valid oracle contract. The scenario was versioned to `v5`
with a parser-only expected/diff file set. The deterministic affected
contract/oracle tests passed `32 tests`, with Ruff, compilation, and
`git diff --check` passing.

The preserved v4 attempt was not overwritten. The v5 real-provider run at
`/tmp/khaos-m8-glm53-rust-v5-final.YNDMgs/feature-rust-parser.jsonl` passed
with Oracle `2/2`, 10 Provider requests, 127,148 input, 7,254 output, and
134,402 total tokens. It changed only `src/parser.rs`, repaired one
intermediate verification failure, and reached CompletionGate, which rejected
the completion proposal fail-closed as `NOT_COMPLETE`. No security violation
or quarantine was recorded.

One earlier v5 attempt is retained as a Provider transport failure with
partial usage and is excluded from coding capability counts. A separate retry
hit the active-task limit because five interrupted tasks had been persisted as
restart-marked `blocked`; they were cancelled through Khaos's supported task
lifecycle command before the valid rerun. This was operational recovery, not
a source or Harness change.

The corrected aggregate is `15` passing outcomes and `2` unresolved
model/output limitations across the 17 scenarios. Provider integration is
`PASS`, real Coding capability is `EARLY SIGNAL ONLY / NOT CONFIRMED`, strict
real-browser capability remains unmeasured under Darwin's fixture-only policy,
full-corpus readiness is `NOT READY`, and production readiness is `NOT READY`.
No commit, push, merge, PR update, or M9 work was performed.

## Post-run forensic audit (2026-09-19)

The complete offline `python/tests/evaluation` suite passed `241 tests` after
the Rust v5 contract correction. Focused P4 contract/oracle tests passed `82`
and runtime/metrics/runner tests passed `44`. P4-v3 reached typed semantic
evaluation with valid JSON/schema/findings and failed only on missing semantic
role concepts; the cache-review output was valid JSON but contained one
unrequested `description` field. The audit found no new generalizable Harness
defect, security failure, hidden-oracle exposure, or CompletionGate defect.

Provider integration remains `PASS`, real Coding capability remains `EARLY
SIGNAL ONLY / NOT CONFIRMED`, strict real-browser capability remains
unmeasured under Darwin's fixture-only policy, and release/production
readiness remain `NOT READY`.

## Final P4/cache contract closure and composite audit (2026-09-19)

The P4-v3 semantic mismatch and cache-review unknown-field result were
resolved as contract defects, not by relaxing evaluation. P4 was versioned to
`v5` with a category-specific primary guard-symbol oracle. The cache review was
versioned to `v5` with an explicit closed finding-key contract; `description`
and other unlisted keys remain rejected fail-closed. Original attempts remain
separate and untouched.

The real `zhipu-coding / glm-5.3` rechecks passed:

- P4-v5: `SUCCESS`, 1 request, 7,756 input / 308 output / 8,064 total tokens,
  three typed findings and zero semantic mismatches.
- Cache-v5: `SUCCESS`, 2 requests, 14,361 input / 1,309 output / 15,670 total
  tokens, one typed finding, zero unknown fields, semantic oracle pass.

Combining preserved unaffected records with versioned affected-task reruns
produces 17 unique `SUCCESS` outcomes. Digest, scenario-version, provider and
model bindings validate; secret/hidden-oracle scans are zero; selected JSONL
artifacts are owner-only `0600`; no security violation or quarantine is
present. The complete offline evaluation suite passes `242 tests`, and
targeted Ruff plus `git diff --check` pass. CompletionGate remained fail
closed with zero false completion acceptance.

This closes the current deterministic 17-scenario evidence pack, but it is not
a universal model claim: strict real-browser runtime remains `UNMEASURED`
under Darwin's fixture/proxy-only policy. The conservative release status is
`Provider Integration: PASS`, `Real Provider Corpus: PASS (17/17 composed)`,
`Full Corpus Readiness: READY for a future homogeneous run`, and
`Production Readiness: NOT READY`. No commit, push, merge, PR update, or M9
work was performed.
