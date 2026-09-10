# ADR-088: Browser/App Computer-Use Coding Boundary

## Status

Accepted for the M8.8 implementation. The functional browser/app facade is
implemented on `codex/m8-coding-evaluation`; production closure still depends
on the exact-SHA CI and real secure-browser environment evidence described in
the closure report.

## Context

Coding-mode UI verification needs to open an explicitly configured local
development app, bind a browser context to the current task workspace, perform
bounded semantic actions, and return evidence that can be consumed by the
existing M8.3 verification pipeline. Browser pages are not trusted control
input: page text, DOM/ARIA projections, URLs, console entries, network
observations, screenshots, downloads, and tooltips can all contain prompt
injection or sensitive data.

The repository already owns the security-critical boundaries:

- `ExecutionService` owns process admission, sandbox selection, lifecycle, and
  terminal process proof.
- `BrowserManager` and its egress proxy own the Playwright/browser context and
  per-request network route guard.
- `NetworkGuard` owns URL/network authorization.
- `ToolScheduler`/`ToolInvocationBroker` and `ApprovalBroker` own capability,
  approval, argument, and effect admission.
- `WorkspaceManager`, `SafeWorkspaceFS`, credential authorities, and the
  M8.3/M8.4/M8.6 owners retain their existing authority.

Adding a second browser sandbox, process launcher, network policy, approval
store, completion gate, or verification authority would make the security
model ambiguous and could create a bypass.

## Decision

### One thin facade

`khaos.coding.browser.service.BrowserCodingService` is the only new
browser/app orchestration facade. It owns bounded in-memory resource records,
not security authority. It composes the existing owners and refuses to operate
without a composed `ExecutionService` and `BrowserManager`.

The facade exposes typed contracts for:

- immutable operator-owned `AppLaunchProfile` values;
- task/workspace/principal/generation-bound `AppInstance` values;
- immutable `BrowserSessionBinding` values;
- semantic `BrowserAction` and verification descriptors;
- bounded, redacted `BrowserObservation` values;
- digest-bound `BrowserVerificationEvidence` and result envelopes.

Only a registered profile id crosses the model-facing app-open tool. The model
cannot register a profile, provide an arbitrary executable, select a shell,
provide inline evaluation, or choose a non-loopback listener.

### Process and local app admission

The local app is started through `ExecutionRequest` and
`ExecutionService.start_managed_process`. The request is read-only from the
workspace perspective, has no general network access, and carries one exact
task-owned loopback listener port. Readiness is bounded and must be proven by
the configured path/status probe. There is no raw subprocess call and no
normal-host browser fallback.

The app profile and the active workspace bind the process to an exact
`127.0.0.1:<port>` origin. `NetworkGuard` and `BrowserManager` are both told
about that exact endpoint; the browser manager snapshots the endpoint set when
each context is created, so a later app cannot widen an existing context.

Linux remains fail-closed for local listener profiles until the existing Linux
browser/execution backend can provide the same isolated listener guarantee.
macOS uses the existing sandbox profile with an exact loopback inbound rule.

### Browser actions and effects

Actions are semantic operations (`navigate`, `click`, `type`, `select`,
`press_key`, `scroll`, `wait_for`, `read`, `screenshot`, `upload`, `download`,
and `close`). Selectors reject XPath/evaluation/javascript/coordinate-shaped
input. There is no arbitrary JavaScript parameter.

Every action carries a session id, monotonic sequence, typed effect class, and
optional observation precondition digest. Sensitive UI input, uploads,
downloads, external navigation, and other effectful actions require the
ordinary scheduler/approval path. The browser facade only accepts the opaque
binding/argument/policy digests injected by that path; page content cannot
request or manufacture approval.

Credential-backed form fill is a separate typed variant of `type`: the model
may name an operator-authorized credential, while the existing
`CredentialBroker` injects an opaque lease and materializes exactly one value
only inside the bound field operation. The lease binding includes principal,
project, task, workspace generation, session, app instance, exact origin,
selector, credential name, policy digest, and purpose. The value is never part
of the model payload, observation, supervision event, or browser journal;
known in-memory values are redacted from later observations and screenshots
are disabled for that session after injection.

An action with an uncertain external result is not silently retried. The
result carries an explicit effect status (`not_applied`, `applied`, or
`unknown`) and the action journal records only bounded metadata and digests.

### Observation and evidence

Observation is bounded to semantic body text, title, URL/origin, console and
network summaries, plus optional artifact references. All browser-originated
content is redacted and labelled `untrusted-observation`. Full HTML, response
bodies, cookies, authorization headers, credentials, and live Playwright
objects do not enter the durable browser journal.

Screenshots are retained behind bounded, quarantined artifact references and
are deleted when the artifact owner closes. Downloads are not implicitly
trusted or executed; the first implementation returns an explicit
infrastructure result until a bounded download adapter is composed.

Evidence binds plan/check/run ids, task/workspace/repository generations,
app/session/binding digests, action/assertion/observation digests, artifact
references, and status. It is an observation for M8.3; it is not completion
authority. Completion remains owned by the existing `CompletionGate` and
trusted verification authority.

The first closure does not claim popup/new-tab, cross-origin iframe, or
download materialization adapters. Unsupported flows return typed negative
results and do not silently widen origin, artifact, or process authority.

### M8.3 and M8.4 integration

Frontend-impact planning can select typed browser checks from
`VerificationProfile.browser_checks`. The existing `VerificationExecutor`
invokes the composed browser facade and maps its result into ordinary
`VerificationEvidence`; unavailable secure-browser infrastructure is a
negative, typed infrastructure result.

AgentLoop labels browser tool results as `browser_observation` and projects
them through the M8.4 context engine as L3,
`ContextSource.BROWSER`, and
`ContextTrust.UNTRUSTED_BROWSER_CONTENT`. Child context projection preserves
that classification and never turns page content into a trusted instruction.

### Lifecycle, supervision, and restart

Pause, resume, cancel, generation invalidation, and close are explicit
resource operations. Cleanup retains an in-memory resource in `QUARANTINED`
state whenever context/process/endpoint terminal proof is incomplete. The
service does not report a clean terminal postcondition while resources remain.

The facade emits bounded descriptive lifecycle metadata through the existing
`TaskSupervisionService`; supervision never authorizes an effect. A v32
metadata-only projection (`browser_resource_state` plus append-only
`browser_resource_events`) stores ids, digests, states, origins, generations,
counts, and bounded artifact references. It rejects source-shaped and
credential-shaped payload fields.

Recovery is explicit. A new runtime reads only non-terminal app/session
metadata, asks the existing process/context owners for terminal proof, records
the old identity as `stale` on success or `quarantined` on failure, and never
silently reuses a previous live browser context.

### Subagents and extensions

Browser tools inherit the existing task/workspace/principal injection and
therefore do not inherit parent approval or evidence. M8.5 child workspace
isolation remains the boundary for child coding work. Extension, MCP, hook,
and skill metadata cannot register browser authority or replace the built-in
browser facade.

### Platform and capability boundary

Arbitrary native desktop mouse/keyboard control, Electron control, and native
desktop app automation are not claimed by this ADR. Browser Coding is the
required first-class capability. Unsupported platform/security combinations
return `ENVIRONMENT_BLOCKED` or another typed negative result; they do not
fall back to ordinary host Chrome or an unconfined process.

## Consequences

The implementation provides a usable typed browser/app coding seam while
keeping authority in the existing security plane. The first version is
deliberately narrower than a universal GUI framework: app profiles are
operator-provided, credential injection is lease-gated and field-scoped, local
browser origins are exact, downloads and unbounded page families are blocked
until adapters exist, and real-browser capability must be measured in the
secure CI/runtime environment rather than inferred from fake-manager tests.

The durable schema version is 32. Older migrations remain unchanged.

## Verification obligations

The local regression suite covers contract validation, origin binding,
approval/sequence checks, prompt-injection redaction, metadata-only recovery,
context trust classification, cleanup quarantine, M8.3 planner/executor
integration, execution backend wiring, and existing browser/network suites.
The final release claim still requires exact-SHA terminal success for the
repository's required Python, Go, Rust, security, and product-integrity jobs.
