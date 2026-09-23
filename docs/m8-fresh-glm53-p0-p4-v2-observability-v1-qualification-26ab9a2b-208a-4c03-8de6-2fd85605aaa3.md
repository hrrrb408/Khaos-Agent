# Khaos Fresh GLM-5.3 P0–P4-v2 Qualification under Observability v1

This is a fresh qualification lineage. It stopped before P0 because the
operator-controlled CredentialSession was locked. No real Provider request was
made and no GLM-5.3 capability claim is made.

## Repository and freeze identity

| Field | Result |
| --- | --- |
| Branch | `codex/m8-coding-evaluation` |
| Exact HEAD | `3c1095ff69b1a5d800d96eb61e8b88a47fceca14` |
| Working-tree identity before | `4e6dbb0eb35e1f03b73bcd87398fd1d2bfa50c403f306d5a630158e5297488bf` |
| Working-tree identity after | `4e6dbb0eb35e1f03b73bcd87398fd1d2bfa50c403f306d5a630158e5297488bf` |
| Identity exclusions | `docs/local-security-closure-report.md` and this report |
| Source identity before/after | HEAD unchanged: `3c1095ff69b1a5d800d96eb61e8b88a47fceca14` |
| Source frozen | `NO`; qualification stopped before the credential gate/freeze |
| Protected report | unchanged / untracked / unstaged |
| Commit/push/PR/merge | none |

## Preflight

```text
Router cold import: PASS
Qualification bootstrap: PASS
P4 scenario: p4-readonly-authority
P4 scenario version: 2
P4 natural-stop contract: PASS
P4 frozen budgets: max_model_turns=12, max_tool_calls=24, timeout=300s
P4 prompt/fixture/oracle contract: PASS
Trace v2: PASS
Observability schema: v1 PASS
Typed JSONL: PASS
Typed TOOL_BUDGET_EXHAUSTED: PASS (deterministic contract)
Hidden Oracle Isolation: PASS
Final-response telemetry contract: PASS
CompletionGate telemetry contract: PASS
Repo/Context telemetry contract: PASS
Timestamp telemetry contract: PASS
Preflight Provider requests: 0
Preflight credential materialization: 0
```

The production qualification bootstrap resolved `zhipu-coding / glm-5.3` using
the normal project configuration entry point (`config.yaml` plus the user
configuration layer). An exploratory explicit load of the user file alone was
rejected by the existing trusted-only configuration boundary; no source or
configuration file was changed.

Static preflight identities:

```text
Effective policy digest: cf1bc0a3a97c13e0c9e00a7954a5c168a999671ffaa83a3a58ab33d17e758f93
Manifest digest: acc964e299b00ca276f0c9943d29f984d77553ba0da1104728f9474cf4887aca
P4 scenario digest: 314b8022fd0eb325bd8199379135d22f3673cf2e27f9ef0a9d1c3b171eb9fa58
P4 fixture digest: 864d4713661e2e803890f143eaf0268458186b2fbb74c7bfa2d47382fc745b99
P4 repository base revision: 5a499966272316ca967d4a366ace2808134f691d
P4 prompt digest: d5a06983c8c5b6f1b827977bda163613a78bc39f6c2caa14a9be9c293c12c42c
System prompt digest: c58fa0da8673fe4e9895877877b1a0d5ae876db9efc27b563400cb0bf99b8356
Production tool count: 73
Production tool-schema digest: 401eab0fb0a481a1f5c20b506f84f1dda42234ff344937807c338eec1fcf1f98
```

## Credential runtime

```text
Operator credential rotation: USER CONFIRMED COMPLETE
Provider: zhipu-coding
Backend: macOS Keychain
Persistent credential: PRESENT
CredentialSession: LOCKED
Runtime credential: UNAVAILABLE
Runtime Keychain UI: 0
Real credential value reads: 0
Credential unlocks performed by Agent: 0
Secretless config: PASS
```

The safe persistent-status and process-local session-status interfaces were
used. The Agent did not unlock the session and did not materialize credential
bytes. This is an operator/environment boundary, not a Provider or coding
failure.

## Experiment identity

```text
Qualification lineage ID: m8-qualification-26ab9a2b-208a-4c03-8de6-2fd85605aaa3 (preflight-only)
Requested model: glm-5.3
Effective model: glm-5.3 (static router resolution; no request made)
HEAD: 3c1095ff69b1a5d800d96eb61e8b88a47fceca14
Working-tree identity: 4e6dbb0eb35e1f03b73bcd87398fd1d2bfa50c403f306d5a630158e5297488bf
Provider config digest: NOT FROZEN (qualification stopped before identity freeze)
Harness digest: NOT FROZEN (qualification stopped before identity freeze)
Trace schema/version: v2 (preflight contract only)
Observability schema/version: v1 (preflight contract only)
Tool-schema digest: 401eab0fb0a481a1f5c20b506f84f1dda42234ff344937807c338eec1fcf1f98 (preflight only)
Policy digest: cf1bc0a3a97c13e0c9e00a7954a5c168a999671ffaa83a3a58ab33d17e758f93 (preflight only)
System-prompt digest: c58fa0da8673fe4e9895877877b1a0d5ae876db9efc27b563400cb0bf99b8356 (preflight only)
P4 prompt digest: d5a06983c8c5b6f1b827977bda163613a78bc39f6c2caa14a9be9c293c12c42c (preflight only)
P4 scenario digest: 314b8022fd0eb325bd8199379135d22f3673cf2e27f9ef0a9d1c3b171eb9fa58 (preflight only)
Fixture digest: 864d4713661e2e803890f143eaf0268458186b2fbb74c7bfa2d47382fc745b99 (preflight only)
```

## Qualification stages

```text
P0-v2: NOT RUN
P1-v2: NOT RUN
P2-v2: NOT RUN
P3-v2: NOT RUN
P4-v2: NOT RUN

GLM-5.3 QUALIFICATION: ENVIRONMENT_BLOCKED
Reason: CREDENTIAL_SESSION_UNLOCK_REQUIRED
Provider requests: 0
No rerun performed: YES
No budget change: YES
No prompt change: YES
No Harness repair: YES
GLM-5.3-Flash: NOT RUN
Real Coding: NOT EVALUATED
Full Corpus: NOT READY
Browser: UNMEASURED
Production: NOT READY
M9: NOT STARTED
```

No P0–P4 JSONL record was created because the qualification runner was not
entered. Historical qualification and offline diagnostic records remain
unchanged and were not reused as current evidence.

## Failure attribution

```text
Provider valid: NOT ASSESSED (zero Provider requests)
Harness valid: YES for deterministic preflight contracts
Benchmark valid: YES for deterministic preflight contracts
Security valid: YES
Automatic repo evidence available: NO (P4 not run)
Tool-acquired repo evidence: NOT RUN
Response present: NOT RUN
Format/JSON/schema/parser/semantic failures: NOT APPLICABLE
CompletionGate rejection: NOT APPLICABLE
Mechanical terminal: preflight blocked

Primary root cause: ENVIRONMENT_BLOCKED
Subtype: CREDENTIAL_SESSION_UNLOCK_REQUIRED
Attribution confidence: HIGH
```

No model limitation, Provider limitation, Harness defect, or benchmark defect
was inferred from this blocked attempt.

## Evidence integrity and security

```text
Typed JSONL: PASS (contract/preflight)
Observability schema: PASS (contract/preflight)
Run identity binding: NOT ESTABLISHED
HEAD binding: PASS
Working-tree binding: PASS
Source binding: PASS
Fixture/prompt/system/tool/policy binding: PASS (static preflight)
Repo/context metadata: PASS (contract/preflight; no target run)
Response/parser telemetry: PASS (contract/preflight; no target run)
CompletionGate telemetry: PASS (contract/preflight; no target run)
Timestamp integrity: PASS (contract/preflight; no target run)
Summary/event reconciliation: PASS (contract/preflight; no target run)

Credential Authority: PASS
New secret exposure: NO
Authorization leakage: NO
Raw model response leakage: NO
Hidden oracle leakage: NO
Credential mutation: NO
Unexpected Keychain UI: NO
Protected report: UNCHANGED
SECURITY STATUS: PASS
```

The safe leakage scan found no authorization-shaped material, credential-shaped
value, raw assistant-output marker, or hidden-oracle marker in the inspected
qualification artifacts. The protected
`docs/local-security-closure-report.md` remained untracked, unstaged, mode
`-rw-r--r--`, 851 bytes, SHA-256
`85dbfe1ee17475154a0f48a6d308750b252aec75f3b67dd4f2e47f06b25597a1`.

## Repository state

```text
Source mutated during qualification: NO
Qualification-generated artifacts: this preflight report only
Engineering implementation: READY for a new qualification preflight after operator unlock
Qualification evidence: PRE-FLIGHT ONLY / NOT CREATED
Git publication: UNCOMMITTED
READY TO COMMIT / NOT READY: NOT READY for qualification
```

Next operator action: explicitly unlock `zhipu-coding` in the trusted operator
flow, then start a new qualification lineage. The Agent must not unlock the
Keychain session. After that action, recapture all identities and run exactly
one fresh P0–P4-v2 qualification; do not run coding, Flash, Browser, the full
corpus, or M9 in this gate.
