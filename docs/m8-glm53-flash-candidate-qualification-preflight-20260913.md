# Khaos GLM-5.3-Flash Candidate Model Qualification Report

## Scope

This is the preflight result for a new `zhipu-coding / glm-5.3-flash`
qualification lineage. The gate stopped before P0 because the operator-owned
CredentialSession was locked. No Provider request, model capability claim, or
qualification stage was made.

The historical GLM-5.3 qualification reports and the protected local security
closure report remain separate and were not overwritten.

## Repository and freeze identity

| Field | Result |
|---|---|
| Branch | `codex/m8-coding-evaluation` |
| Exact HEAD | `3c1095ff69b1a5d800d96eb61e8b88a47fceca14` |
| Working-tree identity before | `983430fa1a295a98b95af5ec0ebe5a381e30722132b392c59ce0e179f934985b` |
| Working-tree identity after | `983430fa1a295a98b95af5ec0ebe5a381e30722132b392c59ce0e179f934985b` |
| Identity exclusions | `docs/local-security-closure-report.md` and this report |
| Source identity before/after | HEAD unchanged: `3c1095ff69b1a5d800d96eb61e8b88a47fceca14` |
| Source frozen | `NO`; P0 did not start |
| Qualification-time source mutation | `NO` |
| Commit / push / PR / merge / rebase | none |

The working tree was already dirty. Existing user changes and unrelated
qualification artifacts were preserved; this report does not claim clean
exact-SHA reproducibility.

## Protected report

`docs/local-security-closure-report.md` is `UNCHANGED`, untracked, unstaged,
mode `-rw-r--r--`, size `851` bytes, SHA-256
`85dbfe1ee17475154a0f48a6d308750b252aec75f3b67dd4f2e47f06b25597a1`.

## Candidate identity

| Field | Value |
|---|---|
| Provider | `zhipu-coding` |
| Requested model | `glm-5.3-flash` |
| Effective model | `glm-5.3-flash` |
| Provider type | `openai_compatible` |
| Endpoint profile | `https://open.bigmodel.cn/api/coding/paas/v4` |
| Credential reference | `khaos/providers/zhipu-coding/default` |
| Qualification lineage | `NOT CREATED; blocked before P0` |
| Adapter | `ModelRouter -> ModelClient -> openai_compatible` |
| Reasoning / sampling | `UNKNOWN / NOT_REPORTED` |

The full safe configured-provider digest is
`f65d26293dd3e6892c4556d4cca51cfe23eb78006615e36e9f018c8eccf1715d`, equal to
the GLM-5.3 reference report. The qualification config-file digest is
`0e40d79f711250ab8f60bccf6381ce804331aff7768013a41f8d8b13935f1529`, also
unchanged. The router's selected-model view intentionally contains only the
requested Flash model; its derived view digest is not treated as a provider
configuration change.

## Comparability Gate

| Check | Result | Evidence |
|---|---|---|
| GLM-5.3 reference qualification | `VALID` | Latest valid post-parser-repair reference preserved |
| Same Provider family | `YES` | `zhipu-coding`, OpenAI-compatible adapter |
| Same Provider config | `YES` | Safe full provider digest unchanged; only selected model identity differs |
| Same Harness | `YES` | Same source HEAD and qualification/tool/runtime digests |
| Same P4 scenario | `YES` | `p4-readonly-authority` |
| Same scenario version | `YES` | `2` |
| Same P4 prompt digest | `YES` | `d5a06983c8c5b6f1b827977bda163613a78bc39f6c2caa14a9be9c293c12c42c` |
| Same fixture digest | `YES` | `864d4713661e2e803890f143eaf0268458186b2fbb74c7bfa2d47382fc745b99` |
| Same Oracle / evaluator | `YES` | Same frozen manifest and external evaluator path |
| Same tool schema | `YES` | 73 tools; digest `401eab0fb0a481a1f5c20b506f84f1dda42234ff344937807c338eec1fcf1f98` |
| Same policy | `YES` | `cf1bc0a3a97c13e0c9e00a7954a5c168a999671ffaa83a3a58ab33d17e758f93` |
| Same system prompt | `YES` | `c58fa0da8673fe4e9895877877b1a0d5ae876db9efc27b563400cb0bf99b8356` |
| Same budgets | `YES` | P3 `8 turns / 8 tools / 120s`; P4 `12 turns / 24 tools / 300s` |
| Same timeout | `YES` | P3 `120s`; P4 `300s` |
| Same Observability schema | `YES` | `1` |
| Same Trace schema | `YES` | `2` |
| Comparability | `PASS` | No material benchmark or Harness delta found |

## Preflight

```text
Router cold import: PASS
Qualification bootstrap: PASS
P4 scenario: p4-readonly-authority
P4 scenario version: 2
P4 natural-stop contract: PASS
Trace: PASS (Trace v2 / CodingTraceCollector)
Observability: PASS (Observability v1)
Typed qualification JSONL: PASS
Typed TOOL_BUDGET_EXHAUSTED contract: PASS
Hidden Oracle Isolation: PASS
Production tool count: 73
Provider calls before qualification: 0
Credential materialization before qualification: 0
Credential session values before qualification: 0
Runtime Keychain UI attempts: 0
Deterministic preflight tests: 31 passed
```

The P4 fixture was materialized only to calculate its bounded digest and base
revision, then cleaned. Hidden fixture material was not placed in the agent
root or exposed in output. No model response was requested.

## Credential Runtime

```text
Credential Authority: PRESENT through macOS Keychain metadata
Persistent credential: PRESENT
CredentialSession: LOCKED
Runtime credential: UNAVAILABLE
Runtime Keychain UI: 0 actual attempts
Backend runtime-authentication capability audit: FAIL
Agent credential unlocks: 0
Real credential value reads by Agent: 0
```

The `FAIL` capability-audit field means the backend cannot safely provide
runtime authentication UI under the current policy; it is not an observed UI
attempt. The safe presence check did not materialize the secret. Per the gate,
the Agent did not unlock the session and stopped before Provider execution.

## Qualification stages

| Stage | Run ID | Result | Provider requests | Evidence |
|---|---|---|---:|---|
| P0-v2 | not created | `NOT RUN` | 0 | blocked before provider smoke |
| P1-v2 | not created | `NOT RUN` | 0 | blocked before provider smoke |
| P2-v2 | not created | `NOT RUN` | 0 | blocked before provider smoke |
| P3-v2 | not created | `NOT RUN` | 0 | blocked before provider smoke |
| P4-v2 | not created | `NOT RUN` | 0 | blocked before provider smoke |

```text
Candidate qualification: ENVIRONMENT_BLOCKED
Reason: CREDENTIAL_SESSION_UNLOCK_REQUIRED
Rerun-to-green: NO
Budget changed: NO
Prompt changed: NO
Oracle changed: NO
Parser changed: NO
CompletionGate changed: NO
Harness changed: NO
```

Because P0 was never entered, there is no Provider response, usage record,
HTTP status, P4 response, semantic result, CompletionGate result, or failure
trajectory to attribute. Usage remains `UNKNOWN / NOT_REPORTED`, not zero.

## Failure attribution

```text
Provider valid: NOT ASSESSED; zero Provider requests
Harness valid: YES for preflight
Benchmark valid: YES for preflight
Security valid: YES
Primary classification: ENVIRONMENT_BLOCKED
Root cause: ENVIRONMENT_DEFECT / CREDENTIAL_SESSION_UNLOCK_REQUIRED
Confidence: HIGH
Explanation: the persistent credential is present, but the operator-owned
CredentialSession is locked in this qualification process. The gate forbids
the Agent from unlocking it, so execution must stop before P0.
Rerun performed: NO
Offline attribution: NOT APPLICABLE
```

## Capability state

```text
Provider Integration: NOT ASSESSED (Router and credential preflight only)
GLM-5.3-Flash qualification: BLOCKED BEFORE P0
GLM-5.3-Flash primary coding: BLOCKED
Real Coding: NOT EVALUATED
Real Browser: UNMEASURED
Full Corpus: NOT READY
Production Readiness: NOT READY
M9: NOT STARTED
```

This gate must not be used for competitive or coding-capability claims. It
does not rerun GLM-5.3, start Coding, launch Browser, or begin M9.

## Required operator action

The operator must unlock `zhipu-coding` through the trusted CLI invocation.
The Agent must not perform that unlock. After the operator unlocks, start a
new process so the command creates a fresh candidate lineage and recaptures
all identities:

```bash
cd /Users/huangruibang/Desktop/Khaos
QUAL_DIR="$(mktemp -d /tmp/khaos-glm53-flash-p0-p4-v2.XXXXXX)"
PYTHONPATH=python .venv/bin/python -m khaos.cli.main eval coding qualify \
  --model glm-5.3-flash \
  --provider zhipu-coding \
  --unlock zhipu-coding \
  --output "$QUAL_DIR/qualification.json" \
  --results-jsonl "$QUAL_DIR/qualification.jsonl"
printf 'QUAL_DIR=%s\n' "$QUAL_DIR"
```

Do not change the model, provider, prompt, parser, Oracle, budgets, or
Harness. If any stage fails, stop and preserve the artifacts; do not rerun to
green.

## Repository state

```text
docs/local-security-closure-report.md: UNCHANGED
Historical GLM-5.3 reports: PRESERVED
Qualification source mutation: NO
Commit: NO
Push: NO
PR #230 update: NO
Repository state: NOT READY for qualification closure
```
