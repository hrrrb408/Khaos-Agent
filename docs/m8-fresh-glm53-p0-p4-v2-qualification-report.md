# Khaos Fresh GLM-5.3 P0–P4-v2 Qualification Report

This is a preflight-invalidated qualification record. No P0–P4 provider
request was made, and no model capability result is claimed.

## Repository and freeze identity

| Field | Result |
| --- | --- |
| Branch | `codex/m8-coding-evaluation` |
| Exact HEAD | `3c1095ff69b1a5d800d96eb61e8b88a47fceca14` |
| Working-tree identity before | `3890ea3fd6ee9313d8ec7fe06e92d4547e3a334a71f7ff7ca684ac66733b5776` |
| Working-tree identity after | `3890ea3fd6ee9313d8ec7fe06e92d4547e3a334a71f7ff7ca684ac66733b5776` |
| Identity exclusions | Protected report and this post-run report only |
| Source identity before/after | HEAD unchanged; source was not mutated |
| Source frozen | `YES` for the preflight attempt; no P0 stage began |
| Protected report | unchanged / untracked / unstaged |
| Commit/push/PR/merge | none |

The working-tree identity was captured before this post-run report was added;
the same report path is excluded from the after snapshot, along with the
protected local report, so the two recorded identities are comparable without
self-referential hashing.

## Credential recovery

```text
Operator rotation: USER CONFIRMED COMPLETE
Credential backend: macos-keychain
Provider: zhipu-coding
Persistent credential: PRESENT
Credential ref: khaos/providers/zhipu-coding/default
Credential session: NOT VERIFIED (Router import failed before session status)
Runtime credential: NOT ESTABLISHED
Secretless config: PASS (safe diagnostics report no legacy plaintext)
Credential leakage: PASS for this gate's durable artifacts; no credential value was accessed or persisted
Runtime Keychain UI: 0 from this gate
```

The safe status command exposed only provider metadata, model names, endpoint
profile, credential presence, and the opaque reference. No credential value,
authorization material, environment dump, or live config was printed.

## Qualification identity

```text
Provider: zhipu-coding
Requested model: glm-5.3
Effective model: NOT ESTABLISHED
Harness identity: 3890ea3fd6ee9313d8ec7fe06e92d4547e3a334a71f7ff7ca684ac66733b5776
Qualification schema: v1 typed JSONL exists in source; no run record created
Provider config digest: f65d26293dd3e6892c4556d4cca51cfe23eb78006615e36e9f018c8eccf1715d (safe provider diagnostic)
Tool schema digest: NOT CAPTURED (preflight invalidated before P2)
Policy digest: NOT CAPTURED (preflight invalidated before policy compilation)
System prompt digest: c58fa0da8673fe4e9895877877b1a0d5ae876db9efc27b563400cb0bf99b8356
P4 manifest digest: acc964e299b00ca276f0c9943d29f984d77553ba0da1104728f9474cf4887aca
P4 scenario digest: 314b8022fd0eb325bd8199379135d22f3673cf2e27f9ef0a9d1c3b171eb9fa58
P4 fixture digest: 864d4713661e2e803890f143eaf0268458186b2fbb74c7bfa2d47382fc745b99
P4 prompt digest: d5a06983c8c5b6f1b827977bda163613a78bc39f6c2caa14a9be9c293c12c42c
```

P4-v2 static contract was confirmed before termination:

```text
scenario_id: p4-readonly-authority
scenario_version: 2
max_model_turns: 12
max_tool_calls: 24
timeout_seconds: 300
natural stopping: PASS
prolongation wording: NOT FOUND
```

## Preflight result

```text
P0-v2: NOT RUN
P1-v2: NOT RUN
P2-v2: NOT RUN
P3-v2: NOT RUN
P4-v2: NOT RUN
P0–P4 qualification: HARNESS_INVALIDATED
Run ID: NOT CREATED (failure occurred before P0)
Provider requests: 0
Provider attempts: 0
HTTP 200/429/5xx: NOT APPLICABLE
Usage: NOT APPLICABLE
JSONL run record: NOT CREATED
```

The production Router could not be imported during the safe preflight session
check. The bounded failure chain was:

```text
khaos.rpc.composition
  -> khaos.audit.logger
  -> khaos.security.secret_redaction
  -> khaos.security.credential_broker
  -> khaos.security.resource_scope
  -> khaos.coding.planning
  -> khaos.agent.error_handler
  -> khaos.audit.logger (partially initialized)
```

Terminal error: `ImportError: cannot import name 'AuditLogger' from partially
initialized module 'khaos.audit.logger'`.

This is a current working-tree Harness/setup invalidation, consistent with the
existing out-of-scope import-cycle diagnostics from the previous engineering
regression. It is not a Provider failure, authentication result, timeout, or
model result. The experiment therefore stops without attempting Router
construction through an alternate import path, credential unlock, P0, or any
later stage.

## Evidence integrity and security

```text
Typed JSONL implementation: PASS (offline contract tests); qualification record: NOT CREATED
Run identity binding: PASS (writer contract); run evidence: NOT CREATED
HEAD binding: PASS
Working-tree binding: PASS for preflight snapshot
Fixture/prompt/system identity: PASS (static preflight digests)
Tool-schema binding: NOT CAPTURED
Policy binding: NOT CAPTURED
Summary/event reconciliation: NOT APPLICABLE (no events)
Hidden Oracle Isolation: PASS from frozen offline P4-v2 gate; no provider run exposed it
Secret leakage: PASS for this gate's durable artifacts
Authorization leakage: NO
Credential mutation: NO
Credential unlock by Agent: NO
Protected report: UNCHANGED
Security status: PASS for this preflight; qualification invalidated by Harness import cycle
```

## Failure classification

| Defect | Classification | Severity | Status |
| --- | --- | --- | --- |
| Production Router import cycle blocks safe session verification before P0 | `HARNESS_INVALIDATED` / `HARNESS_REGRESSION` | HIGH | unresolved; not fixed inside this experiment |

No Provider limitation, model limitation, benchmark result, or P4 convergence
attribution is valid because no real model request was made.

## Capability state

```text
Provider Integration: NOT ASSESSED
Real AgentLoop: NOT ASSESSED
Production Tool Surface: NOT ASSESSED
Sustained Read-Only Qualification: NOT ASSESSED
GLM-5.3 QUALIFICATION: HARNESS_INVALIDATED
Real Coding: NOT EVALUATED
Real Coding Closed Loop: NOT EVALUATED
GLM-5.3 vs GLM-5.3-Flash: NOT RUN
Full Corpus: NOT READY
Browser: UNMEASURED
Production: NOT READY
M9: NOT STARTED
GLM-5.3 PRIMARY CODING: BLOCKED
```

## Repository state

```text
Source mutated during qualification: NO
Engineering implementation: NOT READY (pre-existing import-cycle blocker remains)
Qualification evidence: INVALID (no P0 stage was created)
Git publication: UNCOMMITTED
READY TO COMMIT / NOT READY: NOT READY
```

No Harness or benchmark fix was applied after this qualification attempt began.
The next valid run requires resolving the import-cycle blocker, then starting
a completely new P0–P4-v2 chain with a fresh identity and fresh run ID. It must
not reuse this invalidated attempt.

## Router import-cycle closure follow-up (2026-09-12)

The import-cycle blocker was subsequently repaired in a separate offline gate.
`CanonicalWorkspaceId` now has a neutral owner in
`python/khaos/security/identities.py`, while planning retains only a
compatibility re-export. Fresh direct imports and the complete relevant import
order matrix pass, as do production Router construction and qualification
bootstrap through manifest, fixture, policy, Trace, and JSONL setup.

This follow-up made zero real Provider requests, read zero credential material,
and unlocked zero credential sessions. It does not change this attempt's
`HARNESS_INVALIDATED` result, does not create a qualification record, and does
not add real GLM capability evidence. The next fresh GLM-5.3 P0–P4-v2 run is
ready to start under a new identity; the full real-provider corpus remains
`NOT READY`.

See the [Router import-cycle closure report](m8-router-import-cycle-closure.md)
for the dependency audit and exact verification evidence.
