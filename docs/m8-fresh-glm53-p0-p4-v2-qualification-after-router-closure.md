# Khaos Fresh GLM-5.3 P0–P4-v2 Qualification Report

## Repository and freeze identity

This is a new qualification lineage after Router/import-cycle closure. It was
terminated before P0 because the qualification process had no operator-unlocked
CredentialSession. No real Provider request was made and no model capability is
claimed.

| Field | Result |
| --- | --- |
| Branch | `codex/m8-coding-evaluation` |
| Exact HEAD | `3c1095ff69b1a5d800d96eb61e8b88a47fceca14` |
| Working-tree identity before | `75058e431032b0cecf9631fea3aa7b240ab1658a3678a837cbd3e8d81f6d8b07` |
| Working-tree identity after | `75058e431032b0cecf9631fea3aa7b240ab1658a3678a837cbd3e8d81f6d8b07` |
| Identity exclusions | Protected report and this report |
| Source identity before/after | HEAD unchanged: `3c1095ff69b1a5d800d96eb61e8b88a47fceca14` |
| Source frozen | `NO`; P0 did not start |
| Protected report | unchanged / untracked / unstaged |
| Commit/push/PR/merge | none |

The existing dirty worktree was preserved. Historical P4-v1, the first
Router-invalidated qualification attempt, P4-v2 repair, and Router closure
reports remain separate.

## Preflight

```text
Router cold import: PASS
Qualification bootstrap: PASS
P4 scenario: p4-readonly-authority
P4 scenario version: 2
P4 max model turns: 12
P4 max tool calls: 24
P4 timeout: 300 seconds
P4 natural-stop contract: PASS
P4 prolongation markers: none found
Trace v2: PASS (CodingTraceCollector)
Typed JSONL: PASS (CodingQualificationJsonlWriter)
Typed TOOL_BUDGET_EXHAUSTED: PASS
Hidden Oracle Isolation: PASS
Production tool count: 73
Preflight Provider requests: 0
Preflight credential materialization: 0
Preflight credential sessions: 0
Preflight Keychain UI: 0
```

Qualification bootstrap resolved `zhipu-coding / glm-5.3`, the effective policy,
P4-v2 fixture, Trace collector, and JSONL writer without calling the Provider
or materializing a credential.

## Credential runtime

```text
Operator rotation: USER CONFIRMED COMPLETE
Provider: zhipu-coding
Backend: macOS Keychain
Persistent credential: PRESENT
CredentialSession: LOCKED
Runtime credential: UNAVAILABLE
Secretless config: PASS
Runtime Keychain UI: 0
Real credential value reads: 0
```

The safe persistent status interface reported presence and backend metadata
only. The session status probe does not consult persistent storage. Per the
gate contract, the agent did not unlock the session and stopped before any
Provider call.

## Experiment identity

```text
Requested model: glm-5.3
Effective model: NOT ESTABLISHED
Provider config digest: f65d26293dd3e6892c4556d4cca51cfe23eb78006615e36e9f018c8eccf1715d
Harness/working-tree identity: 75058e431032b0cecf9631fea3aa7b240ab1658a3678a837cbd3e8d81f6d8b07
Manifest digest: acc964e299b00ca276f0c9943d29f984d77553ba0da1104728f9474cf4887aca
P4 scenario digest: 314b8022fd0eb325bd8199379135d22f3673cf2e27f9ef0a9d1c3b171eb9fa58
P4 fixture digest: 864d4713661e2e803890f143eaf0268458186b2fbb74c7bfa2d47382fc745b99
P4 prompt digest: d5a06983c8c5b6f1b827977bda163613a78bc39f6c2caa14a9be9c293c12c42c
System prompt digest: c58fa0da8673fe4e9895877877b1a0d5ae876db9efc27b563400cb0bf99b8356
Production tool-schema digest: 401eab0fb0a481a1f5c20b506f84f1dda42234ff344937807c338eec1fcf1f98
Run ID: NOT CREATED; P0 was not entered
```

## Qualification stages

```text
P0-v2: NOT RUN
P1-v2: NOT RUN
P2-v2: NOT RUN
P3-v2: NOT RUN
P4-v2: NOT RUN

Qualification result: ENVIRONMENT_BLOCKED
Reason: CREDENTIAL_SESSION_UNLOCK_REQUIRED
Provider requests: 0
Rerun-to-green: NO
```

No stage JSONL record was created. There is no P4 failure to attribute and no
offline model forensics were performed.

## Security and evidence integrity

```text
Credential authority safe boundary: PASS
New secret exposure: NO
Authorization leakage: NO
Credential mutation: NO
Unexpected Keychain access: NO
Protected report: UNCHANGED
Security status: PASS
Evidence status: preflight-only; no qualification record
```

The protected `docs/local-security-closure-report.md` remained untracked,
unstaged, 851 bytes, mode `-rw-r--r--`, SHA-256
`85dbfe1ee17475154a0f48a6d308750b252aec75f3b67dd4f2e47f06b25597a1`.

## Capability state

```text
Provider Integration: NOT ASSESSED (Router construction only)
Real AgentLoop: NOT ASSESSED
Production Tool Surface: PREPARED, NOT PROVIDER-VALIDATED
Sustained Read-Only Qualification: NOT RUN
GLM-5.3 QUALIFICATION: ENVIRONMENT_BLOCKED BEFORE P0
Real Coding: NOT EVALUATED
Real Coding Closed Loop: NOT EVALUATED
GLM-5.3 vs GLM-5.3-Flash: NOT RUN
Full Corpus: NOT READY
Browser: UNMEASURED
Production: NOT READY
M9: NOT STARTED
```

## Next operator action

```text
OPERATOR ACTION REQUIRED:
explicitly unlock zhipu-coding in the trusted operator flow, then start a
new qualification lineage. The agent must not unlock the Keychain session.
```

After operator unlock, the next run must recapture HEAD, working-tree identity,
source identity, and all digests. It must not reuse this pre-P0 attempt's run
identity (none was created) or infer capability from this report.

## Repository state

```text
Source mutated during qualification: NO
Engineering implementation: READY for qualification preflight
Qualification evidence: NOT CREATED / PRE-P0 BLOCKED
Git publication: UNCOMMITTED
READY TO COMMIT / NOT READY: NOT READY for qualification; no commit performed
```
