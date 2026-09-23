# Khaos Fresh GLM-5.3-Flash Semantic-Attribution Lineage #2 Report

## Final result

This attempt stopped before Provider execution because the qualification
process's `CredentialSession` was locked. The Gate requires an already
unlocked runtime session and forbids the Agent from unlocking credentials.

```text
Fresh Flash Qualification: ENVIRONMENT_BLOCKED
Reason: CREDENTIAL_SESSION_UNLOCK_REQUIRED
Provider requests: 0
Credential secret materialization: 0
```

No P0-P4 stage was started, so this report contains no model capability or
semantic-attribution result. A new invocation is required after an explicit
operator unlock; this blocked attempt is not a rerun-to-green lineage.

## Repository identity

- Branch: `codex/m8-coding-evaluation`
- Exact HEAD: `3c1095ff69b1a5d800d96eb61e8b88a47fceca14`
- Working-tree identity before: `ba45c4186779ae5ef8e76c45c1f0f77f80070a8c2ce6a40acb7a8925127f74fc`
- Working-tree identity after: `ba45c4186779ae5ef8e76c45c1f0f77f80070a8c2ce6a40acb7a8925127f74fc`
- Identity scope excludes only `docs/local-security-closure-report.md` and
  this blocked report artifact.
- Source identity before/after: `3c1095ff69b1a5d800d96eb61e8b88a47fceca14`
- Source mutated during qualification: `NO`
- Commit/push/PR/merge: none

## Protected report

`docs/local-security-closure-report.md` remains untracked, unchanged,
unstaged, and untouched. Safe metadata remains `mode=0644`, `size=851` bytes,
`mtime=1787640581`; content was not read or hashed.

## Provider and credential boundary

- Provider: `zhipu-coding`
- Requested model: `glm-5.3-flash`
- Model availability in the effective project-root configuration: `YES`
- Endpoint profile: `https://open.bigmodel.cn/api/coding/paas/v4`
- Credential reference: `khaos/providers/zhipu-coding/default`
- Persistent credential status: `PRESENT` from the safe credential-status
  diagnostic
- CredentialSession: `LOCKED`
- Runtime credential: `UNAVAILABLE`
- Agent credential unlocks: `0`
- Provider requests: `0`

The first effective router bootstrap used the project-root configuration
loader, which merges the user configuration through the canonical authority.
No configuration contents, key material, environment dump, authorization
header, or Provider response was printed or persisted.

## Historical boundary

- Historical GLM-5.3 qualification: `FAIL`
- Historical GLM-5.3-Flash qualification: `FAIL`
- Previous fresh semantic-attribution lineage:
  `m8-qualification-9b3ccf143eee4dbd92c40161e358dfb5`
- Previous fresh lineage: `HARNESS_INVALIDATED`
- Previous semantic attribution: `INCONCLUSIVE`
- Historical artifacts modified: `NO`
- Historical no-ID evidence remains explicit as `LEGACY_NO_SELECTION_ID`;
  no historical artifact was retrofitted.

## Preflight

| Preflight | Result |
| --- | --- |
| Cold Router import | `PASS` |
| Import-time Provider requests | `0` |
| Import-time credential materialization | `0` |
| Qualification bootstrap through canonical project-root config loading | `PASS` |
| ContextSelectionIdentity contract | `PASS` |
| Initial/rebalance/cache/different-content identity regressions | `PASS` |
| Identity-based final event/snapshot reconciliation | `PASS` |
| Legacy no-ID handling | `PASS` |
| Historical 18→21 and 19→22 shape coverage | `PASS` |
| Typed-finding evidence and count-boundary coverage | `PASS` |
| Hidden Oracle isolation | `PASS` |
| Selected offline preflight suite | `81 passed` |

The current frozen P4-v2 metadata observed offline was:

- scenario: `p4-readonly-authority`, version `2`
- production tool count: `73`
- max model turns: `12`
- max tool calls: `24`
- timeout: `300s`
- Trace schema: `2`
- Observability schema: `1`
- Semantic-attribution schema: `1`
- Context Selection observability schema: `1`
- P4 scenario digest: `314b8022fd0eb325bd8199379135d22f3673cf2e27f9ef0a9d1c3b171eb9fa58`
- P4 prompt digest: `d5a06983c8c5b6f1b827977bda163613a78bc39f6c2caa14a9be9c293c12c42c`
- P4 fixture digest: `864d4713661e2e803890f143eaf0268458186b2fbb74c7bfa2d47382fc745b99`
- P4 Oracle/evaluator digest: `d025f1e0812cc2d66fa19ca046f3b0731c78bb46039c7c2612d209a528ce9a31`
- production tool schema digest: `401eab0fb0a481a1f5c20b506f84f1dda42234ff344937807c338eec1fcf1f98`
- policy digest: `cf1bc0a3a97c13e0c9e00a7954a5c168a999671ffaa83a3a58ab33d17e758f93`
- P4 fixture base revision: `5a499966272316ca967d4a366ace2808134f691d`

These are safe digests and bounded metadata only; no Oracle values were
printed.

## Source freeze and lineage IDs

```text
SOURCE FREEZE: NOT REACHED
Qualification lineage ID: NOT CREATED
P0 run ID: NOT CREATED
P1 run ID: NOT CREATED
P2 run ID: NOT CREATED
P3 run ID: NOT CREATED
P4 run ID: NOT CREATED
```

The source remained unchanged throughout preflight. Because the mandatory
CredentialSession precondition failed, the experiment identity was not
promoted into a real-provider lineage and no P0-P4 attempt was made.

## P0-P4 execution

| Stage | Result | Provider requests | Notes |
| --- | --- | ---: | --- |
| P0-v2 | `NOT RUN` | 0 | blocked before source freeze/provider use |
| P1-v2 | `NOT RUN` | 0 | no synthetic tool request |
| P2-v2 | `NOT RUN` | 0 | production schema was inspected offline only |
| P3-v2 | `NOT RUN` | 0 | no real AgentLoop provider call |
| P4-v2 | `NOT RUN` | 0 | no typed candidate findings |

Therefore the following are not applicable: effective model returned by the
Provider, HTTP status, retries, usage, model turns, tool trajectory,
CompletionGate evidence from a real run, selection history from a real run,
candidate-to-Oracle comparison, category audit, context salience analysis,
verification behavior, and hypothesis attribution.

## Post-run security checks

- Raw model response persisted: `0` (no model response existed)
- Candidate typed findings persisted: `0` (no run existed)
- Oracle values in candidate artifacts: `0`
- Credential leakage: `0`
- Authorization leakage: `0`
- Unauthorized host-path leakage: `0` in this attempt's generated artifacts
- Provider activity after P4: `0` (P4 was not reached)
- JSONL qualification artifact: not created
- Protected report: unchanged

## Qualification validity and capability state

- Provider validity: `NOT ESTABLISHED`
- Harness preflight validity: `PASS`
- Real-run Context Selection evidence: `NOT RUN`
- Real-run typed-finding evidence: `NOT RUN`
- Benchmark validity: `PRECHECK PASS; QUALIFICATION NOT RUN`
- Security validity: `PASS` for this blocked attempt
- Qualification evidence: `INVALID / NOT CREATED`
- Provider integration: `NOT EXERCISED`
- Real AgentLoop: `NOT RUN`
- Fresh Flash semantic qualification: `NOT RUN`
- Real Coding: `UNMEASURED`
- Full Corpus: `NOT READY`
- Browser: `UNMEASURED`
- Production: `NOT READY`
- M9: `NOT STARTED`

## Recommended next action

```text
BLOCKED_BY_CREDENTIAL_SESSION
```

An operator must complete the approved explicit CredentialSession unlock path
for `zhipu-coding` before a new qualification invocation. The Agent must not
unlock the Keychain, and this blocked attempt must not be resumed as if it had
run. After the operator precondition is satisfied, start a new lineage and
repeat the frozen P0-v2→P4-v2 gate exactly once.

## Repository state

- Qualification artifacts: this blocked report only
- Historical reports: unchanged
- Git publication: `UNCOMMITTED`
- Repository state: `NOT READY`
