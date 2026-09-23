# M8 GLM-5.3-Flash P4-v3 Qualification — Valid Post-Fix Attempt

Date: 2026-09-13

## Scope

This report records the one valid post-fix real-provider P4-v3 attempt. It
does not authorize or start the P0-P3 suite, the full coding corpus, browser
benchmarking, or M9.

The original pre-fix attempt remains preserved separately at
`docs/m8-glm53-flash-p4-v3-qualification-m8-e1650e07da244cf19eb5c8eec7fa74fa.md`.
Its result was `INVALID_FIXTURE` and is not used as model-capability evidence.

## Provider and identity

| Field | Value |
|---|---|
| Provider | `zhipu-coding` |
| Model | `glm-5.3-flash` |
| Khaos source SHA recorded by the evaluator | `3c1095ff69b1a5d800d96eb61e8b88a47fceca14` |
| Run ID | `m8-06958d28a94341a0acc1471c513a1f0c` |
| Scenario | `p4-readonly-authority-v3` |
| Scenario version | `3` |
| Scenario digest | `34c08b50bdb2454f1284f414fbf3c9fe866afde30f40f6161a820d886698091c` |
| Scenario manifest digest | `d7e278cfdbc4dbdc5c1ad98faa30c1e7ee4395cc1dc2c35c84a5255a488ec8b1` |
| Repository fixture base revision | `5a499966272316ca967d4a366ace2808134f691d` |
| Config digest | `0e40d79f711250ab8f60bccf6381ce804331aff7768013a41f8d8b13935f1529` |
| Policy digest | `cf1bc0a3a97c13e0c9e00a7954a5c168a999671ffaa83a3a58ab33d17e758f93` |
| Network policy | `none` |
| Approval policy | `benchmark-local-approved` |
| Budget | 12 turns, 24 tool events, 300 seconds |

The evaluator emitted a sanitized typed CodingBenchmarkResultV1 JSONL record
at `/tmp/khaos-glm53-flash-p4-v3-rerun/qualification.jsonl`. Provider token
usage was not reported by the provider/runtime and remains `null`; it was not
replaced with zero.

## Fix applied between attempts

The first attempt was invalidated because macOS resolves `/tmp` through the
`/private/tmp` symlink. `FixtureManager` retained the lexical spelling while
`WorkspaceManager` returned the canonical spelling, so the runner falsely
reported a valid agent workspace as outside the private fixture root.

`python/khaos/evaluation/coding/runner.py` now:

1. rejects a caller-provided final workspace that is itself a symlink;
2. canonicalizes both the agent workspace and the fixture private root with
   `resolve(strict=True)`; and
3. performs oracle exclusion and private-root containment checks in that same
   canonical namespace.

The fix is general path-boundary handling; it contains no scenario ID,
expected filename, reference answer, or model-specific special case.

Regression coverage was added to
`python/tests/evaluation/test_coding_eval_runner.py` for an owned workspace
whose parent is symlinked. The pre-existing direct-symlink rejection test is
still present.

## Valid attempt result

| Metric | Value |
|---|---:|
| Result | `FAIL` |
| Result state | `FAILURE` |
| Failure taxonomy | `OUTPUT_CONTRACT_FAILURE` |
| Agent status | `COMPLETED` |
| Completion status | `completed` |
| Model requests | `1` |
| Model turns | `1` |
| Tool calls | `0` |
| Context builds / selections | `2 / 2` |
| Repo Intelligence queries | `2` |
| Context files / symbols | `13 / 10` |
| Edit attempts / files changed | `0 / 0` |
| Verification runs | `0` |
| Repair cycles | `1` |
| Subagents | `0` |
| Wall time | `24012 ms` |
| Input / output / total tokens | `UNKNOWN / UNKNOWN / UNKNOWN` |
| Security violation | `false` |
| Quarantined | `false` |

The real provider request completed and the run reached the external Oracle.
The Oracle checks were:

- `DIFF`: passed; the read-only fixture remained unchanged.
- `REVIEW_FINDING`: failed because no typed findings were submitted for the
  three required public findings.

The response observation is shape-only and contains no model text:

```text
format=FENCED_JSON
json_decode_status=FAIL
schema_validation_status=FAIL
typed_parse_status=FAIL
parse_error_code=NON_CANONICAL_FORMAT
typed_finding_count=0
```

The model returned a fenced JSON response even though P4-v3 requires one
canonical JSON object. The P4-v3 parser intentionally rejects that wrapper;
the deterministic parser tests explicitly preserve this distinction from the
legacy v2 compatibility path. CompletionGate was reached and rejected with
`NOT_COMPLETE`; no false completion was accepted.

## Attribution

| Classification | Result | Evidence |
|---|---|---|
| Harness defect | Fixed, not present in valid attempt | Canonical `/tmp` path handling now reaches the Oracle; regression passes. |
| Model limitation | Primary cause of valid attempt failure | One real model response was fenced/non-canonical and yielded zero typed findings. |
| Provider defect | Not observed | The provider resolved credentials and returned a real response. |
| Benchmark defect | Not observed | Fixture and Oracle ran deterministically; the read-only diff check passed. |
| Environment defect | Not observed in valid attempt | No browser or compiler dependency was required. |

Relaxing the v3 parser to strip fences would change the benchmark contract and
would hide the observed model output-contract limitation. No such change was
made.

## Security and artifact checks

- Credential came through the configured host credential authority; the key
  was not printed, passed in argv, placed in the prompt, or persisted in the
  result.
- The persisted result contains safe digests and shape metadata only; model
  response content, authorization data, repository contents, and hidden
  oracle data were not persisted.
- The rerun JSONL is one valid JSON object and retains the original failed
  attempt as a separate artifact.
- `docs/local-security-closure-report.md` was not read or modified.
- No commit, push, PR update, rebase, or merge was performed.

## Gate decision

```text
Provider integration: PASS
Real provider P4-v3 path: PASS (request reached Oracle)
P4-v3 qualification: FAIL (OUTPUT_CONTRACT_FAILURE)
Real coding capability: EARLY_SIGNAL ONLY
Real browser capability: UNMEASURED
Full corpus readiness: NOT READY
Production readiness: NOT READY
```

The valid run proves that Khaos can resolve and use `zhipu-coding/glm-5.3-flash`
through the production-shaped evaluation path. It does not establish coding
capability or justify a full benchmark run. The next model-qualification run,
if authorized, should be a new explicitly identified attempt; this report and
the original invalid attempt must remain immutable records.
