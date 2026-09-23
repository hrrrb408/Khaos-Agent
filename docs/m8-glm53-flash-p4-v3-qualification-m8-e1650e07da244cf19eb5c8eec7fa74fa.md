# Khaos GLM-5.3-Flash P4-v3 Qualification — Attempt `m8-e1650e07da244cf19eb5c8eec7fa74fa`

## Verdict

- Qualification result: `HARNESS_INVALIDATED`
- Primary classification: `HARNESS_DEFECT`
- Confidence: `HIGH`
- Provider/model: `zhipu-coding` / `glm-5.3-flash`
- Scenario: `p4-readonly-authority-v3`, version `3`
- Scenario digest: `34c08b50bdb2454f1284f414fbf3c9fe866afde30f40f6161a820d886698091c`
- Khaos source SHA: `3c1095ff69b1a5d800d96eb61e8b88a47fceca14`

This is the single allowed P4-v3 attempt for this lineage. It is retained as
the original result. No retry, P0-P3 probe, Coding corpus, Browser run, M9
work, commit, or push was performed.

## Provider and credential boundary

- Community Local authorityd was started under the owner-only
  `~/.khaos/authorityd/` trust root.
- Typed resource catalog and policy digest were bound before runtime startup.
- CredentialSession was explicitly unlocked through the operator path; the
  credential value was never printed, persisted in the run record, or passed
  as a command argument.
- One real provider request was observed for this P4-v3 attempt.
- Input/output/total token usage: `UNKNOWN / PROVIDER_NOT_REPORTED`.
- No provider authentication or transport failure was observed.

## Bounded execution evidence

- Model calls / turns: `1` / `1`
- Tool calls: `0`
- Repo Intelligence queries: `2`
- Context selections: `2` (`INITIAL_BUILD`, `REBALANCE`)
- Context tokens: `9170`
- Edit attempts / changed files: `0` / `0`
- Verification calls: `0`
- Repair cycles: `1`
- Subagents: `0`
- Browser calls: `0`
- CompletionGate: reached; status `not_complete`, reason `NOT_COMPLETE`
- Trace events: `11`
- Trace digest: `3ee821515adee7c4444b6630b657260e4ff477034355bc0e251fc102e8f66530`

## Harness invalidation evidence

The persisted Agent execution error was:

```text
agent final workspace is outside the private fixture root
```

The fixture manager retained a lexical `/tmp/...` private root while the
workspace authority canonicalized the same macOS path to `/private/tmp/...`.
The runner compared the canonical Agent worktree against the non-canonical
fixture root and rejected the otherwise owned worktree. The result therefore
became `INVALID_FIXTURE` before oracle evaluation (`oracle=N/A`), so this run
does not provide a valid semantic P4-v3 score.

The model response also recorded a bounded output-contract signal:
`FENCED_JSON`, `json_decode_status=FAIL`, `parse_error_code=NON_CANONICAL_FORMAT`.
Because the harness was invalidated before semantic evaluation, this is only
an observation and is not promoted to a model qualification verdict.

## Artifacts

- Original sanitized JSONL:
  `/tmp/khaos-glm53-flash-p4-v3/qualification.jsonl`
- Run ID: `m8-e1650e07da244cf19eb5c8eec7fa74fa`
- Result digest: `acbffbff40cbcd8760d3ec28f01611cf79488f6d65c78dc7fa788c3d3fedda9a`

The JSONL contains one valid sanitized benchmark record. A valid semantic
qualification JSON was not produced because the runner invalidated the
fixture before oracle evaluation.

## Required disposition

- Do not rescore this attempt as `PASS` or semantic failure.
- Repair the general path-identity contract in a separately authorized
  Harness repair run, with a deterministic regression test, then start a new
  P4-v3 lineage if qualification is still desired.
- Full real coding, browser capability, and production readiness remain
  `UNMEASURED` / `NOT READY`.
