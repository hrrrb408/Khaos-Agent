-- M8.0: append-only Coding capability evaluation run ledger.
--
-- This table is descriptive experiment history only. It is deliberately not
-- referenced by Completion, Verification, Recovery, Permission, Approval,
-- Router, Memory, or TaskStatus writers.
CREATE TABLE IF NOT EXISTS coding_evaluation_runs (
    run_id                 TEXT PRIMARY KEY,
    principal_id           TEXT NOT NULL,
    project_id             TEXT NOT NULL,
    scenario_id            TEXT NOT NULL,
    scenario_version       INTEGER NOT NULL CHECK (scenario_version >= 1),
    scenario_digest        TEXT NOT NULL,
    fixture_digest         TEXT NOT NULL,
    source_sha              TEXT NOT NULL,
    verdict                TEXT NOT NULL CHECK (
        verdict IN (
            'PASS', 'FAIL', 'TIMEOUT', 'AGENT_ERROR', 'ORACLE_ERROR',
            'INVALID_FIXTURE', 'INSUFFICIENT_EVIDENCE'
        )
    ),
    result_json             TEXT NOT NULL,
    result_digest           TEXT NOT NULL,
    started_at              TEXT NOT NULL,
    finished_at             TEXT NOT NULL,
    created_at              TEXT NOT NULL,
    UNIQUE (principal_id, project_id, run_id),
    UNIQUE (principal_id, project_id, scenario_id, scenario_version, result_digest)
);

CREATE INDEX IF NOT EXISTS idx_coding_evaluation_runs_scope
    ON coding_evaluation_runs(principal_id, project_id, created_at, run_id);
CREATE INDEX IF NOT EXISTS idx_coding_evaluation_runs_scenario
    ON coding_evaluation_runs(principal_id, project_id, scenario_id, scenario_version, created_at);

CREATE TRIGGER IF NOT EXISTS trg_coding_evaluation_runs_immutable_update
BEFORE UPDATE ON coding_evaluation_runs
BEGIN
    SELECT RAISE(ABORT, 'coding_evaluation_runs is append-only: updates are forbidden');
END;

CREATE TRIGGER IF NOT EXISTS trg_coding_evaluation_runs_immutable_delete
BEFORE DELETE ON coding_evaluation_runs
BEGIN
    SELECT RAISE(ABORT, 'coding_evaluation_runs is append-only: deletes are forbidden');
END;
