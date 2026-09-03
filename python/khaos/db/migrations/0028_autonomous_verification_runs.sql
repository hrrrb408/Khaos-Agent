-- M8.3: bounded autonomous-verification observations.
-- This table is descriptive history only. It is not read as completion,
-- execution, permission, approval, or trusted-verification authority.
CREATE TABLE IF NOT EXISTS autonomous_verification_runs (
    run_id                  TEXT PRIMARY KEY,
    principal_id            TEXT NOT NULL,
    project_id              TEXT NOT NULL,
    task_id                 TEXT NOT NULL,
    workspace_id            TEXT NOT NULL,
    workspace_generation    INTEGER NOT NULL CHECK (workspace_generation >= 0),
    repository_generation   INTEGER NOT NULL CHECK (repository_generation >= 0),
    plan_id                 TEXT NOT NULL,
    plan_digest             TEXT NOT NULL,
    status                  TEXT NOT NULL CHECK (
        status IN (
            'planned', 'running', 'passed', 'failed', 'timed_out',
            'cancelled', 'stale', 'infrastructure_error', 'unknown'
        )
    ),
    required_count          INTEGER NOT NULL CHECK (required_count >= 0),
    passed_count            INTEGER NOT NULL CHECK (passed_count >= 0),
    result_json             TEXT NOT NULL,
    result_digest           TEXT NOT NULL,
    created_at              TEXT NOT NULL,
    UNIQUE (principal_id, project_id, run_id),
    CHECK (passed_count <= required_count)
);

CREATE INDEX IF NOT EXISTS idx_autonomous_verification_runs_scope
    ON autonomous_verification_runs(principal_id, project_id, task_id, created_at, run_id);

CREATE TRIGGER IF NOT EXISTS trg_autonomous_verification_runs_immutable_update
BEFORE UPDATE ON autonomous_verification_runs
BEGIN
    SELECT RAISE(ABORT, 'autonomous_verification_runs is append-only: updates are forbidden');
END;

CREATE TRIGGER IF NOT EXISTS trg_autonomous_verification_runs_immutable_delete
BEFORE DELETE ON autonomous_verification_runs
BEGIN
    SELECT RAISE(ABORT, 'autonomous_verification_runs is append-only: deletes are forbidden');
END;
