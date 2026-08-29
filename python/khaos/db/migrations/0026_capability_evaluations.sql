-- M7.9: immutable, owner-scoped capability evaluation observations.
--
-- This ledger is descriptive history only.  It never projects task status,
-- verification, plan, recovery, tool, permission, or approval state.
CREATE TABLE IF NOT EXISTS agent_capability_evaluations (
    evaluation_id                 TEXT PRIMARY KEY,
    principal_id                  TEXT NOT NULL,
    project_id                    TEXT NOT NULL,
    task_id                       TEXT NOT NULL,
    evaluation_sequence           INTEGER NOT NULL CHECK (evaluation_sequence >= 1),
    goal_spec_id                  TEXT NOT NULL,
    goal_spec_digest              TEXT NOT NULL,
    snapshot_digest               TEXT NOT NULL,
    policy_digest                 TEXT NOT NULL,
    evaluator_schema_version      INTEGER NOT NULL CHECK (evaluator_schema_version >= 1),
    evaluator_algorithm_version   TEXT NOT NULL,
    disposition                   TEXT NOT NULL CHECK (
        disposition IN ('EVALUATED', 'INSUFFICIENT_EVIDENCE', 'STALE', 'INVALID')
    ),
    evaluation_json               TEXT NOT NULL,
    evaluation_digest             TEXT NOT NULL,
    created_at                    TEXT NOT NULL,
    UNIQUE (principal_id, project_id, task_id, evaluation_sequence)
);

CREATE INDEX IF NOT EXISTS idx_agent_capability_evaluations_scope
    ON agent_capability_evaluations(principal_id, project_id, task_id, evaluation_sequence);
CREATE INDEX IF NOT EXISTS idx_agent_capability_evaluations_snapshot
    ON agent_capability_evaluations(principal_id, project_id, snapshot_digest);

CREATE TRIGGER IF NOT EXISTS trg_agent_capability_evaluations_immutable_update
BEFORE UPDATE ON agent_capability_evaluations
BEGIN
    SELECT RAISE(ABORT, 'agent_capability_evaluations is append-only: updates are forbidden');
END;

CREATE TRIGGER IF NOT EXISTS trg_agent_capability_evaluations_immutable_delete
BEFORE DELETE ON agent_capability_evaluations
BEGIN
    SELECT RAISE(ABORT, 'agent_capability_evaluations is append-only: deletes are forbidden');
END;
