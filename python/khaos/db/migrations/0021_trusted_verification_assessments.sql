-- M7.4: immutable, owner-scoped trusted-verification assessment history.
--
-- An assessment is evidence-bearing history, not a task lifecycle authority.
-- Positive currentness is revalidated by the Python repository against the
-- physical task/GoalSpec/plan snapshot before it is exposed to completion
-- evaluation.  The canonical JSON is retained for strict readback and the
-- duplicated scalar columns are a cross-check, not a second semantic source.
CREATE TABLE IF NOT EXISTS agent_verification_assessments (
    assessment_id                       TEXT PRIMARY KEY,
    task_id                              TEXT NOT NULL,
    principal_id                         TEXT NOT NULL,
    project_id                           TEXT NOT NULL,
    assessment_sequence                  INTEGER NOT NULL CHECK (assessment_sequence >= 1),
    schema_version                       INTEGER NOT NULL CHECK (schema_version >= 1),
    goal_spec_id                         TEXT NOT NULL,
    goal_spec_digest                     TEXT NOT NULL,
    cognitive_state                      TEXT NOT NULL,
    control_state_version                INTEGER NOT NULL CHECK (control_state_version >= 0),
    task_status                          TEXT NOT NULL,
    workspace_id                         TEXT NOT NULL,
    repository_id                        TEXT NOT NULL,
    base_revision                        TEXT,
    published_plan_revision_id           TEXT,
    published_plan_revision_digest       TEXT,
    repository_generation                TEXT,
    change_identity                      TEXT,
    policy_digest                        TEXT NOT NULL,
    catalog_fingerprint                  TEXT NOT NULL,
    verification_algorithm_version      TEXT NOT NULL,
    input_digest                         TEXT NOT NULL,
    disposition                          TEXT NOT NULL CHECK (
        disposition IN ('satisfied', 'failed', 'inconclusive', 'unavailable', 'stale')
    ),
    assessment_digest                   TEXT NOT NULL,
    canonical_json                       TEXT NOT NULL,
    created_at                           TEXT NOT NULL,
    CHECK (
        (published_plan_revision_id IS NULL AND published_plan_revision_digest IS NULL)
        OR (published_plan_revision_id IS NOT NULL AND published_plan_revision_digest IS NOT NULL)
    ),
    CHECK (repository_generation IS NOT NULL OR change_identity IS NOT NULL),
    UNIQUE (task_id, principal_id, project_id, assessment_sequence)
);

CREATE INDEX IF NOT EXISTS idx_agent_verification_assessments_owner_task_sequence
    ON agent_verification_assessments(
        principal_id, project_id, task_id, assessment_sequence
    );

CREATE INDEX IF NOT EXISTS idx_agent_verification_assessments_owner_digest
    ON agent_verification_assessments(
        principal_id, project_id, assessment_digest
    );

CREATE TRIGGER IF NOT EXISTS trg_agent_verification_assessments_immutable_update
BEFORE UPDATE ON agent_verification_assessments
BEGIN
    SELECT RAISE(
        ABORT,
        'agent_verification_assessments is append-only: updates are forbidden'
    );
END;

CREATE TRIGGER IF NOT EXISTS trg_agent_verification_assessments_immutable_delete
BEFORE DELETE ON agent_verification_assessments
BEGIN
    SELECT RAISE(
        ABORT,
        'agent_verification_assessments is append-only: deletes are forbidden'
    );
END;
