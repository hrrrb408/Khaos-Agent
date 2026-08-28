-- M7.5: immutable, owner-scoped recovery decision history.
--
-- A recovery decision is a bounded interpretation of an already-collected
-- control-plane snapshot.  It is not an execution capability and it never
-- projects TaskStatus.  The canonical JSON is retained for strict readback;
-- duplicated scalar fields are integrity checks only.
CREATE TABLE IF NOT EXISTS agent_recovery_decisions (
    recovery_decision_id                 TEXT PRIMARY KEY,
    task_id                              TEXT NOT NULL,
    principal_id                         TEXT NOT NULL,
    project_id                           TEXT NOT NULL,
    recovery_sequence                    INTEGER NOT NULL CHECK (recovery_sequence >= 1),
    schema_version                       INTEGER NOT NULL CHECK (schema_version >= 1),

    goal_spec_id                         TEXT NOT NULL,
    goal_spec_digest                     TEXT NOT NULL,
    source_cognitive_state               TEXT NOT NULL,
    source_control_state_version         INTEGER NOT NULL CHECK (source_control_state_version >= 0),
    source_task_status                   TEXT NOT NULL,
    workspace_id                         TEXT,
    repository_id                        TEXT,
    base_revision                        TEXT,
    published_plan_revision_id           TEXT,
    published_plan_revision_digest       TEXT,
    latest_plan_revision_id              TEXT,
    latest_plan_revision_sequence        INTEGER,

    verification_assessment_id           TEXT,
    verification_assessment_digest       TEXT,
    verification_disposition             TEXT,
    verification_repository_generation   TEXT,
    verification_change_identity         TEXT,
    completion_decision_id               TEXT,
    completion_decision_digest           TEXT,
    completion_decision_sequence         INTEGER,
    completion_outcome                   TEXT,
    completion_continuation_state        TEXT,
    failure_signature_digest             TEXT,
    identical_failure_streak             INTEGER NOT NULL CHECK (identical_failure_streak >= 0),
    recovery_attempt_count               INTEGER NOT NULL CHECK (recovery_attempt_count >= 0),
    replan_count                         INTEGER NOT NULL CHECK (replan_count >= 0),
    total_recovery_count                 INTEGER NOT NULL CHECK (total_recovery_count >= 0),
    planning_status                      TEXT NOT NULL,

    policy_schema_version                INTEGER NOT NULL CHECK (policy_schema_version >= 1),
    policy_max_recovery_attempts_per_plan INTEGER NOT NULL CHECK (policy_max_recovery_attempts_per_plan >= 0),
    policy_identical_failure_threshold   INTEGER NOT NULL CHECK (policy_identical_failure_threshold >= 0),
    policy_max_replans_per_task          INTEGER NOT NULL CHECK (policy_max_replans_per_task >= 0),
    policy_max_recovery_cycles_per_turn  INTEGER NOT NULL CHECK (policy_max_recovery_cycles_per_turn >= 0),
    policy_max_history_records           INTEGER NOT NULL CHECK (policy_max_history_records >= 0),
    policy_digest                        TEXT NOT NULL,

    action                              TEXT NOT NULL CHECK (
        action IN ('no_action', 'recover_current_plan', 'replan', 'block')
    ),
    reason_code                         TEXT NOT NULL CHECK (
        reason_code IN (
            'no_recovery_required',
            'verification_failed',
            'verification_stale',
            'verification_unavailable',
            'completion_replan_required',
            'completion_external_blocked',
            'completion_failure_review_required',
            'identical_failure_signature',
            'recovery_attempt_budget_exhausted',
            'replan_budget_exhausted',
            'planning_blocked',
            'planning_stale',
            'planning_invalid',
            'durable_history_integrity_error',
            'task_terminal'
        )
    ),
    subject_ids_json                     TEXT NOT NULL,
    input_digest                         TEXT NOT NULL,
    decision_digest                      TEXT NOT NULL,
    canonical_json                       TEXT NOT NULL,
    created_at                           TEXT NOT NULL,

    CHECK (
        (published_plan_revision_id IS NULL AND published_plan_revision_digest IS NULL)
        OR (published_plan_revision_id IS NOT NULL AND published_plan_revision_digest IS NOT NULL)
    ),
    CHECK (
        (latest_plan_revision_id IS NULL AND latest_plan_revision_sequence IS NULL)
        OR (latest_plan_revision_id IS NOT NULL AND latest_plan_revision_sequence IS NOT NULL)
    ),
    CHECK (
        (verification_assessment_id IS NULL AND verification_assessment_digest IS NULL)
        OR (verification_assessment_id IS NOT NULL AND verification_assessment_digest IS NOT NULL)
    ),
    CHECK (
        (completion_decision_id IS NULL AND completion_decision_digest IS NULL
            AND completion_decision_sequence IS NULL AND completion_outcome IS NULL
            AND completion_continuation_state IS NULL)
        OR (completion_decision_id IS NOT NULL AND completion_decision_digest IS NOT NULL
            AND completion_decision_sequence IS NOT NULL AND completion_outcome IS NOT NULL
            AND completion_continuation_state IS NOT NULL)
    ),
    UNIQUE (task_id, principal_id, project_id, recovery_sequence)
);

CREATE INDEX IF NOT EXISTS idx_agent_recovery_decisions_owner_task_sequence
    ON agent_recovery_decisions(
        principal_id, project_id, task_id, recovery_sequence
    );

CREATE INDEX IF NOT EXISTS idx_agent_recovery_decisions_owner_digest
    ON agent_recovery_decisions(
        principal_id, project_id, decision_digest
    );

CREATE TRIGGER IF NOT EXISTS trg_agent_recovery_decisions_immutable_update
BEFORE UPDATE ON agent_recovery_decisions
BEGIN
    SELECT RAISE(
        ABORT,
        'agent_recovery_decisions is append-only: updates are forbidden'
    );
END;

CREATE TRIGGER IF NOT EXISTS trg_agent_recovery_decisions_immutable_delete
BEFORE DELETE ON agent_recovery_decisions
BEGIN
    SELECT RAISE(
        ABORT,
        'agent_recovery_decisions is append-only: deletes are forbidden'
    );
END;
