-- M7.1.4: immutable completion-evaluation records.
--
-- This is a passive evidence ledger.  It never projects an outcome onto
-- coding_tasks.status and intentionally contains no historical backfill.
CREATE TABLE IF NOT EXISTS agent_completion_decisions (
    decision_id       TEXT PRIMARY KEY,
    task_id           TEXT NOT NULL,
    principal_id      TEXT NOT NULL,
    project_id        TEXT NOT NULL,
    decision_sequence INTEGER NOT NULL
        CHECK (decision_sequence >= 1),
    schema_version    INTEGER NOT NULL
        CHECK (schema_version >= 1),
    decision_digest   TEXT NOT NULL,
    canonical_json    TEXT NOT NULL,
    created_at        TEXT NOT NULL,
    UNIQUE (task_id, decision_sequence)
);

CREATE INDEX IF NOT EXISTS idx_agent_completion_decisions_owner_task_sequence
    ON agent_completion_decisions(
        principal_id, project_id, task_id, decision_sequence
    );

CREATE TRIGGER IF NOT EXISTS trg_agent_completion_decisions_immutable_update
BEFORE UPDATE ON agent_completion_decisions
BEGIN
    SELECT RAISE(
        ABORT,
        'agent_completion_decisions is append-only: updates are forbidden'
    );
END;

CREATE TRIGGER IF NOT EXISTS trg_agent_completion_decisions_immutable_delete
BEFORE DELETE ON agent_completion_decisions
BEGIN
    SELECT RAISE(
        ABORT,
        'agent_completion_decisions is append-only: deletes are forbidden'
    );
END;
