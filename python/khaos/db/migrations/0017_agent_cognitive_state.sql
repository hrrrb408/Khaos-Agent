-- M7.1.3: durable Agent Cognitive State is an independent CAS domain.
-- Existing tasks intentionally receive UNINITIALIZED/0; no lifecycle or
-- verification history is used to infer a cognitive phase.
ALTER TABLE coding_tasks
    ADD COLUMN cognitive_state TEXT NOT NULL DEFAULT 'uninitialized'
    CHECK (cognitive_state IN (
        'uninitialized',
        'understanding',
        'exploring',
        'planning',
        'implementing',
        'verifying',
        'diagnosing',
        'recovering',
        'replanning',
        'reviewing',
        'completion_check'
    ));

ALTER TABLE coding_tasks
    ADD COLUMN control_state_version INTEGER NOT NULL DEFAULT 0
    CHECK (control_state_version >= 0);
