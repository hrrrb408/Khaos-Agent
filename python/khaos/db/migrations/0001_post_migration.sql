-- F-03 (third-round review): Migration chain v2 — INDEXES AND TRIGGERS.
--
-- This file is FROZEN.  Never modify it after release.
--
-- This file contains ONLY ``CREATE INDEX``, ``CREATE UNIQUE INDEX`` and
-- ``CREATE TRIGGER`` statements.  It is executed AFTER
-- ``_run_legacy_schema_upgrades()`` so that indexes referencing
-- principal_id / project_id / policy_digest (columns added by the legacy
-- upgrade helpers) do not fail on old databases.
--
-- Execution order in ``run_migrations()``:
--   1. 0001_initial_schema.sql   (CREATE TABLE IF NOT EXISTS)
--   2. _run_legacy_schema_upgrades()  (ALTER TABLE ADD COLUMN for old DBs)
--   3. 0001_post_migration.sql   (this file — CREATE INDEX / TRIGGER IF NOT EXISTS)

-- sessions
CREATE INDEX IF NOT EXISTS idx_sessions_principal
    ON sessions(principal_id, status, updated_at);

-- messages
CREATE INDEX IF NOT EXISTS idx_messages_session ON messages(session_id, created_at);
CREATE INDEX IF NOT EXISTS idx_messages_principal
    ON messages(principal_id, session_id, created_at);

-- agent_turns
CREATE INDEX IF NOT EXISTS idx_agent_turns_session
ON agent_turns(session_id, started_at);

-- chat_stream_events
CREATE INDEX IF NOT EXISTS idx_chat_stream_events_owner
ON chat_stream_events(principal_id, project_id, session_id, sequence);

-- chat_streams (round-5 Batch 5.2)
CREATE INDEX IF NOT EXISTS idx_chat_streams_boot
ON chat_streams(boot_id, status);
CREATE INDEX IF NOT EXISTS idx_chat_streams_status_lease
ON chat_streams(status, lease_until);

-- memories FTS5 sync triggers
CREATE TRIGGER IF NOT EXISTS memory_ai AFTER INSERT ON memories BEGIN
    INSERT INTO memory_fts(rowid, key, value) VALUES (new.id, new.key, new.value);
END;

CREATE TRIGGER IF NOT EXISTS memory_ad AFTER DELETE ON memories BEGIN
    INSERT INTO memory_fts(memory_fts, rowid, key, value) VALUES('delete', old.id, old.key, old.value);
END;

CREATE TRIGGER IF NOT EXISTS memory_au AFTER UPDATE ON memories BEGIN
    INSERT INTO memory_fts(memory_fts, rowid, key, value) VALUES('delete', old.id, old.key, old.value);
    INSERT INTO memory_fts(rowid, key, value) VALUES (new.id, new.key, new.value);
END;

-- permissions
CREATE INDEX IF NOT EXISTS idx_permissions_level ON permissions(permission_level, mode);
CREATE INDEX IF NOT EXISTS idx_permissions_principal
    ON permissions(principal_id, project_id, policy_digest, generation, mode, permission_level);

-- audit_log
CREATE INDEX IF NOT EXISTS idx_audit_log_time ON audit_log(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action);
CREATE INDEX IF NOT EXISTS idx_audit_log_principal
    ON audit_log(principal_id, created_at);

-- session_bookmarks
CREATE INDEX IF NOT EXISTS idx_session_bookmarks_principal
    ON session_bookmarks(principal_id, session_id);

-- scheduled_tasks
CREATE INDEX IF NOT EXISTS idx_scheduled_tasks_status ON scheduled_tasks(status, next_run);
CREATE INDEX IF NOT EXISTS idx_scheduled_tasks_principal ON scheduled_tasks(principal_id, status);
CREATE INDEX IF NOT EXISTS idx_scheduled_tasks_policy ON scheduled_tasks(policy_digest, status);

-- scheduled_tasks quarantine triggers (enforce legacy owner rejection at write boundary)
CREATE TRIGGER IF NOT EXISTS trg_scheduled_tasks_quarantine_legacy_insert
AFTER INSERT ON scheduled_tasks
WHEN NEW.principal_id = 'legacy' AND NEW.status != 'failed'
BEGIN
    UPDATE scheduled_tasks
    SET status = 'failed',
        error = 'quarantined: legacy write - task has no authenticated owner; an admin must re-claim it with a real principal before it can run',
        execution_id = NULL,
        lease_until = NULL
    WHERE id = NEW.id;
END;

CREATE TRIGGER IF NOT EXISTS trg_scheduled_tasks_quarantine_legacy_update
AFTER UPDATE OF principal_id, status ON scheduled_tasks
WHEN NEW.principal_id = 'legacy' AND NEW.status != 'failed'
BEGIN
    UPDATE scheduled_tasks
    SET status = 'failed',
        error = 'quarantined: legacy write - task has no authenticated owner; an admin must re-claim it with a real principal before it can run',
        execution_id = NULL,
        lease_until = NULL
    WHERE id = NEW.id;
END;

-- scheduler_operation_journal
CREATE INDEX IF NOT EXISTS idx_scheduler_journal_pending
    ON scheduler_operation_journal(seq) WHERE applied_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_scheduler_journal_task
    ON scheduler_operation_journal(task_id, seq);

-- coding_tasks
CREATE INDEX IF NOT EXISTS idx_coding_tasks_status ON coding_tasks(status, updated_at);
CREATE INDEX IF NOT EXISTS idx_coding_tasks_principal ON coding_tasks(principal_id, status);

-- plan_approval_requests
CREATE INDEX IF NOT EXISTS idx_plan_approval_requests_plan
    ON plan_approval_requests(plan_id, plan_content_hash);
CREATE INDEX IF NOT EXISTS idx_plan_approval_requests_repo
    ON plan_approval_requests(repository_id, task_id, workspace_id);
CREATE INDEX IF NOT EXISTS idx_plan_approval_requests_broker
    ON plan_approval_requests(broker_request_id);
CREATE INDEX IF NOT EXISTS idx_plan_approval_requests_status
    ON plan_approval_requests(status, expires_at);

-- plan_approval_decisions
CREATE INDEX IF NOT EXISTS idx_plan_approval_decisions_request
    ON plan_approval_decisions(approval_request_id, decided_at);

-- plan_execution_authorizations
CREATE INDEX IF NOT EXISTS idx_plan_execution_authorizations_plan
    ON plan_execution_authorizations(plan_id, approval_request_id);
CREATE INDEX IF NOT EXISTS idx_plan_execution_authorizations_scope
    ON plan_execution_authorizations(repository_id, task_id, workspace_id);
CREATE INDEX IF NOT EXISTS idx_plan_execution_authorizations_status
    ON plan_execution_authorizations(status, expires_at);

-- plan_approval_audit_events
CREATE INDEX IF NOT EXISTS idx_plan_approval_audit_events_request
    ON plan_approval_audit_events(approval_request_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_plan_approval_audit_events_plan
    ON plan_approval_audit_events(plan_id, timestamp);

-- plan_approval_receipts
CREATE INDEX IF NOT EXISTS idx_plan_approval_receipts_token
    ON plan_approval_receipts(token_hash);
CREATE INDEX IF NOT EXISTS idx_plan_approval_receipts_request
    ON plan_approval_receipts(approval_request_id);

-- plan_execution_authorizations: at most one ACTIVE per request
CREATE UNIQUE INDEX IF NOT EXISTS uq_plan_exec_auth_active_per_request
    ON plan_execution_authorizations(approval_request_id) WHERE status = 'active';

-- plan_approval_requests: broker_request_id uniqueness for non-empty values
CREATE UNIQUE INDEX IF NOT EXISTS uq_plan_approval_requests_broker
    ON plan_approval_requests(broker_request_id) WHERE broker_request_id != '';

-- plan_snapshots
CREATE INDEX IF NOT EXISTS idx_plan_snapshots_repo
    ON plan_snapshots(repository_id, task_id, workspace_id);

-- plan_execution_leases: at most one ACTIVE per workspace
CREATE UNIQUE INDEX IF NOT EXISTS uq_plan_execution_leases_active_workspace
    ON plan_execution_leases(workspace_id) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_plan_execution_leases_task
    ON plan_execution_leases(task_id, status);

-- plan_execution_phase_leases: at most one ACTIVE per execution_run_id
CREATE UNIQUE INDEX IF NOT EXISTS uq_active_verification_phase_lease
    ON plan_execution_phase_leases(execution_run_id) WHERE status = 'active';

-- verification_cleanup_proofs: one per verification_run_id
CREATE UNIQUE INDEX IF NOT EXISTS ux_vcp_run
    ON verification_cleanup_proofs(verification_run_id);

CREATE TRIGGER IF NOT EXISTS trg_vcp_immutable_update
BEFORE UPDATE ON verification_cleanup_proofs
BEGIN SELECT RAISE(ABORT, 'verification cleanup proof is immutable'); END;

CREATE TRIGGER IF NOT EXISTS trg_vcp_immutable_delete
BEFORE DELETE ON verification_cleanup_proofs
BEGIN SELECT RAISE(ABORT, 'verification cleanup proof cannot be deleted'); END;

-- verification_success_evidence: immutable
CREATE TRIGGER IF NOT EXISTS trg_vse_immutable_update
BEFORE UPDATE ON verification_success_evidence
BEGIN SELECT RAISE(ABORT, 'verification success evidence is immutable'); END;

CREATE TRIGGER IF NOT EXISTS trg_vse_immutable_delete
BEFORE DELETE ON verification_success_evidence
BEGIN SELECT RAISE(ABORT, 'verification success evidence cannot be deleted'); END;

-- operation_approvals
CREATE INDEX IF NOT EXISTS idx_operation_approvals_expiry
    ON operation_approvals(status, expires_at);

-- operation_approval_events
CREATE INDEX IF NOT EXISTS idx_operation_approval_events_approval
    ON operation_approval_events(approval_id, id);

-- webhook_replay_events
CREATE INDEX IF NOT EXISTS idx_webhook_replay_expiry
    ON webhook_replay_events(expires_at)
    WHERE expires_at IS NOT NULL;
