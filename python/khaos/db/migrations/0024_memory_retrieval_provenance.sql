-- M7.7 provenance-bound retrieval metadata.
-- Legacy nodes intentionally receive UNBOUND/empty provenance and are never
-- backfilled as current facts.  The canonical event ledger remains the
-- historical source; these columns are additive node projection metadata.

ALTER TABLE memory_nodes ADD COLUMN source_kind TEXT NOT NULL DEFAULT 'UNBOUND';
ALTER TABLE memory_nodes ADD COLUMN provenance_json TEXT NOT NULL DEFAULT '{}';
ALTER TABLE memory_nodes ADD COLUMN record_digest TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_memory_nodes_retrieval_scope
    ON memory_nodes(project_id, principal_id, namespace, session_id,
                   source_kind, status, updated_at, memory_id);
