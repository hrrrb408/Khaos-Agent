-- M7.3 closure amendment: owner/task-scoped published plan identity.
--
-- The nullable physical column is added idempotently by the v20 migrator
-- because SQLite has no portable ALTER TABLE ... ADD COLUMN IF NOT EXISTS.
-- This artifact owns the lookup index only.  NULL means no READY plan has
-- legally caused the task to enter IMPLEMENTING.
CREATE INDEX IF NOT EXISTS idx_coding_tasks_owner_published_plan
    ON coding_tasks(principal_id, project_id, id, published_plan_revision_id);
