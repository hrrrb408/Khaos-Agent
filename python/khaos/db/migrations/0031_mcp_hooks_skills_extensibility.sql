-- M8.7: owner-scoped MCP / Hook / Skill extension metadata and lifecycle
-- projections.  Descriptor/capability/registration/invocation/activation
-- facts are append-only.  Runtime state is mutable only as a bounded
-- projection; none of these tables is an approval, verification, execution,
-- workspace, or completion authority.

CREATE TABLE IF NOT EXISTS extension_descriptors (
    extension_id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    extension_json TEXT NOT NULL CHECK (length(extension_json) <= 65536),
    descriptor_digest TEXT NOT NULL,
    provenance TEXT NOT NULL,
    lifecycle_state TEXT NOT NULL,
    state_reason TEXT NOT NULL DEFAULT '' CHECK (length(state_reason) <= 2048),
    state_generation INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (extension_id, principal_id, project_id)
);

CREATE INDEX IF NOT EXISTS idx_extension_descriptors_owner
    ON extension_descriptors(principal_id, project_id, extension_id);

CREATE TABLE IF NOT EXISTS extension_capabilities (
    capability_id TEXT NOT NULL,
    extension_id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    capability_json TEXT NOT NULL CHECK (length(capability_json) <= 65536),
    capability_digest TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (capability_id, principal_id, project_id)
);

CREATE INDEX IF NOT EXISTS idx_extension_capabilities_owner
    ON extension_capabilities(principal_id, project_id, extension_id, capability_id);

CREATE TABLE IF NOT EXISTS extension_runtime_instances (
    instance_id TEXT PRIMARY KEY,
    extension_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    session_id TEXT NOT NULL DEFAULT '',
    principal_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    lifecycle_state TEXT NOT NULL,
    process_identity TEXT NOT NULL DEFAULT '' CHECK (length(process_identity) <= 1024),
    runtime_json TEXT NOT NULL CHECK (length(runtime_json) <= 16384),
    started_at TEXT,
    stopped_at TEXT,
    quarantine_reason TEXT NOT NULL DEFAULT '' CHECK (length(quarantine_reason) <= 2048),
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_extension_runtime_owner
    ON extension_runtime_instances(principal_id, project_id, task_id, lifecycle_state);

CREATE TABLE IF NOT EXISTS extension_invocations (
    invocation_id TEXT PRIMARY KEY,
    extension_id TEXT NOT NULL,
    capability_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    session_id TEXT NOT NULL DEFAULT '',
    principal_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    arguments_digest TEXT NOT NULL,
    effect_digest TEXT NOT NULL,
    status TEXT NOT NULL,
    response_bytes INTEGER NOT NULL DEFAULT 0,
    response_digest TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    completed_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_extension_invocations_owner
    ON extension_invocations(principal_id, project_id, task_id, created_at);

CREATE TABLE IF NOT EXISTS hook_registrations (
    hook_id TEXT NOT NULL,
    extension_id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    registration_json TEXT NOT NULL CHECK (length(registration_json) <= 32768),
    registration_digest TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (hook_id, principal_id, project_id)
);

CREATE INDEX IF NOT EXISTS idx_hook_registrations_owner
    ON hook_registrations(principal_id, project_id, extension_id, hook_id);

CREATE TABLE IF NOT EXISTS skill_activations (
    activation_id TEXT PRIMARY KEY,
    skill_id TEXT NOT NULL,
    version TEXT NOT NULL,
    package_digest TEXT NOT NULL,
    selection_reason TEXT NOT NULL CHECK (length(selection_reason) <= 2048),
    task_id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    status TEXT NOT NULL,
    missing_tools_json TEXT NOT NULL DEFAULT '[]' CHECK (length(missing_tools_json) <= 8192),
    stale INTEGER NOT NULL DEFAULT 0 CHECK (stale IN (0, 1)),
    activation_digest TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_skill_activations_owner
    ON skill_activations(principal_id, project_id, task_id, created_at);

CREATE TRIGGER IF NOT EXISTS extension_descriptors_no_delete
    BEFORE DELETE ON extension_descriptors
BEGIN
    SELECT RAISE(ABORT, 'extension_descriptors is append-only');
END;

CREATE TRIGGER IF NOT EXISTS extension_descriptors_identity_immutable
    BEFORE UPDATE ON extension_descriptors
    WHEN NEW.extension_id != OLD.extension_id
      OR NEW.principal_id != OLD.principal_id
      OR NEW.project_id != OLD.project_id
      OR NEW.extension_json != OLD.extension_json
      OR NEW.descriptor_digest != OLD.descriptor_digest
      OR NEW.provenance != OLD.provenance
      OR NEW.created_at != OLD.created_at
BEGIN
    SELECT RAISE(ABORT, 'extension descriptor identity is immutable');
END;

CREATE TRIGGER IF NOT EXISTS extension_capabilities_no_update
    BEFORE UPDATE ON extension_capabilities
BEGIN
    SELECT RAISE(ABORT, 'extension_capabilities is immutable');
END;

CREATE TRIGGER IF NOT EXISTS extension_capabilities_no_delete
    BEFORE DELETE ON extension_capabilities
BEGIN
    SELECT RAISE(ABORT, 'extension_capabilities is immutable');
END;

CREATE TRIGGER IF NOT EXISTS extension_invocations_no_update
    BEFORE UPDATE ON extension_invocations
BEGIN
    SELECT RAISE(ABORT, 'extension_invocations is append-only');
END;

CREATE TRIGGER IF NOT EXISTS extension_invocations_no_delete
    BEFORE DELETE ON extension_invocations
BEGIN
    SELECT RAISE(ABORT, 'extension_invocations is append-only');
END;

CREATE TRIGGER IF NOT EXISTS hook_registrations_no_update
    BEFORE UPDATE ON hook_registrations
BEGIN
    SELECT RAISE(ABORT, 'hook_registrations is immutable');
END;

CREATE TRIGGER IF NOT EXISTS hook_registrations_no_delete
    BEFORE DELETE ON hook_registrations
BEGIN
    SELECT RAISE(ABORT, 'hook_registrations is immutable');
END;

CREATE TRIGGER IF NOT EXISTS skill_activations_no_update
    BEFORE UPDATE ON skill_activations
BEGIN
    SELECT RAISE(ABORT, 'skill_activations is immutable');
END;

CREATE TRIGGER IF NOT EXISTS skill_activations_no_delete
    BEFORE DELETE ON skill_activations
BEGIN
    SELECT RAISE(ABORT, 'skill_activations is immutable');
END;
