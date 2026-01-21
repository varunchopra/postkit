-- =============================================================================
-- SCHEMA AND TABLES FOR POSTKIT/CONFIG
-- =============================================================================
-- Versioned configuration storage for prompts, feature flags, secrets, settings.
-- All config types use the same table — differentiated by key naming conventions.
-- =============================================================================

CREATE SCHEMA IF NOT EXISTS config;

-- =============================================================================
-- ENTRIES TABLE
-- =============================================================================
-- Versioned key-value store. Each key can have multiple versions.
-- Only one version per key is active at a time.
CREATE TABLE config.entries (
    id bigserial PRIMARY KEY,
    namespace text NOT NULL DEFAULT 'default',
    key text NOT NULL,              -- 'prompts/support-bot', 'flags/checkout-v2', 'secrets/OPENAI_API_KEY'
    version int NOT NULL DEFAULT 1,
    value jsonb NOT NULL,
    is_active boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    created_by text,                -- actor who created this version

    CONSTRAINT entries_namespace_key_version_key UNIQUE (namespace, key, version),
    CONSTRAINT entries_key_format CHECK (key ~ '^[a-zA-Z0-9][a-zA-Z0-9_/.-]*$'),
    CONSTRAINT entries_key_length CHECK (length(key) <= 1024),
    CONSTRAINT entries_version_positive CHECK (version > 0)
);

-- =============================================================================
-- VERSION COUNTERS
-- =============================================================================
-- Tracks max version ever assigned per key (survives deletions)
CREATE TABLE config.version_counters (
    namespace text NOT NULL DEFAULT 'default',
    key text NOT NULL,
    max_version int NOT NULL DEFAULT 0,
    PRIMARY KEY (namespace, key)
);

-- =============================================================================
-- ROW-LEVEL SECURITY
-- =============================================================================
-- Note: current_setting(..., TRUE) returns '' when not set.
-- We explicitly check for non-empty to fail-closed when tenant context is missing.

ALTER TABLE config.entries ENABLE ROW LEVEL SECURITY;
ALTER TABLE config.entries FORCE ROW LEVEL SECURITY;

CREATE POLICY entries_tenant_isolation ON config.entries
    USING (
        current_setting('config.tenant_id', TRUE) != ''
        AND namespace = current_setting('config.tenant_id', TRUE)
    )
    WITH CHECK (
        current_setting('config.tenant_id', TRUE) != ''
        AND namespace = current_setting('config.tenant_id', TRUE)
    );

ALTER TABLE config.version_counters ENABLE ROW LEVEL SECURITY;
ALTER TABLE config.version_counters FORCE ROW LEVEL SECURITY;

CREATE POLICY version_counters_tenant_isolation ON config.version_counters
    USING (
        current_setting('config.tenant_id', TRUE) != ''
        AND namespace = current_setting('config.tenant_id', TRUE)
    )
    WITH CHECK (
        current_setting('config.tenant_id', TRUE) != ''
        AND namespace = current_setting('config.tenant_id', TRUE)
    );
