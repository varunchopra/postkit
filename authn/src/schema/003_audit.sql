-- =============================================================================
-- AUDIT LOGGING SCHEMA FOR POSTKIT/AUTHN
-- =============================================================================
--
-- PURPOSE
-- -------
-- Captures all authentication events with full context for compliance,
-- debugging, and security auditing.
--
-- WHAT'S LOGGED
-- =============
-- - User lifecycle: created, updated, disabled, enabled, deleted
-- - Credential changes: password_updated, email_updated, email_verified
-- - Sessions: created, revoked, revoked_all
-- - Tokens: created, consumed
-- - MFA: added, removed, used
-- - Security events: login_attempt_failed, lockout_triggered
--
-- NEVER LOGGED (security)
-- =======================
-- - password_hash
-- - token_hash
-- - mfa secret
--
-- PARTITIONING
-- ============
-- The audit table is partitioned by month for:
-- - Efficient retention management (drop old partitions)
-- - Query performance (partition pruning on time ranges)
-- - Maintenance operations (VACUUM per partition)
--
-- Partitions are named: audit_events_y{YYYY}m{MM}
-- Example: audit_events_y2024m01
--
-- RETENTION
-- =========
-- Use authn.drop_audit_partitions(months) to remove old data.
-- Default retention is 84 months (7 years) for compliance.
--
-- =============================================================================

-- Partitioned audit events table
CREATE TABLE authn.audit_events (
    id bigint GENERATED ALWAYS AS IDENTITY,
    event_id uuid DEFAULT gen_random_uuid(),
    event_type text NOT NULL,
    event_time timestamptz NOT NULL DEFAULT now(),

    -- Actor context (set via authn.set_actor())
    actor_id text,
    request_id text,

    -- Tenant and resource identification
    namespace text NOT NULL,
    resource_type text NOT NULL,
    resource_id text NOT NULL,

    -- Connection context
    ip_address inet,
    user_agent text,

    -- Change tracking (excluding sensitive fields)
    old_values jsonb,
    new_values jsonb,

    -- Partition key must be in primary key for partitioned tables
    PRIMARY KEY (id, event_time),

    -- Validate event types
    CONSTRAINT audit_events_type_valid CHECK (event_type IN (
        'user_created', 'user_updated', 'user_disabled', 'user_enabled', 'user_deleted',
        'password_updated', 'email_updated', 'email_verified',
        'session_created', 'session_revoked', 'sessions_revoked_all',
        'token_created', 'token_consumed',
        'mfa_added', 'mfa_removed', 'mfa_used',
        'login_attempt_failed', 'lockout_triggered'
    ))
) PARTITION BY RANGE (event_time);

-- =============================================================================
-- AUDIT INDEXES
-- =============================================================================

-- Namespace + time queries (most common)
CREATE INDEX audit_events_namespace_time_idx ON authn.audit_events (namespace, event_time DESC);

-- Resource queries (find events for a specific user, session, etc.)
CREATE INDEX audit_events_resource_idx ON authn.audit_events (namespace, resource_type, resource_id, event_time DESC);

-- Actor queries (who did what)
CREATE INDEX audit_events_actor_time_idx ON authn.audit_events (actor_id, event_time DESC)
    WHERE actor_id IS NOT NULL;

-- Event ID lookups (for correlation)
CREATE INDEX audit_events_event_id_idx ON authn.audit_events (event_id);

-- =============================================================================
-- ROW-LEVEL SECURITY
-- =============================================================================
-- Note: Audit events may need cross-tenant access for compliance officers.
-- Consider creating a separate policy for audit roles if needed.

ALTER TABLE authn.audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE authn.audit_events FORCE ROW LEVEL SECURITY;

CREATE POLICY audit_tenant_isolation ON authn.audit_events
    USING (namespace = current_setting('authn.tenant_id', TRUE))
    WITH CHECK (namespace = current_setting('authn.tenant_id', TRUE));
