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
-- - Sessions: created, extended, revoked, revoked_all
-- - Tokens: created, consumed
-- - Credentials: added, removed, used, disabled
-- - Security events: login_attempt_failed, lockout_triggered
-- - Impersonation: started, ended (within same namespace)
--
-- NOTE: Operator impersonation events (cross-namespace) are stored separately in
-- authn.operator_audit_events. This separation exists because:
--   1. Different visibility requirements (tenants can query their data)
--   2. Different indexing patterns (by operator namespace AND target namespace)
--   3. No RLS - accessed via SECURITY DEFINER functions that filter appropriately
--   4. Potentially different retention policies for compliance
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
    reason text,                    -- context for the action
    on_behalf_of text,              -- principal being represented (e.g., admin acting as customer)

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
        'session_created', 'session_extended', 'session_revoked', 'sessions_revoked_all', 'sessions_revoked_other',
        'token_created', 'token_consumed',
        'refresh_token_created', 'refresh_token_rotated', 'refresh_token_reuse_detected',
        'refresh_token_family_revoked', 'refresh_tokens_revoked_all',
        'api_key_created', 'api_key_revoked', 'api_keys_revoked_all',
        'credential_added', 'credential_consumed', 'credential_clone_detected',
        'credential_disabled', 'credential_removed', 'bulk_credentials_disabled',
        'login_attempt_failed', 'lockout_triggered',
        'impersonation_started', 'impersonation_ended'
    ))
) PARTITION BY RANGE (event_time);

-- Default partition catches events if the cron job creating monthly partitions fails.
-- Monitor for rows here - if any appear, investigate partition creation.
CREATE TABLE authn.audit_events_default PARTITION OF authn.audit_events DEFAULT;

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
    USING (
        current_setting('authn.tenant_id', TRUE) != ''
        AND namespace = current_setting('authn.tenant_id', TRUE)
    )
    WITH CHECK (
        current_setting('authn.tenant_id', TRUE) != ''
        AND namespace = current_setting('authn.tenant_id', TRUE)
    );
