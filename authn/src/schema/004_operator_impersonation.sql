-- =============================================================================
-- OPERATOR IMPERSONATION SCHEMA
-- =============================================================================
-- Cross-namespace operator impersonation for platform support staff.
-- Unlike regular impersonation (admin -> user in same org), this allows
-- operators to impersonate users in ANY namespace for customer support.
--
-- Design principles:
-- 1. MECHANISM vs POLICY: authn provides the mechanism (cross-namespace
--    impersonation), the app provides policy (who qualifies as operator).
-- 2. Defense in depth: Operator must have valid authn session; app validates
--    operator status before calling.
-- 3. Single source of truth: Operator audit events provide query-time
--    projection for different visibility levels.
-- 4. Module independence: authn remains independent of authz.
-- =============================================================================

-- =============================================================================
-- OPERATOR IMPERSONATION SESSIONS TABLE
-- =============================================================================
-- Tracks cross-namespace operator impersonation sessions.
-- Different from regular impersonation_sessions:
-- - No FKs to users table (cross-namespace, can't enforce)
-- - Stores snapshots of operator/target info (survives user deletion)
-- - Optional ticket reference for compliance
-- - Accessed only via SECURITY DEFINER functions (no RLS)
CREATE TABLE authn.operator_impersonation_sessions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Operator context (validated via session, snapshots for audit)
    operator_id uuid NOT NULL,              -- No FK (cross-namespace)
    operator_email text NOT NULL,           -- Snapshot
    operator_namespace text NOT NULL,
    original_session_id uuid NOT NULL,      -- Operator's session (any namespace)

    -- Target context
    target_user_id uuid NOT NULL,           -- No FK (cross-namespace)
    target_user_email text NOT NULL,        -- Snapshot
    target_namespace text NOT NULL,
    impersonation_session_id uuid REFERENCES authn.sessions(id) ON DELETE SET NULL,

    -- Metadata
    reason text NOT NULL,
    ticket_reference text,                  -- External ticket (Zendesk, Jira, etc.)
    started_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    ended_at timestamptz,

    -- Reason cannot be empty or whitespace-only
    CONSTRAINT operator_imp_reason_not_empty CHECK (length(trim(reason)) > 0)
);

-- No RLS - accessed only via SECURITY DEFINER functions
-- This table stores cross-namespace data that doesn't fit RLS model

-- =============================================================================
-- OPERATOR AUDIT EVENTS TABLE
-- =============================================================================
-- Dedicated audit trail for operator actions. Separate from regular audit_events
-- because:
-- - Different visibility requirements (tenants can query their data)
-- - Different indexing patterns (by operator namespace and target namespace)
-- - Different retention policies may apply
CREATE TABLE authn.operator_audit_events (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type text NOT NULL,
    occurred_at timestamptz NOT NULL DEFAULT now(),

    -- Operator context
    operator_namespace text NOT NULL,
    operator_id uuid NOT NULL,
    operator_email text NOT NULL,

    -- Target context
    target_namespace text NOT NULL,
    target_user_id uuid NOT NULL,
    target_user_email text NOT NULL,

    -- Session references
    impersonation_session_id uuid,
    operator_original_session_id uuid,

    -- Compliance
    reason text NOT NULL,
    ticket_reference text,
    ip_address inet,
    user_agent text,
    details jsonb DEFAULT '{}'
);

-- No RLS - accessed via SECURITY DEFINER functions that filter appropriately

-- =============================================================================
-- INDEXES
-- =============================================================================

-- Context lookup (hot path) - get operator impersonation context from session id
-- Used to check if a session is an operator impersonation session
CREATE INDEX operator_imp_sessions_session_idx
    ON authn.operator_impersonation_sessions (impersonation_session_id)
    INCLUDE (operator_id, operator_email, operator_namespace, target_user_id, target_user_email, target_namespace, reason, ticket_reference)
    WHERE ended_at IS NULL;

-- Operator queries - "what did this operator access"
CREATE INDEX operator_imp_sessions_operator_idx
    ON authn.operator_impersonation_sessions (operator_namespace, operator_id, started_at DESC);

-- Target namespace queries - "who accessed users in this namespace"
CREATE INDEX operator_imp_sessions_target_idx
    ON authn.operator_impersonation_sessions (target_namespace, target_user_id, started_at DESC);

-- Active impersonations - for platform admin dashboard
CREATE INDEX operator_imp_sessions_active_idx
    ON authn.operator_impersonation_sessions (started_at DESC)
    WHERE ended_at IS NULL;

-- Cleanup expired operator impersonations
CREATE INDEX operator_imp_sessions_expired_idx
    ON authn.operator_impersonation_sessions (expires_at)
    WHERE ended_at IS NULL;

-- Platform queries - all operator activity in an operator namespace
CREATE INDEX operator_audit_events_platform_idx
    ON authn.operator_audit_events (operator_namespace, occurred_at DESC);

-- Tenant queries - activity affecting users in a target namespace
CREATE INDEX operator_audit_events_tenant_idx
    ON authn.operator_audit_events (target_namespace, occurred_at DESC);

-- Event type filtering
CREATE INDEX operator_audit_events_type_idx
    ON authn.operator_audit_events (event_type, occurred_at DESC);

