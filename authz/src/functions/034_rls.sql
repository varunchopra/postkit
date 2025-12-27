-- =============================================================================
-- ROW-LEVEL SECURITY FUNCTIONS
-- =============================================================================
--
-- Functions for managing RLS tenant context.
--
-- =============================================================================
-- =============================================================================
-- SET TENANT CONTEXT
-- =============================================================================
--
-- PURPOSE
-- -------
-- Sets the tenant context for Row-Level Security.
-- All table access will be filtered to rows matching this tenant.
--
-- SCOPE
-- =====
-- Context is session-level (set_config with is_local=false).
-- It persists across transactions until changed or session ends.
--
-- EXAMPLE
-- =======
--   SELECT authz.set_tenant('tenant-123');
--   -- All subsequent queries now scoped to tenant-123
CREATE OR REPLACE FUNCTION authz.set_tenant (p_tenant_id text)
    RETURNS VOID
    AS $$
BEGIN
    PERFORM
        set_config('authz.tenant_id', p_tenant_id, FALSE);
END;
$$
LANGUAGE plpgsql SECURITY INVOKER
SET search_path = authz, pg_temp;

-- =============================================================================
-- CLEAR TENANT CONTEXT
-- =============================================================================
--
-- PURPOSE
-- -------
-- Clears the tenant context, disabling RLS filtering.
-- After calling this, RLS policies will not match any rows (fail-closed).
--
-- EXAMPLE
-- =======
--   SELECT authz.clear_tenant();
--   -- Subsequent queries will return no rows due to RLS
CREATE OR REPLACE FUNCTION authz.clear_tenant()
    RETURNS VOID
    AS $$
BEGIN
    PERFORM set_config('authz.tenant_id', '', FALSE);
END;
$$
LANGUAGE plpgsql SECURITY INVOKER
SET search_path = authz, pg_temp;
