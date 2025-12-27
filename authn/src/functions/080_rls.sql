-- =============================================================================
-- RLS TENANT FUNCTIONS FOR POSTKIT/AUTHN
-- =============================================================================
-- Set and clear tenant context for row-level security.
-- =============================================================================


-- =============================================================================
-- SET TENANT
-- =============================================================================
-- Sets the tenant context for RLS policies.
-- All subsequent queries in this transaction will be filtered by namespace.
CREATE OR REPLACE FUNCTION authn.set_tenant(
    p_tenant_id text
)
RETURNS void
AS $$
BEGIN
    PERFORM authn._validate_namespace(p_tenant_id);
    PERFORM set_config('authn.tenant_id', p_tenant_id, true);
END;
$$ LANGUAGE plpgsql SET search_path = authn, pg_temp;

COMMENT ON FUNCTION authn.set_tenant(text) IS
'Sets tenant context for RLS. All queries will be filtered by this namespace.';


-- =============================================================================
-- CLEAR TENANT
-- =============================================================================
-- Clears the tenant context.
-- WARNING: With RLS enabled, queries will return no rows until tenant is set.
CREATE OR REPLACE FUNCTION authn.clear_tenant()
RETURNS void
AS $$
BEGIN
    PERFORM set_config('authn.tenant_id', '', true);
END;
$$ LANGUAGE plpgsql SET search_path = authn, pg_temp;

COMMENT ON FUNCTION authn.clear_tenant() IS
'Clears tenant context. Queries will return no rows until set_tenant is called.';
