-- @group Multi-tenancy

-- @function authn.set_tenant
-- @brief Set tenant context for RLS (transaction-local, clears on commit).
-- Use BEGIN/COMMIT when autocommit is enabled.
-- @param p_tenant_id Tenant ID
-- @example BEGIN;
-- @example SELECT authn.set_tenant('acme-corp');
-- @example SELECT * FROM authn.users;
-- @example COMMIT;
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

-- @function authn.clear_tenant
-- @brief Clear tenant context (fail-closed: queries return no rows).
-- Call before returning pooled connections or when switching tenants.
-- @example SELECT authn.clear_tenant();
CREATE OR REPLACE FUNCTION authn.clear_tenant()
RETURNS void
AS $$
BEGIN
    PERFORM set_config('authn.tenant_id', '', true);
END;
$$ LANGUAGE plpgsql SET search_path = authn, pg_temp;

