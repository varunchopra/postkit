-- @group Multi-tenancy

-- @function authz.set_tenant
-- @brief Set tenant context for RLS (transaction-local, clears on commit).
-- Use BEGIN/COMMIT when autocommit is enabled.
-- @param p_tenant_id Tenant ID
-- @example BEGIN;
-- @example SELECT authz.set_tenant('acme-corp');
-- @example SELECT * FROM authz.tuples;
-- @example COMMIT;
CREATE OR REPLACE FUNCTION authz.set_tenant (p_tenant_id text)
    RETURNS VOID
    AS $$
BEGIN
    PERFORM authz._validate_namespace(p_tenant_id);
    PERFORM set_config('authz.tenant_id', p_tenant_id, TRUE);
END;
$$
LANGUAGE plpgsql SECURITY INVOKER
SET search_path = authz, pg_temp;

-- @function authz.clear_tenant
-- @brief Clear tenant context (fail-closed: queries return no rows).
-- Call before returning pooled connections or when switching tenants.
-- @example SELECT authz.clear_tenant();
CREATE OR REPLACE FUNCTION authz.clear_tenant()
    RETURNS VOID
    AS $$
BEGIN
    PERFORM set_config('authz.tenant_id', '', TRUE);
END;
$$
LANGUAGE plpgsql SECURITY INVOKER
SET search_path = authz, pg_temp;
