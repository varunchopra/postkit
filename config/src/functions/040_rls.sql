-- @group Multi-tenancy

-- @function config.set_tenant
-- @brief Set tenant context for RLS (transaction-local, clears on commit).
-- Use BEGIN/COMMIT when autocommit is enabled.
-- @param p_tenant_id Tenant ID
-- @example BEGIN;
-- @example SELECT config.set_tenant('acme-corp');
-- @example SELECT * FROM config.entries;
-- @example COMMIT;
CREATE OR REPLACE FUNCTION config.set_tenant(p_tenant_id text)
RETURNS void
AS $$
BEGIN
    PERFORM config._validate_namespace(p_tenant_id);
    PERFORM set_config('config.tenant_id', p_tenant_id, true);
END;
$$ LANGUAGE plpgsql SET search_path = config, pg_temp;


-- @function config.clear_tenant
-- @brief Clear tenant context (fail-closed: queries return no rows).
-- Call before returning pooled connections or when switching tenants.
-- @example SELECT config.clear_tenant();
CREATE OR REPLACE FUNCTION config.clear_tenant()
RETURNS void
AS $$
BEGIN
    PERFORM set_config('config.tenant_id', '', true);
END;
$$ LANGUAGE plpgsql SET search_path = config, pg_temp;
