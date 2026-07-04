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



-- @function authn._rls_bypassed
-- @brief True when the current role's queries bypass row-level security.
-- BYPASSRLS is not inherited through role membership, and FORCE RLS
-- removes the owner exemption, so superuser or a direct BYPASSRLS
-- attribute is the complete condition.
CREATE OR REPLACE FUNCTION authn._rls_bypassed()
RETURNS boolean AS $$
    SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user;
$$ LANGUAGE sql STABLE SECURITY INVOKER SET search_path = authn, pg_temp;


-- @function authn.assert_rls_active
-- @brief Raise unless row-level security applies to the current role.
-- @example SELECT authn.assert_rls_active();
-- Call from CI setup: a suite connecting as a superuser or BYPASSRLS role
-- bypasses every policy and exercises none of the tenancy model.
CREATE OR REPLACE FUNCTION authn.assert_rls_active()
RETURNS void AS $$
BEGIN
    IF authn._rls_bypassed() THEN
        RAISE EXCEPTION 'Role % bypasses row-level security', current_user
            USING ERRCODE = 'object_not_in_prerequisite_state',
                  HINT = 'postkit:authn:BIZ_RLS_NOT_ACTIVE';
    END IF;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = authn, pg_temp;
