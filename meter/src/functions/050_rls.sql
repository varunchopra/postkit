-- @group Multi-tenancy

-- @function meter.set_tenant
-- @brief Set tenant context for RLS (transaction-local, clears on commit).
-- Use BEGIN/COMMIT when autocommit is enabled.
-- @param p_tenant_id Tenant ID
-- @example BEGIN;
-- @example SELECT meter.set_tenant('acme-corp');
-- @example SELECT * FROM meter.balances;
-- @example COMMIT;
CREATE FUNCTION meter.set_tenant(p_tenant_id text)
RETURNS void AS $$
BEGIN
    PERFORM meter._validate_namespace(p_tenant_id);
    PERFORM set_config('meter.tenant_id', p_tenant_id, true);
END;
$$ LANGUAGE plpgsql SET search_path = meter, pg_temp;


-- @function meter.clear_tenant
-- @brief Clear tenant context (fail-closed: queries return no rows).
-- Call before returning pooled connections or when switching tenants.
-- @example SELECT meter.clear_tenant();
CREATE FUNCTION meter.clear_tenant()
RETURNS void AS $$
BEGIN
    PERFORM set_config('meter.tenant_id', '', true);
END;
$$ LANGUAGE plpgsql SET search_path = meter, pg_temp;


-- @function meter.set_actor
-- @brief Set actor context for audit trail
-- @param p_actor_id The actor making changes
-- @param p_request_id Optional request/correlation ID
-- @param p_on_behalf_of Optional principal being represented
-- @param p_reason Optional reason for the action
-- @example SELECT meter.set_actor('user:admin-bob', 'req-123', 'user:alice', 'refund');
CREATE FUNCTION meter.set_actor(
    p_actor_id text,
    p_request_id text DEFAULT NULL,
    p_on_behalf_of text DEFAULT NULL,
    p_reason text DEFAULT NULL
)
RETURNS void AS $$
BEGIN
    PERFORM set_config('meter.actor_id', COALESCE(p_actor_id, ''), true);
    PERFORM set_config('meter.request_id', COALESCE(p_request_id, ''), true);
    PERFORM set_config('meter.on_behalf_of', COALESCE(p_on_behalf_of, ''), true);
    PERFORM set_config('meter.reason', COALESCE(p_reason, ''), true);
END;
$$ LANGUAGE plpgsql SET search_path = meter, pg_temp;


-- @function meter.clear_actor
-- @brief Clear actor context
-- @example SELECT meter.clear_actor();
CREATE FUNCTION meter.clear_actor()
RETURNS void AS $$
BEGIN
    PERFORM set_config('meter.actor_id', '', true);
    PERFORM set_config('meter.request_id', '', true);
    PERFORM set_config('meter.on_behalf_of', '', true);
    PERFORM set_config('meter.reason', '', true);
END;
$$ LANGUAGE plpgsql SET search_path = meter, pg_temp;
