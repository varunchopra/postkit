-- @group Context

-- The context functions below omit SECURITY INVOKER. This is intentional and
-- consistent with the other postkit modules. These functions only call
-- set_config() which is always available to the session owner, and SECURITY
-- INVOKER would not change behavior since RLS policies are evaluated on the
-- calling session regardless.

-- @function outbox.set_tenant
-- @brief Set the tenant context for RLS policies.
-- @param p_tenant_id Tenant/namespace identifier
-- Must be called before any operations. Transaction-local scope.
CREATE OR REPLACE FUNCTION outbox.set_tenant(p_tenant_id text)
RETURNS void AS $$
BEGIN
    PERFORM outbox._validate_namespace(p_tenant_id);
    PERFORM set_config('outbox.tenant_id', p_tenant_id, true);
END;
$$ LANGUAGE plpgsql SET search_path = outbox, pg_temp;


-- @function outbox.clear_tenant
-- @brief Clear the tenant context.
-- Call before returning connections to pool.
CREATE OR REPLACE FUNCTION outbox.clear_tenant()
RETURNS void AS $$
BEGIN
    PERFORM set_config('outbox.tenant_id', '', true);
END;
$$ LANGUAGE plpgsql SET search_path = outbox, pg_temp;


-- @function outbox.set_actor
-- @brief Set actor context, captured on emitted events.
-- @param p_actor_id ID of the user/system performing the action
-- @param p_request_id Optional request/trace ID for correlation
-- @param p_on_behalf_of Optional ID if acting on behalf of another user
-- @param p_reason Optional reason for the action
CREATE OR REPLACE FUNCTION outbox.set_actor(
    p_actor_id text DEFAULT NULL,
    p_request_id text DEFAULT NULL,
    p_on_behalf_of text DEFAULT NULL,
    p_reason text DEFAULT NULL
)
RETURNS void AS $$
BEGIN
    PERFORM set_config('outbox.actor_id', COALESCE(p_actor_id, ''), true);
    PERFORM set_config('outbox.request_id', COALESCE(p_request_id, ''), true);
    PERFORM set_config('outbox.on_behalf_of', COALESCE(p_on_behalf_of, ''), true);
    PERFORM set_config('outbox.reason', COALESCE(p_reason, ''), true);
END;
$$ LANGUAGE plpgsql SET search_path = outbox, pg_temp;


-- @function outbox.clear_actor
-- @brief Clear actor context.
-- Call before returning connections to pool.
CREATE OR REPLACE FUNCTION outbox.clear_actor()
RETURNS void AS $$
BEGIN
    PERFORM set_config('outbox.actor_id', '', true);
    PERFORM set_config('outbox.request_id', '', true);
    PERFORM set_config('outbox.on_behalf_of', '', true);
    PERFORM set_config('outbox.reason', '', true);
END;
$$ LANGUAGE plpgsql SET search_path = outbox, pg_temp;


-- @function outbox._get_actor_context
-- @brief Get current actor context as a record.
-- @returns Table with actor_id, request_id, on_behalf_of, reason
-- Used internally by functions that need to capture actor context.
CREATE OR REPLACE FUNCTION outbox._get_actor_context()
RETURNS TABLE(
    actor_id text,
    request_id text,
    on_behalf_of text,
    reason text
) AS $$
BEGIN
    RETURN QUERY SELECT
        nullif(current_setting('outbox.actor_id', true), ''),
        nullif(current_setting('outbox.request_id', true), ''),
        nullif(current_setting('outbox.on_behalf_of', true), ''),
        nullif(current_setting('outbox.reason', true), '');
END;
$$ LANGUAGE plpgsql STABLE PARALLEL SAFE SECURITY INVOKER SET search_path = outbox, pg_temp;
