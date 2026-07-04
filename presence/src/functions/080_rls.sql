-- @group Context

-- The context functions below omit SECURITY INVOKER. This is intentional and
-- consistent with the other postkit modules. These functions only call
-- set_config() which is always available to the session owner, and SECURITY
-- INVOKER would not change behavior since RLS policies are evaluated on the
-- calling session regardless.

-- @function presence.set_tenant
-- @brief Set the tenant context for RLS policies.
-- @param p_tenant_id Tenant/namespace identifier
-- Must be called before any operations. Transaction-local scope.
CREATE OR REPLACE FUNCTION presence.set_tenant(p_tenant_id text)
RETURNS void AS $$
BEGIN
    PERFORM presence._validate_namespace(p_tenant_id);
    PERFORM set_config('presence.tenant_id', p_tenant_id, true);
END;
$$ LANGUAGE plpgsql SET search_path = presence, pg_temp;


-- @function presence.clear_tenant
-- @brief Clear the tenant context.
-- Call before returning connections to pool.
CREATE OR REPLACE FUNCTION presence.clear_tenant()
RETURNS void AS $$
BEGIN
    PERFORM set_config('presence.tenant_id', '', true);
END;
$$ LANGUAGE plpgsql SET search_path = presence, pg_temp;


-- @function presence.set_actor
-- @brief Set actor context for the transition history.
-- @param p_actor_id ID of the user/system performing the action
-- @param p_request_id Optional request/trace ID for correlation
-- @param p_on_behalf_of Optional ID if acting on behalf of another user
-- @param p_reason Optional reason for the action
-- Actor context is captured on entities and presence.transitions rows.
CREATE OR REPLACE FUNCTION presence.set_actor(
    p_actor_id text DEFAULT NULL,
    p_request_id text DEFAULT NULL,
    p_on_behalf_of text DEFAULT NULL,
    p_reason text DEFAULT NULL
)
RETURNS void AS $$
BEGIN
    PERFORM set_config('presence.actor_id', COALESCE(p_actor_id, ''), true);
    PERFORM set_config('presence.request_id', COALESCE(p_request_id, ''), true);
    PERFORM set_config('presence.on_behalf_of', COALESCE(p_on_behalf_of, ''), true);
    PERFORM set_config('presence.reason', COALESCE(p_reason, ''), true);
END;
$$ LANGUAGE plpgsql SET search_path = presence, pg_temp;


-- @function presence.clear_actor
-- @brief Clear actor context.
-- Call before returning connections to pool.
CREATE OR REPLACE FUNCTION presence.clear_actor()
RETURNS void AS $$
BEGIN
    PERFORM set_config('presence.actor_id', '', true);
    PERFORM set_config('presence.request_id', '', true);
    PERFORM set_config('presence.on_behalf_of', '', true);
    PERFORM set_config('presence.reason', '', true);
END;
$$ LANGUAGE plpgsql SET search_path = presence, pg_temp;


-- @function presence._get_actor_context
-- @brief Get current actor context as a record.
-- @returns Table with actor_id, request_id, on_behalf_of, reason
-- Used internally by functions that need to capture actor context.
CREATE OR REPLACE FUNCTION presence._get_actor_context()
RETURNS TABLE(
    actor_id text,
    request_id text,
    on_behalf_of text,
    reason text
) AS $$
BEGIN
    RETURN QUERY SELECT
        nullif(current_setting('presence.actor_id', true), ''),
        nullif(current_setting('presence.request_id', true), ''),
        nullif(current_setting('presence.on_behalf_of', true), ''),
        nullif(current_setting('presence.reason', true), '');
END;
$$ LANGUAGE plpgsql STABLE PARALLEL SAFE SECURITY INVOKER SET search_path = presence, pg_temp;


-- @function presence._rls_bypassed
-- @brief True when the current role's queries bypass row-level security.
-- BYPASSRLS is not inherited through role membership, and FORCE RLS
-- removes the owner exemption, so superuser or a direct BYPASSRLS
-- attribute is the complete condition.
CREATE OR REPLACE FUNCTION presence._rls_bypassed()
RETURNS boolean AS $$
    SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user;
$$ LANGUAGE sql STABLE SECURITY INVOKER SET search_path = presence, pg_temp;


-- @function presence.assert_rls_active
-- @brief Raise unless row-level security applies to the current role.
-- @example SELECT presence.assert_rls_active();
-- Call from CI setup: a suite connecting as a superuser or BYPASSRLS role
-- bypasses every policy and exercises none of the tenancy model.
CREATE OR REPLACE FUNCTION presence.assert_rls_active()
RETURNS void AS $$
BEGIN
    IF presence._rls_bypassed() THEN
        RAISE EXCEPTION 'Role % bypasses row-level security', current_user
            USING ERRCODE = 'object_not_in_prerequisite_state',
                  HINT = 'postkit:presence:BIZ_RLS_NOT_ACTIVE';
    END IF;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = presence, pg_temp;
