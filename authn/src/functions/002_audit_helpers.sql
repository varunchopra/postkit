-- =============================================================================
-- AUDIT HELPER FUNCTIONS FOR POSTKIT/AUTHN
-- =============================================================================
-- Internal helper to centralize audit event logging.
-- Reads actor context from session config, with optional IP override for
-- cases where caller has the IP directly (e.g., record_login_attempt).
-- =============================================================================


-- =============================================================================
-- LOG AUDIT EVENT
-- =============================================================================
-- Internal helper that inserts audit events with actor context.
-- All audit logging flows through this function for consistency.
--
-- Parameters:
--   p_event_type    - Type of event (e.g., 'user_created', 'session_revoked')
--   p_namespace     - Tenant namespace
--   p_resource_type - Type of resource affected (e.g., 'user', 'session')
--   p_resource_id   - ID of resource affected
--   p_old_values    - Previous state (optional, for updates/deletes)
--   p_new_values    - New state (optional, for creates/updates)
--   p_ip_override   - Explicit IP address (bypasses session config lookup)
--
-- Actor context (actor_id, request_id, ip_address, user_agent) is read from
-- session config set by authn.set_actor(). If p_ip_override is provided,
-- it takes precedence over the session config ip_address.
CREATE OR REPLACE FUNCTION authn._log_event(
    p_event_type text,
    p_namespace text,
    p_resource_type text,
    p_resource_id text,
    p_old_values jsonb DEFAULT NULL,
    p_new_values jsonb DEFAULT NULL,
    p_ip_override inet DEFAULT NULL
)
RETURNS void
AS $$
DECLARE
    v_ip inet;
BEGIN
    -- Use override if provided, otherwise read from session config
    IF p_ip_override IS NOT NULL THEN
        v_ip := p_ip_override;
    ELSE
        v_ip := inet(nullif(current_setting('authn.ip_address', true), ''));
    END IF;

    INSERT INTO authn.audit_events (
        event_type,
        namespace,
        resource_type,
        resource_id,
        actor_id,
        request_id,
        ip_address,
        user_agent,
        old_values,
        new_values
    ) VALUES (
        p_event_type,
        p_namespace,
        p_resource_type,
        p_resource_id,
        nullif(current_setting('authn.actor_id', true), ''),
        nullif(current_setting('authn.request_id', true), ''),
        v_ip,
        nullif(current_setting('authn.user_agent', true), ''),
        p_old_values,
        p_new_values
    );
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = authn, pg_temp;

COMMENT ON FUNCTION authn._log_event(text, text, text, text, jsonb, jsonb, inet) IS
'Internal helper that inserts audit events with actor context from session config.
Use p_ip_override when caller has the IP directly (e.g., login attempts).';
