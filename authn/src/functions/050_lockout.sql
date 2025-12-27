-- =============================================================================
-- LOCKOUT MANAGEMENT FOR POSTKIT/AUTHN
-- =============================================================================
-- Tracks login attempts and enforces lockout after too many failures.
-- is_locked_out uses identical code path regardless of email existence.
-- =============================================================================


-- =============================================================================
-- RECORD LOGIN ATTEMPT
-- =============================================================================
CREATE OR REPLACE FUNCTION authn.record_login_attempt(
    p_email text,
    p_success boolean,
    p_ip_address inet DEFAULT NULL,
    p_namespace text DEFAULT 'default'
)
RETURNS void
AS $$
DECLARE
    v_normalized_email text;
    v_is_locked_out boolean;
BEGIN
    v_normalized_email := authn._validate_email(p_email);
    PERFORM authn._validate_namespace(p_namespace);

    INSERT INTO authn.login_attempts (
        namespace, email, success, ip_address
    ) VALUES (
        p_namespace, v_normalized_email, p_success, p_ip_address
    );

    -- If this failed attempt triggers lockout, log it
    IF NOT p_success THEN
        -- Check if now locked out (use defaults)
        v_is_locked_out := authn.is_locked_out(p_email, p_namespace);

        IF v_is_locked_out THEN
            PERFORM authn._log_event(
                'lockout_triggered', p_namespace, 'email', v_normalized_email,
                NULL,
                jsonb_build_object('email', v_normalized_email),
                p_ip_address
            );
        ELSE
            -- Log failed attempt (not lockout, just failure)
            PERFORM authn._log_event(
                'login_attempt_failed', p_namespace, 'email', v_normalized_email,
                NULL,
                jsonb_build_object('email', v_normalized_email),
                p_ip_address
            );
        END IF;
    END IF;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = authn, pg_temp;

COMMENT ON FUNCTION authn.record_login_attempt(text, boolean, inet, text) IS
'Records a login attempt. Logs lockout_triggered if threshold reached.';


-- =============================================================================
-- IS LOCKED OUT
-- =============================================================================
-- Executes identical code path regardless of whether email exists in users table.
-- Note: execution time may vary based on login_attempts count; application layer
-- should add constant-time delay if stricter timing guarantees are required.
CREATE OR REPLACE FUNCTION authn.is_locked_out(
    p_email text,
    p_namespace text DEFAULT 'default',
    p_window interval DEFAULT NULL,
    p_max_attempts int DEFAULT NULL
)
RETURNS boolean
AS $$
DECLARE
    v_normalized_email text;
    v_window interval;
    v_max_attempts int;
    v_failed_count int;
BEGIN
    v_normalized_email := authn._validate_email(p_email);
    PERFORM authn._validate_namespace(p_namespace);

    v_window := COALESCE(p_window, authn._lockout_window());
    v_max_attempts := COALESCE(p_max_attempts, authn._max_login_attempts());

    -- Count failed attempts in window
    -- Uses index: login_attempts_lockout_idx
    -- Note: email is already lowercase (normalized by _validate_email)
    SELECT COUNT(*)::int INTO v_failed_count
    FROM authn.login_attempts
    WHERE namespace = p_namespace
      AND email = v_normalized_email
      AND success = false
      AND attempted_at > now() - v_window;

    RETURN v_failed_count >= v_max_attempts;
END;
$$ LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = authn, pg_temp;

COMMENT ON FUNCTION authn.is_locked_out(text, text, interval, int) IS
'Returns true if too many failed attempts in window.
Same code path regardless of email existence in users table.';


-- =============================================================================
-- GET RECENT ATTEMPTS
-- =============================================================================
CREATE OR REPLACE FUNCTION authn.get_recent_attempts(
    p_email text,
    p_namespace text DEFAULT 'default',
    p_limit int DEFAULT 10
)
RETURNS TABLE(
    success boolean,
    ip_address inet,
    attempted_at timestamptz
)
AS $$
DECLARE
    v_normalized_email text;
BEGIN
    v_normalized_email := authn._validate_email(p_email);
    PERFORM authn._validate_namespace(p_namespace);
    PERFORM authn._warn_namespace_mismatch(p_namespace);

    -- Clamp limit
    IF p_limit > 100 THEN
        p_limit := 100;
    END IF;

    RETURN QUERY
    SELECT
        la.success,
        la.ip_address,
        la.attempted_at
    FROM authn.login_attempts la
    WHERE la.namespace = p_namespace
      AND la.email = v_normalized_email
    ORDER BY la.attempted_at DESC
    LIMIT p_limit;
END;
$$ LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = authn, pg_temp;

COMMENT ON FUNCTION authn.get_recent_attempts(text, text, int) IS
'Returns recent login attempts for admin UI.';


-- =============================================================================
-- CLEAR ATTEMPTS
-- =============================================================================
CREATE OR REPLACE FUNCTION authn.clear_attempts(
    p_email text,
    p_namespace text DEFAULT 'default'
)
RETURNS bigint
AS $$
DECLARE
    v_normalized_email text;
    v_count bigint;
BEGIN
    v_normalized_email := authn._validate_email(p_email);
    PERFORM authn._validate_namespace(p_namespace);

    DELETE FROM authn.login_attempts
    WHERE namespace = p_namespace
      AND email = v_normalized_email;

    GET DIAGNOSTICS v_count = ROW_COUNT;

    RETURN v_count;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = authn, pg_temp;

COMMENT ON FUNCTION authn.clear_attempts(text, text) IS
'Clears all login attempts for an email. Admin function.';
