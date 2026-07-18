-- @group Lockout

-- @function authn.record_login_attempt
-- @brief Record a login attempt (success or failure) for lockout tracking
-- @param p_success True for successful login, false for failed
-- @example -- After password verification
-- @example SELECT authn.record_login_attempt(email, password_correct, '1.2.3.4');
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

-- @function authn.is_locked_out
-- @brief Check if email is locked out due to too many failed attempts
-- @param p_window Time window to count failures (default from config)
-- @param p_max_attempts Max failures before lockout (default from config)
-- @returns True if locked out. Check before allowing login attempt.
-- @example IF authn.is_locked_out(email) THEN show_lockout_error(); END IF;
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

-- @function authn.get_recent_attempts
-- @brief Get recent login attempts for admin UI or user security page
-- @returns success, ip_address, attempted_at
-- @example SELECT * FROM authn.get_recent_attempts('alice@example.com');
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

    PERFORM authn._validate_limit(p_limit, 'limit', 100);

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

-- @function authn.clear_attempts
-- @brief Clear login attempts to unlock a user (admin function)
-- @returns Count of attempts cleared
-- @example SELECT authn.clear_attempts('alice@example.com'); -- Unlock user
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
