-- =============================================================================
-- CONFIGURATION DEFAULTS FOR POSTKIT/AUTHN
-- =============================================================================
-- Sensible defaults for session duration, token expiry, and lockout settings.
-- Override via database settings: SET authn.session_duration = '30 days';
-- =============================================================================

-- Default session duration (used when expires_in is NULL)
CREATE OR REPLACE FUNCTION authn._session_duration()
RETURNS interval
AS $$
BEGIN
    RETURN COALESCE(
        current_setting('authn.session_duration', true)::interval,
        '7 days'::interval
    );
END;
$$ LANGUAGE plpgsql STABLE PARALLEL SAFE SET search_path = authn, pg_temp;

COMMENT ON FUNCTION authn._session_duration() IS
'Returns default session duration. Override with SET authn.session_duration.';


-- Default token expiry based on token type
CREATE OR REPLACE FUNCTION authn._token_expiry(p_token_type text)
RETURNS interval
AS $$
BEGIN
    RETURN CASE p_token_type
        WHEN 'password_reset' THEN '1 hour'::interval
        WHEN 'email_verify' THEN '24 hours'::interval
        WHEN 'magic_link' THEN '15 minutes'::interval
        ELSE '1 hour'::interval  -- Fallback for unknown types
    END;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SET search_path = authn, pg_temp;

COMMENT ON FUNCTION authn._token_expiry(text) IS
'Returns default token expiry for a given token type.
password_reset: 1 hour, email_verify: 24 hours, magic_link: 15 minutes.';


-- Default lockout window (sliding window for failed attempt counting)
CREATE OR REPLACE FUNCTION authn._lockout_window()
RETURNS interval
AS $$
BEGIN
    RETURN COALESCE(
        current_setting('authn.lockout_window', true)::interval,
        '15 minutes'::interval
    );
END;
$$ LANGUAGE plpgsql STABLE PARALLEL SAFE SET search_path = authn, pg_temp;

COMMENT ON FUNCTION authn._lockout_window() IS
'Returns lockout window duration. Override with SET authn.lockout_window.';


-- Maximum failed login attempts before lockout
CREATE OR REPLACE FUNCTION authn._max_login_attempts()
RETURNS int
AS $$
BEGIN
    RETURN COALESCE(
        current_setting('authn.max_login_attempts', true)::int,
        5
    );
END;
$$ LANGUAGE plpgsql STABLE PARALLEL SAFE SET search_path = authn, pg_temp;

COMMENT ON FUNCTION authn._max_login_attempts() IS
'Returns max failed attempts before lockout. Override with SET authn.max_login_attempts.';


-- Login attempts retention (for cleanup)
CREATE OR REPLACE FUNCTION authn._login_attempts_retention()
RETURNS interval
AS $$
BEGIN
    RETURN COALESCE(
        current_setting('authn.login_attempts_retention', true)::interval,
        '30 days'::interval
    );
END;
$$ LANGUAGE plpgsql STABLE PARALLEL SAFE SET search_path = authn, pg_temp;

COMMENT ON FUNCTION authn._login_attempts_retention() IS
'Returns how long to keep login attempts. Override with SET authn.login_attempts_retention.';
