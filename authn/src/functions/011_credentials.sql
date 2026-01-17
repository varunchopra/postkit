-- @group Credentials

-- @function authn.get_credentials
-- @brief Get password hash for login verification (only function that returns hash)
-- @returns user_id, password_hash, disabled_at. Verify hash in your app, check
--   disabled_at, then call create_session if valid.
--
-- SECURITY NOTE: This function intentionally does NOT check lockout status.
-- The recommended login flow is:
--   1. Call is_locked_out(email) - reject if locked
--   2. Call get_credentials(email) - get hash for verification
--   3. Verify password hash in application code (argon2id)
--   4. Call record_login_attempt(email, success, ip) - track attempt
--   5. If success: call create_session() and return token
--
-- This separation of concerns allows flexibility:
--   - Different lockout policies per user tier or namespace
--   - Custom rate limiting at the application layer
--   - A/B testing authentication flows
-- The application MUST call is_locked_out() before get_credentials() to prevent
-- credential stuffing attacks. Password hashes should use argon2id to make
-- offline cracking impractical even if hashes are harvested.
--
-- @example SELECT * FROM authn.get_credentials('alice@example.com');
CREATE OR REPLACE FUNCTION authn.get_credentials(
    p_email text,
    p_namespace text DEFAULT 'default'
)
RETURNS TABLE(
    user_id uuid,
    password_hash text,
    disabled_at timestamptz
)
AS $$
DECLARE
    v_normalized_email text;
BEGIN
    v_normalized_email := authn._validate_email(p_email);
    PERFORM authn._validate_namespace(p_namespace);
    PERFORM authn._warn_namespace_mismatch(p_namespace);

    RETURN QUERY
    SELECT
        u.id,
        u.password_hash,
        u.disabled_at
    FROM authn.users u
    WHERE u.email = v_normalized_email
      AND u.namespace = p_namespace;
END;
$$ LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = authn, pg_temp;

-- @function authn.update_password
-- @brief Update user's password hash (after password change or reset)
-- @param p_new_password_hash Argon2id hash of new password
-- @example SELECT authn.update_password(user_id, '$argon2id$...');
CREATE OR REPLACE FUNCTION authn.update_password(
    p_user_id uuid,
    p_new_password_hash text,
    p_namespace text DEFAULT 'default'
)
RETURNS boolean
AS $$
DECLARE
    v_count int;
BEGIN
    PERFORM authn._validate_hash(p_new_password_hash, 'password_hash', false);  -- required
    PERFORM authn._validate_namespace(p_namespace);

    UPDATE authn.users
    SET password_hash = p_new_password_hash,
        updated_at = now()
    WHERE id = p_user_id
      AND namespace = p_namespace;

    GET DIAGNOSTICS v_count = ROW_COUNT;

    IF v_count > 0 THEN
        -- Audit log (never log the hash!)
        PERFORM authn._log_event(
            'password_updated', p_namespace, 'user', p_user_id::text
        );
    END IF;

    RETURN v_count > 0;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = authn, pg_temp;

