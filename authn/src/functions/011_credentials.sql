-- =============================================================================
-- CREDENTIAL MANAGEMENT FOR POSTKIT/AUTHN
-- =============================================================================
-- Password hash retrieval and update. The ONLY place password_hash is returned.
-- =============================================================================


-- =============================================================================
-- GET CREDENTIALS
-- =============================================================================
-- Returns password hash for caller to verify.
-- This is the ONLY function that returns password_hash.
-- Also returns disabled_at so caller can check before creating session.
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

COMMENT ON FUNCTION authn.get_credentials(text, text) IS
'Returns user credentials for login verification.
This is the ONLY function that returns password_hash.
Caller must verify the hash and check disabled_at before creating a session.';


-- =============================================================================
-- UPDATE PASSWORD
-- =============================================================================
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

COMMENT ON FUNCTION authn.update_password(uuid, text, text) IS
'Updates password hash. Never logs the hash value.';
