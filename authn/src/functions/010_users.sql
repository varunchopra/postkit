-- =============================================================================
-- USER MANAGEMENT FOR POSTKIT/AUTHN
-- =============================================================================
-- Core user CRUD operations. Password hash is optional (NULL for SSO users).
-- Email is normalized to lowercase.
-- =============================================================================


-- =============================================================================
-- CREATE USER
-- =============================================================================
CREATE OR REPLACE FUNCTION authn.create_user(
    p_email text,
    p_password_hash text DEFAULT NULL,
    p_namespace text DEFAULT 'default'
)
RETURNS uuid
AS $$
DECLARE
    v_user_id uuid;
    v_normalized_email text;
BEGIN
    -- Validate inputs
    v_normalized_email := authn._validate_email(p_email);
    PERFORM authn._validate_hash(p_password_hash, 'password_hash', true);  -- allow null
    PERFORM authn._validate_namespace(p_namespace);

    -- Insert user
    INSERT INTO authn.users (namespace, email, password_hash)
    VALUES (p_namespace, v_normalized_email, p_password_hash)
    RETURNING id INTO v_user_id;

    -- Audit log (exclude password_hash)
    PERFORM authn._log_event(
        'user_created', p_namespace, 'user', v_user_id::text,
        NULL, jsonb_build_object('email', v_normalized_email)
    );

    RETURN v_user_id;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = authn, pg_temp;

COMMENT ON FUNCTION authn.create_user(text, text, text) IS
'Creates a new user. Password hash is optional (NULL for SSO-only users).
Email is normalized to lowercase and trimmed.';


-- =============================================================================
-- GET USER
-- =============================================================================
CREATE OR REPLACE FUNCTION authn.get_user(
    p_user_id uuid,
    p_namespace text DEFAULT 'default'
)
RETURNS TABLE(
    id uuid,
    email text,
    email_verified_at timestamptz,
    disabled_at timestamptz,
    created_at timestamptz,
    updated_at timestamptz
)
AS $$
BEGIN
    PERFORM authn._validate_namespace(p_namespace);
    PERFORM authn._warn_namespace_mismatch(p_namespace);

    RETURN QUERY
    SELECT
        u.id,
        u.email,
        u.email_verified_at,
        u.disabled_at,
        u.created_at,
        u.updated_at
    FROM authn.users u
    WHERE u.id = p_user_id
      AND u.namespace = p_namespace;
END;
$$ LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = authn, pg_temp;

COMMENT ON FUNCTION authn.get_user(uuid, text) IS
'Returns user by ID. Does not return password_hash for security.';


-- =============================================================================
-- GET USER BY EMAIL
-- =============================================================================
CREATE OR REPLACE FUNCTION authn.get_user_by_email(
    p_email text,
    p_namespace text DEFAULT 'default'
)
RETURNS TABLE(
    id uuid,
    email text,
    email_verified_at timestamptz,
    disabled_at timestamptz,
    created_at timestamptz,
    updated_at timestamptz
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
        u.email,
        u.email_verified_at,
        u.disabled_at,
        u.created_at,
        u.updated_at
    FROM authn.users u
    WHERE u.email = v_normalized_email
      AND u.namespace = p_namespace;
END;
$$ LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = authn, pg_temp;

COMMENT ON FUNCTION authn.get_user_by_email(text, text) IS
'Returns user by email. Email is normalized before lookup.';


-- =============================================================================
-- UPDATE EMAIL
-- =============================================================================
CREATE OR REPLACE FUNCTION authn.update_email(
    p_user_id uuid,
    p_new_email text,
    p_namespace text DEFAULT 'default'
)
RETURNS boolean
AS $$
DECLARE
    v_old_email text;
    v_new_email text;
    v_count int;
BEGIN
    v_new_email := authn._validate_email(p_new_email);
    PERFORM authn._validate_namespace(p_namespace);

    -- Get old email for audit
    SELECT email INTO v_old_email
    FROM authn.users
    WHERE id = p_user_id AND namespace = p_namespace;

    IF v_old_email IS NULL THEN
        RETURN false;
    END IF;

    -- Update email and clear verification
    UPDATE authn.users
    SET email = v_new_email,
        email_verified_at = NULL,
        updated_at = now()
    WHERE id = p_user_id
      AND namespace = p_namespace;

    GET DIAGNOSTICS v_count = ROW_COUNT;

    IF v_count > 0 THEN
        -- Audit log
        PERFORM authn._log_event(
            'email_updated', p_namespace, 'user', p_user_id::text,
            jsonb_build_object('email', v_old_email),
            jsonb_build_object('email', v_new_email)
        );
    END IF;

    RETURN v_count > 0;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = authn, pg_temp;

COMMENT ON FUNCTION authn.update_email(uuid, text, text) IS
'Updates user email and clears email_verified_at.';


-- =============================================================================
-- DISABLE USER
-- =============================================================================
CREATE OR REPLACE FUNCTION authn.disable_user(
    p_user_id uuid,
    p_namespace text DEFAULT 'default'
)
RETURNS boolean
AS $$
DECLARE
    v_count int;
    v_sessions_revoked int;
BEGIN
    PERFORM authn._validate_namespace(p_namespace);

    -- Disable user
    UPDATE authn.users
    SET disabled_at = now(),
        updated_at = now()
    WHERE id = p_user_id
      AND namespace = p_namespace
      AND disabled_at IS NULL;

    GET DIAGNOSTICS v_count = ROW_COUNT;

    IF v_count > 0 THEN
        -- Revoke all active sessions
        UPDATE authn.sessions
        SET revoked_at = now()
        WHERE user_id = p_user_id
          AND namespace = p_namespace
          AND revoked_at IS NULL;

        GET DIAGNOSTICS v_sessions_revoked = ROW_COUNT;

        -- Audit log
        PERFORM authn._log_event(
            'user_disabled', p_namespace, 'user', p_user_id::text,
            NULL, jsonb_build_object('sessions_revoked', v_sessions_revoked)
        );
    END IF;

    RETURN v_count > 0;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = authn, pg_temp;

COMMENT ON FUNCTION authn.disable_user(uuid, text) IS
'Disables user and revokes all active sessions.';


-- =============================================================================
-- ENABLE USER
-- =============================================================================
CREATE OR REPLACE FUNCTION authn.enable_user(
    p_user_id uuid,
    p_namespace text DEFAULT 'default'
)
RETURNS boolean
AS $$
DECLARE
    v_count int;
BEGIN
    PERFORM authn._validate_namespace(p_namespace);

    UPDATE authn.users
    SET disabled_at = NULL,
        updated_at = now()
    WHERE id = p_user_id
      AND namespace = p_namespace
      AND disabled_at IS NOT NULL;

    GET DIAGNOSTICS v_count = ROW_COUNT;

    IF v_count > 0 THEN
        -- Audit log
        PERFORM authn._log_event(
            'user_enabled', p_namespace, 'user', p_user_id::text
        );
    END IF;

    RETURN v_count > 0;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = authn, pg_temp;

COMMENT ON FUNCTION authn.enable_user(uuid, text) IS
'Re-enables a disabled user.';


-- =============================================================================
-- DELETE USER
-- =============================================================================
CREATE OR REPLACE FUNCTION authn.delete_user(
    p_user_id uuid,
    p_namespace text DEFAULT 'default'
)
RETURNS boolean
AS $$
DECLARE
    v_email text;
    v_count int;
BEGIN
    PERFORM authn._validate_namespace(p_namespace);

    -- Get email for audit before deletion
    SELECT email INTO v_email
    FROM authn.users
    WHERE id = p_user_id AND namespace = p_namespace;

    IF v_email IS NULL THEN
        RETURN false;
    END IF;

    -- Delete user (cascades to sessions, tokens, mfa)
    DELETE FROM authn.users
    WHERE id = p_user_id
      AND namespace = p_namespace;

    GET DIAGNOSTICS v_count = ROW_COUNT;

    IF v_count > 0 THEN
        -- Audit log
        PERFORM authn._log_event(
            'user_deleted', p_namespace, 'user', p_user_id::text,
            jsonb_build_object('email', v_email)
        );
    END IF;

    RETURN v_count > 0;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = authn, pg_temp;

COMMENT ON FUNCTION authn.delete_user(uuid, text) IS
'Hard deletes user. Cascades to sessions, tokens, and MFA secrets.';


-- =============================================================================
-- LIST USERS
-- =============================================================================
CREATE OR REPLACE FUNCTION authn.list_users(
    p_namespace text DEFAULT 'default',
    p_limit int DEFAULT 100,
    p_cursor uuid DEFAULT NULL
)
RETURNS TABLE(
    id uuid,
    email text,
    email_verified_at timestamptz,
    disabled_at timestamptz,
    created_at timestamptz,
    updated_at timestamptz
)
AS $$
BEGIN
    PERFORM authn._validate_namespace(p_namespace);
    PERFORM authn._warn_namespace_mismatch(p_namespace);

    -- Clamp limit
    IF p_limit > 1000 THEN
        p_limit := 1000;
    END IF;

    RETURN QUERY
    SELECT
        u.id,
        u.email,
        u.email_verified_at,
        u.disabled_at,
        u.created_at,
        u.updated_at
    FROM authn.users u
    WHERE u.namespace = p_namespace
      AND (p_cursor IS NULL OR u.id > p_cursor)
    ORDER BY u.id
    LIMIT p_limit;
END;
$$ LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = authn, pg_temp;

COMMENT ON FUNCTION authn.list_users(text, int, uuid) IS
'Lists users with cursor-based pagination. Max 1000 per page.';
