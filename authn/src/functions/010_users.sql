-- @group Users

-- @function authn.create_user
-- @brief Create a new user account
-- @param p_password_hash Argon2id hash from your app. NULL for SSO-only users.
-- @returns User ID (UUID)
-- @example SELECT authn.create_user('alice@example.com', '$argon2id$...', 'default');
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

-- @function authn.get_user
-- @brief Get user by ID (does not return password hash)
-- @example SELECT * FROM authn.get_user('550e8400-e29b-41d4-a716-446655440000');
CREATE OR REPLACE FUNCTION authn.get_user(
    p_user_id uuid,
    p_namespace text DEFAULT 'default'
)
RETURNS TABLE(
    user_id uuid,
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
        u.id AS user_id,
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

-- @function authn.get_user_by_email
-- @brief Look up user by email (normalized to lowercase)
-- @example SELECT * FROM authn.get_user_by_email('Alice@Example.com');
CREATE OR REPLACE FUNCTION authn.get_user_by_email(
    p_email text,
    p_namespace text DEFAULT 'default'
)
RETURNS TABLE(
    user_id uuid,
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
        u.id AS user_id,
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

-- @function authn.update_email
-- @brief Change user's email address (clears email_verified_at)
-- @returns True if user was found and updated
-- @example SELECT authn.update_email(user_id, 'new@example.com');
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

-- @function authn.disable_user
-- @brief Disable user and revoke all credentials (sessions, API keys, refresh tokens, impersonations, tokens)
-- @returns True if user was found and disabled
-- @example SELECT authn.disable_user(user_id);
CREATE OR REPLACE FUNCTION authn.disable_user(
    p_user_id uuid,
    p_namespace text DEFAULT 'default'
)
RETURNS boolean
AS $$
DECLARE
    v_count int;
    v_sessions_revoked int;
    v_api_keys_revoked int;
    v_refresh_tokens_revoked int;
    v_impersonations_ended int;
    v_operator_impersonations_ended int;
    v_tokens_invalidated int;
BEGIN
    PERFORM authn._validate_namespace(p_namespace);

    UPDATE authn.users
    SET disabled_at = now(), updated_at = now()
    WHERE id = p_user_id AND namespace = p_namespace AND disabled_at IS NULL;
    GET DIAGNOSTICS v_count = ROW_COUNT;

    IF v_count > 0 THEN
        UPDATE authn.sessions SET revoked_at = now()
        WHERE user_id = p_user_id AND namespace = p_namespace AND revoked_at IS NULL;
        GET DIAGNOSTICS v_sessions_revoked = ROW_COUNT;

        UPDATE authn.api_keys SET revoked_at = now()
        WHERE user_id = p_user_id AND namespace = p_namespace AND revoked_at IS NULL;
        GET DIAGNOSTICS v_api_keys_revoked = ROW_COUNT;

        UPDATE authn.refresh_tokens SET revoked_at = now()
        WHERE user_id = p_user_id AND namespace = p_namespace AND revoked_at IS NULL;
        GET DIAGNOSTICS v_refresh_tokens_revoked = ROW_COUNT;

        v_impersonations_ended := authn._end_impersonations_for_user(p_user_id, p_namespace);
        v_operator_impersonations_ended := authn._end_operator_impersonations_for_operator(p_user_id, p_namespace);

        UPDATE authn.tokens SET used_at = now()
        WHERE user_id = p_user_id AND namespace = p_namespace AND used_at IS NULL;
        GET DIAGNOSTICS v_tokens_invalidated = ROW_COUNT;

        PERFORM authn._log_event(
            'user_disabled', p_namespace, 'user', p_user_id::text, NULL,
            jsonb_build_object(
                'sessions_revoked', v_sessions_revoked,
                'api_keys_revoked', v_api_keys_revoked,
                'refresh_tokens_revoked', v_refresh_tokens_revoked,
                'impersonations_ended', v_impersonations_ended,
                'operator_impersonations_ended', v_operator_impersonations_ended,
                'tokens_invalidated', v_tokens_invalidated
            )
        );
    END IF;

    RETURN v_count > 0;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = authn, pg_temp;

-- @function authn.enable_user
-- @brief Re-enable a disabled user account
-- @example SELECT authn.enable_user(user_id);
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

-- @function authn.delete_user
-- @brief Permanently delete user and all their data (sessions, tokens, credentials)
-- @returns True if user was found and deleted
-- @example SELECT authn.delete_user(user_id); -- Irreversible!
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

-- @function authn.list_users
-- @brief List users with cursor-based pagination
-- @param p_limit Max users per page (default 100, max 1000)
-- @param p_cursor User ID to start after (for pagination)
-- @example SELECT * FROM authn.list_users('default', 50, NULL); -- First page
CREATE OR REPLACE FUNCTION authn.list_users(
    p_namespace text DEFAULT 'default',
    p_limit int DEFAULT 100,
    p_cursor uuid DEFAULT NULL
)
RETURNS TABLE(
    user_id uuid,
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
        u.id AS user_id,
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

-- @function authn.get_users_batch
-- @brief Get multiple users by ID in a single query
-- @param p_user_ids Array of user IDs to fetch
-- @param p_namespace Namespace to search in
-- @returns User records for each found ID (missing IDs are silently omitted)
-- @example SELECT * FROM authn.get_users_batch(ARRAY['uuid1', 'uuid2']::uuid[], 'default');
CREATE OR REPLACE FUNCTION authn.get_users_batch(
    p_user_ids uuid[],
    p_namespace text DEFAULT 'default'
)
RETURNS TABLE(
    user_id uuid,
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
        u.id AS user_id,
        u.email,
        u.email_verified_at,
        u.disabled_at,
        u.created_at,
        u.updated_at
    FROM authn.users u
    WHERE u.id = ANY(p_user_ids)
      AND u.namespace = p_namespace;
END;
$$ LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = authn, pg_temp;

-- @function authn.get_or_create_user
-- @brief Atomically get existing user or create new one (for SSO flows)
-- @param p_email User's email address (normalized to lowercase)
-- @param p_password_hash Optional password hash (NULL for SSO-only users)
-- @param p_namespace Namespace to use
-- @returns user_id, created (true if new user), disabled (true if user is disabled)
--
-- EDGE CASE: In an extremely rare race condition where:
--   1. INSERT fails because user exists (ON CONFLICT DO NOTHING)
--   2. Another transaction DELETEs that user before our SELECT
--   3. Our SELECT returns NULL
-- This function will return (NULL, false, false). The SDK raises AuthnError in this case.
-- This scenario requires user deletion during concurrent creation, which is operationally
-- very unusual. If this is a concern for your use case, wrap the call in retry logic.
--
-- @example -- SSO callback: get or create user
-- @example SELECT * FROM authn.get_or_create_user('alice@example.com', NULL, 'default');
CREATE OR REPLACE FUNCTION authn.get_or_create_user(
    p_email text,
    p_password_hash text DEFAULT NULL,
    p_namespace text DEFAULT 'default'
)
RETURNS TABLE(
    user_id uuid,
    created boolean,
    disabled boolean
)
AS $$
DECLARE
    v_user_id uuid;
    v_disabled_at timestamptz;
    v_normalized_email text;
    v_created boolean := false;
BEGIN
    -- Validate inputs
    v_normalized_email := authn._validate_email(p_email);
    PERFORM authn._validate_hash(p_password_hash, 'password_hash', true);  -- allow null
    PERFORM authn._validate_namespace(p_namespace);

    -- Try to insert, do nothing on conflict (atomic upsert pattern)
    INSERT INTO authn.users (namespace, email, password_hash)
    VALUES (p_namespace, v_normalized_email, p_password_hash)
    ON CONFLICT (namespace, email) DO NOTHING
    RETURNING id INTO v_user_id;

    -- If insert succeeded, we created a new user
    IF v_user_id IS NOT NULL THEN
        v_created := true;

        -- Audit log
        PERFORM authn._log_event(
            'user_created', p_namespace, 'user', v_user_id::text,
            NULL, jsonb_build_object('email', v_normalized_email, 'via', 'get_or_create')
        );

        RETURN QUERY SELECT v_user_id, v_created, false;
        RETURN;
    END IF;

    -- Insert failed due to conflict, fetch existing user
    SELECT u.id, u.disabled_at
    INTO v_user_id, v_disabled_at
    FROM authn.users u
    WHERE u.email = v_normalized_email
      AND u.namespace = p_namespace;

    RETURN QUERY SELECT v_user_id, false, (v_disabled_at IS NOT NULL);
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = authn, pg_temp;

