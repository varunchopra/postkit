-- @group Sessions

-- @function authn.create_session
-- @brief Create a session after successful login
-- @param p_token_hash SHA-256 hash of the session token (you generate the token,
--   hash it, store hash here, send raw token to client)
-- @param p_expires_in Session duration (default 7 days)
-- @returns Session ID
-- @example -- After verifying password (token_hash is pre-computed SHA-256 hex string)
-- @example SELECT authn.create_session(user_id, 'a1b2c3...', '7 days', '1.2.3.4');
CREATE OR REPLACE FUNCTION authn.create_session(
    p_user_id uuid,
    p_token_hash text,
    p_expires_in interval DEFAULT NULL,
    p_ip_address inet DEFAULT NULL,
    p_user_agent text DEFAULT NULL,
    p_namespace text DEFAULT 'default'
)
RETURNS uuid
AS $$
DECLARE
    v_session_id uuid;
    v_expires_at timestamptz;
BEGIN
    PERFORM authn._validate_hash(p_token_hash, 'token_hash', false);
    PERFORM authn._validate_namespace(p_namespace);

    -- Use default duration if not specified
    v_expires_at := now() + COALESCE(p_expires_in, authn._session_duration());

    INSERT INTO authn.sessions (
        namespace, user_id, token_hash, expires_at, ip_address, user_agent
    ) VALUES (
        p_namespace, p_user_id, p_token_hash, v_expires_at, p_ip_address, p_user_agent
    )
    RETURNING id INTO v_session_id;

    -- Audit log (never log token_hash!)
    PERFORM authn._log_event(
        'session_created', p_namespace, 'session', v_session_id::text,
        NULL,
        jsonb_build_object('user_id', p_user_id, 'expires_at', v_expires_at),
        p_ip_address
    );

    RETURN v_session_id;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = authn, pg_temp;

-- @function authn.validate_session
-- @brief Check if session is valid and get user info (hot path, no logging)
-- @returns user_id, email, session_id if valid. Empty if expired/revoked/disabled.
--   Also returns impersonation context if this is an impersonation session.
--   When impersonation is detected, automatically sets audit actor context.
--
-- DESIGN NOTE: This function has a deliberate side effect for impersonation sessions.
-- When an impersonation session is detected, it automatically calls set_actor() to configure
-- the audit context. This is intentional for several reasons:
--   1. Convenience: Applications don't need to know about impersonation internals
--   2. Safety: Ensures all actions during impersonation are properly attributed in audit logs
--   3. Transparency: The impersonation context is always returned so apps can display it
-- The function is marked VOLATILE due to this side effect. The side effect only triggers
-- on the rare impersonation path (typically <0.01% of calls). For pure validation without
-- side effects, check is_impersonating in the result and manage actor context manually.
--
-- SECURITY NOTE: Token hash comparison uses PostgreSQL's = operator, which is not
-- constant-time. Timing attacks are not practical here because:
--   1. Attacker must guess the SHA-256 hash (2^256 space), not the original token
--   2. Index lookup timing variance far exceeds string comparison variance
--   3. Network jitter (~1-10ms) drowns out comparison timing (~nanoseconds)
--   4. Even with perfect timing, reconstructing 256 bits via timing would require
--      billions of precisely-timed queries
-- Constant-time comparison would add overhead without meaningful security benefit.
--
-- TRANSACTION NOTE: The auto-set actor context uses transaction-local settings
-- (set_config with is_local=true). In autocommit mode, this context is lost when the
-- implicit transaction commits. Callers using autocommit should use the returned
-- impersonation context to set actor state at the application layer if needed for
-- subsequent operations within the same request.
--
-- @example SELECT * FROM authn.validate_session('a1b2c3...token_hash');
CREATE OR REPLACE FUNCTION authn.validate_session(
    p_token_hash text,
    p_namespace text DEFAULT 'default'
)
RETURNS TABLE(
    user_id uuid,
    email text,
    session_id uuid,
    is_impersonating boolean,
    impersonator_id uuid,
    impersonator_email text,
    impersonation_reason text
)
AS $$
DECLARE
    v_result RECORD;
BEGIN
    PERFORM authn._validate_hash(p_token_hash, 'token_hash', false);
    PERFORM authn._validate_namespace(p_namespace);

    -- Query session with LEFT JOIN to impersonation context.
    -- PERFORMANCE: The LEFT JOINs use covering partial indexes (impersonation_sessions_session_idx)
    -- that make non-impersonation lookups essentially free (index-only scan, no heap access).
    -- For the 99.99% of sessions that aren't impersonation, this adds <0.1ms.
    -- Splitting into two queries would add network round-trip latency (~1-10ms).
    SELECT
        u.id AS user_id,
        u.email,
        s.id AS session_id,
        COALESCE(imp.id IS NOT NULL AND imp.ended_at IS NULL AND imp.expires_at > now(), false) AS is_impersonating,
        imp.actor_id AS impersonator_id,
        actor.email AS impersonator_email,
        imp.reason AS impersonation_reason
    INTO v_result
    FROM authn.sessions s
    JOIN authn.users u ON u.id = s.user_id AND u.namespace = s.namespace
    LEFT JOIN authn.impersonation_sessions imp
        ON imp.impersonation_session_id = s.id
        AND imp.namespace = s.namespace
        AND imp.ended_at IS NULL
        AND imp.expires_at > now()
    LEFT JOIN authn.users actor
        ON actor.id = imp.actor_id
        AND actor.namespace = imp.namespace
    WHERE s.token_hash = p_token_hash
      AND s.namespace = p_namespace
      AND s.revoked_at IS NULL
      AND s.expires_at > now()
      AND u.disabled_at IS NULL
      AND (imp.id IS NULL OR actor.disabled_at IS NULL);

    -- If no session found, return nothing
    IF v_result.user_id IS NULL THEN
        RETURN;
    END IF;

    -- If this is an impersonation session, auto-set audit context
    IF v_result.is_impersonating THEN
        PERFORM authn.set_actor(
            p_actor_id := 'user:' || v_result.impersonator_id::text,
            p_on_behalf_of := 'user:' || v_result.user_id::text,
            p_reason := 'Impersonation: ' || v_result.impersonation_reason
        );
    END IF;

    RETURN QUERY SELECT
        v_result.user_id,
        v_result.email,
        v_result.session_id,
        v_result.is_impersonating,
        v_result.impersonator_id,
        v_result.impersonator_email,
        v_result.impersonation_reason;
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path = authn, pg_temp;

-- @function authn.extend_session
-- @brief Extend session absolute timeout (for "remember me", not idle timeout)
-- @returns New expires_at, or NULL if session invalid
-- @example SELECT authn.extend_session(token_hash, '30 days'); -- "remember me"
CREATE OR REPLACE FUNCTION authn.extend_session(
    p_token_hash text,
    p_extend_by interval DEFAULT NULL,
    p_namespace text DEFAULT 'default'
)
RETURNS timestamptz
AS $$
DECLARE
    v_new_expires_at timestamptz;
    v_session_id uuid;
    v_user_id uuid;
BEGIN
    PERFORM authn._validate_hash(p_token_hash, 'token_hash', false);
    PERFORM authn._validate_namespace(p_namespace);

    v_new_expires_at := now() + COALESCE(p_extend_by, authn._session_duration());

    UPDATE authn.sessions s
    SET expires_at = v_new_expires_at
    FROM authn.users u
    WHERE s.token_hash = p_token_hash
      AND s.namespace = p_namespace
      AND s.revoked_at IS NULL
      AND s.expires_at > now()
      AND u.id = s.user_id
      AND u.namespace = s.namespace
      AND u.disabled_at IS NULL
    RETURNING s.id, s.user_id INTO v_session_id, v_user_id;

    IF NOT FOUND THEN
        RETURN NULL;
    END IF;

    -- Audit log
    PERFORM authn._log_event(
        'session_extended', p_namespace, 'session', v_session_id::text,
        NULL, jsonb_build_object('user_id', v_user_id, 'new_expires_at', v_new_expires_at)
    );

    RETURN v_new_expires_at;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = authn, pg_temp;

-- @function authn.revoke_session
-- @brief Log out a specific session
-- @example SELECT authn.revoke_session(token_hash); -- User clicks "log out"
CREATE OR REPLACE FUNCTION authn.revoke_session(
    p_token_hash text,
    p_namespace text DEFAULT 'default'
)
RETURNS boolean
AS $$
DECLARE
    v_session_id uuid;
    v_user_id uuid;
    v_count int;
BEGIN
    PERFORM authn._validate_hash(p_token_hash, 'token_hash', false);
    PERFORM authn._validate_namespace(p_namespace);

    UPDATE authn.sessions
    SET revoked_at = now()
    WHERE token_hash = p_token_hash
      AND namespace = p_namespace
      AND revoked_at IS NULL
    RETURNING id, user_id INTO v_session_id, v_user_id;

    GET DIAGNOSTICS v_count = ROW_COUNT;

    IF v_count > 0 THEN
        -- Audit log
        PERFORM authn._log_event(
            'session_revoked', p_namespace, 'session', v_session_id::text,
            NULL, jsonb_build_object('user_id', v_user_id)
        );
    END IF;

    RETURN v_count > 0;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = authn, pg_temp;

-- @function authn.revoke_all_sessions
-- @brief Log out all sessions for a user (password change, security concern)
-- @returns Count of sessions revoked
-- @example SELECT authn.revoke_all_sessions(user_id); -- "Log out everywhere"
CREATE OR REPLACE FUNCTION authn.revoke_all_sessions(
    p_user_id uuid,
    p_namespace text DEFAULT 'default'
)
RETURNS int
AS $$
DECLARE
    v_count int;
BEGIN
    PERFORM authn._validate_namespace(p_namespace);

    UPDATE authn.sessions
    SET revoked_at = now()
    WHERE user_id = p_user_id
      AND namespace = p_namespace
      AND revoked_at IS NULL;

    GET DIAGNOSTICS v_count = ROW_COUNT;

    IF v_count > 0 THEN
        -- Audit log
        PERFORM authn._log_event(
            'sessions_revoked_all', p_namespace, 'user', p_user_id::text,
            NULL, jsonb_build_object('sessions_revoked', v_count)
        );
    END IF;

    RETURN v_count;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = authn, pg_temp;

-- @function authn.revoke_other_sessions
-- @brief Log out all sessions except the current one ("sign out other devices")
-- @param p_user_id User whose sessions to revoke
-- @param p_except_session_id Session ID to preserve (current session)
-- @returns Count of sessions revoked (excludes the preserved session)
-- @example SELECT authn.revoke_other_sessions(user_id, current_session_id);
CREATE OR REPLACE FUNCTION authn.revoke_other_sessions(
    p_user_id uuid,
    p_except_session_id uuid,
    p_namespace text DEFAULT 'default'
)
RETURNS int
AS $$
DECLARE
    v_count int;
BEGIN
    PERFORM authn._validate_namespace(p_namespace);

    UPDATE authn.sessions
    SET revoked_at = now()
    WHERE user_id = p_user_id
      AND namespace = p_namespace
      AND id != p_except_session_id
      AND revoked_at IS NULL;

    GET DIAGNOSTICS v_count = ROW_COUNT;

    IF v_count > 0 THEN
        -- Audit log
        PERFORM authn._log_event(
            'sessions_revoked_other', p_namespace, 'user', p_user_id::text,
            NULL, jsonb_build_object(
                'sessions_revoked', v_count,
                'preserved_session_id', p_except_session_id
            )
        );
    END IF;

    RETURN v_count;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = authn, pg_temp;

-- @function authn.list_sessions
-- @brief List active sessions for "manage devices" UI
-- @returns Active sessions with IP, user agent, timestamps (no token hash)
-- @example SELECT * FROM authn.list_sessions(user_id);
CREATE OR REPLACE FUNCTION authn.list_sessions(
    p_user_id uuid,
    p_namespace text DEFAULT 'default'
)
RETURNS TABLE(
    session_id uuid,
    created_at timestamptz,
    expires_at timestamptz,
    ip_address inet,
    user_agent text
)
AS $$
BEGIN
    PERFORM authn._validate_namespace(p_namespace);
    PERFORM authn._warn_namespace_mismatch(p_namespace);

    RETURN QUERY
    SELECT
        s.id AS session_id,
        s.created_at,
        s.expires_at,
        s.ip_address,
        s.user_agent
    FROM authn.sessions s
    WHERE s.user_id = p_user_id
      AND s.namespace = p_namespace
      AND s.revoked_at IS NULL
      AND s.expires_at > now()
    ORDER BY s.created_at DESC;
END;
$$ LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = authn, pg_temp;

-- @function authn.revoke_session_by_id
-- @brief Revoke a specific session by ID (for "manage devices" UI)
-- @param p_session_id Session ID to revoke
-- @param p_user_id User ID (for ownership verification)
-- @returns true if revoked, false if not found or not owned by user
-- @example SELECT authn.revoke_session_by_id(session_id, user_id);
CREATE OR REPLACE FUNCTION authn.revoke_session_by_id(
    p_session_id uuid,
    p_user_id uuid,
    p_namespace text DEFAULT 'default'
)
RETURNS boolean
AS $$
DECLARE
    v_count int;
BEGIN
    PERFORM authn._validate_namespace(p_namespace);

    UPDATE authn.sessions
    SET revoked_at = now()
    WHERE id = p_session_id
      AND user_id = p_user_id  -- Ownership check
      AND namespace = p_namespace
      AND revoked_at IS NULL;

    GET DIAGNOSTICS v_count = ROW_COUNT;

    IF v_count > 0 THEN
        -- Audit log
        PERFORM authn._log_event(
            'session_revoked', p_namespace, 'session', p_session_id::text,
            NULL, jsonb_build_object('user_id', p_user_id)
        );
    END IF;

    RETURN v_count > 0;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = authn, pg_temp;

