-- @group Impersonation

-- =============================================================================
-- IMPERSONATION FUNCTIONS
-- =============================================================================
-- Admin impersonation with full audit trail.
-- Creates real sessions as target user while preserving actor context.
-- All actions during impersonation are automatically tagged in audit.

-- @function authn.start_impersonation
-- @brief Start impersonating a user (creates a session acting as target user)
-- @param p_actor_session_id Session ID of the admin starting impersonation (cannot be an impersonation session)
-- @param p_target_user_id User ID to impersonate
-- @param p_token_hash SHA-256 hash of the impersonation session token (caller generates and hashes)
-- @param p_reason Required justification for impersonation (e.g., "Support ticket #123")
-- @param p_duration How long the impersonation lasts (default 1 hour, max 8 hours)
-- @returns impersonation_id, impersonation_session_id, expires_at
-- @note Impersonation chaining is prevented - you cannot start an impersonation from an impersonation session
-- @example SELECT * FROM authn.start_impersonation(admin_session, target_user, 'a1b2c3...token_hash', 'Support ticket #123');
CREATE OR REPLACE FUNCTION authn.start_impersonation(
    p_actor_session_id uuid,
    p_target_user_id uuid,
    p_token_hash text,
    p_reason text,
    p_duration interval DEFAULT NULL,
    p_namespace text DEFAULT 'default'
)
RETURNS TABLE(
    impersonation_id uuid,
    impersonation_session_id uuid,
    expires_at timestamptz
)
AS $$
DECLARE
    v_actor_id uuid;
    v_actor_email text;
    v_target_email text;
    v_impersonation_id uuid;
    v_session_id uuid;
    v_expires_at timestamptz;
    v_duration interval;
    v_max_duration interval;
BEGIN
    PERFORM authn._validate_hash(p_token_hash, 'token_hash', false);
    PERFORM authn._validate_namespace(p_namespace);

    -- Validate reason is not empty
    IF p_reason IS NULL OR trim(p_reason) = '' THEN
        RAISE EXCEPTION 'Reason cannot be null or empty'
            USING ERRCODE = 'null_value_not_allowed',
                  HINT = 'postkit:authn:VAL_REASON_REQUIRED';
    END IF;

    -- Validate actor session exists and is valid
    SELECT u.id, u.email INTO v_actor_id, v_actor_email
    FROM authn.sessions s
    JOIN authn.users u ON u.id = s.user_id AND u.namespace = s.namespace
    WHERE s.id = p_actor_session_id
      AND s.namespace = p_namespace
      AND s.revoked_at IS NULL
      AND s.expires_at > now()
      AND u.disabled_at IS NULL;

    IF v_actor_id IS NULL THEN
        RAISE EXCEPTION 'Actor session not found or invalid'
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:authn:SESSION_ACTOR_INVALID';
    END IF;

    -- Validate target user exists and is not disabled
    SELECT u.email INTO v_target_email
    FROM authn.users u
    WHERE u.id = p_target_user_id
      AND u.namespace = p_namespace
      AND u.disabled_at IS NULL;

    IF v_target_email IS NULL THEN
        RAISE EXCEPTION 'Target user not found or disabled'
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:authn:SESSION_TARGET_INVALID';
    END IF;

    -- Prevent self-impersonation
    IF v_actor_id = p_target_user_id THEN
        RAISE EXCEPTION 'Cannot impersonate yourself'
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:authn:BIZ_IMPERSONATE_SELF';
    END IF;

    -- Prevent impersonation chaining (cannot start impersonation from any impersonation session)
    -- Check both regular impersonation sessions and operator impersonation sessions
    IF EXISTS (
        SELECT 1 FROM authn.impersonation_sessions imp
        WHERE imp.impersonation_session_id = p_actor_session_id
          AND imp.namespace = p_namespace
          AND imp.ended_at IS NULL
    ) OR EXISTS (
        SELECT 1 FROM authn.operator_impersonation_sessions ois
        WHERE ois.impersonation_session_id = p_actor_session_id
          AND ois.ended_at IS NULL
    ) THEN
        RAISE EXCEPTION 'Cannot start impersonation from an impersonation session'
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:authn:BIZ_IMPERSONATE_CHAIN';
    END IF;

    -- Calculate duration (enforce max)
    v_max_duration := authn._impersonation_max_duration();
    v_duration := COALESCE(p_duration, authn._impersonation_default_duration());

    IF v_duration > v_max_duration THEN
        RAISE EXCEPTION 'Impersonation duration % exceeds maximum allowed %', v_duration, v_max_duration
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:authn:LIMIT_DURATION_EXCEEDED';
    END IF;

    IF v_duration <= interval '0 seconds' THEN
        RAISE EXCEPTION 'Impersonation duration must be positive'
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:authn:VAL_DURATION_POSITIVE';
    END IF;

    v_expires_at := now() + v_duration;

    -- Create an impersonation session (a real session as the target user)
    INSERT INTO authn.sessions (
        namespace, user_id, token_hash, expires_at, ip_address, user_agent
    ) VALUES (
        p_namespace, p_target_user_id, p_token_hash, v_expires_at, NULL, 'impersonation'
    )
    RETURNING id INTO v_session_id;

    -- Create the impersonation record
    INSERT INTO authn.impersonation_sessions (
        namespace, actor_id, target_user_id, original_session_id,
        impersonation_session_id, reason, expires_at
    ) VALUES (
        p_namespace, v_actor_id, p_target_user_id, p_actor_session_id,
        v_session_id, trim(p_reason), v_expires_at
    )
    RETURNING id INTO v_impersonation_id;

    -- Audit log with full context
    PERFORM authn._log_event(
        'impersonation_started', p_namespace, 'impersonation', v_impersonation_id::text,
        NULL,
        jsonb_build_object(
            'actor_id', v_actor_id,
            'actor_email', v_actor_email,
            'target_user_id', p_target_user_id,
            'target_email', v_target_email,
            'impersonation_session_id', v_session_id,
            'reason', trim(p_reason),
            'expires_at', v_expires_at,
            'duration', v_duration::text
        )
    );

    RETURN QUERY SELECT v_impersonation_id, v_session_id, v_expires_at;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = authn, pg_temp;


-- @function authn.end_impersonation
-- @brief End an impersonation session early (revokes the impersonation session)
-- @param p_impersonation_id The impersonation to end
-- @returns true if ended, false if not found or already ended
-- @example SELECT authn.end_impersonation(impersonation_id);
CREATE OR REPLACE FUNCTION authn.end_impersonation(
    p_impersonation_id uuid,
    p_namespace text DEFAULT 'default'
)
RETURNS boolean
AS $$
DECLARE
    v_impersonation authn.impersonation_sessions%ROWTYPE;
    v_actor_email text;
    v_target_email text;
BEGIN
    PERFORM authn._validate_namespace(p_namespace);

    -- Find and lock the impersonation record
    SELECT * INTO v_impersonation
    FROM authn.impersonation_sessions imp
    WHERE imp.id = p_impersonation_id
      AND imp.namespace = p_namespace
      AND imp.ended_at IS NULL
    FOR UPDATE;

    IF v_impersonation.id IS NULL THEN
        RETURN false;
    END IF;

    -- Get emails for audit
    SELECT email INTO v_actor_email FROM authn.users WHERE id = v_impersonation.actor_id AND namespace = p_namespace;
    SELECT email INTO v_target_email FROM authn.users WHERE id = v_impersonation.target_user_id AND namespace = p_namespace;

    -- End the impersonation
    UPDATE authn.impersonation_sessions
    SET ended_at = now()
    WHERE id = p_impersonation_id;

    -- Revoke the impersonation session
    IF v_impersonation.impersonation_session_id IS NOT NULL THEN
        UPDATE authn.sessions
        SET revoked_at = now()
        WHERE id = v_impersonation.impersonation_session_id
          AND revoked_at IS NULL;
    END IF;

    -- Audit log
    PERFORM authn._log_event(
        'impersonation_ended', p_namespace, 'impersonation', p_impersonation_id::text,
        jsonb_build_object(
            'started_at', v_impersonation.started_at,
            'was_expired', v_impersonation.expires_at <= now()
        ),
        jsonb_build_object(
            'actor_id', v_impersonation.actor_id,
            'actor_email', v_actor_email,
            'target_user_id', v_impersonation.target_user_id,
            'target_email', v_target_email,
            'reason', v_impersonation.reason,
            'duration', (now() - v_impersonation.started_at)::text
        )
    );

    RETURN true;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = authn, pg_temp;


-- @function authn.get_impersonation_context
-- @brief Get impersonation context for a session (is this an impersonated session?)
-- @param p_session_id The session to check
-- @returns is_impersonating, actor_id, actor_email, target_user_id, reason
--   Returns is_impersonating=false with NULLs if not an impersonation session
-- @example SELECT * FROM authn.get_impersonation_context(session_id);
CREATE OR REPLACE FUNCTION authn.get_impersonation_context(
    p_session_id uuid,
    p_namespace text DEFAULT 'default'
)
RETURNS TABLE(
    is_impersonating boolean,
    impersonation_id uuid,
    actor_id uuid,
    actor_email text,
    target_user_id uuid,
    reason text,
    started_at timestamptz,
    expires_at timestamptz
)
AS $$
BEGIN
    PERFORM authn._validate_namespace(p_namespace);

    RETURN QUERY
    SELECT
        true AS is_impersonating,
        imp.id AS impersonation_id,
        imp.actor_id,
        u.email AS actor_email,
        imp.target_user_id,
        imp.reason,
        imp.started_at,
        imp.expires_at
    FROM authn.impersonation_sessions imp
    JOIN authn.users u ON u.id = imp.actor_id AND u.namespace = imp.namespace
    JOIN authn.users target ON target.id = imp.target_user_id AND target.namespace = imp.namespace
    JOIN authn.sessions s ON s.id = imp.impersonation_session_id
    WHERE imp.impersonation_session_id = p_session_id
      AND imp.namespace = p_namespace
      AND imp.ended_at IS NULL
      AND imp.expires_at > now()
      AND u.disabled_at IS NULL
      AND target.disabled_at IS NULL
      AND s.revoked_at IS NULL;

    -- If no rows returned, return a single row with is_impersonating=false
    IF NOT FOUND THEN
        RETURN QUERY SELECT
            false::boolean AS is_impersonating,
            NULL::uuid AS impersonation_id,
            NULL::uuid AS actor_id,
            NULL::text AS actor_email,
            NULL::uuid AS target_user_id,
            NULL::text AS reason,
            NULL::timestamptz AS started_at,
            NULL::timestamptz AS expires_at;
    END IF;
END;
$$ LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = authn, pg_temp;


-- @function authn.list_active_impersonations
-- @brief List all active impersonations in a namespace (admin dashboard)
-- @param p_namespace Namespace to query
-- @returns Active impersonations with actor/target info
-- @example SELECT * FROM authn.list_active_impersonations('production');
CREATE OR REPLACE FUNCTION authn.list_active_impersonations(
    p_namespace text DEFAULT 'default'
)
RETURNS TABLE(
    impersonation_id uuid,
    actor_id uuid,
    actor_email text,
    target_user_id uuid,
    target_email text,
    reason text,
    started_at timestamptz,
    expires_at timestamptz,
    impersonation_session_id uuid
)
AS $$
BEGIN
    PERFORM authn._validate_namespace(p_namespace);
    PERFORM authn._warn_namespace_mismatch(p_namespace);

    RETURN QUERY
    SELECT
        imp.id AS impersonation_id,
        imp.actor_id,
        actor.email AS actor_email,
        imp.target_user_id,
        target.email AS target_email,
        imp.reason,
        imp.started_at,
        imp.expires_at,
        imp.impersonation_session_id
    FROM authn.impersonation_sessions imp
    JOIN authn.users actor ON actor.id = imp.actor_id AND actor.namespace = imp.namespace
    JOIN authn.users target ON target.id = imp.target_user_id AND target.namespace = imp.namespace
    JOIN authn.sessions s ON s.id = imp.impersonation_session_id
    WHERE imp.namespace = p_namespace
      AND imp.ended_at IS NULL
      AND imp.expires_at > now()
      AND actor.disabled_at IS NULL
      AND target.disabled_at IS NULL
      AND s.revoked_at IS NULL
    ORDER BY imp.started_at DESC;
END;
$$ LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = authn, pg_temp;


-- @function authn.list_impersonation_history
-- @brief List impersonation history for audit (includes ended impersonations)
-- @param p_namespace Namespace to query
-- @param p_limit Maximum records to return
-- @param p_actor_id Optional filter by actor
-- @param p_target_user_id Optional filter by target user
-- @returns Impersonation history
-- @example SELECT * FROM authn.list_impersonation_history('production', 100);
CREATE OR REPLACE FUNCTION authn.list_impersonation_history(
    p_namespace text DEFAULT 'default',
    p_limit int DEFAULT 100,
    p_actor_id uuid DEFAULT NULL,
    p_target_user_id uuid DEFAULT NULL
)
RETURNS TABLE(
    impersonation_id uuid,
    actor_id uuid,
    actor_email text,
    target_user_id uuid,
    target_email text,
    reason text,
    started_at timestamptz,
    expires_at timestamptz,
    ended_at timestamptz,
    is_active boolean
)
AS $$
BEGIN
    PERFORM authn._validate_namespace(p_namespace);
    PERFORM authn._warn_namespace_mismatch(p_namespace);

    RETURN QUERY
    SELECT
        imp.id AS impersonation_id,
        imp.actor_id,
        actor.email AS actor_email,
        imp.target_user_id,
        target.email AS target_email,
        imp.reason,
        imp.started_at,
        imp.expires_at,
        imp.ended_at,
        (imp.ended_at IS NULL AND imp.expires_at > now() AND actor.disabled_at IS NULL AND target.disabled_at IS NULL AND s.id IS NOT NULL AND s.revoked_at IS NULL) AS is_active
    FROM authn.impersonation_sessions imp
    JOIN authn.users actor ON actor.id = imp.actor_id AND actor.namespace = imp.namespace
    JOIN authn.users target ON target.id = imp.target_user_id AND target.namespace = imp.namespace
    LEFT JOIN authn.sessions s ON s.id = imp.impersonation_session_id
    WHERE imp.namespace = p_namespace
      AND (p_actor_id IS NULL OR imp.actor_id = p_actor_id)
      AND (p_target_user_id IS NULL OR imp.target_user_id = p_target_user_id)
    ORDER BY imp.started_at DESC
    LIMIT p_limit;
END;
$$ LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = authn, pg_temp;


-- @function authn._end_impersonations_for_user
-- @brief End all impersonation sessions where user is actor or target
-- @param p_user_id The user being disabled
-- @param p_namespace The namespace
-- @returns Count of impersonations ended
CREATE OR REPLACE FUNCTION authn._end_impersonations_for_user(
    p_user_id uuid,
    p_namespace text
)
RETURNS int AS $$
DECLARE
    v_count int;
BEGIN
    -- End impersonations and revoke their sessions in one operation
    WITH ended AS (
        UPDATE authn.impersonation_sessions
        SET ended_at = now()
        WHERE namespace = p_namespace
          AND (actor_id = p_user_id OR target_user_id = p_user_id)
          AND ended_at IS NULL
        RETURNING impersonation_session_id
    )
    UPDATE authn.sessions
    SET revoked_at = now()
    WHERE id IN (SELECT impersonation_session_id FROM ended WHERE impersonation_session_id IS NOT NULL)
      AND revoked_at IS NULL;

    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = authn, pg_temp;
