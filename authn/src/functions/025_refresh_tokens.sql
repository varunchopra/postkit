-- @group Refresh Tokens

-- @function authn._refresh_token_duration
-- @brief Returns default refresh token duration
-- @returns Interval (default: 30 days)
-- Override with SET authn.refresh_token_duration.
CREATE OR REPLACE FUNCTION authn._refresh_token_duration()
RETURNS interval
AS $$
BEGIN
    RETURN COALESCE(
        current_setting('authn.refresh_token_duration', true)::interval,
        '30 days'::interval
    );
END;
$$ LANGUAGE plpgsql STABLE PARALLEL SAFE SET search_path = authn, pg_temp;


-- @function authn.create_refresh_token
-- @brief Create a refresh token for a session (call after create_session)
-- @param p_session_id Session to associate with
-- @param p_token_hash SHA-256 hash of the refresh token
-- @param p_expires_in Token lifetime (default 30 days)
-- @returns Table with refresh_token_id, family_id, expires_at
-- @example SELECT * FROM authn.create_refresh_token(session_id, 'a1b2c3...token_hash');
CREATE OR REPLACE FUNCTION authn.create_refresh_token(
    p_session_id uuid,
    p_token_hash text,
    p_expires_in interval DEFAULT NULL,
    p_namespace text DEFAULT 'default'
)
RETURNS TABLE(
    refresh_token_id uuid,
    family_id uuid,
    expires_at timestamptz
)
AS $$
DECLARE
    v_refresh_token_id uuid;
    v_family_id uuid;
    v_expires_at timestamptz;
    v_user_id uuid;
BEGIN
    PERFORM authn._validate_hash(p_token_hash, 'token_hash', false);
    PERFORM authn._validate_namespace(p_namespace);

    -- Verify session exists, is valid, and user is not disabled
    SELECT s.user_id INTO v_user_id
    FROM authn.sessions s
    JOIN authn.users u ON u.id = s.user_id AND u.namespace = s.namespace
    WHERE s.id = p_session_id
      AND s.namespace = p_namespace
      AND s.revoked_at IS NULL
      AND s.expires_at > now()
      AND u.disabled_at IS NULL;

    IF v_user_id IS NULL THEN
        RAISE EXCEPTION 'Session not found, invalid, or user disabled'
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:authn:SESSION_INVALID';
    END IF;

    -- Generate new family ID for this token chain
    v_family_id := gen_random_uuid();
    v_expires_at := now() + COALESCE(p_expires_in, authn._refresh_token_duration());

    INSERT INTO authn.refresh_tokens (
        namespace, user_id, session_id, token_hash, family_id, generation, expires_at
    ) VALUES (
        p_namespace, v_user_id, p_session_id, p_token_hash, v_family_id, 1, v_expires_at
    )
    RETURNING id INTO v_refresh_token_id;

    -- Audit log (never log token_hash!)
    PERFORM authn._log_event(
        'refresh_token_created', p_namespace, 'refresh_token', v_refresh_token_id::text,
        NULL,
        jsonb_build_object(
            'user_id', v_user_id,
            'session_id', p_session_id,
            'family_id', v_family_id,
            'expires_at', v_expires_at
        )
    );

    RETURN QUERY SELECT v_refresh_token_id, v_family_id, v_expires_at;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = authn, pg_temp;


-- @function authn.rotate_refresh_token
-- @brief Rotate a refresh token: invalidate old, create new (secure by default)
-- @param p_old_token_hash Hash of the token being rotated
-- @param p_new_token_hash Hash of the new token to issue
-- @param p_expires_in New token lifetime (default 30 days)
-- @returns user_id, session_id, new_refresh_token_id, family_id, generation, expires_at
--   Returns empty if token invalid, expired, or already used (reuse triggers family revocation)
-- @example SELECT * FROM authn.rotate_refresh_token('old_token_hash', 'new_token_hash');
CREATE OR REPLACE FUNCTION authn.rotate_refresh_token(
    p_old_token_hash text,
    p_new_token_hash text,
    p_expires_in interval DEFAULT NULL,
    p_namespace text DEFAULT 'default'
)
RETURNS TABLE(
    user_id uuid,
    session_id uuid,
    new_refresh_token_id uuid,
    family_id uuid,
    generation int,
    expires_at timestamptz
)
AS $$
DECLARE
    v_old_token authn.refresh_tokens%ROWTYPE;
    v_new_token_id uuid;
    v_new_generation int;
    v_new_expires_at timestamptz;
    v_revoked_count int;
BEGIN
    PERFORM authn._validate_hash(p_old_token_hash, 'old_token_hash', false);
    PERFORM authn._validate_hash(p_new_token_hash, 'new_token_hash', false);
    PERFORM authn._validate_namespace(p_namespace);

    -- Find and lock the old token to prevent concurrent rotation.
    --
    -- FOR UPDATE SKIP LOCKED: if another concurrent request is rotating this same
    -- token, we return empty rather than blocking. This is intentional:
    --   1. Prevents cascading delays under high concurrency
    --   2. The concurrent request will complete and issue a new token
    --   3. Caller receiving empty result should retry their auth flow
    --
    -- This race is rare in practice (requires two requests with same refresh token
    -- arriving within milliseconds). When it happens, one succeeds and the other
    -- gets an empty result - which the client treats like an expired token and
    -- re-authenticates or retries with their session.
    SELECT * INTO v_old_token
    FROM authn.refresh_tokens rt
    WHERE rt.token_hash = p_old_token_hash
      AND rt.namespace = p_namespace
    FOR UPDATE SKIP LOCKED;

    -- Token not found (or locked by concurrent rotation)
    IF v_old_token.id IS NULL THEN
        RETURN;
    END IF;

    -- Check for reuse attack: token already replaced
    IF v_old_token.replaced_by IS NOT NULL THEN
        -- SECURITY BREACH: Token reuse detected!
        -- Revoke entire family
        UPDATE authn.refresh_tokens
        SET revoked_at = now()
        WHERE refresh_tokens.family_id = v_old_token.family_id
          AND refresh_tokens.namespace = p_namespace
          AND revoked_at IS NULL;

        GET DIAGNOSTICS v_revoked_count = ROW_COUNT;

        -- Audit the breach
        PERFORM authn._log_event(
            'refresh_token_reuse_detected', p_namespace, 'refresh_token', v_old_token.id::text,
            NULL,
            jsonb_build_object(
                'user_id', v_old_token.user_id,
                'family_id', v_old_token.family_id,
                'generation', v_old_token.generation,
                'tokens_revoked', v_revoked_count
            )
        );

        RETURN;  -- Empty result, caller must re-authenticate
    END IF;

    -- Token already revoked
    IF v_old_token.revoked_at IS NOT NULL THEN
        RETURN;
    END IF;

    -- Token expired
    IF v_old_token.expires_at <= now() THEN
        RETURN;
    END IF;

    -- Verify associated session is still valid
    IF NOT EXISTS (
        SELECT 1 FROM authn.sessions s
        WHERE s.id = v_old_token.session_id
          AND s.revoked_at IS NULL
          AND s.expires_at > now()
    ) THEN
        RETURN;
    END IF;

    -- Verify user is not disabled
    IF EXISTS (
        SELECT 1 FROM authn.users u
        WHERE u.id = v_old_token.user_id
          AND u.disabled_at IS NOT NULL
    ) THEN
        RETURN;
    END IF;

    -- Create new token
    v_new_generation := v_old_token.generation + 1;
    v_new_expires_at := now() + COALESCE(p_expires_in, authn._refresh_token_duration());

    INSERT INTO authn.refresh_tokens (
        namespace, user_id, session_id, token_hash, family_id, generation, expires_at
    ) VALUES (
        p_namespace,
        v_old_token.user_id,
        v_old_token.session_id,
        p_new_token_hash,
        v_old_token.family_id,  -- Same family
        v_new_generation,
        v_new_expires_at
    )
    RETURNING id INTO v_new_token_id;

    -- Mark old token as replaced
    UPDATE authn.refresh_tokens
    SET replaced_by = v_new_token_id
    WHERE id = v_old_token.id;

    -- Audit log
    PERFORM authn._log_event(
        'refresh_token_rotated', p_namespace, 'refresh_token', v_new_token_id::text,
        jsonb_build_object(
            'old_token_id', v_old_token.id,
            'old_generation', v_old_token.generation
        ),
        jsonb_build_object(
            'user_id', v_old_token.user_id,
            'session_id', v_old_token.session_id,
            'family_id', v_old_token.family_id,
            'generation', v_new_generation,
            'expires_at', v_new_expires_at
        )
    );

    RETURN QUERY SELECT
        v_old_token.user_id,
        v_old_token.session_id,
        v_new_token_id,
        v_old_token.family_id,
        v_new_generation,
        v_new_expires_at;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = authn, pg_temp;


-- @function authn.validate_refresh_token
-- @brief Check if a refresh token is valid WITHOUT rotating (for inspection only)
-- @returns user_id, session_id, family_id, generation, expires_at, is_current if valid
-- @example SELECT * FROM authn.validate_refresh_token('a1b2c3...token_hash');
CREATE OR REPLACE FUNCTION authn.validate_refresh_token(
    p_token_hash text,
    p_namespace text DEFAULT 'default'
)
RETURNS TABLE(
    user_id uuid,
    session_id uuid,
    family_id uuid,
    generation int,
    expires_at timestamptz,
    is_current boolean
)
AS $$
BEGIN
    PERFORM authn._validate_hash(p_token_hash, 'token_hash', false);
    PERFORM authn._validate_namespace(p_namespace);

    RETURN QUERY
    SELECT
        rt.user_id,
        rt.session_id,
        rt.family_id,
        rt.generation,
        rt.expires_at,
        (rt.replaced_by IS NULL AND rt.revoked_at IS NULL) AS is_current
    FROM authn.refresh_tokens rt
    JOIN authn.sessions s ON s.id = rt.session_id
    JOIN authn.users u ON u.id = rt.user_id
    WHERE rt.token_hash = p_token_hash
      AND rt.namespace = p_namespace
      AND rt.revoked_at IS NULL
      AND rt.replaced_by IS NULL
      AND rt.expires_at > now()
      AND s.revoked_at IS NULL
      AND s.expires_at > now()
      AND u.disabled_at IS NULL;
END;
$$ LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = authn, pg_temp;


-- @function authn.revoke_refresh_token_family
-- @brief Revoke all tokens in a family (for security response)
-- @param p_family_id The family to revoke
-- @returns Count of tokens revoked
-- @example SELECT authn.revoke_refresh_token_family(family_id);
CREATE OR REPLACE FUNCTION authn.revoke_refresh_token_family(
    p_family_id uuid,
    p_namespace text DEFAULT 'default'
)
RETURNS int
AS $$
DECLARE
    v_count int;
    v_user_id uuid;
BEGIN
    PERFORM authn._validate_namespace(p_namespace);

    -- Get user_id for audit
    SELECT DISTINCT rt.user_id INTO v_user_id
    FROM authn.refresh_tokens rt
    WHERE rt.family_id = p_family_id
      AND rt.namespace = p_namespace
    LIMIT 1;

    UPDATE authn.refresh_tokens
    SET revoked_at = now()
    WHERE refresh_tokens.family_id = p_family_id
      AND namespace = p_namespace
      AND revoked_at IS NULL;

    GET DIAGNOSTICS v_count = ROW_COUNT;

    IF v_count > 0 THEN
        PERFORM authn._log_event(
            'refresh_token_family_revoked', p_namespace, 'refresh_token_family', p_family_id::text,
            NULL,
            jsonb_build_object('user_id', v_user_id, 'tokens_revoked', v_count)
        );
    END IF;

    RETURN v_count;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = authn, pg_temp;


-- @function authn.revoke_all_refresh_tokens
-- @brief Revoke all refresh tokens for a user (password change, security concern)
-- @returns Count of tokens revoked
-- @example SELECT authn.revoke_all_refresh_tokens(user_id);
CREATE OR REPLACE FUNCTION authn.revoke_all_refresh_tokens(
    p_user_id uuid,
    p_namespace text DEFAULT 'default'
)
RETURNS int
AS $$
DECLARE
    v_count int;
BEGIN
    PERFORM authn._validate_namespace(p_namespace);

    UPDATE authn.refresh_tokens
    SET revoked_at = now()
    WHERE user_id = p_user_id
      AND namespace = p_namespace
      AND revoked_at IS NULL;

    GET DIAGNOSTICS v_count = ROW_COUNT;

    IF v_count > 0 THEN
        PERFORM authn._log_event(
            'refresh_tokens_revoked_all', p_namespace, 'user', p_user_id::text,
            NULL,
            jsonb_build_object('tokens_revoked', v_count)
        );
    END IF;

    RETURN v_count;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = authn, pg_temp;


-- @function authn.list_refresh_tokens
-- @brief List active refresh tokens for a user (for "manage devices" UI)
-- @returns Active tokens with family, generation, timestamps (no token hash)
-- @example SELECT * FROM authn.list_refresh_tokens(user_id);
CREATE OR REPLACE FUNCTION authn.list_refresh_tokens(
    p_user_id uuid,
    p_namespace text DEFAULT 'default'
)
RETURNS TABLE(
    refresh_token_id uuid,
    session_id uuid,
    family_id uuid,
    generation int,
    created_at timestamptz,
    expires_at timestamptz
)
AS $$
BEGIN
    PERFORM authn._validate_namespace(p_namespace);
    PERFORM authn._warn_namespace_mismatch(p_namespace);

    RETURN QUERY
    SELECT
        rt.id AS refresh_token_id,
        rt.session_id,
        rt.family_id,
        rt.generation,
        rt.created_at,
        rt.expires_at
    FROM authn.refresh_tokens rt
    WHERE rt.user_id = p_user_id
      AND rt.namespace = p_namespace
      AND rt.revoked_at IS NULL
      AND rt.replaced_by IS NULL
      AND rt.expires_at > now()
    ORDER BY rt.created_at DESC;
END;
$$ LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = authn, pg_temp;
