-- =============================================================================
-- TOKEN MANAGEMENT FOR POSTKIT/AUTHN
-- =============================================================================
-- One-time tokens for password reset, email verification, and magic links.
-- Caller generates token, hashes with SHA-256, stores hash.
-- =============================================================================


-- =============================================================================
-- CREATE TOKEN
-- =============================================================================
CREATE OR REPLACE FUNCTION authn.create_token(
    p_user_id uuid,
    p_token_hash text,
    p_token_type text,
    p_expires_in interval DEFAULT NULL,
    p_namespace text DEFAULT 'default'
)
RETURNS uuid
AS $$
DECLARE
    v_token_id uuid;
    v_expires_at timestamptz;
BEGIN
    PERFORM authn._validate_hash(p_token_hash, 'token_hash', false);
    PERFORM authn._validate_token_type(p_token_type);
    PERFORM authn._validate_namespace(p_namespace);

    -- Use default expiry for token type if not specified
    v_expires_at := now() + COALESCE(p_expires_in, authn._token_expiry(p_token_type));

    INSERT INTO authn.tokens (
        namespace, user_id, token_hash, token_type, expires_at
    ) VALUES (
        p_namespace, p_user_id, p_token_hash, p_token_type, v_expires_at
    )
    RETURNING id INTO v_token_id;

    -- Audit log (never log token_hash!)
    PERFORM authn._log_event(
        'token_created', p_namespace, 'token', v_token_id::text,
        NULL,
        jsonb_build_object('user_id', p_user_id, 'token_type', p_token_type, 'expires_at', v_expires_at)
    );

    RETURN v_token_id;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = authn, pg_temp;

COMMENT ON FUNCTION authn.create_token(uuid, text, text, interval, text) IS
'Creates a one-time token. Token hash is caller-provided SHA-256.';


-- =============================================================================
-- CONSUME TOKEN
-- =============================================================================
-- Marks token as used and returns user info.
-- Returns empty if: wrong type, expired, already used.
CREATE OR REPLACE FUNCTION authn.consume_token(
    p_token_hash text,
    p_token_type text,
    p_namespace text DEFAULT 'default'
)
RETURNS TABLE(
    user_id uuid,
    email text
)
AS $$
DECLARE
    v_token_id uuid;
    v_user_id uuid;
    v_email text;
BEGIN
    PERFORM authn._validate_hash(p_token_hash, 'token_hash', false);
    PERFORM authn._validate_token_type(p_token_type);
    PERFORM authn._validate_namespace(p_namespace);

    -- Atomically find and consume token
    UPDATE authn.tokens t
    SET used_at = now()
    FROM authn.users u
    WHERE t.token_hash = p_token_hash
      AND t.token_type = p_token_type
      AND t.namespace = p_namespace
      AND t.used_at IS NULL
      AND t.expires_at > now()
      AND u.id = t.user_id
      AND u.namespace = t.namespace
    RETURNING t.id, t.user_id, u.email
    INTO v_token_id, v_user_id, v_email;

    IF v_token_id IS NULL THEN
        RETURN;  -- Empty result
    END IF;

    -- Audit log
    PERFORM authn._log_event(
        'token_consumed', p_namespace, 'token', v_token_id::text,
        NULL,
        jsonb_build_object('user_id', v_user_id, 'token_type', p_token_type)
    );

    RETURN QUERY SELECT v_user_id, v_email;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = authn, pg_temp;

COMMENT ON FUNCTION authn.consume_token(text, text, text) IS
'Consumes a one-time token and returns user info.
Returns empty if: wrong type, expired, already used.';


-- =============================================================================
-- VERIFY EMAIL
-- =============================================================================
-- Convenience: consumes email_verify token and sets email_verified_at.
CREATE OR REPLACE FUNCTION authn.verify_email(
    p_token_hash text,
    p_namespace text DEFAULT 'default'
)
RETURNS TABLE(
    user_id uuid,
    email text
)
AS $$
DECLARE
    v_user_id uuid;
    v_email text;
BEGIN
    -- Consume the token
    SELECT ct.user_id, ct.email
    INTO v_user_id, v_email
    FROM authn.consume_token(p_token_hash, 'email_verify', p_namespace) ct;

    IF v_user_id IS NULL THEN
        RETURN;  -- Token invalid
    END IF;

    -- Set email_verified_at
    UPDATE authn.users
    SET email_verified_at = now(),
        updated_at = now()
    WHERE id = v_user_id
      AND namespace = p_namespace;

    -- Audit log for email verification
    PERFORM authn._log_event(
        'email_verified', p_namespace, 'user', v_user_id::text
    );

    RETURN QUERY SELECT v_user_id, v_email;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = authn, pg_temp;

COMMENT ON FUNCTION authn.verify_email(text, text) IS
'Consumes email_verify token and sets email_verified_at.';


-- =============================================================================
-- INVALIDATE TOKENS
-- =============================================================================
-- Marks all unused tokens of type as used.
-- Use case: invalidate old reset tokens when password changed.
CREATE OR REPLACE FUNCTION authn.invalidate_tokens(
    p_user_id uuid,
    p_token_type text,
    p_namespace text DEFAULT 'default'
)
RETURNS int
AS $$
DECLARE
    v_count int;
BEGIN
    PERFORM authn._validate_token_type(p_token_type);
    PERFORM authn._validate_namespace(p_namespace);

    UPDATE authn.tokens
    SET used_at = now()
    WHERE user_id = p_user_id
      AND token_type = p_token_type
      AND namespace = p_namespace
      AND used_at IS NULL;

    GET DIAGNOSTICS v_count = ROW_COUNT;

    RETURN v_count;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = authn, pg_temp;

COMMENT ON FUNCTION authn.invalidate_tokens(uuid, text, text) IS
'Invalidates all unused tokens of a type for a user.';
