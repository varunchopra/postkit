-- =============================================================================
-- MFA MANAGEMENT FOR POSTKIT/AUTHN
-- =============================================================================
-- Multi-factor authentication: TOTP, WebAuthn, recovery codes.
-- Secrets are stored for caller to verify. Library never validates codes.
-- =============================================================================


-- =============================================================================
-- ADD MFA
-- =============================================================================
CREATE OR REPLACE FUNCTION authn.add_mfa(
    p_user_id uuid,
    p_mfa_type text,
    p_secret text,
    p_name text DEFAULT NULL,
    p_namespace text DEFAULT 'default'
)
RETURNS uuid
AS $$
DECLARE
    v_mfa_id uuid;
BEGIN
    PERFORM authn._validate_mfa_type(p_mfa_type);
    PERFORM authn._validate_secret(p_secret);
    PERFORM authn._validate_namespace(p_namespace);

    INSERT INTO authn.mfa_secrets (
        namespace, user_id, mfa_type, secret, name
    ) VALUES (
        p_namespace, p_user_id, p_mfa_type, p_secret, p_name
    )
    RETURNING id INTO v_mfa_id;

    -- Audit log (never log secret!)
    PERFORM authn._log_event(
        'mfa_added', p_namespace, 'mfa', v_mfa_id::text,
        NULL,
        jsonb_build_object('user_id', p_user_id, 'mfa_type', p_mfa_type, 'name', p_name)
    );

    RETURN v_mfa_id;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = authn, pg_temp;

COMMENT ON FUNCTION authn.add_mfa(uuid, text, text, text, text) IS
'Adds an MFA method for a user. Secret is stored for caller to verify.';


-- =============================================================================
-- GET MFA
-- =============================================================================
-- Returns secrets for caller to verify. May return multiple (e.g., WebAuthn keys).
CREATE OR REPLACE FUNCTION authn.get_mfa(
    p_user_id uuid,
    p_mfa_type text,
    p_namespace text DEFAULT 'default'
)
RETURNS TABLE(
    id uuid,
    secret text,
    name text
)
AS $$
BEGIN
    PERFORM authn._validate_mfa_type(p_mfa_type);
    PERFORM authn._validate_namespace(p_namespace);
    PERFORM authn._warn_namespace_mismatch(p_namespace);

    RETURN QUERY
    SELECT
        m.id,
        m.secret,
        m.name
    FROM authn.mfa_secrets m
    WHERE m.user_id = p_user_id
      AND m.mfa_type = p_mfa_type
      AND m.namespace = p_namespace;
END;
$$ LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = authn, pg_temp;

COMMENT ON FUNCTION authn.get_mfa(uuid, text, text) IS
'Returns MFA secrets for verification. Caller must verify the code/response.';


-- =============================================================================
-- LIST MFA
-- =============================================================================
-- Lists MFA methods without secrets (for display).
CREATE OR REPLACE FUNCTION authn.list_mfa(
    p_user_id uuid,
    p_namespace text DEFAULT 'default'
)
RETURNS TABLE(
    id uuid,
    mfa_type text,
    name text,
    created_at timestamptz,
    last_used_at timestamptz
)
AS $$
BEGIN
    PERFORM authn._validate_namespace(p_namespace);
    PERFORM authn._warn_namespace_mismatch(p_namespace);

    RETURN QUERY
    SELECT
        m.id,
        m.mfa_type,
        m.name,
        m.created_at,
        m.last_used_at
    FROM authn.mfa_secrets m
    WHERE m.user_id = p_user_id
      AND m.namespace = p_namespace
    ORDER BY m.created_at;
END;
$$ LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = authn, pg_temp;

COMMENT ON FUNCTION authn.list_mfa(uuid, text) IS
'Lists MFA methods for a user. Does NOT return secrets.';


-- =============================================================================
-- REMOVE MFA
-- =============================================================================
CREATE OR REPLACE FUNCTION authn.remove_mfa(
    p_mfa_id uuid,
    p_namespace text DEFAULT 'default'
)
RETURNS boolean
AS $$
DECLARE
    v_user_id uuid;
    v_mfa_type text;
    v_name text;
    v_count int;
BEGIN
    PERFORM authn._validate_namespace(p_namespace);

    -- Get info for audit before deletion
    SELECT user_id, mfa_type, name
    INTO v_user_id, v_mfa_type, v_name
    FROM authn.mfa_secrets
    WHERE id = p_mfa_id AND namespace = p_namespace;

    IF v_user_id IS NULL THEN
        RETURN false;
    END IF;

    DELETE FROM authn.mfa_secrets
    WHERE id = p_mfa_id
      AND namespace = p_namespace;

    GET DIAGNOSTICS v_count = ROW_COUNT;

    IF v_count > 0 THEN
        -- Audit log
        PERFORM authn._log_event(
            'mfa_removed', p_namespace, 'mfa', p_mfa_id::text,
            jsonb_build_object('user_id', v_user_id, 'mfa_type', v_mfa_type, 'name', v_name)
        );
    END IF;

    RETURN v_count > 0;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = authn, pg_temp;

COMMENT ON FUNCTION authn.remove_mfa(uuid, text) IS
'Removes an MFA method.';


-- =============================================================================
-- RECORD MFA USE
-- =============================================================================
CREATE OR REPLACE FUNCTION authn.record_mfa_use(
    p_mfa_id uuid,
    p_namespace text DEFAULT 'default'
)
RETURNS boolean
AS $$
DECLARE
    v_count int;
BEGIN
    PERFORM authn._validate_namespace(p_namespace);

    UPDATE authn.mfa_secrets
    SET last_used_at = now()
    WHERE id = p_mfa_id
      AND namespace = p_namespace;

    GET DIAGNOSTICS v_count = ROW_COUNT;

    IF v_count > 0 THEN
        -- Audit log
        PERFORM authn._log_event(
            'mfa_used', p_namespace, 'mfa', p_mfa_id::text
        );
    END IF;

    RETURN v_count > 0;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = authn, pg_temp;

COMMENT ON FUNCTION authn.record_mfa_use(uuid, text) IS
'Records that an MFA method was used successfully.';


-- =============================================================================
-- HAS MFA
-- =============================================================================
CREATE OR REPLACE FUNCTION authn.has_mfa(
    p_user_id uuid,
    p_namespace text DEFAULT 'default'
)
RETURNS boolean
AS $$
BEGIN
    PERFORM authn._validate_namespace(p_namespace);

    RETURN EXISTS (
        SELECT 1
        FROM authn.mfa_secrets
        WHERE user_id = p_user_id
          AND namespace = p_namespace
    );
END;
$$ LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = authn, pg_temp;

COMMENT ON FUNCTION authn.has_mfa(uuid, text) IS
'Returns true if user has any MFA method configured.';
