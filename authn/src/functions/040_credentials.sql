-- @group Credentials

-- @function authn.add_credential
-- @brief Add a credential (TOTP, WebAuthn, or recovery code)
-- @param p_user_id User to add credential for
-- @param p_type One of: 'totp', 'recovery_code', 'webauthn'
-- @param p_lookup_key Lookup key (WebAuthn credential_id, recovery code hash)
-- @param p_secret_data Secret data (TOTP seed, WebAuthn public key)
-- @param p_name User-friendly name like "Work Yubikey"
-- @param p_metadata Optional JSON metadata
-- @param p_created_by UUID of user who added this credential (for audit)
-- @returns Credential ID
-- @example SELECT authn.add_credential(user_id, 'totp', NULL, 'JBSWY3DPEHPK3PXP', 'Authenticator');
CREATE OR REPLACE FUNCTION authn.add_credential(
    p_user_id uuid,
    p_type text,
    p_lookup_key text DEFAULT NULL,
    p_secret_data text DEFAULT NULL,
    p_name text DEFAULT NULL,
    p_metadata jsonb DEFAULT NULL,
    p_created_by uuid DEFAULT NULL,
    p_namespace text DEFAULT 'default'
)
RETURNS uuid
AS $$
DECLARE
    v_credential_id uuid;
BEGIN
    PERFORM authn._validate_credential_type(p_type);
    PERFORM authn._validate_namespace(p_namespace);

    -- Validate that at least one of lookup_key or secret_data is provided
    IF p_lookup_key IS NULL AND p_secret_data IS NULL THEN
        RAISE EXCEPTION 'Either lookup_key or secret_data must be provided'
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:authn:CRED_NO_MATERIAL';
    END IF;

    -- Validate secret_data if provided
    IF p_secret_data IS NOT NULL THEN
        PERFORM authn._validate_secret(p_secret_data);
    END IF;

    -- Verify user exists and is not disabled
    IF NOT EXISTS (
        SELECT 1 FROM authn.users u
        WHERE u.id = p_user_id
          AND u.namespace = p_namespace
          AND u.disabled_at IS NULL
    ) THEN
        RAISE EXCEPTION 'User not found or disabled'
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:authn:USER_DISABLED';
    END IF;

    INSERT INTO authn.credentials (
        namespace, user_id, credential_type, lookup_key, secret_data,
        name, metadata, created_by
    ) VALUES (
        p_namespace, p_user_id, p_type, p_lookup_key, p_secret_data,
        p_name, p_metadata, p_created_by
    )
    RETURNING id INTO v_credential_id;

    -- Audit log (never log secrets!)
    PERFORM authn._log_event(
        'credential_added', p_namespace, 'credential', v_credential_id::text,
        NULL,
        jsonb_build_object(
            'user_id', p_user_id,
            'credential_type', p_type,
            'name', p_name,
            'created_by', p_created_by
        )
    );

    RETURN v_credential_id;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = authn, pg_temp;


-- @function authn.get_credentials
-- @brief Get active credentials for verification (returns secrets)
-- @param p_user_id User to get credentials for
-- @param p_type Credential type to filter by
-- @returns Table of credentials with secrets for verification
-- @note Only returns active credentials (not disabled, not consumed)
-- @example SELECT * FROM authn.get_credentials(user_id, 'totp');
CREATE OR REPLACE FUNCTION authn.get_credentials(
    p_user_id uuid,
    p_type text,
    p_namespace text DEFAULT 'default'
)
RETURNS TABLE(
    id uuid,
    lookup_key text,
    secret_data text,
    sign_count int
)
AS $$
BEGIN
    PERFORM authn._validate_credential_type(p_type);
    PERFORM authn._validate_namespace(p_namespace);
    PERFORM authn._warn_namespace_mismatch(p_namespace);

    RETURN QUERY
    SELECT
        c.id,
        c.lookup_key,
        c.secret_data,
        c.sign_count
    FROM authn.credentials c
    WHERE c.user_id = p_user_id
      AND c.credential_type = p_type
      AND c.namespace = p_namespace
      AND c.disabled_at IS NULL
      AND c.consumed_at IS NULL;
END;
$$ LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = authn, pg_temp;


-- @function authn.get_credential_by_lookup
-- @brief Lookup a credential by its lookup_key (requires user context for security)
-- @param p_user_id User to search within (prevents enumeration)
-- @param p_lookup_key The lookup key to search for
-- @param p_type Credential type to filter by
-- @returns Single credential or empty if not found
-- @note Returns consumed_at so caller knows if already used
-- @example SELECT * FROM authn.get_credential_by_lookup(user_id, hash, 'recovery_code');
CREATE OR REPLACE FUNCTION authn.get_credential_by_lookup(
    p_user_id uuid,
    p_lookup_key text,
    p_type text,
    p_namespace text DEFAULT 'default'
)
RETURNS TABLE(
    id uuid,
    secret_data text,
    sign_count int,
    consumed_at timestamptz
)
AS $$
BEGIN
    PERFORM authn._validate_credential_type(p_type);
    PERFORM authn._validate_namespace(p_namespace);
    PERFORM authn._warn_namespace_mismatch(p_namespace);

    RETURN QUERY
    SELECT
        c.id,
        c.secret_data,
        c.sign_count,
        c.consumed_at
    FROM authn.credentials c
    WHERE c.user_id = p_user_id
      AND c.lookup_key = p_lookup_key
      AND c.credential_type = p_type
      AND c.namespace = p_namespace
      AND c.disabled_at IS NULL;
END;
$$ LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = authn, pg_temp;


-- @function authn.record_credential_use
-- @brief Record credential usage (updates last_used_at)
-- @param p_credential_id Credential that was used
-- @note Lazy update: only updates if >1 hour since last use to reduce writes
-- @example SELECT authn.record_credential_use(credential_id);
CREATE OR REPLACE FUNCTION authn.record_credential_use(
    p_credential_id uuid,
    p_namespace text DEFAULT 'default'
)
RETURNS void
AS $$
BEGIN
    PERFORM authn._validate_namespace(p_namespace);

    -- Lazy update: only update if >1 hour since last use
    UPDATE authn.credentials
    SET last_used_at = now()
    WHERE id = p_credential_id
      AND namespace = p_namespace
      AND disabled_at IS NULL
      AND (last_used_at IS NULL OR last_used_at < now() - interval '1 hour');

    -- Note: No audit log for routine usage to avoid log spam
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = authn, pg_temp;


-- @function authn.consume_credential
-- @brief Consume a one-time credential (e.g., recovery code)
-- @param p_credential_id Credential to consume
-- @returns true if consumed, false if already consumed/disabled
-- @note Atomic operation - safe for concurrent access
-- @example SELECT authn.consume_credential(recovery_code_id);
CREATE OR REPLACE FUNCTION authn.consume_credential(
    p_credential_id uuid,
    p_namespace text DEFAULT 'default'
)
RETURNS boolean
AS $$
DECLARE
    v_count int;
    v_user_id uuid;
    v_type text;
BEGIN
    PERFORM authn._validate_namespace(p_namespace);

    UPDATE authn.credentials
    SET consumed_at = now(),
        last_used_at = now()
    WHERE id = p_credential_id
      AND namespace = p_namespace
      AND consumed_at IS NULL
      AND disabled_at IS NULL
    RETURNING user_id, credential_type INTO v_user_id, v_type;

    GET DIAGNOSTICS v_count = ROW_COUNT;

    IF v_count > 0 THEN
        PERFORM authn._log_event(
            'credential_consumed', p_namespace, 'credential', p_credential_id::text,
            NULL,
            jsonb_build_object('user_id', v_user_id, 'credential_type', v_type)
        );
    END IF;

    RETURN v_count > 0;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = authn, pg_temp;


-- @function authn.update_sign_count
-- @brief Update WebAuthn sign count (clone detection)
-- @param p_credential_id Credential to update
-- @param p_new_count New sign count from authenticator
-- @returns true if updated, false if clone detected (new_count <= current)
-- @note SECURITY: false return indicates potential authenticator cloning
-- @example SELECT authn.update_sign_count(webauthn_credential_id, 42);
CREATE OR REPLACE FUNCTION authn.update_sign_count(
    p_credential_id uuid,
    p_new_count int,
    p_namespace text DEFAULT 'default'
)
RETURNS boolean
AS $$
DECLARE
    v_count int;
    v_user_id uuid;
    v_old_sign_count int;
BEGIN
    PERFORM authn._validate_namespace(p_namespace);

    -- Get current sign count for audit
    SELECT user_id, sign_count
    INTO v_user_id, v_old_sign_count
    FROM authn.credentials
    WHERE id = p_credential_id
      AND namespace = p_namespace
      AND disabled_at IS NULL;

    -- Only update if new count is strictly greater (clone detection)
    UPDATE authn.credentials
    SET sign_count = p_new_count,
        last_used_at = now()
    WHERE id = p_credential_id
      AND namespace = p_namespace
      AND sign_count < p_new_count
      AND disabled_at IS NULL;

    GET DIAGNOSTICS v_count = ROW_COUNT;

    IF v_count = 0 AND v_user_id IS NOT NULL THEN
        -- Clone attack detected - log security event
        PERFORM authn._log_event(
            'credential_clone_detected', p_namespace, 'credential', p_credential_id::text,
            NULL,
            jsonb_build_object(
                'user_id', v_user_id,
                'stored_sign_count', v_old_sign_count,
                'received_sign_count', p_new_count
            )
        );
    END IF;

    RETURN v_count > 0;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = authn, pg_temp;


-- @function authn.disable_credential
-- @brief Soft-disable a credential (preserves for forensics)
-- @param p_credential_id Credential to disable
-- @param p_reason Reason for disabling (required for audit)
-- @returns true if disabled, false if not found/already disabled
-- @example SELECT authn.disable_credential(credential_id, 'Reported as compromised');
CREATE OR REPLACE FUNCTION authn.disable_credential(
    p_credential_id uuid,
    p_reason text,
    p_namespace text DEFAULT 'default'
)
RETURNS boolean
AS $$
DECLARE
    v_count int;
    v_user_id uuid;
    v_type text;
    v_name text;
BEGIN
    PERFORM authn._validate_namespace(p_namespace);

    IF p_reason IS NULL OR trim(p_reason) = '' THEN
        RAISE EXCEPTION 'Reason is required when disabling a credential'
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:authn:CRED_DISABLE_NO_REASON';
    END IF;

    UPDATE authn.credentials
    SET disabled_at = now(),
        disabled_reason = p_reason
    WHERE id = p_credential_id
      AND namespace = p_namespace
      AND disabled_at IS NULL
    RETURNING user_id, credential_type, name INTO v_user_id, v_type, v_name;

    GET DIAGNOSTICS v_count = ROW_COUNT;

    IF v_count > 0 THEN
        PERFORM authn._log_event(
            'credential_disabled', p_namespace, 'credential', p_credential_id::text,
            NULL,
            jsonb_build_object(
                'user_id', v_user_id,
                'credential_type', v_type,
                'name', v_name,
                'reason', p_reason
            )
        );
    END IF;

    RETURN v_count > 0;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = authn, pg_temp;


-- @function authn.remove_credential
-- @brief Hard-delete a credential (user self-service)
-- @param p_credential_id Credential to remove
-- @returns true if removed, false if not found
-- @example SELECT authn.remove_credential(credential_id);
CREATE OR REPLACE FUNCTION authn.remove_credential(
    p_credential_id uuid,
    p_namespace text DEFAULT 'default'
)
RETURNS boolean
AS $$
DECLARE
    v_user_id uuid;
    v_type text;
    v_name text;
    v_count int;
BEGIN
    PERFORM authn._validate_namespace(p_namespace);

    -- Capture metadata before deletion for audit
    SELECT user_id, credential_type, name
    INTO v_user_id, v_type, v_name
    FROM authn.credentials
    WHERE id = p_credential_id AND namespace = p_namespace;

    IF v_user_id IS NULL THEN
        RETURN false;
    END IF;

    DELETE FROM authn.credentials
    WHERE id = p_credential_id
      AND namespace = p_namespace;

    GET DIAGNOSTICS v_count = ROW_COUNT;

    IF v_count > 0 THEN
        PERFORM authn._log_event(
            'credential_removed', p_namespace, 'credential', p_credential_id::text,
            jsonb_build_object(
                'user_id', v_user_id,
                'credential_type', v_type,
                'name', v_name
            )
        );
    END IF;

    RETURN v_count > 0;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = authn, pg_temp;


-- @function authn.list_credentials
-- @brief List credentials for settings UI (no secrets exposed)
-- @param p_user_id User to list credentials for
-- @param p_type Optional: filter by credential type
-- @param p_include_disabled Include disabled credentials (for admin/forensics)
-- @returns Table of credential metadata
-- @example SELECT * FROM authn.list_credentials(user_id);
CREATE OR REPLACE FUNCTION authn.list_credentials(
    p_user_id uuid,
    p_type text DEFAULT NULL,
    p_include_disabled boolean DEFAULT false,
    p_namespace text DEFAULT 'default'
)
RETURNS TABLE(
    id uuid,
    credential_type text,
    name text,
    created_at timestamptz,
    last_used_at timestamptz,
    consumed_at timestamptz,
    disabled_at timestamptz,
    disabled_reason text
)
AS $$
BEGIN
    IF p_type IS NOT NULL THEN
        PERFORM authn._validate_credential_type(p_type);
    END IF;
    PERFORM authn._validate_namespace(p_namespace);
    PERFORM authn._warn_namespace_mismatch(p_namespace);

    RETURN QUERY
    SELECT
        c.id,
        c.credential_type,
        c.name,
        c.created_at,
        c.last_used_at,
        c.consumed_at,
        c.disabled_at,
        c.disabled_reason
    FROM authn.credentials c
    WHERE c.user_id = p_user_id
      AND c.namespace = p_namespace
      AND (p_type IS NULL OR c.credential_type = p_type)
      AND (p_include_disabled OR c.disabled_at IS NULL)
    ORDER BY c.created_at;
END;
$$ LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = authn, pg_temp;


-- @function authn.has_credential
-- @brief Check if user has active credential of a specific type
-- @param p_user_id User to check
-- @param p_type Credential type to check for
-- @returns true if user has at least one active credential of type
-- @example IF authn.has_credential(user_id, 'totp') THEN prompt_for_code(); END IF;
CREATE OR REPLACE FUNCTION authn.has_credential(
    p_user_id uuid,
    p_type text,
    p_namespace text DEFAULT 'default'
)
RETURNS boolean
AS $$
BEGIN
    PERFORM authn._validate_credential_type(p_type);
    PERFORM authn._validate_namespace(p_namespace);

    RETURN EXISTS (
        SELECT 1
        FROM authn.credentials
        WHERE user_id = p_user_id
          AND credential_type = p_type
          AND namespace = p_namespace
          AND disabled_at IS NULL
          AND consumed_at IS NULL
    );
END;
$$ LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = authn, pg_temp;


-- @function authn.disable_all_credentials
-- @brief Bulk disable all credentials for a user (incident response)
-- @param p_user_id User whose credentials to disable
-- @param p_reason Reason for bulk disable (required for audit)
-- @returns Count of credentials disabled
-- @example SELECT authn.disable_all_credentials(user_id, 'User reported device stolen');
CREATE OR REPLACE FUNCTION authn.disable_all_credentials(
    p_user_id uuid,
    p_reason text,
    p_namespace text DEFAULT 'default'
)
RETURNS int
AS $$
DECLARE
    v_count int;
BEGIN
    PERFORM authn._validate_namespace(p_namespace);

    IF p_reason IS NULL OR trim(p_reason) = '' THEN
        RAISE EXCEPTION 'Reason is required when disabling credentials'
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:authn:CRED_DISABLE_NO_REASON';
    END IF;

    UPDATE authn.credentials
    SET disabled_at = now(),
        disabled_reason = p_reason
    WHERE user_id = p_user_id
      AND namespace = p_namespace
      AND disabled_at IS NULL;

    GET DIAGNOSTICS v_count = ROW_COUNT;

    IF v_count > 0 THEN
        PERFORM authn._log_event(
            'bulk_credentials_disabled', p_namespace, 'user', p_user_id::text,
            NULL,
            jsonb_build_object(
                'user_id', p_user_id,
                'count', v_count,
                'reason', p_reason
            )
        );
    END IF;

    RETURN v_count;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = authn, pg_temp;
