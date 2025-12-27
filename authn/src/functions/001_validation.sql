-- =============================================================================
-- INPUT VALIDATION FOR POSTKIT/AUTHN
-- =============================================================================
--
-- Authentication data is security-critical. Bad data causes:
--   - Silent failures (empty emails match nothing)
--   - Security issues (unvalidated hashes could leak)
--   - Hard debugging ("why doesn't login work?")
--   - Injection risks (control characters, null bytes)
--
-- We validate at the database level as the last line of defense.
-- =============================================================================


-- =============================================================================
-- EMAIL VALIDATION
-- =============================================================================
-- Validates and normalizes email: lowercase, trimmed, basic format check.
-- Returns the normalized email or raises an exception.
CREATE OR REPLACE FUNCTION authn._validate_email(p_email text)
RETURNS text
AS $$
DECLARE
    v_normalized text;
BEGIN
    IF p_email IS NULL THEN
        RAISE EXCEPTION 'email cannot be null'
            USING ERRCODE = 'null_value_not_allowed';
    END IF;

    v_normalized := lower(trim(p_email));

    IF v_normalized = '' THEN
        RAISE EXCEPTION 'email cannot be empty'
            USING ERRCODE = 'string_data_length_mismatch';
    END IF;

    IF length(v_normalized) > 1024 THEN
        RAISE EXCEPTION 'email exceeds maximum length of 1024 characters'
            USING ERRCODE = 'string_data_right_truncation';
    END IF;

    -- Reject control characters
    IF v_normalized ~ '[\x00-\x1F\x7F]' THEN
        RAISE EXCEPTION 'email contains invalid control characters'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    -- Basic email format: something@something (no spaces)
    IF v_normalized !~ '^[^\s@]+@[^\s@]+$' THEN
        RAISE EXCEPTION 'email format is invalid'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    RETURN v_normalized;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SET search_path = authn, pg_temp;

COMMENT ON FUNCTION authn._validate_email(text) IS
'Validates and normalizes email address. Returns lowercase, trimmed email.';


-- =============================================================================
-- HASH VALIDATION
-- =============================================================================
-- Validates password_hash or token_hash. Can optionally allow NULL.
CREATE OR REPLACE FUNCTION authn._validate_hash(
    p_hash text,
    p_field_name text,
    p_allow_null boolean DEFAULT false
)
RETURNS void
AS $$
BEGIN
    IF p_hash IS NULL THEN
        IF p_allow_null THEN
            RETURN;
        ELSE
            RAISE EXCEPTION '% cannot be null', p_field_name
                USING ERRCODE = 'null_value_not_allowed';
        END IF;
    END IF;

    IF trim(p_hash) = '' THEN
        RAISE EXCEPTION '% cannot be empty', p_field_name
            USING ERRCODE = 'string_data_length_mismatch';
    END IF;

    IF length(p_hash) > 1024 THEN
        RAISE EXCEPTION '% exceeds maximum length of 1024 characters', p_field_name
            USING ERRCODE = 'string_data_right_truncation';
    END IF;

    -- Reject control characters
    IF p_hash ~ '[\x00-\x1F\x7F]' THEN
        RAISE EXCEPTION '% contains invalid control characters', p_field_name
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SET search_path = authn, pg_temp;

COMMENT ON FUNCTION authn._validate_hash(text, text, boolean) IS
'Validates a hash field (password_hash or token_hash). Use p_allow_null=true for SSO users.';


-- =============================================================================
-- TOKEN TYPE VALIDATION
-- =============================================================================
CREATE OR REPLACE FUNCTION authn._validate_token_type(p_type text)
RETURNS void
AS $$
BEGIN
    IF p_type IS NULL THEN
        RAISE EXCEPTION 'token_type cannot be null'
            USING ERRCODE = 'null_value_not_allowed';
    END IF;

    IF p_type NOT IN ('password_reset', 'email_verify', 'magic_link') THEN
        RAISE EXCEPTION 'token_type must be password_reset, email_verify, or magic_link (got: %)', p_type
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SET search_path = authn, pg_temp;

COMMENT ON FUNCTION authn._validate_token_type(text) IS
'Validates token type is one of: password_reset, email_verify, magic_link.';


-- =============================================================================
-- MFA TYPE VALIDATION
-- =============================================================================
CREATE OR REPLACE FUNCTION authn._validate_mfa_type(p_type text)
RETURNS void
AS $$
BEGIN
    IF p_type IS NULL THEN
        RAISE EXCEPTION 'mfa_type cannot be null'
            USING ERRCODE = 'null_value_not_allowed';
    END IF;

    IF p_type NOT IN ('totp', 'webauthn', 'recovery_codes') THEN
        RAISE EXCEPTION 'mfa_type must be totp, webauthn, or recovery_codes (got: %)', p_type
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SET search_path = authn, pg_temp;

COMMENT ON FUNCTION authn._validate_mfa_type(text) IS
'Validates MFA type is one of: totp, webauthn, recovery_codes.';


-- =============================================================================
-- UUID VALIDATION
-- =============================================================================
-- Validates and returns UUID. Raises on invalid format.
CREATE OR REPLACE FUNCTION authn._validate_uuid(p_value text, p_field_name text)
RETURNS uuid
AS $$
BEGIN
    IF p_value IS NULL THEN
        RAISE EXCEPTION '% cannot be null', p_field_name
            USING ERRCODE = 'null_value_not_allowed';
    END IF;

    BEGIN
        RETURN p_value::uuid;
    EXCEPTION WHEN invalid_text_representation THEN
        RAISE EXCEPTION '% must be a valid UUID (got: %)', p_field_name, p_value
            USING ERRCODE = 'invalid_parameter_value';
    END;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SET search_path = authn, pg_temp;

COMMENT ON FUNCTION authn._validate_uuid(text, text) IS
'Validates and returns a UUID value. Raises invalid_parameter_value on bad format.';


-- =============================================================================
-- NAMESPACE VALIDATION
-- =============================================================================
-- Same rules as authz: alphanumeric, can start with number, underscores/hyphens
CREATE OR REPLACE FUNCTION authn._validate_namespace(p_value text)
RETURNS void
AS $$
BEGIN
    IF p_value IS NULL THEN
        RAISE EXCEPTION 'namespace cannot be null'
            USING ERRCODE = 'null_value_not_allowed';
    END IF;

    IF trim(p_value) = '' THEN
        RAISE EXCEPTION 'namespace cannot be empty'
            USING ERRCODE = 'string_data_length_mismatch';
    END IF;

    IF length(p_value) > 1024 THEN
        RAISE EXCEPTION 'namespace exceeds maximum length of 1024 characters'
            USING ERRCODE = 'string_data_right_truncation';
    END IF;

    -- Alphanumeric (can start with number), underscores, hyphens
    -- Allows: "default", "tenant_123", "550e8400-e29b-41d4-a716-446655440000"
    IF p_value !~ '^[a-z0-9][a-z0-9_-]*$' THEN
        RAISE EXCEPTION 'namespace must be alphanumeric with underscores/hyphens (got: %)', p_value
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SET search_path = authn, pg_temp;

COMMENT ON FUNCTION authn._validate_namespace(text) IS
'Validates namespace format. Must be lowercase alphanumeric with underscores/hyphens.';


-- =============================================================================
-- NAMESPACE MISMATCH WARNING
-- =============================================================================
-- Warns if namespace doesn't match RLS tenant context
CREATE OR REPLACE FUNCTION authn._warn_namespace_mismatch(p_namespace text)
RETURNS void
AS $$
DECLARE
    v_tenant_id text;
BEGIN
    v_tenant_id := current_setting('authn.tenant_id', true);
    IF v_tenant_id IS NOT NULL AND v_tenant_id != '' AND p_namespace != v_tenant_id THEN
        RAISE WARNING 'Querying namespace "%" but RLS tenant context is "%". Results will be empty due to row-level security.',
            p_namespace, v_tenant_id;
    END IF;
END;
$$ LANGUAGE plpgsql STABLE PARALLEL SAFE SET search_path = authn, pg_temp;

COMMENT ON FUNCTION authn._warn_namespace_mismatch(text) IS
'Warns if namespace parameter differs from RLS tenant context.';


-- =============================================================================
-- SECRET VALIDATION (for MFA)
-- =============================================================================
CREATE OR REPLACE FUNCTION authn._validate_secret(p_secret text)
RETURNS void
AS $$
BEGIN
    IF p_secret IS NULL THEN
        RAISE EXCEPTION 'secret cannot be null'
            USING ERRCODE = 'null_value_not_allowed';
    END IF;

    IF trim(p_secret) = '' THEN
        RAISE EXCEPTION 'secret cannot be empty'
            USING ERRCODE = 'string_data_length_mismatch';
    END IF;

    -- Secrets can be longer (recovery codes as JSON, WebAuthn credential data)
    IF length(p_secret) > 65536 THEN
        RAISE EXCEPTION 'secret exceeds maximum length of 65536 characters'
            USING ERRCODE = 'string_data_right_truncation';
    END IF;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SET search_path = authn, pg_temp;

COMMENT ON FUNCTION authn._validate_secret(text) IS
'Validates MFA secret. Allows larger values for WebAuthn and recovery codes.';
