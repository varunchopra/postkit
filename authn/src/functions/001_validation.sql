-- @group Internal

-- @function authn._validate_email
-- @brief Validates and normalizes email address
-- @param p_email The email to validate
-- @returns Lowercase, trimmed email
-- Raises exception on invalid format.
--
-- DESIGN NOTE: Email validation is intentionally minimal (requires non-empty local
-- part and domain: "something@something"). This is deliberate:
--   1. RFC 5321/5322 email syntax is extremely complex (quoted strings, comments, IP literals)
--   2. Strict regex validation rejects valid addresses (e.g., user+tag@domain, unicode domains)
--   3. The only true validation is sending an email and confirming receipt
--   4. Most "invalid" emails that pass this check fail at SMTP delivery anyway
--
-- Applications requiring stricter validation should implement it at their layer using
-- proper email validation libraries. See: https://docs.aws.amazon.com/ses/latest/dg/email-validation.html
-- This library focuses on storage and comparison, not deliverability validation.
CREATE OR REPLACE FUNCTION authn._validate_email(p_email text)
RETURNS text
AS $$
DECLARE
    v_normalized text;
BEGIN
    IF p_email IS NULL THEN
        RAISE EXCEPTION 'Email cannot be null'
            USING ERRCODE = 'null_value_not_allowed',
                  HINT = 'postkit:authn:VAL_EMAIL_NULL';
    END IF;

    v_normalized := lower(trim(p_email));

    IF v_normalized = '' THEN
        RAISE EXCEPTION 'Email cannot be empty'
            USING ERRCODE = 'string_data_length_mismatch',
                  HINT = 'postkit:authn:VAL_EMAIL_EMPTY';
    END IF;

    IF length(v_normalized) > 1024 THEN
        RAISE EXCEPTION 'Email exceeds maximum length of 1024 characters'
            USING ERRCODE = 'string_data_right_truncation',
                  HINT = 'postkit:authn:VAL_EMAIL_TOO_LONG';
    END IF;

    -- Reject control characters
    IF v_normalized ~ '[\x00-\x1F\x7F]' THEN
        RAISE EXCEPTION 'Email contains invalid control characters'
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:authn:VAL_EMAIL_INVALID_CHARS';
    END IF;

    -- Basic email format: something@something (no spaces)
    IF v_normalized !~ '^[^\s@]+@[^\s@]+$' THEN
        RAISE EXCEPTION 'Email format is invalid (got: %)', v_normalized
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:authn:VAL_EMAIL_INVALID_FORMAT';
    END IF;

    RETURN v_normalized;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SET search_path = authn, pg_temp;


-- @function authn._validate_hash
-- @brief Validates password_hash or token_hash
-- @param p_hash The hash to validate
-- @param p_field_name Field name for error messages
-- @param p_allow_null Set true for SSO users (no password)
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
                USING ERRCODE = 'null_value_not_allowed',
                      HINT = 'postkit:authn:VAL_HASH_NULL';
        END IF;
    END IF;

    IF trim(p_hash) = '' THEN
        RAISE EXCEPTION '% cannot be empty', p_field_name
            USING ERRCODE = 'string_data_length_mismatch',
                  HINT = 'postkit:authn:VAL_HASH_EMPTY';
    END IF;

    IF length(p_hash) > 1024 THEN
        RAISE EXCEPTION '% exceeds maximum length of 1024 characters', p_field_name
            USING ERRCODE = 'string_data_right_truncation',
                  HINT = 'postkit:authn:VAL_HASH_TOO_LONG';
    END IF;

    -- Reject control characters
    IF p_hash ~ '[\x00-\x1F\x7F]' THEN
        RAISE EXCEPTION '% contains invalid control characters', p_field_name
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:authn:VAL_HASH_INVALID_CHARS';
    END IF;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SET search_path = authn, pg_temp;


-- @function authn._validate_token_type
-- @brief Validates token type
-- @param p_type The token type to validate
-- Must be password_reset, email_verify, or magic_link.
CREATE OR REPLACE FUNCTION authn._validate_token_type(p_type text)
RETURNS void
AS $$
BEGIN
    IF p_type IS NULL THEN
        RAISE EXCEPTION 'token_type cannot be null'
            USING ERRCODE = 'null_value_not_allowed',
                  HINT = 'postkit:authn:VAL_TOKEN_TYPE_NULL';
    END IF;

    IF p_type NOT IN ('password_reset', 'email_verify', 'magic_link') THEN
        RAISE EXCEPTION 'token_type must be password_reset, email_verify, or magic_link (got: %)', p_type
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:authn:VAL_TOKEN_TYPE_INVALID';
    END IF;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SET search_path = authn, pg_temp;


-- @function authn._validate_credential_type
-- @brief Validates credential type
-- @param p_type The credential type to validate
-- Must be totp, recovery_code, or webauthn.
CREATE OR REPLACE FUNCTION authn._validate_credential_type(p_type text)
RETURNS void
AS $$
BEGIN
    IF p_type IS NULL THEN
        RAISE EXCEPTION 'credential_type cannot be null'
            USING ERRCODE = 'null_value_not_allowed',
                  HINT = 'postkit:authn:VAL_CREDENTIAL_TYPE_NULL';
    END IF;

    IF p_type NOT IN ('totp', 'recovery_code', 'webauthn') THEN
        RAISE EXCEPTION 'credential_type must be totp, recovery_code, or webauthn (got: %)', p_type
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:authn:VAL_CREDENTIAL_TYPE_INVALID';
    END IF;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SET search_path = authn, pg_temp;


-- @function authn._validate_uuid
-- @brief Validates and returns a UUID value
-- @param p_value The value to validate
-- @param p_field_name Field name for error messages
-- @returns The validated UUID
-- Raises invalid_parameter_value on bad format.
CREATE OR REPLACE FUNCTION authn._validate_uuid(p_value text, p_field_name text)
RETURNS uuid
AS $$
BEGIN
    IF p_value IS NULL THEN
        RAISE EXCEPTION '% cannot be null', p_field_name
            USING ERRCODE = 'null_value_not_allowed',
                  HINT = 'postkit:authn:VAL_UUID_NULL';
    END IF;

    BEGIN
        RETURN p_value::uuid;
    EXCEPTION WHEN invalid_text_representation THEN
        RAISE EXCEPTION '% must be a valid UUID (got: %)', p_field_name, p_value
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:authn:VAL_UUID_INVALID';
    END;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SET search_path = authn, pg_temp;


-- @function authn._validate_namespace
-- @brief Validates namespace format
-- @param p_value The namespace to validate
-- Flexible: allows any string except control characters and leading/trailing whitespace.
CREATE OR REPLACE FUNCTION authn._validate_namespace(p_value text)
RETURNS void
AS $$
BEGIN
    IF p_value IS NULL THEN
        RAISE EXCEPTION 'Namespace cannot be null'
            USING ERRCODE = 'null_value_not_allowed',
                  HINT = 'postkit:authn:VAL_NAMESPACE_NULL';
    END IF;

    IF trim(p_value) = '' THEN
        RAISE EXCEPTION 'Namespace cannot be empty'
            USING ERRCODE = 'string_data_length_mismatch',
                  HINT = 'postkit:authn:VAL_NAMESPACE_EMPTY';
    END IF;

    IF length(p_value) > 1024 THEN
        RAISE EXCEPTION 'Namespace exceeds maximum length of 1024 characters'
            USING ERRCODE = 'string_data_right_truncation',
                  HINT = 'postkit:authn:VAL_NAMESPACE_TOO_LONG';
    END IF;

    -- Reject control characters (0x00-0x1F, 0x7F)
    IF p_value ~ '[\x00-\x1F\x7F]' THEN
        RAISE EXCEPTION 'Namespace contains invalid control characters'
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:authn:VAL_NAMESPACE_INVALID_CHARS';
    END IF;

    -- Reject leading/trailing whitespace (causes subtle matching bugs)
    IF p_value != trim(p_value) THEN
        RAISE EXCEPTION 'Namespace cannot have leading or trailing whitespace'
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:authn:VAL_NAMESPACE_WHITESPACE';
    END IF;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SET search_path = authn, pg_temp;


-- @function authn._warn_namespace_mismatch
-- @brief Warns if namespace doesn't match RLS tenant context
-- @param p_namespace The namespace being queried
--
-- SECURITY MODEL: Access control is enforced via explicit p_namespace parameters in
-- all functions. RLS (authn.tenant_id) provides defense-in-depth but is not the
-- primary control. This function raises a WARNING (not ERROR) to:
--   1. Allow legitimate cross-namespace admin operations
--   2. Alert developers to potential mistakes during development
--   3. Avoid breaking functionality for valid use cases
--
-- For deployments requiring strict namespace isolation, consider:
--   - Always setting authn.tenant_id before operations
--   - Monitoring for these warnings in production logs
--   - Using database roles without BYPASSRLS privilege
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


-- @function authn._validate_secret
-- @brief Validates credential secret
-- @param p_secret The secret to validate
-- Allows larger values for WebAuthn and recovery codes.
CREATE OR REPLACE FUNCTION authn._validate_secret(p_secret text)
RETURNS void
AS $$
BEGIN
    IF p_secret IS NULL THEN
        RAISE EXCEPTION 'Secret cannot be null'
            USING ERRCODE = 'null_value_not_allowed',
                  HINT = 'postkit:authn:VAL_SECRET_NULL';
    END IF;

    IF trim(p_secret) = '' THEN
        RAISE EXCEPTION 'Secret cannot be empty'
            USING ERRCODE = 'string_data_length_mismatch',
                  HINT = 'postkit:authn:VAL_SECRET_EMPTY';
    END IF;

    -- Secrets can be longer (recovery codes as JSON, WebAuthn credential data)
    IF length(p_secret) > 65536 THEN
        RAISE EXCEPTION 'Secret exceeds maximum length of 65536 characters'
            USING ERRCODE = 'string_data_right_truncation',
                  HINT = 'postkit:authn:VAL_SECRET_TOO_LONG';
    END IF;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SET search_path = authn, pg_temp;
