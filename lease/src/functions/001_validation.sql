-- @group Internal

-- @function lease._name_violation
-- @brief Check a name against the shared name rules; NULL means the name is fine.
-- @param p_value Name to check
-- @param p_max_len Maximum length in characters
-- @returns The rule that was broken ('null', 'empty', 'too_long', 'invalid_chars', 'whitespace'), or NULL
-- Every name field follows the same rules: a name must exist, must not be
-- empty or only whitespace, must fit the length limit, must not contain
-- control characters (including the Unicode line separators U+0085, U+2028,
-- and U+2029), and must not start or end with whitespace. The per-field
-- validators turn the result into their own error, keeping each HINT code a
-- literal string because the SDK error-code sync test finds codes by
-- scanning the source.
CREATE OR REPLACE FUNCTION lease._name_violation(p_value text, p_max_len int)
RETURNS text AS $$
DECLARE
    v_trimmed text := trim(p_value);
BEGIN
    IF p_value IS NULL THEN
        RETURN 'null';
    END IF;
    IF v_trimmed = '' THEN
        RETURN 'empty';
    END IF;
    IF length(p_value) > p_max_len THEN
        RETURN 'too_long';
    END IF;
    IF p_value ~ '[\x00-\x1F\x7F\u0085\u2028\u2029]' THEN
        RETURN 'invalid_chars';
    END IF;
    IF p_value != v_trimmed THEN
        RETURN 'whitespace';
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = lease, pg_temp;


-- @function lease._validate_namespace
-- @brief Validate namespace format.
-- @param p_value Namespace to validate
-- Accepts any name that passes the shared name rules (see _name_violation); 1-1024 characters.
CREATE OR REPLACE FUNCTION lease._validate_namespace(p_value text)
RETURNS void AS $$
BEGIN
    CASE lease._name_violation(p_value, 1024)
        WHEN 'null' THEN
            RAISE EXCEPTION 'Namespace cannot be null'
                USING ERRCODE = 'null_value_not_allowed',
                      HINT = 'postkit:lease:VAL_NAMESPACE_NULL';
        WHEN 'empty' THEN
            RAISE EXCEPTION 'Namespace cannot be empty'
                USING ERRCODE = 'string_data_length_mismatch',
                      HINT = 'postkit:lease:VAL_NAMESPACE_EMPTY';
        WHEN 'too_long' THEN
            RAISE EXCEPTION 'Namespace exceeds maximum length of 1024 characters'
                USING ERRCODE = 'string_data_right_truncation',
                      HINT = 'postkit:lease:VAL_NAMESPACE_TOO_LONG';
        WHEN 'invalid_chars' THEN
            RAISE EXCEPTION 'Namespace contains invalid control characters'
                USING ERRCODE = 'invalid_parameter_value',
                      HINT = 'postkit:lease:VAL_NAMESPACE_INVALID_CHARS';
        WHEN 'whitespace' THEN
            RAISE EXCEPTION 'Namespace cannot have leading or trailing whitespace'
                USING ERRCODE = 'invalid_parameter_value',
                      HINT = 'postkit:lease:VAL_NAMESPACE_WHITESPACE';
        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = lease, pg_temp;


-- @function lease._validate_lease_name
-- @brief Validate lease name format.
-- @param p_value Lease name to validate
-- Accepts any name that passes the shared name rules (see _name_violation); 1-1024 characters.
CREATE OR REPLACE FUNCTION lease._validate_lease_name(p_value text)
RETURNS void AS $$
BEGIN
    CASE lease._name_violation(p_value, 1024)
        WHEN 'null' THEN
            RAISE EXCEPTION 'Lease name cannot be null'
                USING ERRCODE = 'null_value_not_allowed',
                      HINT = 'postkit:lease:VAL_LEASE_NAME_NULL';
        WHEN 'empty' THEN
            RAISE EXCEPTION 'Lease name cannot be empty'
                USING ERRCODE = 'string_data_length_mismatch',
                      HINT = 'postkit:lease:VAL_LEASE_NAME_EMPTY';
        WHEN 'too_long' THEN
            RAISE EXCEPTION 'Lease name exceeds maximum length of 1024 characters'
                USING ERRCODE = 'string_data_right_truncation',
                      HINT = 'postkit:lease:VAL_LEASE_NAME_TOO_LONG';
        WHEN 'invalid_chars' THEN
            RAISE EXCEPTION 'Lease name contains invalid control characters'
                USING ERRCODE = 'invalid_parameter_value',
                      HINT = 'postkit:lease:VAL_LEASE_NAME_INVALID_CHARS';
        WHEN 'whitespace' THEN
            RAISE EXCEPTION 'Lease name cannot have leading or trailing whitespace'
                USING ERRCODE = 'invalid_parameter_value',
                      HINT = 'postkit:lease:VAL_LEASE_NAME_WHITESPACE';
        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = lease, pg_temp;


-- @function lease._validate_holder
-- @brief Validate holder identifier format.
-- @param p_value Holder ID to validate
-- Accepts any name that passes the shared name rules (see _name_violation); 1-1024 characters.
CREATE OR REPLACE FUNCTION lease._validate_holder(p_value text)
RETURNS void AS $$
BEGIN
    CASE lease._name_violation(p_value, 1024)
        WHEN 'null' THEN
            RAISE EXCEPTION 'Holder ID cannot be null'
                USING ERRCODE = 'null_value_not_allowed',
                      HINT = 'postkit:lease:VAL_HOLDER_NULL';
        WHEN 'empty' THEN
            RAISE EXCEPTION 'Holder ID cannot be empty'
                USING ERRCODE = 'string_data_length_mismatch',
                      HINT = 'postkit:lease:VAL_HOLDER_EMPTY';
        WHEN 'too_long' THEN
            RAISE EXCEPTION 'Holder ID exceeds maximum length of 1024 characters'
                USING ERRCODE = 'string_data_right_truncation',
                      HINT = 'postkit:lease:VAL_HOLDER_TOO_LONG';
        WHEN 'invalid_chars' THEN
            RAISE EXCEPTION 'Holder ID contains invalid control characters'
                USING ERRCODE = 'invalid_parameter_value',
                      HINT = 'postkit:lease:VAL_HOLDER_INVALID_CHARS';
        WHEN 'whitespace' THEN
            RAISE EXCEPTION 'Holder ID cannot have leading or trailing whitespace'
                USING ERRCODE = 'invalid_parameter_value',
                      HINT = 'postkit:lease:VAL_HOLDER_WHITESPACE';
        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = lease, pg_temp;


-- @function lease._validate_ttl
-- @brief Validate a requested TTL against the configured maximum.
-- @param p_ttl Requested TTL (NULL is OK, caller uses the configured default)
-- @param p_max Maximum allowed TTL from config
CREATE OR REPLACE FUNCTION lease._validate_ttl(p_ttl interval, p_max interval)
RETURNS void AS $$
BEGIN
    IF p_ttl IS NULL THEN
        -- NULL is OK, will use default
        RETURN;
    END IF;

    IF p_ttl <= interval '0 seconds' THEN
        RAISE EXCEPTION 'TTL must be a positive interval'
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:lease:VAL_TTL_NOT_POSITIVE';
    END IF;

    IF p_ttl > p_max THEN
        RAISE EXCEPTION 'TTL % exceeds maximum allowed TTL %', p_ttl, p_max
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:lease:VAL_TTL_EXCEEDS_MAX';
    END IF;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = lease, pg_temp;


-- @function lease._validate_fence
-- @brief Validate that a fence token is not null.
-- @param p_value Fence token to validate
CREATE OR REPLACE FUNCTION lease._validate_fence(p_value bigint)
RETURNS void AS $$
BEGIN
    IF p_value IS NULL THEN
        RAISE EXCEPTION 'Fence token cannot be null'
            USING ERRCODE = 'null_value_not_allowed',
                  HINT = 'postkit:lease:VAL_FENCE_NULL';
    END IF;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = lease, pg_temp;


-- @function lease._validate_positive_int
-- @brief Validate that an integer is positive.
-- @param p_value Value to validate
-- @param p_name Name of the parameter for error message
CREATE OR REPLACE FUNCTION lease._validate_positive_int(p_value int, p_name text)
RETURNS void AS $$
BEGIN
    IF p_value IS NULL OR p_value <= 0 THEN
        RAISE EXCEPTION '% must be a positive integer', p_name
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:lease:VAL_NOT_POSITIVE';
    END IF;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = lease, pg_temp;

CREATE OR REPLACE FUNCTION lease._validate_limit(p_value int, p_name text, p_max int)
RETURNS void AS $$
BEGIN
    PERFORM lease._validate_positive_int(p_value, p_name);
    IF p_value > p_max THEN
        RAISE EXCEPTION '% (%) exceeds maximum of %', p_name, p_value, p_max
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:lease:VAL_LIMIT_TOO_LARGE';
    END IF;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = lease, pg_temp;


-- @function lease._warn_namespace_mismatch
-- @brief Warns if namespace doesn't match RLS tenant context.
-- @param p_namespace The namespace being queried
-- Called at start of query functions to alert developers of likely misconfiguration.
CREATE OR REPLACE FUNCTION lease._warn_namespace_mismatch(p_namespace text)
RETURNS void AS $$
DECLARE
    v_tenant_id text;
BEGIN
    v_tenant_id := current_setting('lease.tenant_id', true);
    IF v_tenant_id IS NOT NULL AND v_tenant_id != '' AND p_namespace != v_tenant_id THEN
        RAISE WARNING 'Querying namespace "%" but RLS tenant context is "%". Results will be empty due to row-level security.',
            p_namespace, v_tenant_id;
    END IF;
END;
$$ LANGUAGE plpgsql STABLE PARALLEL SAFE SECURITY INVOKER SET search_path = lease, pg_temp;
