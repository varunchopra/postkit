-- @group Internal

-- @function meter._name_violation
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
CREATE FUNCTION meter._name_violation(p_value text, p_max_len int)
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
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = meter, pg_temp;


-- @function meter._validate_namespace
-- @brief Validate namespace format
-- @param p_value Namespace to validate
-- Accepts any name that passes the shared name rules (see _name_violation); 1-1024 characters.
CREATE FUNCTION meter._validate_namespace(p_value text)
RETURNS void AS $$
BEGIN
    CASE meter._name_violation(p_value, 1024)
        WHEN 'null' THEN
            RAISE EXCEPTION 'Namespace cannot be null'
                USING ERRCODE = 'null_value_not_allowed',
                      HINT = 'postkit:meter:VAL_NAMESPACE_NULL';
        WHEN 'empty' THEN
            RAISE EXCEPTION 'Namespace cannot be empty'
                USING ERRCODE = 'string_data_length_mismatch',
                      HINT = 'postkit:meter:VAL_NAMESPACE_EMPTY';
        WHEN 'too_long' THEN
            RAISE EXCEPTION 'Namespace exceeds maximum length of 1024 characters'
                USING ERRCODE = 'string_data_right_truncation',
                      HINT = 'postkit:meter:VAL_NAMESPACE_TOO_LONG';
        WHEN 'invalid_chars' THEN
            RAISE EXCEPTION 'Namespace contains invalid control characters'
                USING ERRCODE = 'invalid_parameter_value',
                      HINT = 'postkit:meter:VAL_NAMESPACE_INVALID_CHARS';
        WHEN 'whitespace' THEN
            RAISE EXCEPTION 'Namespace cannot have leading or trailing whitespace'
                USING ERRCODE = 'invalid_parameter_value',
                      HINT = 'postkit:meter:VAL_NAMESPACE_WHITESPACE';
        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = meter, pg_temp;


-- @function meter._validate_event_type
-- @brief Validate event_type format
-- @param p_value Event type to validate
-- Accepts any name that passes the shared name rules (see _name_violation); 1-256 characters.
CREATE FUNCTION meter._validate_event_type(p_value text)
RETURNS void AS $$
BEGIN
    CASE meter._name_violation(p_value, 256)
        WHEN 'null' THEN
            RAISE EXCEPTION 'event_type cannot be null'
                USING ERRCODE = 'null_value_not_allowed',
                      HINT = 'postkit:meter:VAL_EVENT_TYPE_NULL';
        WHEN 'empty' THEN
            RAISE EXCEPTION 'event_type cannot be empty'
                USING ERRCODE = 'string_data_length_mismatch',
                      HINT = 'postkit:meter:VAL_EVENT_TYPE_EMPTY';
        WHEN 'too_long' THEN
            RAISE EXCEPTION 'event_type exceeds maximum length of 256 characters'
                USING ERRCODE = 'string_data_right_truncation',
                      HINT = 'postkit:meter:VAL_EVENT_TYPE_TOO_LONG';
        WHEN 'invalid_chars' THEN
            RAISE EXCEPTION 'event_type contains invalid control characters'
                USING ERRCODE = 'invalid_parameter_value',
                      HINT = 'postkit:meter:VAL_EVENT_TYPE_INVALID_CHARS';
        WHEN 'whitespace' THEN
            RAISE EXCEPTION 'event_type cannot have leading or trailing whitespace'
                USING ERRCODE = 'invalid_parameter_value',
                      HINT = 'postkit:meter:VAL_EVENT_TYPE_WHITESPACE';
        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = meter, pg_temp;


-- @function meter._validate_unit
-- @brief Validate unit format
-- @param p_value Unit to validate
-- Accepts any name that passes the shared name rules (see _name_violation); 1-64 characters.
CREATE FUNCTION meter._validate_unit(p_value text)
RETURNS void AS $$
BEGIN
    CASE meter._name_violation(p_value, 64)
        WHEN 'null' THEN
            RAISE EXCEPTION 'Unit cannot be null'
                USING ERRCODE = 'null_value_not_allowed',
                      HINT = 'postkit:meter:VAL_UNIT_NULL';
        WHEN 'empty' THEN
            RAISE EXCEPTION 'Unit cannot be empty'
                USING ERRCODE = 'string_data_length_mismatch',
                      HINT = 'postkit:meter:VAL_UNIT_EMPTY';
        WHEN 'too_long' THEN
            RAISE EXCEPTION 'Unit exceeds maximum length of 64 characters'
                USING ERRCODE = 'string_data_right_truncation',
                      HINT = 'postkit:meter:VAL_UNIT_TOO_LONG';
        WHEN 'invalid_chars' THEN
            RAISE EXCEPTION 'Unit contains invalid control characters'
                USING ERRCODE = 'invalid_parameter_value',
                      HINT = 'postkit:meter:VAL_UNIT_INVALID_CHARS';
        WHEN 'whitespace' THEN
            RAISE EXCEPTION 'Unit cannot have leading or trailing whitespace'
                USING ERRCODE = 'invalid_parameter_value',
                      HINT = 'postkit:meter:VAL_UNIT_WHITESPACE';
        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = meter, pg_temp;


-- @function meter._validate_positive
-- @brief Validate that a numeric value is positive
-- @param p_value Value to validate
-- @param p_name Name of the parameter (for error message)
CREATE FUNCTION meter._validate_positive(p_value numeric, p_name text)
RETURNS void AS $$
BEGIN
    IF p_value IS NULL OR p_value <= 0 THEN
        RAISE EXCEPTION '% must be positive', p_name
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:meter:VAL_NOT_POSITIVE';
    END IF;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = meter, pg_temp;


-- @function meter._warn_namespace_mismatch
-- @brief Warns if namespace doesn't match RLS tenant context
-- @param p_namespace The namespace being queried
-- Called at start of query functions to alert developers of likely misconfiguration.
CREATE FUNCTION meter._warn_namespace_mismatch(p_namespace text)
RETURNS void AS $$
DECLARE
    v_tenant_id text;
BEGIN
    v_tenant_id := current_setting('meter.tenant_id', true);
    IF v_tenant_id IS NOT NULL AND v_tenant_id != '' AND p_namespace != v_tenant_id THEN
        RAISE WARNING 'Querying namespace "%" but RLS tenant context is "%". Results will be empty due to row-level security.',
            p_namespace, v_tenant_id;
    END IF;
END;
$$ LANGUAGE plpgsql STABLE PARALLEL SAFE SECURITY INVOKER SET search_path = meter, pg_temp;
