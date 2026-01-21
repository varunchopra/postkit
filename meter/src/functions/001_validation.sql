-- @group Internal

-- @function meter._validate_namespace
-- @brief Validate namespace format
-- @param p_value Namespace to validate
-- Flexible: allows any string except control characters and leading/trailing whitespace.
CREATE FUNCTION meter._validate_namespace(p_value text)
RETURNS void AS $$
BEGIN
    IF p_value IS NULL THEN
        RAISE EXCEPTION 'Namespace cannot be null'
            USING ERRCODE = 'null_value_not_allowed',
                  HINT = 'postkit:meter:VAL_NAMESPACE_NULL';
    END IF;

    IF trim(p_value) = '' THEN
        RAISE EXCEPTION 'Namespace cannot be empty'
            USING ERRCODE = 'string_data_length_mismatch',
                  HINT = 'postkit:meter:VAL_NAMESPACE_EMPTY';
    END IF;

    IF length(p_value) > 1024 THEN
        RAISE EXCEPTION 'Namespace exceeds maximum length of 1024 characters'
            USING ERRCODE = 'string_data_right_truncation',
                  HINT = 'postkit:meter:VAL_NAMESPACE_TOO_LONG';
    END IF;

    -- Reject control characters (0x00-0x1F, 0x7F)
    IF p_value ~ '[\x00-\x1F\x7F]' THEN
        RAISE EXCEPTION 'Namespace contains invalid control characters'
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:meter:VAL_NAMESPACE_INVALID_CHARS';
    END IF;

    -- Reject leading/trailing whitespace (causes subtle matching bugs)
    IF p_value != trim(p_value) THEN
        RAISE EXCEPTION 'Namespace cannot have leading or trailing whitespace'
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:meter:VAL_NAMESPACE_WHITESPACE';
    END IF;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = meter, pg_temp;


-- @function meter._validate_event_type
-- @brief Validate event_type format
-- @param p_value Event type to validate
CREATE FUNCTION meter._validate_event_type(p_value text)
RETURNS void AS $$
BEGIN
    IF p_value IS NULL THEN
        RAISE EXCEPTION 'event_type cannot be null'
            USING ERRCODE = 'null_value_not_allowed',
                  HINT = 'postkit:meter:VAL_EVENT_TYPE_NULL';
    END IF;

    IF trim(p_value) = '' THEN
        RAISE EXCEPTION 'event_type cannot be empty'
            USING ERRCODE = 'string_data_length_mismatch',
                  HINT = 'postkit:meter:VAL_EVENT_TYPE_EMPTY';
    END IF;

    IF length(p_value) > 256 THEN
        RAISE EXCEPTION 'event_type exceeds maximum length of 256 characters'
            USING ERRCODE = 'string_data_right_truncation',
                  HINT = 'postkit:meter:VAL_EVENT_TYPE_TOO_LONG';
    END IF;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = meter, pg_temp;


-- @function meter._validate_unit
-- @brief Validate unit format
-- @param p_value Unit to validate
CREATE FUNCTION meter._validate_unit(p_value text)
RETURNS void AS $$
BEGIN
    IF p_value IS NULL THEN
        RAISE EXCEPTION 'Unit cannot be null'
            USING ERRCODE = 'null_value_not_allowed',
                  HINT = 'postkit:meter:VAL_UNIT_NULL';
    END IF;

    IF trim(p_value) = '' THEN
        RAISE EXCEPTION 'Unit cannot be empty'
            USING ERRCODE = 'string_data_length_mismatch',
                  HINT = 'postkit:meter:VAL_UNIT_EMPTY';
    END IF;

    IF length(p_value) > 64 THEN
        RAISE EXCEPTION 'Unit exceeds maximum length of 64 characters'
            USING ERRCODE = 'string_data_right_truncation',
                  HINT = 'postkit:meter:VAL_UNIT_TOO_LONG';
    END IF;
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
