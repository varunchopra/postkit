-- @group Internal

-- @function authz._validate_identifier
-- @brief Validates resource_type, subject_type, or relation
-- @param p_value The value to validate
-- @param p_field_name Field name for error messages
-- Must start with lowercase letter, contain only lowercase letters, numbers, underscores, hyphens.
CREATE OR REPLACE FUNCTION authz._validate_identifier(p_value text, p_field_name text)
RETURNS void AS $$
BEGIN
    IF p_value IS NULL THEN
        RAISE EXCEPTION '% cannot be null', p_field_name
            USING ERRCODE = 'null_value_not_allowed',
                  HINT = 'postkit:authz:VAL_IDENTIFIER_NULL';
    END IF;

    IF trim(p_value) = '' THEN
        RAISE EXCEPTION '% cannot be empty', p_field_name
            USING ERRCODE = 'string_data_length_mismatch',
                  HINT = 'postkit:authz:VAL_IDENTIFIER_EMPTY';
    END IF;

    IF length(p_value) > 1024 THEN
        RAISE EXCEPTION '% exceeds maximum length of 1024 characters', p_field_name
            USING ERRCODE = 'string_data_right_truncation',
                  HINT = 'postkit:authz:VAL_IDENTIFIER_TOO_LONG';
    END IF;

    -- Must start with letter, then lowercase alphanumeric/underscore/hyphen
    IF p_value !~ '^[a-z][a-z0-9_-]*$' THEN
        RAISE EXCEPTION '% must start with lowercase letter and contain only lowercase letters, numbers, underscores, and hyphens (got: %)', p_field_name, p_value
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:authz:VAL_IDENTIFIER_FORMAT';
    END IF;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = authz, pg_temp;


-- @function authz._validate_id
-- @brief Validates resource_id or subject_id
-- @param p_value The value to validate
-- @param p_field_name Field name for error messages
-- Flexible: allows paths, URIs, emails, UUIDs. Rejects control characters and leading/trailing whitespace.
CREATE OR REPLACE FUNCTION authz._validate_id(p_value text, p_field_name text)
RETURNS void AS $$
BEGIN
    IF p_value IS NULL THEN
        RAISE EXCEPTION '% cannot be null', p_field_name
            USING ERRCODE = 'null_value_not_allowed',
                  HINT = 'postkit:authz:VAL_ID_NULL';
    END IF;

    IF trim(p_value) = '' THEN
        RAISE EXCEPTION '% cannot be empty', p_field_name
            USING ERRCODE = 'string_data_length_mismatch',
                  HINT = 'postkit:authz:VAL_ID_EMPTY';
    END IF;

    IF length(p_value) > 1024 THEN
        RAISE EXCEPTION '% exceeds maximum length of 1024 characters', p_field_name
            USING ERRCODE = 'string_data_right_truncation',
                  HINT = 'postkit:authz:VAL_ID_TOO_LONG';
    END IF;

    -- Reject control characters (except tab, newline, carriage return)
    IF p_value ~ '[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]' THEN
        RAISE EXCEPTION '% contains invalid control characters', p_field_name
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:authz:VAL_ID_INVALID_CHARS';
    END IF;

    -- Reject leading/trailing whitespace (causes subtle matching bugs)
    IF p_value != trim(p_value) THEN
        RAISE EXCEPTION '% cannot have leading or trailing whitespace', p_field_name
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:authz:VAL_ID_WHITESPACE';
    END IF;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = authz, pg_temp;


-- @function authz._validate_id_array
-- @brief Validates an array of IDs for bulk operations
-- @param p_values The array to validate
-- @param p_field_name Field name for error messages
-- Reports the index of the first invalid element for easier debugging.
CREATE OR REPLACE FUNCTION authz._validate_id_array(p_values text[], p_field_name text)
RETURNS void AS $$
DECLARE
    v_idx int;
    v_id text;
    v_reason text;
BEGIN
    FOR v_idx IN 1..COALESCE(array_length(p_values, 1), 0) LOOP
        v_id := p_values[v_idx];
        IF v_id IS NULL THEN
            v_reason := 'is null';
        ELSIF trim(v_id) = '' THEN
            v_reason := 'is empty';
        ELSIF length(v_id) > 1024 THEN
            v_reason := 'exceeds 1024 characters';
        ELSIF v_id ~ '[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]' THEN
            v_reason := 'contains invalid control characters';
        ELSIF v_id != trim(v_id) THEN
            v_reason := 'has leading or trailing whitespace';
        ELSE
            CONTINUE;  -- Valid, check next
        END IF;
        RAISE EXCEPTION '%[%] %', p_field_name, v_idx, v_reason
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:authz:VAL_ARRAY_ELEMENT_INVALID';
    END LOOP;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = authz, pg_temp;


-- @function authz._warn_namespace_mismatch
-- @brief Warns if namespace doesn't match RLS tenant context
-- @param p_namespace The namespace being queried
-- Called at start of query functions to alert developers of likely misconfiguration.
CREATE OR REPLACE FUNCTION authz._warn_namespace_mismatch(p_namespace text)
RETURNS void AS $$
DECLARE
    v_tenant_id text;
BEGIN
    v_tenant_id := current_setting('authz.tenant_id', true);
    IF v_tenant_id IS NOT NULL AND v_tenant_id != '' AND p_namespace != v_tenant_id THEN
        RAISE WARNING 'Querying namespace "%" but RLS tenant context is "%". Results will be empty due to row-level security.',
            p_namespace, v_tenant_id;
    END IF;
END;
$$ LANGUAGE plpgsql STABLE PARALLEL SAFE SECURITY INVOKER SET search_path = authz, pg_temp;


-- @function authz._validate_namespace
-- @brief Validates namespace format
-- @param p_value The namespace to validate
-- Flexible: allows any string except control characters and leading/trailing whitespace.
CREATE OR REPLACE FUNCTION authz._validate_namespace(p_value text)
RETURNS void AS $$
BEGIN
    IF p_value IS NULL THEN
        RAISE EXCEPTION 'Namespace cannot be null'
            USING ERRCODE = 'null_value_not_allowed',
                  HINT = 'postkit:authz:VAL_NAMESPACE_NULL';
    END IF;

    IF trim(p_value) = '' THEN
        RAISE EXCEPTION 'Namespace cannot be empty'
            USING ERRCODE = 'string_data_length_mismatch',
                  HINT = 'postkit:authz:VAL_NAMESPACE_EMPTY';
    END IF;

    IF length(p_value) > 1024 THEN
        RAISE EXCEPTION 'Namespace exceeds maximum length of 1024 characters'
            USING ERRCODE = 'string_data_right_truncation',
                  HINT = 'postkit:authz:VAL_NAMESPACE_TOO_LONG';
    END IF;

    -- Reject control characters (0x00-0x1F, 0x7F)
    IF p_value ~ '[\x00-\x1F\x7F]' THEN
        RAISE EXCEPTION 'Namespace contains invalid control characters'
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:authz:VAL_NAMESPACE_INVALID_CHARS';
    END IF;

    -- Reject leading/trailing whitespace (causes subtle matching bugs)
    IF p_value != trim(p_value) THEN
        RAISE EXCEPTION 'Namespace cannot have leading or trailing whitespace'
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:authz:VAL_NAMESPACE_WHITESPACE';
    END IF;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = authz, pg_temp;
