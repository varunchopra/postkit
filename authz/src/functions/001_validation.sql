-- @group Internal

-- @function authz._name_violation
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
CREATE OR REPLACE FUNCTION authz._name_violation(p_value text, p_max_len int)
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
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = authz, pg_temp;


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
-- Accepts any name that passes the shared name rules (see _name_violation); 1-1024 characters.
CREATE OR REPLACE FUNCTION authz._validate_id(p_value text, p_field_name text)
RETURNS void AS $$
BEGIN
    CASE authz._name_violation(p_value, 1024)
        WHEN 'null' THEN
            RAISE EXCEPTION '% cannot be null', p_field_name
                USING ERRCODE = 'null_value_not_allowed',
                      HINT = 'postkit:authz:VAL_ID_NULL';
        WHEN 'empty' THEN
            RAISE EXCEPTION '% cannot be empty', p_field_name
                USING ERRCODE = 'string_data_length_mismatch',
                      HINT = 'postkit:authz:VAL_ID_EMPTY';
        WHEN 'too_long' THEN
            RAISE EXCEPTION '% exceeds maximum length of 1024 characters', p_field_name
                USING ERRCODE = 'string_data_right_truncation',
                      HINT = 'postkit:authz:VAL_ID_TOO_LONG';
        WHEN 'invalid_chars' THEN
            RAISE EXCEPTION '% contains invalid control characters', p_field_name
                USING ERRCODE = 'invalid_parameter_value',
                      HINT = 'postkit:authz:VAL_ID_INVALID_CHARS';
        WHEN 'whitespace' THEN
            RAISE EXCEPTION '% cannot have leading or trailing whitespace', p_field_name
                USING ERRCODE = 'invalid_parameter_value',
                      HINT = 'postkit:authz:VAL_ID_WHITESPACE';
        ELSE
            NULL;
    END CASE;
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
        v_reason := CASE authz._name_violation(v_id, 1024)
            WHEN 'null' THEN 'is null'
            WHEN 'empty' THEN 'is empty'
            WHEN 'too_long' THEN 'exceeds 1024 characters'
            WHEN 'invalid_chars' THEN 'contains invalid control characters'
            WHEN 'whitespace' THEN 'has leading or trailing whitespace'
        END;
        CONTINUE WHEN v_reason IS NULL;
        RAISE EXCEPTION '%[%] %', p_field_name, v_idx, v_reason
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:authz:VAL_ARRAY_ELEMENT_INVALID';
    END LOOP;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = authz, pg_temp;

CREATE OR REPLACE FUNCTION authz._validate_limit(p_value int, p_name text, p_max int)
RETURNS void AS $$
BEGIN
    IF p_value IS NULL OR p_value <= 0 THEN
        RAISE EXCEPTION '% must be a positive integer', p_name
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:authz:VAL_NOT_POSITIVE';
    END IF;
    IF p_value > p_max THEN
        RAISE EXCEPTION '% (%) exceeds maximum of %', p_name, p_value, p_max
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:authz:VAL_LIMIT_TOO_LARGE';
    END IF;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = authz, pg_temp;

-- Forces LIMIT validation even when the underlying query returns no rows.
CREATE OR REPLACE FUNCTION authz._validated_limit(p_value int, p_name text, p_max int)
RETURNS int AS $$
BEGIN
    PERFORM authz._validate_limit(p_value, p_name, p_max);
    RETURN p_value;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = authz, pg_temp;

CREATE OR REPLACE FUNCTION authz._validate_batch_size(p_size int, p_name text, p_max int DEFAULT 1000)
RETURNS void AS $$
BEGIN
    IF p_size > p_max THEN
        RAISE EXCEPTION '% contains % items; maximum is %', p_name, p_size, p_max
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:authz:VAL_BATCH_TOO_LARGE';
    END IF;
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
-- Accepts any name that passes the shared name rules (see _name_violation); 1-1024 characters.
CREATE OR REPLACE FUNCTION authz._validate_namespace(p_value text)
RETURNS void AS $$
BEGIN
    CASE authz._name_violation(p_value, 1024)
        WHEN 'null' THEN
            RAISE EXCEPTION 'Namespace cannot be null'
                USING ERRCODE = 'null_value_not_allowed',
                      HINT = 'postkit:authz:VAL_NAMESPACE_NULL';
        WHEN 'empty' THEN
            RAISE EXCEPTION 'Namespace cannot be empty'
                USING ERRCODE = 'string_data_length_mismatch',
                      HINT = 'postkit:authz:VAL_NAMESPACE_EMPTY';
        WHEN 'too_long' THEN
            RAISE EXCEPTION 'Namespace exceeds maximum length of 1024 characters'
                USING ERRCODE = 'string_data_right_truncation',
                      HINT = 'postkit:authz:VAL_NAMESPACE_TOO_LONG';
        WHEN 'invalid_chars' THEN
            RAISE EXCEPTION 'Namespace contains invalid control characters'
                USING ERRCODE = 'invalid_parameter_value',
                      HINT = 'postkit:authz:VAL_NAMESPACE_INVALID_CHARS';
        WHEN 'whitespace' THEN
            RAISE EXCEPTION 'Namespace cannot have leading or trailing whitespace'
                USING ERRCODE = 'invalid_parameter_value',
                      HINT = 'postkit:authz:VAL_NAMESPACE_WHITESPACE';
        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = authz, pg_temp;
