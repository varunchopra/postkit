-- @group Internal

-- @function config._validate_key_pattern
-- @brief Validates schema key pattern format
-- @param p_pattern The pattern to validate
-- Like _validate_key but allows trailing slash for prefix patterns.
-- Prefix patterns: 'flags/', 'rate_limits/' (homogeneous collections)
-- Exact patterns: 'integrations/webhook', 'settings/auth' (unique schemas)
CREATE OR REPLACE FUNCTION config._validate_key_pattern(p_pattern text)
RETURNS void
AS $$
BEGIN
    IF p_pattern IS NULL THEN
        RAISE EXCEPTION 'key_pattern cannot be null'
            USING ERRCODE = 'null_value_not_allowed',
                  HINT = 'postkit:config:VAL_PATTERN_NULL';
    END IF;

    IF trim(p_pattern) = '' THEN
        RAISE EXCEPTION 'key_pattern cannot be empty'
            USING ERRCODE = 'string_data_length_mismatch',
                  HINT = 'postkit:config:VAL_PATTERN_EMPTY';
    END IF;

    IF length(p_pattern) > 1024 THEN
        RAISE EXCEPTION 'key_pattern exceeds maximum length of 1024 characters'
            USING ERRCODE = 'string_data_right_truncation',
                  HINT = 'postkit:config:VAL_PATTERN_TOO_LONG';
    END IF;

    -- Allow alphanumeric, underscores, hyphens, forward slashes, dots
    -- Must start with letter or number
    -- Unlike keys, trailing slash IS allowed (for prefix patterns)
    IF p_pattern !~ '^[a-zA-Z0-9][a-zA-Z0-9_/.-]*$' THEN
        RAISE EXCEPTION 'key_pattern must start with alphanumeric and contain only alphanumerics, underscores, hyphens, forward slashes, and dots (got: %)', p_pattern
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:config:VAL_PATTERN_FORMAT';
    END IF;

    IF p_pattern ~ '//' OR p_pattern ~ '^/' THEN
        RAISE EXCEPTION 'key_pattern cannot have double slashes or leading slashes (got: %)', p_pattern
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:config:VAL_PATTERN_SLASHES';
    END IF;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = config, pg_temp;


-- @function config._set_schema
-- @brief Upserts a schema for a key pattern
-- @param p_key_pattern Pattern to match (prefix ending in / or exact key)
-- @param p_schema JSON Schema document (Draft 7)
-- @param p_description Optional human-readable description
-- @note Requires admin connection that bypasses RLS.
CREATE OR REPLACE FUNCTION config._set_schema(
    p_key_pattern text,
    p_schema jsonb,
    p_description text DEFAULT NULL
)
RETURNS void
AS $$
BEGIN
    PERFORM config._validate_key_pattern(p_key_pattern);

    IF p_schema IS NULL THEN
        RAISE EXCEPTION 'Schema cannot be null'
            USING ERRCODE = 'null_value_not_allowed',
                  HINT = 'postkit:config:VAL_SCHEMA_NULL';
    END IF;

    INSERT INTO config.schemas (key_pattern, schema, description, created_at, updated_at)
    VALUES (p_key_pattern, p_schema, p_description, now(), now())
    ON CONFLICT (key_pattern) DO UPDATE SET
        schema = EXCLUDED.schema,
        description = EXCLUDED.description,
        updated_at = now();
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path = config, pg_temp;


-- @function config._get_configs_for_pattern
-- @brief Get all active configs matching a pattern across ALL namespaces
-- @param p_key_pattern Pattern to match
-- @returns Table of (namespace, key, value) for all matching configs
-- @note Used by SDK set_schema() to validate existing configs before saving.
--       Requires admin connection that bypasses RLS to see all namespaces.
CREATE OR REPLACE FUNCTION config._get_configs_for_pattern(
    p_key_pattern text
)
RETURNS TABLE (namespace text, key text, value jsonb)
AS $$
BEGIN
    PERFORM config._validate_key_pattern(p_key_pattern);

    -- Prefix pattern (ends with /): match all keys starting with it
    -- Exact pattern: match only that key
    IF p_key_pattern LIKE '%/' THEN
        RETURN QUERY
        SELECT e.namespace, e.key, e.value
        FROM config.entries e
        WHERE e.key LIKE replace(p_key_pattern, '_', '\_') || '%' ESCAPE '\'
          AND e.is_active = true;
    ELSE
        RETURN QUERY
        SELECT e.namespace, e.key, e.value
        FROM config.entries e
        WHERE e.key = p_key_pattern
          AND e.is_active = true;
    END IF;
END;
$$ LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = config, pg_temp;


-- @group Schemas

-- @function config.get_schema
-- @brief Get the JSON Schema that applies to a config key
-- @param p_key The config key to find schema for
-- @returns JSON Schema document, or NULL if no matching schema
-- @example SELECT config.get_schema('flags/checkout');
-- Matching precedence:
--   1. Exact match wins over prefix
--   2. Longer prefix wins over shorter
--   3. No match = returns NULL (no validation required)
CREATE OR REPLACE FUNCTION config.get_schema(
    p_key text
)
RETURNS jsonb
AS $$
DECLARE
    v_schema jsonb;
BEGIN
    PERFORM config._validate_key(p_key);

    -- Try exact match first
    SELECT s.schema INTO v_schema
    FROM config.schemas s
    WHERE s.key_pattern = p_key;

    IF v_schema IS NOT NULL THEN
        RETURN v_schema;
    END IF;

    -- Try prefix matches (longest prefix wins)
    SELECT s.schema INTO v_schema
    FROM config.schemas s
    WHERE s.key_pattern LIKE '%/'
      AND p_key LIKE replace(s.key_pattern, '_', '\_') || '%' ESCAPE '\'
    ORDER BY length(s.key_pattern) DESC
    LIMIT 1;

    RETURN v_schema;
END;
$$ LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = config, pg_temp;


-- @function config.delete_schema
-- @brief Delete a schema by its key pattern
-- @param p_key_pattern Pattern to delete
-- @returns true if deleted, false if not found
CREATE OR REPLACE FUNCTION config.delete_schema(
    p_key_pattern text
)
RETURNS boolean
AS $$
DECLARE
    v_deleted int;
BEGIN
    PERFORM config._validate_key_pattern(p_key_pattern);

    DELETE FROM config.schemas
    WHERE key_pattern = p_key_pattern;

    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    RETURN v_deleted > 0;
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path = config, pg_temp;


-- @function config.list_schemas
-- @brief List all schemas, optionally filtered by prefix
-- @param p_prefix Optional prefix to filter by
-- @param p_limit Maximum number of results (default 100)
-- @returns Table of schemas
CREATE OR REPLACE FUNCTION config.list_schemas(
    p_prefix text DEFAULT NULL,
    p_limit int DEFAULT 100
)
RETURNS TABLE (
    key_pattern text,
    schema jsonb,
    description text,
    created_at timestamptz,
    updated_at timestamptz
)
AS $$
BEGIN
    IF p_limit IS NULL OR p_limit < 1 THEN
        p_limit := 100;
    END IF;
    IF p_limit > 1000 THEN
        p_limit := 1000;
    END IF;

    IF p_prefix IS NOT NULL THEN
        RETURN QUERY
        SELECT s.key_pattern, s.schema, s.description, s.created_at, s.updated_at
        FROM config.schemas s
        WHERE s.key_pattern LIKE replace(p_prefix, '_', '\_') || '%' ESCAPE '\'
        ORDER BY s.key_pattern
        LIMIT p_limit;
    ELSE
        RETURN QUERY
        SELECT s.key_pattern, s.schema, s.description, s.created_at, s.updated_at
        FROM config.schemas s
        ORDER BY s.key_pattern
        LIMIT p_limit;
    END IF;
END;
$$ LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = config, pg_temp;
