-- =============================================================================
-- VALIDATION FUNCTIONS FOR POSTKIT/QUEUE
-- =============================================================================
-- @group Internal

-- @function queue._validate_namespace
-- @brief Validate namespace format.
-- @param p_value Namespace to validate
-- Flexible: allows any string except control characters and leading/trailing whitespace.
CREATE OR REPLACE FUNCTION queue._validate_namespace(p_value text)
RETURNS void AS $$
BEGIN
    IF p_value IS NULL THEN
        RAISE EXCEPTION 'Namespace cannot be null'
            USING ERRCODE = 'null_value_not_allowed',
                  HINT = 'postkit:queue:VAL_NAMESPACE_NULL';
    END IF;

    IF trim(p_value) = '' THEN
        RAISE EXCEPTION 'Namespace cannot be empty'
            USING ERRCODE = 'string_data_length_mismatch',
                  HINT = 'postkit:queue:VAL_NAMESPACE_EMPTY';
    END IF;

    IF length(p_value) > 1024 THEN
        RAISE EXCEPTION 'Namespace exceeds maximum length of 1024 characters'
            USING ERRCODE = 'string_data_right_truncation',
                  HINT = 'postkit:queue:VAL_NAMESPACE_TOO_LONG';
    END IF;

    -- Reject control characters (0x00-0x1F, 0x7F)
    IF p_value ~ '[\x00-\x1F\x7F]' THEN
        RAISE EXCEPTION 'Namespace contains invalid control characters'
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:queue:VAL_NAMESPACE_INVALID_CHARS';
    END IF;

    -- Reject leading/trailing whitespace (causes subtle matching bugs)
    IF p_value != trim(p_value) THEN
        RAISE EXCEPTION 'Namespace cannot have leading or trailing whitespace'
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:queue:VAL_NAMESPACE_WHITESPACE';
    END IF;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = queue, pg_temp;


-- @function queue._validate_queue_name
-- @brief Validate queue name format.
-- @param p_value Queue name to validate
-- Queue names: alphanumeric, underscores, hyphens, 1-256 characters.
CREATE OR REPLACE FUNCTION queue._validate_queue_name(p_value text)
RETURNS void AS $$
BEGIN
    IF p_value IS NULL THEN
        RAISE EXCEPTION 'Queue name cannot be null'
            USING ERRCODE = 'null_value_not_allowed',
                  HINT = 'postkit:queue:VAL_QUEUE_NULL';
    END IF;

    IF trim(p_value) = '' THEN
        RAISE EXCEPTION 'Queue name cannot be empty'
            USING ERRCODE = 'string_data_length_mismatch',
                  HINT = 'postkit:queue:VAL_QUEUE_EMPTY';
    END IF;

    IF length(p_value) > 256 THEN
        RAISE EXCEPTION 'Queue name exceeds maximum length of 256 characters'
            USING ERRCODE = 'string_data_right_truncation',
                  HINT = 'postkit:queue:VAL_QUEUE_TOO_LONG';
    END IF;

    -- Queue names must be alphanumeric with underscores/hyphens, start with letter/underscore
    IF p_value !~ '^[a-zA-Z_][a-zA-Z0-9_-]*$' THEN
        RAISE EXCEPTION 'Queue name must start with a letter or underscore and contain only alphanumeric characters, underscores, and hyphens (got: %)', p_value
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:queue:VAL_QUEUE_FORMAT';
    END IF;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = queue, pg_temp;


-- @function queue._validate_priority
-- @brief Validate priority is within allowed range.
-- @param p_value Priority to validate
-- Range: -1000 to 1000. Higher values = higher priority.
CREATE OR REPLACE FUNCTION queue._validate_priority(p_value int)
RETURNS void AS $$
BEGIN
    IF p_value IS NULL THEN
        -- NULL is OK, will use default
        RETURN;
    END IF;

    IF p_value < -1000 OR p_value > 1000 THEN
        RAISE EXCEPTION 'Priority must be between -1000 and 1000 (got: %)', p_value
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:queue:VAL_PRIORITY_RANGE';
    END IF;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = queue, pg_temp;


-- @function queue._validate_positive_int
-- @brief Validate that an integer is positive.
-- @param p_value Value to validate
-- @param p_name Name of the parameter for error message
CREATE OR REPLACE FUNCTION queue._validate_positive_int(p_value int, p_name text)
RETURNS void AS $$
BEGIN
    IF p_value IS NULL OR p_value <= 0 THEN
        RAISE EXCEPTION '% must be a positive integer', p_name
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:queue:VAL_NOT_POSITIVE';
    END IF;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = queue, pg_temp;


-- @function queue._validate_schedule_name
-- @brief Validate schedule name format.
-- @param p_value Schedule name to validate
-- Schedule names follow same rules as queue names.
CREATE OR REPLACE FUNCTION queue._validate_schedule_name(p_value text)
RETURNS void AS $$
BEGIN
    IF p_value IS NULL THEN
        RAISE EXCEPTION 'Schedule name cannot be null'
            USING ERRCODE = 'null_value_not_allowed',
                  HINT = 'postkit:queue:VAL_SCHEDULE_NAME_NULL';
    END IF;

    IF trim(p_value) = '' THEN
        RAISE EXCEPTION 'Schedule name cannot be empty'
            USING ERRCODE = 'string_data_length_mismatch',
                  HINT = 'postkit:queue:VAL_SCHEDULE_NAME_EMPTY';
    END IF;

    IF length(p_value) > 256 THEN
        RAISE EXCEPTION 'Schedule name exceeds maximum length of 256 characters'
            USING ERRCODE = 'string_data_right_truncation',
                  HINT = 'postkit:queue:VAL_SCHEDULE_NAME_TOO_LONG';
    END IF;

    -- Schedule names must be alphanumeric with underscores/hyphens, start with letter/underscore
    IF p_value !~ '^[a-zA-Z_][a-zA-Z0-9_-]*$' THEN
        RAISE EXCEPTION 'Schedule name must start with a letter or underscore and contain only alphanumeric characters, underscores, and hyphens (got: %)', p_value
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:queue:VAL_SCHEDULE_NAME_FORMAT';
    END IF;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = queue, pg_temp;


-- @function queue._validate_cron_expression
-- @brief Basic validation of 5-field cron expression.
-- @param p_value Cron expression to validate
-- Format: minute hour day month weekday
-- Each field can be: *, number, range (1-5), list (1,3,5), step (*/5)
CREATE OR REPLACE FUNCTION queue._validate_cron_expression(p_value text)
RETURNS void AS $$
DECLARE
    v_parts text[];
    v_field text;
    v_field_pattern text := '^(\*|[0-9]+(-[0-9]+)?)(\/[0-9]+)?$|^([0-9]+(-[0-9]+)?,)*[0-9]+(-[0-9]+)?$';
BEGIN
    IF p_value IS NULL THEN
        -- NULL is OK when using every_interval instead
        RETURN;
    END IF;

    IF trim(p_value) = '' THEN
        RAISE EXCEPTION 'Cron expression cannot be empty'
            USING ERRCODE = 'string_data_length_mismatch',
                  HINT = 'postkit:queue:VAL_CRON_EMPTY';
    END IF;

    -- Split by whitespace
    v_parts := string_to_array(trim(regexp_replace(p_value, '\s+', ' ', 'g')), ' ');

    -- Must have exactly 5 fields
    IF array_length(v_parts, 1) != 5 THEN
        RAISE EXCEPTION 'Cron expression must have exactly 5 fields (minute hour day month weekday), got %', array_length(v_parts, 1)
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:queue:VAL_CRON_FIELDS';
    END IF;

    -- Basic format validation for each field
    FOREACH v_field IN ARRAY v_parts LOOP
        IF v_field !~ v_field_pattern THEN
            RAISE EXCEPTION 'Invalid cron field: %', v_field
                USING ERRCODE = 'invalid_parameter_value',
                      HINT = 'postkit:queue:VAL_CRON_INVALID';
        END IF;
    END LOOP;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = queue, pg_temp;


-- @function queue._warn_namespace_mismatch
-- @brief Warns if namespace doesn't match RLS tenant context.
-- @param p_namespace The namespace being queried
-- Called at start of query functions to alert developers of likely misconfiguration.
CREATE OR REPLACE FUNCTION queue._warn_namespace_mismatch(p_namespace text)
RETURNS void AS $$
DECLARE
    v_tenant_id text;
BEGIN
    v_tenant_id := current_setting('queue.tenant_id', true);
    IF v_tenant_id IS NOT NULL AND v_tenant_id != '' AND p_namespace != v_tenant_id THEN
        RAISE WARNING 'Querying namespace "%" but RLS tenant context is "%". Results will be empty due to row-level security.',
            p_namespace, v_tenant_id;
    END IF;
END;
$$ LANGUAGE plpgsql STABLE PARALLEL SAFE SECURITY INVOKER SET search_path = queue, pg_temp;
