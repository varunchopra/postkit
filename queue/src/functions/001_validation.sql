-- @group Internal

-- @function queue._name_violation
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
CREATE OR REPLACE FUNCTION queue._name_violation(p_value text, p_max_len int)
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
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = queue, pg_temp;


-- @function queue._validate_namespace
-- @brief Validate namespace format.
-- @param p_value Namespace to validate
-- Accepts any name that passes the shared name rules (see _name_violation); 1-1024 characters.
CREATE OR REPLACE FUNCTION queue._validate_namespace(p_value text)
RETURNS void AS $$
BEGIN
    CASE queue._name_violation(p_value, 1024)
        WHEN 'null' THEN
            RAISE EXCEPTION 'Namespace cannot be null'
                USING ERRCODE = 'null_value_not_allowed',
                      HINT = 'postkit:queue:VAL_NAMESPACE_NULL';
        WHEN 'empty' THEN
            RAISE EXCEPTION 'Namespace cannot be empty'
                USING ERRCODE = 'string_data_length_mismatch',
                      HINT = 'postkit:queue:VAL_NAMESPACE_EMPTY';
        WHEN 'too_long' THEN
            RAISE EXCEPTION 'Namespace exceeds maximum length of 1024 characters'
                USING ERRCODE = 'string_data_right_truncation',
                      HINT = 'postkit:queue:VAL_NAMESPACE_TOO_LONG';
        WHEN 'invalid_chars' THEN
            RAISE EXCEPTION 'Namespace contains invalid control characters'
                USING ERRCODE = 'invalid_parameter_value',
                      HINT = 'postkit:queue:VAL_NAMESPACE_INVALID_CHARS';
        WHEN 'whitespace' THEN
            RAISE EXCEPTION 'Namespace cannot have leading or trailing whitespace'
                USING ERRCODE = 'invalid_parameter_value',
                      HINT = 'postkit:queue:VAL_NAMESPACE_WHITESPACE';
        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = queue, pg_temp;


-- @function queue._validate_queue_name
-- @brief Validate queue name format.
-- @param p_value Queue name to validate
-- Accepts any name that passes the shared name rules (see _name_violation); 1-256 characters.
CREATE OR REPLACE FUNCTION queue._validate_queue_name(p_value text)
RETURNS void AS $$
BEGIN
    CASE queue._name_violation(p_value, 256)
        WHEN 'null' THEN
            RAISE EXCEPTION 'Queue name cannot be null'
                USING ERRCODE = 'null_value_not_allowed',
                      HINT = 'postkit:queue:VAL_QUEUE_NULL';
        WHEN 'empty' THEN
            RAISE EXCEPTION 'Queue name cannot be empty'
                USING ERRCODE = 'string_data_length_mismatch',
                      HINT = 'postkit:queue:VAL_QUEUE_EMPTY';
        WHEN 'too_long' THEN
            RAISE EXCEPTION 'Queue name exceeds maximum length of 256 characters'
                USING ERRCODE = 'string_data_right_truncation',
                      HINT = 'postkit:queue:VAL_QUEUE_TOO_LONG';
        WHEN 'invalid_chars' THEN
            RAISE EXCEPTION 'Queue name contains invalid control characters'
                USING ERRCODE = 'invalid_parameter_value',
                      HINT = 'postkit:queue:VAL_QUEUE_INVALID_CHARS';
        WHEN 'whitespace' THEN
            RAISE EXCEPTION 'Queue name cannot have leading or trailing whitespace'
                USING ERRCODE = 'invalid_parameter_value',
                      HINT = 'postkit:queue:VAL_QUEUE_WHITESPACE';
        ELSE
            NULL;
    END CASE;
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


-- @function queue._validate_max_attempts
-- @brief Validate max_attempts is within allowed range.
-- @param p_value Max attempts to validate
-- Range: 1 to 30, far above any real retry policy.
CREATE OR REPLACE FUNCTION queue._validate_max_attempts(p_value int)
RETURNS void AS $$
BEGIN
    IF p_value IS NULL THEN
        -- NULL is OK, will use default
        RETURN;
    END IF;

    IF p_value < 1 OR p_value > 30 THEN
        RAISE EXCEPTION 'max_attempts must be between 1 and 30 (got: %)', p_value
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:queue:VAL_MAX_ATTEMPTS_RANGE';
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


-- @function queue._validate_job_id
-- @brief Require a non-null job ID.
-- @param p_value Job ID to validate
CREATE OR REPLACE FUNCTION queue._validate_job_id(p_value bigint)
RETURNS void AS $$
BEGIN
    IF p_value IS NULL THEN
        RAISE EXCEPTION 'Job ID cannot be null'
            USING ERRCODE = 'null_value_not_allowed',
                  HINT = 'postkit:queue:VAL_JOB_ID_NULL';
    END IF;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = queue, pg_temp;


-- @function queue._validate_fence
-- @brief Require a non-null fence token.
-- @param p_value Fence token returned by pull
CREATE OR REPLACE FUNCTION queue._validate_fence(p_value bigint)
RETURNS void AS $$
BEGIN
    IF p_value IS NULL THEN
        RAISE EXCEPTION 'Fence token cannot be null'
            USING ERRCODE = 'null_value_not_allowed',
                  HINT = 'postkit:queue:VAL_FENCE_NULL';
    END IF;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = queue, pg_temp;


CREATE OR REPLACE FUNCTION queue._validate_limit(p_value int, p_name text, p_max int)
RETURNS void AS $$
BEGIN
    PERFORM queue._validate_positive_int(p_value, p_name);
    IF p_value > p_max THEN
        RAISE EXCEPTION '% (%) exceeds maximum of %', p_name, p_value, p_max
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:queue:VAL_LIMIT_TOO_LARGE';
    END IF;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = queue, pg_temp;

CREATE OR REPLACE FUNCTION queue._validate_batch_size(p_size int, p_name text, p_max int DEFAULT 1000)
RETURNS void AS $$
BEGIN
    IF p_size > p_max THEN
        RAISE EXCEPTION '% contains % items; maximum is %', p_name, p_size, p_max
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:queue:VAL_BATCH_TOO_LARGE';
    END IF;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = queue, pg_temp;


-- @function queue._validate_schedule_name
-- @brief Validate schedule name format.
-- @param p_value Schedule name to validate
-- Accepts any name that passes the shared name rules (see _name_violation); 1-256 characters.
CREATE OR REPLACE FUNCTION queue._validate_schedule_name(p_value text)
RETURNS void AS $$
BEGIN
    CASE queue._name_violation(p_value, 256)
        WHEN 'null' THEN
            RAISE EXCEPTION 'Schedule name cannot be null'
                USING ERRCODE = 'null_value_not_allowed',
                      HINT = 'postkit:queue:VAL_SCHEDULE_NAME_NULL';
        WHEN 'empty' THEN
            RAISE EXCEPTION 'Schedule name cannot be empty'
                USING ERRCODE = 'string_data_length_mismatch',
                      HINT = 'postkit:queue:VAL_SCHEDULE_NAME_EMPTY';
        WHEN 'too_long' THEN
            RAISE EXCEPTION 'Schedule name exceeds maximum length of 256 characters'
                USING ERRCODE = 'string_data_right_truncation',
                      HINT = 'postkit:queue:VAL_SCHEDULE_NAME_TOO_LONG';
        WHEN 'invalid_chars' THEN
            RAISE EXCEPTION 'Schedule name contains invalid control characters'
                USING ERRCODE = 'invalid_parameter_value',
                      HINT = 'postkit:queue:VAL_SCHEDULE_NAME_INVALID_CHARS';
        WHEN 'whitespace' THEN
            RAISE EXCEPTION 'Schedule name cannot have leading or trailing whitespace'
                USING ERRCODE = 'invalid_parameter_value',
                      HINT = 'postkit:queue:VAL_SCHEDULE_NAME_WHITESPACE';
        ELSE
            NULL;
    END CASE;
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
    v_step_text text;
    v_field_pattern text := '^(\*|[0-9]+(-[0-9]+)?)(\/[0-9]+)?$|^([0-9]+(-[0-9]+)?,)*[0-9]+(-[0-9]+)?$';
BEGIN
    IF p_value IS NULL THEN
        -- NULL is OK when using every_interval instead
        RETURN;
    END IF;

    IF length(p_value) > 256 THEN
        RAISE EXCEPTION 'Cron expression cannot exceed 256 characters'
            USING ERRCODE = 'string_data_right_truncation',
                  HINT = 'postkit:queue:VAL_CRON_TOO_LONG';
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

        v_step_text := substring(v_field from '/([0-9]+)$');
        IF v_step_text IS NOT NULL AND v_step_text::numeric < 1 THEN
            RAISE EXCEPTION 'Cron step must be at least 1: %', v_field
                USING ERRCODE = 'invalid_parameter_value',
                      HINT = 'postkit:queue:VAL_CRON_STEP_ZERO';
        END IF;
    END LOOP;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = queue, pg_temp;


-- @function queue._validate_schedule_interval
-- @brief Validate that a recurring schedule interval is positive.
-- @param p_value Schedule interval to validate (NULL is allowed for cron schedules)
CREATE OR REPLACE FUNCTION queue._validate_schedule_interval(p_value interval)
RETURNS void AS $$
BEGIN
    IF p_value IS NOT NULL AND p_value <= interval '0' THEN
        RAISE EXCEPTION 'Schedule interval must be positive'
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:queue:VAL_INTERVAL_NOT_POSITIVE';
    END IF;
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
