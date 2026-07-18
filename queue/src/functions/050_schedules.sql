-- @group Schedules

-- @function queue.create_schedule
-- @brief Create a recurring schedule that produces jobs automatically.
-- @param p_namespace Tenant namespace
-- @param p_name Schedule name (unique per namespace)
-- @param p_queue Target queue for generated jobs
-- @param p_payload Job payload template
-- @param p_cron_expression 5-field cron expression (mutually exclusive with p_every_interval)
-- @param p_cron_timezone Timezone for cron evaluation (default 'UTC')
-- @param p_every_interval Fixed interval between runs (mutually exclusive with p_cron_expression)
-- @param p_priority Job priority (-1000 to 1000)
-- @param p_max_attempts Maximum retry attempts for generated jobs
-- @param p_tags Tags applied to generated jobs
-- @param p_is_active Whether schedule starts active
-- @returns Schedule ID
CREATE OR REPLACE FUNCTION queue.create_schedule(
    p_namespace text,
    p_name text,
    p_queue text,
    p_payload jsonb,
    p_cron_expression text DEFAULT NULL,
    p_cron_timezone text DEFAULT 'UTC',
    p_every_interval interval DEFAULT NULL,
    p_priority int DEFAULT 0,
    p_max_attempts int DEFAULT 3,
    p_tags text[] DEFAULT '{}',
    p_is_active boolean DEFAULT true
)
RETURNS bigint AS $$
DECLARE
    v_next_run_at timestamptz;
    v_id bigint;
BEGIN
    -- Validate inputs
    PERFORM queue._validate_namespace(p_namespace);
    PERFORM queue._validate_schedule_name(p_name);
    PERFORM queue._validate_queue_name(p_queue);
    PERFORM queue._validate_priority(p_priority);
    PERFORM queue._validate_max_attempts(p_max_attempts);

    IF p_payload IS NULL THEN
        RAISE EXCEPTION 'Payload cannot be null'
            USING ERRCODE = 'null_value_not_allowed',
                  HINT = 'postkit:queue:VAL_PAYLOAD_NULL';
    END IF;

    -- Validate mutual exclusivity
    IF p_cron_expression IS NOT NULL AND p_every_interval IS NOT NULL THEN
        RAISE EXCEPTION 'Cannot specify both cron_expression and every_interval'
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:queue:BIZ_SCHEDULE_CRON_AND_INTERVAL';
    END IF;

    IF p_cron_expression IS NULL AND p_every_interval IS NULL THEN
        RAISE EXCEPTION 'Must specify either cron_expression or every_interval'
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:queue:BIZ_SCHEDULE_REQUIRES_SCHEDULE';
    END IF;

    PERFORM queue._validate_schedule_interval(p_every_interval);

    -- Validate cron expression if provided
    IF p_cron_expression IS NOT NULL THEN
        PERFORM queue._validate_cron_expression(p_cron_expression);
    END IF;

    -- Warn if namespace mismatch with RLS context
    PERFORM queue._warn_namespace_mismatch(p_namespace);

    -- Calculate initial next_run_at
    IF p_is_active THEN
        IF p_cron_expression IS NOT NULL THEN
            v_next_run_at := queue._cron_next_run(p_cron_expression, p_cron_timezone, now());
        ELSE
            v_next_run_at := now() + p_every_interval;
        END IF;
    END IF;
    -- If not active, next_run_at stays NULL

    -- Insert schedule
    BEGIN
        INSERT INTO queue.schedules (
            namespace, name, queue, payload, priority, max_attempts, tags,
            cron_expression, cron_timezone, every_interval,
            is_active, next_run_at
        )
        VALUES (
            p_namespace, p_name, p_queue, p_payload, p_priority, p_max_attempts, p_tags,
            p_cron_expression, p_cron_timezone, p_every_interval,
            p_is_active, v_next_run_at
        )
        RETURNING id INTO v_id;
    EXCEPTION
        WHEN unique_violation THEN
            RAISE EXCEPTION 'Schedule "%" already exists in namespace "%"', p_name, p_namespace
                USING ERRCODE = 'unique_violation',
                      HINT = 'postkit:queue:BIZ_SCHEDULE_DUPLICATE';
    END;

    RETURN v_id;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = queue, pg_temp;


-- @function queue.get_schedule
-- @brief Get a schedule by name.
-- @param p_namespace Tenant namespace
-- @param p_name Schedule name
-- @returns Schedule row, or empty if not found
CREATE OR REPLACE FUNCTION queue.get_schedule(
    p_namespace text,
    p_name text
)
RETURNS TABLE(
    id bigint,
    name text,
    queue text,
    payload jsonb,
    priority int,
    max_attempts int,
    tags text[],
    cron_expression text,
    cron_timezone text,
    every_interval interval,
    is_active boolean,
    last_run_at timestamptz,
    last_job_id bigint,
    next_run_at timestamptz,
    run_count bigint,
    last_error text,
    consecutive_failures int,
    created_at timestamptz,
    updated_at timestamptz
) AS $$
BEGIN
    PERFORM queue._validate_namespace(p_namespace);
    PERFORM queue._validate_schedule_name(p_name);
    PERFORM queue._warn_namespace_mismatch(p_namespace);

    RETURN QUERY
    SELECT s.id, s.name, s.queue, s.payload, s.priority, s.max_attempts, s.tags,
           s.cron_expression, s.cron_timezone, s.every_interval,
           s.is_active, s.last_run_at, s.last_job_id, s.next_run_at,
           s.run_count, s.last_error, s.consecutive_failures,
           s.created_at, s.updated_at
    FROM queue.schedules s
    WHERE s.namespace = p_namespace
      AND s.name = p_name;
END;
$$ LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = queue, pg_temp;


-- @function queue.list_schedules
-- @brief List schedules with optional filters and cursor pagination.
-- @param p_namespace Tenant namespace
-- @param p_queue Filter by target queue (NULL = all)
-- @param p_is_active Filter by active status (NULL = all)
-- @param p_limit Maximum results (clamped to 1000)
-- @param p_cursor Last schedule name from previous page
-- @returns Schedule rows ordered by name
CREATE OR REPLACE FUNCTION queue.list_schedules(
    p_namespace text,
    p_queue text DEFAULT NULL,
    p_is_active boolean DEFAULT NULL,
    p_limit int DEFAULT 100,
    p_cursor text DEFAULT NULL
)
RETURNS TABLE(
    name text,
    queue text,
    cron_expression text,
    every_interval interval,
    is_active boolean,
    next_run_at timestamptz,
    last_run_at timestamptz,
    run_count bigint,
    last_error text,
    consecutive_failures int,
    created_at timestamptz
) AS $$
BEGIN
    PERFORM queue._validate_namespace(p_namespace);
    PERFORM queue._warn_namespace_mismatch(p_namespace);

    IF p_limit > 1000 THEN
        p_limit := 1000;
    END IF;

    RETURN QUERY
    SELECT s.name, s.queue, s.cron_expression, s.every_interval,
           s.is_active, s.next_run_at, s.last_run_at, s.run_count,
           s.last_error, s.consecutive_failures, s.created_at
    FROM queue.schedules s
    WHERE s.namespace = p_namespace
      AND (p_queue IS NULL OR s.queue = p_queue)
      AND (p_is_active IS NULL OR s.is_active = p_is_active)
      AND (p_cursor IS NULL OR s.name > p_cursor)
    ORDER BY s.name
    LIMIT p_limit;
END;
$$ LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = queue, pg_temp;


-- @function queue.delete_schedule
-- @brief Delete a schedule by name.
-- @param p_namespace Tenant namespace
-- @param p_name Schedule name
-- @returns True if deleted, false if not found
CREATE OR REPLACE FUNCTION queue.delete_schedule(
    p_namespace text,
    p_name text
)
RETURNS boolean AS $$
DECLARE
    v_count int;
BEGIN
    PERFORM queue._validate_namespace(p_namespace);
    PERFORM queue._validate_schedule_name(p_name);
    PERFORM queue._warn_namespace_mismatch(p_namespace);

    DELETE FROM queue.schedules
    WHERE namespace = p_namespace
      AND name = p_name;

    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count > 0;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = queue, pg_temp;


-- @function queue.pause_schedule
-- @brief Pause an active schedule.
-- @param p_namespace Tenant namespace
-- @param p_name Schedule name
-- @returns True if paused, false if already paused or not found
CREATE OR REPLACE FUNCTION queue.pause_schedule(
    p_namespace text,
    p_name text
)
RETURNS boolean AS $$
DECLARE
    v_count int;
BEGIN
    PERFORM queue._validate_namespace(p_namespace);
    PERFORM queue._validate_schedule_name(p_name);
    PERFORM queue._warn_namespace_mismatch(p_namespace);

    UPDATE queue.schedules
    SET is_active = false,
        next_run_at = NULL,
        updated_at = now()
    WHERE namespace = p_namespace
      AND name = p_name
      AND is_active = true;

    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count > 0;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = queue, pg_temp;


-- @function queue.resume_schedule
-- @brief Resume a paused schedule. Recalculates next_run_at from now.
-- @param p_namespace Tenant namespace
-- @param p_name Schedule name
-- @returns True if resumed, false if already active or not found
CREATE OR REPLACE FUNCTION queue.resume_schedule(
    p_namespace text,
    p_name text
)
RETURNS boolean AS $$
DECLARE
    v_schedule queue.schedules;
    v_next timestamptz;
BEGIN
    PERFORM queue._validate_namespace(p_namespace);
    PERFORM queue._validate_schedule_name(p_name);
    PERFORM queue._warn_namespace_mismatch(p_namespace);

    SELECT * INTO v_schedule
    FROM queue.schedules
    WHERE namespace = p_namespace
      AND name = p_name
      AND is_active = false
    FOR UPDATE;

    IF NOT FOUND THEN
        RETURN false;
    END IF;

    PERFORM queue._validate_schedule_interval(v_schedule.every_interval);

    -- Recalculate next_run_at from now
    IF v_schedule.cron_expression IS NOT NULL THEN
        v_next := queue._cron_next_run(v_schedule.cron_expression, v_schedule.cron_timezone, now());
    ELSE
        v_next := now() + v_schedule.every_interval;
    END IF;

    UPDATE queue.schedules
    SET is_active = true,
        next_run_at = v_next,
        updated_at = now()
    WHERE id = v_schedule.id;

    RETURN true;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = queue, pg_temp;
