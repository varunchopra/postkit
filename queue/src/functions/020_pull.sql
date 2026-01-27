-- =============================================================================
-- PULL FUNCTIONS FOR POSTKIT/QUEUE
-- =============================================================================
-- @group Pull

-- @function queue.pull
-- @brief Pull one job from a queue.
-- @param p_namespace Tenant namespace
-- @param p_queue Queue name
-- @param p_worker_id Worker identifier (for debugging stuck jobs)
-- @param p_visibility_timeout How long before job returns to queue if not ack'd
-- @returns Job record, or NULL if queue is empty
--
-- Uses SELECT FOR UPDATE SKIP LOCKED for efficient concurrent access.
-- Job status changes to 'running' and becomes invisible until ack/nack/timeout.
CREATE OR REPLACE FUNCTION queue.pull(
    p_namespace text,
    p_queue text,
    p_worker_id text DEFAULT NULL,
    p_visibility_timeout interval DEFAULT NULL
)
RETURNS SETOF queue.jobs AS $$
DECLARE
    v_config queue.config;
    v_timeout interval;
BEGIN
    -- Validate inputs
    PERFORM queue._validate_namespace(p_namespace);
    PERFORM queue._validate_queue_name(p_queue);

    -- Warn if namespace mismatch with RLS context
    PERFORM queue._warn_namespace_mismatch(p_namespace);

    -- Get config for defaults
    v_config := queue._get_config(p_namespace);
    v_timeout := COALESCE(p_visibility_timeout, v_config.default_visibility_timeout);

    -- Pull one job with SKIP LOCKED
    RETURN QUERY
    WITH next_job AS (
        SELECT j.id
        FROM queue.jobs j
        WHERE j.namespace = p_namespace
          AND j.queue = p_queue
          AND j.status = 'pending'
          AND j.scheduled_at <= now()
        ORDER BY j.priority DESC, j.scheduled_at, j.id
        LIMIT 1
        FOR UPDATE SKIP LOCKED
    )
    UPDATE queue.jobs j
    SET
        status = 'running',
        attempts = j.attempts + 1,
        locked_by = COALESCE(p_worker_id, 'anonymous'),
        locked_at = now(),
        visibility_timeout_at = now() + v_timeout,
        updated_at = now()
    FROM next_job
    WHERE j.id = next_job.id
    RETURNING j.*;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = queue, pg_temp;


-- @function queue.pull_batch
-- @brief Pull multiple jobs from a queue.
-- @param p_namespace Tenant namespace
-- @param p_queue Queue name
-- @param p_limit Maximum jobs to pull
-- @param p_worker_id Worker identifier (for debugging stuck jobs)
-- @param p_visibility_timeout How long before jobs return to queue if not ack'd
-- @returns Set of job records
--
-- More efficient than multiple pull() calls for batch processing.
CREATE OR REPLACE FUNCTION queue.pull_batch(
    p_namespace text,
    p_queue text,
    p_limit int DEFAULT 10,
    p_worker_id text DEFAULT NULL,
    p_visibility_timeout interval DEFAULT NULL
)
RETURNS SETOF queue.jobs AS $$
DECLARE
    v_config queue.config;
    v_timeout interval;
BEGIN
    -- Validate inputs
    PERFORM queue._validate_namespace(p_namespace);
    PERFORM queue._validate_queue_name(p_queue);
    PERFORM queue._validate_positive_int(p_limit, 'limit');

    -- Warn if namespace mismatch with RLS context
    PERFORM queue._warn_namespace_mismatch(p_namespace);

    -- Get config for defaults
    v_config := queue._get_config(p_namespace);
    v_timeout := COALESCE(p_visibility_timeout, v_config.default_visibility_timeout);

    -- Pull multiple jobs with SKIP LOCKED
    RETURN QUERY
    WITH next_jobs AS (
        SELECT j.id
        FROM queue.jobs j
        WHERE j.namespace = p_namespace
          AND j.queue = p_queue
          AND j.status = 'pending'
          AND j.scheduled_at <= now()
        ORDER BY j.priority DESC, j.scheduled_at, j.id
        LIMIT p_limit
        FOR UPDATE SKIP LOCKED
    )
    UPDATE queue.jobs j
    SET
        status = 'running',
        attempts = j.attempts + 1,
        locked_by = COALESCE(p_worker_id, 'anonymous'),
        locked_at = now(),
        visibility_timeout_at = now() + v_timeout,
        updated_at = now()
    FROM next_jobs
    WHERE j.id = next_jobs.id
    RETURNING j.*;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = queue, pg_temp;


-- @function queue.pull_any
-- @brief Pull one job from multiple queues (priority order).
-- @param p_namespace Tenant namespace
-- @param p_queues Queue names in priority order (first queue checked first)
-- @param p_worker_id Worker identifier
-- @param p_visibility_timeout How long before job returns to queue
-- @returns Job record from first queue with available job, or NULL
--
-- Useful for workers that handle multiple queues with different priorities.
-- Example: pull_any(ns, ARRAY['critical', 'default', 'bulk'])
CREATE OR REPLACE FUNCTION queue.pull_any(
    p_namespace text,
    p_queues text[],
    p_worker_id text DEFAULT NULL,
    p_visibility_timeout interval DEFAULT NULL
)
RETURNS SETOF queue.jobs AS $$
DECLARE
    v_queue text;
    v_found boolean := false;
BEGIN
    -- Validate inputs
    PERFORM queue._validate_namespace(p_namespace);

    IF p_queues IS NULL OR array_length(p_queues, 1) IS NULL THEN
        RETURN;
    END IF;

    -- Validate each queue name
    FOREACH v_queue IN ARRAY p_queues LOOP
        PERFORM queue._validate_queue_name(v_queue);
    END LOOP;

    -- Try each queue in order
    FOREACH v_queue IN ARRAY p_queues LOOP
        RETURN QUERY SELECT * FROM queue.pull(
            p_namespace,
            v_queue,
            p_worker_id,
            p_visibility_timeout
        );

        -- Check if we got a job
        GET DIAGNOSTICS v_found = ROW_COUNT;
        IF v_found THEN
            RETURN;
        END IF;
    END LOOP;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = queue, pg_temp;


-- @function queue.extend_visibility
-- @brief Extend the visibility timeout of a running job.
-- @param p_namespace Tenant namespace
-- @param p_job_id Job ID
-- @param p_extension How much time to add
-- @returns True if extended, false if job not found or not running
--
-- Use when processing takes longer than expected.
CREATE OR REPLACE FUNCTION queue.extend_visibility(
    p_namespace text,
    p_job_id bigint,
    p_extension interval
)
RETURNS boolean AS $$
DECLARE
    v_updated int;
BEGIN
    -- Validate inputs
    PERFORM queue._validate_namespace(p_namespace);

    IF p_job_id IS NULL THEN
        RAISE EXCEPTION 'Job ID cannot be null'
            USING ERRCODE = 'null_value_not_allowed',
                  HINT = 'postkit:queue:VAL_JOB_ID_NULL';
    END IF;

    -- Warn if namespace mismatch with RLS context
    PERFORM queue._warn_namespace_mismatch(p_namespace);

    -- Extend visibility timeout
    UPDATE queue.jobs
    SET
        visibility_timeout_at = visibility_timeout_at + p_extension,
        updated_at = now()
    WHERE namespace = p_namespace
      AND id = p_job_id
      AND status = 'running';

    GET DIAGNOSTICS v_updated = ROW_COUNT;
    RETURN v_updated > 0;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = queue, pg_temp;
