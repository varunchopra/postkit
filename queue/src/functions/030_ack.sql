-- @group Completion

-- @function queue.ack
-- @brief Acknowledge successful job completion.
-- @param p_namespace Tenant namespace
-- @param p_job_id Job ID
-- @returns True if acknowledged, false if job not found or not running
--
-- Job is either deleted or marked completed (based on archive_completed config).
CREATE OR REPLACE FUNCTION queue.ack(
    p_namespace text,
    p_job_id bigint
)
RETURNS boolean AS $$
DECLARE
    v_config queue.config;
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

    -- Get config for archive setting
    v_config := queue._get_config(p_namespace);

    IF v_config.archive_completed THEN
        -- Mark as completed (keep for history)
        UPDATE queue.jobs
        SET
            status = 'completed',
            locked_by = NULL,
            locked_at = NULL,
            visibility_timeout_at = NULL,
            completed_at = now(),
            updated_at = now()
        WHERE namespace = p_namespace
          AND id = p_job_id
          AND status = 'running';
    ELSE
        -- Delete the job
        DELETE FROM queue.jobs
        WHERE namespace = p_namespace
          AND id = p_job_id
          AND status = 'running';
    END IF;

    GET DIAGNOSTICS v_updated = ROW_COUNT;
    RETURN v_updated > 0;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = queue, pg_temp;


-- @function queue.ack_batch
-- @brief Acknowledge multiple jobs as completed.
-- @param p_namespace Tenant namespace
-- @param p_job_ids Array of job IDs
-- @returns Count of jobs acknowledged
CREATE OR REPLACE FUNCTION queue.ack_batch(
    p_namespace text,
    p_job_ids bigint[]
)
RETURNS int AS $$
DECLARE
    v_config queue.config;
    v_count int;
BEGIN
    -- Validate inputs
    PERFORM queue._validate_namespace(p_namespace);

    IF p_job_ids IS NULL OR array_length(p_job_ids, 1) IS NULL THEN
        RETURN 0;
    END IF;

    -- Warn if namespace mismatch with RLS context
    PERFORM queue._warn_namespace_mismatch(p_namespace);

    -- Get config for archive setting
    v_config := queue._get_config(p_namespace);

    IF v_config.archive_completed THEN
        -- Mark as completed (keep for history)
        UPDATE queue.jobs
        SET
            status = 'completed',
            locked_by = NULL,
            locked_at = NULL,
            visibility_timeout_at = NULL,
            completed_at = now(),
            updated_at = now()
        WHERE namespace = p_namespace
          AND id = ANY(p_job_ids)
          AND status = 'running';
    ELSE
        -- Delete the jobs
        DELETE FROM queue.jobs
        WHERE namespace = p_namespace
          AND id = ANY(p_job_ids)
          AND status = 'running';
    END IF;

    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = queue, pg_temp;


-- @function queue.nack
-- @brief Return job to queue for retry (temporary failure).
-- @param p_namespace Tenant namespace
-- @param p_job_id Job ID
-- @param p_error Error message (stored for debugging)
-- @param p_backoff Optional custom backoff delay (default: exponential)
-- @returns True if returned to queue, false if max attempts exceeded (moved to DLQ)
--
-- If max_attempts is exceeded, automatically moves to dead letter queue.
CREATE OR REPLACE FUNCTION queue.nack(
    p_namespace text,
    p_job_id bigint,
    p_error text DEFAULT NULL,
    p_backoff interval DEFAULT NULL
)
RETURNS boolean AS $$
DECLARE
    v_job queue.jobs;
    v_delay interval;
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

    -- Lock the row to prevent concurrent ack/nack/fail from racing.
    SELECT * INTO v_job
    FROM queue.jobs
    WHERE namespace = p_namespace
      AND id = p_job_id
      AND status = 'running'
    FOR UPDATE;

    IF NOT FOUND THEN
        -- Job not found or not running - check if it exists at all
        IF EXISTS (SELECT 1 FROM queue.jobs WHERE namespace = p_namespace AND id = p_job_id) THEN
            RAISE EXCEPTION 'Job % is not in running status', p_job_id
                USING ERRCODE = 'invalid_parameter_value',
                      HINT = 'postkit:queue:BIZ_JOB_NOT_RUNNING';
        ELSE
            RAISE EXCEPTION 'Job % not found', p_job_id
                USING ERRCODE = 'no_data_found',
                      HINT = 'postkit:queue:DATA_JOB_NOT_FOUND';
        END IF;
    END IF;

    -- Check if max attempts exceeded
    IF v_job.attempts >= v_job.max_attempts THEN
        -- Move to dead letter queue (row already locked, use internal helper)
        PERFORM queue._move_to_dead_letter(v_job, p_error);
        RETURN false;
    END IF;

    -- Calculate backoff
    IF p_backoff IS NOT NULL THEN
        v_delay := p_backoff;
    ELSE
        v_delay := queue._calculate_backoff(v_job.attempts);
    END IF;

    -- Return job to pending with backoff
    UPDATE queue.jobs
    SET
        status = 'pending',
        error = p_error,
        scheduled_at = now() + v_delay,
        locked_by = NULL,
        locked_at = NULL,
        visibility_timeout_at = NULL,
        updated_at = now()
    WHERE namespace = p_namespace
      AND id = p_job_id
      AND status = 'running';

    RETURN true;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = queue, pg_temp;


-- @function queue.fail
-- @brief Move job to dead letter queue (permanent failure).
-- @param p_namespace Tenant namespace
-- @param p_job_id Job ID
-- @param p_error Error message
-- @returns True if moved to DLQ, false if job not found
--
-- Use when a job cannot be retried (invalid data, business logic failure, etc).
CREATE OR REPLACE FUNCTION queue.fail(
    p_namespace text,
    p_job_id bigint,
    p_error text DEFAULT NULL
)
RETURNS boolean AS $$
DECLARE
    v_job queue.jobs;
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

    -- Lock the row to prevent concurrent fail/nack from racing.
    SELECT * INTO v_job
    FROM queue.jobs
    WHERE namespace = p_namespace
      AND id = p_job_id
      AND status = 'running'
    FOR UPDATE;

    IF NOT FOUND THEN
        -- Intentionally silent. nack() raises because a retry on a non-running
        -- job is a caller bug, but fail() is a cleanup call where the caller
        -- does not care why it was not running.
        RETURN false;
    END IF;

    PERFORM queue._move_to_dead_letter(v_job, p_error);
    RETURN true;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = queue, pg_temp;
