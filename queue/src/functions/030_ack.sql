-- @overview Operations on a running job require the current, unexpired
-- `fence_token` returned by `pull`. If the job is missing or no longer running,
-- or if the token has expired or been superseded, the function raises SQLSTATE
-- `40001` with HINT `postkit:queue:FENCE_STALE`. `ack_batch` validates the whole
-- batch before changing any job.
-- @group Completion

-- @function queue.ack
-- @brief Acknowledge successful job completion.
-- @param p_namespace Tenant namespace
-- @param p_job_id Job ID
-- @param p_fence Fence token returned by pull
-- @returns True when acknowledged
--
-- The job is marked completed when archive_completed is enabled and deleted
-- otherwise. Missing or non-running jobs and expired or superseded tokens raise
-- FENCE_STALE rather than settling a later pull of the same job.
CREATE OR REPLACE FUNCTION queue.ack(
    p_namespace text,
    p_job_id bigint,
    p_fence bigint
)
RETURNS boolean AS $$
DECLARE
    v_config queue.config;
    v_checked_at timestamptz;
    v_updated int;
BEGIN
    PERFORM queue._validate_namespace(p_namespace);
    PERFORM queue._validate_job_id(p_job_id);
    PERFORM queue._validate_fence(p_fence);
    PERFORM queue._warn_namespace_mismatch(p_namespace);

    SELECT c.checked_at INTO v_checked_at
    FROM queue._lock_current_attempt(p_namespace, p_job_id, p_fence) AS c;

    v_config := queue._get_config(p_namespace);

    IF v_config.archive_completed THEN
        UPDATE queue.jobs
        SET status = 'completed',
            locked_by = NULL,
            locked_at = NULL,
            visibility_timeout_at = NULL,
            completed_at = v_checked_at,
            updated_at = v_checked_at,
            fence_token = NULL
        WHERE namespace = p_namespace
          AND id = p_job_id
          AND status = 'running'
          AND fence_token = p_fence;
    ELSE
        DELETE FROM queue.jobs
        WHERE namespace = p_namespace
          AND id = p_job_id
          AND status = 'running'
          AND fence_token = p_fence;
    END IF;

    GET DIAGNOSTICS v_updated = ROW_COUNT;
    RETURN v_updated > 0;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = queue, pg_temp;


-- @function queue.ack_batch
-- @brief Acknowledge multiple jobs atomically.
-- @param p_namespace Tenant namespace
-- @param p_job_ids Job IDs; must not contain NULLs or duplicates
-- @param p_fences Fence tokens in the same order and number as p_job_ids; must not contain NULLs
-- @returns Number acknowledged; zero when both arrays are NULL or both are empty
--
-- Jobs are locked in ascending ID order to avoid deadlocks. After every lock
-- is held, one wall-clock timestamp validates the whole batch. If any job is
-- missing, no longer running, expired, or has the wrong fence, the call raises
-- FENCE_STALE and acknowledges none of them.
--
-- Two NULL arrays, or two empty arrays, return zero. Otherwise the arrays must
-- both be non-NULL, have equal lengths, contain no NULL elements, and name each
-- job ID at most once.
CREATE OR REPLACE FUNCTION queue.ack_batch(
    p_namespace text,
    p_job_ids bigint[],
    p_fences bigint[]
)
RETURNS int AS $$
DECLARE
    v_locked_job queue.jobs;
    v_locked_count int := 0;
    v_requested_count int;
    v_checked_at timestamptz;
    v_config queue.config;
    v_count int;
BEGIN
    PERFORM queue._validate_namespace(p_namespace);

    IF p_job_ids IS NULL AND p_fences IS NULL THEN
        RETURN 0;
    END IF;

    IF p_job_ids IS NULL OR p_fences IS NULL
       OR cardinality(p_job_ids) != cardinality(p_fences) THEN
        RAISE EXCEPTION 'Job IDs and fences must have equal lengths'
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:queue:VAL_ACK_BATCH_LENGTH';
    END IF;

    v_requested_count := cardinality(p_job_ids);
    PERFORM queue._validate_batch_size(v_requested_count, 'job_ids');

    IF v_requested_count = 0 THEN
        RETURN 0;
    END IF;

    IF EXISTS (SELECT 1 FROM unnest(p_job_ids) AS item(value) WHERE value IS NULL) THEN
        PERFORM queue._validate_job_id(NULL::bigint);
    END IF;

    IF EXISTS (SELECT 1 FROM unnest(p_fences) AS item(value) WHERE value IS NULL) THEN
        PERFORM queue._validate_fence(NULL::bigint);
    END IF;

    IF EXISTS (
        SELECT 1
        FROM unnest(p_job_ids) AS requested(job_id)
        GROUP BY requested.job_id
        HAVING count(*) > 1
    ) THEN
        RAISE EXCEPTION 'Job IDs cannot contain duplicates'
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:queue:VAL_ACK_BATCH_DUPLICATE_JOB';
    END IF;

    PERFORM queue._warn_namespace_mismatch(p_namespace);

    FOR v_locked_job IN
        SELECT j.*
        FROM queue.jobs j
        WHERE j.namespace = p_namespace
          AND j.id = ANY(p_job_ids)
        ORDER BY j.id
        FOR UPDATE
    LOOP
        v_locked_count := v_locked_count + 1;
    END LOOP;

    v_checked_at := clock_timestamp();

    IF v_locked_count != v_requested_count OR EXISTS (
        SELECT 1
        FROM unnest(p_job_ids, p_fences)
            AS requested(job_id, fence)
        JOIN queue.jobs j
          ON j.namespace = p_namespace
         AND j.id = requested.job_id
        WHERE j.status != 'running'
           OR j.fence_token IS DISTINCT FROM requested.fence
           OR j.visibility_timeout_at IS NULL
           OR j.visibility_timeout_at <= v_checked_at
    ) THEN
        RAISE EXCEPTION 'One or more queue job fences are no longer valid'
            USING ERRCODE = '40001',
                  HINT = 'postkit:queue:FENCE_STALE';
    END IF;

    v_config := queue._get_config(p_namespace);

    IF v_config.archive_completed THEN
        UPDATE queue.jobs
        SET status = 'completed',
            locked_by = NULL,
            locked_at = NULL,
            visibility_timeout_at = NULL,
            completed_at = v_checked_at,
            updated_at = v_checked_at,
            fence_token = NULL
        WHERE namespace = p_namespace
          AND id = ANY(p_job_ids);
    ELSE
        DELETE FROM queue.jobs
        WHERE namespace = p_namespace
          AND id = ANY(p_job_ids);
    END IF;

    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = queue, pg_temp;


-- @function queue.nack
-- @brief Schedule another attempt with backoff, or dead-letter the job when none remain.
-- @param p_namespace Tenant namespace
-- @param p_job_id Job ID
-- @param p_fence Fence token returned by pull
-- @param p_error Error message stored for debugging
-- @param p_backoff Optional custom delay; defaults to exponential backoff
-- @returns True when returned to pending, false when moved to the dead-letter queue
--
-- A custom p_backoff overrides the exponential delay calculated from the
-- attempt count. Once max_attempts is reached, the job moves to the
-- dead-letter queue instead and the function returns false. Only the current,
-- unexpired fence can schedule the job for another attempt.
CREATE OR REPLACE FUNCTION queue.nack(
    p_namespace text,
    p_job_id bigint,
    p_fence bigint,
    p_error text DEFAULT NULL,
    p_backoff interval DEFAULT NULL
)
RETURNS boolean AS $$
DECLARE
    v_locked record;
    v_job queue.jobs;
    v_checked_at timestamptz;
    v_delay interval;
BEGIN
    PERFORM queue._validate_namespace(p_namespace);
    PERFORM queue._validate_job_id(p_job_id);
    PERFORM queue._validate_fence(p_fence);
    PERFORM queue._warn_namespace_mismatch(p_namespace);

    SELECT c.job, c.checked_at INTO v_locked
    FROM queue._lock_current_attempt(p_namespace, p_job_id, p_fence) AS c;
    v_job := v_locked.job;
    v_checked_at := v_locked.checked_at;

    IF v_job.attempts >= v_job.max_attempts THEN
        PERFORM queue._move_to_dead_letter(v_job, p_error, v_checked_at);
        RETURN false;
    END IF;

    IF p_backoff IS NOT NULL THEN
        v_delay := p_backoff;
    ELSE
        v_delay := queue._calculate_backoff(v_job.attempts);
    END IF;

    UPDATE queue.jobs
    SET status = 'pending',
        error = p_error,
        scheduled_at = v_checked_at + v_delay,
        locked_by = NULL,
        locked_at = NULL,
        visibility_timeout_at = NULL,
        updated_at = v_checked_at,
        fence_token = NULL
    WHERE namespace = p_namespace
      AND id = p_job_id
      AND status = 'running'
      AND fence_token = p_fence;

    RETURN true;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = queue, pg_temp;


-- @function queue.fail
-- @brief Move a running job directly to the dead-letter queue.
-- @param p_namespace Tenant namespace
-- @param p_job_id Job ID
-- @param p_fence Fence token returned by pull
-- @param p_error Error message
-- @returns True when moved to the dead-letter queue
--
-- Use for errors that should not be retried, such as an invalid payload or a
-- permanent business-rule failure. Only the current, unexpired fence can fail
-- the job.
CREATE OR REPLACE FUNCTION queue.fail(
    p_namespace text,
    p_job_id bigint,
    p_fence bigint,
    p_error text DEFAULT NULL
)
RETURNS boolean AS $$
DECLARE
    v_locked record;
    v_job queue.jobs;
    v_checked_at timestamptz;
BEGIN
    PERFORM queue._validate_namespace(p_namespace);
    PERFORM queue._validate_job_id(p_job_id);
    PERFORM queue._validate_fence(p_fence);
    PERFORM queue._warn_namespace_mismatch(p_namespace);

    SELECT c.job, c.checked_at INTO v_locked
    FROM queue._lock_current_attempt(p_namespace, p_job_id, p_fence) AS c;
    v_job := v_locked.job;
    v_checked_at := v_locked.checked_at;

    PERFORM queue._move_to_dead_letter(v_job, p_error, v_checked_at);
    RETURN true;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = queue, pg_temp;


-- @function queue.release
-- @brief Return a running job to the queue immediately.
-- @param p_namespace Tenant namespace
-- @param p_job_id Job ID
-- @param p_fence Fence token returned by pull
-- @returns True when released
--
-- Release applies no retry backoff and preserves the attempt count. The job is
-- immediately available for another pull. During graceful shutdown, release
-- each in-flight job instead of waiting for timeout recovery.
CREATE OR REPLACE FUNCTION queue.release(
    p_namespace text,
    p_job_id bigint,
    p_fence bigint
)
RETURNS boolean AS $$
DECLARE
    v_checked_at timestamptz;
    v_updated int;
BEGIN
    PERFORM queue._validate_namespace(p_namespace);
    PERFORM queue._validate_job_id(p_job_id);
    PERFORM queue._validate_fence(p_fence);
    PERFORM queue._warn_namespace_mismatch(p_namespace);

    SELECT c.checked_at INTO v_checked_at
    FROM queue._lock_current_attempt(p_namespace, p_job_id, p_fence) AS c;

    UPDATE queue.jobs
    SET status = 'pending',
        locked_by = NULL,
        locked_at = NULL,
        visibility_timeout_at = NULL,
        updated_at = v_checked_at,
        fence_token = NULL
    WHERE namespace = p_namespace
      AND id = p_job_id
      AND status = 'running'
      AND fence_token = p_fence;

    GET DIAGNOSTICS v_updated = ROW_COUNT;
    RETURN v_updated > 0;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = queue, pg_temp;


-- @function queue.cancel
-- @brief Cancel a pending job by deleting it.
-- @param p_namespace Tenant namespace
-- @param p_job_id Job ID
-- @returns True if cancelled, false if the job was not pending
--
-- Only pending jobs can be cancelled. Running jobs must be acknowledged,
-- returned for retry, failed, or released with their fence. Cancelled jobs are
-- deleted rather than archived because they were never processed.
CREATE OR REPLACE FUNCTION queue.cancel(
    p_namespace text,
    p_job_id bigint
)
RETURNS boolean AS $$
DECLARE
    v_deleted int;
BEGIN
    PERFORM queue._validate_namespace(p_namespace);
    PERFORM queue._validate_job_id(p_job_id);
    PERFORM queue._warn_namespace_mismatch(p_namespace);

    DELETE FROM queue.jobs
    WHERE namespace = p_namespace
      AND id = p_job_id
      AND status = 'pending';

    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    RETURN v_deleted > 0;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = queue, pg_temp;


-- @function queue.purge_queue
-- @brief Delete all pending jobs from a queue.
-- @param p_namespace Tenant namespace
-- @param p_queue Queue name
-- @returns Count of deleted jobs
--
-- Running, completed, and dead jobs are not affected. Release running jobs
-- individually, or wait for timeout recovery, before purging if they should
-- also be removed.
CREATE OR REPLACE FUNCTION queue.purge_queue(
    p_namespace text,
    p_queue text
)
RETURNS int AS $$
DECLARE
    v_count int;
BEGIN
    PERFORM queue._validate_namespace(p_namespace);
    PERFORM queue._validate_queue_name(p_queue);
    PERFORM queue._warn_namespace_mismatch(p_namespace);

    DELETE FROM queue.jobs
    WHERE namespace = p_namespace
      AND queue = p_queue
      AND status = 'pending';

    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = queue, pg_temp;
