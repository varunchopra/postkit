-- @group Completion

-- @function queue.ack
-- @brief Acknowledge successful job completion.
-- @param p_namespace Tenant namespace
-- @param p_job_id Job ID
-- @param p_worker_id Optional worker identity; refuses jobs running under another worker
-- @returns True if acknowledged, false if job not found, not running, or owned by another worker
--
-- Job is either deleted or marked completed (based on archive_completed config).
--
-- After a visibility-timeout redelivery the job can be re-pulled by another
-- worker. Pass p_worker_id so a late ack from the timed-out worker does not
-- settle the successor's attempt; with NULL the caller is trusted and settles
-- whoever holds it. A wrong-owner ack returns false rather than raising,
-- consistent with ack's existing not-running return.
CREATE OR REPLACE FUNCTION queue.ack(
    p_namespace text,
    p_job_id bigint,
    p_worker_id text DEFAULT NULL
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
          AND status = 'running'
          AND (p_worker_id IS NULL OR locked_by IS NOT DISTINCT FROM p_worker_id);
    ELSE
        -- Delete the job
        DELETE FROM queue.jobs
        WHERE namespace = p_namespace
          AND id = p_job_id
          AND status = 'running'
          AND (p_worker_id IS NULL OR locked_by IS NOT DISTINCT FROM p_worker_id);
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
-- @param p_worker_id Optional worker identity; refuses jobs running under another worker
-- @returns True if returned to queue, false if max attempts exceeded (moved to DLQ)
--
-- If max_attempts is exceeded, automatically moves to dead letter queue.
--
-- A pending job is a valid target: a consumer that rolled back its
-- transaction lost the claim, but its intent to retry stands. The backoff
-- comes from the committed attempt count, so an attempt whose pull rolled
-- back is granted back. A pending job carries no lock fields, so a nack of
-- a job that was never pulled is indistinguishable from rollback recovery
-- and reschedules quietly. Completed and dead jobs are settled and raise.
--
-- Between a rollback and the recovery call, another worker may re-pull the
-- job, and that attempt owns its fate. Pass p_worker_id to refuse such
-- jobs (BIZ_JOB_NOT_YOURS); with NULL the caller is trusted and may
-- release another worker's claim.
CREATE OR REPLACE FUNCTION queue.nack(
    p_namespace text,
    p_job_id bigint,
    p_error text DEFAULT NULL,
    p_backoff interval DEFAULT NULL,
    p_worker_id text DEFAULT NULL
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
      AND status IN ('pending', 'running')
    FOR UPDATE;

    IF NOT FOUND THEN
        -- Job settled or missing - check if it exists at all
        IF EXISTS (SELECT 1 FROM queue.jobs WHERE namespace = p_namespace AND id = p_job_id) THEN
            RAISE EXCEPTION 'Job % is already settled', p_job_id
                USING ERRCODE = 'invalid_parameter_value',
                      HINT = 'postkit:queue:BIZ_JOB_NOT_RUNNING';
        ELSE
            RAISE EXCEPTION 'Job % not found', p_job_id
                USING ERRCODE = 'no_data_found',
                      HINT = 'postkit:queue:DATA_JOB_NOT_FOUND';
        END IF;
    END IF;

    IF p_worker_id IS NOT NULL AND v_job.status = 'running'
       AND v_job.locked_by IS DISTINCT FROM p_worker_id THEN
        RAISE EXCEPTION 'Job % is running under worker %, not %',
            p_job_id, v_job.locked_by, p_worker_id
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:queue:BIZ_JOB_NOT_YOURS';
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

    -- Return job to pending with backoff. The status predicate is defense
    -- in depth: the FOR UPDATE above re-checks status after any lock wait,
    -- so a job settled by a concurrent call never reaches this UPDATE.
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
      AND status IN ('pending', 'running');

    RETURN true;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = queue, pg_temp;


-- @function queue.fail
-- @brief Move job to dead letter queue (permanent failure).
-- @param p_namespace Tenant namespace
-- @param p_job_id Job ID
-- @param p_error Error message
-- @param p_worker_id Optional worker identity; refuses jobs running under another worker
-- @returns True if moved to DLQ, false if job settled, missing, or owned by another worker
--
-- Use when a job cannot be retried (invalid data, business logic failure, etc).
--
-- A pending job is a valid target: a consumer that rolled back its
-- transaction can still dead-letter a poison job. Pass p_worker_id to
-- refuse jobs another worker has since re-pulled; refusal returns false,
-- matching fail's silent cleanup character.
CREATE OR REPLACE FUNCTION queue.fail(
    p_namespace text,
    p_job_id bigint,
    p_error text DEFAULT NULL,
    p_worker_id text DEFAULT NULL
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
      AND status IN ('pending', 'running')
    FOR UPDATE;

    IF NOT FOUND THEN
        -- Intentionally silent. nack() raises because a retry on a settled
        -- job is a caller bug, but fail() is a cleanup call where the caller
        -- does not care why the job was not there to fail.
        RETURN false;
    END IF;

    IF p_worker_id IS NOT NULL AND v_job.status = 'running'
       AND v_job.locked_by IS DISTINCT FROM p_worker_id THEN
        RETURN false;
    END IF;

    PERFORM queue._move_to_dead_letter(v_job, p_error);
    RETURN true;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = queue, pg_temp;


-- @function queue.cancel
-- @brief Cancel a pending job by deleting it.
-- @param p_namespace Tenant namespace
-- @param p_job_id Job ID
-- @returns True if cancelled, false if job not found or not pending
--
-- Only pending jobs can be cancelled. Running jobs must be ack'd, nack'd,
-- or failed. Cancelled jobs are deleted (not archived) because they were
-- never processed - there is no completion state to retain.
CREATE OR REPLACE FUNCTION queue.cancel(
    p_namespace text,
    p_job_id bigint
)
RETURNS boolean AS $$
DECLARE
    v_deleted int;
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

    DELETE FROM queue.jobs
    WHERE namespace = p_namespace
      AND id = p_job_id
      AND status = 'pending';

    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    RETURN v_deleted > 0;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = queue, pg_temp;


-- @function queue.release_jobs
-- @brief Release all jobs held by a worker, returning them to pending.
-- @param p_namespace Tenant namespace
-- @param p_worker_id Worker identifier (as passed to pull)
-- @returns Count of jobs released
--
-- Call during graceful shutdown so jobs are immediately re-deliverable
-- instead of waiting for visibility timeout expiry. Clears lock fields
-- per jobs_locked_consistency; preserves attempt count (consistent with
-- tick_timeouts behavior).
CREATE OR REPLACE FUNCTION queue.release_jobs(
    p_namespace text,
    p_worker_id text
)
RETURNS int AS $$
DECLARE
    v_count int;
BEGIN
    -- Validate inputs
    PERFORM queue._validate_namespace(p_namespace);

    IF p_worker_id IS NULL THEN
        RAISE EXCEPTION 'Worker ID cannot be null'
            USING ERRCODE = 'null_value_not_allowed',
                  HINT = 'postkit:queue:VAL_WORKER_ID_NULL';
    END IF;

    -- Warn if namespace mismatch with RLS context
    PERFORM queue._warn_namespace_mismatch(p_namespace);

    UPDATE queue.jobs
    SET
        status = 'pending',
        locked_by = NULL,
        locked_at = NULL,
        visibility_timeout_at = NULL,
        updated_at = now()
    WHERE namespace = p_namespace
      AND locked_by = p_worker_id
      AND status = 'running';

    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = queue, pg_temp;


-- @function queue.purge_queue
-- @brief Delete all pending jobs from a queue.
-- @param p_namespace Tenant namespace
-- @param p_queue Queue name
-- @returns Count of deleted jobs
--
-- Only deletes pending jobs. Running jobs are held by workers - use
-- release_jobs to return them first, or wait for visibility timeout.
-- Completed and dead jobs are historical and not affected.
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
