-- @group Internal

-- @function queue._get_config
-- @brief Get effective configuration for a namespace.
-- @param p_namespace Namespace to get config for
-- @returns Config record with fallback to global defaults
-- Checks tenant config first, falls back to global.
CREATE OR REPLACE FUNCTION queue._get_config(p_namespace text)
RETURNS queue.config AS $$
DECLARE
    v_config queue.config;
BEGIN
    -- Try tenant-specific config first
    SELECT * INTO v_config
    FROM queue.config
    WHERE namespace = p_namespace;

    IF FOUND THEN
        RETURN v_config;
    END IF;

    -- Fall back to global config
    SELECT * INTO v_config
    FROM queue.config
    WHERE namespace = 'global';

    -- If no global config (shouldn't happen), return defaults
    IF NOT FOUND THEN
        v_config.namespace := 'global';
        v_config.archive_completed := false;
        v_config.notify_on_push := true;
        v_config.default_visibility_timeout := '5 minutes'::interval;
        v_config.default_max_attempts := 3;
    END IF;

    RETURN v_config;
END;
$$ LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = queue, pg_temp;


-- @function queue._notify_if_enabled
-- @brief Send NOTIFY if configured.
-- @param p_config Config record (caller already fetched it)
-- @param p_namespace Tenant namespace for channel name
-- @param p_queue Queue name for channel
-- @param p_payload Notification payload (JSON)
-- Channel derivation lives in queue.channel_name, the public LISTEN contract.
CREATE OR REPLACE FUNCTION queue._notify_if_enabled(
    p_config queue.config,
    p_namespace text,
    p_queue text,
    p_payload jsonb
)
RETURNS void AS $$
BEGIN
    IF p_config.notify_on_push THEN
        PERFORM pg_notify(queue.channel_name(p_namespace, p_queue), p_payload::text);
    END IF;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = queue, pg_temp;


-- @function queue._calculate_backoff
-- @brief Calculate exponential backoff delay.
-- @param p_attempt Current attempt number (1-based)
-- @param p_base_delay Base delay for first retry (default 30 seconds)
-- @param p_max_delay Maximum delay cap (default 1 hour)
-- @returns Backoff interval
-- Formula: base_delay * 2^(attempt-1), capped at max_delay
CREATE OR REPLACE FUNCTION queue._calculate_backoff(
    p_attempt int,
    p_base_delay interval DEFAULT '30 seconds',
    p_max_delay interval DEFAULT '1 hour'
)
RETURNS interval AS $$
DECLARE
    v_exponent int;
    v_delay interval;
BEGIN
    v_exponent := GREATEST(p_attempt - 1, 0);

    -- Saturate in numeric seconds before multiplying: interval arithmetic
    -- overflows at high attempts long before the cap below could apply.
    IF extract(epoch FROM p_base_delay) > 0
        AND (v_exponent >= 64
            OR extract(epoch FROM p_base_delay) * power(2::numeric, v_exponent)
                >= extract(epoch FROM p_max_delay)) THEN
        RETURN p_max_delay;
    END IF;

    v_delay := p_base_delay * power(2, v_exponent);

    IF v_delay > p_max_delay THEN
        v_delay := p_max_delay;
    END IF;

    RETURN v_delay;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = queue, pg_temp;


-- @function queue._lock_current_attempt
-- @brief Lock and return the running attempt identified by a fence token.
-- @param p_namespace Tenant namespace
-- @param p_job_id Job ID
-- @param p_fence Fence token returned by pull
-- @returns The locked job and the wall-clock time at which it was checked
-- Fence and timeout checks happen after the row lock is acquired. A caller
-- that waited for the lock therefore cannot act on a fence that expired while
-- it was waiting.
CREATE OR REPLACE FUNCTION queue._lock_current_attempt(
    p_namespace text,
    p_job_id bigint,
    p_fence bigint
)
RETURNS TABLE(job queue.jobs, checked_at timestamptz) AS $$
DECLARE
    v_job queue.jobs;
    v_found boolean;
    v_checked_at timestamptz;
BEGIN
    SELECT j.* INTO v_job
    FROM queue.jobs j
    WHERE j.namespace = p_namespace
      AND j.id = p_job_id
    FOR UPDATE;

    v_found := FOUND;
    v_checked_at := clock_timestamp();

    IF NOT v_found
       OR v_job.status != 'running'
       OR v_job.fence_token IS DISTINCT FROM p_fence
       OR v_job.visibility_timeout_at IS NULL
       OR v_job.visibility_timeout_at <= v_checked_at THEN
        RAISE EXCEPTION 'Queue job fence is no longer valid'
            USING ERRCODE = '40001',
                  HINT = 'postkit:queue:FENCE_STALE';
    END IF;

    job := v_job;
    checked_at := v_checked_at;
    RETURN NEXT;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = queue, pg_temp;


-- @function queue._move_to_dead_letter
-- @brief Move an already-locked job to the dead-letter queue.
-- @param p_job The job record (caller must hold FOR UPDATE lock)
-- @param p_error Error message for the dead letter entry
-- @param p_checked_at Time at which the job's fence was checked
-- Called by nack after the final attempt and by fail. The caller must have
-- locked and fence-checked p_job; this function does not select the row again.
CREATE OR REPLACE FUNCTION queue._move_to_dead_letter(
    p_job queue.jobs,
    p_error text,
    p_checked_at timestamptz
)
RETURNS void AS $$
BEGIN
    INSERT INTO queue.dead_letters (
        namespace,
        queue,
        original_job_id,
        payload,
        priority,
        tags,
        metadata,
        attempts,
        max_attempts,
        last_error,
        failed_at,
        actor_id,
        request_id,
        on_behalf_of,
        reason
    )
    VALUES (
        p_job.namespace,
        p_job.queue,
        p_job.id,
        p_job.payload,
        p_job.priority,
        p_job.tags,
        p_job.metadata,
        p_job.attempts,
        p_job.max_attempts,
        COALESCE(p_error, p_job.error),
        p_checked_at,
        p_job.actor_id,
        p_job.request_id,
        p_job.on_behalf_of,
        p_job.reason
    );

    UPDATE queue.jobs
    SET
        status = 'dead',
        error = COALESCE(p_error, p_job.error),
        locked_by = NULL,
        locked_at = NULL,
        visibility_timeout_at = NULL,
        fence_token = NULL,
        completed_at = p_checked_at,
        updated_at = p_checked_at
    WHERE id = p_job.id
      AND namespace = p_job.namespace
      AND status = 'running'
      AND fence_token = p_job.fence_token;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = queue, pg_temp;
