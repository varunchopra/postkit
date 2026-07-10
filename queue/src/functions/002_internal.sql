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
    v_delay interval;
    v_multiplier numeric;
BEGIN
    -- 2^(attempt-1): 1, 2, 4, 8, 16, ...
    v_multiplier := power(2, GREATEST(p_attempt - 1, 0));

    -- Calculate delay
    v_delay := p_base_delay * v_multiplier;

    -- Cap at max delay
    IF v_delay > p_max_delay THEN
        v_delay := p_max_delay;
    END IF;

    RETURN v_delay;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path = queue, pg_temp;


-- @function queue._move_to_dead_letter
-- @brief Move an already-locked job to the dead letter queue.
-- @param p_job The job record (caller must hold FOR UPDATE lock)
-- @param p_error Error message for the dead letter entry
-- Called by nack (when max attempts exceeded) and fail. Caller is
-- responsible for locking the row; this function does no SELECT.
CREATE OR REPLACE FUNCTION queue._move_to_dead_letter(
    p_job queue.jobs,
    p_error text
)
RETURNS void AS $$
BEGIN
    -- Insert into dead letters
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
        p_job.actor_id,
        p_job.request_id,
        p_job.on_behalf_of,
        p_job.reason
    );

    -- Mark job as dead
    UPDATE queue.jobs
    SET
        status = 'dead',
        error = COALESCE(p_error, p_job.error),
        locked_by = NULL,
        locked_at = NULL,
        visibility_timeout_at = NULL,
        completed_at = now(),
        updated_at = now()
    WHERE id = p_job.id
      AND namespace = p_job.namespace
      AND status IN ('pending', 'running');
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = queue, pg_temp;
