-- =============================================================================
-- INTERNAL HELPER FUNCTIONS FOR POSTKIT/QUEUE
-- =============================================================================
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
-- @param p_namespace Namespace for config lookup
-- @param p_queue Queue name for channel
-- @param p_payload Notification payload (JSON)
-- Channel name: queue_{queue_name}
CREATE OR REPLACE FUNCTION queue._notify_if_enabled(
    p_namespace text,
    p_queue text,
    p_payload jsonb
)
RETURNS void AS $$
DECLARE
    v_config queue.config;
BEGIN
    v_config := queue._get_config(p_namespace);

    IF v_config.notify_on_push THEN
        PERFORM pg_notify('queue_' || p_queue, p_payload::text);
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
