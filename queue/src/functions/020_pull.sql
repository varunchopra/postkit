-- @group Pull

-- @function queue.pull
-- @brief Pull one available job and return its fence token.
-- @param p_namespace Tenant namespace
-- @param p_queue Queue name
-- @param p_worker_id Optional diagnostic worker identifier
-- @param p_visibility_timeout How long before tick_timeouts may reclaim the job
-- @returns Job record including fence_token, or no row if the queue is empty
--
-- Uses FOR UPDATE SKIP LOCKED so concurrent workers pull different jobs.
-- The job becomes running and cannot be pulled again until ack, nack, fail,
-- release, or tick_timeouts changes its state. The returned fence_token
-- identifies this pull and is required by extend_visibility and every
-- operation that changes the running job.
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
    v_job_id bigint;
    v_job queue.jobs;
    v_pulled_at timestamptz;
BEGIN
    PERFORM queue._validate_namespace(p_namespace);
    PERFORM queue._validate_queue_name(p_queue);
    PERFORM queue._warn_namespace_mismatch(p_namespace);

    v_config := queue._get_config(p_namespace);
    v_timeout := COALESCE(p_visibility_timeout, v_config.default_visibility_timeout);
    PERFORM queue._validate_schedule_interval(v_timeout);

    SELECT j.id INTO v_job_id
    FROM queue.jobs j
    WHERE j.namespace = p_namespace
      AND j.queue = p_queue
      AND j.status = 'pending'
      AND j.scheduled_at <= clock_timestamp()
    ORDER BY j.priority DESC, j.scheduled_at, j.id
    LIMIT 1
    FOR UPDATE SKIP LOCKED;

    IF NOT FOUND THEN
        RETURN;
    END IF;

    v_pulled_at := clock_timestamp();

    UPDATE queue.jobs j
    SET
        status = 'running',
        attempts = j.attempts + 1,
        locked_by = COALESCE(p_worker_id, 'anonymous'),
        locked_at = v_pulled_at,
        visibility_timeout_at = v_pulled_at + v_timeout,
        updated_at = v_pulled_at,
        fence_token = nextval('queue.fence_token_seq'::regclass)
    WHERE j.namespace = p_namespace
      AND j.id = v_job_id
    RETURNING j.* INTO v_job;

    RETURN NEXT v_job;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = queue, pg_temp;


-- @function queue.pull_batch
-- @brief Pull up to a limit of available jobs in one operation.
-- @param p_namespace Tenant namespace
-- @param p_queue Queue name
-- @param p_limit Maximum jobs to pull
-- @param p_worker_id Optional diagnostic worker identifier
-- @param p_visibility_timeout How long before tick_timeouts may reclaim the jobs
-- @returns Job records including fence_token
--
-- Selects and updates the jobs as a set, which is more efficient than repeated
-- pull() calls. All selected rows are locked before one wall-clock timestamp
-- is captured, and every returned job has its own fence_token.
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
    v_job_ids bigint[];
    v_pulled_at timestamptz;
BEGIN
    PERFORM queue._validate_namespace(p_namespace);
    PERFORM queue._validate_queue_name(p_queue);
    PERFORM queue._validate_limit(p_limit, 'limit', 1000);
    PERFORM queue._warn_namespace_mismatch(p_namespace);

    v_config := queue._get_config(p_namespace);
    v_timeout := COALESCE(p_visibility_timeout, v_config.default_visibility_timeout);
    PERFORM queue._validate_schedule_interval(v_timeout);

    SELECT array_agg(candidate.id ORDER BY candidate.priority DESC, candidate.scheduled_at, candidate.id)
    INTO v_job_ids
    FROM (
        SELECT j.id, j.priority, j.scheduled_at
        FROM queue.jobs j
        WHERE j.namespace = p_namespace
          AND j.queue = p_queue
          AND j.status = 'pending'
          AND j.scheduled_at <= clock_timestamp()
        ORDER BY j.priority DESC, j.scheduled_at, j.id
        LIMIT p_limit
        FOR UPDATE OF j SKIP LOCKED
    ) AS candidate;

    IF v_job_ids IS NULL THEN
        RETURN;
    END IF;

    v_pulled_at := clock_timestamp();

    RETURN QUERY
    WITH pulled AS (
        UPDATE queue.jobs j
        SET
            status = 'running',
            attempts = j.attempts + 1,
            locked_by = COALESCE(p_worker_id, 'anonymous'),
            locked_at = v_pulled_at,
            visibility_timeout_at = v_pulled_at + v_timeout,
            updated_at = v_pulled_at,
            fence_token = nextval('queue.fence_token_seq'::regclass)
        WHERE j.namespace = p_namespace
          AND j.id = ANY(v_job_ids)
        RETURNING j.*
    )
    SELECT pulled.*
    FROM unnest(v_job_ids) WITH ORDINALITY AS selected(id, ordinal)
    JOIN pulled ON pulled.id = selected.id
    ORDER BY selected.ordinal;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = queue, pg_temp;


-- @function queue.pull_any
-- @brief Pull one job from the first queue with available work.
-- @param p_namespace Tenant namespace
-- @param p_queues Queue names in priority order (first queue checked first)
-- @param p_worker_id Optional diagnostic worker identifier
-- @param p_visibility_timeout How long before tick_timeouts may reclaim the job
-- @returns Job record including fence_token from the first available queue, or no row
--
-- Useful for workers that consume several queues with explicit priority.
-- Within the first queue that has work, normal job priority and schedule order
-- apply. Example: pull_any(ns, ARRAY['critical', 'default', 'bulk']).
CREATE OR REPLACE FUNCTION queue.pull_any(
    p_namespace text,
    p_queues text[],
    p_worker_id text DEFAULT NULL,
    p_visibility_timeout interval DEFAULT NULL
)
RETURNS SETOF queue.jobs AS $$
DECLARE
    v_queue text;
    v_config queue.config;
    v_timeout interval;
    v_job_id bigint;
    v_job queue.jobs;
    v_pulled_at timestamptz;
BEGIN
    PERFORM queue._validate_namespace(p_namespace);

    IF p_queues IS NULL OR array_length(p_queues, 1) IS NULL THEN
        RETURN;
    END IF;
    PERFORM queue._validate_batch_size(cardinality(p_queues), 'queues');

    FOREACH v_queue IN ARRAY p_queues LOOP
        PERFORM queue._validate_queue_name(v_queue);
    END LOOP;

    PERFORM queue._warn_namespace_mismatch(p_namespace);

    v_config := queue._get_config(p_namespace);
    v_timeout := COALESCE(p_visibility_timeout, v_config.default_visibility_timeout);
    PERFORM queue._validate_schedule_interval(v_timeout);

    -- Keep the pull predicates and state changes in sync with pull(); only
    -- queue selection and ordering differ here.
    SELECT j.id INTO v_job_id
    FROM queue.jobs j
    WHERE j.namespace = p_namespace
      AND j.queue = ANY(p_queues)
      AND j.status = 'pending'
      AND j.scheduled_at <= clock_timestamp()
    ORDER BY array_position(p_queues, j.queue), j.priority DESC, j.scheduled_at, j.id
    LIMIT 1
    FOR UPDATE SKIP LOCKED;

    IF NOT FOUND THEN
        RETURN;
    END IF;

    v_pulled_at := clock_timestamp();

    UPDATE queue.jobs j
    SET
        status = 'running',
        attempts = j.attempts + 1,
        locked_by = COALESCE(p_worker_id, 'anonymous'),
        locked_at = v_pulled_at,
        visibility_timeout_at = v_pulled_at + v_timeout,
        updated_at = v_pulled_at,
        fence_token = nextval('queue.fence_token_seq'::regclass)
    WHERE j.namespace = p_namespace
      AND j.id = v_job_id
    RETURNING j.* INTO v_job;

    RETURN NEXT v_job;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = queue, pg_temp;


-- @function queue.extend_visibility
-- @brief Extend the visibility timeout of a running job.
-- @param p_namespace Tenant namespace
-- @param p_job_id Job ID
-- @param p_fence Fence token returned by pull
-- @param p_extension Amount of time to add to the current deadline
-- @returns True when extended
--
-- Use this when processing will outlast the current visibility timeout. The
-- extension is added to the existing deadline, not to the current time.
-- If the job is missing or no longer running, the token belongs to another
-- pull, or the deadline has passed, the function raises FENCE_STALE.
CREATE OR REPLACE FUNCTION queue.extend_visibility(
    p_namespace text,
    p_job_id bigint,
    p_fence bigint,
    p_extension interval
)
RETURNS boolean AS $$
DECLARE
    v_checked_at timestamptz;
BEGIN
    PERFORM queue._validate_namespace(p_namespace);
    PERFORM queue._validate_job_id(p_job_id);
    PERFORM queue._validate_fence(p_fence);

    IF p_extension IS NULL OR p_extension <= interval '0 seconds' THEN
        RAISE EXCEPTION 'Extension must be a positive interval'
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:queue:VAL_EXTENSION_POSITIVE';
    END IF;

    PERFORM queue._warn_namespace_mismatch(p_namespace);
    SELECT c.checked_at INTO v_checked_at
    FROM queue._lock_current_attempt(p_namespace, p_job_id, p_fence) AS c;

    UPDATE queue.jobs
    SET visibility_timeout_at = visibility_timeout_at + p_extension,
        updated_at = v_checked_at
    WHERE namespace = p_namespace
      AND id = p_job_id
      AND status = 'running'
      AND fence_token = p_fence;

    RETURN true;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = queue, pg_temp;
