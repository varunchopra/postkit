-- @group Push

-- @function queue.push
-- @brief Push a job onto a queue.
-- @param p_namespace Tenant namespace
-- @param p_queue Queue name
-- @param p_payload Job payload (JSONB)
-- @param p_delay Optional delay before job becomes visible
-- @param p_priority Priority (-1000 to 1000, higher = more important)
-- @param p_max_attempts Maximum retry attempts
-- @param p_unique_key Deduplication key (NULL = no dedup)
-- @param p_tags Optional tags for filtering
-- @param p_metadata Optional metadata
-- @returns Job ID, or NULL if deduplicated
--
-- Jobs are immediately visible unless p_delay is specified.
-- With unique_key, returns NULL if a pending/running job with same key exists.
CREATE OR REPLACE FUNCTION queue.push(
    p_namespace text,
    p_queue text,
    p_payload jsonb,
    p_delay interval DEFAULT NULL,
    p_priority int DEFAULT 0,
    p_max_attempts int DEFAULT NULL,
    p_unique_key text DEFAULT NULL,
    p_tags text[] DEFAULT NULL,
    p_metadata jsonb DEFAULT NULL
)
RETURNS bigint AS $$
DECLARE
    v_job_id bigint;
    v_config queue.config;
    v_scheduled_at timestamptz;
    v_actor record;
BEGIN
    -- Validate inputs
    PERFORM queue._validate_namespace(p_namespace);
    PERFORM queue._validate_queue_name(p_queue);
    PERFORM queue._validate_priority(p_priority);

    IF p_payload IS NULL THEN
        RAISE EXCEPTION 'Payload cannot be null'
            USING ERRCODE = 'null_value_not_allowed',
                  HINT = 'postkit:queue:VAL_PAYLOAD_NULL';
    END IF;

    -- Warn if namespace mismatch with RLS context
    PERFORM queue._warn_namespace_mismatch(p_namespace);

    -- Get config for defaults
    v_config := queue._get_config(p_namespace);

    -- Calculate scheduled_at
    v_scheduled_at := now();
    IF p_delay IS NOT NULL THEN
        v_scheduled_at := v_scheduled_at + p_delay;
    END IF;

    -- Get actor context
    SELECT * INTO v_actor FROM queue._get_actor_context();

    -- Insert job (ON CONFLICT handles deduplication)
    INSERT INTO queue.jobs (
        namespace,
        queue,
        payload,
        priority,
        scheduled_at,
        max_attempts,
        unique_key,
        tags,
        metadata,
        actor_id,
        request_id,
        on_behalf_of,
        reason
    )
    VALUES (
        p_namespace,
        p_queue,
        p_payload,
        COALESCE(p_priority, 0),
        v_scheduled_at,
        COALESCE(p_max_attempts, v_config.default_max_attempts),
        p_unique_key,
        COALESCE(p_tags, '{}'),
        p_metadata,
        v_actor.actor_id,
        v_actor.request_id,
        v_actor.on_behalf_of,
        v_actor.reason
    )
    ON CONFLICT (namespace, queue, unique_key)
        WHERE unique_key IS NOT NULL AND status IN ('pending', 'running')
    DO NOTHING
    RETURNING id INTO v_job_id;

    -- Notify if job was inserted and notifications enabled
    IF v_job_id IS NOT NULL THEN
        PERFORM queue._notify_if_enabled(
            v_config,
            p_namespace,
            p_queue,
            jsonb_build_object('id', v_job_id, 'queue', p_queue)
        );
    END IF;

    RETURN v_job_id;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = queue, pg_temp;


-- @function queue.push_batch
-- @brief Push multiple jobs onto a queue efficiently.
-- @param p_namespace Tenant namespace
-- @param p_queue Queue name
-- @param p_payloads Array of job payloads
-- @param p_priority Priority for all jobs (default 0)
-- @param p_max_attempts Maximum retry attempts for all jobs
-- @param p_tags Tags for all jobs
-- @returns Array of job IDs
--
-- More efficient than multiple push() calls. Does not support unique_key.
CREATE OR REPLACE FUNCTION queue.push_batch(
    p_namespace text,
    p_queue text,
    p_payloads jsonb[],
    p_priority int DEFAULT 0,
    p_max_attempts int DEFAULT NULL,
    p_tags text[] DEFAULT NULL
)
RETURNS bigint[] AS $$
DECLARE
    v_job_ids bigint[];
    v_config queue.config;
    v_actor record;
    v_count int;
BEGIN
    -- Validate inputs
    PERFORM queue._validate_namespace(p_namespace);
    PERFORM queue._validate_queue_name(p_queue);
    PERFORM queue._validate_priority(p_priority);

    IF p_payloads IS NULL OR array_length(p_payloads, 1) IS NULL THEN
        RETURN ARRAY[]::bigint[];
    END IF;

    -- Reject NULL elements (each payload must be non-null jsonb)
    IF EXISTS (SELECT 1 FROM unnest(p_payloads) AS p WHERE p IS NULL) THEN
        RAISE EXCEPTION 'Payload cannot be null'
            USING ERRCODE = 'null_value_not_allowed',
                  HINT = 'postkit:queue:VAL_PAYLOAD_NULL';
    END IF;

    -- Warn if namespace mismatch with RLS context
    PERFORM queue._warn_namespace_mismatch(p_namespace);

    -- Get config for defaults
    v_config := queue._get_config(p_namespace);

    -- Get actor context
    SELECT * INTO v_actor FROM queue._get_actor_context();

    -- Insert all jobs
    WITH inserted AS (
        INSERT INTO queue.jobs (
            namespace,
            queue,
            payload,
            priority,
            max_attempts,
            tags,
            actor_id,
            request_id,
            on_behalf_of,
            reason
        )
        SELECT
            p_namespace,
            p_queue,
            unnest(p_payloads),
            COALESCE(p_priority, 0),
            COALESCE(p_max_attempts, v_config.default_max_attempts),
            COALESCE(p_tags, '{}'),
            v_actor.actor_id,
            v_actor.request_id,
            v_actor.on_behalf_of,
            v_actor.reason
        RETURNING id
    )
    SELECT array_agg(id) INTO v_job_ids FROM inserted;

    -- Notify once with count
    v_count := array_length(v_job_ids, 1);
    IF v_count > 0 THEN
        PERFORM queue._notify_if_enabled(
            v_config,
            p_namespace,
            p_queue,
            jsonb_build_object('count', v_count, 'queue', p_queue)
        );
    END IF;

    RETURN COALESCE(v_job_ids, ARRAY[]::bigint[]);
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = queue, pg_temp;
