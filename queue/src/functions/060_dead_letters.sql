-- @group Dead Letters

-- @function queue.retry_dead_letter
-- @brief Retry a dead-lettered job by creating a new job from its payload.
-- @param p_namespace Tenant namespace
-- @param p_dead_letter_id Dead letter ID
-- @param p_queue Queue override (NULL = use original queue)
-- @returns New job ID
--
-- Creates a new pending job from the dead letter's payload, priority,
-- max_attempts, tags, and metadata. The new job starts with attempts = 0
-- (fresh start). The dead letter is marked with retried_at and retry_job_id
-- to prevent double-retry.
--
-- Actor context captures who authorized the retry, not the original pusher.
CREATE OR REPLACE FUNCTION queue.retry_dead_letter(
    p_namespace text,
    p_dead_letter_id bigint,
    p_queue text DEFAULT NULL
)
RETURNS bigint AS $$
DECLARE
    v_dl queue.dead_letters;
    v_job_id bigint;
    v_config queue.config;
    v_actor record;
    v_target_queue text;
BEGIN
    -- Validate inputs
    PERFORM queue._validate_namespace(p_namespace);

    IF p_dead_letter_id IS NULL THEN
        RAISE EXCEPTION 'Dead letter ID cannot be null'
            USING ERRCODE = 'null_value_not_allowed',
                  HINT = 'postkit:queue:VAL_DEAD_LETTER_ID_NULL';
    END IF;

    IF p_queue IS NOT NULL THEN
        PERFORM queue._validate_queue_name(p_queue);
    END IF;

    PERFORM queue._warn_namespace_mismatch(p_namespace);

    -- Lock the dead letter row to prevent concurrent retry.
    SELECT * INTO v_dl
    FROM queue.dead_letters
    WHERE namespace = p_namespace
      AND id = p_dead_letter_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Dead letter % not found', p_dead_letter_id
            USING ERRCODE = 'no_data_found',
                  HINT = 'postkit:queue:DATA_DEAD_LETTER_NOT_FOUND';
    END IF;

    IF v_dl.retried_at IS NOT NULL THEN
        RAISE EXCEPTION 'Dead letter % has already been retried (retry_job_id=%)',
            p_dead_letter_id, v_dl.retry_job_id
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:queue:BIZ_DEAD_LETTER_ALREADY_RETRIED';
    END IF;

    v_target_queue := COALESCE(p_queue, v_dl.queue);

    -- Capture caller's actor context (who authorized the retry).
    SELECT * INTO v_actor FROM queue._get_actor_context();

    -- Create new job from dead letter data with fresh attempt counter.
    INSERT INTO queue.jobs (
        namespace, queue, payload, priority, max_attempts, tags, metadata,
        actor_id, request_id, on_behalf_of, reason
    )
    VALUES (
        p_namespace,
        v_target_queue,
        v_dl.payload,
        v_dl.priority,
        v_dl.max_attempts,
        v_dl.tags,
        v_dl.metadata,
        v_actor.actor_id,
        v_actor.request_id,
        v_actor.on_behalf_of,
        v_actor.reason
    )
    RETURNING id INTO v_job_id;

    -- Mark dead letter as retried.
    UPDATE queue.dead_letters
    SET retried_at = now(),
        retry_job_id = v_job_id
    WHERE id = v_dl.id;

    -- Notify if enabled.
    v_config := queue._get_config(p_namespace);
    PERFORM queue._notify_if_enabled(
        v_config,
        p_namespace,
        v_target_queue,
        jsonb_build_object(
            'id', v_job_id,
            'queue', v_target_queue,
            'retry_of_dead_letter', v_dl.id
        )
    );

    RETURN v_job_id;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = queue, pg_temp;


-- @function queue.retry_dead_letters
-- @brief Retry multiple dead letters for a queue in a single transaction.
-- @param p_namespace Tenant namespace
-- @param p_queue Queue to retry dead letters from
-- @param p_limit Maximum dead letters to retry (clamped to 1000)
-- @returns Rows of (dead_letter_id, job_id) for each retried entry
--
-- Retries un-retried dead letters for a queue, oldest failures first.
-- Uses FOR UPDATE SKIP LOCKED so concurrent callers do not double-retry.
-- Each retried dead letter creates a new pending job with fresh attempts
-- and the caller's actor context.
CREATE OR REPLACE FUNCTION queue.retry_dead_letters(
    p_namespace text,
    p_queue text,
    p_limit int DEFAULT 100
)
RETURNS TABLE(
    dead_letter_id bigint,
    job_id bigint
) AS $$
DECLARE
    v_dl queue.dead_letters;
    v_job_id bigint;
    v_config queue.config;
    v_actor record;
BEGIN
    PERFORM queue._validate_namespace(p_namespace);
    PERFORM queue._validate_queue_name(p_queue);
    PERFORM queue._warn_namespace_mismatch(p_namespace);

    IF p_limit > 1000 THEN
        p_limit := 1000;
    END IF;

    -- Capture actor context once for all retries.
    SELECT * INTO v_actor FROM queue._get_actor_context();
    v_config := queue._get_config(p_namespace);

    FOR v_dl IN
        SELECT d.*
        FROM queue.dead_letters d
        WHERE d.namespace = p_namespace
          AND d.queue = p_queue
          AND d.retried_at IS NULL
        ORDER BY d.failed_at
        LIMIT p_limit
        FOR UPDATE SKIP LOCKED
    LOOP
        -- Create new job from dead letter data.
        INSERT INTO queue.jobs (
            namespace, queue, payload, priority, max_attempts, tags, metadata,
            actor_id, request_id, on_behalf_of, reason
        )
        VALUES (
            p_namespace,
            p_queue,
            v_dl.payload,
            v_dl.priority,
            v_dl.max_attempts,
            v_dl.tags,
            v_dl.metadata,
            v_actor.actor_id,
            v_actor.request_id,
            v_actor.on_behalf_of,
            v_actor.reason
        )
        RETURNING id INTO v_job_id;

        -- Mark dead letter as retried.
        UPDATE queue.dead_letters
        SET retried_at = now(),
            retry_job_id = v_job_id
        WHERE id = v_dl.id;

        PERFORM queue._notify_if_enabled(
            v_config,
            p_namespace,
            p_queue,
            jsonb_build_object(
                'id', v_job_id,
                'queue', p_queue,
                'retry_of_dead_letter', v_dl.id
            )
        );

        dead_letter_id := v_dl.id;
        job_id := v_job_id;
        RETURN NEXT;
    END LOOP;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = queue, pg_temp;


-- @function queue.purge_dead_letters
-- @brief Delete old un-retried dead letters.
-- @param p_namespace Tenant namespace
-- @param p_queue Queue filter (NULL = all queues)
-- @param p_older_than Only delete entries older than this interval (default 30 days)
-- @returns Count of deleted dead letters
--
-- Only purges un-retried dead letters. Retried entries are kept because
-- they link the dead letter to its retry job (historical record).
CREATE OR REPLACE FUNCTION queue.purge_dead_letters(
    p_namespace text,
    p_queue text DEFAULT NULL,
    p_older_than interval DEFAULT '30 days'
)
RETURNS int AS $$
DECLARE
    v_count int;
BEGIN
    PERFORM queue._validate_namespace(p_namespace);

    IF p_queue IS NOT NULL THEN
        PERFORM queue._validate_queue_name(p_queue);
    END IF;

    PERFORM queue._warn_namespace_mismatch(p_namespace);

    DELETE FROM queue.dead_letters
    WHERE namespace = p_namespace
      AND (p_queue IS NULL OR queue = p_queue)
      AND retried_at IS NULL
      AND failed_at < now() - p_older_than;

    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = queue, pg_temp;
