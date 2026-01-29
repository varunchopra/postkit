-- @group Schedules

-- @function queue.tick_schedules
-- @brief Process due schedules and create jobs.
-- @param p_namespace Tenant namespace (NULL = all namespaces, requires RLS bypass)
-- @param p_limit Maximum schedules to process per call
-- @returns Rows of (schedule_name, job_id, next_run_at) for each processed schedule
--
-- Finds active schedules where next_run_at <= now(), creates a job for each,
-- and advances next_run_at. Uses FOR UPDATE SKIP LOCKED for safe concurrent
-- execution from multiple workers.
CREATE OR REPLACE FUNCTION queue.tick_schedules(
    p_namespace text DEFAULT NULL,
    p_limit int DEFAULT 100
)
RETURNS TABLE(
    schedule_name text,
    job_id bigint,
    next_run_at timestamptz
) AS $$
DECLARE
    v_schedule queue.schedules;
    v_job_id bigint;
    v_next timestamptz;
    v_config queue.config;
    v_actor record;
BEGIN
    -- Capture actor context once (same as push() does per-call).
    SELECT * INTO v_actor FROM queue._get_actor_context();

    FOR v_schedule IN
        SELECT s.*
        FROM queue.schedules s
        WHERE s.is_active = true
          AND s.next_run_at <= now()
          AND (p_namespace IS NULL OR s.namespace = p_namespace)
        ORDER BY s.next_run_at
        LIMIT p_limit
        FOR UPDATE SKIP LOCKED
    LOOP
        -- Insert job directly (skip queue.push overhead since inputs were
        -- validated at schedule creation time)
        INSERT INTO queue.jobs (
            namespace, queue, payload, priority, max_attempts, tags,
            actor_id, request_id, on_behalf_of, reason
        )
        VALUES (
            v_schedule.namespace,
            v_schedule.queue,
            v_schedule.payload,
            v_schedule.priority,
            v_schedule.max_attempts,
            v_schedule.tags,
            v_actor.actor_id,
            v_actor.request_id,
            v_actor.on_behalf_of,
            v_actor.reason
        )
        RETURNING id INTO v_job_id;

        -- Calculate next run time
        IF v_schedule.cron_expression IS NOT NULL THEN
            v_next := queue._cron_next_run(
                v_schedule.cron_expression,
                v_schedule.cron_timezone,
                now()
            );
        ELSE
            v_next := now() + v_schedule.every_interval;
        END IF;

        -- Update schedule state
        UPDATE queue.schedules
        SET last_run_at = now(),
            last_job_id = v_job_id,
            next_run_at = v_next,
            run_count = queue.schedules.run_count + 1,
            updated_at = now()
        WHERE id = v_schedule.id;

        -- Notify listeners
        v_config := queue._get_config(v_schedule.namespace);
        PERFORM queue._notify_if_enabled(
            v_config,
            v_schedule.namespace,
            v_schedule.queue,
            jsonb_build_object(
                'id', v_job_id,
                'queue', v_schedule.queue,
                'schedule', v_schedule.name
            )
        );

        -- Return result row
        schedule_name := v_schedule.name;
        job_id := v_job_id;
        next_run_at := v_next;
        RETURN NEXT;
    END LOOP;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = queue, pg_temp;
