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
    PERFORM queue._validate_limit(p_limit, 'limit', 1000);
    IF p_namespace IS NULL AND NOT queue._rls_bypassed() THEN
        RAISE EXCEPTION 'All-namespaces mode requires a role that bypasses RLS; pass an explicit namespace or run as a BYPASSRLS role'
            USING ERRCODE = 'insufficient_privilege',
                  HINT = 'postkit:queue:BIZ_ALL_NAMESPACES_REQUIRES_BYPASS';
    END IF;

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
        BEGIN
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

            IF v_schedule.cron_expression IS NOT NULL THEN
                v_next := queue._cron_next_run(
                    v_schedule.cron_expression,
                    v_schedule.cron_timezone,
                    now()
                );
            ELSE
                v_next := now() + v_schedule.every_interval;
            END IF;

            UPDATE queue.schedules
            SET last_run_at = now(),
                last_job_id = v_job_id,
                next_run_at = v_next,
                run_count = queue.schedules.run_count + 1,
                last_error = NULL,
                consecutive_failures = 0,
                updated_at = now()
            WHERE id = v_schedule.id;

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

            schedule_name := v_schedule.name;
            job_id := v_job_id;
            next_run_at := v_next;
            RETURN NEXT;
        EXCEPTION WHEN OTHERS THEN
            UPDATE queue.schedules
            SET last_error = SQLERRM,
                consecutive_failures = queue.schedules.consecutive_failures + 1,
                next_run_at = clock_timestamp() + interval '1 minute',
                is_active = (queue.schedules.consecutive_failures + 1 < 10),
                updated_at = clock_timestamp()
            WHERE id = v_schedule.id;
        END;
    END LOOP;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = queue, pg_temp;


-- @function queue.tick_timeouts
-- @brief Reclaim running jobs whose visibility timeout has expired.
-- @param p_namespace Tenant namespace (NULL = all namespaces, requires RLS bypass)
-- @param p_limit Maximum jobs to reclaim per call
-- @returns Rows of (job_id, queue, stuck_duration) for each reclaimed job
--
-- Workers that crash or hang leave jobs stuck in 'running' status. This
-- function finds those jobs (visibility_timeout_at < now()) and returns them
-- to 'pending' for re-delivery. Attempt count is preserved so the next
-- pull increments it normally. Does NOT check max_attempts - the next
-- nack cycle handles DLQ routing, keeping that decision in one place.
--
-- Call periodically alongside tick_schedules(). Uses FOR UPDATE SKIP LOCKED
-- so multiple tick workers can run concurrently without double-processing.
CREATE OR REPLACE FUNCTION queue.tick_timeouts(
    p_namespace text DEFAULT NULL,
    p_limit int DEFAULT 100
)
RETURNS TABLE(
    job_id bigint,
    queue text,
    stuck_duration interval
) AS $$
DECLARE
    v_job record;
BEGIN
    PERFORM queue._validate_limit(p_limit, 'limit', 1000);
    IF p_namespace IS NULL AND NOT queue._rls_bypassed() THEN
        RAISE EXCEPTION 'All-namespaces mode requires a role that bypasses RLS; pass an explicit namespace or run as a BYPASSRLS role'
            USING ERRCODE = 'insufficient_privilege',
                  HINT = 'postkit:queue:BIZ_ALL_NAMESPACES_REQUIRES_BYPASS';
    END IF;

    FOR v_job IN
        SELECT j.id, j.queue, (now() - j.locked_at) AS stuck_duration
        FROM queue.jobs j
        WHERE j.status = 'running'
          AND j.visibility_timeout_at < now()
          AND (p_namespace IS NULL OR j.namespace = p_namespace)
        ORDER BY j.visibility_timeout_at
        LIMIT p_limit
        FOR UPDATE SKIP LOCKED
    LOOP
        -- Return to pending, clearing lock fields per jobs_locked_consistency.
        -- Attempt count is NOT reset: the job keeps its history.
        UPDATE queue.jobs
        SET
            status = 'pending',
            locked_by = NULL,
            locked_at = NULL,
            visibility_timeout_at = NULL,
            updated_at = now()
        WHERE id = v_job.id
          AND status = 'running';

        job_id := v_job.id;
        queue := v_job.queue;
        stuck_duration := v_job.stuck_duration;
        RETURN NEXT;
    END LOOP;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = queue, pg_temp;
