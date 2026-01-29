-- @group Stats

-- @function queue.get_stats
-- @brief Get namespace-wide queue statistics.
-- @param p_namespace Tenant namespace
-- @returns Row with total_jobs, pending, running, completed, dead, total_queues
CREATE OR REPLACE FUNCTION queue.get_stats(p_namespace text)
RETURNS TABLE(
    total_jobs bigint,
    pending bigint,
    running bigint,
    completed bigint,
    dead bigint,
    total_queues bigint
) AS $$
BEGIN
    PERFORM queue._validate_namespace(p_namespace);
    PERFORM queue._warn_namespace_mismatch(p_namespace);

    RETURN QUERY
    SELECT
        COUNT(*),
        COUNT(*) FILTER (WHERE j.status = 'pending'),
        COUNT(*) FILTER (WHERE j.status = 'running'),
        -- Non-zero only when archive_completed is enabled in tenant config;
        -- default config deletes completed jobs on ack.
        COUNT(*) FILTER (WHERE j.status = 'completed'),
        COUNT(*) FILTER (WHERE j.status = 'dead'),
        COUNT(DISTINCT j.queue)
    FROM queue.jobs j
    WHERE j.namespace = p_namespace;
END;
$$ LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = queue, pg_temp;


-- @function queue.get_queue_stats
-- @brief Get per-queue statistics with operational metrics.
-- @param p_namespace Tenant namespace
-- @param p_queue Queue filter (NULL = all queues)
-- @returns Row per queue with status counts, oldest pending age, and un-retried dead letter count
--
-- Unlike get_stats (namespace-wide totals), this breaks down by queue and
-- includes operational metrics: how stale the backlog is and how many jobs
-- have failed and not yet been retried. Use get_stats for dashboards;
-- use this for debugging.
CREATE OR REPLACE FUNCTION queue.get_queue_stats(
    p_namespace text,
    p_queue text DEFAULT NULL
)
RETURNS TABLE(
    queue text,
    pending bigint,
    running bigint,
    completed bigint,
    dead bigint,
    oldest_pending_seconds numeric,
    dead_letters bigint
) AS $$
BEGIN
    PERFORM queue._validate_namespace(p_namespace);

    IF p_queue IS NOT NULL THEN
        PERFORM queue._validate_queue_name(p_queue);
    END IF;

    PERFORM queue._warn_namespace_mismatch(p_namespace);

    RETURN QUERY
    SELECT
        j.queue,
        COUNT(*) FILTER (WHERE j.status = 'pending'),
        COUNT(*) FILTER (WHERE j.status = 'running'),
        COUNT(*) FILTER (WHERE j.status = 'completed'),
        COUNT(*) FILTER (WHERE j.status = 'dead'),
        EXTRACT(EPOCH FROM (now() - MIN(j.scheduled_at) FILTER (WHERE j.status = 'pending'))),
        COALESCE(dl.cnt, 0)
    FROM queue.jobs j
    LEFT JOIN (
        -- Count only un-retried dead letters: these are actionable failures
        -- awaiting intervention. Retried entries are historical records kept
        -- for audit (linking dead letter -> retry job) and are already
        -- reflected in the 'dead' column from queue.jobs. Matches the
        -- filter used by retry_dead_letters() and purge_dead_letters().
        SELECT d.queue AS q, COUNT(*) AS cnt
        FROM queue.dead_letters d
        WHERE d.namespace = p_namespace
          AND (p_queue IS NULL OR d.queue = p_queue)
          AND d.retried_at IS NULL
        GROUP BY d.queue
    ) dl ON dl.q = j.queue
    WHERE j.namespace = p_namespace
      AND (p_queue IS NULL OR j.queue = p_queue)
    GROUP BY j.queue, dl.cnt
    ORDER BY j.queue;
END;
$$ LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = queue, pg_temp;
