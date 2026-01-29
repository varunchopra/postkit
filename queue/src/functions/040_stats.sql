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
        COUNT(*) FILTER (WHERE j.status = 'completed'),
        COUNT(*) FILTER (WHERE j.status = 'dead'),
        COUNT(DISTINCT j.queue)
    FROM queue.jobs j
    WHERE j.namespace = p_namespace;
END;
$$ LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = queue, pg_temp;
