-- @group Inspection

-- @function outbox.lag
-- @brief Per-consumer backlog for a topic (or all topics).
-- @param p_namespace Tenant namespace
-- @param p_topic Topic filter (NULL = all topics)
-- @returns One row per consumer: position pair, backlog count, age of the
--          oldest unprocessed event, and the current visibility horizon
-- @example SELECT * FROM outbox.lag('default', 'orders');
--
-- lag_events counts readable events past the cursor. It is a count, not a
-- subtraction: event ids are global across topics, so within one topic they
-- are sparse and id arithmetic measures platform-wide inserts, not this
-- consumer's backlog. The count is a range scan over the consumer's backlog;
-- a caught-up consumer costs almost nothing.
--
-- The horizon column makes a stalled long transaction visible: if it stops
-- advancing, some transaction is holding delivery back. Join it against
-- pg_stat_activity (under your own grants) to find the culprit.
CREATE OR REPLACE FUNCTION outbox.lag(
    p_namespace text,
    p_topic text DEFAULT NULL
)
RETURNS TABLE(
    topic text,
    consumer text,
    position_xid xid8,
    position_id bigint,
    lag_events bigint,
    lag_time interval,
    horizon xid8
) AS $$
BEGIN
    -- Validate inputs
    PERFORM outbox._validate_namespace(p_namespace);
    IF p_topic IS NOT NULL THEN
        PERFORM outbox._validate_topic(p_topic);
    END IF;

    -- Warn if namespace mismatch with RLS context
    PERFORM outbox._warn_namespace_mismatch(p_namespace);

    RETURN QUERY
    SELECT
        c.topic,
        c.consumer,
        c.position_xid,
        c.position_id,
        (SELECT COUNT(*)
         FROM outbox.events e
         WHERE e.namespace = c.namespace AND e.topic = c.topic
           AND (e.xid, e.id) > (c.position_xid, c.position_id)
           AND e.xid < outbox._horizon()),
        (SELECT now() - MIN(e.created_at)
         FROM outbox.events e
         WHERE e.namespace = c.namespace AND e.topic = c.topic
           AND (e.xid, e.id) > (c.position_xid, c.position_id)
           AND e.xid < outbox._horizon()),
        outbox._horizon()
    FROM outbox.cursors c
    WHERE c.namespace = p_namespace
      AND (p_topic IS NULL OR c.topic = p_topic)
    ORDER BY c.topic, c.consumer;
END;
$$ LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = outbox, pg_temp;


-- @function outbox.get_stats
-- @brief Get namespace-wide outbox statistics.
-- @param p_namespace Tenant namespace
-- @returns Row with total_events, total_topics, total_consumers, max_lag_events
-- @example SELECT * FROM outbox.get_stats('default');
--
-- max_lag_events uses the same backlog count as outbox.lag, never id
-- subtraction (ids are sparse within a topic).
CREATE OR REPLACE FUNCTION outbox.get_stats(p_namespace text)
RETURNS TABLE(
    total_events bigint,
    total_topics bigint,
    total_consumers bigint,
    max_lag_events bigint
) AS $$
BEGIN
    PERFORM outbox._validate_namespace(p_namespace);
    PERFORM outbox._warn_namespace_mismatch(p_namespace);

    RETURN QUERY
    SELECT
        (SELECT COUNT(*) FROM outbox.events e WHERE e.namespace = p_namespace),
        (SELECT COUNT(*) FROM outbox.topics t WHERE t.namespace = p_namespace),
        (SELECT COUNT(*) FROM outbox.cursors c WHERE c.namespace = p_namespace),
        (SELECT COALESCE(MAX(l.lag_events), 0)
         FROM outbox.lag(p_namespace) l);
END;
$$ LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = outbox, pg_temp;


-- @function outbox.list_consumers
-- @brief List consumer cursors in a namespace.
-- @param p_namespace Tenant namespace
-- @param p_topic Topic filter (NULL = all topics)
-- @returns Cursor rows
-- @example SELECT * FROM outbox.list_consumers('default', 'orders');
CREATE OR REPLACE FUNCTION outbox.list_consumers(
    p_namespace text,
    p_topic text DEFAULT NULL
)
RETURNS SETOF outbox.cursors AS $$
BEGIN
    PERFORM outbox._validate_namespace(p_namespace);
    IF p_topic IS NOT NULL THEN
        PERFORM outbox._validate_topic(p_topic);
    END IF;
    PERFORM outbox._warn_namespace_mismatch(p_namespace);

    RETURN QUERY
    SELECT c.*
    FROM outbox.cursors c
    WHERE c.namespace = p_namespace
      AND (p_topic IS NULL OR c.topic = p_topic)
    ORDER BY c.topic, c.consumer;
END;
$$ LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = outbox, pg_temp;
