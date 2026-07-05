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


-- @function outbox.horizon_blockers
-- @brief Transactions whose open writes pin the visibility horizon.
-- @returns One row per in-progress write transaction, oldest first
-- @example SELECT * FROM outbox.horizon_blockers();
--
-- Answers "who is freezing delivery" when lag's horizon column stalls.
-- Only transactions that have allocated an xid (that is, have written)
-- appear in the snapshot and can pin the horizon; read-only transactions
-- never do. is_horizon marks the transaction whose xid IS the horizon;
-- the others are next in line. The xid space is cluster-wide, so a
-- blocker can live in another database (datname says which).
--
-- Two sources, because blockers come in two kinds. Backends: open write
-- transactions from pg_stat_activity. Prepared transactions: two-phase
-- commits from pg_prepared_xacts, which hold their xid in progress until
-- COMMIT PREPARED or ROLLBACK PREPARED and are exempt from every timeout,
-- including transaction_timeout - an orphaned one pins the horizon until
-- an operator resolves it, and only this function surfaces it. A
-- prepared transaction has no backend: pid and query are NULL, state is
-- 'prepared', and application_name carries the gid, the handle that
-- ROLLBACK PREPARED takes.
--
-- Seeing other sessions requires pg_read_all_stats (or superuser):
-- pg_stat_activity nulls other backends' details for unprivileged
-- callers, including backend_xid, so their rows are filtered out here.
-- pg_prepared_xacts has no such gate. Database-global by construction,
-- like the horizon itself: no namespace parameter and no tenant-context
-- interaction.
CREATE OR REPLACE FUNCTION outbox.horizon_blockers()
RETURNS TABLE(
    pid int,
    datname text,
    xact_age interval,
    state text,
    application_name text,
    query text,
    is_horizon boolean
) AS $$
    -- Backend xids and prepared xids are 32-bit; the horizon is a 64-bit
    -- xid8. Compare on the xid8's low 32 bits (its epoch-less xid part),
    -- computed once here for both branches.
    WITH h AS (
        SELECT mod(outbox._horizon()::text::numeric, 4294967296::numeric)
               AS horizon_xid32
    )
    SELECT
        a.pid,
        a.datname::text,
        now() - a.xact_start,
        a.state,
        a.application_name,
        a.query,
        a.backend_xid::text::numeric = h.horizon_xid32
    FROM pg_stat_activity a, h
    WHERE a.backend_xid IS NOT NULL
    UNION ALL
    SELECT
        NULL,
        p.database::text,
        now() - p.prepared,
        'prepared',
        p.gid,
        NULL,
        p.transaction::text::numeric = h.horizon_xid32
    FROM pg_prepared_xacts p, h
    ORDER BY 3 DESC;
$$ LANGUAGE sql STABLE SECURITY INVOKER SET search_path = outbox, pg_temp;
