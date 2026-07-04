-- @group Poll and Ack

-- @function outbox.poll
-- @brief Read the next events for a consumer. Does not advance the cursor.
-- @param p_namespace Tenant namespace
-- @param p_topic Topic name
-- @param p_consumer Consumer name (must be subscribed)
-- @param p_limit Maximum events to return
-- @returns Events after the cursor, in (xid, id) order
-- @example SELECT * FROM outbox.poll('default', 'orders', 'billing');
--
-- Returns only events whose emitting transaction has finished (O1, see
-- 001_tables.sql). A consequence worth knowing: one long-running write
-- transaction anywhere in the database holds back delivery of everything
-- committed after it began, until it finishes. outbox.lag exposes the
-- horizon so a stall is visible.
--
-- Poll then ack is at-least-once delivery: a consumer that crashes between
-- processing and ack sees the events again, so make processing idempotent.
-- Processing and acking in one transaction (when the effect lives in this
-- database) is exactly-once.
--
-- The cursor row is locked while polling, so concurrent polls of the same
-- consumer serialize; two workers sharing a consumer name see duplicates,
-- not gaps.
CREATE OR REPLACE FUNCTION outbox.poll(
    p_namespace text,
    p_topic text,
    p_consumer text,
    p_limit int DEFAULT 100
)
RETURNS SETOF outbox.events AS $$
DECLARE
    v_xid xid8;
    v_id bigint;
    v_trimmed_xid xid8;
    v_trimmed_id bigint;
BEGIN
    -- Validate inputs
    PERFORM outbox._validate_namespace(p_namespace);
    PERFORM outbox._validate_topic(p_topic);
    PERFORM outbox._validate_consumer(p_consumer);
    PERFORM outbox._validate_positive_int(p_limit, 'limit');

    -- Warn if namespace mismatch with RLS context
    PERFORM outbox._warn_namespace_mismatch(p_namespace);

    SELECT c.position_xid, c.position_id INTO v_xid, v_id
    FROM outbox.cursors c
    WHERE c.namespace = p_namespace
      AND c.topic = p_topic
      AND c.consumer = p_consumer
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Consumer % is not subscribed to topic % (call outbox.subscribe first)', p_consumer, p_topic
            USING ERRCODE = 'no_data_found',
                  HINT = 'postkit:outbox:BIZ_CONSUMER_UNKNOWN';
    END IF;

    SELECT t.trimmed_xid, t.trimmed_id INTO v_trimmed_xid, v_trimmed_id
    FROM outbox._trimmed_through(p_namespace, p_topic) t;
    IF (v_xid, v_id) < (v_trimmed_xid, v_trimmed_id) THEN
        -- Never skip silently (O5): the consumer missed trimmed events and
        -- must resync from its source of truth, then replay.
        RAISE EXCEPTION 'Cursor at (%, %) is below the oldest retained event; events through (%, %) have been trimmed. Resync from your source of truth, then replay to (%, %).',
            v_xid, v_id, v_trimmed_xid, v_trimmed_id, v_trimmed_xid, v_trimmed_id
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:outbox:BIZ_CURSOR_LOST';
    END IF;

    RETURN QUERY
    SELECT e.*
    FROM outbox.events e
    WHERE e.namespace = p_namespace
      AND e.topic = p_topic
      AND (e.xid, e.id) > (v_xid, v_id)
      AND e.xid < outbox._horizon()
    ORDER BY e.xid, e.id
    LIMIT p_limit;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = outbox, pg_temp;


-- @function outbox.has_pending
-- @brief Whether a consumer has readable events past its cursor.
-- @param p_namespace Tenant namespace
-- @param p_topic Topic name
-- @param p_consumer Consumer name (must be subscribed)
-- @returns True iff a readable event lies past the cursor or the cursor
--          is below the retained range
-- @example SELECT outbox.has_pending('default', 'orders', 'billing');
--
-- The per-heartbeat check. Deliberately neither poll nor lag: poll takes
-- FOR UPDATE on the cursor row, so a high-frequency caller would
-- serialize against real consumption, and lag counts the whole backlog.
-- Do not reimplement this as a wrapper over either. Same visibility gate
-- as poll (O1, see 001_tables.sql).
--
-- A cursor below the trimmed pair returns true rather than raising
-- CURSOR_LOST: callers bundle this check with their own writes, which a
-- raise would abort, and the next poll raises the loss loudly anyway
-- (O5). The trimmed check must precede the EXISTS: a fully trimmed topic
-- leaves nothing for the EXISTS to find, so a consumer that lost every
-- event would otherwise look caught up.
CREATE OR REPLACE FUNCTION outbox.has_pending(
    p_namespace text,
    p_topic text,
    p_consumer text
)
RETURNS boolean AS $$
DECLARE
    v_xid xid8;
    v_id bigint;
    v_trimmed_xid xid8;
    v_trimmed_id bigint;
BEGIN
    -- Validate inputs
    PERFORM outbox._validate_namespace(p_namespace);
    PERFORM outbox._validate_topic(p_topic);
    PERFORM outbox._validate_consumer(p_consumer);

    -- Warn if namespace mismatch with RLS context
    PERFORM outbox._warn_namespace_mismatch(p_namespace);

    SELECT c.position_xid, c.position_id INTO v_xid, v_id
    FROM outbox.cursors c
    WHERE c.namespace = p_namespace
      AND c.topic = p_topic
      AND c.consumer = p_consumer;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Consumer % is not subscribed to topic % (call outbox.subscribe first)', p_consumer, p_topic
            USING ERRCODE = 'no_data_found',
                  HINT = 'postkit:outbox:BIZ_CONSUMER_UNKNOWN';
    END IF;

    SELECT t.trimmed_xid, t.trimmed_id INTO v_trimmed_xid, v_trimmed_id
    FROM outbox._trimmed_through(p_namespace, p_topic) t;
    IF (v_xid, v_id) < (v_trimmed_xid, v_trimmed_id) THEN
        RETURN true;
    END IF;

    RETURN EXISTS (
        SELECT 1
        FROM outbox.events e
        WHERE e.namespace = p_namespace
          AND e.topic = p_topic
          AND (e.xid, e.id) > (v_xid, v_id)
          AND e.xid < outbox._horizon()
    );
END;
$$ LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = outbox, pg_temp;


-- @function outbox.read_from
-- @brief Read events from a position, for callers that keep their own cursor.
-- @param p_namespace Tenant namespace
-- @param p_topic Topic name
-- @param p_xid Transaction component of the last-seen position
-- @param p_id Id component of the last-seen position
-- @param p_limit Maximum events to return
-- @returns Events after the position, in (xid, id) order
-- @example SELECT * FROM outbox.read_from('default', 'orders', '0', 0, 50);
--
-- For external cursor holders: mobile clients syncing state, customer
-- webhook endpoints storing their own position. Store BOTH components of
-- the last row read and pass them back; the pair is opaque. Same
-- visibility rule as poll, and the same loud CURSOR_LOST when the position
-- is below the oldest retained event (O5).
CREATE OR REPLACE FUNCTION outbox.read_from(
    p_namespace text,
    p_topic text,
    p_xid xid8,
    p_id bigint,
    p_limit int DEFAULT 100
)
RETURNS SETOF outbox.events AS $$
DECLARE
    v_trimmed_xid xid8;
    v_trimmed_id bigint;
BEGIN
    -- Validate inputs
    PERFORM outbox._validate_namespace(p_namespace);
    PERFORM outbox._validate_topic(p_topic);
    PERFORM outbox._validate_position(p_xid, p_id);
    PERFORM outbox._validate_positive_int(p_limit, 'limit');

    -- Warn if namespace mismatch with RLS context
    PERFORM outbox._warn_namespace_mismatch(p_namespace);

    SELECT t.trimmed_xid, t.trimmed_id INTO v_trimmed_xid, v_trimmed_id
    FROM outbox._trimmed_through(p_namespace, p_topic) t;
    IF (p_xid, p_id) < (v_trimmed_xid, v_trimmed_id) THEN
        RAISE EXCEPTION 'Position (%, %) is below the oldest retained event; events through (%, %) have been trimmed. Resync from your source of truth, then read from (%, %).',
            p_xid, p_id, v_trimmed_xid, v_trimmed_id, v_trimmed_xid, v_trimmed_id
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:outbox:BIZ_CURSOR_LOST';
    END IF;

    RETURN QUERY
    SELECT e.*
    FROM outbox.events e
    WHERE e.namespace = p_namespace
      AND e.topic = p_topic
      AND (e.xid, e.id) > (p_xid, p_id)
      AND e.xid < outbox._horizon()
    ORDER BY e.xid, e.id
    LIMIT p_limit;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = outbox, pg_temp;


-- @function outbox.ack
-- @brief Advance a consumer's cursor after processing.
-- @param p_namespace Tenant namespace
-- @param p_topic Topic name
-- @param p_consumer Consumer name
-- @param p_xid Transaction component of the last event processed (its xid column)
-- @param p_id Id component of the last event processed (its id column)
-- @returns True if the cursor advanced, false if the pair is not ahead of it
-- @example SELECT outbox.ack('default', 'orders', 'billing', '742', 42);
--
-- Pass the xid and id columns of the last polled row; the pair is the
-- cursor. Only moves forward: acking at or behind the current position
-- returns false without changing anything (moving a cursor backwards is
-- replay's job). Acking beyond the readable head raises: pairs above the
-- horizon may belong to transactions still in flight, and passing them
-- would skip their events once they commit.
CREATE OR REPLACE FUNCTION outbox.ack(
    p_namespace text,
    p_topic text,
    p_consumer text,
    p_xid xid8,
    p_id bigint
)
RETURNS boolean AS $$
DECLARE
    v_head_xid xid8;
    v_head_id bigint;
    v_updated int;
BEGIN
    -- Validate inputs
    PERFORM outbox._validate_namespace(p_namespace);
    PERFORM outbox._validate_topic(p_topic);
    PERFORM outbox._validate_consumer(p_consumer);
    PERFORM outbox._validate_position(p_xid, p_id);

    -- Warn if namespace mismatch with RLS context
    PERFORM outbox._warn_namespace_mismatch(p_namespace);

    IF NOT EXISTS (
        SELECT 1 FROM outbox.cursors c
        WHERE c.namespace = p_namespace
          AND c.topic = p_topic
          AND c.consumer = p_consumer
    ) THEN
        RAISE EXCEPTION 'Consumer % is not subscribed to topic %', p_consumer, p_topic
            USING ERRCODE = 'no_data_found',
                  HINT = 'postkit:outbox:BIZ_CONSUMER_UNKNOWN';
    END IF;

    SELECT h.head_xid, h.head_id INTO v_head_xid, v_head_id
    FROM outbox._gated_head(p_namespace, p_topic) h;
    IF (p_xid, p_id) > (v_head_xid, v_head_id) THEN
        RAISE EXCEPTION 'Position (%, %) is beyond the readable head (%, %)',
            p_xid, p_id, v_head_xid, v_head_id
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:outbox:BIZ_POSITION_BEYOND_HEAD';
    END IF;

    UPDATE outbox.cursors c
    SET position_xid = p_xid,
        position_id = p_id,
        updated_at = now()
    WHERE c.namespace = p_namespace
      AND c.topic = p_topic
      AND c.consumer = p_consumer
      AND (c.position_xid, c.position_id) < (p_xid, p_id);

    GET DIAGNOSTICS v_updated = ROW_COUNT;
    RETURN v_updated > 0;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = outbox, pg_temp;
