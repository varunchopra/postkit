-- @group Subscribe

-- @function outbox.subscribe
-- @brief Register a consumer on a topic and set its starting position.
-- @param p_namespace Tenant namespace
-- @param p_topic Topic name
-- @param p_consumer Consumer name
-- @param p_from Starting point: 'start' (replay everything retained) or 'head' (only new events)
-- @returns The starting position pair (position_xid, position_id)
-- @example SELECT * FROM outbox.subscribe('default', 'orders', 'billing', 'start');
--
-- p_from has no default on purpose: the wrong silent choice either replays
-- the topic's whole history into a consumer that didn't want it or skips
-- everything it did. Pass 'start' or 'head' explicitly.
--
-- 'head' uses the highest readable (xid, id) pair, not the raw maximum: a
-- pair from a still-uncommitted transaction sorts above everything
-- readable, and a raw-max cursor would strand its events behind the new
-- consumer forever (O1, see 001_tables.sql).
--
-- Re-subscribing an existing consumer raises CONSUMER_EXISTS: silently
-- resetting a live cursor would lose or replay events without anyone
-- deciding that. Use outbox.replay to move a cursor deliberately.
CREATE OR REPLACE FUNCTION outbox.subscribe(
    p_namespace text,
    p_topic text,
    p_consumer text,
    p_from text
)
RETURNS TABLE(
    position_xid xid8,
    position_id bigint
) AS $$
DECLARE
    v_xid xid8;
    v_id bigint;
BEGIN
    -- Validate inputs
    PERFORM outbox._validate_namespace(p_namespace);
    PERFORM outbox._validate_topic(p_topic);
    PERFORM outbox._validate_consumer(p_consumer);

    IF p_from IS NULL OR p_from NOT IN ('start', 'head') THEN
        RAISE EXCEPTION 'Subscribe requires an explicit starting point: ''start'' or ''head'' (got: %)', COALESCE(p_from, 'NULL')
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:outbox:VAL_SUBSCRIBE_FROM_REQUIRED';
    END IF;

    -- Warn if namespace mismatch with RLS context
    PERFORM outbox._warn_namespace_mismatch(p_namespace);

    -- Subscribing before the first emit is the normal rollout order
    PERFORM outbox._ensure_topic(p_namespace, p_topic);

    IF p_from = 'start' THEN
        SELECT t.trimmed_xid, t.trimmed_id INTO v_xid, v_id
        FROM outbox._trimmed_through(p_namespace, p_topic) t;
    ELSE
        SELECT h.head_xid, h.head_id INTO v_xid, v_id
        FROM outbox._gated_head(p_namespace, p_topic) h;
    END IF;

    INSERT INTO outbox.cursors (namespace, topic, consumer, position_xid, position_id)
    VALUES (p_namespace, p_topic, p_consumer, v_xid, v_id)
    ON CONFLICT (namespace, topic, consumer) DO NOTHING;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Consumer % already subscribed to topic % (use outbox.replay to move its cursor)', p_consumer, p_topic
            USING ERRCODE = 'unique_violation',
                  HINT = 'postkit:outbox:BIZ_CONSUMER_EXISTS';
    END IF;

    RETURN QUERY SELECT v_xid, v_id;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = outbox, pg_temp;


-- @function outbox.replay
-- @brief Move an existing consumer's cursor to a chosen position.
-- @param p_namespace Tenant namespace
-- @param p_topic Topic name
-- @param p_consumer Consumer name
-- @param p_xid Transaction component of the new position
-- @param p_id Id component of the new position (events after the pair are delivered again)
-- @example SELECT outbox.replay('default', 'orders', 'billing', '0', 0);
--
-- The deliberate way to re-deliver or skip: set the cursor to any pair
-- between the oldest retained event and the current readable head. Take
-- the pair from a previously polled row, from the trimmed pair in a
-- CURSOR_LOST message, or ('0', 0) for everything retained. Below the
-- retained range raises CURSOR_LOST (the events are gone); above the
-- readable head raises POSITION_BEYOND_HEAD (acking the future would skip
-- events that later become readable below it).
CREATE OR REPLACE FUNCTION outbox.replay(
    p_namespace text,
    p_topic text,
    p_consumer text,
    p_xid xid8,
    p_id bigint
)
RETURNS void AS $$
DECLARE
    v_trimmed_xid xid8;
    v_trimmed_id bigint;
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

    SELECT t.trimmed_xid, t.trimmed_id INTO v_trimmed_xid, v_trimmed_id
    FROM outbox._trimmed_through(p_namespace, p_topic) t;
    IF (p_xid, p_id) < (v_trimmed_xid, v_trimmed_id) THEN
        RAISE EXCEPTION 'Position (%, %) is below the oldest retained event; events through (%, %) have been trimmed. Resync from your source of truth, then replay to (%, %).',
            p_xid, p_id, v_trimmed_xid, v_trimmed_id, v_trimmed_xid, v_trimmed_id
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:outbox:BIZ_CURSOR_LOST';
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
      AND c.consumer = p_consumer;

    GET DIAGNOSTICS v_updated = ROW_COUNT;
    IF v_updated = 0 THEN
        RAISE EXCEPTION 'Consumer % is not subscribed to topic %', p_consumer, p_topic
            USING ERRCODE = 'no_data_found',
                  HINT = 'postkit:outbox:BIZ_CONSUMER_UNKNOWN';
    END IF;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = outbox, pg_temp;
