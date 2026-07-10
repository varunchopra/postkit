-- @group Internal

-- @function outbox._get_config
-- @brief Get effective configuration for a topic.
-- @param p_namespace Namespace to get config for
-- @param p_topic Topic to get config for
-- @returns Config record with wildcard fallback
-- Fallback order: (namespace, topic) -> (namespace, '*') -> ('global', '*').
CREATE OR REPLACE FUNCTION outbox._get_config(p_namespace text, p_topic text)
RETURNS outbox.config AS $$
DECLARE
    v_config outbox.config;
BEGIN
    SELECT * INTO v_config
    FROM outbox.config
    WHERE namespace = p_namespace AND topic = p_topic;

    IF FOUND THEN
        RETURN v_config;
    END IF;

    SELECT * INTO v_config
    FROM outbox.config
    WHERE namespace = p_namespace AND topic = '*';

    IF FOUND THEN
        RETURN v_config;
    END IF;

    SELECT * INTO v_config
    FROM outbox.config
    WHERE namespace = 'global' AND topic = '*';

    -- If no global config (shouldn't happen), return defaults
    IF NOT FOUND THEN
        v_config.namespace := 'global';
        v_config.topic := '*';
        v_config.notify := true;
        v_config.protect_cursors := true;
        v_config.retain_min_rows := 0;
    END IF;

    RETURN v_config;
END;
$$ LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = outbox, pg_temp;


-- @function outbox._notify_if_enabled
-- @brief Send NOTIFY for a committed emit if configured.
-- @param p_config Config record (caller already fetched it)
-- @param p_namespace Tenant namespace for channel name
-- @param p_topic Topic for channel
-- @param p_event_id Id of the emitted event (hint payload only)
-- Channel derivation lives in outbox.channel_name, the public LISTEN contract.
-- NOTIFY is transactional, so the wake-up is delivered only if the emitting
-- transaction commits; the payload is a hint, never correctness. Consumers
-- re-read via poll.
CREATE OR REPLACE FUNCTION outbox._notify_if_enabled(
    p_config outbox.config,
    p_namespace text,
    p_topic text,
    p_event_id bigint
)
RETURNS void AS $$
BEGIN
    IF p_config.notify THEN
        PERFORM pg_notify(outbox.channel_name(p_namespace, p_topic), jsonb_build_object(
            'topic', p_topic,
            'id', p_event_id
        )::text);
    END IF;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = outbox, pg_temp;


-- @function outbox._horizon
-- @brief The xid below which every transaction has finished.
-- @returns Snapshot xmin as xid8
-- The single definition of the visibility gate (O1, see 001_tables.sql):
-- an event is readable only when its xid is below this. Anything that
-- becomes visible later carries an xid at or above it, so it sorts after
-- every (xid, id) pair already delivered.
CREATE OR REPLACE FUNCTION outbox._horizon()
RETURNS xid8 AS $$
    SELECT pg_snapshot_xmin(pg_current_snapshot());
$$ LANGUAGE sql STABLE SECURITY INVOKER SET search_path = outbox, pg_temp;


-- @function outbox._gated_head
-- @brief Highest readable (xid, id) pair for a topic.
-- @param p_namespace Tenant namespace
-- @param p_topic Topic name
-- @returns The greatest gated pair, or the trimmed pair when none is readable
-- Deliberately a backward index scan (ORDER BY xid DESC, id DESC LIMIT 1),
-- not a MAX aggregate: the scan stops at the first row below the horizon,
-- so it only walks the in-flight tail, typically a handful of rows. ack
-- calls this on every invocation; an aggregate would scan the topic's
-- whole range. Do not rewrite as an aggregate.
CREATE OR REPLACE FUNCTION outbox._gated_head(
    p_namespace text,
    p_topic text,
    OUT head_xid xid8,
    OUT head_id bigint
) AS $$
BEGIN
    SELECT e.xid, e.id INTO head_xid, head_id
    FROM outbox.events e
    WHERE e.namespace = p_namespace
      AND e.topic = p_topic
      AND e.xid < outbox._horizon()
    ORDER BY e.xid DESC, e.id DESC
    LIMIT 1;

    IF head_xid IS NULL THEN
        SELECT t.trimmed_xid, t.trimmed_id INTO head_xid, head_id
        FROM outbox.topics t
        WHERE t.namespace = p_namespace AND t.topic = p_topic;
    END IF;

    head_xid := COALESCE(head_xid, '0');
    head_id := COALESCE(head_id, 0);
END;
$$ LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = outbox, pg_temp;


-- @function outbox._ensure_topic
-- @brief Create the per-topic bookkeeping row if absent.
-- @param p_namespace Tenant namespace
-- @param p_topic Topic name
-- Called by emit AND subscribe: deploying the consumer before the producer
-- is the normal rollout order, so reads must never depend on an emit
-- having happened. emit calls this on every event, so the existing-topic
-- case must not touch the write path; the ON CONFLICT stays for the race
-- between two first-emitters that both miss the EXISTS.
CREATE OR REPLACE FUNCTION outbox._ensure_topic(p_namespace text, p_topic text)
RETURNS void AS $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM outbox.topics t
        WHERE t.namespace = p_namespace AND t.topic = p_topic
    ) THEN
        RETURN;
    END IF;

    INSERT INTO outbox.topics (namespace, topic)
    VALUES (p_namespace, p_topic)
    ON CONFLICT (namespace, topic) DO NOTHING;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = outbox, pg_temp;


-- @function outbox._trimmed_through
-- @brief The greatest (xid, id) pair ever trimmed for a topic.
-- @param p_namespace Tenant namespace
-- @param p_topic Topic name
-- @returns The trimmed pair, or ('0', 0) for an absent topics row
CREATE OR REPLACE FUNCTION outbox._trimmed_through(
    p_namespace text,
    p_topic text,
    OUT trimmed_xid xid8,
    OUT trimmed_id bigint
) AS $$
    SELECT
        COALESCE((SELECT t.trimmed_xid FROM outbox.topics t
                  WHERE t.namespace = p_namespace AND t.topic = p_topic), '0'),
        COALESCE((SELECT t.trimmed_id FROM outbox.topics t
                  WHERE t.namespace = p_namespace AND t.topic = p_topic), 0);
$$ LANGUAGE sql STABLE SECURITY INVOKER SET search_path = outbox, pg_temp;
