-- @group Emit

-- @function outbox.emit
-- @brief Append an event inside the caller's transaction.
-- @param p_namespace Tenant namespace
-- @param p_topic Topic name
-- @param p_type Event type (consumers switch on this)
-- @param p_payload Event payload (JSONB)
-- @param p_key Optional entity key, an aid for downstream sharding
-- @returns The event id
-- @example SELECT outbox.emit('default', 'orders', 'order.created', '{"order_id": 42}');
--
-- Call this inside the same transaction as the state change it describes.
-- That is the point of the module (O2, see 001_tables.sql): the event then
-- exists exactly when the state change committed, so there is no dual-write
-- problem. An emit in its own transaction produces an event describing
-- nothing.
--
-- Sends a NOTIFY wake-up on the topic channel when configured. NOTIFY is
-- delivered only on commit, so the wake-up cannot precede the event.
CREATE OR REPLACE FUNCTION outbox.emit(
    p_namespace text,
    p_topic text,
    p_type text,
    p_payload jsonb,
    p_key text DEFAULT NULL
)
RETURNS bigint AS $$
DECLARE
    v_config outbox.config;
    v_actor record;
    v_id bigint;
BEGIN
    -- Validate inputs
    PERFORM outbox._validate_namespace(p_namespace);
    PERFORM outbox._validate_topic(p_topic);
    PERFORM outbox._validate_event_type(p_type);

    IF p_payload IS NULL THEN
        RAISE EXCEPTION 'Payload cannot be null'
            USING ERRCODE = 'null_value_not_allowed',
                  HINT = 'postkit:outbox:VAL_PAYLOAD_NULL';
    END IF;

    -- Warn if namespace mismatch with RLS context
    PERFORM outbox._warn_namespace_mismatch(p_namespace);

    v_config := outbox._get_config(p_namespace, p_topic);
    PERFORM outbox._ensure_topic(p_namespace, p_topic);

    -- Get actor context
    SELECT * INTO v_actor FROM outbox._get_actor_context();

    INSERT INTO outbox.events (
        namespace, topic, event_type, key, payload,
        actor_id, request_id, on_behalf_of, reason
    )
    VALUES (
        p_namespace, p_topic, p_type, p_key, p_payload,
        v_actor.actor_id, v_actor.request_id, v_actor.on_behalf_of, v_actor.reason
    )
    RETURNING id INTO v_id;

    PERFORM outbox._notify_if_enabled(v_config, p_namespace, p_topic, v_id);

    RETURN v_id;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = outbox, pg_temp;
