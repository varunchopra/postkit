-- @group Heartbeat

-- @function presence._heartbeat_one
-- @brief Heartbeat a single entity; NULL result means the entity is unknown.
-- @param p_namespace Tenant namespace
-- @param p_entity Entity id
-- @returns The resulting status, or NULL when the entity is not registered
-- Shared by heartbeat (which raises on NULL) and heartbeat_many (which
-- reports 'unknown' instead - one typo must not abort a fleet batch).
--
-- The coalesce fast path reads without locking: a stale read costs at most
-- one redundant write, and skipping the row lock is the point of
-- heartbeat_coalesce (the user-presence write-rate valve). Only the locked
-- path below writes or emits transitions (P1, see 001_tables.sql).
CREATE OR REPLACE FUNCTION presence._heartbeat_one(
    p_namespace text,
    p_entity text
)
RETURNS text AS $$
DECLARE
    v_entity presence.entities;
    v_config presence.config;
    v_transition presence.transitions;
    v_now timestamptz;
BEGIN
    SELECT * INTO v_entity
    FROM presence.entities e
    WHERE e.namespace = p_namespace AND e.entity_id = p_entity;

    IF NOT FOUND THEN
        RETURN NULL;
    END IF;

    v_config := presence._get_config(p_namespace, v_entity.kind);

    IF v_config.heartbeat_coalesce > interval '0'
       AND v_entity.status = 'alive'
       AND v_entity.last_seen > clock_timestamp() - v_config.heartbeat_coalesce THEN
        RETURN 'alive';
    END IF;

    SELECT * INTO v_entity
    FROM presence.entities e
    WHERE e.namespace = p_namespace AND e.entity_id = p_entity
    FOR UPDATE;

    IF NOT FOUND THEN
        -- Deregistered between the unlocked read and the lock
        RETURN NULL;
    END IF;

    -- Wall clock, captured after the lock is held: the wait above and the
    -- caller's transaction start must not backdate the heartbeat (P3, see
    -- 001_tables.sql).
    v_now := clock_timestamp();

    IF v_entity.status IN ('unknown', 'dead') THEN
        -- Revival (or first contact) is captured HERE, never deferred to
        -- sweep (P2). Revival also clears a deferred death hook: the flap
        -- storm ended alive, so there is no terminal alert to deliver.
        v_transition := presence._record_transition(v_entity, v_config, 'alive');

        UPDATE presence.entities e
        SET status = 'alive',
            last_seen = v_now,
            alive_since = v_now,
            dead_since = NULL,
            hook_suppressed = false,
            updated_at = v_now
        WHERE e.namespace = p_namespace AND e.entity_id = p_entity;

        PERFORM presence._notify_if_enabled(v_config, v_transition);
        IF NOT v_transition.flapping THEN
            PERFORM presence._fire_hooks(
                v_config, p_namespace, p_entity, v_entity.kind,
                v_entity.status, 'alive', v_transition.at
            );
        END IF;
    ELSE
        UPDATE presence.entities e
        SET last_seen = v_now,
            updated_at = v_now
        WHERE e.namespace = p_namespace AND e.entity_id = p_entity;
    END IF;

    RETURN 'alive';
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = presence, pg_temp;


-- @function presence.heartbeat
-- @brief Report an entity alive.
-- @param p_namespace Tenant namespace
-- @param p_entity Entity id (must be registered)
-- @returns The resulting status (always 'alive')
-- @example SELECT presence.heartbeat('default', 'worker-7');
--
-- Updates last_seen on the wall clock. A dead or never-seen entity revives
-- here and now - the revival transition is emitted by this call, never
-- deferred to a sweep tick. An unregistered entity raises: registration is
-- explicit, and silently auto-registering would hide typos as phantom
-- entities (heartbeat_many reports 'unknown' instead of raising - the
-- documented batch asymmetry).
CREATE OR REPLACE FUNCTION presence.heartbeat(
    p_namespace text,
    p_entity text
)
RETURNS text AS $$
DECLARE
    v_status text;
BEGIN
    -- Validate inputs
    PERFORM presence._validate_namespace(p_namespace);
    PERFORM presence._validate_entity_id(p_entity);

    -- Warn if namespace mismatch with RLS context
    PERFORM presence._warn_namespace_mismatch(p_namespace);

    v_status := presence._heartbeat_one(p_namespace, p_entity);

    IF v_status IS NULL THEN
        RAISE EXCEPTION 'Entity % is not registered (call presence.register first)', p_entity
            USING ERRCODE = 'no_data_found',
                  HINT = 'postkit:presence:ENTITY_UNKNOWN';
    END IF;

    RETURN v_status;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = presence, pg_temp;


-- @function presence.heartbeat_many
-- @brief Report a batch of entities alive in one round trip.
-- @param p_namespace Tenant namespace
-- @param p_entities Entity ids
-- @returns One row per distinct entity: its resulting status, or 'unknown'
--          for entities that are not registered (no row is created)
-- @example SELECT * FROM presence.heartbeat_many('default', ARRAY['w1', 'w2']);
--
-- Per-entity semantics match heartbeat, including revivals - a revival
-- inside the batch is visible in the returned status the same way. Unknown
-- entities are reported, not raised: one typo must not abort a
-- 500-entity fleet batch (the documented asymmetry with heartbeat, which
-- raises).
--
-- Rows are locked in entity_id order so two overlapping batches cannot
-- deadlock against each other.
CREATE OR REPLACE FUNCTION presence.heartbeat_many(
    p_namespace text,
    p_entities text[]
)
RETURNS TABLE (
    entity_id text,
    status text
) AS $$
DECLARE
    v_entity text;
    v_status text;
BEGIN
    -- Validate inputs
    PERFORM presence._validate_namespace(p_namespace);
    IF p_entities IS NULL THEN
        RAISE EXCEPTION 'Entities array cannot be null'
            USING ERRCODE = 'null_value_not_allowed',
                  HINT = 'postkit:presence:VAL_ENTITIES_NULL';
    END IF;

    -- Warn if namespace mismatch with RLS context
    PERFORM presence._warn_namespace_mismatch(p_namespace);

    FOR v_entity IN SELECT DISTINCT e FROM unnest(p_entities) AS e ORDER BY e
    LOOP
        PERFORM presence._validate_entity_id(v_entity);
        v_status := presence._heartbeat_one(p_namespace, v_entity);
        entity_id := v_entity;
        status := COALESCE(v_status, 'unknown');
        RETURN NEXT;
    END LOOP;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = presence, pg_temp;
