-- @group Register

-- @function presence.register
-- @brief Register an entity for liveness tracking, or update its attributes.
-- @param p_namespace Tenant namespace
-- @param p_entity Entity id (e.g. 'worker-7', 'sensor:eu:42')
-- @param p_kind Entity kind, keys the config row. NULL means 'default' for
--        a new entity and keeps the current kind on re-register
-- @param p_timeout Per-entity liveness window replacing the kind's
--        dead_after. NULL keeps the current override; clearing one back to
--        the kind default is a direct UPDATE of timeout_override (an
--        ergonomic clear parameter is backlog)
-- @param p_metadata Metadata stored on the entity. NULL keeps the existing
--        metadata on re-register; new entities store '{}' when NULL
-- @returns The entity row
-- @example SELECT * FROM presence.register('default', 'worker-7');
--
-- Registration is explicit and idempotent: deploys re-run register safely
-- because NULL arguments preserve what is stored. Re-register is an
-- attribute update, NOT a heartbeat and NOT a transition - status and
-- last_seen are untouched, and liveness only ever changes through
-- heartbeat and sweep. A new entity starts at 'unknown' and cannot be
-- swept dead before its first heartbeat.
CREATE OR REPLACE FUNCTION presence.register(
    p_namespace text,
    p_entity text,
    p_kind text DEFAULT NULL,
    p_timeout interval DEFAULT NULL,
    p_metadata jsonb DEFAULT NULL
)
RETURNS presence.entities AS $$
DECLARE
    v_actor record;
    v_row presence.entities;
BEGIN
    -- Validate inputs
    PERFORM presence._validate_namespace(p_namespace);
    PERFORM presence._validate_entity_id(p_entity);
    IF p_kind IS NOT NULL THEN
        PERFORM presence._validate_kind(p_kind);
    END IF;
    PERFORM presence._validate_timeout(p_timeout);

    -- Warn if namespace mismatch with RLS context
    PERFORM presence._warn_namespace_mismatch(p_namespace);

    -- Get actor context
    SELECT * INTO v_actor FROM presence._get_actor_context();

    INSERT INTO presence.entities (
        namespace, entity_id, kind, timeout_override, metadata,
        actor_id, request_id, on_behalf_of, reason
    )
    VALUES (
        p_namespace, p_entity, COALESCE(p_kind, 'default'), p_timeout,
        COALESCE(p_metadata, '{}'),
        v_actor.actor_id, v_actor.request_id, v_actor.on_behalf_of, v_actor.reason
    )
    ON CONFLICT (namespace, entity_id) DO UPDATE
    SET kind = COALESCE(p_kind, presence.entities.kind),
        timeout_override = COALESCE(p_timeout, presence.entities.timeout_override),
        metadata = COALESCE(p_metadata, presence.entities.metadata),
        actor_id = v_actor.actor_id,
        request_id = v_actor.request_id,
        on_behalf_of = v_actor.on_behalf_of,
        reason = v_actor.reason,
        updated_at = clock_timestamp()
    RETURNING * INTO v_row;

    RETURN v_row;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = presence, pg_temp;


-- @function presence.deregister
-- @brief Remove an entity deliberately, emitting a departed transition.
-- @param p_namespace Tenant namespace
-- @param p_entity Entity id
-- @returns True if the entity existed and was removed, false otherwise
--          (idempotent - never raises for an absent entity)
-- @example SELECT presence.deregister('default', 'worker-7');
--
-- Intentional exit is not death (P4, see 001_tables.sql): the transition
-- type is 'departed', death hooks never fire, and nobody gets paged for a
-- planned shutdown. The row is deleted; re-registering recreates the
-- entity at 'unknown'. The transitions history survives.
CREATE OR REPLACE FUNCTION presence.deregister(
    p_namespace text,
    p_entity text
)
RETURNS boolean AS $$
DECLARE
    v_entity presence.entities;
    v_config presence.config;
    v_transition presence.transitions;
BEGIN
    -- Validate inputs
    PERFORM presence._validate_namespace(p_namespace);
    PERFORM presence._validate_entity_id(p_entity);

    -- Warn if namespace mismatch with RLS context
    PERFORM presence._warn_namespace_mismatch(p_namespace);

    SELECT * INTO v_entity
    FROM presence.entities e
    WHERE e.namespace = p_namespace AND e.entity_id = p_entity
    FOR UPDATE;

    IF NOT FOUND THEN
        RETURN false;
    END IF;

    v_config := presence._get_config(p_namespace, v_entity.kind);
    v_transition := presence._record_transition(v_entity, v_config, 'departed');

    DELETE FROM presence.entities e
    WHERE e.namespace = p_namespace AND e.entity_id = p_entity;

    PERFORM presence._notify_if_enabled(v_config, v_transition);

    RETURN true;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = presence, pg_temp;
