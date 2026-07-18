-- @group Inspection

-- @function presence.status
-- @brief Inspect one entity, with the wall-clock truth alongside the cache.
-- @param p_namespace Tenant namespace
-- @param p_entity Entity id
-- @returns The entity's liveness fields plus overdue; empty when not registered
-- @example SELECT * FROM presence.status('default', 'worker-7');
--
-- The status column is a cache that lags until the next sweep (P2, see
-- 001_tables.sql); overdue is the honest read - true when the entity is
-- nominally alive but its heartbeat is already past the liveness window on
-- the wall clock. Reads never mutate: an overdue entity stays 'alive' here
-- until sweep emits the death.
--
-- overdue uses the same exclusive rule as sweep: a timeout_override
-- REPLACES the kind's dead_after, never combines with it.
CREATE OR REPLACE FUNCTION presence.status(
    p_namespace text,
    p_entity text
)
RETURNS TABLE(
    entity_id text,
    kind text,
    status text,
    last_seen timestamptz,
    alive_since timestamptz,
    dead_since timestamptz,
    timeout_override interval,
    metadata jsonb,
    overdue boolean
) AS $$
DECLARE
    v_entity presence.entities;
    v_config presence.config;
BEGIN
    -- Validate inputs
    PERFORM presence._validate_namespace(p_namespace);
    PERFORM presence._validate_entity_id(p_entity);

    -- Warn if namespace mismatch with RLS context
    PERFORM presence._warn_namespace_mismatch(p_namespace);

    SELECT * INTO v_entity
    FROM presence.entities e
    WHERE e.namespace = p_namespace AND e.entity_id = p_entity;

    IF NOT FOUND THEN
        RETURN;
    END IF;

    v_config := presence._get_config(p_namespace, v_entity.kind);

    RETURN QUERY SELECT
        v_entity.entity_id,
        v_entity.kind,
        v_entity.status,
        v_entity.last_seen,
        v_entity.alive_since,
        v_entity.dead_since,
        v_entity.timeout_override,
        v_entity.metadata,
        v_entity.status = 'alive' AND (
            (v_entity.timeout_override IS NULL
             AND v_entity.last_seen < clock_timestamp() - v_config.dead_after)
            OR (v_entity.timeout_override IS NOT NULL
                AND v_entity.last_seen < clock_timestamp() - v_entity.timeout_override)
        );
END;
$$ LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = presence, pg_temp;


-- @function presence.list
-- @brief List entities in a namespace.
-- @param p_namespace Tenant namespace
-- @param p_kind Kind filter (NULL = all kinds)
-- @param p_status Status filter (NULL = all statuses)
-- @returns Entity rows, per kind and entity id
-- @example SELECT * FROM presence.list('default', p_status := 'dead');
CREATE OR REPLACE FUNCTION presence.list(
    p_namespace text,
    p_kind text DEFAULT NULL,
    p_status text DEFAULT NULL
)
RETURNS SETOF presence.entities AS $$
BEGIN
    -- Validate inputs
    PERFORM presence._validate_namespace(p_namespace);
    IF p_kind IS NOT NULL THEN
        PERFORM presence._validate_kind(p_kind);
    END IF;
    IF p_status IS NOT NULL AND p_status NOT IN ('unknown', 'alive', 'dead') THEN
        RAISE EXCEPTION 'Status filter must be unknown, alive, or dead (got: %)', p_status
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:presence:VAL_STATUS_INVALID';
    END IF;

    -- Warn if namespace mismatch with RLS context
    PERFORM presence._warn_namespace_mismatch(p_namespace);

    RETURN QUERY
    SELECT e.*
    FROM presence.entities e
    WHERE e.namespace = p_namespace
      AND (p_kind IS NULL OR e.kind = p_kind)
      AND (p_status IS NULL OR e.status = p_status)
    ORDER BY e.kind, e.entity_id;
END;
$$ LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = presence, pg_temp;


-- @function presence.get_transitions
-- @brief Read the transition history, newest first.
-- @param p_namespace Tenant namespace
-- @param p_entity Entity filter (NULL = all entities)
-- @param p_limit Maximum transitions to return
-- @returns Transition rows with actor context
-- @example SELECT * FROM presence.get_transitions('default', 'worker-7');
--
-- History, not a feed: do not poll this by id (see the transitions table
-- comment). Delivery is the queue hooks and NOTIFY.
CREATE OR REPLACE FUNCTION presence.get_transitions(
    p_namespace text,
    p_entity text DEFAULT NULL,
    p_limit int DEFAULT 100
)
RETURNS SETOF presence.transitions AS $$
BEGIN
    PERFORM presence._validate_namespace(p_namespace);
    IF p_entity IS NOT NULL THEN
        PERFORM presence._validate_entity_id(p_entity);
    END IF;
    PERFORM presence._validate_limit(p_limit, 'limit', 1000);
    PERFORM presence._warn_namespace_mismatch(p_namespace);

    RETURN QUERY
    SELECT t.*
    FROM presence.transitions t
    WHERE t.namespace = p_namespace
      AND (p_entity IS NULL OR t.entity_id = p_entity)
    ORDER BY t.at DESC, t.id DESC
    LIMIT p_limit;
END;
$$ LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = presence, pg_temp;


-- @function presence.get_stats
-- @brief Get namespace-wide presence statistics.
-- @param p_namespace Tenant namespace
-- @returns Row with total_entities, alive, dead, unknown, overdue,
--          total_transitions
-- @example SELECT * FROM presence.get_stats('default');
--
-- overdue counts nominally-alive entities already past their liveness
-- window on the wall clock (the same exclusive override rule as sweep) -
-- deaths the next sweep will emit.
CREATE OR REPLACE FUNCTION presence.get_stats(p_namespace text)
RETURNS TABLE(
    total_entities bigint,
    alive bigint,
    dead bigint,
    unknown bigint,
    overdue bigint,
    total_transitions bigint
) AS $$
BEGIN
    PERFORM presence._validate_namespace(p_namespace);
    PERFORM presence._warn_namespace_mismatch(p_namespace);

    RETURN QUERY
    SELECT
        (SELECT COUNT(*) FROM presence.entities e WHERE e.namespace = p_namespace),
        (SELECT COUNT(*) FROM presence.entities e
         WHERE e.namespace = p_namespace AND e.status = 'alive'),
        (SELECT COUNT(*) FROM presence.entities e
         WHERE e.namespace = p_namespace AND e.status = 'dead'),
        (SELECT COUNT(*) FROM presence.entities e
         WHERE e.namespace = p_namespace AND e.status = 'unknown'),
        (SELECT COUNT(*)
         FROM presence.entities e,
              LATERAL presence._get_config(e.namespace, e.kind) cfg
         WHERE e.namespace = p_namespace
           AND e.status = 'alive'
           AND (
               (e.timeout_override IS NULL
                AND e.last_seen < clock_timestamp() - cfg.dead_after)
               OR (e.timeout_override IS NOT NULL
                   AND e.last_seen < clock_timestamp() - e.timeout_override)
           )),
        (SELECT COUNT(*) FROM presence.transitions t WHERE t.namespace = p_namespace);
END;
$$ LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = presence, pg_temp;
