-- @group Internal

-- @function presence._get_config
-- @brief Get effective configuration for a kind.
-- @param p_namespace Namespace to get config for
-- @param p_kind Kind to get config for
-- @returns Config record with fallback
-- Fallback order: (namespace, kind) -> (namespace, 'default') ->
-- ('global', 'default'). Deliberately no ('global', kind) step: global
-- rows for tenant-defined kinds are incoherent.
CREATE OR REPLACE FUNCTION presence._get_config(p_namespace text, p_kind text)
RETURNS presence.config AS $$
DECLARE
    v_config presence.config;
BEGIN
    SELECT * INTO v_config
    FROM presence.config
    WHERE namespace = p_namespace AND kind = p_kind;

    IF FOUND THEN
        RETURN v_config;
    END IF;

    SELECT * INTO v_config
    FROM presence.config
    WHERE namespace = p_namespace AND kind = 'default';

    IF FOUND THEN
        RETURN v_config;
    END IF;

    SELECT * INTO v_config
    FROM presence.config
    WHERE namespace = 'global' AND kind = 'default';

    -- If no global config (shouldn't happen), return defaults
    IF NOT FOUND THEN
        v_config.namespace := 'global';
        v_config.kind := 'default';
        v_config.dead_after := interval '90 seconds';
        v_config.heartbeat_coalesce := interval '0';
        v_config.flap_threshold := 4;
        v_config.flap_window := interval '10 minutes';
        v_config.notify := true;
    END IF;

    RETURN v_config;
END;
$$ LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = presence, pg_temp;


-- @function presence._record_transition
-- @brief Append a transitions row and advance the entity's flap state.
-- @param p_entity The entity row BEFORE the transition (caller holds its row lock)
-- @param p_config Effective config for the entity's kind (caller already fetched it)
-- @param p_to_status Target status ('alive', 'dead', 'departed')
-- @param p_silent_for For deaths: how long the entity was silent
-- @returns The inserted transitions row, flapping set
-- Call ONLY with the entity row locked; the flap read-modify-write and the
-- exactly-once guarantee (P1, see 001_tables.sql) depend on it.
--
-- Flap algorithm: if flap_window_started is NULL or older than flap_window,
-- the window resets (count 1); otherwise the count increments. flapping is
-- count > flap_threshold. Both real edges count (death and revival);
-- departed never counts and is never marked flapping.
CREATE OR REPLACE FUNCTION presence._record_transition(
    p_entity presence.entities,
    p_config presence.config,
    p_to_status text,
    p_silent_for interval DEFAULT NULL
)
RETURNS presence.transitions AS $$
DECLARE
    v_actor record;
    v_count int;
    v_started timestamptz;
    v_flapping boolean := false;
    v_transition presence.transitions;
BEGIN
    IF p_to_status != 'departed' THEN
        IF p_entity.flap_window_started IS NULL
           OR p_entity.flap_window_started < clock_timestamp() - p_config.flap_window THEN
            v_count := 1;
            v_started := clock_timestamp();
        ELSE
            v_count := p_entity.flap_count + 1;
            v_started := p_entity.flap_window_started;
        END IF;
        v_flapping := v_count > p_config.flap_threshold;

        UPDATE presence.entities e
        SET flap_count = v_count,
            flap_window_started = v_started
        WHERE e.namespace = p_entity.namespace
          AND e.entity_id = p_entity.entity_id;
    END IF;

    SELECT * INTO v_actor FROM presence._get_actor_context();

    INSERT INTO presence.transitions (
        namespace, entity_id, kind, from_status, to_status,
        silent_for, flapping,
        actor_id, request_id, on_behalf_of, reason
    )
    VALUES (
        p_entity.namespace, p_entity.entity_id, p_entity.kind,
        p_entity.status, p_to_status,
        p_silent_for, v_flapping,
        v_actor.actor_id, v_actor.request_id, v_actor.on_behalf_of, v_actor.reason
    )
    RETURNING * INTO v_transition;

    RETURN v_transition;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = presence, pg_temp;


-- @function presence._notify_if_enabled
-- @brief Send NOTIFY for a transition if configured and not flapping.
-- @param p_config Config record (caller already fetched it)
-- @param p_transition The transition to announce
-- Channel name: presence_{md5(namespace/kind)}. Hash the channel name to
-- fit PostgreSQL's 63-byte identifier limit: without hashing, long
-- namespace + kind names get silently truncated, causing unrelated kinds
-- to share a channel. md5 is non-cryptographic here; replace with pgcrypto
-- where md5 is prohibited. NOTIFY is transactional, so the wake-up is
-- delivered only if the emitting transaction commits; the payload is a
-- hint, never correctness. Suppressed while flapping (P5, see
-- 001_tables.sql).
CREATE OR REPLACE FUNCTION presence._notify_if_enabled(
    p_config presence.config,
    p_transition presence.transitions
)
RETURNS void AS $$
DECLARE
    v_channel text;
BEGIN
    IF p_config.notify AND NOT p_transition.flapping THEN
        v_channel := 'presence_'
            || md5(p_transition.namespace || '/' || p_transition.kind);
        PERFORM pg_notify(v_channel, jsonb_build_object(
            'entity_id', p_transition.entity_id,
            'from', p_transition.from_status,
            'to', p_transition.to_status
        )::text);
    END IF;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = presence, pg_temp;


-- @function presence._fire_hooks
-- @brief Push the configured queue job for a death or revival edge.
-- @param p_config Effective config (carries the queue targets)
-- @param p_namespace Tenant namespace
-- @param p_entity_id Entity that transitioned
-- @param p_kind Entity kind
-- @param p_from_status Status before the edge
-- @param p_to_status Status after the edge ('dead' or 'alive')
-- @param p_at When the edge happened (for a deferred death fire, the REAL
--        death time - the entity row's dead_since - not the sweep's time)
-- @param p_silent_for For deaths: how long the entity was silent
--
-- queue is a soft dependency: presence installs and runs without it, and
-- this function is reached only when a hook target is configured. If the
-- target is set but queue is absent, or the queue name is wrong
-- (queue.push's own error propagates - deliberately not caught), the sweep
-- or heartbeat FAILS LOUDLY: a liveness system that quietly stops alerting
-- is worse than one that stops visibly. Fix the config or remove the hook.
--
-- The push runs inside the caller's transaction: the death and its alert
-- job commit together, which is the module's atomicity argument.
CREATE OR REPLACE FUNCTION presence._fire_hooks(
    p_config presence.config,
    p_namespace text,
    p_entity_id text,
    p_kind text,
    p_from_status text,
    p_to_status text,
    p_at timestamptz,
    p_silent_for interval DEFAULT NULL
)
RETURNS void AS $$
DECLARE
    v_queue text;
BEGIN
    IF p_to_status = 'dead' THEN
        v_queue := p_config.on_death_queue;
    ELSIF p_to_status = 'alive' THEN
        v_queue := p_config.on_revival_queue;
    END IF;

    IF v_queue IS NULL THEN
        RETURN;
    END IF;

    IF to_regproc('queue.push') IS NULL THEN
        RAISE EXCEPTION 'Hook % is configured for kind % but the queue module is not installed',
            v_queue, p_kind
            USING ERRCODE = 'undefined_function',
                  HINT = 'postkit:presence:HOOK_QUEUE_MISSING';
    END IF;

    EXECUTE 'SELECT queue.push($1, $2, $3)'
    USING p_namespace, v_queue, jsonb_build_object(
        'namespace', p_namespace,
        'entity_id', p_entity_id,
        'kind', p_kind,
        'from', p_from_status,
        'to', p_to_status,
        'at', p_at,
        'silent_for', p_silent_for
    );
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = presence, pg_temp;
