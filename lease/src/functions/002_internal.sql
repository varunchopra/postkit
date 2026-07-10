-- @group Internal

-- @function lease._get_config
-- @brief Get effective configuration for a namespace.
-- @param p_namespace Namespace to get config for
-- @returns Config record with fallback to global defaults
-- Checks tenant config first, falls back to global.
CREATE OR REPLACE FUNCTION lease._get_config(p_namespace text)
RETURNS lease.config AS $$
DECLARE
    v_config lease.config;
BEGIN
    -- Try tenant-specific config first
    SELECT * INTO v_config
    FROM lease.config
    WHERE namespace = p_namespace;

    IF FOUND THEN
        RETURN v_config;
    END IF;

    -- Fall back to global config
    SELECT * INTO v_config
    FROM lease.config
    WHERE namespace = 'global';

    -- If no global config (shouldn't happen), return defaults
    IF NOT FOUND THEN
        v_config.namespace := 'global';
        v_config.default_ttl := '30 seconds'::interval;
        v_config.max_ttl := '1 hour'::interval;
        v_config.notify_on_release := false;
    END IF;

    RETURN v_config;
END;
$$ LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = lease, pg_temp;


-- @function lease._notify_if_enabled
-- @brief Send NOTIFY on lease release if configured.
-- @param p_config Config record (caller already fetched it)
-- @param p_namespace Tenant namespace for channel name
-- @param p_name Lease name for channel
-- Channel derivation lives in lease.channel_name, the public LISTEN contract.
CREATE OR REPLACE FUNCTION lease._notify_if_enabled(
    p_config lease.config,
    p_namespace text,
    p_name text
)
RETURNS void AS $$
BEGIN
    IF p_config.notify_on_release THEN
        PERFORM pg_notify(lease.channel_name(p_namespace, p_name), jsonb_build_object(
            'name', p_name,
            'event', 'released'
        )::text);
    END IF;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = lease, pg_temp;


-- @function lease._lock_name
-- @brief Take the per-name acquire mutex (the fence counter row).
-- @param p_namespace Tenant namespace
-- @param p_name Lease name
-- Upserts the counter row if absent, then locks it FOR UPDATE. The counter
-- row is the per-name acquire mutex: acquire always locks counter -> lease,
-- in that order, while renew/release/verify touch only the lease row. This
-- uniform lock order makes each lease function individually deadlock-free
-- and serializes concurrent first-acquires without a retry loop – do not
-- "simplify" this away or the first-acquire race returns.
--
-- The hierarchy covers the functions themselves. A caller COMPOSING
-- verify -> acquire on the same name inside one transaction holds a FOR
-- SHARE on the lease row while requesting this mutex, inverting the order
-- against a concurrent acquirer; Postgres detects that and aborts one
-- transaction (deadlock_detected, 40P01 – safe and retryable).
--
-- Returns void deliberately: the counter value here is NOT a fence token;
-- fences are issued only by _next_fence.
CREATE OR REPLACE FUNCTION lease._lock_name(p_namespace text, p_name text)
RETURNS void AS $$
BEGIN
    INSERT INTO lease.fence_counters (namespace, name)
    VALUES (p_namespace, p_name)
    ON CONFLICT (namespace, name) DO NOTHING;

    PERFORM 1
    FROM lease.fence_counters
    WHERE namespace = p_namespace AND name = p_name
    FOR UPDATE;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = lease, pg_temp;


-- @function lease._next_fence
-- @brief Issue the next fence token for a lease name.
-- @param p_namespace Tenant namespace
-- @param p_name Lease name
-- @returns The new fence token (strictly greater than all previously issued)
-- Must only be called with the name mutex held (_lock_name), so this is a
-- plain guarded UPDATE on an already-locked row. Tokens are monotonic per
-- (namespace, name); gaps are legal and expected (an acquisition that finds
-- the lease held does not consume a token, but other paths may).
CREATE OR REPLACE FUNCTION lease._next_fence(p_namespace text, p_name text)
RETURNS bigint AS $$
DECLARE
    v_fence bigint;
BEGIN
    UPDATE lease.fence_counters
    SET counter = counter + 1
    WHERE namespace = p_namespace AND name = p_name
    RETURNING counter INTO v_fence;

    IF v_fence IS NULL THEN
        RAISE EXCEPTION 'Fence counter missing for lease % (call _lock_name first)', p_name
            USING ERRCODE = 'internal_error',
                  HINT = 'postkit:lease:INT_COUNTER_MISSING';
    END IF;

    RETURN v_fence;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = lease, pg_temp;


-- @function lease._log_event
-- @brief Append a lease lifecycle event.
-- @param p_namespace Tenant namespace
-- @param p_name Lease name
-- @param p_event Event type: acquired, released, taken_over
-- @param p_holder Holder involved in the event
-- @param p_fence Fence token involved in the event
-- @param p_previous_holder Previous holder (taken_over only)
CREATE OR REPLACE FUNCTION lease._log_event(
    p_namespace text,
    p_name text,
    p_event text,
    p_holder text,
    p_fence bigint,
    p_previous_holder text DEFAULT NULL
)
RETURNS void AS $$
DECLARE
    v_actor record;
BEGIN
    SELECT * INTO v_actor FROM lease._get_actor_context();

    INSERT INTO lease.events (
        namespace, name, event, holder_id, fence_token, previous_holder,
        actor_id, request_id, on_behalf_of, reason
    )
    VALUES (
        p_namespace, p_name, p_event, p_holder, p_fence, p_previous_holder,
        v_actor.actor_id, v_actor.request_id, v_actor.on_behalf_of, v_actor.reason
    );
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = lease, pg_temp;
