-- @group Acquire

-- @function lease.acquire
-- @brief Acquire or take over a named lease.
-- @param p_namespace Tenant namespace
-- @param p_name Lease name (e.g. 'scheduler', 'exporter:cust_42')
-- @param p_holder Opaque holder identity (hostname, pod name, worker ID)
-- @param p_ttl Lease duration (default from config; capped at max_ttl)
-- @param p_metadata Optional metadata stored on the lease
-- @returns acquired flag, fence token (NULL when the lease is held by another
--          live holder), expiry, and current holder
-- @example SELECT * FROM lease.acquire('default', 'scheduler', 'worker-1');
--
-- Non-blocking with respect to lease lifetime: a live lease held by someone
-- else returns acquired=false immediately with the current holder and expiry
-- for observability – there is no wait queue. Contended acquires do
-- serialize behind in-flight row locks (including verify transactions on the
-- same name); a lock-free fast path for the held-by-other case is a known
-- future optimization.
--
-- Branch semantics:
--   - Free or expired: caller becomes holder with a NEW fence token. Taking
--     over an expired lease is event-logged as 'taken_over' – including
--     re-acquiring your OWN expired lease, which also gets a new fence (a
--     holder that let its lease expire must never keep fencing on the old
--     token).
--   - Live, same holder: renew semantics – expiry extends, metadata is
--     updated (unlike lease.renew, which leaves metadata untouched), and the
--     fence token is UNCHANGED. Not event-logged.
--   - Live, other holder: no write; returns (false, NULL, expiry, holder).
--
-- Do not call verify then acquire on the same name inside one transaction:
-- that inverts the module's lock order and can abort with deadlock_detected
-- (40P01) under concurrency – retryable, but avoidable.
CREATE OR REPLACE FUNCTION lease.acquire(
    p_namespace text,
    p_name text,
    p_holder text,
    p_ttl interval DEFAULT NULL,
    p_metadata jsonb DEFAULT '{}'
)
RETURNS TABLE(
    acquired boolean,
    fence_token bigint,
    expires_at timestamptz,
    current_holder text
) AS $$
DECLARE
    v_config lease.config;
    v_ttl interval;
    v_lease lease.leases;
    v_fence bigint;
    v_expires timestamptz;
    v_actor record;
BEGIN
    -- Validate inputs
    PERFORM lease._validate_namespace(p_namespace);
    PERFORM lease._validate_lease_name(p_name);
    PERFORM lease._validate_holder(p_holder);

    -- Warn if namespace mismatch with RLS context
    PERFORM lease._warn_namespace_mismatch(p_namespace);

    -- Get config for defaults and TTL cap
    v_config := lease._get_config(p_namespace);
    PERFORM lease._validate_ttl(p_ttl, v_config.max_ttl);
    v_ttl := COALESCE(p_ttl, v_config.default_ttl);

    -- Get actor context
    SELECT * INTO v_actor FROM lease._get_actor_context();

    -- Per-name mutex: uniform lock order counter -> lease (see _lock_name)
    PERFORM lease._lock_name(p_namespace, p_name);

    SELECT * INTO v_lease
    FROM lease.leases l
    WHERE l.namespace = p_namespace AND l.name = p_name
    FOR UPDATE;

    IF NOT FOUND THEN
        -- Free: become holder. Plain INSERT cannot conflict – the name mutex
        -- serializes concurrent first-acquires.
        v_fence := lease._next_fence(p_namespace, p_name);
        v_expires := now() + v_ttl;

        INSERT INTO lease.leases (
            namespace, name, holder_id, fence_token,
            acquired_at, expires_at, metadata,
            actor_id, request_id, on_behalf_of, reason
        )
        VALUES (
            p_namespace, p_name, p_holder, v_fence,
            now(), v_expires, COALESCE(p_metadata, '{}'),
            v_actor.actor_id, v_actor.request_id, v_actor.on_behalf_of, v_actor.reason
        );

        PERFORM lease._log_event(p_namespace, p_name, 'acquired', p_holder, v_fence);
        RETURN QUERY SELECT true, v_fence, v_expires, p_holder;

    ELSIF v_lease.expires_at <= now() THEN
        -- Expired: take over with a NEW fence, even if the previous holder
        -- is the caller itself (invariant I3, see 001_tables.sql).
        v_fence := lease._next_fence(p_namespace, p_name);
        v_expires := now() + v_ttl;

        UPDATE lease.leases l
        SET holder_id = p_holder,
            fence_token = v_fence,
            acquired_at = now(),
            expires_at = v_expires,
            metadata = COALESCE(p_metadata, '{}'),
            actor_id = v_actor.actor_id,
            request_id = v_actor.request_id,
            on_behalf_of = v_actor.on_behalf_of,
            reason = v_actor.reason,
            updated_at = now()
        WHERE l.namespace = p_namespace AND l.name = p_name;

        PERFORM lease._log_event(
            p_namespace, p_name, 'taken_over', p_holder, v_fence,
            v_lease.holder_id
        );
        RETURN QUERY SELECT true, v_fence, v_expires, p_holder;

    ELSIF v_lease.holder_id = p_holder THEN
        -- Live, same holder: renew semantics, SAME fence. No event (renewals
        -- are not logged – see lease.events schema note).
        v_expires := now() + v_ttl;

        UPDATE lease.leases l
        SET expires_at = v_expires,
            metadata = COALESCE(p_metadata, '{}'),
            updated_at = now()
        WHERE l.namespace = p_namespace AND l.name = p_name;

        RETURN QUERY SELECT true, v_lease.fence_token, v_expires, p_holder;

    ELSE
        -- Live, other holder: no write, no event.
        RETURN QUERY SELECT false, NULL::bigint, v_lease.expires_at, v_lease.holder_id;
    END IF;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = lease, pg_temp;
