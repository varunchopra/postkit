-- @group Acquire

-- @function lease.acquire
-- @brief Acquire or take over a named lease.
-- @param p_namespace Tenant namespace
-- @param p_name Lease name (e.g. 'scheduler', 'exporter:cust_42')
-- @param p_holder Opaque holder identity (hostname, pod name, worker ID)
-- @param p_ttl Lease duration (default from config; capped at max_ttl)
-- @param p_metadata Metadata stored on the lease. NULL keeps the existing
--        metadata on a live same-holder re-acquire; new acquisitions and
--        takeovers store '{}' when NULL
-- @returns acquired flag, fence token (NULL when the lease is held by another
--          live holder), expiry, and current holder. On a lock timeout (a
--          competing transaction held the row for more than 2 seconds) the
--          result is acquired=false with all other columns NULL – the holder
--          is unknown; callers treat it like any contended miss and retry.
-- @example SELECT * FROM lease.acquire('default', 'scheduler', 'worker-1');
--
-- Non-blocking with respect to lease lifetime: a live lease held by someone
-- else returns acquired=false immediately with the current holder and expiry
-- for observability – there is no wait queue. The held-by-other case is
-- answered by a lock-free fast path, so contended acquires do not queue
-- behind each other or behind open verify transactions; only the paths that
-- may grant take locks, and those waits are bounded by a 2 second lock
-- timeout that surfaces as a plain miss.
--
-- Expiry uses the wall clock (clock_timestamp), not the transaction start
-- time, so acquiring inside a long transaction cannot backdate or stretch a
-- lease.
--
-- Branch semantics:
--   - Free or expired: caller becomes holder with a NEW fence token. Taking
--     over an expired lease is event-logged as 'taken_over' – including
--     re-acquiring your OWN expired lease, which also gets a new fence (a
--     holder that let its lease expire must never keep fencing on the old
--     token).
--   - Live, same holder: renew semantics – expiry extends, metadata is
--     updated when passed (NULL keeps what is there; unlike lease.renew,
--     which never touches metadata), and the fence token is UNCHANGED. Not
--     event-logged.
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
    p_metadata jsonb DEFAULT NULL
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
    v_now timestamptz;
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

    -- Fast path: a live lease held by someone else is a miss, answered from
    -- an unlocked read. A stale read is harmless – the caller's poll loop
    -- retries – and skipping the locks here is what keeps contended acquires
    -- from queueing behind each other or behind open verify transactions.
    -- Only the locked path below may grant.
    SELECT * INTO v_lease
    FROM lease.leases l
    WHERE l.namespace = p_namespace AND l.name = p_name;

    IF FOUND AND v_lease.holder_id != p_holder
       AND v_lease.expires_at > clock_timestamp() THEN
        RETURN QUERY SELECT false, NULL::bigint, v_lease.expires_at, v_lease.holder_id;
        RETURN;
    END IF;

    -- Get actor context
    SELECT * INTO v_actor FROM lease._get_actor_context();

    -- Per-name mutex: uniform lock order counter -> lease (see _lock_name)
    PERFORM lease._lock_name(p_namespace, p_name);

    SELECT * INTO v_lease
    FROM lease.leases l
    WHERE l.namespace = p_namespace AND l.name = p_name
    FOR UPDATE;

    -- Wall clock, captured once AFTER the lock is held (the wait above can
    -- last up to the lock timeout, and stamping a pre-wait time would
    -- backdate the lease) so expires_at - acquired_at equals the ttl
    -- exactly. now() would pin to the transaction start with the same
    -- backdating effect.
    v_now := clock_timestamp();

    IF NOT FOUND THEN
        -- Free: become holder. Plain INSERT cannot conflict – the name mutex
        -- serializes concurrent first-acquires.
        v_fence := lease._next_fence(p_namespace, p_name);
        v_expires := v_now + v_ttl;

        INSERT INTO lease.leases (
            namespace, name, holder_id, fence_token,
            acquired_at, expires_at, metadata,
            actor_id, request_id, on_behalf_of, reason
        )
        VALUES (
            p_namespace, p_name, p_holder, v_fence,
            v_now, v_expires, COALESCE(p_metadata, '{}'),
            v_actor.actor_id, v_actor.request_id, v_actor.on_behalf_of, v_actor.reason
        );

        PERFORM lease._log_event(p_namespace, p_name, 'acquired', p_holder, v_fence);
        RETURN QUERY SELECT true, v_fence, v_expires, p_holder;

    ELSIF v_lease.expires_at <= v_now THEN
        -- Expired: take over with a NEW fence, even if the previous holder
        -- is the caller itself (invariant I3, see 001_tables.sql).
        v_fence := lease._next_fence(p_namespace, p_name);
        v_expires := v_now + v_ttl;

        UPDATE lease.leases l
        SET holder_id = p_holder,
            fence_token = v_fence,
            acquired_at = v_now,
            expires_at = v_expires,
            metadata = COALESCE(p_metadata, '{}'),
            actor_id = v_actor.actor_id,
            request_id = v_actor.request_id,
            on_behalf_of = v_actor.on_behalf_of,
            reason = v_actor.reason,
            updated_at = v_now
        WHERE l.namespace = p_namespace AND l.name = p_name;

        PERFORM lease._log_event(
            p_namespace, p_name, 'taken_over', p_holder, v_fence,
            v_lease.holder_id
        );
        RETURN QUERY SELECT true, v_fence, v_expires, p_holder;

    ELSIF v_lease.holder_id = p_holder THEN
        -- Live, same holder: renew semantics, SAME fence. No event (renewals
        -- are not logged – see lease.events schema note). Unlike the branches
        -- above, NULL metadata falls back to the stored value, not '{}':
        -- keepalive re-acquires must not wipe it.
        v_expires := v_now + v_ttl;

        UPDATE lease.leases l
        SET expires_at = v_expires,
            metadata = COALESCE(p_metadata, l.metadata),
            updated_at = v_now
        WHERE l.namespace = p_namespace AND l.name = p_name;

        RETURN QUERY SELECT true, v_lease.fence_token, v_expires, p_holder;

    ELSE
        -- Live, other holder: no write, no event. Reached when the fast-path
        -- read was stale and the lease turned out live under the lock.
        RETURN QUERY SELECT false, NULL::bigint, v_lease.expires_at, v_lease.holder_id;
    END IF;

-- The EXCEPTION clause makes this whole block a subtransaction – a savepoint
-- per acquire call. That cost is accepted on this poll-path function; it is
-- what lets a lock timeout surface as a clean miss instead of an error. The
-- 2 second lock_timeout below belongs to acquire alone; verify deliberately
-- has none (see 030_verify.sql).
EXCEPTION WHEN lock_not_available THEN
    RETURN QUERY SELECT false, NULL::bigint, NULL::timestamptz, NULL::text;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER
   SET search_path = lease, pg_temp
   SET lock_timeout = '2s';
