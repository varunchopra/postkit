-- @group Renew and Release

-- @function lease.renew
-- @brief Extend a live lease you hold.
-- @param p_namespace Tenant namespace
-- @param p_name Lease name
-- @param p_holder Holder identity (must match the lease)
-- @param p_fence Fence token from acquire (must match the lease)
-- @param p_ttl New duration from now (default from config; capped at max_ttl)
-- @returns renewed flag and the new expiry (NULLs when not renewed)
-- @example SELECT * FROM lease.renew('default', 'scheduler', 'worker-1', 42);
--
-- Succeeds ONLY for a matching (holder, fence) on a LIVE lease. Renewing an
-- expired lease FAILS even if nobody else has taken it yet: past expires_at
-- the holder must treat the lease as lost and re-acquire, receiving a NEW
-- fence token. This rule is what makes fencing sound – a paused holder must
-- never resume against its own stale-but-unclaimed lease.
--
-- renew does NOT update metadata; acquire's same-holder branch does. Not
-- event-logged (renewals fire at ~ttl/3 – see lease.events schema note).
--
-- Expiry uses the wall clock (clock_timestamp), not the transaction start
-- time: renewing from inside a long transaction extends from the real
-- present, and a lease that expired on the wall clock cannot be renewed just
-- because the transaction began before expiry.
CREATE OR REPLACE FUNCTION lease.renew(
    p_namespace text,
    p_name text,
    p_holder text,
    p_fence bigint,
    p_ttl interval DEFAULT NULL
)
RETURNS TABLE(
    renewed boolean,
    expires_at timestamptz
) AS $$
DECLARE
    v_config lease.config;
    v_ttl interval;
    v_expires timestamptz;
BEGIN
    -- Validate inputs
    PERFORM lease._validate_namespace(p_namespace);
    PERFORM lease._validate_lease_name(p_name);
    PERFORM lease._validate_holder(p_holder);
    PERFORM lease._validate_fence(p_fence);

    -- Warn if namespace mismatch with RLS context
    PERFORM lease._warn_namespace_mismatch(p_namespace);

    -- Get config for defaults and TTL cap
    v_config := lease._get_config(p_namespace);
    PERFORM lease._validate_ttl(p_ttl, v_config.max_ttl);
    v_ttl := COALESCE(p_ttl, v_config.default_ttl);

    -- Single guarded UPDATE: the WHERE clause is the whole check, including
    -- liveness on the wall clock (invariant I3, see 001_tables.sql).
    UPDATE lease.leases l
    SET expires_at = clock_timestamp() + v_ttl,
        updated_at = clock_timestamp()
    WHERE l.namespace = p_namespace
      AND l.name = p_name
      AND l.holder_id = p_holder
      AND l.fence_token = p_fence
      AND l.expires_at > clock_timestamp()
    RETURNING l.expires_at INTO v_expires;

    IF v_expires IS NOT NULL THEN
        RETURN QUERY SELECT true, v_expires;
    ELSE
        RETURN QUERY SELECT false, NULL::timestamptz;
    END IF;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = lease, pg_temp;


-- @function lease.release
-- @brief Release a lease you hold.
-- @param p_namespace Tenant namespace
-- @param p_name Lease name
-- @param p_holder Holder identity (must match the lease)
-- @param p_fence Fence token from acquire (must match the lease)
-- @returns True if released, false if the lease was not held with this
--          holder and fence (idempotent – never raises)
-- @example SELECT lease.release('default', 'scheduler', 'worker-1', 42);
--
-- Deletes the lease row; the fence counter row is intentionally kept so
-- tokens keep increasing across acquisitions forever. Releasing your own
-- already-expired-but-unclaimed lease succeeds (harmless and idempotent);
-- releasing a lease someone else has since taken over returns false because
-- the (holder, fence) no longer matches.
--
-- Fires pg_notify on the lease channel when notify_on_release is configured;
-- waiters wake and race acquire (a wake-up, never a queue).
CREATE OR REPLACE FUNCTION lease.release(
    p_namespace text,
    p_name text,
    p_holder text,
    p_fence bigint
)
RETURNS boolean AS $$
DECLARE
    v_config lease.config;
    v_deleted int;
BEGIN
    -- Validate inputs
    PERFORM lease._validate_namespace(p_namespace);
    PERFORM lease._validate_lease_name(p_name);
    PERFORM lease._validate_holder(p_holder);
    PERFORM lease._validate_fence(p_fence);

    -- Warn if namespace mismatch with RLS context
    PERFORM lease._warn_namespace_mismatch(p_namespace);

    v_config := lease._get_config(p_namespace);

    DELETE FROM lease.leases l
    WHERE l.namespace = p_namespace
      AND l.name = p_name
      AND l.holder_id = p_holder
      AND l.fence_token = p_fence;

    GET DIAGNOSTICS v_deleted = ROW_COUNT;

    IF v_deleted > 0 THEN
        PERFORM lease._log_event(p_namespace, p_name, 'released', p_holder, p_fence);
        PERFORM lease._notify_if_enabled(v_config, p_namespace, p_name);
        RETURN true;
    END IF;

    RETURN false;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = lease, pg_temp;
