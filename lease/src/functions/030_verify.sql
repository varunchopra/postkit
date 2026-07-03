-- @group Verify

-- @function lease.verify
-- @brief Assert, inside your transaction, that you still hold a lease.
-- @param p_namespace Tenant namespace
-- @param p_name Lease name
-- @param p_holder Holder identity (must match the lease)
-- @param p_fence Fence token from acquire (must match the lease)
-- @example SELECT lease.verify('default', 'exporter:cust_42', 'worker-1', 42);
--
-- THE fencing primitive. Raises (SQLSTATE 40001, hint
-- postkit:lease:FENCE_STALE) unless (holder, fence) matches a live lease.
-- Call it inside the same transaction as the writes the lease protects:
--
--     BEGIN;
--       SELECT lease.verify('default', 'exporter:cust_42', me, my_fence);
--       UPDATE ...; INSERT ...;
--     COMMIT;
--
-- The row is locked FOR SHARE, so a concurrent takeover (which must UPDATE
-- the row) serializes against this transaction: either verify sees the
-- takeover and raises, or the takeover waits for this commit. There is no
-- window where both win. It MUST be FOR SHARE, not FOR KEY SHARE: takeover
-- rewrites holder_id/fence_token, which are non-key columns, so KEY SHARE
-- would not conflict and the guarantee silently breaks. Do not "optimize"
-- this. Consequence: while a verify-holding transaction is open, a competing
-- acquire on this name blocks rather than returning acquired=false.
--
-- On 40001 from verify, the correct retry is RE-ACQUIRE, THEN REDO – never
-- replay the same transaction with the same fence; the fence is dead and the
-- replay fails deterministically, so a naive driver-level 40001 retry loop
-- spins. Also: do not call verify then acquire on the same name inside one
-- transaction (lock-order inversion; can abort with 40P01 – retryable).
--
-- verify is only meaningful inside an explicit transaction: under
-- autocommit the share lock is released the instant the statement ends and
-- the guarantee evaporates without any error.
--
-- Liveness is judged on the wall clock (clock_timestamp), so a lease that
-- expired mid-transaction fails verify even though now() predates expiry.
-- verify deliberately has NO lock timeout (acquire does): blocking briefly
-- behind an in-flight takeover is the correct behavior here, and mapping a
-- timeout to any error would misreport it. The hung-client case – a
-- transaction that verifies and then never commits – is bounded by the
-- server's idle_in_transaction_session_timeout, which deployments must set.
--
-- Scope honestly stated: verify protects Postgres-resident writes. For
-- external side effects the token can only be carried to the other system;
-- the ordinary fencing caveat applies there.
CREATE OR REPLACE FUNCTION lease.verify(
    p_namespace text,
    p_name text,
    p_holder text,
    p_fence bigint
)
RETURNS void AS $$
BEGIN
    -- Validate inputs
    PERFORM lease._validate_namespace(p_namespace);
    PERFORM lease._validate_lease_name(p_name);
    PERFORM lease._validate_holder(p_holder);
    PERFORM lease._validate_fence(p_fence);

    -- Warn if namespace mismatch with RLS context
    PERFORM lease._warn_namespace_mismatch(p_namespace);

    -- FOR SHARE, not FOR KEY SHARE – see function docs. The share lock is
    -- held until the caller's transaction ends; that is the mechanism.
    PERFORM 1
    FROM lease.leases l
    WHERE l.namespace = p_namespace
      AND l.name = p_name
      AND l.holder_id = p_holder
      AND l.fence_token = p_fence
      AND l.expires_at > clock_timestamp()
    FOR SHARE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Lease % is not held by % with fence % (lost, expired, or taken over)',
            p_name, p_holder, p_fence
            USING ERRCODE = 'serialization_failure',
                  HINT = 'postkit:lease:FENCE_STALE';
    END IF;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = lease, pg_temp;
