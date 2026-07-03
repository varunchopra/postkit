-- @group Inspection

-- @function lease.current
-- @brief Inspect a lease without locking it.
-- @param p_namespace Tenant namespace
-- @param p_name Lease name
-- @returns Holder, fence token, expiry, and metadata; empty when no row exists
-- @example SELECT * FROM lease.current('default', 'scheduler');
--
-- Returns the row even when it is past expires_at (lazy expiry keeps expired
-- rows until someone acquires or releases them) – compare expires_at to
-- now() to judge liveness. For a fenced liveness check use lease.verify.
CREATE OR REPLACE FUNCTION lease.current(
    p_namespace text,
    p_name text
)
RETURNS TABLE(
    holder_id text,
    fence_token bigint,
    expires_at timestamptz,
    metadata jsonb
) AS $$
BEGIN
    -- Validate inputs
    PERFORM lease._validate_namespace(p_namespace);
    PERFORM lease._validate_lease_name(p_name);

    -- Warn if namespace mismatch with RLS context
    PERFORM lease._warn_namespace_mismatch(p_namespace);

    RETURN QUERY
    SELECT l.holder_id, l.fence_token, l.expires_at, l.metadata
    FROM lease.leases l
    WHERE l.namespace = p_namespace AND l.name = p_name;
END;
$$ LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = lease, pg_temp;


-- @function lease.list
-- @brief List leases in a namespace.
-- @param p_namespace Tenant namespace
-- @param p_include_expired Include rows past their expiry (default true)
-- @returns Lease rows, most recently acquired first
-- @example SELECT * FROM lease.list('default', p_include_expired := false);
CREATE OR REPLACE FUNCTION lease.list(
    p_namespace text,
    p_include_expired boolean DEFAULT true
)
RETURNS SETOF lease.leases AS $$
BEGIN
    -- Validate inputs
    PERFORM lease._validate_namespace(p_namespace);

    -- Warn if namespace mismatch with RLS context
    PERFORM lease._warn_namespace_mismatch(p_namespace);

    RETURN QUERY
    SELECT l.*
    FROM lease.leases l
    WHERE l.namespace = p_namespace
      AND (p_include_expired OR l.expires_at > clock_timestamp())
    ORDER BY l.acquired_at DESC;
END;
$$ LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = lease, pg_temp;


-- @function lease.get_stats
-- @brief Get namespace-wide lease statistics.
-- @param p_namespace Tenant namespace
-- @returns Row with total_leases, live, expired, total_names, total_events
-- @example SELECT * FROM lease.get_stats('default');
--
-- total_names counts every lease name ever used (fence counter rows survive
-- release); total_events grows until lease.prune_events() trims it.
CREATE OR REPLACE FUNCTION lease.get_stats(p_namespace text)
RETURNS TABLE(
    total_leases bigint,
    live bigint,
    expired bigint,
    total_names bigint,
    total_events bigint
) AS $$
BEGIN
    PERFORM lease._validate_namespace(p_namespace);
    PERFORM lease._warn_namespace_mismatch(p_namespace);

    RETURN QUERY
    SELECT
        (SELECT COUNT(*) FROM lease.leases l WHERE l.namespace = p_namespace),
        (SELECT COUNT(*) FROM lease.leases l
         WHERE l.namespace = p_namespace AND l.expires_at > clock_timestamp()),
        (SELECT COUNT(*) FROM lease.leases l
         WHERE l.namespace = p_namespace AND l.expires_at <= clock_timestamp()),
        (SELECT COUNT(*) FROM lease.fence_counters c WHERE c.namespace = p_namespace),
        (SELECT COUNT(*) FROM lease.events e WHERE e.namespace = p_namespace);
END;
$$ LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = lease, pg_temp;


-- @function lease.get_events
-- @brief Read the lease event log, newest first.
-- @param p_namespace Tenant namespace
-- @param p_name Lease name filter (NULL = all names)
-- @param p_limit Maximum events to return
-- @returns Event rows (acquired, released, taken_over) with actor context
-- @example SELECT * FROM lease.get_events('default', 'scheduler');
CREATE OR REPLACE FUNCTION lease.get_events(
    p_namespace text,
    p_name text DEFAULT NULL,
    p_limit int DEFAULT 100
)
RETURNS SETOF lease.events AS $$
BEGIN
    PERFORM lease._validate_namespace(p_namespace);
    IF p_name IS NOT NULL THEN
        PERFORM lease._validate_lease_name(p_name);
    END IF;
    PERFORM lease._validate_positive_int(p_limit, 'limit');
    PERFORM lease._warn_namespace_mismatch(p_namespace);

    RETURN QUERY
    SELECT e.*
    FROM lease.events e
    WHERE e.namespace = p_namespace
      AND (p_name IS NULL OR e.name = p_name)
    ORDER BY e.at DESC, e.id DESC
    LIMIT p_limit;
END;
$$ LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = lease, pg_temp;
