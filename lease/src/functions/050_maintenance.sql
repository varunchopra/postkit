-- @group Maintenance

-- @function lease.prune_events
-- @brief Delete old lease events.
-- @param p_namespace Tenant namespace
-- @param p_older_than Delete events older than this interval (required)
-- @param p_name Lease name filter (NULL = all names)
-- @returns Count of deleted events
-- @example SELECT lease.prune_events('default', '90 days');
--
-- Call from cron or a maintenance loop; nothing runs on its own.
-- p_older_than has no default on purpose: event-log retention is a
-- deployment policy decision.
CREATE OR REPLACE FUNCTION lease.prune_events(
    p_namespace text,
    p_older_than interval,
    p_name text DEFAULT NULL
)
RETURNS int AS $$
DECLARE
    v_count int;
BEGIN
    PERFORM lease._validate_namespace(p_namespace);

    IF p_older_than IS NULL OR p_older_than <= interval '0 seconds' THEN
        RAISE EXCEPTION 'Prune interval must be a positive interval'
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:lease:VAL_PRUNE_INTERVAL_NOT_POSITIVE';
    END IF;

    IF p_name IS NOT NULL THEN
        PERFORM lease._validate_lease_name(p_name);
    END IF;

    PERFORM lease._warn_namespace_mismatch(p_namespace);

    DELETE FROM lease.events
    WHERE namespace = p_namespace
      AND (p_name IS NULL OR name = p_name)
      AND at < now() - p_older_than;

    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = lease, pg_temp;
