-- @group Maintenance

-- @function presence.trim
-- @brief Delete old transitions.
-- @param p_older_than Delete transitions older than this interval (required)
-- @param p_namespace Tenant namespace (NULL = all namespaces, requires RLS bypass)
-- @param p_limit Maximum transitions to delete per call
-- @returns One row per namespace touched: (namespace, deleted count)
-- @example SELECT * FROM presence.trim('90 days', 'default');
--
-- Call from cron or a maintenance loop; nothing runs on its own. Each call
-- deletes at most p_limit transitions; call repeatedly until the return is
-- empty. p_older_than has no default on purpose: transition-history
-- retention is a deployment policy decision. It precedes p_namespace
-- because a parameter with a default cannot come before one without, and
-- the all-namespaces mode (one cron across tenants) must keep its default.
--
-- A plain age delete, no prefix machinery: transitions is history, not a
-- cursored feed (see the xid note on the transitions table), so nothing
-- downstream depends on the id range being contiguous.
CREATE OR REPLACE FUNCTION presence.trim(
    p_older_than interval,
    p_namespace text DEFAULT NULL,
    p_limit int DEFAULT 10000
)
RETURNS TABLE(
    namespace text,
    deleted int
) AS $$
BEGIN
    IF p_older_than IS NULL OR p_older_than <= interval '0 seconds' THEN
        RAISE EXCEPTION 'Trim interval must be a positive interval'
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:presence:VAL_TRIM_INTERVAL_NOT_POSITIVE';
    END IF;

    IF p_namespace IS NOT NULL THEN
        PERFORM presence._validate_namespace(p_namespace);
        PERFORM presence._warn_namespace_mismatch(p_namespace);
    ELSIF NOT presence._rls_bypassed() THEN
        RAISE EXCEPTION 'All-namespaces mode requires a role that bypasses RLS; pass an explicit namespace or run as a BYPASSRLS role'
            USING ERRCODE = 'insufficient_privilege',
                  HINT = 'postkit:presence:BIZ_ALL_NAMESPACES_REQUIRES_BYPASS';
    END IF;
    PERFORM presence._validate_limit(p_limit, 'limit', 10000);

    RETURN QUERY
    WITH batch AS (
        SELECT t.id, t.namespace AS ns
        FROM presence.transitions t
        WHERE (p_namespace IS NULL OR t.namespace = p_namespace)
          AND t.at < now() - p_older_than
        ORDER BY t.id
        LIMIT p_limit
    ),
    removed AS (
        DELETE FROM presence.transitions t
        USING batch
        WHERE t.id = batch.id
        RETURNING batch.ns
    )
    SELECT r.ns, COUNT(*)::int
    FROM removed r
    GROUP BY r.ns
    ORDER BY r.ns;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = presence, pg_temp;
