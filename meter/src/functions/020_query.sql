-- @group Querying

-- @function meter.get_balance
-- @brief Get current balance for an account
-- @param p_user_id User ID
-- @param p_event_type Event type
-- @param p_unit Unit of measurement
-- @param p_resource Optional resource identifier
-- @param p_namespace Tenant namespace
-- @returns balance, reserved, available (balance - reserved)
--
-- PERFORMANCE: Hot path - called for balance checks and UI displays. Single index
-- lookup on accounts PK (namespace, user_id, event_type, resource, unit).
-- IS NOT DISTINCT FROM handles NULL user_id for namespace-level accounts.
--
-- @example SELECT * FROM meter.get_balance('alice', 'llm_call', 'tokens', 'claude-sonnet');
CREATE FUNCTION meter.get_balance(
    p_user_id text,
    p_event_type text,
    p_unit text,
    p_resource text DEFAULT NULL,
    p_namespace text DEFAULT 'default'
)
RETURNS TABLE(balance numeric, reserved numeric, available numeric) AS $$
BEGIN
    PERFORM meter._warn_namespace_mismatch(p_namespace);

    RETURN QUERY
    SELECT a.balance, a.reserved, a.balance - a.reserved
    FROM meter.accounts a
    WHERE a.namespace = p_namespace
      AND a.user_id IS NOT DISTINCT FROM p_user_id
      AND a.event_type = p_event_type
      AND a.resource = COALESCE(p_resource, '')
      AND a.unit = p_unit;

    -- Return zeros if account doesn't exist
    IF NOT FOUND THEN
        RETURN QUERY SELECT 0::numeric, 0::numeric, 0::numeric;
    END IF;
END;
$$ LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = meter, pg_temp;


-- @function meter.get_account
-- @brief Get full account details
-- @param p_user_id User ID
-- @param p_event_type Event type
-- @param p_unit Unit of measurement
-- @param p_resource Optional resource identifier
-- @param p_namespace Tenant namespace
-- @returns Full account row
-- @example SELECT * FROM meter.get_account('alice', 'llm_call', 'tokens');
CREATE FUNCTION meter.get_account(
    p_user_id text,
    p_event_type text,
    p_unit text,
    p_resource text DEFAULT NULL,
    p_namespace text DEFAULT 'default'
)
RETURNS meter.accounts AS $$
    SELECT * FROM meter.accounts
    WHERE namespace = p_namespace
      AND user_id IS NOT DISTINCT FROM p_user_id
      AND event_type = p_event_type
      AND resource = COALESCE(p_resource, '')
      AND unit = p_unit;
$$ LANGUAGE sql STABLE SECURITY INVOKER SET search_path = meter, pg_temp;


-- @function meter.get_user_balances
-- @brief Get all balances for a user across all event types and resources
-- @param p_user_id User ID
-- @param p_namespace Tenant namespace
-- @returns List of balances per event_type/resource/unit
-- @example SELECT * FROM meter.get_user_balances('alice');
CREATE FUNCTION meter.get_user_balances(
    p_user_id text,
    p_namespace text DEFAULT 'default'
)
RETURNS TABLE(
    event_type text,
    resource text,
    unit text,
    balance numeric,
    reserved numeric,
    available numeric
) AS $$
BEGIN
    PERFORM meter._warn_namespace_mismatch(p_namespace);

    RETURN QUERY
    SELECT
        a.event_type,
        NULLIF(a.resource, ''),
        a.unit,
        a.balance,
        a.reserved,
        a.balance - a.reserved
    FROM meter.accounts a
    WHERE a.namespace = p_namespace
      AND a.user_id = p_user_id
    ORDER BY a.event_type, a.resource, a.unit;
END;
$$ LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = meter, pg_temp;


-- @function meter.get_ledger
-- @brief Get ledger entries for an account
-- @param p_user_id User ID
-- @param p_event_type Event type
-- @param p_unit Unit of measurement
-- @param p_resource Optional resource identifier
-- @param p_start_time Optional start time filter
-- @param p_end_time Optional end time filter
-- @param p_limit Maximum entries to return (default 100, max 10000)
-- @param p_namespace Tenant namespace
-- @returns Ledger entries
-- @example SELECT * FROM meter.get_ledger('alice', 'llm_call', 'tokens', p_limit := 50);
CREATE FUNCTION meter.get_ledger(
    p_user_id text,
    p_event_type text,
    p_unit text,
    p_resource text DEFAULT NULL,
    p_start_time timestamptz DEFAULT NULL,
    p_end_time timestamptz DEFAULT NULL,
    p_limit int DEFAULT 100,
    p_namespace text DEFAULT 'default'
)
RETURNS TABLE(
    id bigint,
    entry_type text,
    amount numeric,
    balance_after numeric,
    event_time timestamptz,
    reservation_id text,
    reference_id bigint,
    actor_id text,
    reason text,
    metadata jsonb
) AS $$
BEGIN
    PERFORM meter._warn_namespace_mismatch(p_namespace);

    IF p_limit > 10000 THEN
        p_limit := 10000;
    END IF;

    RETURN QUERY
    SELECT
        l.id, l.entry_type, l.amount, l.balance_after, l.event_time,
        l.reservation_id, l.reference_id, l.actor_id, l.reason, l.metadata
    FROM meter.ledger l
    WHERE l.namespace = p_namespace
      AND l.user_id IS NOT DISTINCT FROM p_user_id
      AND l.event_type = p_event_type
      AND l.resource = COALESCE(p_resource, '')
      AND l.unit = p_unit
      AND (p_start_time IS NULL OR l.event_time >= p_start_time)
      AND (p_end_time IS NULL OR l.event_time < p_end_time)
    ORDER BY l.event_time DESC, l.id DESC
    LIMIT p_limit;
END;
$$ LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = meter, pg_temp;


-- @function meter.get_usage
-- @brief Get aggregated usage (consumption only) for a user
-- @param p_user_id User ID
-- @param p_start_time Start of period
-- @param p_end_time End of period
-- @param p_namespace Tenant namespace
-- @returns Aggregated consumption per event_type/resource/unit
-- @example SELECT * FROM meter.get_usage('alice', '2025-01-01', '2025-02-01');
CREATE FUNCTION meter.get_usage(
    p_user_id text,
    p_start_time timestamptz,
    p_end_time timestamptz,
    p_namespace text DEFAULT 'default'
)
RETURNS TABLE(
    event_type text,
    resource text,
    unit text,
    total_consumed numeric,
    event_count bigint
) AS $$
BEGIN
    PERFORM meter._warn_namespace_mismatch(p_namespace);

    RETURN QUERY
    SELECT
        l.event_type,
        NULLIF(l.resource, ''),
        l.unit,
        -SUM(l.amount) AS total_consumed,  -- consumption is negative, flip sign
        COUNT(*) AS event_count
    FROM meter.ledger l
    WHERE l.namespace = p_namespace
      AND l.user_id = p_user_id
      AND l.entry_type = 'consumption'
      AND l.event_time >= p_start_time
      AND l.event_time < p_end_time
    GROUP BY l.event_type, l.resource, l.unit
    ORDER BY total_consumed DESC;
END;
$$ LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = meter, pg_temp;


-- @function meter.get_namespace_usage
-- @brief Get org-level usage totals across all users
-- @param p_start_time Start of period
-- @param p_end_time End of period
-- @param p_namespace Tenant namespace
-- @returns Aggregated consumption per event_type/resource/unit with user counts
-- @example SELECT * FROM meter.get_namespace_usage('2025-01-01', '2025-02-01');
CREATE FUNCTION meter.get_namespace_usage(
    p_start_time timestamptz,
    p_end_time timestamptz,
    p_namespace text DEFAULT 'default'
)
RETURNS TABLE(
    event_type text,
    resource text,
    unit text,
    total_consumed numeric,
    event_count bigint,
    unique_users bigint
) AS $$
BEGIN
    PERFORM meter._warn_namespace_mismatch(p_namespace);

    RETURN QUERY
    SELECT
        l.event_type,
        NULLIF(l.resource, ''),
        l.unit,
        -SUM(l.amount) AS total_consumed,
        COUNT(*) AS event_count,
        COUNT(DISTINCT l.user_id) AS unique_users
    FROM meter.ledger l
    WHERE l.namespace = p_namespace
      AND l.entry_type = 'consumption'
      AND l.event_time >= p_start_time
      AND l.event_time < p_end_time
    GROUP BY l.event_type, l.resource, l.unit
    ORDER BY total_consumed DESC;
END;
$$ LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = meter, pg_temp;
