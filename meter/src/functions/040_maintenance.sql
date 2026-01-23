-- @group Maintenance

-- @function meter.create_partition
-- @brief Create a monthly partition for ledger
-- @param p_year Year (e.g., 2025)
-- @param p_month Month (1-12)
-- @returns Partition name if created, NULL if already exists
-- @example SELECT meter.create_partition(2025, 1);
CREATE FUNCTION meter.create_partition(
    p_year int,
    p_month int
)
RETURNS text AS $$
DECLARE
    v_name text;
    v_start date;
    v_end date;
BEGIN
    IF p_month < 1 OR p_month > 12 THEN
        RAISE EXCEPTION 'Month must be between 1 and 12'
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:meter:VAL_MONTH_OUT_OF_RANGE';
    END IF;

    v_name := format('ledger_y%sm%s', to_char(p_year, 'FM0000'), to_char(p_month, 'FM00'));
    v_start := make_date(p_year, p_month, 1);
    v_end := v_start + interval '1 month';

    IF EXISTS (
        SELECT 1 FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'meter' AND c.relname = v_name
    ) THEN
        RETURN NULL;
    END IF;

    EXECUTE format(
        'CREATE TABLE meter.%I PARTITION OF meter.ledger FOR VALUES FROM (%L) TO (%L)',
        v_name, v_start, v_end
    );

    RETURN v_name;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = meter, pg_temp;


-- @function meter.ensure_partitions
-- @brief Create partitions for upcoming months
-- @param p_months_ahead Number of months ahead to create (default 3)
-- @returns Names of created partitions
-- @example SELECT * FROM meter.ensure_partitions(6);
CREATE FUNCTION meter.ensure_partitions(
    p_months_ahead int DEFAULT 3
)
RETURNS SETOF text AS $$
DECLARE
    v_current date;
    v_target date;
    v_result text;
BEGIN
    v_current := date_trunc('month', now())::date;
    v_target := v_current + (p_months_ahead || ' months')::interval;

    WHILE v_current <= v_target LOOP
        v_result := meter.create_partition(
            EXTRACT(YEAR FROM v_current)::int,
            EXTRACT(MONTH FROM v_current)::int
        );
        IF v_result IS NOT NULL THEN
            RETURN NEXT v_result;
        END IF;
        v_current := v_current + interval '1 month';
    END LOOP;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = meter, pg_temp;


-- @function meter.drop_old_partitions
-- @brief Drop partitions older than retention period
-- @param p_older_than_months Months to retain (default 24)
-- @returns Names of dropped partitions
-- @example SELECT * FROM meter.drop_old_partitions(12);
CREATE FUNCTION meter.drop_old_partitions(
    p_older_than_months int DEFAULT 24
)
RETURNS SETOF text AS $$
DECLARE
    v_cutoff date;
    v_partition RECORD;
    v_partition_end date;
BEGIN
    IF p_older_than_months < 1 THEN
        RAISE EXCEPTION 'older_than_months must be at least 1'
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:meter:VAL_MONTHS_MIN';
    END IF;

    v_cutoff := date_trunc('month', now())::date - (p_older_than_months || ' months')::interval;

    FOR v_partition IN
        SELECT c.relname AS name
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        JOIN pg_inherits i ON i.inhrelid = c.oid
        JOIN pg_class parent ON parent.oid = i.inhparent
        WHERE n.nspname = 'meter'
          AND parent.relname = 'ledger'
          AND c.relname ~ '^ledger_y\d{4}m\d{2}$'
        ORDER BY c.relname
    LOOP
        v_partition_end := make_date(
            substring(v_partition.name FROM 9 FOR 4)::int,
            substring(v_partition.name FROM 14 FOR 2)::int,
            1
        ) + interval '1 month';

        IF v_partition_end <= v_cutoff THEN
            EXECUTE format('DROP TABLE meter.%I', v_partition.name);
            RETURN NEXT v_partition.name;
        END IF;
    END LOOP;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = meter, pg_temp;


-- @function meter.reconcile
-- @brief Verify account invariants: balance vs ledger sum, reserved vs active reservations
-- @param p_namespace Tenant namespace
-- @returns Accounts with discrepancies (issue_type: 'balance_mismatch' or 'reserved_mismatch')
-- @example SELECT * FROM meter.reconcile();
CREATE FUNCTION meter.reconcile(
    p_namespace text DEFAULT 'default'
)
RETURNS TABLE(
    user_id text,
    event_type text,
    resource text,
    unit text,
    issue_type text,
    expected numeric,
    actual numeric,
    discrepancy numeric
) AS $$
BEGIN
    -- Check invariant 1: account.balance = SUM(ledger.amount)
    RETURN QUERY
    SELECT
        a.user_id,
        a.event_type,
        a.resource,
        a.unit,
        'balance_mismatch'::text AS issue_type,
        COALESCE(l.total, 0) AS expected,
        a.balance AS actual,
        a.balance - COALESCE(l.total, 0) AS discrepancy
    FROM meter.accounts a
    LEFT JOIN (
        SELECT
            lg.namespace, lg.user_id, lg.event_type, lg.resource, lg.unit,
            SUM(lg.amount) AS total
        FROM meter.ledger lg
        WHERE lg.namespace = p_namespace
        GROUP BY lg.namespace, lg.user_id, lg.event_type, lg.resource, lg.unit
    ) l ON a.namespace = l.namespace
        AND a.user_id IS NOT DISTINCT FROM l.user_id
        AND a.event_type = l.event_type
        AND a.resource = l.resource
        AND a.unit = l.unit
    WHERE a.namespace = p_namespace
      AND a.balance != COALESCE(l.total, 0);

    -- Check invariant 2: account.reserved = SUM(active_reservations.amount)
    RETURN QUERY
    SELECT
        a.user_id,
        a.event_type,
        a.resource,
        a.unit,
        'reserved_mismatch'::text AS issue_type,
        COALESCE(r.total, 0) AS expected,
        a.reserved AS actual,
        a.reserved - COALESCE(r.total, 0) AS discrepancy
    FROM meter.accounts a
    LEFT JOIN (
        SELECT
            rs.namespace, rs.user_id, rs.event_type, rs.resource, rs.unit,
            SUM(rs.amount) AS total
        FROM meter.reservations rs
        WHERE rs.namespace = p_namespace
          AND rs.status = 'active'
        GROUP BY rs.namespace, rs.user_id, rs.event_type, rs.resource, rs.unit
    ) r ON a.namespace = r.namespace
        AND a.user_id IS NOT DISTINCT FROM r.user_id
        AND a.event_type = r.event_type
        AND a.resource = r.resource
        AND a.unit = r.unit
    WHERE a.namespace = p_namespace
      AND a.reserved != COALESCE(r.total, 0);
END;
$$ LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = meter, pg_temp;


-- @function meter.get_stats
-- @brief Get namespace statistics
-- @param p_namespace Tenant namespace
-- @returns Counts and totals
-- @example SELECT * FROM meter.get_stats();
CREATE FUNCTION meter.get_stats(
    p_namespace text DEFAULT 'default'
)
RETURNS TABLE(
    total_accounts bigint,
    total_ledger_entries bigint,
    active_reservations bigint,
    total_balance numeric,
    total_reserved numeric
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        a.cnt::bigint,
        l.cnt::bigint,
        r.cnt::bigint,
        a.total_balance,
        a.total_reserved
    FROM
        (SELECT COUNT(*) AS cnt,
                COALESCE(SUM(balance), 0) AS total_balance,
                COALESCE(SUM(reserved), 0) AS total_reserved
         FROM meter.accounts WHERE namespace = p_namespace) a,
        (SELECT COUNT(*) AS cnt
         FROM meter.ledger WHERE namespace = p_namespace) l,
        (SELECT COUNT(*) AS cnt
         FROM meter.reservations WHERE namespace = p_namespace AND status = 'active') r;
END;
$$ LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = meter, pg_temp;


-- =============================================================================
-- INITIALIZE PARTITIONS
-- =============================================================================
-- Create partitions for current month and 3 months ahead on schema installation.

SELECT meter.ensure_partitions(3);
