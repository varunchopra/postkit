-- @group Periods

-- @function meter.set_period_config
-- @brief Configure period settings for an account
-- @param p_user_id User ID
-- @param p_event_type Event type
-- @param p_unit Unit of measurement
-- @param p_resource Optional resource identifier
-- @param p_period_start First day of the period
-- @param p_period_allocation Amount granted each period
-- @param p_carry_over_limit Max unused to roll forward (NULL = no limit)
-- @param p_namespace Tenant namespace
-- @example SELECT meter.set_period_config('alice', 'llm_call', 'tokens', NULL, '2025-01-01', 100000, 10000);
CREATE FUNCTION meter.set_period_config(
    p_user_id text,
    p_event_type text,
    p_unit text,
    p_resource text,
    p_period_start date,
    p_period_allocation numeric,
    p_carry_over_limit numeric DEFAULT NULL,
    p_namespace text DEFAULT 'default'
)
RETURNS void AS $$
BEGIN
    UPDATE meter.accounts SET
        period_start = p_period_start,
        period_allocation = p_period_allocation,
        carry_over_limit = p_carry_over_limit,
        updated_at = now()
    WHERE namespace = p_namespace
      AND user_id IS NOT DISTINCT FROM p_user_id
      AND event_type = p_event_type
      AND resource = COALESCE(p_resource, '')
      AND unit = p_unit;

    IF NOT FOUND THEN
        -- Create account with period config
        INSERT INTO meter.accounts (
            namespace, user_id, event_type, resource, unit,
            period_start, period_allocation, carry_over_limit
        ) VALUES (
            p_namespace, p_user_id, p_event_type, COALESCE(p_resource, ''), p_unit,
            p_period_start, p_period_allocation, p_carry_over_limit
        );
    END IF;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = meter, pg_temp;


-- @function meter.close_period
-- @brief Close a billing period, handle expiration and carry-over
-- @param p_user_id User ID
-- @param p_event_type Event type
-- @param p_unit Unit of measurement
-- @param p_resource Optional resource identifier
-- @param p_period_end Last day of the period being closed
-- @param p_namespace Tenant namespace
-- @returns expired amount, carried_over amount, new_balance
-- @example SELECT * FROM meter.close_period('alice', 'llm_call', 'tokens', NULL, '2025-01-31');
CREATE FUNCTION meter.close_period(
    p_user_id text,
    p_event_type text,
    p_unit text,
    p_resource text,
    p_period_end date,
    p_namespace text DEFAULT 'default'
)
RETURNS TABLE(expired numeric, carried_over numeric, new_balance numeric) AS $$
DECLARE
    v_account meter.accounts;
    v_available numeric;
    v_carry numeric;
    v_expire numeric;
    v_new_balance numeric;
BEGIN
    -- Lock account
    SELECT * INTO v_account
    FROM meter.accounts
    WHERE namespace = p_namespace
      AND user_id IS NOT DISTINCT FROM p_user_id
      AND event_type = p_event_type
      AND resource = COALESCE(p_resource, '')
      AND unit = p_unit
    FOR UPDATE;

    IF NOT FOUND THEN
        RETURN QUERY SELECT 0::numeric, 0::numeric, 0::numeric;
        RETURN;
    END IF;

    -- Calculate available (not reserved)
    v_available := GREATEST(v_account.balance - v_account.reserved, 0);

    -- Determine carry-over amount
    IF v_account.carry_over_limit IS NULL THEN
        v_carry := v_available;  -- no limit, carry all
    ELSE
        v_carry := LEAST(v_available, v_account.carry_over_limit);
    END IF;

    v_expire := v_available - v_carry;

    -- Create expiration entry if needed
    IF v_expire > 0 THEN
        PERFORM meter._insert_ledger(
            p_namespace, p_user_id, p_event_type, p_resource, p_unit,
            'expiration', -v_expire, v_account.balance - v_expire, now(),
            'period_close:' || p_period_end, NULL, NULL,
            jsonb_build_object('period_end', p_period_end)
        );
    END IF;

    v_new_balance := v_account.balance - v_expire;

    -- Update account
    UPDATE meter.accounts SET
        balance = v_new_balance,
        updated_at = now()
    WHERE namespace = p_namespace
      AND user_id IS NOT DISTINCT FROM p_user_id
      AND event_type = p_event_type
      AND resource = COALESCE(p_resource, '')
      AND unit = p_unit;

    RETURN QUERY SELECT v_expire, v_carry, v_new_balance;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = meter, pg_temp;


-- @function meter.open_period
-- @brief Open a new billing period with fresh allocation
-- @param p_user_id User ID
-- @param p_event_type Event type
-- @param p_unit Unit of measurement
-- @param p_resource Optional resource identifier
-- @param p_period_start First day of new period
-- @param p_allocation Amount to allocate (uses period_allocation if NULL)
-- @param p_namespace Tenant namespace
-- @returns New balance
-- @example SELECT meter.open_period('alice', 'llm_call', 'tokens', NULL, '2025-02-01');
CREATE FUNCTION meter.open_period(
    p_user_id text,
    p_event_type text,
    p_unit text,
    p_resource text,
    p_period_start date,
    p_allocation numeric DEFAULT NULL,
    p_namespace text DEFAULT 'default'
)
RETURNS numeric AS $$
DECLARE
    v_account meter.accounts;
    v_allocation numeric;
    v_new_balance numeric;
    v_entry_id bigint;
BEGIN
    -- Get account
    SELECT * INTO v_account
    FROM meter.accounts
    WHERE namespace = p_namespace
      AND user_id IS NOT DISTINCT FROM p_user_id
      AND event_type = p_event_type
      AND resource = COALESCE(p_resource, '')
      AND unit = p_unit
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Account not found'
            USING ERRCODE = 'no_data_found',
                  HINT = 'postkit:meter:DATA_ACCOUNT_NOT_FOUND';
    END IF;

    -- Use provided allocation or account default
    v_allocation := COALESCE(p_allocation, v_account.period_allocation);

    IF v_allocation IS NULL OR v_allocation <= 0 THEN
        RAISE EXCEPTION 'No allocation amount specified'
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:meter:VAL_ALLOCATION_REQUIRED';
    END IF;

    v_new_balance := v_account.balance + v_allocation;

    -- Create allocation entry
    v_entry_id := meter._insert_ledger(
        p_namespace, p_user_id, p_event_type, p_resource, p_unit,
        'allocation', v_allocation, v_new_balance, now(),
        'period_open:' || p_period_start, NULL, NULL,
        jsonb_build_object('period_start', p_period_start)
    );

    -- Update account
    UPDATE meter.accounts SET
        balance = v_new_balance,
        total_credited = total_credited + v_allocation,
        period_start = p_period_start,
        last_entry_id = v_entry_id,
        updated_at = now()
    WHERE namespace = p_namespace
      AND user_id IS NOT DISTINCT FROM p_user_id
      AND event_type = p_event_type
      AND resource = COALESCE(p_resource, '')
      AND unit = p_unit;

    RETURN v_new_balance;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = meter, pg_temp;


-- @function meter.release_expired_reservations
-- @brief Mark expired reservations as 'expired' and release their holds.
-- Distinct from 'released' to distinguish automatic expiry. No ledger entries.
-- @param p_namespace Optional namespace filter (NULL = all namespaces)
-- @returns Count of reservations expired
-- @example SELECT meter.release_expired_reservations();
CREATE FUNCTION meter.release_expired_reservations(
    p_namespace text DEFAULT NULL
)
RETURNS int AS $$
DECLARE
    v_count int;
BEGIN
    -- Prevent concurrent calls for the same namespace
    PERFORM pg_advisory_xact_lock(hashtext('meter.release_expired:' || COALESCE(p_namespace, '*')));

    -- Update accounts in one statement using aggregated amounts per account
    WITH expired_agg AS (
        SELECT namespace, user_id, event_type, resource, unit, SUM(amount) AS total_amount
        FROM meter.reservations
        WHERE status = 'active'
          AND expires_at <= now()
          AND (p_namespace IS NULL OR namespace = p_namespace)
        GROUP BY namespace, user_id, event_type, resource, unit
    )
    UPDATE meter.accounts a SET
        reserved = reserved - e.total_amount,
        updated_at = now()
    FROM expired_agg e
    WHERE a.namespace = e.namespace
      AND a.user_id IS NOT DISTINCT FROM e.user_id
      AND a.event_type = e.event_type
      AND a.resource = e.resource
      AND a.unit = e.unit;

    -- Mark all expired reservations in one statement
    WITH expired AS (
        UPDATE meter.reservations SET
            status = 'expired',
            completed_at = now()
        WHERE status = 'active'
          AND expires_at <= now()
          AND (p_namespace IS NULL OR namespace = p_namespace)
        RETURNING 1
    )
    SELECT COUNT(*) INTO v_count FROM expired;

    RETURN v_count;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = meter, pg_temp;
