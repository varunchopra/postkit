-- @group Recording

-- @function meter.reserve
-- @brief Reserve quota for pending operation. Reservations are HOLDS, not balance
-- changes. They don't create ledger entries. Only commit affects balance.
-- @param p_user_id User ID (required)
-- @param p_event_type Event type
-- @param p_amount Amount to reserve
-- @param p_unit Unit of measurement
-- @param p_resource Optional resource identifier
-- @param p_ttl_seconds Time until reservation auto-expires (default 300 = 5 min)
-- @param p_idempotency_key Optional dedup key for safe retries
-- @param p_metadata Optional JSON metadata
-- @param p_namespace Tenant namespace
-- @returns granted flag, reservation_id, balance, available, expires_at
-- @example SELECT * FROM meter.reserve('alice', 'llm_call', 4000, 'tokens', 'claude-sonnet');
CREATE FUNCTION meter.reserve(
    p_user_id text,
    p_event_type text,
    p_amount numeric,
    p_unit text,
    p_resource text DEFAULT NULL,
    p_ttl_seconds int DEFAULT 300,
    p_idempotency_key text DEFAULT NULL,
    p_metadata jsonb DEFAULT NULL,
    p_namespace text DEFAULT 'default'
)
RETURNS TABLE(
    granted boolean,
    reservation_id text,
    balance numeric,
    available numeric,
    expires_at timestamptz
) AS $$
DECLARE
    v_account meter.accounts;
    v_available numeric;
    v_reservation_id text;
    v_expires_at timestamptz;
    v_existing meter.reservations;
BEGIN
    -- Validate
    PERFORM meter._validate_namespace(p_namespace);
    PERFORM meter._validate_event_type(p_event_type);
    PERFORM meter._validate_unit(p_unit);
    PERFORM meter._validate_positive(p_amount, 'amount');

    IF p_user_id IS NULL THEN
        RAISE EXCEPTION 'user_id is required for reservations'
            USING ERRCODE = 'null_value_not_allowed',
                  HINT = 'postkit:meter:VAL_USER_ID_REQUIRED';
    END IF;

    IF p_ttl_seconds < 1 OR p_ttl_seconds > 86400 THEN
        RAISE EXCEPTION 'ttl_seconds must be between 1 and 86400'
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:meter:VAL_TTL_OUT_OF_RANGE';
    END IF;

    v_expires_at := now() + (p_ttl_seconds || ' seconds')::interval;

    -- Check idempotency via reservations table (not ledger)
    IF p_idempotency_key IS NOT NULL THEN
        PERFORM meter._idempotency_lock(p_namespace, p_idempotency_key);

        SELECT * INTO v_existing
        FROM meter.reservations r
        WHERE r.namespace = p_namespace
          AND r.idempotency_key = p_idempotency_key;

        IF FOUND THEN
            RETURN QUERY SELECT
                v_existing.status = 'active',
                v_existing.reservation_id,
                v_existing.balance_at_create,
                v_existing.balance_at_create - COALESCE((
                    SELECT a.reserved FROM meter.accounts a
                    WHERE a.namespace = p_namespace AND a.user_id = p_user_id
                      AND a.event_type = p_event_type
                      AND a.resource = COALESCE(p_resource, '')
                      AND a.unit = p_unit
                ), 0),
                v_existing.expires_at;
            RETURN;
        END IF;
    END IF;

    -- Get or create account with lock
    v_account := meter._upsert_account(p_namespace, p_user_id, p_event_type, p_resource, p_unit);

    -- Check available (balance minus already reserved)
    v_available := v_account.balance - v_account.reserved;

    IF v_available < p_amount THEN
        RETURN QUERY SELECT false, NULL::text, v_account.balance, v_available, NULL::timestamptz;
        RETURN;
    END IF;

    -- Generate reservation ID
    v_reservation_id := 'res_' || replace(gen_random_uuid()::text, '-', '');

    -- Track reservation (NO ledger entry - reservations are holds, not balance changes)
    INSERT INTO meter.reservations (
        reservation_id, namespace, user_id, event_type, resource, unit,
        amount, balance_at_create, expires_at, status,
        idempotency_key, actor_id, request_id, metadata
    )
    SELECT
        v_reservation_id, p_namespace, p_user_id, p_event_type,
        COALESCE(p_resource, ''), p_unit,
        p_amount, v_account.balance, v_expires_at, 'active',
        p_idempotency_key, ctx.actor_id, ctx.request_id, p_metadata
    FROM meter._get_actor_context() ctx;

    -- Update account: only increment reserved (balance unchanged)
    UPDATE meter.accounts SET
        reserved = reserved + p_amount,
        updated_at = now()
    WHERE namespace = p_namespace
      AND user_id = p_user_id
      AND event_type = p_event_type
      AND resource = COALESCE(p_resource, '')
      AND unit = p_unit;

    -- Return: balance unchanged, available reduced by reservation
    RETURN QUERY SELECT true, v_reservation_id, v_account.balance,
                        v_available - p_amount, v_expires_at;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = meter, pg_temp;


-- @function meter.commit
-- @brief Commit a reservation with actual consumption. Only actual consumption
-- affects balance. The hold is released and reservation marked 'committed'.
-- @param p_reservation_id Reservation to commit
-- @param p_actual_amount Actual amount consumed (can exceed reserved; overage policy is caller's responsibility)
-- @param p_metadata Optional JSON metadata
-- @param p_namespace Tenant namespace
-- @returns success, consumed, released, reserved_amount, balance, entry_id
-- @example SELECT * FROM meter.commit('res_abc123', 2347);
-- @example SELECT consumed - reserved_amount AS overage FROM meter.commit('res_abc123', 500);
CREATE FUNCTION meter.commit(
    p_reservation_id text,
    p_actual_amount numeric,
    p_metadata jsonb DEFAULT NULL,
    p_namespace text DEFAULT 'default'
)
RETURNS TABLE(
    success boolean,
    consumed numeric,
    released numeric,
    reserved_amount numeric,
    balance numeric,
    entry_id bigint
) AS $$
DECLARE
    v_res meter.reservations;
    v_account meter.accounts;
    v_released numeric;
    v_new_balance numeric;
    v_entry_id bigint;
BEGIN
    PERFORM meter._validate_namespace(p_namespace);

    IF p_actual_amount < 0 THEN
        RAISE EXCEPTION 'actual_amount cannot be negative'
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:meter:VAL_AMOUNT_NEGATIVE';
    END IF;

    -- Find and lock active reservation
    SELECT * INTO v_res
    FROM meter.reservations
    WHERE reservation_id = p_reservation_id
      AND namespace = p_namespace
      AND status = 'active'
    FOR UPDATE;

    IF NOT FOUND THEN
        RETURN QUERY SELECT false, NULL::numeric, NULL::numeric, NULL::numeric, NULL::numeric, NULL::bigint;
        RETURN;
    END IF;

    -- Lock account
    SELECT * INTO v_account
    FROM meter.accounts
    WHERE namespace = p_namespace
      AND user_id IS NOT DISTINCT FROM v_res.user_id
      AND event_type = v_res.event_type
      AND resource = v_res.resource
      AND unit = v_res.unit
    FOR UPDATE;

    -- Calculate released amount (difference between reserved and actual)
    v_released := GREATEST(v_res.amount - p_actual_amount, 0);

    -- New balance: only deduct actual consumption (no restore needed)
    v_new_balance := v_account.balance - p_actual_amount;

    -- Insert consumption ledger entry (only if actual > 0)
    IF p_actual_amount > 0 THEN
        v_entry_id := meter._insert_ledger(
            p_namespace, v_res.user_id, v_res.event_type, v_res.resource, v_res.unit,
            'consumption', -p_actual_amount, v_new_balance, now(),
            NULL, p_reservation_id, NULL, p_metadata
        );
    END IF;

    -- Update account: deduct actual from balance, release hold
    UPDATE meter.accounts SET
        balance = v_new_balance,
        reserved = reserved - v_res.amount,
        total_debited = total_debited + p_actual_amount,
        last_entry_id = COALESCE(v_entry_id, last_entry_id),
        updated_at = now()
    WHERE namespace = p_namespace
      AND user_id IS NOT DISTINCT FROM v_res.user_id
      AND event_type = v_res.event_type
      AND resource = v_res.resource
      AND unit = v_res.unit;

    -- Mark reservation as committed (preserve for audit)
    UPDATE meter.reservations SET
        status = 'committed',
        completed_at = now(),
        actual_amount = p_actual_amount,
        consumption_entry_id = v_entry_id
    WHERE reservation_id = p_reservation_id;

    RETURN QUERY SELECT true, p_actual_amount, v_released, v_res.amount, v_new_balance, v_entry_id;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = meter, pg_temp;


-- @function meter.release
-- @brief Release a reservation without consuming. Does not affect balance or
-- create ledger entries. Only releases the hold and marks reservation 'released'.
-- @param p_reservation_id Reservation to release
-- @param p_namespace Tenant namespace
-- @returns True if released, false if not found
-- @example SELECT meter.release('res_abc123');
CREATE FUNCTION meter.release(
    p_reservation_id text,
    p_namespace text DEFAULT 'default'
)
RETURNS boolean AS $$
DECLARE
    v_res meter.reservations;
BEGIN
    -- Find and lock active reservation
    SELECT * INTO v_res
    FROM meter.reservations
    WHERE reservation_id = p_reservation_id
      AND namespace = p_namespace
      AND status = 'active'
    FOR UPDATE;

    IF NOT FOUND THEN
        RETURN false;
    END IF;

    -- Update account: only release hold (balance unchanged)
    UPDATE meter.accounts SET
        reserved = reserved - v_res.amount,
        updated_at = now()
    WHERE namespace = p_namespace
      AND user_id IS NOT DISTINCT FROM v_res.user_id
      AND event_type = v_res.event_type
      AND resource = v_res.resource
      AND unit = v_res.unit;

    -- Mark reservation as released (preserve for audit)
    UPDATE meter.reservations SET
        status = 'released',
        completed_at = now()
    WHERE reservation_id = p_reservation_id;

    RETURN true;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = meter, pg_temp;
