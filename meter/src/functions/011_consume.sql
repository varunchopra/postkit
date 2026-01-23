-- @group Recording

-- @function meter.consume
-- @brief Record consumption (debit from account)
-- @param p_user_id User ID (required for consumption)
-- @param p_event_type Event type
-- @param p_amount Amount consumed (must be positive, stored as negative)
-- @param p_unit Unit of measurement
-- @param p_resource Optional resource identifier
-- @param p_check_balance If true, fails when insufficient balance
-- @param p_idempotency_key Optional dedup key for safe retries
-- @param p_event_time When consumption occurred (defaults to now)
-- @param p_metadata Optional JSON metadata
-- @param p_namespace Tenant namespace
-- @returns success flag, new balance, available balance, entry_id
--
-- PERFORMANCE: Hot path - called for every usage event. Uses advisory lock on
-- idempotency key for safe retries without read-before-write races. Account
-- upsert uses ON CONFLICT for single round-trip insert-or-update.
--
-- @example SELECT * FROM meter.consume('alice', 'llm_call', 1500, 'tokens', 'claude-sonnet');
CREATE FUNCTION meter.consume(
    p_user_id text,
    p_event_type text,
    p_amount numeric,
    p_unit text,
    p_resource text DEFAULT NULL,
    p_check_balance boolean DEFAULT false,
    p_idempotency_key text DEFAULT NULL,
    p_event_time timestamptz DEFAULT NULL,
    p_metadata jsonb DEFAULT NULL,
    p_namespace text DEFAULT 'default'
)
RETURNS TABLE(success boolean, balance numeric, available numeric, entry_id bigint) AS $$
DECLARE
    v_account meter.accounts;
    v_new_balance numeric;
    v_available numeric;
    v_entry_id bigint;
    v_event_time timestamptz;
    v_existing RECORD;
BEGIN
    -- Validate
    PERFORM meter._validate_namespace(p_namespace);
    PERFORM meter._validate_event_type(p_event_type);
    PERFORM meter._validate_unit(p_unit);
    PERFORM meter._validate_positive(p_amount, 'amount');

    IF p_user_id IS NULL THEN
        RAISE EXCEPTION 'user_id is required for consumption'
            USING ERRCODE = 'null_value_not_allowed',
                  HINT = 'postkit:meter:VAL_USER_ID_REQUIRED';
    END IF;

    v_event_time := COALESCE(p_event_time, now());

    -- Check idempotency (with advisory lock to prevent race conditions)
    IF p_idempotency_key IS NOT NULL THEN
        PERFORM meter._idempotency_lock(p_namespace, p_idempotency_key);

        SELECT l.id, l.balance_after INTO v_existing
        FROM meter.ledger l
        WHERE l.namespace = p_namespace AND l.idempotency_key = p_idempotency_key;

        IF FOUND THEN
            RETURN QUERY SELECT true, v_existing.balance_after,
                v_existing.balance_after - COALESCE((
                    SELECT a.reserved FROM meter.accounts a
                    WHERE a.namespace = p_namespace AND a.user_id = p_user_id
                      AND a.event_type = p_event_type
                      AND a.resource = COALESCE(p_resource, '')
                      AND a.unit = p_unit
                ), 0), v_existing.id;
            RETURN;
        END IF;
    END IF;

    -- Get or create account with lock
    v_account := meter._upsert_account(p_namespace, p_user_id, p_event_type, p_resource, p_unit);

    -- Check available balance
    v_available := v_account.balance - v_account.reserved;

    IF p_check_balance AND v_available < p_amount THEN
        RETURN QUERY SELECT false, v_account.balance, v_available, NULL::bigint;
        RETURN;
    END IF;

    -- Calculate new balance
    v_new_balance := v_account.balance - p_amount;

    -- Insert ledger entry (negative amount)
    v_entry_id := meter._insert_ledger(
        p_namespace, p_user_id, p_event_type, p_resource, p_unit,
        'consumption', -p_amount, v_new_balance, v_event_time,
        p_idempotency_key, NULL, NULL, p_metadata
    );

    -- Update account
    UPDATE meter.accounts SET
        balance = v_new_balance,
        total_debited = total_debited + p_amount,
        last_entry_id = v_entry_id,
        updated_at = now()
    WHERE namespace = p_namespace
      AND user_id = p_user_id
      AND event_type = p_event_type
      AND resource = COALESCE(p_resource, '')
      AND unit = p_unit;

    RETURN QUERY SELECT true, v_new_balance, v_new_balance - v_account.reserved, v_entry_id;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = meter, pg_temp;
