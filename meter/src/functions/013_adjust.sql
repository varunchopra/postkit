-- @group Recording

-- @function meter.adjust
-- @brief Create an adjustment entry (correction, refund, etc.)
-- @param p_user_id User ID
-- @param p_event_type Event type
-- @param p_amount Adjustment amount (positive = credit, negative = debit)
-- @param p_unit Unit of measurement
-- @param p_resource Optional resource identifier
-- @param p_reference_id Optional ledger entry ID being corrected
-- @param p_idempotency_key Optional dedup key for safe retries
-- @param p_metadata Optional JSON metadata
-- @param p_namespace Tenant namespace
-- @returns New balance and entry_id
-- @example SELECT * FROM meter.adjust('alice', 'llm_call', -500, 'tokens', 'claude-sonnet', p_reference_id := 12345);
CREATE FUNCTION meter.adjust(
    p_user_id text,
    p_event_type text,
    p_amount numeric,
    p_unit text,
    p_resource text DEFAULT NULL,
    p_reference_id bigint DEFAULT NULL,
    p_idempotency_key text DEFAULT NULL,
    p_metadata jsonb DEFAULT NULL,
    p_namespace text DEFAULT 'default'
)
RETURNS TABLE(balance numeric, entry_id bigint) AS $$
DECLARE
    v_account meter.accounts;
    v_new_balance numeric;
    v_entry_id bigint;
    v_existing RECORD;
BEGIN
    -- Validate
    PERFORM meter._validate_namespace(p_namespace);
    PERFORM meter._validate_event_type(p_event_type);
    PERFORM meter._validate_unit(p_unit);

    IF p_amount = 0 THEN
        RAISE EXCEPTION 'Adjustment amount cannot be zero'
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:meter:VAL_ADJUSTMENT_ZERO';
    END IF;

    -- Check idempotency (with advisory lock to prevent race conditions)
    IF p_idempotency_key IS NOT NULL THEN
        PERFORM meter._idempotency_lock(p_namespace, p_idempotency_key);

        SELECT l.id, l.balance_after INTO v_existing
        FROM meter.ledger l
        WHERE l.namespace = p_namespace AND l.idempotency_key = p_idempotency_key;

        IF FOUND THEN
            RETURN QUERY SELECT v_existing.balance_after, v_existing.id;
            RETURN;
        END IF;
    END IF;

    -- Get or create account with lock
    v_account := meter._upsert_account(p_namespace, p_user_id, p_event_type, p_resource, p_unit);

    -- Calculate new balance
    v_new_balance := v_account.balance + p_amount;

    -- Insert ledger entry
    v_entry_id := meter._insert_ledger(
        p_namespace, p_user_id, p_event_type, p_resource, p_unit,
        'adjustment', p_amount, v_new_balance, now(),
        p_idempotency_key, NULL, p_reference_id, p_metadata
    );

    -- Update account
    UPDATE meter.accounts SET
        balance = v_new_balance,
        total_credited = CASE WHEN p_amount > 0 THEN total_credited + p_amount ELSE total_credited END,
        total_debited = CASE WHEN p_amount < 0 THEN total_debited + abs(p_amount) ELSE total_debited END,
        last_entry_id = v_entry_id,
        updated_at = now()
    WHERE namespace = p_namespace
      AND user_id IS NOT DISTINCT FROM p_user_id
      AND event_type = p_event_type
      AND resource = COALESCE(p_resource, '')
      AND unit = p_unit;

    RETURN QUERY SELECT v_new_balance, v_entry_id;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = meter, pg_temp;
