-- @group Recording

-- @function meter.allocate
-- @brief Add quota/credits to an account
-- @param p_user_id User ID (NULL for namespace-level pool)
-- @param p_event_type Event type ('llm_call', 'api_request', etc.)
-- @param p_amount Amount to allocate (must be positive)
-- @param p_unit Unit of measurement ('tokens', 'requests', 'bytes')
-- @param p_resource Optional resource identifier ('claude-sonnet', 'gpt-4')
-- @param p_idempotency_key Optional dedup key for safe retries
-- @param p_event_time When the allocation occurred (defaults to now)
-- @param p_metadata Optional JSON metadata
-- @param p_namespace Tenant namespace
-- @returns New balance and entry_id
-- @example SELECT * FROM meter.allocate('alice', 'llm_call', 100000, 'tokens', 'claude-sonnet');
CREATE FUNCTION meter.allocate(
    p_user_id text,
    p_event_type text,
    p_amount numeric,
    p_unit text,
    p_resource text DEFAULT NULL,
    p_idempotency_key text DEFAULT NULL,
    p_event_time timestamptz DEFAULT NULL,
    p_metadata jsonb DEFAULT NULL,
    p_namespace text DEFAULT 'default'
)
RETURNS TABLE(balance numeric, entry_id bigint) AS $$
DECLARE
    v_account meter.accounts;
    v_new_balance numeric;
    v_entry_id bigint;
    v_event_time timestamptz;
    v_existing_id bigint;
    v_rows int;
BEGIN
    -- Validate
    PERFORM meter._validate_namespace(p_namespace);
    PERFORM meter._validate_event_type(p_event_type);
    PERFORM meter._validate_unit(p_unit);
    PERFORM meter._validate_positive(p_amount, 'amount');

    v_event_time := COALESCE(p_event_time, now());

    -- Check idempotency (with advisory lock to prevent race conditions)
    IF p_idempotency_key IS NOT NULL THEN
        PERFORM meter._idempotency_lock(p_namespace, p_idempotency_key);

        SELECT l.id, l.balance_after INTO v_existing_id, v_new_balance
        FROM meter.ledger l
        WHERE l.namespace = p_namespace AND l.idempotency_key = p_idempotency_key;

        IF FOUND THEN
            RETURN QUERY SELECT v_new_balance, v_existing_id;
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
        'allocation', p_amount, v_new_balance, v_account.reserved,
        v_event_time, p_idempotency_key, NULL, NULL, p_metadata
    );

    -- Update account
    UPDATE meter.accounts SET
        balance = v_new_balance,
        total_credited = total_credited + p_amount,
        last_entry_id = v_entry_id,
        updated_at = now()
    WHERE namespace = p_namespace
      AND (user_id = p_user_id OR (user_id IS NULL AND p_user_id IS NULL))
      AND event_type = p_event_type
      AND resource = COALESCE(p_resource, '')
      AND unit = p_unit;
    GET DIAGNOSTICS v_rows = ROW_COUNT;
    PERFORM meter._assert_account_write(v_rows);

    RETURN QUERY SELECT v_new_balance, v_entry_id;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = meter, pg_temp;
