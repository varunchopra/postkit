-- @group Internal

-- @function meter._hash64
-- @brief Generate a 64-bit hash from a text key using md5
-- @param p_key Text to hash
-- @returns bigint hash value
-- Uses first 16 hex chars of md5 (64 bits) for better collision resistance than hashtext (32 bits).
CREATE FUNCTION meter._hash64(p_key text)
RETURNS bigint AS $$
    SELECT ('x' || substr(md5(p_key), 1, 16))::bit(64)::bigint;
$$ LANGUAGE sql IMMUTABLE PARALLEL SAFE SECURITY INVOKER;


-- @function meter._idempotency_lock
-- @brief Acquire advisory lock for idempotency key to prevent race conditions
-- @param p_namespace Namespace
-- @param p_idempotency_key Idempotency key
-- @returns void (lock held until transaction ends)
CREATE FUNCTION meter._idempotency_lock(p_namespace text, p_idempotency_key text)
RETURNS void AS $$
BEGIN
    -- Advisory lock scoped to transaction, automatically released on commit/rollback
    PERFORM pg_advisory_xact_lock(meter._hash64(p_namespace || ':' || p_idempotency_key));
END;
$$ LANGUAGE plpgsql;


-- @function meter._get_actor_context
-- @brief Get current actor context from session settings
-- @returns Table with actor_id, on_behalf_of, reason, request_id
CREATE FUNCTION meter._get_actor_context()
RETURNS TABLE(actor_id text, on_behalf_of text, reason text, request_id text) AS $$
BEGIN
    RETURN QUERY SELECT
        nullif(current_setting('meter.actor_id', true), ''),
        nullif(current_setting('meter.on_behalf_of', true), ''),
        nullif(current_setting('meter.reason', true), ''),
        nullif(current_setting('meter.request_id', true), '');
END;
$$ LANGUAGE plpgsql STABLE;


-- @function meter._upsert_account
-- @brief Get or create account, returns current state with row lock
-- @param p_namespace Tenant namespace
-- @param p_user_id User ID (NULL for namespace-level pool)
-- @param p_event_type Event type
-- @param p_resource Resource identifier
-- @param p_unit Unit of measurement
-- @returns The account row (locked for update)
CREATE FUNCTION meter._upsert_account(
    p_namespace text,
    p_user_id text,
    p_event_type text,
    p_resource text,
    p_unit text
)
RETURNS meter.accounts AS $$
DECLARE
    v_account meter.accounts;
BEGIN
    -- IS NOT DISTINCT FROM is not sargable and seq-scans; hence this spelling.
    SELECT * INTO v_account
    FROM meter.accounts
    WHERE namespace = p_namespace
      AND (user_id = p_user_id OR (user_id IS NULL AND p_user_id IS NULL))
      AND event_type = p_event_type
      AND resource = COALESCE(p_resource, '')
      AND unit = p_unit
    FOR UPDATE;

    IF FOUND THEN
        RETURN v_account;
    END IF;

    -- ON CONFLICT inference cannot name a partial index by its predicate, so a
    -- pool row (conflicting on the WHERE user_id IS NULL index) routes through
    -- the catch-all rather than a named arbiter. A single per-user insert used
    -- for a pool row would miss its arbiter and raise unique_violation on a
    -- concurrent cold-start, hence the split by kind.
    IF p_user_id IS NOT NULL THEN
        INSERT INTO meter.accounts (namespace, user_id, event_type, resource, unit)
        VALUES (p_namespace, p_user_id, p_event_type, COALESCE(p_resource, ''), p_unit)
        ON CONFLICT (namespace, user_id, event_type, resource, unit)
            WHERE user_id IS NOT NULL
            DO NOTHING;
    ELSE
        INSERT INTO meter.accounts (namespace, user_id, event_type, resource, unit)
        VALUES (p_namespace, NULL, p_event_type, COALESCE(p_resource, ''), p_unit)
        ON CONFLICT DO NOTHING;
    END IF;

    -- Re-fetch with lock
    SELECT * INTO v_account
    FROM meter.accounts
    WHERE namespace = p_namespace
      AND (user_id = p_user_id OR (user_id IS NULL AND p_user_id IS NULL))
      AND event_type = p_event_type
      AND resource = COALESCE(p_resource, '')
      AND unit = p_unit
    FOR UPDATE;

    RETURN v_account;
END;
$$ LANGUAGE plpgsql;


-- @function meter._assert_account_write
-- @brief Guard that a balance write touched exactly one account row.
-- @param p_rows ROW_COUNT from the preceding UPDATE meter.accounts
-- A balance write is keyed by an account just upserted or locked, so it must
-- affect exactly one row. Zero means the WHERE clause missed it - the
-- three-valued user_id = NULL trap pool accounts invite - which silently
-- diverges the stored balance from the ledger. Fail loudly instead.
CREATE OR REPLACE FUNCTION meter._assert_account_write(p_rows int)
RETURNS void AS $$
BEGIN
    IF p_rows <> 1 THEN
        RAISE EXCEPTION 'account balance write affected % rows, expected exactly 1', p_rows
            USING ERRCODE = 'internal_error';
    END IF;
END;
$$ LANGUAGE plpgsql;


-- @function meter._insert_ledger
-- @brief Insert ledger entry with actor context
-- @returns The new ledger entry ID
CREATE FUNCTION meter._insert_ledger(
    p_namespace text,
    p_user_id text,
    p_event_type text,
    p_resource text,
    p_unit text,
    p_entry_type text,
    p_amount numeric,
    p_balance_after numeric,
    p_reserved_after numeric,
    p_event_time timestamptz,
    p_idempotency_key text DEFAULT NULL,
    p_reservation_id text DEFAULT NULL,
    p_reference_id bigint DEFAULT NULL,
    p_metadata jsonb DEFAULT NULL
)
RETURNS bigint AS $$
DECLARE
    v_ctx RECORD;
    v_id bigint;
BEGIN
    SELECT * INTO v_ctx FROM meter._get_actor_context();

    INSERT INTO meter.ledger (
        namespace, user_id, event_type, resource, unit,
        entry_type, amount, balance_after, reserved_after, event_time,
        idempotency_key, reservation_id, reference_id,
        actor_id, on_behalf_of, reason, request_id, metadata
    ) VALUES (
        p_namespace, p_user_id, p_event_type, COALESCE(p_resource, ''), p_unit,
        p_entry_type, p_amount, p_balance_after, p_reserved_after, p_event_time,
        p_idempotency_key, p_reservation_id, p_reference_id,
        v_ctx.actor_id, v_ctx.on_behalf_of, v_ctx.reason, v_ctx.request_id, p_metadata
    )
    RETURNING id INTO v_id;

    RETURN v_id;
END;
$$ LANGUAGE plpgsql;
