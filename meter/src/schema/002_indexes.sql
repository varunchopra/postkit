-- =============================================================================
-- INDEXES FOR POSTKIT/METER
-- =============================================================================

-- Idempotency lookup (not unique due to partitioning constraints)
-- Uniqueness is enforced by the functions checking before insert
CREATE INDEX ledger_idempotency_idx
    ON meter.ledger (namespace, idempotency_key)
    WHERE idempotency_key IS NOT NULL;

-- Account history queries
CREATE INDEX ledger_account_time_idx
    ON meter.ledger (namespace, user_id, event_type, resource, unit, event_time DESC);

-- Find entries by reservation
CREATE INDEX ledger_reservation_idx
    ON meter.ledger (reservation_id)
    WHERE reservation_id IS NOT NULL;

-- Adjustment reference lookup
CREATE INDEX ledger_reference_idx
    ON meter.ledger (reference_id)
    WHERE reference_id IS NOT NULL;

-- Active reservations by expiry (for cleanup job)
CREATE INDEX reservations_active_expires_idx
    ON meter.reservations (expires_at)
    WHERE status = 'active';

-- Active reservations by account (for balance checks)
CREATE INDEX reservations_active_account_idx
    ON meter.reservations (namespace, user_id, event_type, resource, unit)
    WHERE status = 'active';

-- Reservation history by namespace (for audit queries)
CREATE INDEX reservations_namespace_time_idx
    ON meter.reservations (namespace, created_at DESC);

-- Idempotency lookup (unique to prevent duplicate reservations)
CREATE UNIQUE INDEX reservations_idempotency_idx
    ON meter.reservations (namespace, idempotency_key)
    WHERE idempotency_key IS NOT NULL;

-- Namespace-level account lookup
CREATE INDEX accounts_namespace_idx
    ON meter.accounts (namespace, event_type, resource, unit);

-- User balance lookups (get_user_balances, dashboard queries)
CREATE INDEX accounts_user_lookup_idx
    ON meter.accounts (namespace, user_id)
    WHERE user_id IS NOT NULL;
