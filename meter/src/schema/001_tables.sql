-- =============================================================================
-- SCHEMA AND TABLES FOR POSTKIT/METER
-- =============================================================================
-- Double-entry ledger for usage tracking.
-- Meter measures. It does not price.
--
-- Design principles:
--   1. Double-entry ledger: Every balance change is an immutable ledger entry
--   2. Atomic operations: Check-and-decrement in single statement
--   3. Reservations: Hold tokens before operation, commit actual after
--   4. Idempotent: Safe retries via idempotency_key
--   5. Immutable audit trail: Ledger entries cannot be modified

CREATE SCHEMA IF NOT EXISTS meter;

-- =============================================================================
-- ACCOUNTS TABLE
-- =============================================================================
-- Current state, denormalized for fast reads.
-- One row per user/event_type/resource/unit combination.
-- Balance is authoritative but must equal SUM(ledger.amount) always.

CREATE TABLE meter.accounts (
    namespace text NOT NULL DEFAULT 'default',
    user_id text,                       -- NULL = namespace-level pool
    event_type text NOT NULL,
    resource text NOT NULL DEFAULT '',
    unit text NOT NULL,

    -- Current state
    balance numeric NOT NULL DEFAULT 0,
    reserved numeric NOT NULL DEFAULT 0,  -- amount held by active reservations

    -- Lifetime totals (for analytics)
    total_credited numeric NOT NULL DEFAULT 0,  -- sum of positive entries
    total_debited numeric NOT NULL DEFAULT 0,   -- sum of negative entries (stored positive)

    -- Period management
    period_start date,
    period_allocation numeric,          -- amount granted this period
    carry_over_limit numeric,           -- max unused to roll forward (NULL = no limit)

    -- Reconciliation
    last_entry_id bigint,
    last_reconciled_at timestamptz,

    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (namespace, user_id, event_type, resource, unit),

    CONSTRAINT accounts_balance_reserved CHECK (reserved >= 0),
    CONSTRAINT accounts_totals_positive CHECK (total_credited >= 0 AND total_debited >= 0)
);

-- Handle NULL user_id in primary key (namespace-level accounts)
CREATE UNIQUE INDEX accounts_namespace_pool_idx
    ON meter.accounts (namespace, event_type, resource, unit)
    WHERE user_id IS NULL;

-- =============================================================================
-- LEDGER TABLE
-- =============================================================================
-- Append-only, immutable. Every balance change is recorded here.
-- Partitioned by event_time for efficient retention management.
--
-- Entry types (balance-affecting only):
--   allocation          (+) Quota granted (purchase, plan, top-up)
--   consumption         (-) Usage recorded (includes reservation commits)
--   adjustment          (+/-) Correction (references original)
--   expiration          (-) Unused quota expired at period end
--   carry_over          (+) Rolled from previous period
--
-- Note: Reservations are NOT ledger entries - they're holds tracked in
-- meter.reservations table. Only actual consumption affects balance.

CREATE TABLE meter.ledger (
    id bigint GENERATED ALWAYS AS IDENTITY,
    namespace text NOT NULL DEFAULT 'default',

    -- Account reference
    user_id text,
    event_type text NOT NULL,
    resource text NOT NULL DEFAULT '',
    unit text NOT NULL,

    -- Entry details
    entry_type text NOT NULL,
    amount numeric NOT NULL,            -- signed: + credit, - debit
    balance_after numeric NOT NULL,     -- running balance after this entry

    -- Timing
    event_time timestamptz NOT NULL,    -- when usage occurred
    created_at timestamptz NOT NULL DEFAULT now(),

    -- Idempotency
    idempotency_key text,

    -- For consumption from committed reservations (links to original reservation)
    reservation_id text,

    -- For adjustments: reference to original entry
    reference_id bigint,

    -- Actor context
    actor_id text,
    on_behalf_of text,
    reason text,
    request_id text,

    metadata jsonb,

    PRIMARY KEY (id, event_time),

    CONSTRAINT ledger_entry_type_valid CHECK (entry_type IN (
        'allocation',
        'consumption',
        'adjustment',
        'expiration',
        'carry_over'
    )),
    CONSTRAINT ledger_amount_sign CHECK (
        (entry_type = 'allocation' AND amount > 0) OR
        (entry_type = 'consumption' AND amount < 0) OR
        (entry_type = 'expiration' AND amount < 0) OR
        (entry_type = 'carry_over' AND amount > 0) OR
        (entry_type = 'adjustment')
    )
) PARTITION BY RANGE (event_time);

-- =============================================================================
-- RESERVATIONS TABLE
-- =============================================================================
-- Tracks reservation lifecycle for holds management and audit trail.
-- Reservations are NOT balance changes - they're holds tracked separately.
-- Status transitions: active -> committed/released/expired
-- Records are retained for audit (not deleted on completion).

CREATE TABLE meter.reservations (
    reservation_id text PRIMARY KEY,
    namespace text NOT NULL,
    user_id text,
    event_type text NOT NULL,
    resource text NOT NULL DEFAULT '',
    unit text NOT NULL,

    amount numeric NOT NULL,
    balance_at_create numeric NOT NULL,  -- account balance when reservation was created

    -- Lifecycle tracking
    status text NOT NULL DEFAULT 'active',
    completed_at timestamptz,           -- when committed/released/expired
    actual_amount numeric,              -- actual consumption (for committed)

    -- Reference to consumption ledger entry (set on commit)
    consumption_entry_id bigint,

    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),

    -- Idempotency (separate from request_id which is for tracing)
    idempotency_key text,

    -- Actor context
    actor_id text,
    request_id text,                    -- for tracing/correlation
    metadata jsonb,

    CONSTRAINT reservations_status_valid CHECK (
        status IN ('active', 'committed', 'released', 'expired')
    ),
    CONSTRAINT reservations_completed_fields CHECK (
        (status = 'active' AND completed_at IS NULL) OR
        (status != 'active' AND completed_at IS NOT NULL)
    ),
    CONSTRAINT reservations_actual_amount CHECK (
        (status = 'committed' AND actual_amount IS NOT NULL) OR
        (status != 'committed')
    )
);

-- =============================================================================
-- ROW-LEVEL SECURITY
-- =============================================================================
-- Note: current_setting(..., TRUE) returns '' when not set.
-- We explicitly check for non-empty to fail-closed when tenant context is missing.

ALTER TABLE meter.accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE meter.accounts FORCE ROW LEVEL SECURITY;
CREATE POLICY accounts_tenant_isolation ON meter.accounts
    USING (
        current_setting('meter.tenant_id', TRUE) != ''
        AND namespace = current_setting('meter.tenant_id', TRUE)
    )
    WITH CHECK (
        current_setting('meter.tenant_id', TRUE) != ''
        AND namespace = current_setting('meter.tenant_id', TRUE)
    );

ALTER TABLE meter.ledger ENABLE ROW LEVEL SECURITY;
ALTER TABLE meter.ledger FORCE ROW LEVEL SECURITY;
CREATE POLICY ledger_tenant_isolation ON meter.ledger
    USING (
        current_setting('meter.tenant_id', TRUE) != ''
        AND namespace = current_setting('meter.tenant_id', TRUE)
    )
    WITH CHECK (
        current_setting('meter.tenant_id', TRUE) != ''
        AND namespace = current_setting('meter.tenant_id', TRUE)
    );

ALTER TABLE meter.reservations ENABLE ROW LEVEL SECURITY;
ALTER TABLE meter.reservations FORCE ROW LEVEL SECURITY;
CREATE POLICY reservations_tenant_isolation ON meter.reservations
    USING (
        current_setting('meter.tenant_id', TRUE) != ''
        AND namespace = current_setting('meter.tenant_id', TRUE)
    )
    WITH CHECK (
        current_setting('meter.tenant_id', TRUE) != ''
        AND namespace = current_setting('meter.tenant_id', TRUE)
    );
