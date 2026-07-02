-- =============================================================================
-- SCHEMA AND TABLES FOR POSTKIT/LEASE
-- =============================================================================
-- TTL-based named locks with fencing tokens.
-- The lock and the write it protects commit together.
--
-- Design principles:
--   1. Fencing: Every acquisition gets a monotonic token; lease.verify()
--      inside the caller's transaction makes fence-check and protected
--      write atomic
--   2. Lazy expiry: No reaper. An expired lease is simply acquirable;
--      takeover overwrites it and is event-logged
--   3. Multi-tenant: Namespace isolation via RLS
--   4. Non-blocking: acquire never waits for a live lease to expire
--      (it may wait briefly on in-flight row locks)
--   5. Auditable: acquire/takeover/release append to lease.events
--
-- Invariants (referenced as I1-I5 by function comments and the test suite):
--   I1. At most one live (unexpired) holder per (namespace, name)
--   I2. fence_token strictly increases across distinct acquisitions of a
--       name (gaps are legal); renewal never changes it
--   I3. Past expires_at, the old holder can never renew or verify with the
--       old token – even before anyone else acquires. Re-acquiring (even
--       your own expired lease) issues a new token
--   I4. verify in transaction T and a takeover in T' serialize: T commits
--       with a valid lease, or T aborts. No interleaving where both win
--   I5. Fence tokens are comparable only within one lease name (per-name
--       counters, never a global sequence)
--
-- Deployment-level concerns (intentionally not handled by this library):
--
--   6. No GRANT/REVOKE statements. Role creation and permission grants are
--      the deployer's responsibility. A library cannot assume role names,
--      connection pooling strategy, or pg_hba.conf layout. Shipping
--      opinionated grants would be either too permissive or too restrictive.
--
--   7. No metadata size constraint. PostgreSQL already limits TOAST-able
--      columns to ~1 GB. The acceptable metadata size is a deployment
--      policy decision. Deployers can add a CHECK constraint or validate
--      at the application layer.
--
--   8. Actor context columns are nullable. Requiring them would break
--      migrations, cron tickers, REPL debugging, and any non-request
--      context. The audit trail is best-effort by design; the application
--      layer decides when actor attribution is mandatory.

CREATE SCHEMA IF NOT EXISTS lease;

-- =============================================================================
-- LEASES TABLE
-- =============================================================================
-- One row per held lease. There is no 'expired' status: a row whose
-- expires_at has passed is simply acquirable (lazy expiry). Rows are
-- deleted on release and overwritten on takeover.

CREATE TABLE lease.leases (
    namespace text NOT NULL,
    name text NOT NULL,

    -- Holder identity (opaque to the module)
    holder_id text NOT NULL,

    -- Fencing token: monotonic per (namespace, name), sourced from
    -- lease.fence_counters. Comparable ONLY within one lease name.
    fence_token bigint NOT NULL,

    -- Lifetime
    acquired_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,

    -- Metadata
    metadata jsonb NOT NULL DEFAULT '{}',

    -- Actor context (captured at acquire time)
    actor_id text,
    request_id text,
    on_behalf_of text,
    reason text,

    -- Timestamps
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (namespace, name),

    CONSTRAINT leases_expiry_sane CHECK (expires_at > acquired_at)
);

-- =============================================================================
-- FENCE COUNTERS TABLE
-- =============================================================================
-- Tracks the highest fence token ever issued per lease name. Kept separate
-- from lease.leases so the counter survives lease-row deletion (release) –
-- fence tokens must strictly increase across distinct acquisitions forever.
-- Same pattern as config.version_counters.
--
-- One row per lease name ever used, kept permanently (deleting one would
-- reset its fence sequence). Use stable names ('exporter:cust_42'), not
-- per-job ephemeral names, or this table grows without bound.
--
-- The counter row doubles as the per-name acquire mutex: acquire locks it
-- (FOR UPDATE) before touching the lease row, giving all acquire paths a
-- uniform lock order (counter -> lease) and serializing concurrent
-- first-acquires without a retry loop.

CREATE TABLE lease.fence_counters (
    namespace text NOT NULL,
    name text NOT NULL,
    counter bigint NOT NULL DEFAULT 0,
    PRIMARY KEY (namespace, name)
);

-- =============================================================================
-- EVENTS TABLE
-- =============================================================================
-- Append-only log of lease lifecycle events: acquired, released, taken_over.
-- Prune with lease.prune_events(); retention is the deployer's decision.
--
-- There is deliberately NO 'renewed' event: renewals fire at ~ttl/3 per
-- holder, so logging them would be unbounded high-frequency growth.
-- Renewal observability lives in leases.updated_at.

CREATE TABLE lease.events (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    namespace text NOT NULL,
    name text NOT NULL,
    event text NOT NULL,

    holder_id text,
    fence_token bigint,
    previous_holder text,               -- set on taken_over

    at timestamptz NOT NULL DEFAULT now(),

    -- Actor context (captured at event time)
    actor_id text,
    request_id text,
    on_behalf_of text,
    reason text,

    CONSTRAINT events_type_valid CHECK (
        event IN ('acquired', 'released', 'taken_over')
    )
);

CREATE INDEX events_name_idx ON lease.events (namespace, name, at DESC);

-- Unfiltered event reads (get_events without a name) and prune scans
CREATE INDEX events_time_idx ON lease.events (namespace, at DESC, id DESC);

-- =============================================================================
-- CONFIG TABLE
-- =============================================================================
-- Per-tenant configuration with global defaults.
-- 'global' row provides defaults; tenants can override with their own row.

CREATE TABLE lease.config (
    namespace text NOT NULL PRIMARY KEY,
    default_ttl interval NOT NULL DEFAULT '30 seconds',
    max_ttl interval NOT NULL DEFAULT '1 hour',
    notify_on_release boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- Global defaults (read by all, write-protected via RLS)
INSERT INTO lease.config (namespace) VALUES ('global') ON CONFLICT DO NOTHING;

-- =============================================================================
-- ROW-LEVEL SECURITY
-- =============================================================================
-- Fail-closed: empty tenant context returns zero rows.
-- current_setting(..., TRUE) returns '' when not set.

-- Leases: standard tenant isolation
ALTER TABLE lease.leases ENABLE ROW LEVEL SECURITY;
ALTER TABLE lease.leases FORCE ROW LEVEL SECURITY;

CREATE POLICY leases_tenant_isolation ON lease.leases
    USING (
        current_setting('lease.tenant_id', TRUE) != ''
        AND namespace = current_setting('lease.tenant_id', TRUE)
    )
    WITH CHECK (
        current_setting('lease.tenant_id', TRUE) != ''
        AND namespace = current_setting('lease.tenant_id', TRUE)
    );

-- Fence counters: standard tenant isolation
ALTER TABLE lease.fence_counters ENABLE ROW LEVEL SECURITY;
ALTER TABLE lease.fence_counters FORCE ROW LEVEL SECURITY;

CREATE POLICY fence_counters_tenant_isolation ON lease.fence_counters
    USING (
        current_setting('lease.tenant_id', TRUE) != ''
        AND namespace = current_setting('lease.tenant_id', TRUE)
    )
    WITH CHECK (
        current_setting('lease.tenant_id', TRUE) != ''
        AND namespace = current_setting('lease.tenant_id', TRUE)
    );

-- Events: standard tenant isolation
ALTER TABLE lease.events ENABLE ROW LEVEL SECURITY;
ALTER TABLE lease.events FORCE ROW LEVEL SECURITY;

CREATE POLICY events_tenant_isolation ON lease.events
    USING (
        current_setting('lease.tenant_id', TRUE) != ''
        AND namespace = current_setting('lease.tenant_id', TRUE)
    )
    WITH CHECK (
        current_setting('lease.tenant_id', TRUE) != ''
        AND namespace = current_setting('lease.tenant_id', TRUE)
    );

-- Config: global readable, tenant can only write their own row
ALTER TABLE lease.config ENABLE ROW LEVEL SECURITY;
ALTER TABLE lease.config FORCE ROW LEVEL SECURITY;

-- All tenants can read global config
CREATE POLICY config_global_read ON lease.config
    FOR SELECT
    USING (namespace = 'global');

-- Tenants can read/write their own config
CREATE POLICY config_tenant_isolation ON lease.config
    USING (
        current_setting('lease.tenant_id', TRUE) != ''
        AND namespace = current_setting('lease.tenant_id', TRUE)
    )
    WITH CHECK (
        current_setting('lease.tenant_id', TRUE) != ''
        AND namespace = current_setting('lease.tenant_id', TRUE)
    );

-- Prevent any tenant from writing to global (RESTRICTIVE policy)
CREATE POLICY config_global_write_protection ON lease.config
    AS RESTRICTIVE
    FOR ALL
    USING (TRUE)
    WITH CHECK (namespace != 'global');
