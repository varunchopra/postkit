-- =============================================================================
-- SCHEMA AND TABLES FOR POSTKIT/PRESENCE
-- =============================================================================
-- Heartbeat liveness for a fleet of entities with clean edge detection.
-- Transitions, not statuses, are what callers act on; the death transition
-- can be atomic with its response (mark dead, reassign work, enqueue the
-- alert) in one commit.
--
-- Design principles:
--   1. Transitions are the API: an append-only alive -> dead -> alive
--      stream; the status column is a cache of the latest edge
--   2. Passive: sweep is a function the deployer calls on a timer; nothing
--      runs on its own
--   3. Both edges captured where they happen: death in sweep, revival in
--      heartbeat - revival never waits for a tick
--   4. Multi-tenant: namespace isolation via RLS
--   5. Standalone: queue hooks are optional composition; presence installs
--      and runs with nothing else
--
-- Invariants (referenced as P1-P5 by function comments and the test suite):
--   P1. Exactly-once transitions: each logical edge produces exactly one
--       transitions row, under concurrent sweeps and heartbeats. All
--       transitions happen under the entity row lock (heartbeat's UPDATE
--       vs sweep's FOR UPDATE SKIP LOCKED); status checks happen under
--       the lock
--   P2. Transitions are the API; status is cache. The status column may
--       lag the wall-clock truth by up to the sweep cadence; death
--       detection latency is at most dead_after + the sweep interval
--   P3. Liveness math on the wall clock: every last_seen stamp and every
--       comparison against dead_after uses clock_timestamp(), never
--       now() - a heartbeat riding a long caller transaction must record
--       its real send time, not the transaction start
--   P4. departed is not died: deregister emits a departed transition,
--       never fires death hooks, and never counts toward flap damping
--   P5. Flap damping records but suppresses, and suppression DEFERS
--       terminal alerts, never drops them: transitions are always
--       recorded; hooks and NOTIFY are suppressed while flapping; a death
--       hook suppressed by damping is fired by a later sweep once the
--       flap window expires and the entity is still dead
--
-- Deployment-level concerns (intentionally not handled by this library):
--
--   6. No GRANT/REVOKE statements. Role creation and permission grants are
--      the deployer's responsibility.
--
--   7. No metadata size constraint. PostgreSQL already limits TOAST-able
--      columns to ~1 GB; acceptable metadata size is a deployment decision.
--
--   8. No retention default. presence.trim requires the retention interval
--      explicitly - transition history retention is a policy decision.
--
--   9. Actor context columns are nullable. Requiring them would break
--      migrations, cron tickers, and non-request contexts.

CREATE SCHEMA IF NOT EXISTS presence;

-- =============================================================================
-- ENTITIES TABLE
-- =============================================================================
-- One row per tracked entity. Statuses: 'unknown' (registered, never
-- heartbeated), 'alive', 'dead'. Nothing can die before first contact:
-- unknown entities have last_seen NULL and are never swept. Deregister
-- deletes the row (departed is a transition type, not a status);
-- re-register recreates it at unknown.

CREATE TABLE presence.entities (
    namespace text NOT NULL,
    entity_id text NOT NULL,
    kind text NOT NULL DEFAULT 'default',

    status text NOT NULL DEFAULT 'unknown',
    last_seen timestamptz,
    alive_since timestamptz,
    dead_since timestamptz,

    -- Flap damping state (see _record_transition)
    flap_count int NOT NULL DEFAULT 0,
    flap_window_started timestamptz,

    -- Set when damping suppresses a DEATH hook; a later sweep fires the
    -- deferred hook and clears it (or revival clears it). Suppression must
    -- defer terminal alerts, never drop them: a final death during a flap
    -- window would otherwise never page anyone (P5).
    hook_suppressed boolean NOT NULL DEFAULT false,

    -- Per-entity liveness window; REPLACES the kind's dead_after when set
    -- (never combined with it - see sweep's predicate)
    timeout_override interval,

    metadata jsonb NOT NULL DEFAULT '{}',

    -- Actor context (captured at register time)
    actor_id text,
    request_id text,
    on_behalf_of text,
    reason text,

    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (namespace, entity_id),

    CONSTRAINT entities_status_valid CHECK (
        status IN ('unknown', 'alive', 'dead')
    ),
    CONSTRAINT entities_timeout_positive CHECK (
        timeout_override IS NULL OR timeout_override > interval '0'
    )
)
-- Heartbeats rewrite last_seen constantly and no index covers the mutated
-- columns, so page slack keeps those updates HOT (no index maintenance).
WITH (fillfactor = 90);

-- list/sweep scans. Deliberately NO index on last_seen: it is the hottest
-- mutated column, and indexing it would make every heartbeat a non-HOT
-- update, defeating the fillfactor on the module's highest-frequency write
-- path. The cost lands on sweep, which filters the alive set through this
-- index once per tick - acceptable at fleet scale, and a periodic tick is
-- the right place to pay it. Revisiting this is an index decision taken
-- with the heartbeat trade-off in hand, not a drive-by.
CREATE INDEX entities_kind_status_idx
    ON presence.entities (namespace, kind, status);

-- =============================================================================
-- TRANSITIONS TABLE
-- =============================================================================
-- Append-only edge stream; the product surface. Rows are emitted by
-- heartbeat (unknown/dead -> alive), sweep (alive -> dead), and deregister
-- (any -> departed). Prune with presence.trim(); retention is the
-- deployer's decision.
--
-- Transitions is queryable HISTORY, not a pollable feed. Rows emitted by
-- heartbeat ride the caller's transaction, so a transition's id order and
-- its commit order diverge exactly as outbox events do (xid is assigned at
-- the transaction's first write, id at insert): an id-cursor poller would
-- silently lose a late-committing revival. Delivery is the queue hooks and
-- NOTIFY. The xid column exists so a horizon-gated (xid, id) reader can be
-- added without a migration; until then, do not poll this table by id.

CREATE TABLE presence.transitions (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    namespace text NOT NULL,
    entity_id text NOT NULL,
    kind text NOT NULL,

    xid xid8 NOT NULL DEFAULT pg_current_xact_id(),

    from_status text NOT NULL,
    to_status text NOT NULL,

    -- Wall clock (P3): a revival riding a long caller transaction must not
    -- stamp the transaction start while silent_for uses the real clock
    at timestamptz NOT NULL DEFAULT clock_timestamp(),

    silent_for interval,               -- for deaths: how long the entity was quiet
    flapping boolean NOT NULL DEFAULT false,

    -- Actor context (captured at transition time)
    actor_id text,
    request_id text,
    on_behalf_of text,
    reason text,

    CONSTRAINT transitions_from_valid CHECK (
        from_status IN ('unknown', 'alive', 'dead')
    ),
    CONSTRAINT transitions_to_valid CHECK (
        to_status IN ('alive', 'dead', 'departed')
    )
);

CREATE INDEX transitions_entity_idx
    ON presence.transitions (namespace, entity_id, at DESC);

-- Namespace-wide reads (get_transitions without an entity) and trim scans
CREATE INDEX transitions_time_idx
    ON presence.transitions (namespace, at DESC, id DESC);

-- =============================================================================
-- CONFIG TABLE
-- =============================================================================
-- Per (namespace, kind) with fallback: (ns, kind) -> (ns, 'default') ->
-- ('global', 'default'). Deliberately NO ('global', kind) step - global
-- rows for tenant-defined kinds are incoherent. Seeded row is
-- ('global', 'default').

CREATE TABLE presence.config (
    namespace text NOT NULL,
    kind text NOT NULL DEFAULT 'default',

    dead_after interval NOT NULL DEFAULT '90 seconds',
    heartbeat_coalesce interval NOT NULL DEFAULT '0',

    flap_threshold int NOT NULL DEFAULT 4,
    flap_window interval NOT NULL DEFAULT '10 minutes',

    -- queue.push targets; queue is a soft dependency (see _fire_hooks)
    on_death_queue text,
    on_revival_queue text,

    notify boolean NOT NULL DEFAULT true,

    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (namespace, kind),

    CONSTRAINT config_dead_after_positive CHECK (dead_after > interval '0'),
    CONSTRAINT config_flap_threshold_positive CHECK (flap_threshold > 0)
);

-- Global defaults (read by all, write-protected via RLS)
INSERT INTO presence.config (namespace, kind)
VALUES ('global', 'default')
ON CONFLICT DO NOTHING;

-- =============================================================================
-- ROW-LEVEL SECURITY
-- =============================================================================
-- Fail-closed: empty tenant context returns zero rows.
-- current_setting(..., TRUE) returns '' when not set.

-- Entities: standard tenant isolation
ALTER TABLE presence.entities ENABLE ROW LEVEL SECURITY;
ALTER TABLE presence.entities FORCE ROW LEVEL SECURITY;

CREATE POLICY entities_tenant_isolation ON presence.entities
    USING (
        current_setting('presence.tenant_id', TRUE) != ''
        AND namespace = current_setting('presence.tenant_id', TRUE)
    )
    WITH CHECK (
        current_setting('presence.tenant_id', TRUE) != ''
        AND namespace = current_setting('presence.tenant_id', TRUE)
    );

-- Transitions: standard tenant isolation
ALTER TABLE presence.transitions ENABLE ROW LEVEL SECURITY;
ALTER TABLE presence.transitions FORCE ROW LEVEL SECURITY;

CREATE POLICY transitions_tenant_isolation ON presence.transitions
    USING (
        current_setting('presence.tenant_id', TRUE) != ''
        AND namespace = current_setting('presence.tenant_id', TRUE)
    )
    WITH CHECK (
        current_setting('presence.tenant_id', TRUE) != ''
        AND namespace = current_setting('presence.tenant_id', TRUE)
    );

-- Config: global readable, tenant can only write their own rows
ALTER TABLE presence.config ENABLE ROW LEVEL SECURITY;
ALTER TABLE presence.config FORCE ROW LEVEL SECURITY;

-- All tenants can read global config
CREATE POLICY config_global_read ON presence.config
    FOR SELECT
    USING (namespace = 'global');

-- Tenants can read/write their own config
CREATE POLICY config_tenant_isolation ON presence.config
    USING (
        current_setting('presence.tenant_id', TRUE) != ''
        AND namespace = current_setting('presence.tenant_id', TRUE)
    )
    WITH CHECK (
        current_setting('presence.tenant_id', TRUE) != ''
        AND namespace = current_setting('presence.tenant_id', TRUE)
    );

-- Prevent any tenant from writing to global (RESTRICTIVE policy)
CREATE POLICY config_global_write_protection ON presence.config
    AS RESTRICTIVE
    FOR ALL
    USING (TRUE)
    WITH CHECK (namespace != 'global');
