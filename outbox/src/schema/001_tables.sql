-- =============================================================================
-- SCHEMA AND TABLES FOR POSTKIT/OUTBOX
-- =============================================================================
-- Transactional event feed with durable per-consumer cursors.
-- The event exists iff the state change that caused it committed.
--
-- Design principles:
--   1. Transactional emit: events append inside the caller's transaction,
--      eliminating the dual-write problem entirely
--   2. Ordered fan-out: every consumer independently sees every event in
--      (xid, id) order (queue is competing consumers; outbox is fan-out)
--   3. Horizon gating: reads return only events whose transaction has
--      finished, so cursors are safe under concurrent commits
--   4. Pull + wake-up: consumers poll; NOTIFY only wakes them
--   5. Multi-tenant: Namespace isolation via RLS
--
-- Positions everywhere in this module are (xid, id) PAIRS, compared
-- lexicographically. Ids alone cannot order delivery safely: xid is
-- assigned at a transaction's FIRST write while id is assigned at emit, so
-- a transaction that does business writes before emitting (the documented
-- usage) carries an OLD xid with a HIGH id, and a plain id cursor can be
-- acked past a not-yet-visible lower id that then commits behind it,
-- permanently. What IS frozen below the horizon is xid order: every gated
-- xid has finished, and anything that becomes visible later carries a
-- higher xid. A test that emits as its transaction's first write cannot
-- tell id order from xid order and validates nothing about the gate; the
-- gate's tests must put a business write before the emit.
--
-- Invariants (referenced as O1-O5 by function comments and the test suite):
--   O1. Cursor safety: no event ever becomes visible at or behind a
--       consumer's cursor – reads return only rows with xid below the
--       snapshot horizon, every later-visible event sorts above every
--       gated (xid, id) pair, and cursors are such pairs
--   O2. Transactional emit: an event exists iff the transaction that
--       emitted it committed
--   O3. Independent fan-out: each (topic, consumer) cursor advances
--       independently; acking one consumer never affects another
--   O4. Ordered delivery: within a topic a consumer receives events in
--       strictly increasing (xid, id) order with no gaps below the horizon
--   O5. Loud loss: a position below the trimmed pair raises CURSOR_LOST
--       carrying the oldest available position; reads never silently skip
--
-- Deployment-level concerns (intentionally not handled by this library):
--
--   6. No GRANT/REVOKE statements. Role creation and permission grants are
--      the deployer's responsibility. A library cannot assume role names,
--      connection pooling strategy, or pg_hba.conf layout.
--
--   7. No payload size constraint. PostgreSQL already limits TOAST-able
--      columns to ~1 GB; acceptable payload size is a deployment decision.
--
--   8. No retention default. outbox.trim requires the retention interval
--      explicitly – how much event history to keep is a policy decision.
--
--   9. Actor context columns are nullable. Requiring them would break
--      migrations, cron tickers, and non-request contexts.

CREATE SCHEMA IF NOT EXISTS outbox;

-- =============================================================================
-- EVENTS TABLE
-- =============================================================================
-- Append-only. The id sequence is GLOBAL across topics and namespaces, so
-- within one topic ids are strictly increasing but SPARSE – never do
-- arithmetic on them (count backlogs, don't subtract positions).
--
-- created_at is transaction-start time while id is assigned at insert
-- execution, so age order and (xid, id) order can diverge by up to a
-- transaction's duration; trim's prefix boundary accounts for this.

CREATE TABLE outbox.events (
    namespace text NOT NULL,
    topic text NOT NULL,
    id bigint GENERATED ALWAYS AS IDENTITY,

    -- Emitting transaction: the leading component of the delivery order
    -- and of the horizon gate (O1). Reads return only rows with xid below
    -- the snapshot horizon; everything visible later sorts above them.
    xid xid8 NOT NULL DEFAULT pg_current_xact_id(),

    -- Event content
    event_type text NOT NULL,
    key text,                          -- optional entity key for downstream sharding
    payload jsonb NOT NULL,

    created_at timestamptz NOT NULL DEFAULT now(),

    -- Actor context (captured at emit time)
    actor_id text,
    request_id text,
    on_behalf_of text,
    reason text,

    -- Identity only; id stays the human-readable reference in errors and
    -- payload hints. All range scans use the order index below.
    PRIMARY KEY (namespace, topic, id)
);

-- The delivery order (O1): poll, ack's head check, and trim all range-scan
-- (xid, id) pairs through this index.
CREATE INDEX events_order_idx ON outbox.events (namespace, topic, xid, id);

-- Exists only for trim's age boundary. Without it that lookup walks the
-- order index backwards through the entire retained set, heap-checking
-- created_at row by row on every tick; with it trim scans just the rows
-- older than the cutoff, which it is about to delete anyway. The price is
-- a third index on the append path, cheap because created_at is
-- near-monotonic and inserts land near the rightmost leaf.
CREATE INDEX events_trim_idx ON outbox.events (namespace, topic, created_at);

-- =============================================================================
-- CURSORS TABLE
-- =============================================================================
-- One durable position per (topic, consumer): the (xid, id) of the last
-- acked event. ('0', 0) means nothing acked. Consumers treat the pair as
-- opaque; it flows from polled rows into ack.

CREATE TABLE outbox.cursors (
    namespace text NOT NULL,
    topic text NOT NULL,
    consumer text NOT NULL,
    position_xid xid8 NOT NULL,
    position_id bigint NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (namespace, topic, consumer)
)
-- Every ack rewrites the row and no index covers the position columns, so
-- page slack keeps those updates HOT (no index maintenance).
WITH (fillfactor = 90);

-- =============================================================================
-- TOPICS TABLE
-- =============================================================================
-- Per-topic bookkeeping. (trimmed_xid, trimmed_id) is the greatest pair
-- ever deleted by trim; a position below it means trimmed-away events,
-- detected exactly (O5) – probing the oldest surviving row instead would
-- be ambiguous on an empty topic.
--
-- Rows are created lazily on first emit AND first subscribe: deploying the
-- consumer before the producer is the normal rollout order, so reads must
-- never depend on an emit having happened.

CREATE TABLE outbox.topics (
    namespace text NOT NULL,
    topic text NOT NULL,
    trimmed_xid xid8 NOT NULL DEFAULT '0',
    trimmed_id bigint NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (namespace, topic)
);

-- =============================================================================
-- CONFIG TABLE
-- =============================================================================
-- Per (namespace, topic) with wildcard fallback: exact -> (namespace, '*')
-- -> ('global', '*'). The '*' topic value is reserved (topic validation
-- rejects it) so a real topic can never shadow the wildcard.

CREATE TABLE outbox.config (
    namespace text NOT NULL,
    topic text NOT NULL DEFAULT '*',
    notify boolean NOT NULL DEFAULT true,
    protect_cursors boolean NOT NULL DEFAULT true,
    retain_min_rows int NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (namespace, topic),
    CONSTRAINT config_retain_min_rows_nonnegative CHECK (retain_min_rows >= 0)
);

-- Global defaults (read by all, write-protected via RLS)
INSERT INTO outbox.config (namespace, topic) VALUES ('global', '*') ON CONFLICT DO NOTHING;

-- =============================================================================
-- ROW-LEVEL SECURITY
-- =============================================================================
-- Fail-closed: empty tenant context returns zero rows.
-- current_setting(..., TRUE) returns '' when not set.

-- Events: standard tenant isolation
ALTER TABLE outbox.events ENABLE ROW LEVEL SECURITY;
ALTER TABLE outbox.events FORCE ROW LEVEL SECURITY;

CREATE POLICY events_tenant_isolation ON outbox.events
    USING (
        current_setting('outbox.tenant_id', TRUE) != ''
        AND namespace = current_setting('outbox.tenant_id', TRUE)
    )
    WITH CHECK (
        current_setting('outbox.tenant_id', TRUE) != ''
        AND namespace = current_setting('outbox.tenant_id', TRUE)
    );

-- Cursors: standard tenant isolation
ALTER TABLE outbox.cursors ENABLE ROW LEVEL SECURITY;
ALTER TABLE outbox.cursors FORCE ROW LEVEL SECURITY;

CREATE POLICY cursors_tenant_isolation ON outbox.cursors
    USING (
        current_setting('outbox.tenant_id', TRUE) != ''
        AND namespace = current_setting('outbox.tenant_id', TRUE)
    )
    WITH CHECK (
        current_setting('outbox.tenant_id', TRUE) != ''
        AND namespace = current_setting('outbox.tenant_id', TRUE)
    );

-- Topics: standard tenant isolation
ALTER TABLE outbox.topics ENABLE ROW LEVEL SECURITY;
ALTER TABLE outbox.topics FORCE ROW LEVEL SECURITY;

CREATE POLICY topics_tenant_isolation ON outbox.topics
    USING (
        current_setting('outbox.tenant_id', TRUE) != ''
        AND namespace = current_setting('outbox.tenant_id', TRUE)
    )
    WITH CHECK (
        current_setting('outbox.tenant_id', TRUE) != ''
        AND namespace = current_setting('outbox.tenant_id', TRUE)
    );

-- Config: global readable, tenant can only write their own rows
ALTER TABLE outbox.config ENABLE ROW LEVEL SECURITY;
ALTER TABLE outbox.config FORCE ROW LEVEL SECURITY;

-- All tenants can read global config
CREATE POLICY config_global_read ON outbox.config
    FOR SELECT
    USING (namespace = 'global');

-- Tenants can read/write their own config
CREATE POLICY config_tenant_isolation ON outbox.config
    USING (
        current_setting('outbox.tenant_id', TRUE) != ''
        AND namespace = current_setting('outbox.tenant_id', TRUE)
    )
    WITH CHECK (
        current_setting('outbox.tenant_id', TRUE) != ''
        AND namespace = current_setting('outbox.tenant_id', TRUE)
    );

-- Prevent any tenant from writing to global (RESTRICTIVE policy)
CREATE POLICY config_global_write_protection ON outbox.config
    AS RESTRICTIVE
    FOR ALL
    USING (TRUE)
    WITH CHECK (namespace != 'global');

-- DELETE consults only USING, never WITH CHECK, so the write protection
-- above cannot block deleting the global rows.
CREATE POLICY config_global_delete_protection ON outbox.config
    AS RESTRICTIVE
    FOR DELETE
    USING (namespace != 'global');
