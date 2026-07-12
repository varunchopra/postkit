-- =============================================================================
-- SCHEMA AND TABLES FOR POSTKIT/MEMORY
-- =============================================================================
-- Agent memory: append-only episodes, distilled facts and entities, typed edges.
--
-- Design principles:
--   1. Write isolation: record() is a single append and never touches
--      nodes/edges
--   2. Bi-temporal facts: valid time (valid_from/valid_until) and system
--      time (recorded_at/invalidated_at) are independent
--   3. Supersession, never update-in-place: node content is immutable; a
--      correction creates a new node
--   4. Multi-tenant: namespace isolation via row-level security (RLS)
--   5. Computed relations: similarity and temporal order are derived at query
--      time; only entity/causal/assoc edges are stored
--
-- Invariants (referenced as M1-M4 by function comments and the test suite):
--   M1. Episode content is immutable after insert; the only legal UPDATE sets
--       consolidated_at from NULL. Rows may be DELETEd (retention belongs to
--       the deployer)
--   M2. Every edge endpoint references an existing node in the same namespace
--   M3. consolidate() with an idempotency key is replay-safe: re-running with
--       the same key is a no-op
--   M4. Supersession is single-step and acyclic: a node cannot supersede
--       itself, an already-superseded node cannot be superseded again, and
--       the replacement must be live. A superseded node is always
--       invalidated, so the live-replacement requirement makes a
--       supersession cycle unreachable
--
-- Deployment-level concerns (intentionally not handled by this library):
--
--   6. No GRANT/REVOKE statements. Role creation and permission grants are
--      the deployer's responsibility. A library cannot assume role names,
--      connection pooling strategy, or pg_hba.conf layout. Shipping
--      opinionated grants would be either too permissive or too restrictive.
--
--   7. No metadata size constraint. PostgreSQL already caps a single
--      stored value at roughly 1 GB. The acceptable metadata size is a deployment
--      policy decision. Deployers can add a CHECK constraint or validate
--      at the application layer.
--
--   8. Actor context columns are nullable. Requiring them would break
--      migrations, cron tickers, REPL debugging, and any non-request
--      context. The audit trail is best-effort by design; the application
--      layer decides when actor attribution is mandatory.
--
--   9. pgvector is required. The CREATE EXTENSION below runs at install; the
--      module loads only on servers where the extension is available. This
--      is the one postkit module with an extension dependency; the other
--      eight remain extension-free.

CREATE EXTENSION IF NOT EXISTS vector;

CREATE SCHEMA IF NOT EXISTS memory;

-- =============================================================================
-- EPISODES TABLE
-- =============================================================================
-- Append-only interaction log: one row per message or event, written as it
-- happened and never edited (M1). The embedding column is dimensionless until
-- memory.set_dimension() fixes it; raw content is always stored so the log
-- outlives its embedding model and can be re-embedded.

CREATE TABLE memory.episodes (
    id bigint GENERATED ALWAYS AS IDENTITY,
    namespace text NOT NULL,
    session_id text NOT NULL,
    role text NOT NULL,
    content text NOT NULL,
    embedding vector,                 -- dimensionless until memory.set_dimension()
    embed_model text,
    keywords text[] NOT NULL DEFAULT '{}',
    occurred_at timestamptz NOT NULL DEFAULT now(),
    consolidated_at timestamptz,
    metadata jsonb NOT NULL DEFAULT '{}',
    actor_id text, request_id text, on_behalf_of text, reason text,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (namespace, id),
    CONSTRAINT episodes_embedding_model_paired CHECK (
        (embedding IS NULL) = (embed_model IS NULL)
    )
);
ALTER TABLE memory.episodes ADD COLUMN search tsvector
    GENERATED ALWAYS AS (to_tsvector('simple', content)) STORED;
CREATE INDEX episodes_session_idx ON memory.episodes (namespace, session_id, occurred_at DESC, id DESC);
CREATE INDEX episodes_time_idx ON memory.episodes (namespace, occurred_at DESC, id DESC);
CREATE INDEX episodes_search_idx ON memory.episodes USING gin (search);
CREATE INDEX episodes_unconsolidated_idx ON memory.episodes (namespace, id) WHERE consolidated_at IS NULL;

-- =============================================================================
-- NODES TABLE
-- =============================================================================
-- Distilled knowledge: facts and the entities they are about, produced by
-- consolidation. Content is immutable; corrections supersede (M4). The two
-- timestamp pairs are bi-temporal: valid_from/valid_until is when the fact was
-- true in the world, recorded_at/invalidated_at is when the system learned and
-- retired it. evidence lists the episode ids a fact was distilled from; it is
-- intentionally not FK-enforced because episodes are deletable (M1).

CREATE TABLE memory.nodes (
    id bigint GENERATED ALWAYS AS IDENTITY,
    namespace text NOT NULL,
    kind text NOT NULL,
    content text NOT NULL,
    embedding vector,
    embed_model text,
    confidence real,
    valid_from timestamptz NOT NULL DEFAULT now(),
    valid_until timestamptz,
    recorded_at timestamptz NOT NULL DEFAULT now(),
    invalidated_at timestamptz,
    superseded_by bigint,
    evidence bigint[] NOT NULL DEFAULT '{}',   -- episode ids, intentionally not FK-enforced (episodes are deletable, M1)
    actor_id text, request_id text, on_behalf_of text, reason text,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (namespace, id),
    CONSTRAINT nodes_kind_valid CHECK (kind IN ('fact', 'entity')),
    CONSTRAINT nodes_embedding_model_paired CHECK ((embedding IS NULL) = (embed_model IS NULL)),
    CONSTRAINT nodes_no_self_supersede CHECK (superseded_by IS NULL OR superseded_by != id),
    FOREIGN KEY (namespace, superseded_by) REFERENCES memory.nodes (namespace, id)
);
ALTER TABLE memory.nodes ADD COLUMN search tsvector
    GENERATED ALWAYS AS (to_tsvector('simple', content)) STORED;
CREATE INDEX nodes_kind_idx ON memory.nodes (namespace, kind, recorded_at DESC, id DESC);
CREATE INDEX nodes_time_idx ON memory.nodes (namespace, recorded_at DESC, id DESC);
CREATE INDEX nodes_search_idx ON memory.nodes USING gin (search);
CREATE INDEX nodes_live_idx ON memory.nodes (namespace, id) WHERE invalidated_at IS NULL;
CREATE UNIQUE INDEX nodes_entity_unique ON memory.nodes (namespace, content) WHERE kind = 'entity' AND invalidated_at IS NULL;

-- =============================================================================
-- EDGES TABLE
-- =============================================================================
-- Stored connections between nodes, from a small fixed vocabulary. Only
-- relations that cannot be recomputed live here (entity, causal, assoc);
-- similarity and temporal order are derived at query time, never stored. Both
-- endpoints reference a node in the same namespace (M2), enforced by the
-- composite foreign keys and cascaded on node delete.

CREATE TABLE memory.edges (
    namespace text NOT NULL,
    from_node bigint NOT NULL,
    to_node bigint NOT NULL,
    relation text NOT NULL,
    weight real NOT NULL DEFAULT 1.0,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (namespace, from_node, to_node, relation),
    CONSTRAINT edges_relation_valid CHECK (relation IN ('entity', 'causal', 'assoc')),
    CONSTRAINT edges_no_self_loop CHECK (from_node != to_node),
    CONSTRAINT edges_weight_range CHECK (weight > 0 AND weight <= 1),
    FOREIGN KEY (namespace, from_node) REFERENCES memory.nodes (namespace, id) ON DELETE CASCADE,  -- M2
    FOREIGN KEY (namespace, to_node)   REFERENCES memory.nodes (namespace, id) ON DELETE CASCADE   -- M2
);
CREATE INDEX edges_to_idx ON memory.edges (namespace, to_node);

-- =============================================================================
-- CONSOLIDATIONS TABLE
-- =============================================================================
-- Bookkeeping for replay safety (M3): one row per applied consolidation keyed
-- by the caller's idempotency key. A second consolidate() with the same key
-- finds this row and is a no-op.

CREATE TABLE memory.consolidations (        -- M3 bookkeeping
    namespace text NOT NULL,
    idempotency_key text NOT NULL,
    applied_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (namespace, idempotency_key)
);

-- =============================================================================
-- CONFIG TABLE
-- =============================================================================
-- Per-tenant configuration with global defaults.
-- 'global' row provides defaults; tenants can override with their own row.

CREATE TABLE memory.config (
    namespace text NOT NULL PRIMARY KEY,
    recall_max_hops int NOT NULL DEFAULT 2,
    recall_max_nodes int NOT NULL DEFAULT 200,
    recall_halflife interval NOT NULL DEFAULT '30 days',
    consolidation_batch_size int NOT NULL DEFAULT 50,
    notify_on_record boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- Global defaults (read by all, write-protected via RLS)
INSERT INTO memory.config (namespace) VALUES ('global') ON CONFLICT DO NOTHING;

-- =============================================================================
-- ROW-LEVEL SECURITY
-- =============================================================================
-- Fail-closed: empty tenant context returns zero rows.
-- current_setting(..., TRUE) returns '' when not set.

ALTER TABLE memory.episodes ENABLE ROW LEVEL SECURITY;
ALTER TABLE memory.episodes FORCE ROW LEVEL SECURITY;

CREATE POLICY episodes_tenant_isolation ON memory.episodes
    USING (
        current_setting('memory.tenant_id', TRUE) != ''
        AND namespace = current_setting('memory.tenant_id', TRUE)
    )
    WITH CHECK (
        current_setting('memory.tenant_id', TRUE) != ''
        AND namespace = current_setting('memory.tenant_id', TRUE)
    );

ALTER TABLE memory.nodes ENABLE ROW LEVEL SECURITY;
ALTER TABLE memory.nodes FORCE ROW LEVEL SECURITY;

CREATE POLICY nodes_tenant_isolation ON memory.nodes
    USING (
        current_setting('memory.tenant_id', TRUE) != ''
        AND namespace = current_setting('memory.tenant_id', TRUE)
    )
    WITH CHECK (
        current_setting('memory.tenant_id', TRUE) != ''
        AND namespace = current_setting('memory.tenant_id', TRUE)
    );

ALTER TABLE memory.edges ENABLE ROW LEVEL SECURITY;
ALTER TABLE memory.edges FORCE ROW LEVEL SECURITY;

CREATE POLICY edges_tenant_isolation ON memory.edges
    USING (
        current_setting('memory.tenant_id', TRUE) != ''
        AND namespace = current_setting('memory.tenant_id', TRUE)
    )
    WITH CHECK (
        current_setting('memory.tenant_id', TRUE) != ''
        AND namespace = current_setting('memory.tenant_id', TRUE)
    );

ALTER TABLE memory.consolidations ENABLE ROW LEVEL SECURITY;
ALTER TABLE memory.consolidations FORCE ROW LEVEL SECURITY;

CREATE POLICY consolidations_tenant_isolation ON memory.consolidations
    USING (
        current_setting('memory.tenant_id', TRUE) != ''
        AND namespace = current_setting('memory.tenant_id', TRUE)
    )
    WITH CHECK (
        current_setting('memory.tenant_id', TRUE) != ''
        AND namespace = current_setting('memory.tenant_id', TRUE)
    );

-- Config: global readable, tenant can only write their own row
ALTER TABLE memory.config ENABLE ROW LEVEL SECURITY;
ALTER TABLE memory.config FORCE ROW LEVEL SECURITY;

CREATE POLICY config_global_read ON memory.config
    FOR SELECT
    USING (namespace = 'global');

CREATE POLICY config_tenant_isolation ON memory.config
    USING (
        current_setting('memory.tenant_id', TRUE) != ''
        AND namespace = current_setting('memory.tenant_id', TRUE)
    )
    WITH CHECK (
        current_setting('memory.tenant_id', TRUE) != ''
        AND namespace = current_setting('memory.tenant_id', TRUE)
    );

-- Prevent any tenant from writing to global (RESTRICTIVE policy)
CREATE POLICY config_global_write_protection ON memory.config
    AS RESTRICTIVE
    FOR ALL
    USING (TRUE)
    WITH CHECK (namespace != 'global');

-- DELETE consults only USING, never WITH CHECK, so the write protection
-- above cannot block deleting the global row.
CREATE POLICY config_global_delete_protection ON memory.config
    AS RESTRICTIVE
    FOR DELETE
    USING (namespace != 'global');

-- The embedding dimension is NOT stored in any column: it is read from the
-- embedding column's own type modifier (atttypmod) by memory._embedding_dim().
-- The vector search indexes (HNSW, pgvector's approximate nearest-neighbor
-- index) are created by memory.set_dimension() once a dimension is fixed,
-- not here.
