-- =============================================================================
-- AUDIT LOGGING SCHEMA
-- =============================================================================
--
-- PURPOSE
-- -------
-- Captures all authorization changes with full context for compliance,
-- debugging, and security auditing.
--
-- WHAT'S LOGGED
-- =============
-- - Tuple changes: INSERT/UPDATE/DELETE on authz.tuples
-- - Hierarchy changes: INSERT/DELETE on authz.permission_hierarchy
-- - Actor context: Who made the change (set via set_actor())
-- - Connection context: session_user, client_addr, etc.
-- - Expiration: expires_at captured for time-bound permissions
--
-- PARTITIONING
-- ============
-- The audit table is partitioned by month for:
-- - Efficient retention management (drop old partitions)
-- - Query performance (partition pruning on time ranges)
-- - Maintenance operations (VACUUM per partition)
--
-- Partitions are named: audit_events_y{YYYY}m{MM}
-- Example: audit_events_y2024m01
--
-- RETENTION
-- =========
-- Use authz.drop_audit_partitions(months) to remove old data.
-- Default retention is 84 months (7 years) for compliance.
--
-- =============================================================================
-- Partitioned audit events table
CREATE TABLE authz.audit_events (
    id bigint GENERATED ALWAYS AS IDENTITY,
    event_id uuid DEFAULT gen_random_uuid (),
    event_type text NOT NULL,
    event_time timestamptz NOT NULL DEFAULT now(),
    -- Actor context (set via authz.set_actor())
    actor_id text,
    request_id text,
    reason text,
    -- PostgreSQL connection context
    session_user_name text DEFAULT SESSION_USER,
    current_user_name text DEFAULT CURRENT_USER,
    client_addr inet DEFAULT inet_client_addr(),
    client_port int DEFAULT inet_client_port(),
    application_name text DEFAULT current_setting('application_name', TRUE),
    backend_pid int DEFAULT pg_backend_pid(),
    -- Tuple/hierarchy data
    namespace text NOT NULL,
    resource_type text NOT NULL,
    resource_id text NOT NULL,
    relation text NOT NULL,
    subject_type text NOT NULL,
    subject_id text NOT NULL,
    subject_relation text,
    tuple_id bigint,
    expires_at timestamptz,  -- The tuple's expiration at time of event
    -- Partition key must be in primary key for partitioned tables
    PRIMARY KEY (id, event_time),
    -- Validate event types
    CONSTRAINT valid_event_type CHECK (event_type IN (
        'tuple_created', 'tuple_updated', 'tuple_deleted',
        'hierarchy_created', 'hierarchy_deleted'
    ))
)
PARTITION BY RANGE (event_time);

-- Create index on parent table for namespace + time queries
-- Note: Indexes on partitioned tables are automatically created on each partition
CREATE INDEX audit_events_namespace_time_idx ON authz.audit_events (namespace, event_time DESC);

-- Index for actor queries
CREATE INDEX audit_events_actor_time_idx ON authz.audit_events (actor_id, event_time DESC)
WHERE
    actor_id IS NOT NULL;

-- Index for resource queries
-- NOTE: There is no get_audit_events() function by design. Query this table directly.
-- Audit queries have highly variable filter combinations (resource, actor, time range,
-- event type, subject, etc.). A stored function would need 10+ optional parameters
-- and complex conditional logic. Client-side query building is clearer and equally safe
-- with parameterized queries. The indexes below support common access patterns.
CREATE INDEX audit_events_resource_time_idx ON authz.audit_events (namespace, resource_type, resource_id, event_time DESC);

-- Index for tuple correlation
CREATE INDEX audit_events_tuple_id_idx ON authz.audit_events (tuple_id)
WHERE
    tuple_id IS NOT NULL;

-- Index for event_id lookups
CREATE INDEX audit_events_event_id_idx ON authz.audit_events (event_id);

-- Row-Level Security for tenant isolation
ALTER TABLE authz.audit_events ENABLE ROW LEVEL SECURITY;

ALTER TABLE authz.audit_events FORCE ROW LEVEL SECURITY;

CREATE POLICY audit_tenant_isolation ON authz.audit_events
    USING (namespace = current_setting('authz.tenant_id', TRUE))
    WITH CHECK (namespace = current_setting('authz.tenant_id', TRUE));
