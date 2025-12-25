-- =============================================================================
-- SCHEMA AND TABLES FOR PG-AUTHZ
-- =============================================================================

CREATE SCHEMA IF NOT EXISTS authz;

-- Core tuples table: stores all relationships
CREATE TABLE authz.tuples (
    id BIGSERIAL PRIMARY KEY,
    namespace TEXT NOT NULL DEFAULT 'default',
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    relation TEXT NOT NULL,
    subject_type TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    subject_relation TEXT,  -- For userset references (e.g., group#member)
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    -- Uniqueness constraint note:
    -- We need to treat NULL and '' as equivalent for subject_relation to prevent
    -- duplicate tuples like (doc, 1, editor, team, eng, NULL) and (doc, 1, editor, team, eng, '').
    -- PostgreSQL doesn't support expressions (like COALESCE) in UNIQUE constraints directly.
    -- Therefore, uniqueness is enforced via a unique index in 002_indexes.sql:
    --   CREATE UNIQUE INDEX tuples_unique_idx ON authz.tuples(..., COALESCE(subject_relation, ''))
);

-- =============================================================================
-- COMPUTED PERMISSIONS TABLE
-- =============================================================================
--
-- WHY PRE-COMPUTE?
-- ================
-- Permission checks need to be FAST - often called on every API request.
-- Instead of traversing the tuple graph at query time (expensive), we
-- pre-compute the effective permissions whenever tuples change.
--
-- This trades write-time computation for O(1) read-time lookups.
--
-- WHAT'S STORED
-- =============
-- Each row says: "user X has permission Y on resource Z"
--
-- Example: If alice is in team:engineering, and engineering has admin on repo:api,
-- and admin implies read, we store:
--   (repo, api, admin, alice)
--   (repo, api, read, alice)    -- via hierarchy
--
-- WHY NO source_tuple_id?
-- =======================
-- You might expect a "source_tuple_id" to track where a permission came from.
-- But permissions often come from MULTIPLE sources:
--   - Direct grant (tuple A)
--   - Group membership (tuple B)
--   - Permission hierarchy (config rule)
--
-- Storing one "source" would be misleading. Instead, use authz.explain()
-- to get the full provenance chain when debugging.

CREATE TABLE authz.computed (
    id BIGSERIAL PRIMARY KEY,
    namespace TEXT NOT NULL DEFAULT 'default',
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    permission TEXT NOT NULL,
    user_id TEXT NOT NULL,
    computed_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    UNIQUE (namespace, resource_type, resource_id, permission, user_id)
);

-- Permission hierarchy: defines which permissions imply other permissions
-- Example: ('repo', 'admin', 'write') means admin implies write access
CREATE TABLE authz.permission_hierarchy (
    id BIGSERIAL PRIMARY KEY,
    namespace TEXT NOT NULL DEFAULT 'default',
    resource_type TEXT NOT NULL,
    permission TEXT NOT NULL,
    implies TEXT NOT NULL,

    UNIQUE (namespace, resource_type, permission, implies)
);

-- =============================================================================
-- ROW-LEVEL SECURITY
-- =============================================================================
--
-- Enforces tenant isolation at the database level. Each tenant can only
-- access rows where namespace matches their tenant_id.
--
-- Set tenant context before operations:
--   SELECT authz.set_tenant('tenant-123');
--
-- Without tenant context, queries return no rows and writes fail.
-- Only superusers bypass RLS (Postgres limitation).

-- Enable and force RLS on all tables
ALTER TABLE authz.tuples ENABLE ROW LEVEL SECURITY;
ALTER TABLE authz.tuples FORCE ROW LEVEL SECURITY;

ALTER TABLE authz.computed ENABLE ROW LEVEL SECURITY;
ALTER TABLE authz.computed FORCE ROW LEVEL SECURITY;

ALTER TABLE authz.permission_hierarchy ENABLE ROW LEVEL SECURITY;
ALTER TABLE authz.permission_hierarchy FORCE ROW LEVEL SECURITY;

-- Tenant isolation policies
CREATE POLICY tenant_isolation ON authz.tuples
    USING (namespace = current_setting('authz.tenant_id', true))
    WITH CHECK (namespace = current_setting('authz.tenant_id', true));

CREATE POLICY tenant_isolation ON authz.computed
    USING (namespace = current_setting('authz.tenant_id', true))
    WITH CHECK (namespace = current_setting('authz.tenant_id', true));

CREATE POLICY tenant_isolation ON authz.permission_hierarchy
    USING (namespace = current_setting('authz.tenant_id', true))
    WITH CHECK (namespace = current_setting('authz.tenant_id', true));

