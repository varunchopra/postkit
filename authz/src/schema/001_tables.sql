-- =============================================================================
-- SCHEMA AND TABLES FOR POSTKIT/AUTHZ
-- =============================================================================
CREATE SCHEMA IF NOT EXISTS authz;

-- =============================================================================
-- TUPLES TABLE
-- =============================================================================
-- The source of truth for all relationships.
-- Format: (resource_type, resource_id) has relation to (subject_type, subject_id)
--
-- Examples:
--   Direct grant: (doc, 123, viewer, user, alice, NULL)
--   Group grant:  (doc, 123, editor, team, engineering, NULL)
--   Group member: (team, engineering, member, user, alice, NULL)
--   Nested team:  (team, platform, member, team, infrastructure, NULL)
--   Userset:      (repo, api, admin, team, engineering, admin)
CREATE TABLE authz.tuples (
    id bigserial PRIMARY KEY,
    namespace text NOT NULL DEFAULT 'default',
    resource_type text NOT NULL,
    resource_id text NOT NULL,
    relation text NOT NULL,
    subject_type text NOT NULL,
    subject_id text NOT NULL,
    subject_relation text,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz DEFAULT NULL
);

-- Uniqueness constraint treating NULL and '' as equivalent for subject_relation
CREATE UNIQUE INDEX tuples_unique_idx ON authz.tuples (namespace, resource_type, resource_id, relation, subject_type, subject_id, COALESCE(subject_relation, ''));

-- =============================================================================
-- PERMISSION HIERARCHY TABLE
-- =============================================================================
-- Defines permission implications: having 'permission' implies having 'implies'
-- Example: admin -> write -> read
--
-- TWO-TIER HIERARCHY SYSTEM:
--
-- Permission checks look at BOTH global AND tenant-specific hierarchies:
--
--   1. GLOBAL HIERARCHIES (namespace = 'global')
--      - App-wide defaults defined by the developer
--      - Example: "owner -> edit -> view" applies to all tenants
--      - Readable by all tenants via RLS policy
--
--   2. TENANT HIERARCHIES (namespace = 'org:xxx')
--      - Org-specific customizations defined by customers
--      - Example: Org adds "approver -> reviewer" for their workflow
--      - Allows customers to extend the permission model for their org structure
--
-- WHY: Different organizations have different structures. A startup might use
-- simple owner/editor/viewer roles, while an enterprise might need custom roles
-- like "legal_reviewer" or "compliance_approver" that imply specific permissions.
--
-- HOW IT WORKS:
--   - Permission checks use: namespace IN ('global', p_namespace)
--   - Global hierarchies provide sensible defaults
--   - Tenants can ADD rules but cannot remove global ones
--
-- Example:
--   Global: owner -> edit -> view (all tenants get this)
--   Tenant A adds: approver -> view (their custom role)
--   Result: Tenant A users with "approver" get "view" via their custom rule
--
CREATE TABLE authz.permission_hierarchy (
    id bigserial PRIMARY KEY,
    namespace text NOT NULL DEFAULT 'default',
    resource_type text NOT NULL,
    permission text NOT NULL,
    implies text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (namespace, resource_type, permission, implies)
);

-- =============================================================================
-- ROW-LEVEL SECURITY
-- =============================================================================
ALTER TABLE authz.tuples ENABLE ROW LEVEL SECURITY;

ALTER TABLE authz.tuples FORCE ROW LEVEL SECURITY;

ALTER TABLE authz.permission_hierarchy ENABLE ROW LEVEL SECURITY;

ALTER TABLE authz.permission_hierarchy FORCE ROW LEVEL SECURITY;

-- Note: current_setting(..., TRUE) returns '' when not set.
-- We explicitly check for non-empty to fail-closed when tenant context is missing.
CREATE POLICY tuples_tenant_isolation ON authz.tuples
    USING (
        current_setting('authz.tenant_id', TRUE) != ''
        AND namespace = current_setting('authz.tenant_id', TRUE)
    )
    WITH CHECK (
        current_setting('authz.tenant_id', TRUE) != ''
        AND namespace = current_setting('authz.tenant_id', TRUE)
    );

-- Cross-namespace visibility: Subjects can see grants where they are the subject.
-- This enables "Shared with me" functionality across organizations.
-- Works for any subject type (user, api_key, service, etc.).
CREATE POLICY tuples_recipient_visibility ON authz.tuples
    FOR SELECT
    USING (
        subject_type = current_setting('authz.viewer_type', TRUE)
        AND subject_id = current_setting('authz.viewer_id', TRUE)
    );

-- Cross-namespace leave: Subjects can delete/leave grants where they are the subject.
-- This allows recipients to decline or leave shares from other organizations.
-- Works for any subject type (user, api_key, service, etc.).
CREATE POLICY tuples_recipient_can_leave ON authz.tuples
    FOR DELETE
    USING (
        subject_type = current_setting('authz.viewer_type', TRUE)
        AND subject_id = current_setting('authz.viewer_id', TRUE)
    );

-- Index for efficient cross-namespace recipient queries
CREATE INDEX IF NOT EXISTS tuples_subject_idx
    ON authz.tuples(subject_id, subject_type);

CREATE POLICY hierarchy_tenant_isolation ON authz.permission_hierarchy
    USING (
        current_setting('authz.tenant_id', TRUE) != ''
        AND namespace = current_setting('authz.tenant_id', TRUE)
    )
    WITH CHECK (
        current_setting('authz.tenant_id', TRUE) != ''
        AND namespace = current_setting('authz.tenant_id', TRUE)
    );

-- Global hierarchies: readable by all tenants (Zanzibar-style schema separation)
-- This allows any tenant to read the global permission schema while maintaining
-- write isolation. Hierarchies are defined once in 'global' namespace and
-- automatically apply to permission checks in all tenant namespaces.
CREATE POLICY hierarchy_global_read ON authz.permission_hierarchy
    FOR SELECT
    USING (namespace = 'global');

-- SECURITY: Block tenant writes to 'global' namespace
-- The global namespace is reserved for app-wide permission hierarchies defined by
-- the application developer (via migrations or admin tools). Tenants must not be
-- able to modify global hierarchies, even if they set authz.tenant_id = 'global'.
-- This policy explicitly denies all write operations to the global namespace.
CREATE POLICY hierarchy_global_write_protection ON authz.permission_hierarchy
    AS RESTRICTIVE
    FOR ALL
    USING (TRUE)
    WITH CHECK (namespace != 'global');
