-- =============================================================================
-- PERMISSION CHECK (LAZY EVALUATION)
-- =============================================================================
-- Evaluates permissions at query time via recursive CTEs.
--
-- Algorithm:
-- 1. Find all groups the user belongs to (including via nested teams)
-- 2. Find resource and all ancestor resources (via parent relations)
-- 3. Find all grants on resource or ancestors (direct to user + via groups)
-- 4. Expand permission hierarchy (admin -> write -> read)
-- 5. Check if requested permission exists
--
-- Nested teams example:
--   alice in team:infra in team:platform in team:engineering
--   team:engineering has admin on repo:api
--   alice can access repo:api with admin permission
--
-- Resource hierarchy example:
--   doc:spec has parent folder:projects has parent folder:root
--   alice has read on folder:root
--   alice can access doc:spec with read permission

-- =============================================================================
-- HELPER: Get all effective permissions for a user on a resource
-- =============================================================================
-- Returns the set of all permissions a user has on a resource, including:
-- - Direct grants to the user
-- - Grants via group membership (including nested groups)
-- - Grants on ancestor resources (via parent relations)
-- - Implied permissions via hierarchy expansion
--
-- This is an internal function (prefixed with _) used by check, check_any, check_all.
CREATE OR REPLACE FUNCTION authz._get_user_permissions(
    p_user_id text,
    p_resource_type text,
    p_resource_id text,
    p_namespace text DEFAULT 'default'
)
RETURNS TABLE(permission text)
AS $$
    WITH RECURSIVE
    -- Phase 1: Find all groups/entities the user belongs to (including nested)
    -- Uses reusable helper function to avoid code duplication
    user_memberships AS (
        SELECT * FROM authz._expand_user_memberships(p_user_id, p_namespace)
    ),

    -- Phase 2: Find resource and all ancestor resources (via parent relations)
    resource_chain AS (
        SELECT * FROM authz._expand_resource_ancestors(p_resource_type, p_resource_id, p_namespace)
    ),

    -- Phase 3: Find permissions granted on the resource or any ancestor
    granted_permissions AS (
        -- Direct grants to user on resource or ancestor
        SELECT t.relation AS perm
        FROM authz.tuples t
        JOIN resource_chain rc
          ON t.resource_type = rc.resource_type
          AND t.resource_id = rc.resource_id
        WHERE t.namespace = p_namespace
          AND t.subject_type = 'user'
          AND t.subject_id = p_user_id
          AND (t.expires_at IS NULL OR t.expires_at > now())

        UNION

        -- Grants via groups (including nested) on resource or ancestor
        SELECT t.relation AS perm
        FROM authz.tuples t
        JOIN resource_chain rc
          ON t.resource_type = rc.resource_type
          AND t.resource_id = rc.resource_id
        JOIN user_memberships um
          ON t.subject_type = um.group_type
          AND t.subject_id = um.group_id
          AND (t.subject_relation IS NULL OR t.subject_relation = um.membership_relation)
        WHERE t.namespace = p_namespace
          AND (t.expires_at IS NULL OR t.expires_at > now())
    ),

    -- Phase 4: Expand permission hierarchy
    -- Note: We use the original resource_type for hierarchy lookup, not ancestors
    all_permissions AS (
        SELECT perm FROM granted_permissions

        UNION

        SELECT h.implies
        FROM all_permissions ap
        JOIN authz.permission_hierarchy h
          ON h.namespace = p_namespace
          AND h.resource_type = p_resource_type
          AND h.permission = ap.perm
    )

    SELECT perm AS permission FROM all_permissions;
$$ LANGUAGE sql STABLE PARALLEL SAFE SET search_path = authz, pg_temp;


-- =============================================================================
-- CHECK (single permission)
-- =============================================================================
CREATE OR REPLACE FUNCTION authz.check(
    p_user_id text,
    p_permission text,
    p_resource_type text,
    p_resource_id text,
    p_namespace text DEFAULT 'default'
) RETURNS boolean AS $$
    SELECT EXISTS (
        SELECT 1 FROM authz._get_user_permissions(p_user_id, p_resource_type, p_resource_id, p_namespace)
        WHERE permission = p_permission
    );
$$ LANGUAGE sql STABLE PARALLEL SAFE SET search_path = authz, pg_temp;


-- =============================================================================
-- CHECK ANY (at least one permission required)
-- =============================================================================
CREATE OR REPLACE FUNCTION authz.check_any(
    p_user_id text,
    p_permissions text[],
    p_resource_type text,
    p_resource_id text,
    p_namespace text DEFAULT 'default'
) RETURNS boolean AS $$
    SELECT EXISTS (
        SELECT 1 FROM authz._get_user_permissions(p_user_id, p_resource_type, p_resource_id, p_namespace)
        WHERE permission = ANY(p_permissions)
    );
$$ LANGUAGE sql STABLE PARALLEL SAFE SET search_path = authz, pg_temp;


-- =============================================================================
-- CHECK ALL (all permissions required)
-- =============================================================================
CREATE OR REPLACE FUNCTION authz.check_all(
    p_user_id text,
    p_permissions text[],
    p_resource_type text,
    p_resource_id text,
    p_namespace text DEFAULT 'default'
) RETURNS boolean AS $$
    SELECT COALESCE(array_length(p_permissions, 1), 0) = 0
        OR (
            SELECT COUNT(DISTINCT permission)
            FROM authz._get_user_permissions(p_user_id, p_resource_type, p_resource_id, p_namespace)
            WHERE permission = ANY(p_permissions)
        ) = array_length(p_permissions, 1);
$$ LANGUAGE sql STABLE PARALLEL SAFE SET search_path = authz, pg_temp;
