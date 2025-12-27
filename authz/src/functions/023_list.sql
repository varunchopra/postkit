-- =============================================================================
-- LIST RESOURCES
-- =============================================================================
-- Returns resources the user can access with the given permission.
-- Supports nested teams, permission hierarchy, and resource hierarchy.
-- Includes descendants of accessible resources.
--
-- NAMESPACE NOTE: Unlike check(), this function does not warn on namespace/tenant
-- mismatch. These listing functions are SQL (not plpgsql) for performance, and
-- check() is the primary API that developers use. If namespace != tenant_id,
-- RLS will return empty results (fail-closed).
--
-- PERF NOTE: The CROSS JOIN LATERAL in accessible_resources fires a recursive
-- CTE per granted resource. This is O(n) where n = number of accessible resources.
-- Known scaling limit: ~1000 accessible resources before query time degrades.
--
-- MITIGATION OPTIONS for high-volume use cases:
--   1. Use filter_authorized() with a pre-filtered candidate set instead
--   2. Implement application-layer caching of list_resources results
--   3. Partition resources by type and call separately with smaller p_limit
CREATE OR REPLACE FUNCTION authz.list_resources (p_user_id text, p_resource_type text, p_permission text, p_namespace text DEFAULT 'default', p_limit int DEFAULT 100, p_cursor text DEFAULT NULL)
    RETURNS TABLE (
        resource_id text
    )
    AS $$
    WITH RECURSIVE
    -- Find all groups/entities user belongs to (including nested)
    -- Uses reusable helper function to avoid code duplication
    user_memberships AS (
        SELECT * FROM authz._expand_user_memberships(p_user_id, p_namespace)
    ),
-- Find permissions that imply the requested permission (reverse hierarchy)
implied_by AS (
    SELECT
        p_permission AS permission
    UNION
    SELECT
        h.permission
    FROM
        implied_by ib
        JOIN authz.permission_hierarchy h ON h.namespace = p_namespace
            AND h.resource_type = p_resource_type
            AND h.implies = ib.permission
),
-- Find ALL resources with grants (any type, for descendant expansion)
granted_resources AS (
    -- Direct grants to user
    SELECT DISTINCT
        t.resource_type,
        t.resource_id
    FROM
        authz.tuples t
    JOIN implied_by ib ON t.relation = ib.permission
    WHERE
        t.namespace = p_namespace
        AND t.subject_type = 'user'
        AND t.subject_id = p_user_id
        AND (t.expires_at IS NULL
            OR t.expires_at > now())
    UNION
    -- Grants via groups
    SELECT DISTINCT
        t.resource_type,
        t.resource_id
    FROM
        authz.tuples t
        JOIN implied_by ib ON t.relation = ib.permission
        JOIN user_memberships um ON t.subject_type = um.group_type
            AND t.subject_id = um.group_id
            AND (t.subject_relation IS NULL
                OR t.subject_relation = um.membership_relation)
    WHERE
        t.namespace = p_namespace
        AND (t.expires_at IS NULL
            OR t.expires_at > now())
),
-- Expand to include descendants of granted resources, filter to requested type
accessible_resources AS (
    -- Direct grants on the requested type
    SELECT gr.resource_id FROM granted_resources gr
    WHERE gr.resource_type = p_resource_type
    UNION
    -- Descendants of any granted resource that match requested type
    SELECT d.resource_id
    FROM granted_resources gr
    CROSS JOIN LATERAL authz._expand_resource_descendants(
        gr.resource_type, gr.resource_id, p_namespace
    ) d
    WHERE d.resource_type = p_resource_type
)
SELECT
    ar.resource_id
FROM
    accessible_resources ar
WHERE (p_cursor IS NULL
    OR ar.resource_id > p_cursor)
ORDER BY
    ar.resource_id
LIMIT p_limit;
$$
LANGUAGE sql
STABLE PARALLEL SAFE SECURITY INVOKER SET search_path = authz, pg_temp;

-- =============================================================================
-- LIST USERS
-- =============================================================================
-- Returns users who can access the resource with the given permission.
-- Expands nested teams to find all member users.
-- Includes users with access via ancestor resources (resource hierarchy).
CREATE OR REPLACE FUNCTION authz.list_users (p_resource_type text, p_resource_id text, p_permission text, p_namespace text DEFAULT 'default', p_limit int DEFAULT 100, p_cursor text DEFAULT NULL)
    RETURNS TABLE (
        user_id text
    )
    AS $$
    WITH RECURSIVE
    -- Find resource and all ancestor resources (via parent relations)
    resource_chain AS (
        SELECT * FROM authz._expand_resource_ancestors(p_resource_type, p_resource_id, p_namespace)
    ),
    -- Find permissions that imply the requested permission
    implied_by AS (
        SELECT
            p_permission AS permission
        UNION
        SELECT
            h.permission
        FROM
            implied_by ib
            JOIN authz.permission_hierarchy h ON h.namespace = p_namespace
                AND h.resource_type = p_resource_type
                AND h.implies = ib.permission
),
-- Expand from grantees down to users
-- Start with subjects that have grants on the resource or ancestors,
-- then recursively expand groups to find all member users.
--
-- USERSET FEATURE: The COALESCE(es.subject_relation, 'member') handles usersets.
-- If a grant specifies subject_relation='admin', we find users who are admins
-- of that group, not just members.
-- Example: (repo, api, viewer, team, eng, admin) means "admins of team:eng can view repo:api"
expanded_subjects AS (
    -- Direct grantees on the resource or ancestors
    SELECT
        t.subject_type,
        t.subject_id,
        t.subject_relation,
        1 AS depth
    FROM
        authz.tuples t
    JOIN implied_by ib ON t.relation = ib.permission
    JOIN resource_chain rc ON t.resource_type = rc.resource_type
        AND t.resource_id = rc.resource_id
    WHERE
        t.namespace = p_namespace
        AND (t.expires_at IS NULL
            OR t.expires_at > now())
    UNION
    -- Recursively find members of groups
    SELECT
        t.subject_type,
        t.subject_id,
        t.relation AS subject_relation,
        es.depth + 1
    FROM
        expanded_subjects es
        JOIN authz.tuples t ON t.namespace = p_namespace
            AND t.resource_type = es.subject_type
            AND t.resource_id = es.subject_id
            AND t.relation = COALESCE(es.subject_relation, 'member')
            AND (t.expires_at IS NULL
                OR t.expires_at > now())
    WHERE
        es.subject_type != 'user'
        AND es.depth < authz._max_group_depth()
)
SELECT DISTINCT
    es.subject_id AS user_id
FROM
    expanded_subjects es
WHERE
    es.subject_type = 'user'
    AND (p_cursor IS NULL
        OR es.subject_id > p_cursor)
ORDER BY
    es.subject_id
LIMIT p_limit;
$$
LANGUAGE sql
STABLE PARALLEL SAFE SECURITY INVOKER SET search_path = authz, pg_temp;

-- =============================================================================
-- FILTER AUTHORIZED (batch check)
-- =============================================================================
-- Given a list of resource IDs, returns only those the user can access.
-- Checks grants on each resource and its ancestors (resource hierarchy).
CREATE OR REPLACE FUNCTION authz.filter_authorized (p_user_id text, p_resource_type text, p_permission text, p_resource_ids text[], p_namespace text DEFAULT 'default')
    RETURNS text[]
    AS $$
    -- Note: RECURSIVE keyword required for implied_by CTE below;
    -- user_memberships itself is not recursive (delegates to helper function)
    WITH RECURSIVE user_memberships AS (
        SELECT * FROM authz._expand_user_memberships(p_user_id, p_namespace)
    ),
-- Expand each candidate resource to include its ancestors
candidate_with_ancestors AS (
    SELECT
        rid AS original_resource_id,
        a.resource_type,
        a.resource_id
    FROM unnest(p_resource_ids) AS rid
    CROSS JOIN LATERAL authz._expand_resource_ancestors(p_resource_type, rid, p_namespace) a
),
implied_by AS (
    SELECT
        p_permission AS permission
    UNION
    SELECT
        h.permission
    FROM
        implied_by ib
        JOIN authz.permission_hierarchy h ON h.namespace = p_namespace
            AND h.resource_type = p_resource_type
            AND h.implies = ib.permission
),
accessible AS (
    -- Direct grants on resource or ancestor
    SELECT DISTINCT
        ca.original_resource_id AS resource_id
    FROM
        authz.tuples t
    JOIN implied_by ib ON t.relation = ib.permission
    JOIN candidate_with_ancestors ca ON t.resource_type = ca.resource_type
        AND t.resource_id = ca.resource_id
    WHERE
        t.namespace = p_namespace
        AND t.subject_type = 'user'
        AND t.subject_id = p_user_id
        AND (t.expires_at IS NULL
            OR t.expires_at > now())
    UNION
    -- Group grants on resource or ancestor
    SELECT DISTINCT
        ca.original_resource_id AS resource_id
    FROM
        authz.tuples t
        JOIN implied_by ib ON t.relation = ib.permission
        JOIN candidate_with_ancestors ca ON t.resource_type = ca.resource_type
            AND t.resource_id = ca.resource_id
        JOIN user_memberships um ON t.subject_type = um.group_type
            AND t.subject_id = um.group_id
            AND (t.subject_relation IS NULL
                OR t.subject_relation = um.membership_relation)
    WHERE
        t.namespace = p_namespace
        AND (t.expires_at IS NULL
            OR t.expires_at > now()))
SELECT
    ARRAY (
        SELECT
            resource_id
        FROM
            accessible
        ORDER BY
            resource_id);
$$
LANGUAGE sql
STABLE PARALLEL SAFE SECURITY INVOKER SET search_path = authz, pg_temp;
