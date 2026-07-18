-- @group Listing

-- @function authz.list_resources
-- @brief List all resources a subject can access ("What can Alice read?")
-- @param p_subject_type The subject type (e.g., 'user', 'api_key', 'service')
-- @param p_subject_id The subject ID
-- @param p_limit Pagination limit. For >1000 resources, use filter_authorized() instead.
-- @param p_cursor Pass last resource_id from previous page to get next page
-- @returns Resource IDs the subject can access (via direct grant, team membership,
--   or folder inheritance)
-- @example -- Show alice all docs she can read
-- @example SELECT * FROM authz.list_resources('user', 'alice', 'doc', 'read', 'default');
-- @example -- Show API key all repos it can access
-- @example SELECT * FROM authz.list_resources('api_key', 'key-123', 'repo', 'read', 'default');
CREATE OR REPLACE FUNCTION authz.list_resources (p_subject_type text, p_subject_id text, p_resource_type text, p_permission text, p_namespace text DEFAULT 'default', p_limit int DEFAULT 100, p_cursor text DEFAULT NULL)
    RETURNS TABLE (
        resource_id text
    )
    AS $$
    WITH RECURSIVE
    -- Find all groups/entities subject belongs to (including nested)
    -- Uses reusable helper function to avoid code duplication
    subject_memberships AS (
        SELECT * FROM authz._expand_subject_memberships(p_subject_type, p_subject_id, p_namespace)
    ),
-- Find permissions that imply the requested permission (reverse hierarchy lookup).
-- Check BOTH global (app-wide defaults) AND tenant namespace (org customizations).
implied_by AS (
    SELECT
        p_permission AS permission
    UNION
    SELECT
        h.permission
    FROM
        implied_by ib
        JOIN authz.permission_hierarchy h ON h.namespace IN ('global', p_namespace)
            AND h.resource_type = p_resource_type
            AND h.implies = ib.permission
),
-- Find ALL resources with grants (any type, for descendant expansion)
granted_resources AS (
    -- Direct grants to subject
    SELECT DISTINCT
        t.resource_type,
        t.resource_id
    FROM
        authz.tuples t
    JOIN implied_by ib ON t.relation = ib.permission
    WHERE
        t.namespace = p_namespace
        AND t.subject_type = p_subject_type
        AND t.subject_id = p_subject_id
        AND t.subject_relation IS NULL
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
        JOIN subject_memberships sm ON t.subject_type = sm.group_type
            AND t.subject_id = sm.group_id
            AND (t.subject_relation IS NULL
                OR t.subject_relation = sm.membership_relation)
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

-- @function authz._grantee_leaves
-- @brief Leaf subjects with a permission on a resource, expanded from its grants.
-- @param p_resource_type The resource type
-- @param p_resource_id The resource ID
-- @param p_permission The permission to resolve
-- @param p_namespace Namespace (default: 'default')
-- @returns (subject_type, subject_id) for each leaf principal with the permission
-- Shared by list_subjects and count_subjects. Mirrors check: a plain grant (null
-- qualifier) reaches subjects of any relation, a userset grant reaches only its
-- qualified relation, and membership nests only through member edges, so a subject
-- reached through a non-member edge is a grantee whose own members do not inherit.
-- Only a null-qualifier row is a grantee; a userset qualifier names a group to
-- descend into, not a subject with access.
CREATE OR REPLACE FUNCTION authz._grantee_leaves (p_resource_type text, p_resource_id text, p_permission text, p_namespace text DEFAULT 'default')
    RETURNS TABLE (
        subject_type text,
        subject_id text
    )
    AS $$
    WITH RECURSIVE
    resource_chain AS (
        SELECT * FROM authz._expand_resource_ancestors(p_resource_type, p_resource_id, p_namespace)
    ),
    implied_by AS (
        SELECT p_permission AS permission
        UNION
        SELECT h.permission
        FROM implied_by ib
        JOIN authz.permission_hierarchy h ON h.namespace IN ('global', p_namespace)
            AND h.resource_type = p_resource_type
            AND h.implies = ib.permission
    ),
    expanded_subjects AS (
        -- Direct grantees on the resource or its ancestors
        SELECT
            t.subject_type,
            t.subject_id,
            t.subject_relation,
            true AS expandable,
            1 AS depth
        FROM authz.tuples t
        JOIN implied_by ib ON t.relation = ib.permission
        JOIN resource_chain rc ON t.resource_type = rc.resource_type
            AND t.resource_id = rc.resource_id
        WHERE t.namespace = p_namespace
            AND (t.expires_at IS NULL OR t.expires_at > now())
        UNION
        -- Descend: a null qualifier follows any membership relation, a userset
        -- qualifier its own; only member edges nest, so a non-member hop is a
        -- terminal grantee. The reserved 'parent' relation is resource hierarchy,
        -- excluded here to match _expand_subject_memberships (check's walk).
        SELECT
            t.subject_type,
            t.subject_id,
            t.subject_relation,
            t.relation = 'member' AS expandable,
            es.depth + 1
        FROM expanded_subjects es
        JOIN authz.tuples t ON t.namespace = p_namespace
            AND t.resource_type = es.subject_type
            AND t.resource_id = es.subject_id
            AND (es.subject_relation IS NULL OR t.relation = es.subject_relation)
            AND t.relation != 'parent'
            AND (t.expires_at IS NULL OR t.expires_at > now())
        WHERE es.expandable AND es.depth < authz._max_group_depth()
    )
    -- A grantee is a null-qualifier row. Expand a group to its members only when
    -- it was reached to be expanded (a member hop, or the grant itself); a group
    -- reached through a non-member edge is a terminal grantee, emitted as-is even
    -- when it has members. The rule is per row, before the distinct, so a
    -- member-path row for a subject cannot mask a non-expandable one.
    SELECT DISTINCT es.subject_type, es.subject_id
    FROM expanded_subjects es
    WHERE es.subject_relation IS NULL
        AND (NOT es.expandable
             OR NOT EXISTS (
                SELECT 1 FROM authz.tuples t
                WHERE t.namespace = p_namespace
                    AND t.resource_type = es.subject_type
                    AND t.resource_id = es.subject_id
                    AND t.relation = 'member'
                    AND (t.expires_at IS NULL OR t.expires_at > now())
             ));
$$
LANGUAGE sql
STABLE PARALLEL SAFE SECURITY INVOKER SET search_path = authz, pg_temp;

-- @function authz.list_subjects
-- @brief List all subjects who can access a resource ("Who can read this doc?")
-- @param p_subject_type Optional filter to only return subjects of this type (e.g., 'user')
-- @param p_cursor_type Subject type from last result for pagination (NULL for first page)
-- @param p_cursor_id Subject ID from last result for pagination (NULL for first page)
-- @returns The (type, id) of every subject check would admit, expanded to leaves
--   (a plainly granted group contributes its admins and other relation holders,
--   not only its members)
-- @example -- First page
-- @example SELECT * FROM authz.list_subjects('repo', 'payments', 'admin', 'default');
-- @example -- Filter to only users
-- @example SELECT * FROM authz.list_subjects('repo', 'payments', 'admin', 'default', 100, 'user');
-- @example -- Next page using cursor from last result
-- @example SELECT * FROM authz.list_subjects('repo', 'payments', 'admin', 'default', 100, NULL, 'user', 'alice');
CREATE OR REPLACE FUNCTION authz.list_subjects (p_resource_type text, p_resource_id text, p_permission text, p_namespace text DEFAULT 'default', p_limit int DEFAULT 100, p_subject_type text DEFAULT NULL, p_cursor_type text DEFAULT NULL, p_cursor_id text DEFAULT NULL)
    RETURNS TABLE (
        subject_type text,
        subject_id text
    )
    AS $$
    SELECT g.subject_type, g.subject_id
    FROM authz._grantee_leaves(p_resource_type, p_resource_id, p_permission, p_namespace) g
    WHERE (p_subject_type IS NULL OR g.subject_type = p_subject_type)
      AND ((p_cursor_type IS NULL AND p_cursor_id IS NULL)
           OR (g.subject_type, g.subject_id) > (p_cursor_type, p_cursor_id))
    ORDER BY g.subject_type, g.subject_id
    LIMIT p_limit;
$$
LANGUAGE sql
STABLE PARALLEL SAFE SECURITY INVOKER SET search_path = authz, pg_temp;

-- @function authz.count_subjects
-- @brief Count subjects who can access a resource (without fetching all)
-- @param p_resource_type Resource type (e.g., 'team')
-- @param p_resource_id Resource ID
-- @param p_permission Permission to check (e.g., 'member')
-- @param p_subject_type Optional filter to specific subject type (e.g., 'user')
-- @returns Count of subjects with access
-- @example SELECT authz.count_subjects('team', 'engineering', 'member', 'default', 'user');
CREATE OR REPLACE FUNCTION authz.count_subjects(
    p_resource_type text,
    p_resource_id text,
    p_permission text,
    p_namespace text DEFAULT 'default',
    p_subject_type text DEFAULT NULL
)
RETURNS bigint
AS $$
    SELECT COUNT(*)
    FROM authz._grantee_leaves(p_resource_type, p_resource_id, p_permission, p_namespace) g
    WHERE p_subject_type IS NULL OR g.subject_type = p_subject_type;
$$
LANGUAGE sql
STABLE PARALLEL SAFE SECURITY INVOKER SET search_path = authz, pg_temp;

-- @function authz.filter_authorized
-- @brief Filter a list to only resources the subject can access (batch check)
-- @param p_subject_type The subject type (e.g., 'user', 'api_key', 'service')
-- @param p_subject_id The subject ID
-- @param p_resource_ids Candidate resources to check (e.g., from a search query)
-- @returns Subset of p_resource_ids the subject has permission on
-- @example -- User searches for "api", filter to only repos they can see
-- @example SELECT authz.filter_authorized('user', 'alice', 'repo', 'read',
-- @example   ARRAY['payments-api', 'internal-api', 'public-api'], 'default');
-- @example -- Returns: ['payments-api', 'public-api'] (if alice can't see internal-api)
CREATE OR REPLACE FUNCTION authz.filter_authorized (p_subject_type text, p_subject_id text, p_resource_type text, p_permission text, p_resource_ids text[], p_namespace text DEFAULT 'default')
    RETURNS text[]
    AS $$
    -- Note: RECURSIVE keyword required for implied_by CTE below;
    -- subject_memberships itself is not recursive (delegates to helper function)
    WITH RECURSIVE subject_memberships AS (
        SELECT * FROM authz._expand_subject_memberships(p_subject_type, p_subject_id, p_namespace)
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
        JOIN authz.permission_hierarchy h ON h.namespace IN ('global', p_namespace)
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
        AND t.subject_type = p_subject_type
        AND t.subject_id = p_subject_id
        AND t.subject_relation IS NULL
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
        JOIN subject_memberships sm ON t.subject_type = sm.group_type
            AND t.subject_id = sm.group_id
            AND (t.subject_relation IS NULL
                OR t.subject_relation = sm.membership_relation)
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
