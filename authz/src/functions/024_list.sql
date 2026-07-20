-- @group Listing

-- @function authz.list_resources
-- @brief List all resources a subject can access ("What can Alice read?")
-- @param p_subject_type The subject type (e.g., 'user', 'api_key', 'service')
-- @param p_subject_id The subject ID
-- @param p_limit Maximum returned rows; graph traversal occurs before pagination
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
    subject_memberships AS (
        SELECT * FROM authz._expand_subject_memberships(p_subject_type, p_subject_id, p_namespace)
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
granted_resources AS (
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
accessible_resources(resource_type, resource_id, depth) AS (
    SELECT gr.resource_type, gr.resource_id COLLATE authz.canonical, 0
    FROM granted_resources gr
    UNION
    SELECT child.resource_type, child.resource_id, ar.depth + 1
    FROM accessible_resources ar
    JOIN authz.tuples child
      ON child.namespace = p_namespace
     AND child.relation = 'parent'
     AND child.subject_type = ar.resource_type
     AND child.subject_id = ar.resource_id
     AND (child.expires_at IS NULL OR child.expires_at > now())
    WHERE ar.depth < authz._max_resource_depth()
)
SELECT
    ar.resource_id
FROM
    accessible_resources ar
WHERE ar.resource_type = p_resource_type
  AND (p_cursor IS NULL OR ar.resource_id > p_cursor COLLATE authz.canonical)
GROUP BY ar.resource_id
ORDER BY
    ar.resource_id COLLATE authz.canonical
LIMIT authz._validated_limit(p_limit, 'limit', 1000);
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
-- A null qualifier follows any relation, a userset qualifier follows only its
-- named relation, and only member edges continue nested membership expansion.
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
    -- Membership markers reuse each subject-expansion probe, avoiding both a
    -- second probe per grantee and a scan of unrelated tenant memberships.
    expanded_subjects(
        subject_type,
        subject_id,
        subject_relation,
        expandable,
        depth,
        membership_marker
    ) AS (
        SELECT
            t.subject_type,
            t.subject_id,
            t.subject_relation,
            true AS expandable,
            1 AS depth,
            false AS membership_marker
        FROM authz.tuples t
        JOIN implied_by ib ON t.relation = ib.permission
        JOIN resource_chain rc ON t.resource_type = rc.resource_type
            AND t.resource_id = rc.resource_id
        WHERE t.namespace = p_namespace
            AND (t.expires_at IS NULL OR t.expires_at > now())

        UNION

        SELECT
            step.subject_type,
            step.subject_id,
            step.subject_relation,
            step.expandable,
            step.depth,
            step.membership_marker
        FROM expanded_subjects es
        CROSS JOIN LATERAL (
            WITH children AS MATERIALIZED (
                SELECT
                    t.subject_type,
                    t.subject_id,
                    t.subject_relation,
                    t.relation
                FROM authz.tuples t
                WHERE t.namespace = p_namespace
                  AND t.resource_type = es.subject_type
                  AND t.resource_id = es.subject_id
                  AND (es.subject_relation IS NULL OR t.relation = es.subject_relation)
                  AND t.relation != 'parent'
                  AND (t.expires_at IS NULL OR t.expires_at > now())
            )
            SELECT
                c.subject_type,
                c.subject_id,
                c.subject_relation,
                c.relation = 'member' AS expandable,
                es.depth + 1 AS depth,
                false AS membership_marker
            FROM children c
            WHERE es.depth < authz._max_group_depth()

            UNION ALL

            SELECT
                es.subject_type,
                es.subject_id,
                es.subject_relation,
                false AS expandable,
                es.depth,
                true AS membership_marker
            WHERE EXISTS (
                SELECT 1 FROM children c WHERE c.relation = 'member'
            )
        ) step
        WHERE es.expandable AND NOT es.membership_marker
    ),
    active_membership_containers AS MATERIALIZED (
        SELECT DISTINCT
            es.subject_type,
            es.subject_id,
            es.subject_relation,
            es.depth
        FROM expanded_subjects es
        WHERE es.membership_marker
    )
    SELECT DISTINCT es.subject_type, es.subject_id
    FROM expanded_subjects es
    LEFT JOIN active_membership_containers mc
      ON es.expandable
     AND mc.subject_type = es.subject_type
     AND mc.subject_id = es.subject_id
     AND mc.subject_relation IS NOT DISTINCT FROM es.subject_relation
     AND mc.depth = es.depth
    WHERE NOT es.membership_marker
      AND es.subject_relation IS NULL
      AND (NOT es.expandable OR mc.subject_type IS NULL);
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
    LIMIT authz._validated_limit(p_limit, 'limit', 1000);
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
DECLARE
    v_direct_ids text[];
    v_unresolved_ids text[];
BEGIN
    PERFORM authz._validate_batch_size(cardinality(p_resource_ids), 'resource_ids');
    PERFORM authz._warn_namespace_mismatch(p_namespace);

    WITH RECURSIVE
    candidate_ids(resource_id) AS MATERIALIZED (
        SELECT DISTINCT resource_id
        FROM unnest(p_resource_ids) AS resource_id
    ),
    implied_by(permission, depth) AS (
        SELECT p_permission, 1

        UNION

        SELECT h.permission, ib.depth + 1
        FROM implied_by ib
        JOIN authz.permission_hierarchy h
          ON h.namespace IN ('global', p_namespace)
         AND h.resource_type = p_resource_type
         AND h.implies = ib.permission
        WHERE ib.depth < 50
    )
    SELECT COALESCE(array_agg(d.resource_id ORDER BY d.resource_id), ARRAY[]::text[])
    INTO v_direct_ids
    FROM (
        SELECT DISTINCT c.resource_id
        FROM candidate_ids c
        JOIN authz.tuples t
          ON t.namespace = p_namespace
         AND t.resource_type = p_resource_type
         AND t.resource_id = c.resource_id COLLATE authz.canonical
         AND t.subject_type = p_subject_type
         AND t.subject_id = p_subject_id
         AND t.subject_relation IS NULL
         AND (t.expires_at IS NULL OR t.expires_at > now())
        JOIN implied_by ib ON ib.permission = t.relation
    ) d;

    SELECT COALESCE(array_agg(c.resource_id ORDER BY c.resource_id), ARRAY[]::text[])
    INTO v_unresolved_ids
    FROM (
        SELECT DISTINCT resource_id
        FROM unnest(p_resource_ids) AS resource_id
    ) c
    WHERE NOT EXISTS (
        SELECT 1
        FROM unnest(v_direct_ids) AS direct_id
        WHERE direct_id = c.resource_id
    );

    IF cardinality(v_unresolved_ids) = 0 THEN
        RETURN v_direct_ids;
    END IF;

    RETURN (
    WITH RECURSIVE subject_memberships AS (
        SELECT * FROM authz._expand_subject_memberships(p_subject_type, p_subject_id, p_namespace)
    ),
candidate_with_ancestors AS (
    SELECT
        rid AS original_resource_id,
        a.resource_type,
        a.resource_id
    FROM unnest(v_unresolved_ids) AS rid
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
            (
                SELECT unnest(v_direct_ids) AS resource_id
                UNION
                SELECT accessible.resource_id
                FROM accessible
            ) resolved
        ORDER BY
            resource_id));
END;
$$
LANGUAGE plpgsql
STABLE PARALLEL SAFE SECURITY INVOKER SET search_path = authz, pg_temp;
