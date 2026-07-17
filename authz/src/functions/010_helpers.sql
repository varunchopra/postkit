-- @group Internal

-- @function authz._expand_subject_memberships
-- @brief Expand memberships for any subject type recursively
-- @param p_subject_type The subject type (e.g., 'user', 'api_key', 'service')
-- @param p_subject_id The subject ID
-- @param p_namespace Namespace (default: 'default')
-- @returns Table of (group_type, group_id, membership_relation)
-- Given a subject, returns all groups it belongs to, including nested groups.
-- @example If user:alice is in team:infra, and team:infra is in team:platform,
-- @example returns both (team, infra, member) and (team, platform, member).
CREATE OR REPLACE FUNCTION authz._expand_subject_memberships(
    p_subject_type text,
    p_subject_id text,
    p_namespace text DEFAULT 'default'
)
RETURNS TABLE(group_type text, group_id text, membership_relation text)
AS $$
    WITH RECURSIVE subject_memberships AS (
        -- Direct memberships
        SELECT
            resource_type AS group_type,
            resource_id AS group_id,
            relation AS membership_relation,
            1 AS depth
        FROM authz.tuples
        WHERE namespace = p_namespace
          AND subject_type = p_subject_type
          AND subject_id = p_subject_id
          AND subject_relation IS NULL
          AND (expires_at IS NULL OR expires_at > now())

        UNION

        -- Nested: groups containing groups the subject is in
        SELECT
            t.resource_type,
            t.resource_id,
            t.relation,
            sm.depth + 1
        FROM subject_memberships sm
        JOIN authz.tuples t
          ON t.namespace = p_namespace
          AND t.subject_type = sm.group_type
          AND t.subject_id = sm.group_id
          AND t.relation = 'member'
          AND (t.subject_relation IS NULL OR t.subject_relation = sm.membership_relation)
          AND (t.expires_at IS NULL OR t.expires_at > now())
        WHERE sm.depth < authz._max_group_depth()
    )
    SELECT group_type, group_id, membership_relation FROM subject_memberships;
$$ LANGUAGE sql STABLE PARALLEL SAFE SECURITY INVOKER SET search_path = authz, pg_temp;


-- @function authz._expand_resource_ancestors
-- @brief Expand resource ancestors recursively
-- @param p_resource_type The resource type
-- @param p_resource_id The resource ID
-- @param p_namespace Namespace (default: 'default')
-- @returns Table of (resource_type, resource_id)
-- Given a resource, returns itself and all ancestor resources by following
-- 'parent' relations upward. Used by check() to find grants on containing resources.
-- @example If doc:spec has parent folder:projects, and folder:projects has
-- @example parent folder:root, returns (doc, spec), (folder, projects), (folder, root).
CREATE OR REPLACE FUNCTION authz._expand_resource_ancestors(
    p_resource_type text,
    p_resource_id text,
    p_namespace text DEFAULT 'default'
)
RETURNS TABLE(resource_type text, resource_id text)
AS $$
    WITH RECURSIVE ancestors AS (
        -- The resource itself. PostgreSQL requires both halves of a
        -- recursive UNION to use the same collation. The recursive half
        -- reads the id columns, which carry authz.canonical; this first row
        -- is built from parameters, which do not, so the collation is set
        -- explicitly.
        SELECT
            p_resource_type AS resource_type,
            p_resource_id COLLATE authz.canonical AS resource_id,
            0 AS depth

        UNION

        -- Walk up via parent relations
        SELECT
            t.subject_type,
            t.subject_id,
            a.depth + 1
        FROM ancestors a
        JOIN authz.tuples t
          ON t.namespace = p_namespace
          AND t.resource_type = a.resource_type
          AND t.resource_id = a.resource_id
          AND t.relation = 'parent'
          AND (t.expires_at IS NULL OR t.expires_at > now())
        WHERE a.depth < authz._max_resource_depth()
    )
    SELECT ancestors.resource_type, ancestors.resource_id FROM ancestors;
$$ LANGUAGE sql STABLE PARALLEL SAFE SECURITY INVOKER SET search_path = authz, pg_temp;


-- @function authz._expand_resource_descendants
-- @brief Expand resource descendants recursively
-- @param p_resource_type The resource type
-- @param p_resource_id The resource ID
-- @param p_namespace Namespace (default: 'default')
-- @returns Table of (resource_type, resource_id)
-- Given a resource, returns itself and all descendant resources by following
-- 'parent' relations downward. Used by list_resources() to include children
-- of accessible resources.
-- @example If folder:root contains folder:projects contains doc:spec,
-- @example returns (folder, root), (folder, projects), (doc, spec).
CREATE OR REPLACE FUNCTION authz._expand_resource_descendants(
    p_resource_type text,
    p_resource_id text,
    p_namespace text DEFAULT 'default'
)
RETURNS TABLE(resource_type text, resource_id text)
AS $$
    WITH RECURSIVE descendants AS (
        -- The resource itself. PostgreSQL requires both halves of a
        -- recursive UNION to use the same collation. The recursive half
        -- reads the id columns, which carry authz.canonical; this first row
        -- is built from parameters, which do not, so the collation is set
        -- explicitly.
        SELECT
            p_resource_type AS resource_type,
            p_resource_id COLLATE authz.canonical AS resource_id,
            0 AS depth

        UNION

        -- Walk down: find resources that have current resource as parent
        SELECT
            t.resource_type,
            t.resource_id,
            d.depth + 1
        FROM descendants d
        JOIN authz.tuples t
          ON t.namespace = p_namespace
          AND t.subject_type = d.resource_type
          AND t.subject_id = d.resource_id
          AND t.relation = 'parent'
          AND (t.expires_at IS NULL OR t.expires_at > now())
        WHERE d.depth < authz._max_resource_depth()
    )
    SELECT descendants.resource_type, descendants.resource_id FROM descendants;
$$ LANGUAGE sql STABLE PARALLEL SAFE SECURITY INVOKER SET search_path = authz, pg_temp;
