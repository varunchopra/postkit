-- =============================================================================
-- INTERNAL HELPERS
-- =============================================================================
-- Reusable functions used by multiple core operations. These are internal
-- (prefixed with _ or named generically) and not part of the public API.


-- Expand user memberships recursively
--
-- Given a user, returns all groups they belong to, including nested groups.
-- Used by check, list_resources, and filter_authorized to avoid duplicating
-- the same recursive CTE logic.
--
-- Example: If alice is in team:infra, and team:infra is in team:platform,
-- this returns both (team, infra, member) and (team, platform, member).
--
-- Note: list_users expands in the opposite direction (from resource down to
-- users) so it can't use this function.
CREATE OR REPLACE FUNCTION authz._expand_user_memberships(
    p_user_id text,
    p_namespace text DEFAULT 'default'
)
RETURNS TABLE(group_type text, group_id text, membership_relation text)
AS $$
    WITH RECURSIVE user_memberships AS (
        -- Direct memberships
        SELECT
            resource_type AS group_type,
            resource_id AS group_id,
            relation AS membership_relation,
            1 AS depth
        FROM authz.tuples
        WHERE namespace = p_namespace
          AND subject_type = 'user'
          AND subject_id = p_user_id
          AND (expires_at IS NULL OR expires_at > now())

        UNION

        -- Nested: groups containing groups the user is in
        SELECT
            t.resource_type,
            t.resource_id,
            t.relation,
            um.depth + 1
        FROM user_memberships um
        JOIN authz.tuples t
          ON t.namespace = p_namespace
          AND t.subject_type = um.group_type
          AND t.subject_id = um.group_id
          AND t.relation = 'member'
          AND (t.expires_at IS NULL OR t.expires_at > now())
        WHERE um.depth < authz._max_group_depth()
    )
    SELECT group_type, group_id, membership_relation FROM user_memberships;
$$ LANGUAGE sql STABLE PARALLEL SAFE SET search_path = authz, pg_temp;


-- Expand resource ancestors recursively
--
-- Given a resource, returns itself and all ancestor resources by following
-- 'parent' relations upward. Used by check() to find grants on containing
-- resources.
--
-- Example: If doc:spec has parent folder:projects, and folder:projects has
-- parent folder:root, this returns (doc, spec), (folder, projects), (folder, root).
CREATE OR REPLACE FUNCTION authz._expand_resource_ancestors(
    p_resource_type text,
    p_resource_id text,
    p_namespace text DEFAULT 'default'
)
RETURNS TABLE(resource_type text, resource_id text)
AS $$
    WITH RECURSIVE ancestors AS (
        -- The resource itself
        SELECT
            p_resource_type AS resource_type,
            p_resource_id AS resource_id,
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
$$ LANGUAGE sql STABLE PARALLEL SAFE SET search_path = authz, pg_temp;


-- Expand resource descendants recursively
--
-- Given a resource, returns itself and all descendant resources by following
-- 'parent' relations downward. Used by list_resources() to include children
-- of accessible resources.
--
-- Example: If folder:root contains folder:projects contains doc:spec,
-- this returns (folder, root), (folder, projects), (doc, spec).
CREATE OR REPLACE FUNCTION authz._expand_resource_descendants(
    p_resource_type text,
    p_resource_id text,
    p_namespace text DEFAULT 'default'
)
RETURNS TABLE(resource_type text, resource_id text)
AS $$
    WITH RECURSIVE descendants AS (
        -- The resource itself
        SELECT
            p_resource_type AS resource_type,
            p_resource_id AS resource_id,
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
$$ LANGUAGE sql STABLE PARALLEL SAFE SET search_path = authz, pg_temp;
