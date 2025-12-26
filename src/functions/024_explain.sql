-- =============================================================================
-- EXPLAIN PERMISSION - Trace how a user got a permission
-- =============================================================================
--
-- This function traces the permission graph on-demand to explain why a user
-- has (or doesn't have) a permission. Supports nested teams and resource hierarchies.
--
-- ALGORITHM: BACKWARD CHAINING
-- ============================
-- We start from the question "does user X have permission Y on resource Z?"
-- and work backwards through all possible paths:
--
--   1. Check direct: Is there a tuple (resource, relation=permission, user)?
--   2. Check groups: Is there a tuple (resource, relation=permission, group)
--      where user is a member of that group (including nested)?
--   3. Check hierarchy: Is there a higher permission that implies this one?
--      If so, recursively explain how they got the higher permission.
--   4. Check resource ancestors: Is there a grant on a parent resource?
--      If so, recursively explain the permission on the ancestor.
-- Return type for explain results
DO $$
BEGIN
    CREATE TYPE authz.permission_path AS (
        path_type text,        -- 'direct', 'group', 'hierarchy', or 'resource'
        via_relation text,     -- The relation that granted access (e.g., 'admin')
        via_subject_type text, -- For group/hierarchy: the group type (e.g., 'team')
                               -- For resource: the ancestor resource type (e.g., 'folder')
        via_subject_id text,   -- For group/hierarchy: the group id (e.g., 'engineering')
                               -- For resource: the ancestor resource id (e.g., 'projects')
        via_membership text,   -- For group/hierarchy: user's relation to group (e.g., 'member')
        path_chain text[]      -- Path traversed (usage depends on path_type):
                               --   'group': nested group chain, e.g., ['team:infra', 'team:platform']
                               --   'hierarchy': permission chain, e.g., ['admin', 'write', 'read']
                               --   'resource': resource chain, e.g., ['folder:projects', 'folder:root']
                               --   'direct': NULL
    );
EXCEPTION
    WHEN duplicate_object THEN
        NULL;
END
$$;

-- Explain how a user has (or doesn't have) a permission
CREATE OR REPLACE FUNCTION authz.explain (p_user_id text, p_permission text, p_resource_type text, p_resource_id text, p_namespace text DEFAULT 'default', p_max_depth int DEFAULT NULL)
    RETURNS SETOF authz.permission_path
    AS $$
DECLARE
    v_path authz.permission_path;
    v_higher_permission text;
    v_chain text[];
    v_higher_path authz.permission_path;
    v_group RECORD;
    v_max_depth int;
BEGIN
    -- Use centralized default if not specified
    v_max_depth := COALESCE(p_max_depth, authz.max_group_depth());

    -- Depth limit to prevent runaway recursion on malformed data
    IF v_max_depth <= 0 THEN
        RAISE WARNING 'explain() reached maximum recursion depth for permission % on %:%', p_permission, p_resource_type, p_resource_id;
        RETURN;
    END IF;
    -- ==========================================================================
    -- PATH 1: DIRECT PERMISSION
    -- ==========================================================================
    FOR v_path IN
    SELECT
        'direct'::text,
        t.relation,
        NULL::text,
        NULL::text,
        NULL::text,
        NULL::text[]
    FROM
        authz.tuples t
    WHERE
        t.namespace = p_namespace
        AND t.resource_type = p_resource_type
        AND t.resource_id = p_resource_id
        AND t.relation = p_permission
        AND t.subject_type = 'user'
        AND t.subject_id = p_user_id
        AND t.subject_relation IS NULL
        AND (t.expires_at IS NULL
            OR t.expires_at > now())
            LOOP
                RETURN NEXT v_path;
            END LOOP;
    -- ==========================================================================
    -- PATH 2: GROUP MEMBERSHIP (including nested teams)
    -- ==========================================================================
    -- Find all groups the user belongs to (including via nested teams)
    -- and check if any of those groups have the permission on the resource
    -- Depth limit of 50 prevents runaway recursion on malformed data
    FOR v_group IN WITH RECURSIVE user_memberships AS (
        -- Direct memberships: user is member of group
        SELECT
            resource_type AS group_type,
            resource_id AS group_id,
            relation AS membership_relation,
            ARRAY[resource_type || ':' || resource_id] AS path,
            1 AS depth
        FROM
            authz.tuples
        WHERE
            namespace = p_namespace
            AND subject_type = 'user'
            AND subject_id = p_user_id
            AND (expires_at IS NULL
                OR expires_at > now())
        UNION
        -- Nested memberships: groups that contain groups the user is in
        SELECT
            t.resource_type,
            t.resource_id,
            t.relation,
            um.path || (t.resource_type || ':' || t.resource_id),
            um.depth + 1
        FROM
            user_memberships um
            JOIN authz.tuples t ON t.namespace = p_namespace
                AND t.subject_type = um.group_type
                AND t.subject_id = um.group_id
                AND t.relation = 'member'
                AND (t.expires_at IS NULL
                    OR t.expires_at > now())
        WHERE
            um.depth < v_max_depth)
        -- Find grants on the resource to any of these groups
        SELECT
            um.group_type,
            um.group_id,
            um.membership_relation,
            um.path
        FROM
            user_memberships um
            JOIN authz.tuples t ON t.namespace = p_namespace
                AND t.resource_type = p_resource_type
                AND t.resource_id = p_resource_id
                AND t.relation = p_permission
                AND t.subject_type = um.group_type
                AND t.subject_id = um.group_id
                AND (t.subject_relation IS NULL
                    OR t.subject_relation = um.membership_relation)
                AND (t.expires_at IS NULL
                    OR t.expires_at > now())
                    LOOP
                        v_path := ('group',
                            p_permission,
                            v_group.group_type,
                            v_group.group_id,
                            v_group.membership_relation,
                            v_group.path);
                        RETURN NEXT v_path;
                    END LOOP;
    -- ==========================================================================
    -- PATH 3: PERMISSION HIERARCHY
    -- ==========================================================================
    FOR v_higher_permission IN
    SELECT
        h.permission
    FROM
        authz.permission_hierarchy h
    WHERE
        h.namespace = p_namespace
        AND h.resource_type = p_resource_type
        AND h.implies = p_permission LOOP
            -- Recursively explain how they got the higher permission
            FOR v_higher_path IN
            SELECT
                *
            FROM
                authz.explain (p_user_id, v_higher_permission, p_resource_type, p_resource_id, p_namespace, v_max_depth - 1)
                LOOP
                    -- Build the permission chain
                    IF v_higher_path.path_chain IS NULL THEN
                        v_chain := ARRAY[v_higher_permission, p_permission];
                    ELSE
                        v_chain := v_higher_path.path_chain || p_permission;
                    END IF;
                    v_path := ('hierarchy',
                        v_higher_path.via_relation,
                        v_higher_path.via_subject_type,
                        v_higher_path.via_subject_id,
                        v_higher_path.via_membership,
                        v_chain);
                    RETURN NEXT v_path;
                END LOOP;
        END LOOP;
    -- ==========================================================================
    -- PATH 4: RESOURCE HIERARCHY (access via parent resource)
    -- ==========================================================================
    -- Check if permission is granted on an ancestor resource
    FOR v_group IN
        SELECT
            t.subject_type AS parent_type,
            t.subject_id AS parent_id
        FROM authz.tuples t
        WHERE t.namespace = p_namespace
          AND t.resource_type = p_resource_type
          AND t.resource_id = p_resource_id
          AND t.relation = 'parent'
          AND (t.expires_at IS NULL OR t.expires_at > now())
    LOOP
        -- Recursively explain how they got the permission on the parent
        FOR v_higher_path IN
            SELECT *
            FROM authz.explain(p_user_id, p_permission, v_group.parent_type, v_group.parent_id, p_namespace, v_max_depth - 1)
        LOOP
            -- Build the resource chain
            IF v_higher_path.path_type = 'resource' THEN
                -- Extend existing resource chain
                v_chain := ARRAY[p_resource_type || ':' || p_resource_id] || v_higher_path.path_chain;
            ELSE
                -- Start new resource chain
                v_chain := ARRAY[p_resource_type || ':' || p_resource_id, v_group.parent_type || ':' || v_group.parent_id];
            END IF;
            v_path := ('resource',
                v_higher_path.via_relation,
                v_group.parent_type,
                v_group.parent_id,
                v_higher_path.via_membership,
                v_chain);
            RETURN NEXT v_path;
        END LOOP;
    END LOOP;
    RETURN;
    END;
$$
LANGUAGE plpgsql
STABLE PARALLEL SAFE SET search_path = authz, pg_temp;

-- =============================================================================
-- EXPLAIN TEXT - Human-readable version of explain
-- =============================================================================
CREATE OR REPLACE FUNCTION authz.explain_text (p_user_id text, p_permission text, p_resource_type text, p_resource_id text, p_namespace text DEFAULT 'default')
    RETURNS SETOF TEXT
    AS $$
DECLARE
    v_path authz.permission_path;
    v_text text;
    v_found boolean := FALSE;
BEGIN
    FOR v_path IN
    SELECT
        *
    FROM
        authz.explain (p_user_id, p_permission, p_resource_type, p_resource_id, p_namespace)
        LOOP
            v_found := TRUE;
            CASE v_path.path_type
            WHEN 'direct' THEN
                v_text := format('DIRECT: user:%s has %s on %s:%s', p_user_id, v_path.via_relation, p_resource_type, p_resource_id);
            WHEN 'group' THEN
                -- path_chain contains nested group traversal for group paths
                IF v_path.path_chain IS NOT NULL AND array_length(v_path.path_chain, 1) > 1 THEN
                    -- Nested group path: show the chain of groups traversed
                    v_text := format('GROUP: user:%s is %s of %s (via %s) which has %s on %s:%s',
                        p_user_id, v_path.via_membership,
                        v_path.via_subject_type || ':' || v_path.via_subject_id,
                        array_to_string(v_path.path_chain, ' -> '),
                        v_path.via_relation, p_resource_type, p_resource_id);
                ELSE
                    -- Direct group membership
                    v_text := format('GROUP: user:%s is %s of %s:%s which has %s on %s:%s',
                        p_user_id, v_path.via_membership,
                        v_path.via_subject_type, v_path.via_subject_id,
                        v_path.via_relation, p_resource_type, p_resource_id);
                END IF;
            WHEN 'hierarchy' THEN
                -- path_chain contains permission implication chain for hierarchy paths
                IF v_path.via_subject_type IS NOT NULL THEN
                    v_text := format('HIERARCHY: user:%s is %s of %s:%s which has %s (%s) on %s:%s',
                        p_user_id, v_path.via_membership,
                        v_path.via_subject_type, v_path.via_subject_id,
                        v_path.via_relation, array_to_string(v_path.path_chain, ' -> '),
                        p_resource_type, p_resource_id);
                ELSE
                    v_text := format('HIERARCHY: user:%s has %s (%s) on %s:%s',
                        p_user_id, v_path.via_relation,
                        array_to_string(v_path.path_chain, ' -> '),
                        p_resource_type, p_resource_id);
                END IF;
            WHEN 'resource' THEN
                -- path_chain contains resource containment chain
                v_text := format('RESOURCE: user:%s has %s on %s:%s which contains %s',
                    p_user_id, v_path.via_relation,
                    v_path.via_subject_type, v_path.via_subject_id,
                    array_to_string(v_path.path_chain, ' -> '));
            END CASE;
            RETURN NEXT v_text;
        END LOOP;
    -- If no paths found, explain that permission is not granted
    IF NOT v_found THEN
        RETURN NEXT format('NO ACCESS: user:%s does not have %s on %s:%s', p_user_id, p_permission, p_resource_type, p_resource_id);
    END IF;
    RETURN;
END;
$$
LANGUAGE plpgsql
STABLE PARALLEL SAFE SET search_path = authz, pg_temp;
