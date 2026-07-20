-- @group Permission Checks

-- Core permission check functions for any subject type (user, api_key, service, etc.)
-- Note: _expand_subject_memberships is in 010_helpers.sql

-- @function authz._get_permissions
-- @brief Get all effective permissions for a subject on a resource
-- @param p_subject_type The subject type (e.g., 'user', 'api_key', 'service')
-- @param p_subject_id The subject ID
-- @param p_resource_type The resource type
-- @param p_resource_id The resource ID
-- @param p_namespace Namespace (default: 'default')
-- @returns Table of permissions the subject has
CREATE OR REPLACE FUNCTION authz._get_permissions(
    p_subject_type text,
    p_subject_id text,
    p_resource_type text,
    p_resource_id text,
    p_namespace text DEFAULT 'default'
)
RETURNS TABLE(permission text)
AS $$
    WITH RECURSIVE
    subject_memberships AS (
        SELECT * FROM authz._expand_subject_memberships(p_subject_type, p_subject_id, p_namespace)
    ),
    resource_chain AS (
        SELECT * FROM authz._expand_resource_ancestors(p_resource_type, p_resource_id, p_namespace)
    ),
    granted_permissions AS (
        SELECT t.relation AS perm
        FROM authz.tuples t
        JOIN resource_chain rc
          ON t.resource_type = rc.resource_type
          AND t.resource_id = rc.resource_id
        WHERE t.namespace = p_namespace
          AND t.subject_type = p_subject_type
          AND t.subject_id = p_subject_id
          AND t.subject_relation IS NULL
          AND (t.expires_at IS NULL OR t.expires_at > now())

        UNION
        SELECT t.relation AS perm
        FROM authz.tuples t
        JOIN resource_chain rc
          ON t.resource_type = rc.resource_type
          AND t.resource_id = rc.resource_id
        JOIN subject_memberships sm
          ON t.subject_type = sm.group_type
          AND t.subject_id = sm.group_id
          AND (t.subject_relation IS NULL OR t.subject_relation = sm.membership_relation)
        WHERE t.namespace = p_namespace
          AND (t.expires_at IS NULL OR t.expires_at > now())
    ),

    -- Permission implications combine global defaults with tenant rules and use
    -- the same depth bound as group and resource traversal.
    all_permissions(perm, depth) AS (
        SELECT perm, 1 FROM granted_permissions

        UNION

        SELECT h.implies, ap.depth + 1
        FROM all_permissions ap
        JOIN authz.permission_hierarchy h
          ON h.resource_type = p_resource_type
          AND h.permission = ap.perm
          AND h.namespace IN ('global', p_namespace)
        WHERE ap.depth < 50
    )

    SELECT perm AS permission FROM all_permissions;
$$ LANGUAGE sql STABLE PARALLEL SAFE SECURITY INVOKER SET search_path = authz, pg_temp;


-- Exact-resource grants can be decided without expanding subject memberships or
-- resource ancestors. Reverse hierarchy traversal preserves tenant and global
-- permission implications and the public traversal depth bound.
CREATE OR REPLACE FUNCTION authz._has_direct_permission(
    p_subject_type text,
    p_subject_id text,
    p_permissions text[],
    p_resource_type text,
    p_resource_id text,
    p_namespace text
) RETURNS boolean AS $$
    WITH RECURSIVE implied_by(permission, depth) AS (
        SELECT permission, 1
        FROM unnest(p_permissions) AS permission

        UNION

        SELECT h.permission, ib.depth + 1
        FROM implied_by ib
        JOIN authz.permission_hierarchy h
          ON h.namespace IN ('global', p_namespace)
         AND h.resource_type = p_resource_type
         AND h.implies = ib.permission
        WHERE ib.depth < 50
    )
    SELECT EXISTS (
        SELECT 1
        FROM authz.tuples t
        JOIN implied_by ib ON ib.permission = t.relation
        WHERE t.namespace = p_namespace
          AND t.resource_type = p_resource_type
          AND t.resource_id = p_resource_id
          AND t.subject_type = p_subject_type
          AND t.subject_id = p_subject_id
          AND t.subject_relation IS NULL
          AND (t.expires_at IS NULL OR t.expires_at > now())
    );
$$ LANGUAGE sql STABLE PARALLEL SAFE SECURITY INVOKER SET search_path = authz, pg_temp;


-- @function authz.check
-- @brief Check if a subject has a permission on a resource
-- @param p_subject_type The subject type (e.g., 'user', 'api_key', 'service')
-- @param p_subject_id The subject ID
-- @param p_permission The permission to verify (e.g., 'read', 'write', 'admin')
-- @param p_resource_type The type of resource (e.g., 'repo', 'doc')
-- @param p_resource_id The resource identifier
-- @returns True if the subject has the permission
--
-- Direct grants avoid graph traversal. Group-derived and inherited access uses
-- bounded subject and resource traversal.
--
-- @example SELECT authz.check('user', 'alice', 'read', 'doc', 'spec-123');
-- @example SELECT authz.check('api_key', 'key-123', 'read', 'repo', 'api');
CREATE OR REPLACE FUNCTION authz.check(
    p_subject_type text,
    p_subject_id text,
    p_permission text,
    p_resource_type text,
    p_resource_id text,
    p_namespace text DEFAULT 'default'
) RETURNS boolean AS $$
BEGIN
    PERFORM authz._warn_namespace_mismatch(p_namespace);
    IF authz._has_direct_permission(
        p_subject_type,
        p_subject_id,
        ARRAY[p_permission],
        p_resource_type,
        p_resource_id,
        p_namespace
    ) THEN
        RETURN true;
    END IF;
    RETURN EXISTS (
        SELECT 1 FROM authz._get_permissions(
            p_subject_type, p_subject_id, p_resource_type, p_resource_id, p_namespace
        )
        WHERE permission = p_permission
    );
END;
$$ LANGUAGE plpgsql STABLE PARALLEL SAFE SECURITY INVOKER SET search_path = authz, pg_temp;


-- @function authz.check_any
-- @brief Check if a subject has any of the specified permissions
-- @param p_subject_type The subject type
-- @param p_subject_id The subject ID
-- @param p_permissions Array of permissions (subject needs at least one)
-- @param p_resource_type The type of resource
-- @param p_resource_id The resource identifier
-- @returns True if the subject has at least one of the permissions
-- @example SELECT authz.check_any('user', 'alice', ARRAY['read', 'write'], 'doc', 'spec-123');
CREATE OR REPLACE FUNCTION authz.check_any(
    p_subject_type text,
    p_subject_id text,
    p_permissions text[],
    p_resource_type text,
    p_resource_id text,
    p_namespace text DEFAULT 'default'
) RETURNS boolean AS $$
BEGIN
    PERFORM authz._validate_batch_size(cardinality(p_permissions), 'permissions');
    PERFORM authz._warn_namespace_mismatch(p_namespace);
    IF authz._has_direct_permission(
        p_subject_type,
        p_subject_id,
        p_permissions,
        p_resource_type,
        p_resource_id,
        p_namespace
    ) THEN
        RETURN true;
    END IF;
    RETURN EXISTS (
        SELECT 1 FROM authz._get_permissions(
            p_subject_type, p_subject_id, p_resource_type, p_resource_id, p_namespace
        )
        WHERE permission = ANY(p_permissions)
    );
END;
$$ LANGUAGE plpgsql STABLE PARALLEL SAFE SECURITY INVOKER SET search_path = authz, pg_temp;


-- @function authz.check_all
-- @brief Check if a subject has all of the specified permissions
-- @param p_subject_type The subject type
-- @param p_subject_id The subject ID
-- @param p_permissions Array of permissions (subject needs all of them)
-- @param p_resource_type The type of resource
-- @param p_resource_id The resource identifier
-- @returns True if the subject has all of the permissions
-- @example SELECT authz.check_all('user', 'alice', ARRAY['read', 'write'], 'doc', 'spec-123');
CREATE OR REPLACE FUNCTION authz.check_all(
    p_subject_type text,
    p_subject_id text,
    p_permissions text[],
    p_resource_type text,
    p_resource_id text,
    p_namespace text DEFAULT 'default'
) RETURNS boolean AS $$
BEGIN
    PERFORM authz._validate_batch_size(cardinality(p_permissions), 'permissions');
    PERFORM authz._warn_namespace_mismatch(p_namespace);
    -- Compare distinct counts on both sides so duplicate entries in
    -- p_permissions do not inflate the requirement.
    RETURN COALESCE(array_length(p_permissions, 1), 0) = 0
        OR (
            SELECT COUNT(DISTINCT permission)
            FROM authz._get_permissions(
                p_subject_type, p_subject_id, p_resource_type, p_resource_id, p_namespace
            )
            WHERE permission = ANY(p_permissions)
        ) = (SELECT COUNT(DISTINCT p) FROM unnest(p_permissions) AS p);
END;
$$ LANGUAGE plpgsql STABLE PARALLEL SAFE SECURITY INVOKER SET search_path = authz, pg_temp;
