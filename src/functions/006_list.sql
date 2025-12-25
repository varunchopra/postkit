-- =============================================================================
-- LIST OPERATIONS - Query permissions by user or resource
-- =============================================================================
--
-- PURPOSE
-- -------
-- These functions answer "what can user X access?" and "who can access resource Y?"
-- Used for:
--   - Rendering UI (show user their accessible resources)
--   - Security audits (who has access to sensitive data?)
--   - Batch authorization (filter a list of resources to authorized ones)
--
-- PAGINATION
-- ----------
-- All list functions support cursor-based pagination:
--   - p_limit: Maximum rows to return (default 100)
--   - p_cursor: Resume after this value (sorted alphabetically)
--
-- To paginate: pass the last returned value as the cursor for the next page.
-- When the result count < limit, you've reached the end.
--
-- COMPLEXITY
-- ----------
-- Time:  O(log N + K) where N = total entries, K = result size (uses indexes)
-- Space: O(K) for the result set
--
-- =============================================================================

-- List resources a user can access

CREATE OR REPLACE FUNCTION authz.list_resources(
    p_user_id TEXT,
    p_resource_type TEXT,
    p_permission TEXT,
    p_namespace TEXT DEFAULT 'default',
    p_limit INT DEFAULT 100,
    p_cursor TEXT DEFAULT NULL
) RETURNS TABLE(resource_id TEXT) AS $$
BEGIN
    -- Validate inputs
    PERFORM authz.validate_id(p_user_id, 'user_id');
    PERFORM authz.validate_identifier(p_resource_type, 'resource_type');
    PERFORM authz.validate_identifier(p_permission, 'permission');
    PERFORM authz.validate_namespace(p_namespace);

    RETURN QUERY
    SELECT c.resource_id
    FROM authz.computed c
    WHERE c.namespace = p_namespace
      AND c.user_id = p_user_id
      AND c.resource_type = p_resource_type
      AND c.permission = p_permission
      AND (p_cursor IS NULL OR c.resource_id > p_cursor)
      AND (c.expires_at IS NULL OR c.expires_at > now())
    ORDER BY c.resource_id
    LIMIT p_limit;
END;
$$ LANGUAGE plpgsql STABLE PARALLEL SAFE SET search_path = authz, pg_temp;

-- List users who have permission on a resource

CREATE OR REPLACE FUNCTION authz.list_users(
    p_resource_type TEXT,
    p_resource_id TEXT,
    p_permission TEXT,
    p_namespace TEXT DEFAULT 'default',
    p_limit INT DEFAULT 100,
    p_cursor TEXT DEFAULT NULL
) RETURNS TABLE(user_id TEXT) AS $$
BEGIN
    -- Validate inputs
    PERFORM authz.validate_identifier(p_resource_type, 'resource_type');
    PERFORM authz.validate_id(p_resource_id, 'resource_id');
    PERFORM authz.validate_identifier(p_permission, 'permission');
    PERFORM authz.validate_namespace(p_namespace);

    RETURN QUERY
    SELECT c.user_id
    FROM authz.computed c
    WHERE c.namespace = p_namespace
      AND c.resource_type = p_resource_type
      AND c.resource_id = p_resource_id
      AND c.permission = p_permission
      AND (p_cursor IS NULL OR c.user_id > p_cursor)
      AND (c.expires_at IS NULL OR c.expires_at > now())
    ORDER BY c.user_id
    LIMIT p_limit;
END;
$$ LANGUAGE plpgsql STABLE PARALLEL SAFE SET search_path = authz, pg_temp;

-- Filter a list of resource IDs to only those the user can access

CREATE OR REPLACE FUNCTION authz.filter_authorized(
    p_user_id TEXT,
    p_resource_type TEXT,
    p_permission TEXT,
    p_resource_ids TEXT[],
    p_namespace TEXT DEFAULT 'default'
) RETURNS TEXT[] AS $$
BEGIN
    -- Validate inputs
    PERFORM authz.validate_id(p_user_id, 'user_id');
    PERFORM authz.validate_identifier(p_resource_type, 'resource_type');
    PERFORM authz.validate_identifier(p_permission, 'permission');
    PERFORM authz.validate_namespace(p_namespace);
    -- Note: p_resource_ids validation is skipped - empty/invalid IDs just won't match

    RETURN ARRAY(
        SELECT c.resource_id
        FROM authz.computed c
        WHERE c.namespace = p_namespace
          AND c.user_id = p_user_id
          AND c.resource_type = p_resource_type
          AND c.permission = p_permission
          AND c.resource_id = ANY(p_resource_ids)
          AND (c.expires_at IS NULL OR c.expires_at > now())
    );
END;
$$ LANGUAGE plpgsql STABLE PARALLEL SAFE SET search_path = authz, pg_temp;
