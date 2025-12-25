-- =============================================================================
-- CHECK PERMISSION - Fast O(1) permission lookup
-- =============================================================================
--
-- PURPOSE
-- -------
-- The core authorization check: "Can user X do action Y on resource Z?"
-- This is the hot path - called on every API request that needs auth.
--
-- ALGORITHM
-- ---------
-- Direct index lookup on the computed table. No graph traversal needed
-- because permissions are pre-computed on write.
--
-- COMPLEXITY
-- ----------
-- Time:  O(1) - single index lookup via computed table's unique constraint
-- Space: O(1) - no additional memory allocation
--
-- EXAMPLE
-- -------
-- SELECT authz.check('alice', 'read', 'doc', 'design-spec', 'default');
-- => true (if alice has read permission on doc:design-spec)
--
-- VARIANTS
-- --------
-- - check_any(user, permissions[], ...) - true if user has ANY permission
-- - check_all(user, permissions[], ...) - true if user has ALL permissions

CREATE OR REPLACE FUNCTION authz.check(
    p_user_id TEXT,
    p_permission TEXT,
    p_resource_type TEXT,
    p_resource_id TEXT,
    p_namespace TEXT DEFAULT 'default'
) RETURNS BOOLEAN AS $$
BEGIN
    -- Fast path: check pre-computed permissions
    -- Exclude expired permissions (NULL expires_at = never expires)
    RETURN EXISTS (
        SELECT 1 FROM authz.computed
        WHERE namespace = p_namespace
          AND user_id = p_user_id
          AND permission = p_permission
          AND resource_type = p_resource_type
          AND resource_id = p_resource_id
          AND (expires_at IS NULL OR expires_at > now())
    );
END;
$$ LANGUAGE plpgsql STABLE PARALLEL SAFE SET search_path = authz, pg_temp;

-- Check multiple permissions at once (returns first matching)
CREATE OR REPLACE FUNCTION authz.check_any(
    p_user_id TEXT,
    p_permissions TEXT[],
    p_resource_type TEXT,
    p_resource_id TEXT,
    p_namespace TEXT DEFAULT 'default'
) RETURNS BOOLEAN AS $$
BEGIN
    RETURN EXISTS (
        SELECT 1 FROM authz.computed
        WHERE namespace = p_namespace
          AND user_id = p_user_id
          AND permission = ANY(p_permissions)
          AND resource_type = p_resource_type
          AND resource_id = p_resource_id
          AND (expires_at IS NULL OR expires_at > now())
    );
END;
$$ LANGUAGE plpgsql STABLE PARALLEL SAFE SET search_path = authz, pg_temp;

-- Check all permissions (user must have all)
-- Returns true if user has ALL of the specified permissions
-- Returns true for empty array (vacuous truth - user trivially has all zero permissions)
CREATE OR REPLACE FUNCTION authz.check_all(
    p_user_id TEXT,
    p_permissions TEXT[],
    p_resource_type TEXT,
    p_resource_id TEXT,
    p_namespace TEXT DEFAULT 'default'
) RETURNS BOOLEAN AS $$
BEGIN
    -- Empty array = vacuous truth (user has all zero required permissions)
    IF p_permissions IS NULL OR array_length(p_permissions, 1) IS NULL THEN
        RETURN true;
    END IF;

    RETURN (
        SELECT COUNT(DISTINCT permission) = array_length(p_permissions, 1)
        FROM authz.computed
        WHERE namespace = p_namespace
          AND user_id = p_user_id
          AND permission = ANY(p_permissions)
          AND resource_type = p_resource_type
          AND resource_id = p_resource_id
          AND (expires_at IS NULL OR expires_at > now())
    );
END;
$$ LANGUAGE plpgsql STABLE PARALLEL SAFE SET search_path = authz, pg_temp;
