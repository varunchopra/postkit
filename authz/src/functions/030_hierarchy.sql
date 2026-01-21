-- @group Hierarchy
-- =============================================================================
-- PERMISSION HIERARCHY FUNCTIONS
-- =============================================================================
--
-- TWO-TIER HIERARCHY SYSTEM:
--
-- Permission checks look at BOTH global AND tenant-specific hierarchies:
--
--   1. GLOBAL (namespace = 'global')
--      - App-wide defaults set by developer
--      - Example: "owner -> edit -> view" for all tenants
--      - RLS allows all tenants to READ but not WRITE global rules
--
--   2. TENANT-SPECIFIC (namespace = tenant namespace)
--      - Org-specific customizations set by customers
--      - Example: "legal_approver -> viewer" for enterprise workflow
--      - Allows orgs to extend the model for their structure
--
-- HOW IT WORKS:
--   - Permission checks use: namespace IN ('global', p_namespace)
--   - SDK passes tenant namespace for org-specific rules
--   - SDK passes 'global' for app-wide defaults
--   - RLS ensures tenants can only modify their own rules, not global ones
--
-- See 001_tables.sql for full architecture documentation.
-- =============================================================================

-- @function authz.add_hierarchy
-- @brief Define that one permission implies another (e.g., admin implies write)
-- @param p_permission The higher permission (e.g., 'admin')
-- @param p_implies The implied permission (e.g., 'write')
-- @returns Rule ID
-- @example -- admin can do everything write can do, write can do everything read can do
-- @example SELECT authz.add_hierarchy('repo', 'admin', 'write', 'default');
-- @example SELECT authz.add_hierarchy('repo', 'write', 'read', 'default');
CREATE OR REPLACE FUNCTION authz.add_hierarchy (p_resource_type text, p_permission text, p_implies text, p_namespace text DEFAULT 'default')
    RETURNS bigint
    AS $$
DECLARE
    v_id bigint;
    v_has_cycle boolean;
BEGIN
    -- Validate inputs
    PERFORM
        authz._validate_namespace (p_namespace);
    PERFORM
        authz._validate_identifier (p_resource_type, 'resource_type');
    PERFORM
        authz._validate_identifier (p_permission, 'permission');
    PERFORM
        authz._validate_identifier (p_implies, 'implies');
    -- Check for direct self-cycle
    IF p_permission = p_implies THEN
        RAISE EXCEPTION 'Hierarchy cycle detected: % implies itself', p_permission
            USING ERRCODE = 'PK001',
                  HINT = 'postkit:authz:BIZ_CYCLE_SELF';
    END IF;
    -- Check for indirect cycle: would p_implies eventually lead back to p_permission?
    -- Must check both global and tenant namespaces since permission checks use both.
    WITH RECURSIVE hierarchy_chain AS (
        SELECT
            implies AS perm,
            1 AS depth
        FROM
            authz.permission_hierarchy
        WHERE
            namespace IN ('global', p_namespace)
            AND resource_type = p_resource_type
            AND permission = p_implies
        UNION
        SELECT
            h.implies,
            hc.depth + 1
        FROM
            hierarchy_chain hc
            JOIN authz.permission_hierarchy h ON h.namespace IN ('global', p_namespace)
                AND h.resource_type = p_resource_type
                AND h.permission = hc.perm
        WHERE hc.depth < authz._max_group_depth()
)
        SELECT
            EXISTS (
                SELECT
                    1
                FROM
                    hierarchy_chain
            WHERE
                perm = p_permission) INTO v_has_cycle;
    IF v_has_cycle THEN
        RAISE EXCEPTION 'Hierarchy cycle detected: adding % -> % would create a cycle', p_permission, p_implies
            USING ERRCODE = 'PK001',
                  HINT = 'postkit:authz:BIZ_CYCLE_HIERARCHY';
    END IF;
    INSERT INTO authz.permission_hierarchy (namespace, resource_type, permission, implies)
        VALUES (p_namespace, p_resource_type, p_permission, p_implies)
    ON CONFLICT (namespace, resource_type, permission, implies)
        DO UPDATE SET
            permission = authz.permission_hierarchy.permission -- no-op, return existing
        RETURNING
            id INTO v_id;
    RETURN v_id;
END;
$$
LANGUAGE plpgsql SECURITY INVOKER
SET search_path = authz, pg_temp;

-- @function authz.remove_hierarchy
-- @brief Remove a permission implication rule
-- @example SELECT authz.remove_hierarchy('repo', 'admin', 'write', 'default');
CREATE OR REPLACE FUNCTION authz.remove_hierarchy (p_resource_type text, p_permission text, p_implies text, p_namespace text DEFAULT 'default')
    RETURNS boolean
    AS $$
BEGIN
    -- Validate inputs
    PERFORM
        authz._validate_namespace (p_namespace);
    PERFORM
        authz._validate_identifier (p_resource_type, 'resource_type');
    PERFORM
        authz._validate_identifier (p_permission, 'permission');
    PERFORM
        authz._validate_identifier (p_implies, 'implies');
    DELETE FROM authz.permission_hierarchy
    WHERE namespace = p_namespace
        AND resource_type = p_resource_type
        AND permission = p_permission
        AND implies = p_implies;
    RETURN FOUND;
END;
$$
LANGUAGE plpgsql SECURITY INVOKER
SET search_path = authz, pg_temp;

-- @function authz.clear_hierarchy
-- @brief Remove all hierarchy rules for a resource type (start fresh)
-- @returns Number of rules deleted
-- @example SELECT authz.clear_hierarchy('repo', 'default');
CREATE OR REPLACE FUNCTION authz.clear_hierarchy (p_resource_type text, p_namespace text DEFAULT 'default')
    RETURNS int
    AS $$
DECLARE
    v_count int;
BEGIN
    -- Validate inputs
    PERFORM
        authz._validate_namespace (p_namespace);
    PERFORM
        authz._validate_identifier (p_resource_type, 'resource_type');
    DELETE FROM authz.permission_hierarchy
    WHERE namespace = p_namespace
        AND resource_type = p_resource_type;
    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count;
END;
$$
LANGUAGE plpgsql SECURITY INVOKER
SET search_path = authz, pg_temp;
