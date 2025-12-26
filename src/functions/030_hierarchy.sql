-- =============================================================================
-- HIERARCHY MANAGEMENT FUNCTIONS
-- =============================================================================
--
-- PURPOSE
-- -------
-- Manages permission hierarchy rules (e.g., "admin implies write implies read").
-- These functions safely add/remove hierarchy rules.
--
-- With lazy evaluation, hierarchy changes take effect immediately for all
-- subsequent permission checks without needing recomputation.
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
        RAISE EXCEPTION 'Hierarchy cycle detected: % implies itself', p_permission;
    END IF;
    -- Check for indirect cycle: would p_implies eventually lead back to p_permission?
    WITH RECURSIVE hierarchy_chain AS (
        -- Start with what p_implies currently implies
        SELECT
            implies AS perm
        FROM
            authz.permission_hierarchy
        WHERE
            namespace = p_namespace
            AND resource_type = p_resource_type
            AND permission = p_implies
        UNION
        -- Follow the chain
        SELECT
            h.implies
        FROM
            hierarchy_chain hc
            JOIN authz.permission_hierarchy h ON h.namespace = p_namespace
                AND h.resource_type = p_resource_type
                AND h.permission = hc.perm
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
        RAISE EXCEPTION 'Hierarchy cycle detected: adding % -> % would create a cycle', p_permission, p_implies;
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
LANGUAGE plpgsql
SET search_path = authz, pg_temp;

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
LANGUAGE plpgsql
SET search_path = authz, pg_temp;

-- Clear all hierarchy rules for a resource type
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
LANGUAGE plpgsql
SET search_path = authz, pg_temp;
