-- =============================================================================
-- MAINTENANCE FUNCTIONS
-- =============================================================================
-- Functions for bulk operations, consistency checking, and statistics.

-- =============================================================================
-- INTEGRITY CHECK
-- =============================================================================
-- Checks for data integrity issues like circular group memberships and
-- circular resource hierarchies.
CREATE OR REPLACE FUNCTION authz.verify_integrity(p_namespace text DEFAULT 'default')
RETURNS TABLE (
    resource_type text,
    resource_id text,
    status text,
    details text
)
AS $$
BEGIN
    -- Check for group membership cycles
    RETURN QUERY
    SELECT
        'system'::text AS resource_type,
        'group_cycles'::text AS resource_id,
        'warning'::text AS status,
        'Circular group membership detected: ' || array_to_string(cycle_path, ' -> ') AS details
    FROM authz._detect_cycles(p_namespace);

    -- Check for resource hierarchy cycles
    RETURN QUERY
    SELECT
        'system'::text AS resource_type,
        'resource_cycles'::text AS resource_id,
        'warning'::text AS status,
        'Circular resource hierarchy detected: ' || array_to_string(cycle_path, ' -> ') AS details
    FROM authz._detect_resource_cycles(p_namespace);

    RETURN;
END;
$$ LANGUAGE plpgsql SET search_path = authz, pg_temp;

-- =============================================================================
-- STATISTICS
-- =============================================================================
-- Returns namespace statistics for monitoring and capacity planning.
CREATE OR REPLACE FUNCTION authz.get_stats(p_namespace text DEFAULT 'default')
RETURNS TABLE (
    tuple_count bigint,
    hierarchy_rule_count bigint,
    unique_users bigint,
    unique_resources bigint
)
AS $$
BEGIN
    RETURN QUERY
    SELECT
        (SELECT COUNT(*) FROM authz.tuples WHERE namespace = p_namespace)::bigint,
        (SELECT COUNT(*) FROM authz.permission_hierarchy WHERE namespace = p_namespace)::bigint,
        (SELECT COUNT(DISTINCT subject_id) FROM authz.tuples WHERE namespace = p_namespace AND subject_type = 'user')::bigint,
        (SELECT COUNT(DISTINCT (resource_type, resource_id)) FROM authz.tuples WHERE namespace = p_namespace)::bigint;
END;
$$ LANGUAGE plpgsql STABLE PARALLEL SAFE SET search_path = authz, pg_temp;

-- =============================================================================
-- BULK GRANT TO RESOURCES
-- =============================================================================
-- Grant permission to a subject on many resources at once.
CREATE OR REPLACE FUNCTION authz.grant_to_resources_bulk (p_resource_type text, p_resource_ids text[], p_relation text, p_subject_type text, p_subject_id text, p_subject_relation text DEFAULT NULL, p_namespace text DEFAULT 'default')
    RETURNS int
    AS $$
DECLARE
    v_count int;
BEGIN
    -- Validate inputs once
    PERFORM
        authz._validate_namespace (p_namespace);
    PERFORM
        authz._validate_identifier (p_resource_type, 'resource_type');
    PERFORM
        authz._validate_identifier (p_relation, 'relation');
    PERFORM
        authz._validate_identifier (p_subject_type, 'subject_type');
    PERFORM
        authz._validate_id (p_subject_id, 'subject_id');
    IF p_subject_relation IS NOT NULL THEN
        PERFORM
            authz._validate_identifier (p_subject_relation, 'subject_relation');
    END IF;
    -- Validate resource_ids array
    PERFORM authz._validate_id_array(p_resource_ids, 'resource_ids');
    -- Reject relations that require cycle detection (must use write_tuple instead)
    IF p_relation = 'member' AND p_subject_type != 'user' THEN
        RAISE EXCEPTION 'grant_to_resources_bulk cannot create group-to-group memberships; use write_tuple instead'
            USING ERRCODE = 'feature_not_supported';
    END IF;
    IF p_relation = 'parent' THEN
        RAISE EXCEPTION 'grant_to_resources_bulk cannot create parent relations; use write_tuple instead'
            USING ERRCODE = 'feature_not_supported';
    END IF;
    INSERT INTO authz.tuples (namespace, resource_type, resource_id, relation, subject_type, subject_id, subject_relation)
    SELECT
        p_namespace,
        p_resource_type,
        unnest(p_resource_ids),
        p_relation,
        p_subject_type,
        p_subject_id,
        p_subject_relation
    ON CONFLICT (namespace,
        resource_type,
        resource_id,
        relation,
        subject_type,
        subject_id,
        COALESCE(subject_relation, ''))
        DO NOTHING;
    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count;
END;
$$
LANGUAGE plpgsql
SET search_path = authz, pg_temp;
