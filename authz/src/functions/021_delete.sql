-- =============================================================================
-- DELETE TUPLE
-- =============================================================================
-- Removes a relationship tuple. Audit trigger will log the deletion.
CREATE OR REPLACE FUNCTION authz.delete_tuple(
    p_resource_type text,
    p_resource_id text,
    p_relation text,
    p_subject_type text,
    p_subject_id text,
    p_subject_relation text DEFAULT NULL,
    p_namespace text DEFAULT 'default'
)
RETURNS boolean AS $$
DECLARE
    v_deleted int;
BEGIN
    -- Validate inputs (consistent with write_tuple)
    PERFORM authz._validate_identifier(p_resource_type, 'resource_type');
    PERFORM authz._validate_identifier(p_relation, 'relation');
    PERFORM authz._validate_identifier(p_subject_type, 'subject_type');
    PERFORM authz._validate_id(p_resource_id, 'resource_id');
    PERFORM authz._validate_id(p_subject_id, 'subject_id');
    PERFORM authz._validate_namespace(p_namespace);
    IF p_subject_relation IS NOT NULL THEN
        PERFORM authz._validate_identifier(p_subject_relation, 'subject_relation');
    END IF;

    DELETE FROM authz.tuples
    WHERE namespace = p_namespace
        AND resource_type = p_resource_type
        AND resource_id = p_resource_id
        AND relation = p_relation
        AND subject_type = p_subject_type
        AND subject_id = p_subject_id
        AND COALESCE(subject_relation, '') = COALESCE(p_subject_relation, '');
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    RETURN v_deleted > 0;
END;
$$
LANGUAGE plpgsql SECURITY INVOKER
SET search_path = authz, pg_temp;

-- =============================================================================
-- CONVENIENCE WRAPPER
-- =============================================================================
CREATE OR REPLACE FUNCTION authz.delete(
    p_resource_type text,
    p_resource_id text,
    p_relation text,
    p_subject_type text,
    p_subject_id text,
    p_namespace text DEFAULT 'default'
)
RETURNS boolean AS $$
BEGIN
    RETURN authz.delete_tuple(p_resource_type, p_resource_id, p_relation,
        p_subject_type, p_subject_id, NULL, p_namespace);
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = authz, pg_temp;
