-- =============================================================================
-- WRITE TUPLE
-- =============================================================================
-- Inserts or updates a relationship tuple.
--
-- NESTED TEAMS
-- ------------
-- Nested team relationships MUST use the 'member' relation:
--   SELECT authz.write('team', 'platform', 'member', 'team', 'infrastructure');
-- This makes infrastructure team a member of platform team.
--
-- Other relations like 'admin' represent a user's role WITHIN a group, not nesting:
--   SELECT authz.write('team', 'eng', 'admin', 'user', 'alice');  -- alice is admin OF eng
--
-- The permission resolution logic only follows 'member' relations when expanding
-- nested groups. Using other relations for nesting will NOT propagate permissions.
--
-- Circular memberships are detected and rejected.
--
-- RESOURCE HIERARCHIES
-- --------------------
-- Resource containment uses the 'parent' relation:
--   SELECT authz.write('doc', 'spec', 'parent', 'folder', 'projects');
-- This makes doc:spec a child of folder:projects.
--
-- Circular resource hierarchies are detected and rejected.
CREATE OR REPLACE FUNCTION authz.write_tuple(
    p_resource_type text,
    p_resource_id text,
    p_relation text,
    p_subject_type text,
    p_subject_id text,
    p_subject_relation text DEFAULT NULL,
    p_namespace text DEFAULT 'default',
    p_expires_at timestamptz DEFAULT NULL
)
RETURNS bigint AS $$
DECLARE
    v_tuple_id bigint;
BEGIN
    -- Validate inputs
    PERFORM
        authz._validate_identifier (p_resource_type, 'resource_type');
    PERFORM
        authz._validate_identifier (p_relation, 'relation');
    PERFORM
        authz._validate_identifier (p_subject_type, 'subject_type');
    PERFORM
        authz._validate_id (p_resource_id, 'resource_id');
    PERFORM
        authz._validate_id (p_subject_id, 'subject_id');
    PERFORM
        authz._validate_namespace (p_namespace);
    IF p_subject_relation IS NOT NULL THEN
        PERFORM
            authz._validate_identifier (p_subject_relation, 'subject_relation');
    END IF;
    -- Validate expiration is in the future
    IF p_expires_at IS NOT NULL AND p_expires_at <= now() THEN
        RAISE EXCEPTION 'expires_at must be in the future'
            USING ERRCODE = 'check_violation';
    END IF;

    -- Check for cycles when adding group-to-group membership
    IF p_relation = 'member' AND p_subject_type != 'user' THEN
        -- Fast path: self-reference (no locks needed)
        IF p_resource_type = p_subject_type AND p_resource_id = p_subject_id THEN
            RAISE EXCEPTION 'A group cannot be a member of itself'
                USING ERRCODE = 'invalid_parameter_value';
        END IF;

        -- Lock both endpoints to prevent concurrent cycle creation
        PERFORM authz._acquire_dual_lock(
            p_namespace,
            p_resource_type, p_resource_id,
            p_subject_type, p_subject_id
        );

        -- Transitive cycle check (now safe under dual lock)
        IF authz._would_create_cycle(p_resource_type, p_resource_id, p_subject_type, p_subject_id, p_namespace) THEN
            RAISE EXCEPTION 'This would create a circular group membership'
                USING ERRCODE = 'invalid_parameter_value';
        END IF;
    END IF;

    -- Check for cycles when adding parent relation (resource hierarchy)
    IF p_relation = 'parent' THEN
        -- Fast path: self-reference (no locks needed)
        IF p_resource_type = p_subject_type AND p_resource_id = p_subject_id THEN
            RAISE EXCEPTION 'A resource cannot be its own parent'
                USING ERRCODE = 'invalid_parameter_value';
        END IF;

        -- Lock both endpoints to prevent concurrent cycle creation
        PERFORM authz._acquire_dual_lock(
            p_namespace,
            p_resource_type, p_resource_id,
            p_subject_type, p_subject_id
        );

        -- Transitive cycle check (now safe under dual lock)
        IF authz._would_create_resource_cycle(p_resource_type, p_resource_id, p_subject_type, p_subject_id, p_namespace) THEN
            RAISE EXCEPTION 'This would create a circular resource hierarchy'
                USING ERRCODE = 'invalid_parameter_value';
        END IF;
    END IF;

    -- Insert or update the tuple
    INSERT INTO authz.tuples (namespace, resource_type, resource_id, relation, subject_type, subject_id, subject_relation, expires_at)
        VALUES (p_namespace, p_resource_type, p_resource_id, p_relation, p_subject_type, p_subject_id, p_subject_relation, p_expires_at)
    ON CONFLICT (namespace, resource_type, resource_id, relation, subject_type, subject_id, COALESCE(subject_relation, ''))
        DO UPDATE SET
            expires_at = EXCLUDED.expires_at
        RETURNING id INTO v_tuple_id;

    RETURN v_tuple_id;
END;
$$
LANGUAGE plpgsql SECURITY INVOKER
SET search_path = authz, pg_temp;

-- =============================================================================
-- CONVENIENCE WRAPPER
-- =============================================================================
CREATE OR REPLACE FUNCTION authz.write(
    p_resource_type text,
    p_resource_id text,
    p_relation text,
    p_subject_type text,
    p_subject_id text,
    p_namespace text DEFAULT 'default',
    p_expires_at timestamptz DEFAULT NULL
)
RETURNS bigint AS $$
BEGIN
    RETURN authz.write_tuple(p_resource_type, p_resource_id, p_relation,
        p_subject_type, p_subject_id, NULL, p_namespace, p_expires_at);
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = authz, pg_temp;

-- =============================================================================
-- BULK WRITE - Insert multiple tuples efficiently
-- =============================================================================
-- Use this for bulk imports.
CREATE OR REPLACE FUNCTION authz.write_tuples_bulk(
    p_resource_type text,
    p_resource_id text,
    p_relation text,
    p_subject_type text,
    p_subject_ids text[],
    p_namespace text DEFAULT 'default'
)
RETURNS int AS $$
DECLARE
    v_count int;
BEGIN
    -- Validate once (not per row)
    PERFORM
        authz._validate_namespace (p_namespace);
    PERFORM
        authz._validate_identifier (p_resource_type, 'resource_type');
    PERFORM
        authz._validate_id (p_resource_id, 'resource_id');
    PERFORM
        authz._validate_identifier (p_relation, 'relation');
    PERFORM
        authz._validate_identifier (p_subject_type, 'subject_type');
    -- Reject relations that require cycle detection (must use write_tuple instead)
    IF p_relation = 'member' AND p_subject_type != 'user' THEN
        RAISE EXCEPTION 'write_tuples_bulk cannot create group-to-group memberships; use write_tuple instead'
            USING ERRCODE = 'feature_not_supported';
    END IF;
    IF p_relation = 'parent' THEN
        RAISE EXCEPTION 'write_tuples_bulk cannot create parent relations; use write_tuple instead'
            USING ERRCODE = 'feature_not_supported';
    END IF;
    -- Validate subject_ids array (consistent with write_tuple behavior)
    PERFORM authz._validate_id_array(p_subject_ids, 'subject_ids');
INSERT INTO authz.tuples (namespace, resource_type, resource_id, relation, subject_type, subject_id)
SELECT
    p_namespace,
    p_resource_type,
    p_resource_id,
    p_relation,
    p_subject_type,
    unnest(p_subject_ids)
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
LANGUAGE plpgsql SECURITY INVOKER
SET search_path = authz, pg_temp;
