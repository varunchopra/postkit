-- =============================================================================
-- WRITE TUPLE - Create a relationship in the authorization graph
-- =============================================================================
--
-- PURPOSE
-- -------
-- Creates a relationship tuple representing an edge in the authorization graph.
-- This is the primary write operation for granting permissions.
--
-- WHAT IS A TUPLE?
-- ================
-- A tuple represents an edge in the authorization graph:
--   (resource) --[relation]--> (subject)
--
-- Examples:
--   ("repo", "api", "admin", "team", "engineering")
--   = "team:engineering has admin on repo:api"
--
--   ("team", "engineering", "member", "user", "alice")
--   = "user:alice is a member of team:engineering"
--
-- COMPLEXITY
-- ----------
-- Time:  O(G + H) where G = group members affected, H = hierarchy depth
-- Space: O(G × H) for computed table entries
--
-- The write itself is O(1), but triggers recompute which is O(G + H).
--
-- IDEMPOTENCY
-- ===========
-- Writing the same tuple twice is safe - it returns the existing tuple's ID.
-- This is important for:
--   - Retries after network failures
--   - Sync operations that may re-send data
--   - Declarative "ensure this permission exists" patterns

CREATE OR REPLACE FUNCTION authz.write_tuple(
    p_resource_type TEXT,
    p_resource_id TEXT,
    p_relation TEXT,
    p_subject_type TEXT,
    p_subject_id TEXT,
    p_subject_relation TEXT DEFAULT NULL,
    p_namespace TEXT DEFAULT 'default',
    p_expires_at TIMESTAMPTZ DEFAULT NULL
) RETURNS BIGINT AS $$
DECLARE
    v_tuple_id BIGINT;
BEGIN
    -- Serialize ALL writes within this namespace
    -- This ensures triggers always see complete, consistent state
    -- Different namespaces can write in parallel
    --
    -- HASH COLLISION NOTE:
    -- hashtext() returns a 32-bit integer. Collision probability:
    --   - 1,000 namespaces: ~0.01% collision probability
    --   - 10,000 namespaces: ~1.2% collision probability
    --   - 100,000 namespaces: ~69% collision probability (birthday paradox)
    --
    -- If you have >10K namespaces, consider:
    --   1. Using namespace IDs instead of names for locking
    --   2. Accepting occasional false serialization (still safe, just slower)
    --   3. Implementing a custom locking strategy
    --
    -- The two-argument form (prefix, namespace) reduces cross-component collisions.
    PERFORM pg_advisory_xact_lock(hashtext('authz:write'), hashtext(p_namespace));

    -- Validate all inputs (fail fast with clear error messages)
    PERFORM authz.validate_tuple_fields(
        p_namespace, p_resource_type, p_resource_id,
        p_relation, p_subject_type, p_subject_id, p_subject_relation
    );

    -- Validate expiration is in the future if provided
    IF p_expires_at IS NOT NULL AND p_expires_at <= now() THEN
        RAISE EXCEPTION 'expires_at must be in the future'
            USING ERRCODE = 'check_violation';
    END IF;

    INSERT INTO authz.tuples (
        namespace, resource_type, resource_id, relation,
        subject_type, subject_id, subject_relation, expires_at
    ) VALUES (
        p_namespace, p_resource_type, p_resource_id, p_relation,
        p_subject_type, p_subject_id, p_subject_relation, p_expires_at
    )
    ON CONFLICT (namespace, resource_type, resource_id, relation, subject_type, subject_id, COALESCE(subject_relation, ''))
    DO UPDATE SET expires_at = EXCLUDED.expires_at  -- Allow updating expiration
    RETURNING id INTO v_tuple_id;

    RETURN v_tuple_id;
END;
$$ LANGUAGE plpgsql SET search_path = authz, pg_temp;

-- Convenience alias
CREATE OR REPLACE FUNCTION authz.write(
    p_resource_type TEXT,
    p_resource_id TEXT,
    p_relation TEXT,
    p_subject_type TEXT,
    p_subject_id TEXT,
    p_namespace TEXT DEFAULT 'default',
    p_expires_at TIMESTAMPTZ DEFAULT NULL
) RETURNS BIGINT AS $$
BEGIN
    RETURN authz.write_tuple(p_resource_type, p_resource_id, p_relation, p_subject_type, p_subject_id, NULL, p_namespace, p_expires_at);
END;
$$ LANGUAGE plpgsql SET search_path = authz, pg_temp;

-- =============================================================================
-- BULK WRITE - Insert multiple tuples efficiently with proper serialization
-- =============================================================================
-- Use this for bulk imports. Acquires the namespace lock once, validates once,
-- then inserts all tuples in a single statement.

CREATE OR REPLACE FUNCTION authz.write_tuples_bulk(
    p_resource_type TEXT,
    p_resource_id TEXT,
    p_relation TEXT,
    p_subject_type TEXT,
    p_subject_ids TEXT[],
    p_namespace TEXT DEFAULT 'default'
) RETURNS INT AS $$
DECLARE
    v_count INT;
BEGIN
    -- Serialize writes (same lock as write_tuple)
    PERFORM pg_advisory_xact_lock(hashtext('authz:write'), hashtext(p_namespace));

    -- Validate once (not per row)
    PERFORM authz.validate_namespace(p_namespace);
    PERFORM authz.validate_identifier(p_resource_type, 'resource_type');
    PERFORM authz.validate_id(p_resource_id, 'resource_id');
    PERFORM authz.validate_identifier(p_relation, 'relation');
    PERFORM authz.validate_identifier(p_subject_type, 'subject_type');

    -- Validate subject_ids array (consistent with write_tuple behavior)
    IF EXISTS (
        SELECT 1 FROM unnest(p_subject_ids) AS id
        WHERE id IS NULL
           OR trim(id) = ''
           OR length(id) > 1024
           OR id ~ '[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]'
           OR id != trim(id)
    ) THEN
        RAISE EXCEPTION 'subject_ids contains invalid values (null, empty, too long, or invalid characters)';
    END IF;

    INSERT INTO authz.tuples (
        namespace, resource_type, resource_id, relation, subject_type, subject_id
    )
    SELECT p_namespace, p_resource_type, p_resource_id, p_relation, p_subject_type, unnest(p_subject_ids)
    ON CONFLICT (namespace, resource_type, resource_id, relation, subject_type, subject_id, COALESCE(subject_relation, ''))
    DO NOTHING;

    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count;
END;
$$ LANGUAGE plpgsql SET search_path = authz, pg_temp;
