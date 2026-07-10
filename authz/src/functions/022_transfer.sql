-- @group Transfers

-- @function authz.transfer_tuple
-- @brief Move a grant from one subject to another atomically.
-- @param p_resource_type Resource type
-- @param p_resource_id Resource identifier
-- @param p_relation Permission being transferred
-- @param p_from_subject_type Current holder's type
-- @param p_from_subject_id Current holder's identifier
-- @param p_to_subject_type New holder's type
-- @param p_to_subject_id New holder's identifier
-- @param p_namespace Tenant namespace
-- @returns True if the grant was transferred, false if the source had no active (non-expired) grant.
--   Expiration is preserved: temporary grants remain temporary after transfer.
-- @example -- Transfer ownership from alice to bob
-- @example SELECT authz.transfer_tuple('org', '1', 'owner', 'user', 'alice', 'user', 'bob');
CREATE OR REPLACE FUNCTION authz.transfer_tuple(
    p_resource_type text,
    p_resource_id text,
    p_relation text,
    p_from_subject_type text,
    p_from_subject_id text,
    p_to_subject_type text,
    p_to_subject_id text,
    p_namespace text DEFAULT 'default'
)
RETURNS boolean AS $$
DECLARE
    v_source_id bigint;
    v_expires_at timestamptz;
BEGIN
    -- Self-transfer is a no-op: return whether the grant exists without
    -- touching the row (preserves tuple_id and avoids spurious audit events).
    -- Both sides of this comparison are function parameters, and parameters
    -- compare under the database's default byte-wise collation rather than
    -- the id columns' collation, so COLLATE is spelled out to treat two
    -- Unicode spellings of the same id as the same subject.
    IF p_from_subject_type = p_to_subject_type
       AND p_from_subject_id = p_to_subject_id COLLATE authz.canonical THEN
        RETURN EXISTS (
            SELECT 1 FROM authz.tuples
            WHERE namespace = p_namespace
              AND resource_type = p_resource_type
              AND resource_id = p_resource_id
              AND relation = p_relation
              AND subject_type = p_from_subject_type
              AND subject_id = p_from_subject_id
              AND subject_relation IS NULL
              AND (expires_at IS NULL OR expires_at > now())
        );
    END IF;

    -- Lock the source row to prevent concurrent transfers from both
    -- succeeding. Without FOR UPDATE, two transactions can read the same
    -- row, both proceed past this check, and both create target grants -
    -- duplicating a permission that should be exclusive.
    SELECT t.id, t.expires_at INTO v_source_id, v_expires_at
    FROM authz.tuples t
    WHERE t.namespace = p_namespace
      AND t.resource_type = p_resource_type
      AND t.resource_id = p_resource_id
      AND t.relation = p_relation
      AND t.subject_type = p_from_subject_type
      AND t.subject_id = p_from_subject_id
      AND t.subject_relation IS NULL
      AND (t.expires_at IS NULL OR t.expires_at > now())
    FOR UPDATE;

    IF NOT FOUND THEN
        RETURN false;
    END IF;

    -- Delete by PK. The row is locked by our SELECT, so no concurrent
    -- session can modify or delete it between the check and this point.
    DELETE FROM authz.tuples WHERE id = v_source_id;

    -- Create the target grant. write_tuple handles input validation,
    -- cycle detection (for member/parent relations), and upsert (if the
    -- target already holds this grant, only expiration is updated).
    PERFORM authz.write_tuple(
        p_resource_type, p_resource_id, p_relation,
        p_to_subject_type, p_to_subject_id, NULL, p_namespace, v_expires_at
    );

    RETURN true;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = authz, pg_temp;
