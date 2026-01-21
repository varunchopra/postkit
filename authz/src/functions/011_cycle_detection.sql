-- @group Internal

-- @function authz._hash64
-- @brief Generate a 64-bit hash from a text key using md5
-- @param p_key Text to hash
-- @returns bigint hash value
-- Uses first 16 hex chars of md5 (64 bits) for better collision resistance than hashtext (32 bits).
CREATE OR REPLACE FUNCTION authz._hash64(p_key text)
RETURNS bigint AS $$
    SELECT ('x' || substr(md5(p_key), 1, 16))::bit(64)::bigint;
$$ LANGUAGE sql IMMUTABLE PARALLEL SAFE SECURITY INVOKER;

-- @function authz._acquire_dual_lock
-- @brief Acquires advisory locks on both endpoints of an edge
-- @param p_namespace Namespace
-- @param p_type1 First endpoint type
-- @param p_id1 First endpoint ID
-- @param p_type2 Second endpoint type
-- @param p_id2 Second endpoint ID
-- Prevents race conditions where two concurrent transactions both pass cycle detection.
-- Locks both endpoints in deterministic order to prevent deadlocks.
CREATE OR REPLACE FUNCTION authz._acquire_dual_lock(
    p_namespace text,
    p_type1 text,
    p_id1 text,
    p_type2 text,
    p_id2 text
) RETURNS void AS $$
DECLARE
    v_key1 text := p_namespace || E'\x1F' || p_type1 || E'\x1F' || p_id1;
    v_key2 text := p_namespace || E'\x1F' || p_type2 || E'\x1F' || p_id2;
BEGIN
    -- Use single-argument pg_advisory_xact_lock(bigint) with 64-bit hash.
    -- This provides much better collision resistance than the two 32-bit hash approach:
    -- - hashtext() returns 32-bit int, birthday paradox kicks in at ~65K entities
    -- - md5-based 64-bit hash: birthday threshold is ~4 billion entities
    -- Collisions cause unnecessary serialization (performance) not correctness issues.
    IF v_key1 < v_key2 THEN
        PERFORM pg_advisory_xact_lock(authz._hash64(v_key1));
        PERFORM pg_advisory_xact_lock(authz._hash64(v_key2));
    ELSE
        PERFORM pg_advisory_xact_lock(authz._hash64(v_key2));
        PERFORM pg_advisory_xact_lock(authz._hash64(v_key1));
    END IF;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = authz, pg_temp;


-- @function authz._would_create_cycle
-- @brief Check if adding a membership would create a cycle
-- @param p_parent_type Parent group type
-- @param p_parent_id Parent group ID
-- @param p_child_type Child group type
-- @param p_child_id Child group ID
-- @param p_namespace Namespace (default: 'default')
-- @returns True if adding this edge would create a cycle
-- Called before inserting group-to-group membership tuples.
CREATE OR REPLACE FUNCTION authz._would_create_cycle(
    p_parent_type text,
    p_parent_id text,
    p_child_type text,
    p_child_id text,
    p_namespace text DEFAULT 'default'
)
RETURNS boolean AS $$
    WITH RECURSIVE ancestors AS (
        -- Start from the proposed parent
        SELECT
            p_parent_type AS group_type,
            p_parent_id AS group_id,
            1 AS depth

        UNION

        -- Walk up: find groups that contain the current group
        SELECT
            t.resource_type,
            t.resource_id,
            a.depth + 1
        FROM ancestors a
        JOIN authz.tuples t
          ON t.namespace = p_namespace
          AND t.subject_type = a.group_type
          AND t.subject_id = a.group_id
          AND t.relation = 'member'
        WHERE a.depth < authz._max_group_depth()
    )
    -- Cycle exists if child appears in parent's ancestor chain
    SELECT EXISTS (
        SELECT 1 FROM ancestors
        WHERE group_type = p_child_type AND group_id = p_child_id
    );
$$ LANGUAGE sql STABLE SECURITY INVOKER SET search_path = authz, pg_temp;


-- @function authz._detect_cycles
-- @brief Find existing cycles in the group membership graph
-- @param p_namespace Namespace (default: 'default')
-- @returns Table of cycle paths
-- Use to diagnose problems if cycles get created (e.g., by direct SQL inserts).
CREATE OR REPLACE FUNCTION authz._detect_cycles(p_namespace text DEFAULT 'default')
RETURNS TABLE(cycle_path text[]) AS $$
    WITH RECURSIVE
    -- All group-to-group membership edges
    group_edges AS (
        SELECT
            resource_type AS parent_type,
            resource_id AS parent_id,
            subject_type AS child_type,
            subject_id AS child_id
        FROM authz.tuples
        WHERE namespace = p_namespace
          AND relation = 'member'
          AND subject_type != 'user'
    ),

    -- Explore all paths, detecting when we revisit a node
    paths AS (
        SELECT
            parent_type,
            parent_id,
            child_type,
            child_id,
            ARRAY[parent_type || E'\x1F' || parent_id, child_type || E'\x1F' || child_id] AS path,
            (parent_type = child_type AND parent_id = child_id) AS is_cycle
        FROM group_edges

        UNION ALL

        SELECT
            p.parent_type,
            p.parent_id,
            e.child_type,
            e.child_id,
            p.path || (e.child_type || E'\x1F' || e.child_id),
            (e.child_type || E'\x1F' || e.child_id) = ANY(p.path)
        FROM paths p
        JOIN group_edges e
          ON e.parent_type = p.child_type
          AND e.parent_id = p.child_id
        WHERE NOT p.is_cycle
          AND array_length(p.path, 1) < authz._max_group_depth()
    )

    SELECT DISTINCT path AS cycle_path
    FROM paths
    WHERE is_cycle;
$$ LANGUAGE sql STABLE SECURITY INVOKER SET search_path = authz, pg_temp;


-- @function authz._would_create_resource_cycle
-- @brief Check if adding a parent relation would create a cycle
-- @param p_child_type Child resource type
-- @param p_child_id Child resource ID
-- @param p_parent_type Parent resource type
-- @param p_parent_id Parent resource ID
-- @param p_namespace Namespace (default: 'default')
-- @returns True if adding this edge would create a cycle
-- Called before inserting parent relation tuples.
CREATE OR REPLACE FUNCTION authz._would_create_resource_cycle(
    p_child_type text,
    p_child_id text,
    p_parent_type text,
    p_parent_id text,
    p_namespace text DEFAULT 'default'
)
RETURNS boolean AS $$
    WITH RECURSIVE ancestors AS (
        -- Start from the proposed parent
        SELECT
            p_parent_type AS resource_type,
            p_parent_id AS resource_id,
            1 AS depth

        UNION

        -- Walk up: find parents of the current resource
        SELECT
            t.subject_type,
            t.subject_id,
            a.depth + 1
        FROM ancestors a
        JOIN authz.tuples t
          ON t.namespace = p_namespace
          AND t.resource_type = a.resource_type
          AND t.resource_id = a.resource_id
          AND t.relation = 'parent'
        WHERE a.depth < authz._max_resource_depth()
    )
    -- Cycle exists if child appears in parent's ancestor chain
    SELECT EXISTS (
        SELECT 1 FROM ancestors
        WHERE resource_type = p_child_type AND resource_id = p_child_id
    );
$$ LANGUAGE sql STABLE SECURITY INVOKER SET search_path = authz, pg_temp;


-- @function authz._detect_resource_cycles
-- @brief Find existing cycles in the resource hierarchy graph
-- @param p_namespace Namespace (default: 'default')
-- @returns Table of cycle paths
-- Use to diagnose problems if cycles get created (e.g., by direct SQL inserts).
CREATE OR REPLACE FUNCTION authz._detect_resource_cycles(p_namespace text DEFAULT 'default')
RETURNS TABLE(cycle_path text[]) AS $$
    WITH RECURSIVE
    -- All parent relation edges
    parent_edges AS (
        SELECT
            resource_type AS child_type,
            resource_id AS child_id,
            subject_type AS parent_type,
            subject_id AS parent_id
        FROM authz.tuples
        WHERE namespace = p_namespace
          AND relation = 'parent'
    ),

    -- Explore all paths, detecting when we revisit a node
    paths AS (
        SELECT
            child_type,
            child_id,
            parent_type,
            parent_id,
            ARRAY[child_type || E'\x1F' || child_id, parent_type || E'\x1F' || parent_id] AS path,
            (child_type = parent_type AND child_id = parent_id) AS is_cycle
        FROM parent_edges

        UNION ALL

        SELECT
            p.child_type,
            p.child_id,
            e.parent_type,
            e.parent_id,
            p.path || (e.parent_type || E'\x1F' || e.parent_id),
            (e.parent_type || E'\x1F' || e.parent_id) = ANY(p.path)
        FROM paths p
        JOIN parent_edges e
          ON e.child_type = p.parent_type
          AND e.child_id = p.parent_id
        WHERE NOT p.is_cycle
          AND array_length(p.path, 1) < authz._max_resource_depth()
    )

    SELECT DISTINCT path AS cycle_path
    FROM paths
    WHERE is_cycle;
$$ LANGUAGE sql STABLE SECURITY INVOKER SET search_path = authz, pg_temp;
