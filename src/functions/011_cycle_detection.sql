-- =============================================================================
-- CYCLE DETECTION
-- =============================================================================
-- Prevents and detects circular memberships in groups and resource hierarchies.
--
-- Cycles are bad because they cause infinite recursion during permission
-- checks. Example group cycle: team:A contains team:B contains team:C contains team:A
-- Example resource cycle: folder:A contains folder:B contains folder:A
--
-- would_create_cycle() is called before inserting group-to-group memberships.
-- would_create_resource_cycle() is called before inserting parent relations.
-- detect_cycles() and detect_resource_cycles() are maintenance tools to find
-- cycles if they somehow exist.


-- Check if adding a membership would create a cycle
--
-- Called before inserting: (parent, member, child) tuples where child is a group.
-- Returns true if p_parent is already a descendant of p_child (which would
-- make adding p_child as a member of p_parent create a cycle).
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
$$ LANGUAGE sql STABLE SET search_path = authz, pg_temp;


-- Find existing cycles in the group membership graph
--
-- Use this to diagnose problems if cycles somehow get created (e.g., by
-- direct SQL inserts bypassing write_tuple validation).
--
-- Returns the path of each cycle found.
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
            ARRAY[parent_type || ':' || parent_id, child_type || ':' || child_id] AS path,
            (parent_type = child_type AND parent_id = child_id) AS is_cycle
        FROM group_edges

        UNION ALL

        SELECT
            p.parent_type,
            p.parent_id,
            e.child_type,
            e.child_id,
            p.path || (e.child_type || ':' || e.child_id),
            (e.child_type || ':' || e.child_id) = ANY(p.path)
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
$$ LANGUAGE sql STABLE SET search_path = authz, pg_temp;


-- =============================================================================
-- RESOURCE HIERARCHY CYCLE DETECTION
-- =============================================================================

-- Check if adding a parent relation would create a cycle
--
-- Called before inserting: (child, parent, parent_resource) tuples.
-- Returns true if the proposed parent is already a descendant of the child
-- (which would create a cycle).
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
$$ LANGUAGE sql STABLE SET search_path = authz, pg_temp;


-- Find existing cycles in the resource hierarchy graph
--
-- Use this to diagnose problems if cycles somehow get created (e.g., by
-- direct SQL inserts bypassing write_tuple validation).
--
-- Returns the path of each cycle found.
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
            ARRAY[child_type || ':' || child_id, parent_type || ':' || parent_id] AS path,
            (child_type = parent_type AND child_id = parent_id) AS is_cycle
        FROM parent_edges

        UNION ALL

        SELECT
            p.child_type,
            p.child_id,
            e.parent_type,
            e.parent_id,
            p.path || (e.parent_type || ':' || e.parent_id),
            (e.parent_type || ':' || e.parent_id) = ANY(p.path)
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
$$ LANGUAGE sql STABLE SET search_path = authz, pg_temp;
