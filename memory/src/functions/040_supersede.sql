-- @group Supersession

-- @function memory.supersede
-- @brief Replace a node with a newer one, keeping the old for history (M4).
-- @param p_namespace Tenant namespace
-- @param p_node Node being superseded
-- @param p_replacement Node that replaces it
-- @returns void
-- @example SELECT memory.supersede('default', 10, 11);
--
-- Never updates content in place: the old node is marked invalidated and
-- pointed at its replacement, so "what did we believe then" stays answerable.
-- M4 (single-step, acyclic): a node cannot supersede itself, an already
-- superseded node cannot be superseded again, and the replacement must be
-- live. A superseded node is always invalidated, so requiring a live
-- replacement makes a supersession cycle unreachable. Both rows are locked
-- in id order before the checks so concurrent supersessions serialize
-- without deadlock.
CREATE OR REPLACE FUNCTION memory.supersede(
    p_namespace text,
    p_node bigint,
    p_replacement bigint
)
RETURNS void AS $$
DECLARE
    v_superseded_by bigint;
    v_replacement_invalidated_at timestamptz;
BEGIN
    PERFORM memory._validate_namespace(p_namespace);
    PERFORM memory._warn_namespace_mismatch(p_namespace);

    IF p_node = p_replacement THEN
        RAISE EXCEPTION 'A node cannot supersede itself'
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:memory:BIZ_SUPERSEDE_SELF';
    END IF;

    PERFORM 1
    FROM memory.nodes n
    WHERE n.namespace = p_namespace AND n.id IN (p_node, p_replacement)
    ORDER BY n.id
    FOR UPDATE;

    SELECT n.superseded_by INTO v_superseded_by
    FROM memory.nodes n
    WHERE n.namespace = p_namespace AND n.id = p_node;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Node % not found', p_node
            USING ERRCODE = 'no_data_found',
                  HINT = 'postkit:memory:DATA_NODE_NOT_FOUND';
    END IF;

    IF v_superseded_by IS NOT NULL THEN
        RAISE EXCEPTION 'Node % has already been superseded', p_node
            USING ERRCODE = 'object_not_in_prerequisite_state',
                  HINT = 'postkit:memory:BIZ_ALREADY_SUPERSEDED';
    END IF;

    SELECT n.invalidated_at INTO v_replacement_invalidated_at
    FROM memory.nodes n
    WHERE n.namespace = p_namespace AND n.id = p_replacement;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Replacement node % not found', p_replacement
            USING ERRCODE = 'no_data_found',
                  HINT = 'postkit:memory:DATA_NODE_NOT_FOUND';
    END IF;

    IF v_replacement_invalidated_at IS NOT NULL THEN
        RAISE EXCEPTION 'Replacement node % is invalidated', p_replacement
            USING ERRCODE = 'object_not_in_prerequisite_state',
                  HINT = 'postkit:memory:BIZ_REPLACEMENT_INVALIDATED';
    END IF;

    UPDATE memory.nodes
    SET superseded_by = p_replacement,
        invalidated_at = now(),
        valid_until = COALESCE(valid_until, now())
    WHERE namespace = p_namespace AND id = p_node;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path = memory, pg_temp;
