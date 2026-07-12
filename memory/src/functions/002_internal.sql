-- @group Internal

-- @function memory._get_config
-- @brief Get effective configuration for a namespace.
-- @param p_namespace Namespace to get config for
-- @returns The namespace's own config row, or the global defaults row
CREATE OR REPLACE FUNCTION memory._get_config(p_namespace text)
RETURNS memory.config AS $$
DECLARE
    v_config memory.config;
BEGIN
    SELECT * INTO v_config
    FROM memory.config
    WHERE namespace = p_namespace;

    IF FOUND THEN
        RETURN v_config;
    END IF;

    SELECT * INTO v_config
    FROM memory.config
    WHERE namespace = 'global';

    IF NOT FOUND THEN
        v_config.namespace := 'global';
        v_config.recall_max_hops := 2;
        v_config.recall_max_nodes := 200;
        v_config.recall_halflife := '30 days'::interval;
        v_config.consolidation_batch_size := 50;
        v_config.notify_on_record := false;
    END IF;

    RETURN v_config;
END;
$$ LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = memory, pg_temp;


-- @function memory._embedding_dim
-- @brief The fixed embedding dimension, or NULL when set_dimension has not run.
-- @returns Dimension in use, or NULL when the embedding columns are still dimensionless
-- Read from the episodes.embedding column's own type modifier (atttypmod): for
-- the vector type the typmod IS the dimension, and -1 means unset. Nothing
-- stores the dimension separately; the column type is the single source of
-- truth, so set_dimension()'s ALTER TYPE is the only way it changes.
CREATE OR REPLACE FUNCTION memory._embedding_dim()
RETURNS int AS $$
DECLARE
    v_typmod int;
BEGIN
    SELECT a.atttypmod INTO v_typmod
    FROM pg_attribute a
    WHERE a.attrelid = 'memory.episodes'::regclass
      AND a.attname = 'embedding';

    IF v_typmod IS NULL OR v_typmod = -1 THEN
        RETURN NULL;
    END IF;

    RETURN v_typmod;
END;
$$ LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = memory, pg_temp;


-- @function memory._resolve_edge_ref
-- @brief Resolve a consolidate() edge endpoint to an existing node id.
-- @param p_namespace Tenant namespace
-- @param p_ref Endpoint from the edge element: a JSON number (node id) or an "n<i>" string
-- @param p_node_ids Node ids inserted this batch, in fact order (for "n<i>" refs)
-- @returns The resolved node id
-- A numeric ref must reference a node that exists in this namespace (M2), else
-- DATA_NODE_NOT_FOUND. An "n<i>" string references the i-th fact (0-based) of
-- the same batch; anything else, or an out-of-range index, is VAL_EDGE_MALFORMED.
CREATE OR REPLACE FUNCTION memory._resolve_edge_ref(
    p_namespace text,
    p_ref jsonb,
    p_node_ids bigint[]
)
RETURNS bigint AS $$
DECLARE
    v_id bigint;
    v_str text;
    v_i int;
BEGIN
    IF p_ref IS NULL OR jsonb_typeof(p_ref) IS NULL THEN
        RAISE EXCEPTION 'Edge endpoint is missing'
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:memory:VAL_EDGE_MALFORMED';
    END IF;

    IF jsonb_typeof(p_ref) = 'number' THEN
        v_str := p_ref#>>'{}';
        -- Up to 18 digits always fits bigint; a fraction or exponent
        -- survives jsonb normalization and must not reach the cast.
        IF v_str !~ '^-?[0-9]{1,18}$' THEN
            RAISE EXCEPTION 'Edge endpoint % is not a node id', v_str
                USING ERRCODE = 'invalid_parameter_value',
                      HINT = 'postkit:memory:VAL_EDGE_MALFORMED';
        END IF;
        v_id := v_str::bigint;
        IF NOT EXISTS (
            SELECT 1 FROM memory.nodes n
            WHERE n.namespace = p_namespace AND n.id = v_id
        ) THEN
            RAISE EXCEPTION 'Edge references node % which does not exist in namespace', v_id
                USING ERRCODE = 'no_data_found',
                      HINT = 'postkit:memory:DATA_NODE_NOT_FOUND';
        END IF;
        RETURN v_id;
    END IF;

    IF jsonb_typeof(p_ref) = 'string' THEN
        v_str := p_ref#>>'{}';
        IF v_str ~ '^n[0-9]{1,9}$' THEN
            v_i := substring(v_str FROM 2)::int;
            IF v_i >= 0 AND v_i < COALESCE(cardinality(p_node_ids), 0) THEN
                RETURN p_node_ids[v_i + 1];
            END IF;
        END IF;
        RAISE EXCEPTION 'Edge reference "%" does not resolve to a fact in this batch', v_str
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'postkit:memory:VAL_EDGE_MALFORMED';
    END IF;

    RAISE EXCEPTION 'Edge endpoint must be a node id or an "n<i>" reference'
        USING ERRCODE = 'invalid_parameter_value',
              HINT = 'postkit:memory:VAL_EDGE_MALFORMED';
END;
$$ LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = memory, pg_temp;
